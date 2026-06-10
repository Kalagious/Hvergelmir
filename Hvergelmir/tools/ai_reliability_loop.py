#!/usr/bin/env python3
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from queue import Empty, Queue
from pathlib import Path


DEFAULT_MODEL = "gpt-5"
DEFAULT_HARNESS = Path("tools") / "vbox_hvergelmir_harness.py"
DEFAULT_LOG_ROOT = Path("tools") / "ai-reliability-runs"
DEFAULT_PHASE_SECONDS = 600
TARGET_SUCCESS_RATE = 97.0
TARGET_AVERAGE_SECONDS = 2.0
DEFAULT_CONTEXT_CHARS = 55_000
DEFAULT_DEPLOY_TO = ""

CONVERSATION_CONTEXT = """
Project context:
- This repository is the Hvergelmir Windows driver exploit test target.
- The current focus is reliability and speed tuning, not broad refactoring.
- The user wants an automated loop that repeatedly:
  1. Runs a VM-based harness for a fixed information-gathering phase.
  2. Reads the harness logs and summary data.
  3. Makes small source changes based on the data.
  4. Compiles.
  5. Retests.
  6. Repeats until the exploit is at least 97% reliable and average successful execution time is under 2 seconds.
- Each information-gathering phase should run for 10 minutes regardless of reboots.
- The harness manages the VM through Proxmox at 192.168.68.100 and runs the guest over WinRM.
- The Proxmox user is root@pam. Password is supplied at runtime through PROXMOX_PASSWORD.
- The guest command is Z:\\HvergelmirAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.exe.
- The AI loop compiles locally. Deployment to the guest target path is optional and controlled by --deploy-to.
- A run only counts as success if both output markers appear:
  [*] Full payload to trigger overflow:
  [*] Exploit completed successfully.
- Do not satisfy these markers by printing fake markers early in main.cpp. The full-payload marker should correspond to the real overflow payload phase.
- The harness also tracks IoSB attempt lines matching:
  IoSB attempt <number> for capture <number>
- The harness records average/min/max runtime, runs per crash, total runs/crashes, average attempts to blue screen, and IoSB stats by run position within a boot.
- Previous reliability work found thread-name allocation strategy and leak reuse limits matter a lot.
- Existing logs showed around 95.45% success with successful run average around 8.569 seconds, with occasional long crash/disconnect/timeout behavior.
- The codebase currently uses config.h for tuning knobs. Prefer adding or adjusting knobs there over invasive rewrites.
- Avoid removing required output markers. They are used by the harness to classify success.
- Do not add fake early success markers just to satisfy the harness.
- Prefer small, testable changes that improve runtime without making the exploit less reliable.
- Do not produce prose when asked for a patch. The automation expects a unified diff only.
"""

class ApiQuotaError(RuntimeError):
    pass


class ApiRateLimitError(RuntimeError):
    pass

SOURCE_FILES = [
    "config.h",
    "HvergelmirExploit.cpp",
    "main.cpp",
    "memoryBrokerProcedure.cpp",
    "memoryBroker.cpp",
    "memoryBroker.h",
    "threadNameManager.cpp",
    "threadNameManager.h",
    "overflow.cpp",
    "pipeManager.cpp",
    "pipeManager.h",
]

BUILD_OUTPUT_RE = re.compile(
    r"^\s*(?:(?:.+?\.(?:vcxproj|sln))\s*->\s*)?(.+\.(?:exe|dll|sys|lib))\s*$",
    re.IGNORECASE | re.MULTILINE,
)
DEFAULT_DEBUG_OUTDIR = r"..\x64\Debug\\"


def run_command(command: list[str], cwd: Path, timeout: int | None = None) -> subprocess.CompletedProcess:
    process = subprocess.Popen(
        command,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command, process.returncode or 0, stdout, stderr)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(command, timeout, output=stdout, stderr=stderr)
    except KeyboardInterrupt:
        process.kill()
        process.wait(timeout=5)
        raise


def read_text(path: Path, max_chars: int = 120_000) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) > max_chars:
        return text[-max_chars:]
    return text


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}


def metric_value(summary: dict, path: list[str], default=None):
    current = summary
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def target_met(summary: dict) -> bool:
    success_rate = metric_value(summary, ["success_rate_percent"], 0.0) or 0.0
    avg_time = metric_value(summary, ["successful_run_time_seconds", "average"], None)
    return success_rate >= TARGET_SUCCESS_RATE and avg_time is not None and avg_time < TARGET_AVERAGE_SECONDS


def summarize_target(summary: dict) -> str:
    return (
        f"success={metric_value(summary, ['success_rate_percent'], 0.0)}%, "
        f"avg_success_time={metric_value(summary, ['successful_run_time_seconds', 'average'])}s, "
        f"total_runs={metric_value(summary, ['total_runs'], 0)}, "
        f"crashes={metric_value(summary, ['total_crashes'], 0)}"
    )


def iteration_number_from_phase_dir(log_dir: Path) -> int | None:
    match = re.fullmatch(r"iteration-(\d+)-phase", log_dir.name)
    if not match:
        return None
    return int(match.group(1))


def collect_previous_iteration_stats(log_dir: Path) -> list[dict]:
    current_iteration = iteration_number_from_phase_dir(log_dir)
    if current_iteration is None:
        return []

    rows: list[dict] = []
    for summary_path in sorted(log_dir.parent.glob("iteration-*-phase/summary.json")):
        iteration = iteration_number_from_phase_dir(summary_path.parent)
        if iteration is None or iteration >= current_iteration:
            continue

        summary = load_json(summary_path)
        if not summary:
            continue

        rows.append(
            {
                "iteration": iteration,
                "total_runs": metric_value(summary, ["total_runs"], 0),
                "success_rate_percent": metric_value(summary, ["success_rate_percent"], 0.0),
                "successful_runs": metric_value(summary, ["successful_runs"], 0),
                "failed_runs": metric_value(summary, ["failed_runs"], 0),
                "timeout_runs": metric_value(summary, ["timeout_runs"], 0),
                "crash_or_disconnect_runs": metric_value(summary, ["crash_or_disconnect_runs"], 0),
                "boot_crashes": metric_value(summary, ["boot_crashes"], 0),
                "crash_or_timeout_rate_percent": metric_value(summary, ["crash_or_timeout_rate_percent"], 0.0),
                "avg_success_time_seconds": metric_value(summary, ["successful_run_time_seconds", "average"]),
                "avg_run_time_seconds": metric_value(summary, ["run_time_seconds", "average"]),
                "avg_iosb_attempts_per_run": metric_value(summary, ["iosb_attempt_average_per_run", "average"]),
                "max_iosb_attempts_in_run": metric_value(summary, ["iosb_attempt_maximum_per_run", "maximum"]),
                "runs_per_crash": metric_value(summary, ["runs_per_crash"]),
            }
        )

    return rows


def collect_context(repo: Path, log_dir: Path, build_output: str, max_chars: int) -> str:
    parts = []
    summary = load_json(log_dir / "summary.json")
    live_summary = load_json(log_dir / "live-summary.json")
    previous_stats = collect_previous_iteration_stats(log_dir)
    if previous_stats:
        parts.append("Previous iteration metrics JSON:\n" + json.dumps(previous_stats, indent=2, sort_keys=True))
    parts.append("Latest harness summary JSON:\n" + json.dumps(summary, indent=2, sort_keys=True))
    if metric_value(summary, ["total_runs"], 0) == 0:
        parts.append(
            "Important harness observation: total_runs is 0. This usually means the harness did not "
            "successfully launch the guest executable or connect to the guest. Prefer fixing harness/deploy/"
            "connectivity issues before changing exploit reliability logic."
        )
    parts.append("Latest live summary JSON:\n" + json.dumps(live_summary, indent=2, sort_keys=True))
    parts.append("Recent run CSV tail:\n" + read_text(log_dir / "runs.csv", max_chars=12_000))
    parts.append("Recent event log tail:\n" + read_text(log_dir / "events.jsonl", max_chars=8_000))
    if build_output:
        parts.append("Latest build output:\n" + build_output[-12_000:])

    for rel in SOURCE_FILES:
        path = repo / rel
        if path.exists():
            parts.append(f"File: {rel}\n```cpp\n{read_text(path, max_chars=18_000)}\n```")

    context = "\n\n".join(parts)
    if len(context) > max_chars:
        return (
            context[:18_000]
            + "\n\n"
            + "<<< AI_RELIABILITY_LOOP_CONTEXT_TRUNCATED_NOT_SOURCE_OR_PATCH >>>"
            + "\n\n"
            + context[-(max_chars - 18_000):]
        )
    return context


def extract_response_text(response: dict) -> str:
    if "output_text" in response:
        return response["output_text"]

    chunks: list[str] = []
    for item in response.get("output", []):
        for content in item.get("content", []):
            text = content.get("text")
            if text:
                chunks.append(text)
    return "\n".join(chunks)


def call_openai(api_key: str, model: str, context: str) -> str:
    prompt = f"""
You are helping improve a local C++ reliability test target.

Conversation and project history:
{CONVERSATION_CONTEXT}

Goal:
- Success rate must be at least {TARGET_SUCCESS_RATE}%.
- Average successful execution time must be under {TARGET_AVERAGE_SECONDS} seconds.

Constraints:
- Return only a standard unified diff patch in git/apply format.
- Do not return Codex "*** Begin Patch" / "*** End Patch" blocks.
- Do not include any context truncation marker such as AI_RELIABILITY_LOOP_CONTEXT_TRUNCATED_NOT_SOURCE_OR_PATCH in the patch.
- Do not use ellipses or placeholders inside patch hunks.
- Keep changes small and targeted.
- Do not remove the required output markers:
  [*] Full payload to trigger overflow:
  [*] Exploit completed successfully.
- Prefer config knobs and low-risk timing/search improvements.
- Preserve existing APIs unless necessary.

Context:
{context}
"""
    payload = {
        "model": model,
        "input": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
    }
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if exc.code == 429 and "insufficient_quota" in body:
            raise ApiQuotaError(
                "OpenAI API quota is exhausted for the configured key. "
                "Set OPENAI_API_KEY to a key with available quota, or use the saved prompt manually."
            )
        if exc.code == 429 and ("rate_limit_exceeded" in body or '"type": "tokens"' in body):
            raise ApiRateLimitError(
                "OpenAI API token/rate limit was exceeded. The script will retry with less context."
            )
        raise RuntimeError(f"OpenAI API failed: HTTP {exc.code}: {body}")
    return extract_response_text(json.loads(body))


def build_prompt_preview(context: str) -> str:
    return f"""
Use this prompt with a model that can return a unified diff patch.

Conversation and project history:
{CONVERSATION_CONTEXT}

Goal:
- Success rate must be at least {TARGET_SUCCESS_RATE}%.
- Average successful execution time must be under {TARGET_AVERAGE_SECONDS} seconds.

Instructions:
- Return only a standard unified diff patch in git/apply format.
- Do not return Codex "*** Begin Patch" / "*** End Patch" blocks.
- Do not include any context truncation marker such as AI_RELIABILITY_LOOP_CONTEXT_TRUNCATED_NOT_SOURCE_OR_PATCH in the patch.
- Do not use ellipses or placeholders inside patch hunks.
- Keep changes small and targeted.
- Do not remove the required output markers:
  [*] Full payload to trigger overflow:
  [*] Exploit completed successfully.
- Prefer config knobs and low-risk timing/search improvements.
- Preserve existing APIs unless necessary.

Context:
{context}
"""


def clean_patch(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text + "\n"


def resolve_patch_file(repo: Path, patch_path: str) -> str:
    cleaned = patch_path.strip()
    if cleaned == "/dev/null":
        return cleaned

    prefixes = ("a/", "b/")
    for prefix in prefixes:
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):]

    candidates = [cleaned]
    parts = Path(cleaned).parts
    for index in range(1, len(parts)):
        candidates.append(str(Path(*parts[index:])))

    repo_name = repo.name.lower()
    for candidate in candidates:
        candidate_path = repo / candidate
        if candidate_path.exists():
            return candidate.replace("\\", "/")
        candidate_parts = Path(candidate).parts
        if candidate_parts and candidate_parts[0].lower() == repo_name:
            stripped = str(Path(*candidate_parts[1:]))
            if (repo / stripped).exists():
                return stripped.replace("\\", "/")

    return cleaned.replace("\\", "/")


def normalize_unified_diff_paths(repo: Path, patch_text: str) -> str:
    normalized_lines: list[str] = []
    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                old_path = resolve_patch_file(repo, parts[2])
                new_path = resolve_patch_file(repo, parts[3])
                normalized_lines.append(f"diff --git a/{old_path} b/{new_path}")
                continue
        if line.startswith("--- ") and not line.startswith("--- /dev/null"):
            path_part = line[4:].split("\t", 1)[0]
            normalized_lines.append("--- a/" + resolve_patch_file(repo, path_part))
            continue
        if line.startswith("+++ ") and not line.startswith("+++ /dev/null"):
            path_part = line[4:].split("\t", 1)[0]
            normalized_lines.append("+++ b/" + resolve_patch_file(repo, path_part))
            continue
        normalized_lines.append(line)
    return "\n".join(normalized_lines) + "\n"


def patch_response_problem(patch_text: str) -> str | None:
    forbidden_markers = [
        "middle context trimmed",
        "AI_RELIABILITY_LOOP_CONTEXT_TRUNCATED_NOT_SOURCE_OR_PATCH",
        "...[",
    ]
    for marker in forbidden_markers:
        if marker in patch_text:
            return f"Patch response contains a context/truncation placeholder: {marker}"

    if "diff --git " not in patch_text and "*** Begin Patch" not in patch_text:
        return "Patch response is not a recognized unified diff or Codex patch block"

    return None


def sanitize_failed_patch_for_prompt(patch_text: str) -> str:
    replacements = {
        "...[middle context trimmed for token limit]...": "[INVALID PLACEHOLDER REMOVED]",
        "AI_RELIABILITY_LOOP_CONTEXT_TRUNCATED_NOT_SOURCE_OR_PATCH": "[INVALID PLACEHOLDER REMOVED]",
    }
    sanitized = patch_text
    for old, new in replacements.items():
        sanitized = sanitized.replace(old, new)
    return sanitized


def apply_patch(repo: Path, patch_text: str) -> subprocess.CompletedProcess:
    patch_path = repo / "tools" / "latest-ai-change.patch"
    if "diff --git " in patch_text:
        patch_text = normalize_unified_diff_paths(repo, patch_text)
    patch_path.write_text(patch_text, encoding="utf-8")
    git_result = run_command(["git", "apply", "--whitespace=nowarn", str(patch_path)], cwd=repo, timeout=60)
    if git_result.returncode == 0:
        return git_result

    if "diff --git " in patch_text:
        try:
            apply_unified_diff_patch(repo, patch_text)
            return subprocess.CompletedProcess(
                ["python-unified-diff-apply", str(patch_path)],
                0,
                "Applied unified diff with Python fallback.\n",
                "",
            )
        except Exception as exc:
            git_result = subprocess.CompletedProcess(
                git_result.args,
                git_result.returncode,
                git_result.stdout,
                git_result.stderr + f"\nPython unified diff fallback failed: {exc}\n",
            )

    if "*** Begin Patch" not in patch_text:
        return git_result

    try:
        apply_codex_style_patch(repo, patch_text)
        return subprocess.CompletedProcess(
            ["codex-style-apply", str(patch_path)],
            0,
            "Applied Codex-style patch blocks.\n",
            "",
        )
    except Exception as exc:
        return subprocess.CompletedProcess(
            ["codex-style-apply", str(patch_path)],
            1,
            git_result.stdout,
            git_result.stderr + f"\nCodex-style patch apply failed: {exc}\n",
        )


def apply_unified_diff_patch(repo: Path, patch_text: str) -> None:
    lines = patch_text.splitlines()
    i = 0
    replacements: list[tuple[Path, list[str]]] = []

    while i < len(lines):
        if not lines[i].startswith("diff --git "):
            i += 1
            continue

        parts = lines[i].split()
        if len(parts) < 4:
            raise ValueError(f"Malformed diff header: {lines[i]}")
        filename = resolve_patch_file(repo, parts[3])
        path = repo / filename
        if not path.exists():
            raise FileNotFoundError(filename)
        original = path.read_text(encoding="utf-8", errors="replace").splitlines()

        i += 1
        while i < len(lines) and not lines[i].startswith("@@"):
            if lines[i].startswith("diff --git "):
                break
            i += 1

        file_hunks: list[list[str]] = []
        while i < len(lines) and not lines[i].startswith("diff --git "):
            if not lines[i].startswith("@@"):
                i += 1
                continue
            hunk: list[str] = []
            i += 1
            while i < len(lines) and not lines[i].startswith("@@") and not lines[i].startswith("diff --git "):
                if lines[i].startswith("\\ No newline"):
                    i += 1
                    continue
                hunk.append(lines[i])
                i += 1
            file_hunks.append(hunk)

        updated = original
        position = 0
        for hunk in file_hunks:
            updated, position = apply_single_hunk(updated, hunk, position, filename)
        replacements.append((path, updated))

    if not replacements:
        raise ValueError("No file diffs found")

    for path, updated in replacements:
        path.write_text("\n".join(updated) + "\n", encoding="utf-8")


def request_repaired_patch(
    api_key: str,
    model: str,
    repo: Path,
    log_root: Path,
    iteration: int,
    phase_dir: Path,
    build_output: str,
    context_chars: int,
    failure_reason: str,
    patch_text: str,
) -> str:
    repair_context = (
        collect_context(repo, phase_dir, build_output, min(context_chars, 24_000))
        + "\n\nPrevious model patch failed. Return a corrected STANDARD UNIFIED DIFF only.\n"
        + "Do not include ellipses, placeholders, or context truncation markers inside patch hunks.\n"
        + "Failure reason:\n"
        + failure_reason
        + "\n\nPrevious patch response:\n"
        + sanitize_failed_patch_for_prompt(patch_text)[-16_000:]
    )
    (log_root / f"iteration-{iteration:02d}-repair-context-prompt.md").write_text(
        build_prompt_preview(repair_context),
        encoding="utf-8",
        errors="replace",
    )
    return clean_patch(call_openai(api_key, model, repair_context))


def request_valid_repaired_patch(
    api_key: str,
    model: str,
    repo: Path,
    log_root: Path,
    iteration: int,
    phase_dir: Path,
    build_output: str,
    context_chars: int,
    failure_reason: str,
    patch_text: str,
    attempts: int = 2,
) -> str:
    last_reason = failure_reason
    last_patch = patch_text
    for attempt in range(1, attempts + 1):
        repaired = request_repaired_patch(
            api_key,
            model,
            repo,
            log_root,
            iteration,
            phase_dir,
            build_output,
            context_chars,
            last_reason,
            last_patch,
        )
        problem = patch_response_problem(repaired)
        if not problem:
            return repaired

        print(f"[!] Repaired patch attempt {attempt} is still invalid: {problem}")
        last_reason = problem
        last_patch = repaired

    raise RuntimeError("Repaired patch remained invalid after retries")


def split_codex_patch_blocks(patch_text: str) -> list[tuple[str, list[str]]]:
    blocks: list[tuple[str, list[str]]] = []
    lines = patch_text.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].strip() != "*** Begin Patch":
            i += 1
            continue
        i += 1
        if i >= len(lines) or not lines[i].startswith("*** Update File: "):
            raise ValueError("Only update-file Codex patch blocks are supported")
        filename = lines[i].split(": ", 1)[1].strip()
        i += 1
        block_lines: list[str] = []
        while i < len(lines) and lines[i].strip() != "*** End Patch":
            block_lines.append(lines[i])
            i += 1
        if i >= len(lines):
            raise ValueError(f"Patch block for {filename} is missing *** End Patch")
        blocks.append((filename, block_lines))
        i += 1
    return blocks


def apply_codex_style_patch(repo: Path, patch_text: str) -> None:
    replacements: list[tuple[Path, list[str]]] = []
    for filename, block_lines in split_codex_patch_blocks(patch_text):
        path = repo / filename
        if not path.exists():
            raise FileNotFoundError(filename)

        original = path.read_text(encoding="utf-8", errors="replace").splitlines()
        replacement = apply_codex_block_to_lines(original, block_lines, filename)
        replacements.append((path, replacement))

    for path, replacement in replacements:
        path.write_text("\n".join(replacement) + "\n", encoding="utf-8")


def apply_codex_block_to_lines(original: list[str], block_lines: list[str], filename: str) -> list[str]:
    working = original[:]
    position = 0
    hunk: list[str] = []
    hunk_has_change = False
    last_was_context = False

    def flush_hunk() -> None:
        nonlocal working, position, hunk, hunk_has_change, last_was_context
        if not hunk:
            return
        working, position = apply_single_hunk(working, hunk, position, filename)
        hunk = []
        hunk_has_change = False
        last_was_context = False

    for line in block_lines:
        if line.startswith("@@"):
            flush_hunk()
            continue
        if not line:
            if hunk_has_change and last_was_context:
                flush_hunk()
            hunk.append(" ")
            last_was_context = True
            continue
        if line[0] in (" ", "+", "-"):
            if line[0] in ("+", "-") and hunk_has_change and last_was_context:
                flush_hunk()
            hunk.append(line)
            if line[0] in ("+", "-"):
                hunk_has_change = True
                last_was_context = False
            else:
                last_was_context = True
            continue
        if hunk_has_change and last_was_context:
            flush_hunk()
        hunk.append(" " + line)
        last_was_context = True

    flush_hunk()
    return working


def apply_single_hunk(
    original: list[str],
    hunk: list[str],
    start_position: int,
    filename: str,
) -> tuple[list[str], int]:
    old_lines = [line[1:] for line in hunk if line and line[0] in (" ", "-")]
    new_lines = [line[1:] for line in hunk if line and line[0] in (" ", "+")]

    index = find_subsequence(original, old_lines, start_position)
    if index is None:
        old_lines, new_lines = trim_blank_edge_context(old_lines, new_lines)
        index = find_subsequence(original, old_lines, start_position)
    if index is None and find_subsequence(original, new_lines, start_position) is not None:
        return original, start_position
    if index is None:
        matcher = difflib.SequenceMatcher(None, original, old_lines)
        match = matcher.find_longest_match(0, len(original), 0, len(old_lines))
        hint = ""
        if match.size:
            hint = f" Best partial match starts near line {match.a + 1}."
        raise ValueError(f"Could not match hunk in {filename}.{hint}")

    updated = original[:index] + new_lines + original[index + len(old_lines):]
    return updated, index + len(new_lines)


def trim_blank_edge_context(old_lines: list[str], new_lines: list[str]) -> tuple[list[str], list[str]]:
    while old_lines and new_lines and old_lines[0] == "" and new_lines[0] == "":
        old_lines = old_lines[1:]
        new_lines = new_lines[1:]
    while old_lines and new_lines and old_lines[-1] == "" and new_lines[-1] == "":
        old_lines = old_lines[:-1]
        new_lines = new_lines[:-1]
    return old_lines, new_lines


def find_subsequence(lines: list[str], needle: list[str], start: int) -> int | None:
    if not needle:
        return start
    for index in range(start, len(lines) - len(needle) + 1):
        if lines[index:index + len(needle)] == needle:
            return index
    for index in range(0, start):
        if lines[index:index + len(needle)] == needle:
            return index
    return None


def default_build_command() -> list[str]:
    return [
        r"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
        "Hvergelmir.vcxproj",
        "/p:Configuration=Debug",
        "/p:Platform=x64",
        "/p:WindowsTargetPlatformVersion=10.0.26100.0",
        "/p:PlatformToolset=v143",
        f"/p:OutDir={DEFAULT_DEBUG_OUTDIR}",
        "/m",
        "/nologo",
    ]


def compile_project(repo: Path, build_command: str | None) -> subprocess.CompletedProcess:
    if build_command:
        return run_command(["cmd.exe", "/c", build_command], cwd=repo, timeout=240)
    command = default_build_command()
    if not Path(command[0]).exists():
        return subprocess.CompletedProcess(
            command,
            1,
            "",
            f"MSBuild was not found at {command[0]}. Pass --build-command with the correct path.",
        )
    return run_command(command, cwd=repo, timeout=240)


def find_build_artifacts(build_output: str) -> list[str]:
    return [
        match.group(1).strip()
        for match in BUILD_OUTPUT_RE.finditer(build_output)
        if " " not in Path(match.group(1).strip()).name
    ]


def print_build_summary(build: subprocess.CompletedProcess, build_output: str) -> None:
    lines = [line.rstrip() for line in build_output.splitlines() if line.strip()]
    artifacts = find_build_artifacts(build_output)

    if build.returncode == 0:
        print("[+] Build completed.")
    else:
        print("[!] Build failed.")

    if artifacts:
        print("[*] Build artifact candidates:")
        for artifact in artifacts[-5:]:
            print(f"    {artifact}")
    else:
        print(f"[*] Expected Debug output directory: {DEFAULT_DEBUG_OUTDIR}")

    if lines:
        print("[*] Build output tail:")
        for line in lines[-25:]:
            print(f"    {line}")


def deploy_artifact(build_output: str, deploy_to: str | None) -> None:
    if not deploy_to:
        print("[*] Deploy step skipped; use --deploy-to PATH to copy the built exe somewhere.")
        return

    artifacts = find_build_artifacts(build_output)
    if not artifacts:
        print("[!] No build artifact found to deploy.")
        return

    source = Path(artifacts[-1])
    destination = Path(deploy_to)
    if not source.exists():
        print(f"[!] Build artifact does not exist: {source}")
        return

    try:
        if source.resolve() == destination.resolve():
            print(f"[*] Build artifact already at harness target: {destination}")
            return
    except OSError:
        pass

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        print(f"[*] Deployed build artifact to: {destination}")
    except OSError as exc:
        print(f"[!] Failed to deploy build artifact to {destination}: {exc}")


def run_harness(repo: Path, harness: Path, log_dir: Path, phase_seconds: int, extra_args: list[str]) -> subprocess.CompletedProcess:
    harness_args = add_default_harness_args(extra_args)
    command = [
        sys.executable,
        "-u",
        str(harness),
        "--phase-seconds",
        str(phase_seconds),
        "--log-dir",
        str(log_dir),
        *harness_args,
    ]
    return run_command(command, cwd=repo, timeout=phase_seconds + 120)


def run_harness_streaming(
    repo: Path,
    harness: Path,
    log_dir: Path,
    phase_seconds: int,
    extra_args: list[str],
    console_log: Path,
) -> subprocess.CompletedProcess:
    harness_args = add_default_harness_args(extra_args)
    command = [
        sys.executable,
        "-u",
        str(harness),
        "--phase-seconds",
        str(phase_seconds),
        "--log-dir",
        str(log_dir),
        *harness_args,
    ]
    output_parts: list[str] = []
    deadline = time.monotonic() + phase_seconds + 120
    log_dir.mkdir(parents=True, exist_ok=True)
    console_log.parent.mkdir(parents=True, exist_ok=True)

    print("[*] Harness command:")
    print("    " + " ".join(command))

    def stop_process(process: subprocess.Popen, grace_seconds: float = 5.0) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    with console_log.open("w", encoding="utf-8", errors="replace") as log_file:
        try:
            process = subprocess.Popen(
                command,
                cwd=str(repo),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except Exception as exc:
            error = f"[!] Failed to start harness process: {exc}\n"
            print(error, end="")
            log_file.write(error)
            return subprocess.CompletedProcess(command, 127, "", error)

        try:
            assert process.stdout is not None
            output_queue: Queue[str | None] = Queue()

            def read_output() -> None:
                try:
                    for line in process.stdout:
                        output_queue.put(line)
                finally:
                    output_queue.put(None)

            reader = threading.Thread(target=read_output, daemon=True)
            reader.start()
            reader_done = False

            while True:
                line = ""
                try:
                    item = output_queue.get(timeout=0.1)
                except Empty:
                    item = ""

                if item is None:
                    reader_done = True
                elif item:
                    line = item

                if line:
                    print(line, end="")
                    log_file.write(line)
                    log_file.flush()
                    output_parts.append(line)

                if process.poll() is not None and reader_done:
                    break

                if time.monotonic() > deadline:
                    stop_process(process)
                    timeout_line = "\n[!] Harness process exceeded phase timeout and was killed.\n"
                    print(timeout_line, end="")
                    log_file.write(timeout_line)
                    output_parts.append(timeout_line)
                    return subprocess.CompletedProcess(command, 124, "".join(output_parts), "")
        except KeyboardInterrupt:
            stop_process(process)
            interrupt_line = "\n[!] Harness interrupted; child process was stopped.\n"
            print(interrupt_line, end="")
            log_file.write(interrupt_line)
            output_parts.append(interrupt_line)
            return subprocess.CompletedProcess(command, 130, "".join(output_parts), "")
        finally:
            stop_process(process)

    return subprocess.CompletedProcess(command, process.returncode or 0, "".join(output_parts), "")


def add_default_harness_args(extra_args: list[str]) -> list[str]:
    args = list(extra_args)
    stage_option_present = any(arg in ("--stage-target", "--no-stage-target") for arg in args)
    if not stage_option_present:
        args.append("--stage-target")
    if "--boot-timeout" not in args:
        args.extend(["--boot-timeout", "90"])
    if "--winrm-status-interval" not in args:
        args.extend(["--winrm-status-interval", "5"])
    share_password = os.environ.get("HVERGELMIR_SHARE_PASSWORD") or os.environ.get("HVERGELMIR_SHARE_PASS")
    if share_password and "--share-password" not in args:
        args.extend(["--share-password", share_password])
    return args


def print_harness_summary(phase: subprocess.CompletedProcess, console_output: str, console_log: Path) -> None:
    print(f"[*] Harness exited with code {phase.returncode}")
    print(f"[*] Harness console log: {console_log}")

    lines = [line.rstrip() for line in console_output.splitlines() if line.strip()]
    if lines:
        print("[*] Harness output tail:")
        for line in lines[-40:]:
            print(f"    {line}")
    else:
        print("[!] Harness produced no console output.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI-assisted reliability tuning loop.")
    parser.add_argument("--repo", default=".")
    parser.add_argument("--harness", default=str(DEFAULT_HARNESS))
    parser.add_argument("--log-root", default=str(DEFAULT_LOG_ROOT))
    parser.add_argument("--phase-seconds", type=int, default=DEFAULT_PHASE_SECONDS)
    parser.add_argument("--max-iterations", type=int, default=20)
    parser.add_argument("--context-chars", type=int, default=DEFAULT_CONTEXT_CHARS)
    parser.add_argument("--model", default=os.environ.get("OPENAI_MODEL", DEFAULT_MODEL))
    parser.add_argument("--api-key-env", default="OPENAI_API_KEY")
    parser.add_argument("--build-command", default=None)
    parser.add_argument(
        "--deploy-to",
        default=DEFAULT_DEPLOY_TO,
        help="Optional path to copy the built exe to before running the harness.",
    )
    parser.add_argument("--skip-ai", action="store_true", help="Only run/build/report; do not call OpenAI.")
    parser.add_argument(
        "--harness-arg",
        action="append",
        default=[],
        help="Extra harness argument. Repeat for each token, e.g. --harness-arg --host --harness-arg 192.168.68.101",
    )
    args, passthrough = parser.parse_known_args()
    if passthrough and passthrough[0] == "--":
        passthrough = passthrough[1:]
    args.harness_arg.extend(passthrough)
    return args


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).resolve()
    harness = (repo / args.harness).resolve()
    log_root = (repo / args.log_root).resolve()
    log_root.mkdir(parents=True, exist_ok=True)

    api_key = os.environ.get(args.api_key_env)
    if not args.skip_ai and not api_key:
        print(f"[!] Missing API key. Set ${args.api_key_env}.")
        return 2

    build_output = ""
    for iteration in range(1, args.max_iterations + 1):
        print(f"\n[*] Iteration {iteration}/{args.max_iterations}: compiling")
        build = compile_project(repo, args.build_command)
        build_output = build.stdout + build.stderr
        (log_root / f"iteration-{iteration:02d}-build.log").write_text(
            build_output, encoding="utf-8", errors="replace"
        )
        print_build_summary(build, build_output)
        if build.returncode != 0:
            if args.skip_ai:
                return build.returncode
            phase_dir = log_root / f"iteration-{iteration:02d}-phase"
            phase_dir.mkdir(parents=True, exist_ok=True)
        else:
            deploy_artifact(build_output, args.deploy_to)
            phase_dir = log_root / f"iteration-{iteration:02d}-phase"
            print(f"[*] Iteration {iteration}: running {args.phase_seconds}s harness phase")
            print("[*] This is the exploit test phase. The harness should start/reset the VM and run the target exe now.")
            harness_log = log_root / f"iteration-{iteration:02d}-harness-console.log"
            phase = run_harness_streaming(
                repo,
                harness,
                phase_dir,
                args.phase_seconds,
                args.harness_arg,
                harness_log,
            )
            harness_output = phase.stdout + phase.stderr
            print_harness_summary(phase, harness_output, harness_log)

        summary = load_json(phase_dir / "summary.json")
        print(f"[*] Iteration {iteration}: {summarize_target(summary)}")
        if target_met(summary):
            print("[+] Target met.")
            return 0

        total_runs = metric_value(summary, ["total_runs"], 0) or 0
        if build.returncode == 0 and total_runs == 0:
            print("[!] The harness did not record any exploit runs, so no exploit reliability test occurred.")
            print("[!] Fix the harness/VM/WinRM/guest path first. The AI loop will not request exploit patches from zero-run data.")
            print(f"[*] Check harness logs in: {phase_dir}")
            return 3

        if args.skip_ai:
            print("[!] Target not met and --skip-ai was provided.")
            return 1

        print("[*] Asking OpenAI for a targeted patch")
        context = collect_context(repo, phase_dir, build_output, args.context_chars)
        prompt_preview = build_prompt_preview(context)
        (log_root / f"iteration-{iteration:02d}-full-context-prompt.md").write_text(
            prompt_preview, encoding="utf-8", errors="replace"
        )

        try:
            patch_text = clean_patch(call_openai(api_key, args.model, context))
        except ApiQuotaError as exc:
            print(f"[!] {exc}")
            print(
                "[*] Saved the full context prompt here: "
                f"{log_root / f'iteration-{iteration:02d}-full-context-prompt.md'}"
            )
            return 2
        except ApiRateLimitError as exc:
            print(f"[!] {exc}")
            patch_text = ""
            for retry, retry_chars in enumerate((35_000, 24_000, 16_000), start=1):
                print(f"[*] Retrying OpenAI request with context limited to {retry_chars} chars")
                retry_context = collect_context(repo, phase_dir, build_output, retry_chars)
                (log_root / f"iteration-{iteration:02d}-retry-{retry}-context-prompt.md").write_text(
                    build_prompt_preview(retry_context),
                    encoding="utf-8",
                    errors="replace",
                )
                try:
                    patch_text = clean_patch(call_openai(api_key, args.model, retry_context))
                    break
                except ApiRateLimitError:
                    continue
                except ApiQuotaError as quota_exc:
                    print(f"[!] {quota_exc}")
                    return 2

            if not patch_text:
                print("[!] OpenAI request still exceeded the token/rate limit after retries.")
                print(
                    "[*] Smallest prompt saved here: "
                    f"{log_root / f'iteration-{iteration:02d}-retry-3-context-prompt.md'}"
                )
                return 2

        print("[*] Model response:")
        print(patch_text)

        problem = patch_response_problem(patch_text)
        if problem:
            print(f"[!] Model patch response is not directly applyable: {problem}")
            try:
                patch_text = request_valid_repaired_patch(
                    api_key,
                    args.model,
                    repo,
                    log_root,
                    iteration,
                    phase_dir,
                    build_output,
                    args.context_chars,
                    problem,
                    patch_text,
                )
            except (ApiQuotaError, ApiRateLimitError) as exc:
                print(f"[!] Could not request repaired patch: {exc}")
                return 2
            print("[*] Repaired model response:")
            print(patch_text)

        (log_root / f"iteration-{iteration:02d}-proposal.patch").write_text(
            patch_text, encoding="utf-8"
        )

        print("[*] Applying proposed patch")
        applied = apply_patch(repo, patch_text)
        if applied.returncode != 0:
            print("[!] Patch failed to apply.")
            apply_error = (applied.stdout + applied.stderr)[-4000:]
            print(apply_error)

            try:
                repair_patch = request_valid_repaired_patch(
                    api_key,
                    args.model,
                    repo,
                    log_root,
                    iteration,
                    phase_dir,
                    build_output,
                    args.context_chars,
                    "Patch apply error:\n" + apply_error,
                    patch_text,
                )
            except (ApiQuotaError, ApiRateLimitError) as exc:
                print(f"[!] Could not request repaired patch: {exc}")
                return applied.returncode

            print("[*] Repaired model response:")
            print(repair_patch)
            (log_root / f"iteration-{iteration:02d}-repair-proposal.patch").write_text(
                repair_patch,
                encoding="utf-8",
            )

            print("[*] Applying repaired patch")
            repaired = apply_patch(repo, repair_patch)
            if repaired.returncode != 0:
                print("[!] Repaired patch also failed to apply.")
                print((repaired.stdout + repaired.stderr)[-4000:])
                return repaired.returncode

        time.sleep(1)

    print("[!] Reached max iterations without meeting target.")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
        raise SystemExit(130)
