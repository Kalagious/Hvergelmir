#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from pathlib import PureWindowsPath

try:
    import winrm
except ImportError:
    winrm = None

DEFAULT_VM_NAME = "Win11"
DEFAULT_VM_UUID = "6508b006-bfda-4635-926e-2a73b4d304d3"
DEFAULT_HOST = "192.168.68.101"
DEFAULT_USER = "test"
DEFAULT_PASSWORD = "test"
DEFAULT_EXE = r"Z:\HvergelmirAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.exe"
DEFAULT_WINRM_PORT = 5985
DEFAULT_PROXMOX_HOST = "192.168.68.100"
DEFAULT_PROXMOX_PORT = 8006
DEFAULT_PROXMOX_USER = "root@pam"
DEFAULT_PROXMOX_NODE = "proxmox"
DEFAULT_PROXMOX_VMID = "100"
DEFAULT_WINRM_STATUS_INTERVAL = 10
DEFAULT_CRASH_TIMEOUT = 10
DEFAULT_RUN_TIMEOUT = 60
DEFAULT_RESET_START_DELAY = 8
DEFAULT_SHARE_DRIVE = "Z:"
DEFAULT_SHARE_PATH = r"\\192.168.68.54\Users\Jordan\Documents\Drivers\DriverExploits\Hvergelmir\x64\Debug"
DEFAULT_SHARE_USER = "jordan"
DEFAULT_USE_UNC_TARGET = True
DEFAULT_STAGE_TARGET = True
FULL_PAYLOAD_MARKER = "[*] Full payload to trigger overflow:"
SUCCESS_MARKER = "[*] Exploit completed successfully."
IOSB_ATTEMPT_RE = re.compile(r"IoSB attempt (\d+) for capture (\d+)")


@dataclass
class RunResult:
    timestamp: str
    boot_index: int
    run_index: int
    runs_this_boot: int
    vm_state_before: str
    vm_state_after: str
    remote_ready_before: bool
    remote_ready_after: bool
    outcome: str
    exit_code: int | None
    duration_seconds: float
    saw_full_payload_marker: bool
    saw_success_marker: bool
    iosb_attempt_count: int
    iosb_attempt_average: float | None
    iosb_attempt_minimum: int | None
    iosb_attempt_maximum: int | None
    iosb_last_attempt: int | None
    iosb_last_capture: int | None
    stdout_tail: str
    stderr_tail: str
    note: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def tail_text(value: str, max_chars: int = 4000) -> str:
    value = value.replace("\r\n", "\n")
    if len(value) <= max_chars:
        return value
    return value[-max_chars:]


def ps_quote(value: str | None) -> str:
    return "'" + (value or "").replace("'", "''") + "'"


def run_local(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def analyze_run_output(stdout: str, stderr: str) -> dict:
    combined = f"{stdout}\n{stderr}"
    iosb_matches = [
        (int(match.group(1)), int(match.group(2)))
        for match in IOSB_ATTEMPT_RE.finditer(combined)
    ]
    iosb_attempts = [attempt for attempt, capture in iosb_matches]
    last_attempt, last_capture = iosb_matches[-1] if iosb_matches else (None, None)

    return {
        "saw_full_payload_marker": FULL_PAYLOAD_MARKER in combined,
        "saw_success_marker": SUCCESS_MARKER in combined,
        "iosb_attempt_count": len(iosb_attempts),
        "iosb_attempt_average": (
            round(sum(iosb_attempts) / len(iosb_attempts), 3) if iosb_attempts else None
        ),
        "iosb_attempt_minimum": min(iosb_attempts) if iosb_attempts else None,
        "iosb_attempt_maximum": max(iosb_attempts) if iosb_attempts else None,
        "iosb_last_attempt": last_attempt,
        "iosb_last_capture": last_capture,
    }


class VBox:
    def __init__(self, vboxmanage: str, vm_name: str, vm_uuid: str):
        self.vboxmanage = vboxmanage
        self.vm_name = vm_name
        self.vm_uuid = vm_uuid

    @property
    def vm_ref(self) -> str:
        return self.vm_uuid or self.vm_name

    def command(self, *args: str, timeout: int = 30) -> subprocess.CompletedProcess:
        return run_local([self.vboxmanage, *args], timeout=timeout)

    def state(self) -> str:
        result = self.command("showvminfo", self.vm_ref, "--machinereadable")
        if result.returncode != 0:
            return f"unknown: {tail_text(result.stderr, 300)}"

        for line in result.stdout.splitlines():
            if line.startswith("VMState="):
                return line.split("=", 1)[1].strip().strip('"')
        return "unknown"

    def wait_for_state(self, states: set[str], timeout_seconds: int = 60) -> str:
        deadline = time.monotonic() + timeout_seconds
        last_state = self.state()
        while time.monotonic() < deadline:
            last_state = self.state()
            if last_state in states:
                return last_state
            time.sleep(1)
        return last_state

    def start(self, headless: bool) -> None:
        state = self.state()
        if state == "running":
            return

        mode = "headless" if headless else "gui"
        error_text = ""
        for attempt in range(1, 7):
            result = self.command("startvm", self.vm_ref, "--type", mode, timeout=60)
            if result.returncode == 0:
                if self.wait_for_state({"running"}, timeout_seconds=45) == "running":
                    return
            error_text = f"{result.stdout}\n{result.stderr}"
            recoverable_lock = (
                "already locked by a session" in error_text
                or "VBOX_E_INVALID_OBJECT_STATE" in error_text
                or "being locked or unlocked" in error_text
                or "already running" in error_text
            )
            settled_state = self.wait_for_state({"running", "poweroff", "aborted"}, timeout_seconds=15)
            if settled_state == "running":
                return
            if not recoverable_lock and result.returncode != 0:
                break
            time.sleep(min(10, attempt * 2))

        raise RuntimeError(f"VBoxManage startvm failed: {error_text.strip()}")

    def reset(self, headless: bool, start_delay_seconds: int = DEFAULT_RESET_START_DELAY) -> None:
        state = self.state()
        if state == "running":
            self.command("controlvm", self.vm_ref, "reset", timeout=60)
            self.wait_for_state({"running"}, timeout_seconds=60)
            return

        if state not in ("poweroff", "aborted", "saved"):
            self.command("controlvm", self.vm_ref, "poweroff", timeout=60)
            self.wait_for_state({"poweroff", "aborted"}, timeout_seconds=60)

        if start_delay_seconds > 0:
            time.sleep(start_delay_seconds)
        self.start(headless=headless)


class Proxmox:
    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        password: str | None,
        token_id: str | None,
        token_secret: str | None,
        node: str | None,
        vmid: str | None,
        vm_name: str,
        verify_ssl: bool,
    ):
        self.base_url = f"https://{host}:{port}/api2/json"
        self.user = user
        self.password = password
        self.token_id = token_id
        self.token_secret = token_secret
        self.node = node
        self.vmid = vmid
        self.vm_name = vm_name
        self.verify_ssl = verify_ssl
        self.csrf_token = None
        self.cookie = None
        self.ssl_context = None if verify_ssl else ssl._create_unverified_context()
        self.headers = {}
        if not verify_ssl:
            os.environ.setdefault("PYTHONHTTPSVERIFY", "0")

        if token_id and token_secret:
            self.headers["Authorization"] = f"PVEAPIToken={user}!{token_id}={token_secret}"
        elif password:
            self.login_with_password()
        else:
            raise RuntimeError(
                "Proxmox credentials are required. Set PROXMOX_PASSWORD, or set "
                "PROXMOX_TOKEN_ID and PROXMOX_TOKEN_SECRET."
            )

        if not self.node or not self.vmid:
            self.discover_vm()

    def request(self, method: str, path: str, **kwargs) -> dict:
        headers = dict(self.headers)
        headers.update(kwargs.pop("headers", {}))
        if method.upper() != "GET" and self.csrf_token:
            headers["CSRFPreventionToken"] = self.csrf_token
        if self.cookie:
            headers["Cookie"] = self.cookie

        params = kwargs.pop("params", None)
        data = kwargs.pop("data", None)
        url = f"{self.base_url}{path}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"

        encoded_data = None
        if data is not None:
            encoded_data = urllib.parse.urlencode(data).encode("utf-8")
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif method.upper() != "GET":
            encoded_data = b""

        request = urllib.request.Request(
            url,
            data=encoded_data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=30, context=self.ssl_context) as response:
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Proxmox API {method} {path} failed: HTTP {exc.code}: {body}")
        return json.loads(body)

    def login_with_password(self) -> None:
        data = urllib.parse.urlencode(
            {"username": self.user, "password": self.password}
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/access/ticket",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30, context=self.ssl_context) as response:
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Proxmox login failed: HTTP {exc.code}: {body}")

        auth_data = json.loads(body)["data"]
        self.cookie = f"PVEAuthCookie={auth_data['ticket']}"
        self.csrf_token = auth_data["CSRFPreventionToken"]

    def discover_vm(self) -> None:
        resources = self.request("GET", "/cluster/resources", params={"type": "vm"})["data"]
        matches = [
            resource
            for resource in resources
            if str(resource.get("type")) == "qemu"
            and (
                (self.vmid and str(resource.get("vmid")) == str(self.vmid))
                or (resource.get("name") == self.vm_name)
            )
        ]
        if not matches:
            available = ", ".join(
                f"{resource.get('name', '<unnamed>')} vmid={resource.get('vmid')} node={resource.get('node')}"
                for resource in resources
                if str(resource.get("type")) == "qemu"
            )
            raise RuntimeError(
                f"Could not find Proxmox QEMU VM named '{self.vm_name}'. "
                "Pass --proxmox-node and --proxmox-vmid if discovery is not possible. "
                f"Available QEMU VMs: {available or '<none>'}"
            )

        match = matches[0]
        self.node = self.node or match.get("node")
        self.vmid = self.vmid or str(match.get("vmid"))

    def vm_path(self, suffix: str) -> str:
        return f"/nodes/{self.node}/qemu/{self.vmid}{suffix}"

    def state(self) -> str:
        try:
            data = self.request("GET", self.vm_path("/status/current"))["data"]
            return str(data.get("status", "unknown"))
        except Exception as exc:
            return f"unknown: {exc}"

    def wait_for_state(self, states: set[str], timeout_seconds: int = 60) -> str:
        deadline = time.monotonic() + timeout_seconds
        last_state = self.state()
        while time.monotonic() < deadline:
            last_state = self.state()
            if last_state in states:
                return last_state
            time.sleep(1)
        return last_state

    def start(self, headless: bool = True) -> None:
        if self.state() == "running":
            return

        last_error = ""
        for attempt in range(1, 7):
            try:
                self.request("POST", self.vm_path("/status/start"))
            except Exception as exc:
                last_error = repr(exc)
            state = self.wait_for_state({"running"}, timeout_seconds=45)
            if state == "running":
                return
            if not last_error:
                last_error = f"start attempt {attempt} ended with state={state}"
            time.sleep(min(10, attempt * 2))

        raise RuntimeError(f"Proxmox VM start failed after retries: {last_error}")

    def reset(self, headless: bool = True, start_delay_seconds: int = DEFAULT_RESET_START_DELAY) -> None:
        if self.state() == "running":
            self.request("POST", self.vm_path("/status/stop"))
            self.wait_for_state({"stopped"}, timeout_seconds=90)

        if start_delay_seconds > 0:
            time.sleep(start_delay_seconds)
        self.start(headless=headless)


class Guest:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int,
        transport: str,
        use_ssl: bool,
        server_cert_validation: str,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.transport = transport
        self.use_ssl = use_ssl
        self.server_cert_validation = server_cert_validation
        scheme = "https" if use_ssl else "http"
        self.endpoint = f"{scheme}://{host}:{port}/wsman"
        self.use_pywinrm = winrm is not None
        self.winrs = shutil.which("winrs")
        if not self.use_pywinrm and not self.winrs:
            raise RuntimeError("Missing pywinrm and winrs.exe; one is required for WinRM.")

    def session(self, read_timeout_seconds: int = 20, operation_timeout_seconds: int = 10):
        if not self.use_pywinrm:
            raise RuntimeError("pywinrm is not installed")
        return winrm.Session(
            self.endpoint,
            auth=(self.username, self.password),
            transport=self.transport,
            server_cert_validation=self.server_cert_validation,
            read_timeout_sec=read_timeout_seconds,
            operation_timeout_sec=operation_timeout_seconds,
        )

    def run_remote(self, command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                self.winrs,
                f"-r:{self.endpoint}",
                f"-u:{self.username}",
                f"-p:{self.password}",
                *command,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

    def can_connect_tcp(self, timeout_seconds: float = 2.0) -> tuple[bool, str]:
        try:
            with socket.create_connection((self.host, self.port), timeout=timeout_seconds):
                return True, "tcp connected"
        except OSError as exc:
            return False, repr(exc)

    def wait_ready(self, deadline_seconds: int, status_interval: int = DEFAULT_WINRM_STATUS_INTERVAL) -> tuple[bool, str]:
        deadline = time.monotonic() + deadline_seconds
        last_error = "WinRM readiness check did not run"
        next_status = time.monotonic()
        attempt = 0

        while time.monotonic() < deadline:
            attempt += 1
            tcp_ready, tcp_detail = self.can_connect_tcp()
            if not tcp_ready:
                last_error = f"TCP {self.host}:{self.port} failed: {tcp_detail}"
                now = time.monotonic()
                if now >= next_status:
                    remaining = max(0, int(deadline - now))
                    print(f" [*] WinRM wait attempt {attempt}: {last_error} ({remaining}s remaining)")
                    next_status = now + status_interval
                time.sleep(2)
                continue

            try:
                if self.use_pywinrm:
                    result = self.session(read_timeout_seconds=10, operation_timeout_seconds=5).run_cmd(
                        "cmd.exe", ["/c", "echo", "ready"]
                    )
                    stdout = result.std_out.decode("utf-8", errors="replace")
                    stderr = result.std_err.decode("utf-8", errors="replace")
                    if result.status_code == 0 and "ready" in stdout:
                        return True, f"ready after {attempt} attempt(s) using pywinrm"
                    last_error = (
                        f"pywinrm exit={result.status_code} "
                        f"stdout={tail_text(stdout, 500)!r} "
                        f"stderr={tail_text(stderr, 500)!r}"
                    )
                else:
                    result = self.run_remote(["cmd.exe", "/c", "echo", "ready"], timeout_seconds=5)
                    if result.returncode == 0 and "ready" in result.stdout:
                        return True, f"ready after {attempt} attempt(s) using winrs"
                    last_error = (
                        f"winrs exit={result.returncode} "
                        f"stdout={tail_text(result.stdout, 500)!r} "
                        f"stderr={tail_text(result.stderr, 500)!r}"
                    )
            except Exception as exc:
                last_error = repr(exc)

            now = time.monotonic()
            if now >= next_status:
                remaining = max(0, int(deadline - now))
                print(f" [*] WinRM wait attempt {attempt}: {last_error} ({remaining}s remaining)")
                next_status = now + status_interval

            time.sleep(2)
        return False, last_error

    def can_run_remote_command(self, read_timeout_seconds: int = 10, operation_timeout_seconds: int = 5) -> bool:
        try:
            if self.use_pywinrm:
                result = self.session(
                    read_timeout_seconds=read_timeout_seconds,
                    operation_timeout_seconds=operation_timeout_seconds,
                ).run_cmd(
                    "cmd.exe", ["/c", "echo", "ready"]
                )
                stdout = result.std_out.decode("utf-8", errors="replace")
                return result.status_code == 0 and "ready" in stdout
            result = self.run_remote(["cmd.exe", "/c", "echo", "ready"], timeout_seconds=read_timeout_seconds)
            return result.returncode == 0 and "ready" in result.stdout
        except Exception:
            return False

    def share_preamble(self, drive: str, share_path: str, username: str, password: str | None) -> str:
        if not drive or not share_path:
            return ""

        drive_name = drive.rstrip("\\/").rstrip(":")
        if not drive_name:
            return ""

        if not password:
            return "$harnessShareError='share password is missing';Write-Output 'HARNESS_SHARE_ERROR=share password is missing';"

        ps = (
            f"$shareDrive={ps_quote(drive_name)};"
            f"$shareRoot={ps_quote(share_path)};"
            f"$shareUser={ps_quote(username)};"
            f"$sharePass={ps_quote(password)};"
            "$harnessShareError=$null;"
            "$harnessShareMapped=$false;"
            "try {"
            "  Remove-PSDrive -Name $shareDrive -Force -ErrorAction SilentlyContinue;"
            "  $securePass=ConvertTo-SecureString $sharePass -AsPlainText -Force;"
            "  $cred=New-Object System.Management.Automation.PSCredential($shareUser,$securePass);"
            "  New-PSDrive -Name $shareDrive -PSProvider FileSystem -Root $shareRoot -Credential $cred -ErrorAction Stop | Out-Null;"
            "  $harnessShareMapped=$true;"
            "  Write-Output ('HARNESS_SHARE_READY=' + $shareDrive + ':');"
            "} catch {"
            "  $harnessShareError=$_.Exception.Message;"
            "  Write-Output ('HARNESS_SHARE_ERROR=' + $_.Exception.Message);"
            "}"
        )
        return ps

    def share_cleanup(self, drive: str, share_path: str) -> str:
        if not drive or not share_path:
            return ""

        return (
            "if ($harnessShareMapped) {"
            "  Remove-PSDrive -Name $shareDrive -Force -ErrorAction SilentlyContinue;"
            "}"
        )

    def check_path(
        self,
        path: str,
        share_drive: str = "",
        share_path: str = "",
        share_user: str = "",
        share_password: str | None = None,
    ) -> tuple[bool, str]:
        ps = (
            self.share_preamble(share_drive, share_path, share_user, share_password)
            + f"$p={ps_quote(path)};"
            "Write-Output ('HARNESS_PATH=' + $p);"
            "Write-Output ('HARNESS_TEST_PATH=' + (Test-Path -LiteralPath $p));"
            "try {"
            "  $item=Get-Item -LiteralPath $p -ErrorAction Stop;"
            "  Write-Output ('HARNESS_ITEM=' + $item.FullName);"
            "  Write-Output ('HARNESS_LENGTH=' + $item.Length);"
            "} catch {"
            "  Write-Output ('HARNESS_PATH_ERROR=' + $_.Exception.Message);"
            "}"
            + self.share_cleanup(share_drive, share_path)
        )
        try:
            if self.use_pywinrm:
                result = self.session(read_timeout_seconds=20, operation_timeout_seconds=10).run_ps(ps)
                out = result.std_out.decode("utf-8", errors="replace")
                err = result.std_err.decode("utf-8", errors="replace")
                return "HARNESS_TEST_PATH=True" in out, tail_text(out + err, 1500)

            encoded = base64.b64encode(ps.encode("utf-16le")).decode("ascii")
            result = self.run_remote(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
                timeout_seconds=20,
            )
            return "HARNESS_TEST_PATH=True" in result.stdout, tail_text(result.stdout + result.stderr, 1500)
        except Exception as exc:
            return False, repr(exc)

    def map_share(self, drive: str, share_path: str, username: str, password: str) -> tuple[bool, str]:
        if not drive or not share_path:
            return True, "share mapping not configured"
        if not password:
            return False, "share password is missing"

        drive = drive.rstrip("\\")
        delete_args = ["use", drive, "/delete", "/y"]
        map_args = ["use", drive, share_path, password, f"/user:{username}", "/persistent:no"]

        try:
            if self.use_pywinrm:
                delete_result = self.session(read_timeout_seconds=15, operation_timeout_seconds=10).run_cmd(
                    "net.exe", delete_args
                )
                map_result = self.session(read_timeout_seconds=30, operation_timeout_seconds=15).run_cmd(
                    "net.exe", map_args
                )
                out = (
                    delete_result.std_out.decode("utf-8", errors="replace")
                    + delete_result.std_err.decode("utf-8", errors="replace")
                    + map_result.std_out.decode("utf-8", errors="replace")
                    + map_result.std_err.decode("utf-8", errors="replace")
                )
                return map_result.status_code == 0, tail_text(out, 2000)

            delete_result = self.run_remote(["net.exe", *delete_args], timeout_seconds=15)
            map_result = self.run_remote(["net.exe", *map_args], timeout_seconds=30)
            out = delete_result.stdout + delete_result.stderr + map_result.stdout + map_result.stderr
            return map_result.returncode == 0, tail_text(out, 2000)
        except Exception as exc:
            return False, repr(exc)

    def stage_exe(
        self,
        source_path: str,
        share_drive: str = "",
        share_path: str = "",
        share_user: str = "",
        share_password: str | None = None,
    ) -> tuple[bool, str, str]:
        ps = (
            "$ErrorActionPreference='Stop';"
            + self.share_preamble(share_drive, share_path, share_user, share_password)
            + f"$source={ps_quote(source_path)};"
            "if ($harnessShareError) { exit 125; }"
            "try {"
            "$stageDir=Join-Path $env:TEMP 'hvergelmir-harness';"
            "New-Item -ItemType Directory -Path $stageDir -Force | Out-Null;"
            "$dest=Join-Path $stageDir ([System.IO.Path]::GetFileName($source));"
            "Copy-Item -LiteralPath $source -Destination $dest -Force;"
            "try { Unblock-File -LiteralPath $dest -ErrorAction SilentlyContinue } catch {}"
            "$item=Get-Item -LiteralPath $dest -ErrorAction Stop;"
            "Write-Output ('HARNESS_STAGE_PATH=' + $item.FullName);"
            "Write-Output ('HARNESS_STAGE_LENGTH=' + $item.Length);"
            "} finally {"
            + self.share_cleanup(share_drive, share_path)
            + "}"
        )
        try:
            if self.use_pywinrm:
                result = self.session(read_timeout_seconds=60, operation_timeout_seconds=45).run_ps(ps)
                out = result.std_out.decode("utf-8", errors="replace")
                err = result.std_err.decode("utf-8", errors="replace")
                if result.status_code != 0:
                    return False, "", tail_text(out + err, 2000)
            else:
                encoded = base64.b64encode(ps.encode("utf-16le")).decode("ascii")
                result = self.run_remote(
                    ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
                    timeout_seconds=60,
                )
                out = result.stdout
                err = result.stderr
                if result.returncode != 0:
                    return False, "", tail_text(out + err, 2000)

            stage_match = re.search(r"HARNESS_STAGE_PATH=(.+)", out)
            if not stage_match:
                return False, "", tail_text(out + err, 2000)
            return True, stage_match.group(1).strip(), tail_text(out + err, 2000)
        except Exception as exc:
            return False, "", repr(exc)

    def run_exe(
        self,
        exe_path: str,
        timeout_seconds: int,
        crash_timeout_seconds: int = DEFAULT_CRASH_TIMEOUT,
        share_drive: str = "",
        share_path: str = "",
        share_user: str = "",
        share_password: str | None = None,
    ) -> tuple[str, int | None, str, str, str]:
        ps = (
            "$ErrorActionPreference='Continue';"
            + self.share_preamble(share_drive, share_path, share_user, share_password)
            + f"$exe={ps_quote(exe_path)};"
            "if ($harnessShareError) { exit 125; }"
            "$stamp=[Guid]::NewGuid().ToString('N');"
            "$outPath=Join-Path $env:TEMP ('hvergelmir-' + $stamp + '.out.txt');"
            "$errPath=Join-Path $env:TEMP ('hvergelmir-' + $stamp + '.err.txt');"
            "$started=Get-Date;"
            "$p=$null;"
            "try {"
            "  $p=Start-Process -FilePath $exe -PassThru -WindowStyle Hidden "
            "  -RedirectStandardOutput $outPath -RedirectStandardError $errPath -ErrorAction Stop;"
            "} catch {"
            "  Write-Output ('HARNESS_LAUNCH_ERROR=' + $_.Exception.Message);"
            "  Remove-Item -LiteralPath $outPath,$errPath -Force -ErrorAction SilentlyContinue;"
            + self.share_cleanup(share_drive, share_path)
            + "  exit 125;"
            "}"
            f"if ($p.WaitForExit({timeout_seconds * 1000})) {{"
            "  $ended=Get-Date;"
            "  if (Test-Path $outPath) { Get-Content -LiteralPath $outPath -Raw }"
            "  if (Test-Path $errPath) { [Console]::Error.Write((Get-Content -LiteralPath $errPath -Raw)) }"
            "  Write-Output ('HARNESS_EXIT_CODE=' + $p.ExitCode);"
            "  Write-Output ('HARNESS_GUEST_SECONDS=' + [int](New-TimeSpan -Start $started -End $ended).TotalSeconds);"
            "  Remove-Item -LiteralPath $outPath,$errPath -Force -ErrorAction SilentlyContinue;"
            + self.share_cleanup(share_drive, share_path)
            +
            "  exit $p.ExitCode;"
            "} else {"
            "  Write-Output 'HARNESS_TIMEOUT=1';"
            "  try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}"
            "  if (Test-Path $outPath) { Get-Content -LiteralPath $outPath -Raw }"
            "  if (Test-Path $errPath) { [Console]::Error.Write((Get-Content -LiteralPath $errPath -Raw)) }"
            "  Remove-Item -LiteralPath $outPath,$errPath -Force -ErrorAction SilentlyContinue;"
            + self.share_cleanup(share_drive, share_path)
            +
            "  exit 124;"
            "}"
        )

        try:
            crash_timeout_seconds = max(2, crash_timeout_seconds)
            if self.use_pywinrm:
                operation_timeout_seconds = max(1, min(crash_timeout_seconds - 1, crash_timeout_seconds // 2))
                result = self.session(
                    read_timeout_seconds=crash_timeout_seconds,
                    operation_timeout_seconds=operation_timeout_seconds,
                ).run_ps(ps)
                exit_code = result.status_code
                out = result.std_out.decode("utf-8", errors="replace")
                err = result.std_err.decode("utf-8", errors="replace")
            else:
                encoded = base64.b64encode(ps.encode("utf-16le")).decode("ascii")
                result = self.run_remote(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-EncodedCommand",
                        encoded,
                    ],
                    timeout_seconds=crash_timeout_seconds,
                )
                exit_code = result.returncode
                out = result.stdout
                err = result.stderr
            if "HARNESS_TIMEOUT=1" in out or exit_code == 124:
                return (
                    "timeout",
                    exit_code,
                    out,
                    err,
                    f"Target did not exit within {timeout_seconds}s; killed hung process",
                )
            if exit_code == 125:
                if "HARNESS_SHARE_ERROR=" in out:
                    return ("failure", exit_code, out, err, "Guest share mapping failed before launch")
                if "HARNESS_LAUNCH_ERROR=" in out:
                    return ("failure", exit_code, out, err, "Guest failed to launch target process")
                return ("failure", exit_code, out, err, "Guest harness failed before target launch")

            output_info = analyze_run_output(out, err)
            missing_markers = []
            if not output_info["saw_full_payload_marker"]:
                missing_markers.append(FULL_PAYLOAD_MARKER)
            if not output_info["saw_success_marker"]:
                missing_markers.append(SUCCESS_MARKER)
            if exit_code == 0 and not missing_markers:
                return ("success", exit_code, out, err, "")
            if exit_code == 0 and missing_markers:
                return (
                    "failure",
                    exit_code,
                    out,
                    err,
                    "Missing required success marker(s): " + ", ".join(missing_markers),
                )
            return ("failure", exit_code, out, err, "Process returned a non-zero exit code")
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or ""
            err = exc.stderr or ""
            return (
                "crash_or_disconnect",
                None,
                out,
                err,
                f"WinRM stopped responding for {crash_timeout_seconds}s during target run; assuming guest crash",
            )
        except Exception as exc:
            return (
                "crash_or_disconnect",
                None,
                "",
                "",
                f"WinRM disconnected during target run; assuming guest crash: {exc!r}",
            )

    def taskkill(self, image_name: str) -> None:
        try:
            if self.use_pywinrm:
                self.session(read_timeout_seconds=10, operation_timeout_seconds=5).run_cmd(
                    "taskkill.exe", ["/IM", image_name, "/F"]
                )
            else:
                self.run_remote(["taskkill.exe", "/IM", image_name, "/F"], timeout_seconds=10)
        except Exception:
            pass


class Recorder:
    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = self.log_dir / "runs.jsonl"
        self.events_path = self.log_dir / "events.jsonl"
        self.csv_path = self.log_dir / "runs.csv"
        self.summary_path = self.log_dir / "summary.json"
        self.live_summary_path = self.log_dir / "live-summary.json"
        self.csv_file = self.csv_path.open("a", newline="", encoding="utf-8")
        self.csv_writer = None

    def close(self) -> None:
        self.csv_file.close()

    def record(self, result: RunResult) -> None:
        row = asdict(result)
        with self.jsonl_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(row, sort_keys=True) + "\n")
            file.flush()
            os.fsync(file.fileno())

        if self.csv_writer is None:
            exists = self.csv_path.exists() and self.csv_path.stat().st_size > 0
            self.csv_writer = csv.DictWriter(self.csv_file, fieldnames=list(row.keys()))
            if not exists:
                self.csv_writer.writeheader()

        self.csv_writer.writerow(row)
        self.csv_file.flush()
        os.fsync(self.csv_file.fileno())

    def event(self, event_type: str, **values) -> None:
        row = {"timestamp": utc_now(), "event": event_type, **values}
        with self.events_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(row, sort_keys=True) + "\n")
            file.flush()
            os.fsync(file.fileno())

    def write_summary(self, summary: dict) -> None:
        self.write_json_atomic(self.summary_path, summary)

    def write_live_summary(self, summary: dict, last_event: str, **values) -> None:
        live_summary = {
            "last_updated": utc_now(),
            "last_event": last_event,
            **values,
            "summary": summary,
        }
        self.write_json_atomic(self.live_summary_path, live_summary)

    def write_json_atomic(self, path: Path, value: dict) -> None:
        temp_path = path.with_suffix(path.suffix + ".tmp")
        with temp_path.open("w", encoding="utf-8") as file:
            json.dump(value, file, indent=2, sort_keys=True)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        temp_path.replace(path)


def find_vboxmanage(explicit: str | None) -> str:
    if explicit:
        return explicit

    found = shutil.which("VBoxManage")
    if found:
        return found

    candidates = [
        r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
        r"C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate

    raise RuntimeError("Could not find VBoxManage.exe. Pass --vboxmanage PATH.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Hvergelmir inside a Windows VM and measure per-boot reliability."
    )
    parser.add_argument("--vm-provider", default="proxmox", choices=("proxmox", "vbox"))
    parser.add_argument("--vm-name", default=DEFAULT_VM_NAME)
    parser.add_argument("--vm-uuid", default=DEFAULT_VM_UUID)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--user", default=DEFAULT_USER)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--port", type=int, default=DEFAULT_WINRM_PORT)
    parser.add_argument("--winrm-transport", default="ntlm")
    parser.add_argument("--winrm-ssl", action="store_true")
    parser.add_argument("--winrm-cert-validation", default="ignore", choices=("ignore", "validate"))
    parser.add_argument("--exe", default=DEFAULT_EXE)
    parser.add_argument("--share-drive", default=DEFAULT_SHARE_DRIVE)
    parser.add_argument("--share-path", default=DEFAULT_SHARE_PATH)
    parser.add_argument("--share-user", default=os.environ.get("HVERGELMIR_SHARE_USER", DEFAULT_SHARE_USER))
    parser.add_argument("--share-password", default=os.environ.get("HVERGELMIR_SHARE_PASSWORD"))
    parser.add_argument(
        "--stage-target",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_STAGE_TARGET,
        help="Copy the target exe to the guest temp folder once per boot and run that local copy.",
    )
    parser.add_argument("--vboxmanage", default=None)
    parser.add_argument("--proxmox-host", default=DEFAULT_PROXMOX_HOST)
    parser.add_argument("--proxmox-port", type=int, default=DEFAULT_PROXMOX_PORT)
    parser.add_argument("--proxmox-user", default=os.environ.get("PROXMOX_USER", DEFAULT_PROXMOX_USER))
    parser.add_argument("--proxmox-password", default=os.environ.get("PROXMOX_PASSWORD"))
    parser.add_argument("--proxmox-token-id", default=os.environ.get("PROXMOX_TOKEN_ID"))
    parser.add_argument("--proxmox-token-secret", default=os.environ.get("PROXMOX_TOKEN_SECRET"))
    parser.add_argument("--proxmox-node", default=os.environ.get("PROXMOX_NODE", DEFAULT_PROXMOX_NODE))
    parser.add_argument("--proxmox-vmid", default=os.environ.get("PROXMOX_VMID", DEFAULT_PROXMOX_VMID))
    parser.add_argument("--proxmox-verify-ssl", action="store_true")
    parser.add_argument("--log-dir", default="harness-logs")
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--max-boots", type=int, default=100)
    parser.add_argument("--max-runs", type=int, default=0, help="0 means no total run limit.")
    parser.add_argument("--phase-seconds", type=int, default=0, help="0 means no time limit.")
    parser.add_argument(
        "--run-timeout",
        type=int,
        default=DEFAULT_RUN_TIMEOUT,
        help="Seconds to wait for the target process before killing it and continuing.",
    )
    parser.add_argument(
        "--crash-timeout",
        type=int,
        default=DEFAULT_CRASH_TIMEOUT,
        help="Seconds to wait for WinRM during a target run before assuming the guest crashed.",
    )
    parser.add_argument("--boot-timeout", type=int, default=1900)
    parser.add_argument("--winrm-status-interval", type=int, default=DEFAULT_WINRM_STATUS_INTERVAL)
    parser.add_argument(
        "--reset-start-delay",
        type=int,
        default=DEFAULT_RESET_START_DELAY,
        help="Seconds to wait after a crash/stop settles before starting the VM again.",
    )
    parser.add_argument("--reboot-settle", type=int, default=8)
    parser.add_argument("--stop-on-first-failure", action="store_true")
    return parser.parse_args()


def build_summary(results: list[RunResult], boot_crashes: int) -> dict:
    total = len(results)
    successes = sum(1 for result in results if result.outcome == "success")
    timeouts = sum(1 for result in results if result.outcome == "timeout")
    failures = sum(1 for result in results if result.outcome == "failure")
    disconnects = sum(1 for result in results if result.outcome == "crash_or_disconnect")
    crash_runs = timeouts + disconnects
    success_rate = (successes / total * 100.0) if total else 0.0
    crash_rate = (crash_runs / total * 100.0) if total else 0.0
    runs_per_crash = (total / boot_crashes) if boot_crashes else None

    durations = [result.duration_seconds for result in results]
    successful_durations = [
        result.duration_seconds for result in results if result.outcome == "success"
    ]
    attempts_to_bluescreen = [
        result.runs_this_boot for result in results if result.outcome == "crash_or_disconnect"
    ]
    iosb_averages = [
        result.iosb_attempt_average
        for result in results
        if result.iosb_attempt_average is not None
    ]
    iosb_maximums = [
        result.iosb_attempt_maximum
        for result in results
        if result.iosb_attempt_maximum is not None
    ]

    def numeric_stats(values: list[float] | list[int]) -> dict:
        if not values:
            return {
                "average": None,
                "minimum": None,
                "maximum": None,
            }

        return {
            "average": round(sum(values) / len(values), 3),
            "minimum": min(values),
            "maximum": max(values),
        }

    per_boot: dict[str, dict] = {}
    iosb_by_run_number: dict[str, list[float]] = {}
    for result in results:
        key = str(result.boot_index)
        stats = per_boot.setdefault(
            key,
            {
                "runs": 0,
                "successes": 0,
                "timeouts": 0,
                "failures": 0,
                "crash_or_disconnects": 0,
                "iosb_attempt_averages": [],
                "iosb_attempt_average": None,
                "iosb_attempt_minimum": None,
                "iosb_attempt_maximum": None,
            },
        )
        stats["runs"] += 1
        if result.outcome == "success":
            stats["successes"] += 1
        elif result.outcome == "timeout":
            stats["timeouts"] += 1
        elif result.outcome == "failure":
            stats["failures"] += 1
        elif result.outcome == "crash_or_disconnect":
            stats["crash_or_disconnects"] += 1

        if result.iosb_attempt_average is not None:
            stats["iosb_attempt_averages"].append(result.iosb_attempt_average)
            iosb_by_run_number.setdefault(str(result.runs_this_boot), []).append(
                result.iosb_attempt_average
            )

    for stats in per_boot.values():
        iosb_values = stats["iosb_attempt_averages"]
        iosb_stats = numeric_stats(iosb_values)
        stats["iosb_attempt_average"] = iosb_stats["average"]
        stats["iosb_attempt_minimum"] = iosb_stats["minimum"]
        stats["iosb_attempt_maximum"] = iosb_stats["maximum"]

    iosb_by_run_position = {
        run_number: {
            "samples": len(values),
            **numeric_stats(values),
        }
        for run_number, values in sorted(
            iosb_by_run_number.items(),
            key=lambda item: int(item[0]),
        )
    }

    return {
        "generated_at": utc_now(),
        "total_runs": total,
        "successful_runs": successes,
        "timeout_runs": timeouts,
        "failed_runs": failures,
        "crash_or_disconnect_runs": disconnects,
        "boot_crashes": boot_crashes,
        "total_crashes": boot_crashes,
        "runs_per_crash": round(runs_per_crash, 3) if runs_per_crash is not None else None,
        "success_rate_percent": round(success_rate, 2),
        "crash_or_timeout_rate_percent": round(crash_rate, 2),
        "run_time_seconds": numeric_stats(durations),
        "successful_run_time_seconds": numeric_stats(successful_durations),
        "attempts_to_bluescreen": numeric_stats(attempts_to_bluescreen),
        "iosb_attempt_average_per_run": numeric_stats(iosb_averages),
        "iosb_attempt_maximum_per_run": numeric_stats(iosb_maximums),
        "iosb_by_run_position_within_boot": iosb_by_run_position,
        "per_boot": per_boot,
    }


def seconds_text(value) -> str:
    if value is None:
        return "None"
    return f"{value}s"


def main() -> int:
    args = parse_args()
    if args.vm_provider == "proxmox":
        vm = Proxmox(
            args.proxmox_host,
            args.proxmox_port,
            args.proxmox_user,
            args.proxmox_password,
            args.proxmox_token_id,
            args.proxmox_token_secret,
            args.proxmox_node,
            args.proxmox_vmid,
            args.vm_name,
            args.proxmox_verify_ssl,
        )
    else:
        vboxmanage = find_vboxmanage(args.vboxmanage)
        vm = VBox(vboxmanage, args.vm_name, args.vm_uuid)

    guest = Guest(
        args.host,
        args.user,
        args.password,
        args.port,
        args.winrm_transport,
        args.winrm_ssl,
        args.winrm_cert_validation,
    )
    recorder = Recorder(Path(args.log_dir))

    results: list[RunResult] = []
    boot_crashes = 0
    total_runs = 0
    phase_deadline = time.monotonic() + args.phase_seconds if args.phase_seconds else None

    def phase_remaining() -> int | None:
        if phase_deadline is None:
            return None
        return max(0, int(phase_deadline - time.monotonic()))

    def phase_expired() -> bool:
        remaining = phase_remaining()
        return remaining is not None and remaining <= 0

    def update_live_summary(last_event: str, **values) -> None:
        recorder.write_live_summary(
            build_summary(results, boot_crashes),
            last_event,
            total_runs=total_runs,
            boot_crashes=boot_crashes,
            **values,
        )

    print(f"[*] Logs: {recorder.log_dir.resolve()}")
    if args.vm_provider == "proxmox":
        print(
            f"[*] VM: {args.vm_name} via Proxmox "
            f"{args.proxmox_host}:{args.proxmox_port} "
            f"node={vm.node} vmid={vm.vmid}"
        )
    else:
        print(f"[*] VM: {args.vm_name} {{{args.vm_uuid}}} via VirtualBox")
    print(
        f"[*] Guest WinRM: {args.user}@{args.host}:{args.port} "
        f"transport={args.winrm_transport} client={'pywinrm' if guest.use_pywinrm else 'winrs'}"
    )
    print(f"[*] Target: {args.exe}")

    try:
        for boot_index in range(1, args.max_boots + 1):
            if phase_expired():
                recorder.event("phase_complete", boot_index=boot_index, total_runs=total_runs)
                update_live_summary("phase_complete", boot_index=boot_index)
                return 0

            print(f"\n[*] Boot {boot_index}/{args.max_boots}: starting VM")
            recorder.event("boot_start", boot_index=boot_index, vm_state=vm.state())
            update_live_summary("boot_start", boot_index=boot_index)
            vm.start(headless=args.headless)

            wait_seconds = args.boot_timeout
            remaining = phase_remaining()
            if remaining is not None:
                wait_seconds = min(wait_seconds, remaining)
            if wait_seconds <= 0:
                recorder.event("phase_complete", boot_index=boot_index, total_runs=total_runs)
                update_live_summary("phase_complete", boot_index=boot_index)
                return 0

            print(f"[*] Waiting for WinRM at {guest.endpoint} for up to {wait_seconds}s")
            winrm_ready, winrm_detail = guest.wait_ready(wait_seconds, args.winrm_status_interval)
            if winrm_ready:
                print(f"[+] WinRM connected: {args.user}@{args.host}:{args.port}")
                recorder.event(
                    "winrm_ready",
                    boot_index=boot_index,
                    endpoint=guest.endpoint,
                    detail=winrm_detail,
                )
                update_live_summary("winrm_ready", boot_index=boot_index)
            else:
                boot_crashes += 1
                print("[!] WinRM never became ready; resetting VM")
                print(f"[!] Last WinRM error: {winrm_detail}")
                recorder.event(
                    "boot_winrm_timeout",
                    boot_index=boot_index,
                    vm_state=vm.state(),
                    boot_timeout=wait_seconds,
                    endpoint=guest.endpoint,
                    error=winrm_detail,
                )
                update_live_summary("boot_winrm_timeout", boot_index=boot_index)
                vm.reset(headless=args.headless, start_delay_seconds=args.reset_start_delay)
                print(f"[*] VM state after reset/start request: {vm.state()}")
                time.sleep(args.reboot_settle)
                continue

            recorder.event("boot_ready", boot_index=boot_index, vm_state=vm.state())
            update_live_summary("boot_ready", boot_index=boot_index)

            target_exe = args.exe
            target_share_drive = args.share_drive
            target_share_path = args.share_path
            target_share_user = args.share_user
            target_share_password = args.share_password

            if args.share_drive and args.share_path and not args.stage_target:
                print(f"[*] Mapping {args.share_drive} to {args.share_path} for WinRM session")
                share_ok, share_detail = guest.map_share(
                    args.share_drive,
                    args.share_path,
                    args.share_user,
                    args.share_password,
                )
                if share_ok:
                    print(f"[+] Share mapped for WinRM session: {args.share_drive}")
                else:
                    print(f"[!] Failed to map share for WinRM session: {share_detail}")
                recorder.event(
                    "share_map",
                    boot_index=boot_index,
                    drive=args.share_drive,
                    path=args.share_path,
                    ok=share_ok,
                    detail=share_detail,
                )
                update_live_summary("share_map", boot_index=boot_index, share_map_ok=share_ok)

            path_ok, path_detail = guest.check_path(
                args.exe,
                args.share_drive,
                args.share_path,
                args.share_user,
                args.share_password,
            )
            if path_ok:
                print(f"[+] WinRM can see target executable: {args.exe}")
            else:
                print(f"[!] WinRM cannot see target executable: {args.exe}")
                print(f"[!] Target path check: {path_detail}")
            recorder.event(
                "target_path_check",
                boot_index=boot_index,
                path=args.exe,
                ok=path_ok,
                detail=path_detail,
            )
            update_live_summary("target_path_check", boot_index=boot_index, target_path_ok=path_ok)

            if args.stage_target and path_ok:
                print("[*] Staging target executable into guest temp for this boot")
                stage_ok, staged_path, stage_detail = guest.stage_exe(
                    args.exe,
                    args.share_drive,
                    args.share_path,
                    args.share_user,
                    args.share_password,
                )
                if stage_ok:
                    target_exe = staged_path
                    target_share_drive = ""
                    target_share_path = ""
                    target_share_user = ""
                    target_share_password = None
                    print(f"[+] Staged target executable: {target_exe}")
                else:
                    print("[!] Failed to stage target executable; falling back to original path")
                    print(f"[!] Stage detail: {stage_detail}")
                recorder.event(
                    "target_stage",
                    boot_index=boot_index,
                    source=args.exe,
                    staged_path=staged_path,
                    ok=stage_ok,
                    detail=stage_detail,
                )
                update_live_summary("target_stage", boot_index=boot_index, target_stage_ok=stage_ok)

            runs_this_boot = 0
            while True:
                if phase_expired():
                    recorder.event("phase_complete", boot_index=boot_index, total_runs=total_runs)
                    update_live_summary("phase_complete", boot_index=boot_index)
                    return 0

                if args.max_runs and total_runs >= args.max_runs:
                    return 0

                runs_this_boot += 1
                total_runs += 1
                state_before = vm.state()
                remote_ready_before = guest.can_run_remote_command()
                start = time.monotonic()

                print(f"[*] Boot {boot_index} run {runs_this_boot}: launching target")
                effective_run_timeout = args.run_timeout
                remaining = phase_remaining()
                if remaining is not None:
                    effective_run_timeout = min(effective_run_timeout, remaining)
                if effective_run_timeout <= 0:
                    recorder.event("phase_complete", boot_index=boot_index, total_runs=total_runs)
                    update_live_summary("phase_complete", boot_index=boot_index)
                    return 0

                outcome, exit_code, stdout, stderr, note = guest.run_exe(
                    target_exe,
                    effective_run_timeout,
                    args.crash_timeout,
                    target_share_drive,
                    target_share_path,
                    target_share_user,
                    target_share_password,
                )
                duration = time.monotonic() - start
                output_info = analyze_run_output(stdout, stderr)

                if outcome == "timeout":
                    guest.taskkill(PureWindowsPath(target_exe).name)

                time.sleep(1)
                state_after = vm.state()
                remote_ready_after = False
                if state_after == "running":
                    remote_ready_after = guest.can_run_remote_command(
                        read_timeout_seconds=5,
                        operation_timeout_seconds=3,
                    )
                    state_after = vm.state()

                if state_after != "running" or not remote_ready_after:
                    if outcome != "crash_or_disconnect":
                        note = (
                            (note + "; ") if note else ""
                        ) + "Guest health check failed after target run"
                    outcome = "crash_or_disconnect"

                result = RunResult(
                    timestamp=utc_now(),
                    boot_index=boot_index,
                    run_index=total_runs,
                    runs_this_boot=runs_this_boot,
                    vm_state_before=state_before,
                    vm_state_after=state_after,
                    remote_ready_before=remote_ready_before,
                    remote_ready_after=remote_ready_after,
                    outcome=outcome,
                    exit_code=exit_code,
                    duration_seconds=round(duration, 3),
                    saw_full_payload_marker=output_info["saw_full_payload_marker"],
                    saw_success_marker=output_info["saw_success_marker"],
                    iosb_attempt_count=output_info["iosb_attempt_count"],
                    iosb_attempt_average=output_info["iosb_attempt_average"],
                    iosb_attempt_minimum=output_info["iosb_attempt_minimum"],
                    iosb_attempt_maximum=output_info["iosb_attempt_maximum"],
                    iosb_last_attempt=output_info["iosb_last_attempt"],
                    iosb_last_capture=output_info["iosb_last_capture"],
                    stdout_tail=tail_text(stdout),
                    stderr_tail=tail_text(stderr),
                    note=note,
                )
                results.append(result)
                recorder.record(result)
                update_live_summary(
                    "run_recorded",
                    boot_index=boot_index,
                    run_index=total_runs,
                    runs_this_boot=runs_this_boot,
                    outcome=result.outcome,
                    remote_ready_after=result.remote_ready_after,
                    vm_state_after=result.vm_state_after,
                    iosb_attempt_average=result.iosb_attempt_average,
                    iosb_last_attempt=result.iosb_last_attempt,
                    iosb_last_capture=result.iosb_last_capture,
                )

                print(
                    f"    outcome={result.outcome} exit={result.exit_code} "
                    f"duration={result.duration_seconds}s "
                    f"iosb_avg={result.iosb_attempt_average} "
                    f"iosb_last={result.iosb_last_attempt} "
                    f"vm={result.vm_state_after} "
                    f"winrm_after={result.remote_ready_after}"
                )
                if result.outcome != "success":
                    if result.note:
                        print(f"    note={result.note}")
                    output_tail = tail_text((stdout or "") + (stderr or ""), 1200).strip()
                    if output_tail:
                        print("    output tail:")
                        for line in output_tail.splitlines()[-12:]:
                            print(f"      {line}")

                if result.outcome == "crash_or_disconnect":
                    boot_crashes += 1
                    print(f"[!] Boot {boot_index} ended after {runs_this_boot} run(s); hard stop/start VM")
                    recorder.event(
                        "boot_reset_after_run",
                        boot_index=boot_index,
                        runs_this_boot=runs_this_boot,
                        outcome=result.outcome,
                        vm_state=result.vm_state_after,
                    )
                    update_live_summary(
                        "boot_reset_after_run",
                        boot_index=boot_index,
                        runs_this_boot=runs_this_boot,
                        outcome=result.outcome,
                    )
                    vm.reset(headless=args.headless, start_delay_seconds=args.reset_start_delay)
                    print(f"[*] VM state after reset/start request: {vm.state()}")
                    time.sleep(args.reboot_settle)
                    break

                if args.stop_on_first_failure and result.outcome != "success":
                    return 1
    finally:
        summary = build_summary(results, boot_crashes)
        recorder.write_summary(summary)
        recorder.close()

        print("\n[*] Summary")
        print(f"    total runs: {summary['total_runs']}")
        print(f"    successful runs: {summary['successful_runs']}")
        print(f"    failed runs: {summary['failed_runs']}")
        print(f"    timeout runs: {summary['timeout_runs']}")
        print(f"    crash/disconnect runs: {summary['crash_or_disconnect_runs']}")
        print(f"    boot crashes: {summary['boot_crashes']}")
        print(f"    runs per crash: {summary['runs_per_crash']}")
        print(f"    avg run time: {seconds_text(summary['run_time_seconds']['average'])}")
        print(f"    min run time: {seconds_text(summary['run_time_seconds']['minimum'])}")
        print(f"    max run time: {seconds_text(summary['run_time_seconds']['maximum'])}")
        print(
            "    avg attempts to blue screen: "
            f"{summary['attempts_to_bluescreen']['average']}"
        )
        print(
            "    min/max attempts to blue screen: "
            f"{summary['attempts_to_bluescreen']['minimum']}/"
            f"{summary['attempts_to_bluescreen']['maximum']}"
        )
        print(
            "    avg IoSB attempt per run: "
            f"{summary['iosb_attempt_average_per_run']['average']}"
        )
        print(
            "    min/max avg IoSB attempt per run: "
            f"{summary['iosb_attempt_average_per_run']['minimum']}/"
            f"{summary['iosb_attempt_average_per_run']['maximum']}"
        )
        print(f"    success rate: {summary['success_rate_percent']}%")
        print(f"    crash/timeout rate: {summary['crash_or_timeout_rate_percent']}%")
        print(f"    summary: {recorder.summary_path.resolve()}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
        raise SystemExit(130)
