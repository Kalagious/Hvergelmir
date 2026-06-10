
Use this prompt with a model that can return a unified diff patch.

Conversation and project history:

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
- The guest command is Z:\HvergelmirAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.exe.
- A run only counts as success if both output markers appear:
  [*] Full payload to trigger overflow:
  [*] Exploit completed successfully.
- The harness also tracks IoSB attempt lines matching:
  IoSB attempt <number> for capture <number>
- The harness records average/min/max runtime, runs per crash, total runs/crashes, average attempts to blue screen, and IoSB stats by run position within a boot.
- Previous reliability work found thread-name allocation strategy and leak reuse limits matter a lot.
- Existing logs showed around 95.45% success with successful run average around 8.569 seconds, with occasional long crash/disconnect/timeout behavior.
- The codebase currently uses config.h for tuning knobs. Prefer adding or adjusting knobs there over invasive rewrites.
- Avoid removing required output markers. They are used by the harness to classify success.
- Prefer small, testable changes that improve runtime without making the exploit less reliable.
- Do not produce prose when asked for a patch. The automation expects a unified diff only.


Goal:
- Success rate must be at least 97.0%.
- Average successful execution time must be under 2.0 seconds.

Instructions:
- Return only a unified diff patch.
- Keep changes small and targeted.
- Do not remove the required output markers:
  [*] Full payload to trigger overflow:
  [*] Exploit completed successfully.
- Prefer config knobs and low-risk timing/search improvements.
- Preserve existing APIs unless necessary.

Context:
Latest harness summary JSON:
{}

Latest live summary JSON:
{}

Recent run CSV tail:


Recent event log tail:


Latest build output:
MSBUILD : error MSB1009: Project file does not exist.
Switch: Hvergelmir.vcxproj

