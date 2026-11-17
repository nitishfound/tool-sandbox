"""Build a hardened `docker run` command for running agent commands in a throwaway container.

Process-level checks (allowlists, timeouts) reduce risk; a container adds a real wall:
the code can't reach the network, can't write outside a scratch dir, has no Linux
capabilities, can't gain privileges, and has CPU/memory/process limits.
"""

from __future__ import annotations

from pathlib import Path


def docker_argv(command: str, args: list[str], workspace: Path, image: str = "python:3.12-slim",
                memory: str = "256m", cpus: str = "0.5", pids: int = 64) -> list[str]:
    return [
        "docker", "run", "--rm",
        "--network", "none",                      # no internet, no internal network (stops exfiltration/SSRF)
        "--read-only",                            # root filesystem is read-only
        "--tmpfs", "/tmp:rw,size=64m,noexec",     # small scratch space, can't execute from it
        "--cap-drop", "ALL",                      # no Linux capabilities
        "--security-opt", "no-new-privileges",    # setuid binaries can't escalate
        "--pids-limit", str(pids),                # no fork bombs
        "--memory", memory, "--cpus", cpus,       # resource limits
        "--user", "65534:65534",                  # run as 'nobody', not root
        "-v", f"{Path(workspace).resolve()}:/work:ro",  # workspace mounted read-only
        "-w", "/work",
        image, command, *args,
    ]
