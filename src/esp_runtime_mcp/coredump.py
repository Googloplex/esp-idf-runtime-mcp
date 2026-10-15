"""Thin async wrapper around Espressif's `esp-coredump` (pip: esp-coredump).

Reads a core dump either from the device flash partition (needs the port) or
from a file, and extracts the crashed-thread stack from the GDB-based report.
Requires the chip's GDB (xtensa-esp32-elf-gdb / riscv32-esp-elf-gdb) on PATH,
which an activated ESP-IDF environment provides.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import sys
from pathlib import Path

GDB_FRAME_RE = re.compile(r"^#(?P<n>\d+)\s+(?:(?P<addr>0x[0-9a-fA-F]+) in )?(?P<func>\S+) \(.*?\)(?: at (?P<loc>\S+))?")
CRASHED_TASK_RE = re.compile(r"Crashed task (?:handle|is): (?P<task>.+)", re.I)
CUR_STACK_HDR = "CURRENT THREAD STACK"
UART_START_RE = re.compile(r"=+ CORE DUMP START =+")
UART_END_RE = re.compile(r"=+ CORE DUMP END =+")
B64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")


class CoredumpError(RuntimeError):
    pass


def _cmd() -> list[str]:
    if exe := shutil.which("esp-coredump"):
        return [exe]
    return [sys.executable, "-m", "esp_coredump"]


def extract_uart_coredump(log: str) -> str | None:
    """Return the base64 body of the last core dump printed to UART, if any.

    With CONFIG_ESP_COREDUMP_ENABLE_TO_UART the panic handler prints the dump
    between START/END banners; returning the *last* one handles reboot loops.
    """
    found: str | None = None
    body: list[str] | None = None
    for line in log.splitlines():
        line = line.strip()
        if UART_START_RE.search(line):
            body = []
        elif UART_END_RE.search(line) and body is not None:
            found = "\n".join(body) if body else None
            body = None
        elif body is not None and line and B64_RE.match(line):
            body.append(line)
    return found


def summarize(report: str) -> dict:
    """Pull the crashed task and its stack frames out of `info_corefile` output."""
    task = None
    frames: list[dict] = []
    in_stack = False
    for line in report.splitlines():
        if task is None and (m := CRASHED_TASK_RE.search(line)):
            task = m["task"].strip()
        if CUR_STACK_HDR in line:
            in_stack = True
            continue
        if in_stack:
            if line.startswith("=") or (frames and not line.strip()):
                break
            if m := GDB_FRAME_RE.match(line.strip()):
                frames.append({k: v for k, v in m.groupdict().items() if v})
    return {"crashed_task": task, "frames": frames}


async def read_coredump(
    elf: Path,
    port: str | None = None,
    core_file: str | None = None,
    core_format: str = "auto",
    timeout_s: float = 120.0,
    max_chars: int = 20_000,
) -> dict:
    if bool(port) == bool(core_file):
        raise CoredumpError("pass exactly one of `port` (read from flash) or `core_file`")
    args = _cmd()
    if port:
        args += ["--port", port]
    args += ["info_corefile"]
    if core_file:
        if not Path(core_file).expanduser().is_file():
            raise CoredumpError(f"core file not found: {core_file}")
        args += ["--core", str(Path(core_file).expanduser()), "--core-format", core_format]
    args.append(str(elf))

    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout_s)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise CoredumpError(f"esp-coredump timed out after {timeout_s}s") from None
    text = out.decode(errors="replace")
    if proc.returncode != 0:
        if "No module named esp_coredump" in text:
            raise CoredumpError("esp-coredump is not installed: pip install esp-coredump (or activate ESP-IDF)")
        raise CoredumpError(f"esp-coredump failed ({proc.returncode}):\n{text[-3000:]}")

    truncated = len(text) > max_chars
    return {
        "summary": summarize(text),
        "report": text[:max_chars],
        "truncated": truncated,
    }
