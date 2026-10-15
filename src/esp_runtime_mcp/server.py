"""esp-runtime-mcp: the runtime half of an ESP-IDF agent loop.

The official `idf.py mcp-server` (ESP-IDF >= 6.0) covers set_target / build /
flash / clean. This server covers what happens *after* flashing: reading the
console, waiting for expected output, catching crashes, symbolising them
against the ELF, and reading core dumps.

Defaults follow ESP-IDF conventions: $ESPPORT / $ESPBAUD for the port, and
$ESP_RUNTIME_PROJECT_DIR (or the server's cwd, if it contains build/) for the
project whose ELF is used for symbolisation.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from . import coredump, decode, serial_io
from .panic import parse_log

INSTRUCTIONS = """\
Runtime tools for ESP-IDF devices. Typical loop with the official ESP-IDF MCP server:
  1. build_project / flash_project (idf.py mcp-server)
  2. capture_log(reset=true, expect=[...]) here: did it boot and reach the expected state?
  3. if `crashes` is non-empty: read the decoded backtrace, fix the code, go to 1.
Use analyze_log on logs pasted by the user (no hardware needed).
Use read_coredump when the panic backtrace is corrupted or the crash is in another task.
"""

mcp = MCPServer("esp-runtime", instructions=INSTRUCTIONS, version="0.1.0")

# Last captured log, so the agent can re-analyze without re-running the device.
_state: dict[str, str] = {}


# ------------------------------------------------------------------ helpers
def _port(port: str | None) -> str:
    p = port or os.environ.get("ESPPORT")
    if not p:
        raise ToolError("no port given and $ESPPORT is not set; call list_serial_ports first")
    return p


def _baud(baud: int | None) -> int:
    return baud or int(os.environ.get("ESPBAUD", "115200"))


def _project(project_dir: str | None) -> str | None:
    if project_dir:
        return project_dir
    if env := os.environ.get("ESP_RUNTIME_PROJECT_DIR"):
        return env
    return os.getcwd() if Path("build").is_dir() else None


def _try_elf(elf: str | None, project_dir: str | None) -> tuple[Path | None, str | None]:
    """Resolve the ELF if possible; a missing ELF downgrades analysis, it doesn't fail it."""
    proj = _project(project_dir)
    if not elf and not proj:
        return None, "no ELF/project given: backtraces are raw addresses"
    try:
        return decode.resolve_elf(elf, proj), None
    except decode.DecodeError as e:
        return None, str(e)


async def _analyze(text: str, elf: str | None, project_dir: str | None) -> dict:
    parsed = parse_log(text)
    elf_path, note = _try_elf(elf, project_dir)
    crashes = []
    for ev in parsed.events:
        item = ev.to_dict()
        addrs = ev.code_addresses()
        if elf_path and addrs:
            try:
                frames = await decode.decode_addresses(addrs, elf_path)
                item["decoded"] = decode.format_frames(frames)
                item["frames"] = [f.to_dict() for f in frames]
            except decode.DecodeError as e:
                item["decode_error"] = str(e)
        if ev.stack_candidates:
            item["stack_candidates_note"] = (
                "RISC-V prints no backtrace by default; these are code-range words found in the "
                "stack dump. Some may be stale. Enable CONFIG_ESP_SYSTEM_USE_EH_FRAME for real backtraces."
            )
            if elf_path:
                try:
                    cand = await decode.decode_addresses(ev.stack_candidates, elf_path)
                    item["stack_candidates_decoded"] = decode.format_frames([f for f in cand if f.resolved])
                except decode.DecodeError:
                    pass
        crashes.append(item)
    out = {"crashes": crashes, "reset_reasons": parsed.reset_reasons}
    if elf_path:
        out["elf"] = str(elf_path)
    if note:
        out["note"] = note
    return out


# -------------------------------------------------------------------- tools
@mcp.tool()
def list_serial_ports() -> list[dict]:
    """List serial ports; `likely_esp` marks Espressif USB, CP210x, CH340/CH9102 and FTDI bridges."""
    return serial_io.list_ports()


@mcp.tool()
async def capture_log(
    port: Annotated[str | None, Field(description="Serial port or URL (rfc2217://host:port). Default $ESPPORT")] = None,
    baud: Annotated[int | None, Field(description="Default $ESPBAUD or 115200")] = None,
    duration_s: Annotated[float, Field(gt=0, le=600, description="Maximum capture time")] = 5.0,
    expect: Annotated[list[str] | None, Field(description="Regexes that must appear IN ORDER; capture stops when all matched")] = None,
    reset: Annotated[bool, Field(description="Hard-reset via RTS/EN before capturing, to see boot")] = False,
    stop_on_panic: bool = True,
    tail_lines: Annotated[int, Field(ge=10, le=2000)] = 200,
    project_dir: Annotated[str | None, Field(description="ESP-IDF project for backtrace symbolisation")] = None,
    elf: str | None = None,
) -> dict:
    """Read the device console until all `expect` patterns match, a crash is caught, or time runs out.

    Crashes found in the log are parsed and symbolised automatically. Check `passed`:
    true only if every expect pattern matched and no crash was seen.
    """
    try:
        res = await serial_io.capture(_port(port), _baud(baud), duration_s, expect, stop_on_panic, reset)
    except serial_io.SerialToolError as e:
        raise ToolError(str(e)) from e
    full = "\n".join(res.lines)
    _state["last_log"] = full
    out = res.to_dict(tail=tail_lines)
    analysis = await _analyze(full, elf, project_dir)
    out.update(analysis)
    fatal = [c for c in analysis["crashes"] if c["kind"] != "task_wdt"]
    out["passed"] = all(e["matched"] for e in res.expect) and not fatal
    return out


@mcp.tool()
async def analyze_log(
    text: Annotated[str | None, Field(description="Raw console log. Omit to re-analyze the last capture")] = None,
    project_dir: str | None = None,
    elf: str | None = None,
) -> dict:
    """Find crashes (Guru Meditation, abort, assert, ESP_ERROR_CHECK, stack overflow, TWDT, heap
    corruption, brownout) and reset reasons in a log, and symbolise backtraces against the ELF."""
    if text is None:
        text = _state.get("last_log")
        if text is None:
            raise ToolError("no text given and nothing captured yet")
    return await _analyze(text, elf, project_dir)


_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{6,8}")


@mcp.tool()
async def decode_addresses(
    addresses: Annotated[str, Field(description="Any text containing hex addresses, e.g. a 'Backtrace:' line")],
    project_dir: str | None = None,
    elf: str | None = None,
) -> dict:
    """Symbolise code addresses (function, file:line, inlining) with the toolchain's addr2line.
    For a 'Backtrace: PC:SP PC:SP' line only the PCs are decoded."""
    if "Backtrace:" in addresses:
        addrs = [int(pc, 16) for pc, _ in re.findall(r"(0x[0-9a-fA-F]+):(0x[0-9a-fA-F]+)", addresses)]
    else:
        addrs = [int(a, 16) for a in _ADDR_RE.findall(addresses)]
    if not addrs:
        raise ToolError("no hex addresses found in input")
    try:
        elf_path = decode.resolve_elf(elf, _project(project_dir))
        frames = await decode.decode_addresses(addrs, elf_path)
    except decode.DecodeError as e:
        raise ToolError(str(e)) from e
    return {"elf": str(elf_path), "decoded": decode.format_frames(frames), "frames": [f.to_dict() for f in frames]}


@mcp.tool()
async def reset_device(port: str | None = None, baud: int | None = None) -> str:
    """Hard-reset the chip via the RTS->EN auto-reset circuit (app boot, not download mode)."""
    try:
        await serial_io.reset_device(_port(port), _baud(baud))
    except serial_io.SerialToolError as e:
        raise ToolError(str(e)) from e
    return "reset pulse sent"


@mcp.tool()
async def read_coredump(
    source: Annotated[str, Field(description="'flash' (needs port), 'file' (needs core_file) or 'last_capture' (UART core dump in the last captured log)")] = "flash",
    port: str | None = None,
    core_file: str | None = None,
    project_dir: str | None = None,
    elf: str | None = None,
) -> dict:
    """Run esp-coredump info_corefile and return the crashed task, its stack frames and the full report."""
    try:
        elf_path = decode.resolve_elf(elf, _project(project_dir))
    except decode.DecodeError as e:
        raise ToolError(str(e)) from e
    try:
        if source == "flash":
            return await coredump.read_coredump(elf_path, port=_port(port))
        if source == "file":
            return await coredump.read_coredump(elf_path, core_file=core_file)
        if source == "last_capture":
            b64 = coredump.extract_uart_coredump(_state.get("last_log", ""))
            if not b64:
                raise ToolError("no 'CORE DUMP START/END' block in the last capture "
                                "(is CONFIG_ESP_COREDUMP_ENABLE_TO_UART set?)")
            with tempfile.NamedTemporaryFile("w", suffix=".b64", delete=False) as f:
                f.write(b64)
            try:
                return await coredump.read_coredump(elf_path, core_file=f.name, core_format="b64")
            finally:
                os.unlink(f.name)
        raise ToolError(f"unknown source '{source}'")
    except coredump.CoredumpError as e:
        raise ToolError(str(e)) from e


def main() -> None:
    mcp.run("stdio")


if __name__ == "__main__":
    main()
