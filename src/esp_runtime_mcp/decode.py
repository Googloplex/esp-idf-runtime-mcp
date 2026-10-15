"""Symbolise code addresses against an ESP-IDF application ELF via addr2line.

Toolchain discovery order:
  1. explicit `tool` argument
  2. $ESP_RUNTIME_ADDR2LINE
  3. arch-specific Espressif binutils on PATH (exported by `. export.sh` / EIM)
  4. the same binaries under $IDF_TOOLS_PATH (default ~/.espressif/tools)
  5. llvm-addr2line (handles RISC-V; recent LLVM also handles Xtensa)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path

EM_XTENSA = 94
EM_RISCV = 243

ADDR2LINE_CANDIDATES = {
    "xtensa": [
        "xtensa-esp-elf-addr2line",  # unified toolchain, IDF >= 5.2
        "xtensa-esp32-elf-addr2line",
        "xtensa-esp32s3-elf-addr2line",
        "xtensa-esp32s2-elf-addr2line",
    ],
    "riscv": ["riscv32-esp-elf-addr2line"],
}
FALLBACK_TOOLS = ["llvm-addr2line"]


class DecodeError(RuntimeError):
    pass


@dataclass
class Frame:
    address: str
    function: str | None
    file: str | None
    line: int | None
    inlined_by: list[dict] = field(default_factory=list)

    @property
    def resolved(self) -> bool:
        return self.function is not None or self.file is not None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["resolved"] = self.resolved
        return d


# ---------------------------------------------------------------- ELF helpers
def elf_arch(path: Path) -> str:
    with open(path, "rb") as f:
        hdr = f.read(20)
    if len(hdr) < 20 or hdr[:4] != b"\x7fELF":
        raise DecodeError(f"{path} is not an ELF file")
    endian = "<" if hdr[5] == 1 else ">"
    (machine,) = struct.unpack(endian + "H", hdr[18:20])
    return {EM_XTENSA: "xtensa", EM_RISCV: "riscv"}.get(machine, f"em_{machine}")


def find_app_elf(project_dir: str | Path) -> Path:
    """Locate the application ELF of a built ESP-IDF project.

    Prefers build/project_description.json (authoritative, written by CMake);
    falls back to the newest non-bootloader *.elf in build/.
    """
    project = Path(project_dir).expanduser()
    build = project / "build"
    desc = build / "project_description.json"
    if desc.is_file():
        try:
            data = json.loads(desc.read_text())
            elf = Path(data.get("build_dir", build)) / data["app_elf"]
            if elf.is_file():
                return elf
        except (KeyError, ValueError, OSError):
            pass  # fall through to globbing
    elfs = [p for p in build.glob("*.elf") if "bootloader" not in p.name]
    if not elfs:
        raise DecodeError(f"no application ELF in {build}; build the project first (idf.py build)")
    return max(elfs, key=lambda p: p.stat().st_mtime)


def resolve_elf(elf: str | None, project_dir: str | None) -> Path:
    if elf:
        p = Path(elf).expanduser()
        if not p.is_file():
            raise DecodeError(f"ELF not found: {p}")
        return p
    if project_dir:
        return find_app_elf(project_dir)
    raise DecodeError("pass either `elf` or `project_dir`")


def find_addr2line(arch: str, tool: str | None = None) -> str:
    if tool:
        found = shutil.which(tool) or (tool if Path(tool).is_file() else None)
        if not found:
            raise DecodeError(f"addr2line tool not found: {tool}")
        return found
    if env := os.environ.get("ESP_RUNTIME_ADDR2LINE"):
        return find_addr2line(arch, env)

    names = ADDR2LINE_CANDIDATES.get(arch, [])
    for n in names:
        if p := shutil.which(n):
            return p
    tools_root = Path(os.environ.get("IDF_TOOLS_PATH", "~/.espressif")).expanduser() / "tools"
    for n in names:
        hits = sorted(tools_root.glob(f"*/*/*/bin/{n}"), reverse=True)  # newest version dir first
        if hits:
            return str(hits[0])
    for n in FALLBACK_TOOLS:
        if p := shutil.which(n):
            return p
    raise DecodeError(
        f"no addr2line for arch '{arch}'. Activate ESP-IDF (export.sh / eim run) "
        f"or set ESP_RUNTIME_ADDR2LINE. Tried: {', '.join(names + FALLBACK_TOOLS)}"
    )


# ------------------------------------------------------------- output parsing
# `addr2line -a -p -f -i -C` emits, per address:
#   0x400d2d48: app_main at /proj/main/main.c:23
#    (inlined by) helper at /proj/main/util.h:7
# and for unknown locations "?? ??:0" / "func at ??:?"
_HEAD_RE = re.compile(r"^(?P<addr>0x[0-9a-fA-F]+):\s+(?P<rest>.*)$")
_INL_RE = re.compile(r"^\s*\(inlined by\)\s+(?P<rest>.*)$")
_LOC_RE = re.compile(r"^(?P<func>.+?) at (?P<file>.+?):(?P<line>\d+|\?)(?: \(discriminator \d+\))?$")


def _split_loc(rest: str) -> tuple[str | None, str | None, int | None]:
    rest = rest.strip()
    if rest.startswith("??") and " at " not in rest:
        return None, None, None
    m = _LOC_RE.match(rest)
    if not m:
        return (rest or None), None, None
    func = None if m["func"] == "??" else m["func"]
    file = None if m["file"] == "??" else m["file"]
    line = int(m["line"]) if m["line"].isdigit() and m["line"] != "0" else None
    return func, file, line


def parse_addr2line_output(text: str) -> list[Frame]:
    frames: list[Frame] = []
    for raw in text.splitlines():
        if m := _HEAD_RE.match(raw):
            func, file, line = _split_loc(m["rest"])
            addr = int(m["addr"], 16)
            frames.append(Frame(f"0x{addr:08x}", func, file, line))
        elif (m := _INL_RE.match(raw)) and frames:
            func, file, line = _split_loc(m["rest"])
            frames[-1].inlined_by.append({"function": func, "file": file, "line": line})
    return frames


# ------------------------------------------------------------------- decoding
_cache: dict[tuple[str, float, int], Frame] = {}


async def decode_addresses(
    addresses: list[int],
    elf: Path,
    tool: str | None = None,
    timeout_s: float = 20.0,
) -> list[Frame]:
    """Return one Frame per input address, in input order.

    Results are cached per (ELF path, ELF mtime, address), so repeated crash
    analysis in a reboot loop costs one addr2line call.
    """
    if not addresses:
        return []
    mtime = elf.stat().st_mtime
    key = lambda a: (str(elf), mtime, a)  # noqa: E731
    todo = [a for a in dict.fromkeys(addresses) if key(a) not in _cache]

    if todo:
        exe = find_addr2line(elf_arch(elf), tool)
        proc = await asyncio.create_subprocess_exec(
            exe, "-a", "-p", "-f", "-i", "-C", "-e", str(elf), *[f"0x{a:x}" for a in todo],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout_s)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise DecodeError(f"addr2line timed out after {timeout_s}s") from None
        if proc.returncode != 0:
            raise DecodeError(f"addr2line failed ({proc.returncode}): {err.decode(errors='replace').strip()}")
        frames = parse_addr2line_output(out.decode(errors="replace"))
        if len(frames) != len(todo):
            raise DecodeError(f"addr2line returned {len(frames)} frames for {len(todo)} addresses")
        for a, fr in zip(todo, frames):
            _cache[key(a)] = fr

    return [_cache[key(a)] for a in addresses]


def format_frames(frames: list[Frame]) -> str:
    """Human/LLM-friendly one-line-per-frame rendering."""
    out = []
    for i, f in enumerate(frames):
        loc = f"{f.file}:{f.line}" if f.file else "??"
        out.append(f"#{i:<2} {f.address} {f.function or '??'} at {loc}")
        for inl in f.inlined_by:
            out.append(f"      inlined by {inl['function'] or '??'} at {inl['file'] or '??'}:{inl['line'] or '?'}")
    return "\n".join(out)
