"""Decoder tests.

The addr2line *output parser* is tested on canned text. The full subprocess
path is tested end-to-end on a host-compiled ELF with the host addr2line, so
CI needs no Espressif toolchain; the same code path runs with
xtensa-esp-elf-addr2line on a real project.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from esp_runtime_mcp import decode

CANNED = """\
0x400d2d48: sensor_read at /proj/main/sensor.c:57
0x400d1c27: helper at /proj/main/util.h:12
 (inlined by) app_main at /proj/main/main.c:23
0x400e2a3d: ?? ??:0
0x40081a6e: panic_abort at ??:?
"""


def test_parse_addr2line_output():
    fr = decode.parse_addr2line_output(CANNED)
    assert len(fr) == 4
    assert (fr[0].function, fr[0].file, fr[0].line) == ("sensor_read", "/proj/main/sensor.c", 57)
    assert fr[1].inlined_by == [{"function": "app_main", "file": "/proj/main/main.c", "line": 23}]
    assert not fr[2].resolved
    assert fr[3].function == "panic_abort" and fr[3].file is None


def test_elf_arch_detection(tmp_path):
    xt = tmp_path / "x.elf"
    xt.write_bytes(b"\x7fELF\x01\x01\x01" + b"\0" * 11 + (94).to_bytes(2, "little"))
    rv = tmp_path / "r.elf"
    rv.write_bytes(b"\x7fELF\x01\x01\x01" + b"\0" * 11 + (243).to_bytes(2, "little"))
    assert decode.elf_arch(xt) == "xtensa"
    assert decode.elf_arch(rv) == "riscv"
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"nope" * 10)
    with pytest.raises(decode.DecodeError):
        decode.elf_arch(bad)


def test_find_app_elf_prefers_project_description(tmp_path):
    build = tmp_path / "build"
    build.mkdir()
    (build / "bootloader.elf").write_bytes(b"x")
    (build / "app.elf").write_bytes(b"x")
    (build / "project_description.json").write_text(json.dumps({"build_dir": str(build), "app_elf": "app.elf"}))
    assert decode.find_app_elf(tmp_path).name == "app.elf"


def test_find_app_elf_missing_build_is_explicit(tmp_path):
    with pytest.raises(decode.DecodeError, match="idf.py build"):
        decode.find_app_elf(tmp_path)


C_SRC = r"""
static inline int __attribute__((always_inline)) deref(int *p) { return *p; }
int crash_here(int *p) {
    return deref(p) + 1;
}
int main(void) { return crash_here(0); }
"""


@pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("addr2line")), reason="host toolchain needed")
async def test_decode_end_to_end_with_host_elf(tmp_path):
    src = tmp_path / "t.c"
    src.write_text(C_SRC)
    elf = tmp_path / "t.elf"
    subprocess.run(["gcc", "-g", "-O1", "-o", str(elf), str(src)], check=True)
    nm = subprocess.run(["nm", str(elf)], capture_output=True, text=True, check=True).stdout
    addr = next(int(l.split()[0], 16) for l in nm.splitlines() if l.endswith(" crash_here"))

    frames = await decode.decode_addresses([addr, addr], elf, tool="addr2line")
    assert len(frames) == 2 and frames[0] is frames[1]  # dedup + cache
    assert frames[0].file.endswith("t.c")
    assert frames[0].function in ("crash_here", "deref")
    text = decode.format_frames(frames[:1])
    assert "t.c:" in text


async def test_decode_reports_missing_tool(tmp_path):
    elf = tmp_path / "x.elf"
    elf.write_bytes(b"\x7fELF\x01\x01\x01" + b"\0" * 11 + (94).to_bytes(2, "little"))
    with pytest.raises(decode.DecodeError, match="not found"):
        await decode.decode_addresses([0x400D0000], elf, tool="definitely-not-addr2line")
