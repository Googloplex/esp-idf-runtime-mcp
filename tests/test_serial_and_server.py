"""Capture loop tests on pyserial's loop:// device (real pyserial read path,
no hardware), plus MCP-level tests through an in-memory client."""

import asyncio
import json
import threading
import time
from pathlib import Path

import pytest
import serial
from mcp.client.client import Client

from esp_runtime_mcp import serial_io, server

FX = Path(__file__).parent / "fixtures"


def streaming_opener(payload: bytes, chunk: int = 64, gap_s: float = 0.005):
    """Opener that returns a loop:// port and feeds `payload` into it in chunks,
    so line splitting across reads is exercised like on a real UART."""

    def opener(port: str, baud: int) -> serial.SerialBase:
        s = serial.serial_for_url("loop://", baudrate=baud, timeout=0.05)

        def feed():
            for i in range(0, len(payload), chunk):
                if not s.is_open:
                    return
                s.write(payload[i : i + chunk])
                time.sleep(gap_s)

        threading.Thread(target=feed, daemon=True).start()
        return s

    return opener


BOOT = (
    b"rst:0x1 (POWERON),boot:0x13 (SPI_FAST_FLASH_BOOT)\r\n"
    b"I (300) wifi: sta start\r\n"
    b"I (1200) wifi: connected, ip 192.168.1.42\r\n"
    b"I (1500) mqtt: subscribed\r\n"
    b"I (1600) app: idle\r\n"
)


async def test_expect_sequence_stops_early():
    res = await serial_io.capture(
        "fake", duration_s=5, expect=[r"connected, ip (\S+)", r"mqtt: subscribed"],
        opener=streaming_opener(BOOT),
    )
    assert res.stop_reason == "expect_complete"
    assert res.elapsed_s < 2
    assert all(e["matched"] for e in res.expect)
    assert "192.168.1.42" in res.expect[0]["line"]


async def test_expect_order_matters():
    res = await serial_io.capture(
        "fake", duration_s=0.5, expect=[r"mqtt: subscribed", r"wifi: sta start"],
        opener=streaming_opener(BOOT),
    )
    assert res.stop_reason == "timeout"
    assert [e["matched"] for e in res.expect] == [True, False]


async def test_panic_captures_backtrace_then_stops():
    payload = (FX / "xtensa_loadprohibited.log").read_bytes() + b"I (0) after: reboot noise\n" * 50
    res = await serial_io.capture("fake", duration_s=5, opener=streaming_opener(payload))
    assert res.stop_reason == "panic"
    assert "Guru Meditation" in res.panic_line
    log = "\n".join(res.lines)
    assert "Backtrace: 0x400d2d48" in log
    assert "after: reboot noise" not in log  # stopped at "Rebooting..."


async def test_ring_buffer_reports_dropped_lines():
    payload = b"".join(b"I (%d) spam: line\n" % i for i in range(500))
    res = await serial_io.capture("fake", duration_s=1, buffer_lines=100, opener=streaming_opener(payload, chunk=512))
    assert len(res.lines) == 100
    assert res.lines_dropped == res.lines_total - 100 > 0


async def test_same_port_is_locked():
    slow = streaming_opener(BOOT)
    t1 = asyncio.create_task(serial_io.capture("p0", duration_s=0.5, opener=slow))
    await asyncio.sleep(0.05)
    with pytest.raises(serial_io.SerialToolError, match="already being captured"):
        await serial_io.capture("p0", duration_s=0.5, opener=slow)
    await t1


async def test_bad_regex_is_a_clean_error():
    with pytest.raises(serial_io.SerialToolError, match="bad regex"):
        await serial_io.capture("fake", expect=["(unclosed"], opener=streaming_opener(b""))


# ----------------------------------------------------------------- MCP level
def _payload(result) -> dict:
    if result.structured_content is not None:
        sc = result.structured_content
        return sc.get("result", sc) if isinstance(sc, dict) else sc
    return json.loads(result.content[0].text)


async def test_tools_are_registered():
    async with Client(server.mcp) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert names == {"list_serial_ports", "capture_log", "analyze_log", "decode_addresses",
                     "reset_device", "read_coredump"}


async def test_analyze_log_tool_without_elf():
    text = (FX / "esp_error_check.log").read_text()
    async with Client(server.mcp) as c:
        r = await c.call_tool("analyze_log", {"text": text})
    assert not r.is_error
    out = _payload(r)
    assert out["crashes"][0]["kind"] == "esp_error_check"
    assert "note" in out  # no ELF -> raw addresses, not a failure


async def test_capture_log_tool_reports_failure_on_crash(monkeypatch):
    payload = (FX / "esp_error_check.log").read_bytes()
    real_capture = serial_io.capture

    async def fake_capture(*a, **kw):
        return await real_capture(*a, opener=streaming_opener(payload), **kw)

    monkeypatch.setattr(serial_io, "capture", fake_capture)
    async with Client(server.mcp) as c:
        r = await c.call_tool("capture_log", {"port": "fake", "duration_s": 3, "expect": ["wifi: connected"]})
        out = _payload(r)
        assert out["passed"] is False
        assert out["stop_reason"] == "panic"
        assert out["crashes"][0]["details"]["func"] == "net_start"
        # re-analysis of the last capture without passing text
        again = _payload(await c.call_tool("analyze_log", {}))
        assert again["crashes"][0]["kind"] == "esp_error_check"


async def test_missing_port_is_tool_error(monkeypatch):
    monkeypatch.delenv("ESPPORT", raising=False)
    async with Client(server.mcp) as c:
        r = await c.call_tool("reset_device", {})
    assert r.is_error
    assert "ESPPORT" in r.content[0].text


async def test_analyze_log_symbolises_with_elf(tmp_path, monkeypatch):
    """Full path: log -> parser -> addr2line -> decoded frames in the tool result.
    Host ELF + host addr2line stand in for the Xtensa toolchain."""
    import shutil
    import subprocess

    if not (shutil.which("gcc") and shutil.which("addr2line")):
        pytest.skip("host toolchain needed")
    src = tmp_path / "fw.c"
    src.write_text("int sensor_read(int *p){\n  return *p;\n}\nint main(void){ return sensor_read(0); }\n")
    elf = tmp_path / "fw.elf"
    subprocess.run(["gcc", "-g", "-O0", "-o", str(elf), str(src)], check=True)
    nm = subprocess.run(["nm", str(elf)], capture_output=True, text=True, check=True).stdout
    addr = next(int(l.split()[0], 16) for l in nm.splitlines() if l.endswith(" sensor_read"))

    log = (
        "Guru Meditation Error: Core  0 panic'ed (LoadProhibited). Exception was unhandled.\n"
        f"PC      : 0x{addr + 4:08x}  PS      : 0x00060a30  A0      : 0x800d1c2a  A1      : 0x3ffb5640\n"
        "EXCVADDR: 0x00000000  LBEG    : 0x400014fd  LEND    : 0x4000150d  LCOUNT  : 0xffffffff\n"
        f"Backtrace: 0x{addr + 4:08x}:0x3ffb5640\n"
        "Rebooting...\n"
    )
    monkeypatch.setenv("ESP_RUNTIME_ADDR2LINE", "addr2line")
    async with Client(server.mcp) as c:
        out = _payload(await c.call_tool("analyze_log", {"text": log, "elf": str(elf)}))
    crash = out["crashes"][0]
    assert "decode_error" not in crash, crash.get("decode_error")
    assert crash["frames"][0]["function"] == "sensor_read"
    assert "fw.c:" in crash["decoded"]
