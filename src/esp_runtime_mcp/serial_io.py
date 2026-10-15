"""Serial console capture with stop conditions, for agent-driven HIL loops.

pyserial is blocking, so the read loop runs in a worker thread and the async
API wraps it. `serial_for_url` is used for opening, which means the same code
works with local ports (/dev/ttyUSB0, COM5), remote boards over RFC2217
(`rfc2217://host:port`, e.g. esp_rfc2217_server) and `loop://` in tests.
"""

from __future__ import annotations

import asyncio
import re
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

import serial
import serial.tools.list_ports

from .panic import END_RE, GURU_RE, ABORT_RE, ASSERT_RE, STACK_OVF_RE, ESP_ERR_RE, clean_line

KNOWN_VIDS = {
    0x303A: "Espressif (native USB / USB-Serial-JTAG)",
    0x10C4: "Silicon Labs CP210x",
    0x1A86: "WCH CH340/CH9102",
    0x0403: "FTDI",
}
FATAL_RES = (GURU_RE, ABORT_RE, ASSERT_RE, STACK_OVF_RE, ESP_ERR_RE)

Opener = Callable[[str, int], "serial.SerialBase"]

# One capture per port at a time: a second open would either fail (EBUSY) or,
# worse on some OSes, silently split bytes between two readers.
_port_locks: dict[str, asyncio.Lock] = {}


class SerialToolError(RuntimeError):
    pass


def default_opener(port: str, baud: int) -> serial.SerialBase:
    try:
        # do_not_open lets us set DTR/RTS *before* open: on many dev boards
        # the default asserted lines would hold the chip in reset/boot mode.
        s = serial.serial_for_url(port, baudrate=baud, timeout=0.05, do_not_open=True)
        s.dtr = False
        s.rts = False
        s.open()
        return s
    except serial.SerialException as e:
        msg = str(e)
        hint = ""
        if "busy" in msg.lower() or "denied" in msg.lower() or "Errno 16" in msg:
            hint = " (port in use? close `idf.py monitor` or check dialout group membership)"
        raise SerialToolError(f"cannot open {port}: {msg}{hint}") from e


def list_ports() -> list[dict]:
    out = []
    for p in serial.tools.list_ports.comports():
        out.append({
            "device": p.device,
            "description": p.description,
            "vid_pid": f"{p.vid:04X}:{p.pid:04X}" if p.vid is not None else None,
            "serial_number": p.serial_number,
            "likely_esp": p.vid in KNOWN_VIDS,
            "bridge": KNOWN_VIDS.get(p.vid),
        })
    return out


def hard_reset(ser: serial.SerialBase, pulse_s: float = 0.1) -> None:
    """Classic auto-reset circuit: RTS drives EN (inverted), DTR drives IO0.

    Keep IO0 high (DTR=False) so the chip boots the app, not the ROM loader.
    """
    ser.dtr = False
    ser.rts = True
    time.sleep(pulse_s)
    ser.rts = False


@dataclass
class CaptureResult:
    stop_reason: str  # expect_complete | panic | timeout | max_lines_total
    elapsed_s: float
    lines_total: int
    lines_dropped: int  # older lines evicted from the ring buffer
    lines: list[str]
    expect: list[dict] = field(default_factory=list)  # [{"pattern","matched","line"}]
    panic_line: str | None = None

    def to_dict(self, tail: int | None = None) -> dict:
        lines = self.lines if tail is None else self.lines[-tail:]
        return {
            "stop_reason": self.stop_reason,
            "elapsed_s": round(self.elapsed_s, 3),
            "lines_total": self.lines_total,
            "lines_dropped": self.lines_dropped + (len(self.lines) - len(lines)),
            "expect": self.expect,
            "panic_line": self.panic_line,
            "log": "\n".join(lines),
        }


def _capture_blocking(
    ser: serial.SerialBase,
    duration_s: float,
    expect: list[re.Pattern],
    stop_on_panic: bool,
    buffer_lines: int,
    max_lines_total: int,
    cancel: threading.Event,
    panic_grace_s: float = 1.5,
) -> CaptureResult:
    t0 = time.monotonic()
    deadline = t0 + duration_s
    ring: deque[str] = deque(maxlen=buffer_lines)
    total = 0
    pending = b""
    exp_state = [{"pattern": p.pattern, "matched": False, "line": None} for p in expect]
    exp_idx = 0
    panic_line: str | None = None
    stop_reason = "timeout"

    def handle(line: str) -> str | None:
        nonlocal exp_idx, panic_line, deadline
        if exp_idx < len(expect) and expect[exp_idx].search(line):
            exp_state[exp_idx].update(matched=True, line=line)
            exp_idx += 1
            if exp_idx == len(expect):
                return "expect_complete"
        if stop_on_panic:
            if panic_line is None and any(r.search(line) for r in FATAL_RES):
                panic_line = line
                # keep reading: register dump + backtrace follow the trigger
                deadline = min(deadline, time.monotonic() + panic_grace_s)
            elif panic_line is not None and END_RE.match(line):
                return "panic"
        return None

    while not cancel.is_set():
        now = time.monotonic()
        if now >= deadline:
            stop_reason = "panic" if panic_line else "timeout"
            break
        chunk = ser.read(ser.in_waiting or 1)
        if not chunk:
            continue
        pending += chunk
        *complete, pending = pending.split(b"\n")
        reason = None
        for raw in complete:
            line = clean_line(raw.decode("utf-8", errors="replace"))
            ring.append(line)
            total += 1
            reason = handle(line)
            if reason or total >= max_lines_total:
                reason = reason or "max_lines_total"
                break
        if reason:
            stop_reason = reason
            break
    else:
        stop_reason = "cancelled"

    if pending and stop_reason in ("timeout", "panic", "cancelled"):
        ring.append(clean_line(pending.decode("utf-8", errors="replace")) + " <partial>")
        total += 1

    return CaptureResult(
        stop_reason=stop_reason,
        elapsed_s=time.monotonic() - t0,
        lines_total=total,
        lines_dropped=max(0, total - len(ring)),
        lines=list(ring),
        expect=exp_state,
        panic_line=panic_line,
    )


async def capture(
    port: str,
    baud: int = 115200,
    duration_s: float = 5.0,
    expect: list[str] | None = None,
    stop_on_panic: bool = True,
    reset: bool = False,
    buffer_lines: int = 2000,
    max_lines_total: int = 200_000,
    opener: Opener = default_opener,
) -> CaptureResult:
    if duration_s <= 0 or duration_s > 600:
        raise SerialToolError("duration_s must be in (0, 600]")
    try:
        pats = [re.compile(p) for p in (expect or [])]
    except re.error as e:
        raise SerialToolError(f"bad regex in expect: {e}") from e

    lock = _port_locks.setdefault(port, asyncio.Lock())
    if lock.locked():
        raise SerialToolError(f"{port} is already being captured by another call")
    async with lock:
        ser = await asyncio.to_thread(opener, port, baud)
        cancel = threading.Event()
        try:
            if reset:
                await asyncio.to_thread(hard_reset, ser)
            return await asyncio.to_thread(
                _capture_blocking, ser, duration_s, pats, stop_on_panic,
                buffer_lines, max_lines_total, cancel,
            )
        except asyncio.CancelledError:
            cancel.set()  # let the worker thread exit promptly
            raise
        finally:
            await asyncio.to_thread(ser.close)


async def reset_device(port: str, baud: int = 115200, opener: Opener = default_opener) -> None:
    lock = _port_locks.setdefault(port, asyncio.Lock())
    if lock.locked():
        raise SerialToolError(f"{port} is busy (capture in progress); pass reset=true to capture_log instead")
    async with lock:
        ser = await asyncio.to_thread(opener, port, baud)
        try:
            await asyncio.to_thread(hard_reset, ser)
        finally:
            await asyncio.to_thread(ser.close)
