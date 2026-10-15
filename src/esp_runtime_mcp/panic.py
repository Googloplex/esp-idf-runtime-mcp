"""Parse ESP-IDF crash output (Xtensa and RISC-V) from raw console logs.

The parser is deliberately line-oriented and stateless across calls: it takes a
log (possibly containing several crash/reboot cycles) and returns a list of
`CrashEvent`s. It does not need the ELF; symbolisation is done separately in
`decode.py`, so the parser is fully testable on recorded logs.

Formats covered (ESP-IDF v4.4 .. v6.x):
  * Guru Meditation (CPU exception, IWDT, debug exception / stack canary)
  * abort() / assert failed / ESP_ERROR_CHECK failed
  * FreeRTOS stack overflow hook
  * Task watchdog (non-fatal by default, but prints backtraces)
  * Heap corruption (CORRUPT HEAP)
  * Brownout
  * ROM reset reason line after reboot (rst:0x.. (REASON))
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# --- trigger lines -----------------------------------------------------------
GURU_RE = re.compile(
    r"Guru Meditation Error: Core\s+(?P<core>\d+) panic'ed \((?P<reason>[^)]*)\)"
)
ABORT_RE = re.compile(r"abort\(\) was called at PC (?P<pc>0x[0-9a-fA-F]+) on core (?P<core>\d+)")
# IDF >= 5: "assert failed: app_main main.c:23 (ptr != NULL)"
ASSERT_RE = re.compile(r"assert failed: (?P<func>\S+) (?P<file>[^:\s]+):(?P<line>\d+) \((?P<expr>.*)\)\s*$")
# newlib style (IDF 4.x): assertion "x" failed: file "main.c", line 12, function: foo
ASSERT_OLD_RE = re.compile(
    r'assertion "(?P<expr>.*)" failed: file "(?P<file>[^"]+)", line (?P<line>\d+)(?:, function: (?P<func>\S+))?'
)
ESP_ERR_RE = re.compile(
    r"ESP_ERROR_CHECK failed: esp_err_t (?P<code>0x[0-9a-fA-F]+) \((?P<name>[A-Z0-9_]+)\) at (?P<pc>0x[0-9a-fA-F]+)"
)
STACK_OVF_RE = re.compile(r"\*\*\*ERROR\*\*\* A stack overflow in task (?P<task>.+?) has been detected")
TWDT_RE = re.compile(r"task_wdt: Task watchdog got triggered")
HEAP_RE = re.compile(r"CORRUPT HEAP: (?P<msg>.*)")
BROWNOUT_RE = re.compile(r"Brownout detector was triggered")

# --- follow-up lines ---------------------------------------------------------
BACKTRACE_RE = re.compile(r"^Backtrace:\s*(?P<body>.*)$")
BT_PAIR_RE = re.compile(r"(0x[0-9a-fA-F]+):(0x[0-9a-fA-F]+)")
# register dump: "PC      : 0x400d2d4b  PS      : 0x00060a30  ..."
REG_RE = re.compile(r"\b([A-Z][A-Z0-9]{0,8})\s*:\s*(0x[0-9a-fA-F]{8})\b")
DEBUG_REASON_RE = re.compile(r"Debug exception reason:\s*(?P<reason>.*)")
ESP_ERR_FILE_RE = re.compile(r'^file: "(?P<file>[^"]+)" line (?P<line>\d+)')
ESP_ERR_FUNC_RE = re.compile(r"^func: (?P<func>\S+)")
ESP_ERR_EXPR_RE = re.compile(r"^expression: (?P<expr>.*)")
TWDT_TASK_RE = re.compile(r"task_wdt:\s+-\s+(?P<task>\S+) \(CPU (?P<cpu>\d+)\)")
STACK_DUMP_RE = re.compile(r"^(?P<base>[0-9a-fA-F]{8}):\s+(?P<words>(?:0x[0-9a-fA-F]{8}\s*)+)$")
RESET_RE = re.compile(r"rst:(?P<code>0x[0-9a-fA-F]+) \((?P<reason>[A-Z0-9_]+)\)")
END_RE = re.compile(r"^(Rebooting\.\.\.|ELF file SHA256:|ets [A-Z][a-z]{2} |ESP-ROM:)")

# Address windows that can hold executable code. Used only for the RISC-V
# stack-scan heuristic; the union covers ESP32-C2/C3/C5/C6/H2/P4 IRAM + flash
# instruction bus. Kept broad on purpose; false positives are flagged.
RISCV_CODE_RANGES = (
    (0x40000000, 0x40080000),  # ROM
    (0x40380000, 0x40400000),  # IRAM (C3/C2)
    (0x40800000, 0x40880000),  # HP SRAM (C6/H2/C5)
    (0x42000000, 0x44000000),  # flash I-bus
    (0x4FC00000, 0x50000000),  # P4 HP SRAM / ROM
)


@dataclass
class CrashEvent:
    kind: str  # guru | abort | assert | esp_error_check | stack_overflow | task_wdt | heap_corruption | brownout
    line_no: int  # 1-based line of the trigger in the input
    summary: str
    core: int | None = None
    arch: str | None = None  # "xtensa" | "riscv" | None (unknown)
    pc: int | None = None  # faulting PC (PC on Xtensa, MEPC on RISC-V, or abort PC)
    fault_addr: int | None = None  # EXCVADDR / MTVAL
    registers: dict[str, int] = field(default_factory=dict)
    backtrace: list[int] = field(default_factory=list)
    backtrace_corrupted: bool = False
    other_backtraces: list[list[int]] = field(default_factory=list)  # e.g. TWDT prints one per CPU
    stack_candidates: list[int] = field(default_factory=list)  # RISC-V heuristic only
    details: dict[str, str] = field(default_factory=dict)

    def code_addresses(self) -> list[int]:
        """Addresses worth symbolising, most important first, de-duplicated."""
        out: list[int] = []
        for a in [self.pc, *self.backtrace, *(a for bt in self.other_backtraces for a in bt)]:
            if a and a not in out:
                out.append(a)
        if self.arch == "riscv":
            ra = self.registers.get("RA")
            if ra and ra not in out:
                out.append(ra)
        if "abort_pc" in self.details:
            a = int(self.details["abort_pc"], 16)
            if a not in out:
                out.append(a)
        return out

    def to_dict(self) -> dict:
        d = asdict(self)
        for k in ("pc", "fault_addr"):
            if d[k] is not None:
                d[k] = f"0x{d[k]:08x}"
        d["registers"] = {k: f"0x{v:08x}" for k, v in self.registers.items()}
        d["backtrace"] = [f"0x{a:08x}" for a in self.backtrace]
        d["other_backtraces"] = [[f"0x{a:08x}" for a in bt] for bt in self.other_backtraces]
        d["stack_candidates"] = [f"0x{a:08x}" for a in self.stack_candidates]
        return d


@dataclass
class ParseResult:
    events: list[CrashEvent]
    reset_reasons: list[dict[str, str]]  # [{"line_no", "code", "reason"}]

    def to_dict(self) -> dict:
        return {
            "events": [e.to_dict() for e in self.events],
            "reset_reasons": self.reset_reasons,
        }


def clean_line(line: str) -> str:
    """Strip ANSI colour codes and trailing CR/whitespace."""
    return ANSI_RE.sub("", line).rstrip("\r\n ")


def _hex(s: str) -> int:
    return int(s, 16)


def _match_trigger(line: str, line_no: int) -> CrashEvent | None:
    if m := GURU_RE.search(line):
        return CrashEvent("guru", line_no, f"Guru Meditation: {m['reason']}", core=int(m["core"]),
                          details={"reason": m["reason"]})
    if m := ABORT_RE.search(line):
        return CrashEvent("abort", line_no, "abort() called", core=int(m["core"]), pc=_hex(m["pc"]))
    if m := ESP_ERR_RE.search(line):
        return CrashEvent("esp_error_check", line_no, f"ESP_ERROR_CHECK failed: {m['name']} ({m['code']})",
                          pc=_hex(m["pc"]), details={"err_code": m["code"], "err_name": m["name"]})
    if m := ASSERT_RE.search(line) or ASSERT_OLD_RE.search(line):
        d = {k: v for k, v in m.groupdict().items() if v}
        return CrashEvent("assert", line_no, f"assert failed: {d.get('expr', '?')} at {d.get('file')}:{d.get('line')}",
                          details=d)
    if m := STACK_OVF_RE.search(line):
        return CrashEvent("stack_overflow", line_no, f"stack overflow in task '{m['task']}'",
                          details={"task": m["task"]})
    if TWDT_RE.search(line):
        return CrashEvent("task_wdt", line_no, "task watchdog triggered")
    if m := HEAP_RE.search(line):
        return CrashEvent("heap_corruption", line_no, f"heap corruption: {m['msg']}", details={"msg": m["msg"]})
    if BROWNOUT_RE.search(line):
        return CrashEvent("brownout", line_no, "brownout detector triggered")
    return None


# A secondary trigger appearing shortly after a "message" trigger belongs to the
# same crash (e.g. ESP_ERROR_CHECK -> abort(), stack overflow -> Guru).
_MERGE_WINDOW = 12


def _absorb(primary: CrashEvent, secondary: CrashEvent) -> None:
    if secondary.kind == "abort":
        primary.details["abort_pc"] = f"0x{secondary.pc:08x}"
        primary.core = primary.core if primary.core is not None else secondary.core
    elif secondary.kind == "guru":
        primary.details["guru_reason"] = secondary.details["reason"]
        primary.core = secondary.core
    else:
        primary.details[f"also_{secondary.kind}"] = secondary.summary


def _feed(ev: CrashEvent, line: str) -> None:
    """Attach a follow-up line to the event currently being assembled."""
    if m := BACKTRACE_RE.match(line):
        body = m["body"]
        pcs = [_hex(pc) for pc, _sp in BT_PAIR_RE.findall(body)]
        if ev.backtrace:
            ev.other_backtraces.append(pcs)
        else:
            ev.backtrace.extend(pcs)
        if "CORRUPTED" in body:
            ev.backtrace_corrupted = True
        return
    if m := DEBUG_REASON_RE.search(line):
        ev.details["debug_reason"] = m["reason"]
        return
    if ev.kind == "esp_error_check":
        for rx in (ESP_ERR_FILE_RE, ESP_ERR_FUNC_RE, ESP_ERR_EXPR_RE):
            if m := rx.match(line):
                ev.details.update(m.groupdict())
                return
    if ev.kind == "task_wdt" and (m := TWDT_TASK_RE.search(line)):
        tasks = ev.details.get("tasks", "")
        ev.details["tasks"] = (tasks + "," if tasks else "") + f"{m['task']}@CPU{m['cpu']}"
        return
    if m := STACK_DUMP_RE.match(line):
        for w in m["words"].split():
            v = _hex(w)
            if any(lo <= v < hi for lo, hi in RISCV_CODE_RANGES) and v not in ev.stack_candidates:
                ev.stack_candidates.append(v)
        return
    regs = REG_RE.findall(line)
    if len(regs) >= 2:  # a register dump row, not an incidental "X: 0x..." log
        for name, val in regs:
            ev.registers[name] = _hex(val)
        if "MEPC" in ev.registers:
            ev.arch = "riscv"
            ev.pc = ev.registers["MEPC"]
            ev.fault_addr = ev.registers.get("MTVAL", ev.fault_addr)
        elif "PC" in ev.registers:
            ev.arch = "xtensa"
            ev.pc = ev.registers["PC"]
            ev.fault_addr = ev.registers.get("EXCVADDR", ev.fault_addr)


def parse_log(text: str) -> ParseResult:
    events: list[CrashEvent] = []
    resets: list[dict[str, str]] = []
    cur: CrashEvent | None = None

    for i, raw in enumerate(text.splitlines(), start=1):
        line = clean_line(raw)

        if m := RESET_RE.search(line):
            resets.append({"line_no": str(i), "code": m["code"], "reason": m["reason"]})

        if END_RE.match(line):
            cur = None
            continue

        trig = _match_trigger(line, i)
        if trig:
            if (
                cur is not None
                and not cur.backtrace
                and not cur.registers
                and trig.kind in ("abort", "guru")
                and trig.line_no - cur.line_no <= _MERGE_WINDOW
            ):
                _absorb(cur, trig)
                if cur.pc is None:
                    cur.pc = trig.pc
                continue
            cur = trig
            events.append(cur)
            continue

        if cur is not None and line:
            _feed(cur, line)

    for ev in events:
        if ev.arch is None and ev.backtrace:
            ev.arch = "xtensa"  # only Xtensa prints PC:SP backtraces by default
        if ev.arch != "riscv" or ev.backtrace:
            ev.stack_candidates.clear()  # heuristic only useful without a real backtrace
    return ParseResult(events, resets)
