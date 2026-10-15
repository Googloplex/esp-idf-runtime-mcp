from pathlib import Path

from esp_runtime_mcp.panic import parse_log

FX = Path(__file__).parent / "fixtures"


def load(name: str) -> str:
    return (FX / name).read_text()


def test_xtensa_guru_registers_and_backtrace():
    r = parse_log(load("xtensa_loadprohibited.log"))
    assert len(r.events) == 1
    ev = r.events[0]
    assert ev.kind == "guru"
    assert ev.details["reason"] == "LoadProhibited"
    assert ev.core == 0
    assert ev.arch == "xtensa"
    assert ev.pc == 0x400D2D4B
    assert ev.fault_addr == 0  # NULL dereference
    assert ev.registers["EXCCAUSE"] == 0x1C
    assert ev.backtrace == [0x400D2D48, 0x400D1C27, 0x400E2A3D]
    assert not ev.backtrace_corrupted
    # reset reason after reboot is reported separately
    assert [x["reason"] for x in r.reset_reasons] == ["SW_CPU_RESET"]


def test_riscv_uses_mepc_ra_and_stack_scan():
    ev = parse_log(load("riscv_load_fault.log")).events[0]
    assert ev.arch == "riscv"
    assert ev.pc == 0x4200A1B2
    assert ev.fault_addr == 0
    assert ev.backtrace == []
    # MEPC first, then RA; stack heuristic kept separate
    assert ev.code_addresses() == [0x4200A1B2, 0x4200A1A8]
    assert ev.stack_candidates == [0x4200A2C4, 0x403847D6]


def test_esp_error_check_absorbs_abort_and_ansi():
    r = parse_log(load("esp_error_check.log"))
    assert len(r.events) == 1, "abort() after ESP_ERROR_CHECK is the same crash"
    ev = r.events[0]
    assert ev.kind == "esp_error_check"
    assert ev.details["err_name"] == "ESP_ERR_INVALID_STATE"
    assert ev.details["file"] == "main/net.c" and ev.details["line"] == "87"
    assert ev.details["func"] == "net_start"
    assert ev.details["abort_pc"] == "0x40086b9b"
    assert ev.backtrace_corrupted
    assert len(ev.backtrace) == 5


def test_reboot_loop_yields_separate_events():
    r = parse_log(load("stack_overflow_and_assert.log"))
    kinds = [e.kind for e in r.events]
    assert kinds == ["stack_overflow", "assert"]
    assert r.events[0].details["task"] == "sensor_task"
    a = r.events[1]
    assert a.details["func"] == "parse_frame" and a.details["line"] == "142"
    assert a.details["expr"] == "len <= MAX_FRAME"
    assert a.backtrace[-1] == 0x400D7E02
    assert len(r.reset_reasons) == 2


def test_task_wdt_keeps_per_cpu_backtraces():
    ev = parse_log(load("twdt.log")).events[0]
    assert ev.kind == "task_wdt"
    assert ev.details["tasks"] == "IDLE0@CPU0"
    assert ev.backtrace == [0x400D5E12, 0x400D5E40]
    assert ev.other_backtraces == [[0x40084F31, 0x400846B9]]
    assert 0x40084F31 in ev.code_addresses()


def test_plain_log_has_no_events():
    r = parse_log("I (1) main: hello\nW (2) wifi: PC: 0x400d0000 something\n")
    assert r.events == []


def test_old_newlib_assert_format():
    ev = parse_log('assertion "x == 1" failed: file "main/a.c", line 12, function: foo\n').events[0]
    assert ev.kind == "assert"
    assert ev.details == {"expr": "x == 1", "file": "main/a.c", "line": "12", "func": "foo"}
