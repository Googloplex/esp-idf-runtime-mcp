# esp-runtime-mcp

MCP server for the **runtime** side of ESP-IDF development: what happens on the chip *after* flashing.

ESP-IDF 6.0 ships an official MCP server (`idf.py mcp-server`) with `set_target`, `build_project`, `flash_project` and `clean_project`. Other community servers cover the same build/flash ground. None of them let the agent read the console, so the agent can flash firmware but cannot see that it crashed. This server closes the loop:

```
edit -> build -> flash             (idf.py mcp-server)
     -> capture_log(reset, expect) (this server: did it boot and reach the expected state?)
     -> crash? decoded backtrace   (this server: file:line, inlining, fault address)
     -> fix -> ...
```

## Tools

| Tool | What it does |
|---|---|
| `capture_log` | Reads the console until all `expect` regexes have matched **in order**, a crash is caught, or the timeout expires. It can hard-reset the chip first. Any crash in the log is parsed and symbolised automatically, and `passed` gives a single boolean verdict for the run. |
| `analyze_log` | Parses a log the user pasted, or the last capture, without hardware. |
| `decode_addresses` | Runs addr2line on any text containing addresses, such as a `Backtrace:` line. |
| `read_coredump` | Runs `esp-coredump` on a core dump from flash, from a file, or from a base64 dump printed to UART in the last capture. Returns the crashed task and its stack frames. |
| `reset_device` | Sends an RTS→EN reset pulse, holding IO0 high so the chip boots the app. |
| `list_serial_ports` | Lists serial ports and flags the likely ESP bridges: Espressif USB, CP210x, CH340/CH9102 and FTDI. |

### Crash parser coverage

- Guru Meditation on Xtensa (PC / EXCVADDR / `PC:SP` backtrace) and RISC-V (MEPC / RA / MTVAL). Includes IWDT and stack-canary debug exceptions.
- `abort()`, `assert failed` (both the IDF ≥5 and newlib formats), and `ESP_ERROR_CHECK` with file, line, function and expression. A trailing `abort()` is merged into the same event.
- FreeRTOS stack overflow hook, heap corruption and brownout.
- Task WDT, keeping a separate backtrace for each CPU.
- ROM reset reasons (`rst:0xc (SW_CPU_RESET)`) and reboot loops; each crash in a loop becomes its own event.
- RISC-V without EH-frame backtraces: words from the stack dump that fall in code address ranges are offered as candidates and labelled as a heuristic.

## Design notes

- **Port I/O.** pyserial is blocking, so the read loop runs in a worker thread behind an async API. Each port has its own lock, so two tools never read the same UART at once. Ports are opened with `serial_for_url`, which means `rfc2217://host:port` works for boards connected to another machine.
- **Line handling.** Reads use a ring buffer, and the result reports how many lines were dropped. Chunked reads are split into lines correctly, and ANSI colour codes are stripped.
- **Stopping after a crash.** The panic message is only the start of the crash output: the register dump and backtrace come after it. Capture therefore continues until `Rebooting...` or a 1.5 s grace period (for builds configured to halt on panic).
- **Symbolisation.** The architecture comes from `e_machine` in the ELF header. The tool is then looked up in this order: `xtensa-esp-elf-addr2line` / `riscv32-esp-elf-addr2line`, then `$IDF_TOOLS_PATH`, then `llvm-addr2line`. Results are cached per ELF modification time, so a reboot loop costs a single addr2line call.
- **ESP-IDF conventions.** The defaults follow `$ESPPORT` and `$ESPBAUD`. The ELF path is taken from `build/project_description.json`.

## Install

```bash
pip install -e ".[coredump]"
```

Claude Code / Cursor config (run with ESP-IDF activated so the toolchain is on PATH):

```json
{
  "mcpServers": {
    "esp-idf":     { "command": "eim", "args": ["run", "idf.py mcp-server"] },
    "esp-runtime": {
      "command": "esp-runtime-mcp",
      "env": { "ESPPORT": "/dev/ttyUSB0", "ESP_RUNTIME_PROJECT_DIR": "/path/to/project" }
    }
  }
}
```

## Tests

```bash
pip install -e ".[dev]" && pytest
```

The tests need no hardware and no Espressif toolchain:

- The parser is tested against recorded crash logs in `tests/fixtures`.
- The capture loop is tested through pyserial's `loop://` device, with data fed in chunks the way a real UART delivers it.
- The addr2line path is tested end to end on a host-compiled ELF.
- The MCP tools are tested through an in-memory MCP client.

## License

MIT
