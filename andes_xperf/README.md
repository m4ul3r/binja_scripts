# andes_xperf

A Binary Ninja architecture hook that teaches the built-in `rv32gc` architecture
to decode the **Andes XAndesPerf** custom RISC-V instructions.

Firmware built with the Andes AndeStar V5 toolchain (`nds32le-linux-musl` GCC,
`.riscv.attributes = rv32imafdc_xandes5p0`) is peppered with Andes custom-opcode
instructions (custom-0 `0x0b`, custom-2 `0x5b`). Stock Binary Ninja can't decode
them, so linear sweep desyncs and function recovery stalls — you get a handful of
functions and a `.text` full of `??`.

This plugin adds decode + control flow + LLIL lifting for the instructions that
show up in these binaries, delegating everything standard to `rv32gc`:

| Instruction | Semantics |
|---|---|
| `nds.addigp rd, imm` | `rd = gp + imm` |
| `nds.lbugp rd, imm` | `rd = zext8(mem[gp + imm])` |
| `nds.sbgp rs2, imm` | `mem[gp + imm] = rs2[7:0]` |
| `nds.lea.h rd, rs1, rs2` | `rd = rs1 + (rs2 << 1)` |
| `nds.bfoz rd, rs1, msb, lsb` | `rd = zext((rs1 >> lsb) & mask)` |
| `nds.beqc rs1, cimm, off` | `if (rs1 == cimm) goto off` |
| `nds.bnec rs1, cimm, off` | `if (rs1 != cimm) goto off` |
| `nds.bbc rs1, bit, off` | `if (((rs1 >> bit) & 1) == 0) goto off` |
| `nds.bbs rs1, bit, off` | `if (((rs1 >> bit) & 1) == 1) goto off` |

It also resolves `gp`-relative addressing. `gp` (`__global_pointer$`) is a fixed
link-time constant in static-musl firmware; its symbol is stripped, so the plugin
recovers the value by decoding the entry point's `auipc gp; addi gp` pair, then
lifts `nds.addigp`/`lbugp`/`sbgp` to absolute const pointers. The result is that
Binary Ninja resolves them to real strings/symbols in HLIL — e.g.
`getenv("REQUEST_METHOD")` instead of `getenv(gp - 0x2e74)` — while the
disassembly stays faithful to the raw instruction. If `gp` can't be recovered it
falls back to `gp + imm` (still correct, just unresolved).

### How it was built

Field layouts were derived by differential bit-probing of LLVM 22's assembler
(`llvm-mc`) and validated against `llvm-objdump` — 12,600+ fuzzed instructions
decode identically. Semantics were confirmed against LLVM's
`RISCVInstrInfoXAndes.td` (LEA `ShxAddPat`, BFOZ `msb`/`lsb`) and the Andes QEMU
`bfo` helper.

### Usage

1. Copy `arch_andes_xperf.py` into your Binary Ninja user plugins directory
   (Linux: `~/.binaryninja/plugins/`).
2. Restart Binary Ninja.
3. Open an `rv32gc` Andes binary — the custom instructions now decode, control
   flow is recovered, and HLIL lifts cleanly.

For a database that was analyzed before the plugin was installed, run
**Analysis → Reanalyze all functions**.

### Notes / limitations

- Covers the 8 instructions observed in the targeted firmware. Other XAndesPerf
  instructions are easy to add — the decode logic is table-driven in `decode()`.
- `nds.bfoz` with `msb < lsb` (an insert/rotate form not seen in practice) lifts
  as unimplemented.
- `gp` resolution assumes `gp == __global_pointer$` throughout, which holds for
  static-musl firmware but is an analysis convenience rather than per-instruction
  truth.
