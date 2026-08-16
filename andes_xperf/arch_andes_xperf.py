"""
Binary Ninja architecture hook: Andes XAndesPerf custom RISC-V instructions.

Firmware built with the Andes AndeStar V5 toolchain (nds32le-linux-musl GCC)
declares `xandes5p0` in .riscv.attributes and is peppered with Andes custom-opcode
instructions (custom-0 = 0x0b, custom-2 = 0x5b) that Binary Ninja's stock RISC-V
decoder cannot decode -- so linear sweep desyncs and function recovery stalls
(only a handful of functions get created).

This plugin hooks the built-in `rv32gc` architecture and adds decode + control
flow + LLIL lifting for the eight Andes instructions seen in such binaries:

    nds.addigp   rd, imm          rd = gp + imm                       (custom-0)
    nds.lbugp    rd, imm          rd = zext8( mem[gp + imm] )          (custom-0)
    nds.sbgp     rs2, imm         mem[gp + imm] = rs2[7:0]             (custom-0)
    nds.lea.h    rd, rs1, rs2     rd = rs1 + (rs2 << 1)                (custom-2)
    nds.bfoz     rd, rs1, msb,lsb rd = zext( (rs1 >> lsb) & mask )     (custom-2)
    nds.beqc     rs1, cimm, off   if (rs1 == cimm) goto off            (custom-2)
    nds.bnec     rs1, cimm, off   if (rs1 != cimm) goto off            (custom-2)
    nds.bbc      rs1, bit,  off   if (((rs1 >> bit) & 1) == 0) goto off(custom-2)
    nds.bbs      rs1, bit,  off   if (((rs1 >> bit) & 1) == 1) goto off(custom-2)

Encodings were derived by differential probing of LLVM 22's assembler and
validated against llvm-objdump (12,600+ fuzz instructions decode identically).
Instruction *semantics* were confirmed against LLVM's RISCVInstrInfoXAndes.td
(LEA ShxAddPat, BFOZ msb/lsb) and the Andes QEMU helper (bfo).

Install: copy this file into your Binary Ninja user plugins directory
(Linux: ~/.binaryninja/plugins/), restart Binary Ninja, then open the binary.
For an already-open database use: Analysis -> Reanalyze all functions.
"""

from binaryninja import (
    Architecture, ArchitectureHook, InstructionInfo, BranchType,
    InstructionTextToken, InstructionTextTokenType as TT,
    LowLevelILLabel, log,
)

# ---------------------------------------------------------------------------
# Decoder (self-contained; no external tools at runtime).
# Field bit-maps: value-bit -> instruction-bit.
# ---------------------------------------------------------------------------
ABI = ['zero','ra','sp','gp','tp','t0','t1','t2','s0','s1','a0','a1','a2','a3',
       'a4','a5','a6','a7','s2','s3','s4','s5','s6','s7','s8','s9','s10','s11',
       't3','t4','t5','t6']

IMM_GP_LOAD  = [14,21,22,23,24,25,26,27,28,29,30,20,17,18,19,15,16,31]  # addigp/lbugp
IMM_GP_STORE = [14, 8, 9,10,11,25,26,27,28,29,30, 7,17,18,19,15,16,31]  # sbgp
BR_OFF       = [8,9,10,11,25,26,27,28,29,31]   # 10-bit signed, encodes off/2
BR_CIMM7     = [20,21,22,23,24,7,30]           # beqc/bnec 7-bit unsigned
BR_CIMM5     = [20,21,22,23,24]                # bbc/bbs 5-bit bit-index


def _gather(word, mapping):
    v = 0
    for vbit, ibit in enumerate(mapping):
        if (word >> ibit) & 1:
            v |= (1 << vbit)
    return v


def _sext(v, nbits):
    if v & (1 << (nbits - 1)):
        v -= (1 << nbits)
    return v


def _hx(v):
    return f'-{-v:#x}' if v < 0 else f'{v:#x}'


def decode(word, addr):
    """Return a dict describing an Andes custom instruction, or None."""
    word &= 0xffffffff
    op = word & 0x7f
    rd  = (word >> 7)  & 0x1f
    rs1 = (word >> 15) & 0x1f
    rs2 = (word >> 20) & 0x1f

    if op == 0x0b:                                    # custom-0: GP-relative
        sel = (word >> 12) & 0x3                      # bits[13:12]
        if sel == 0b01:
            imm = _sext(_gather(word, IMM_GP_LOAD), 18)
            return dict(mnem='nds.addigp', kind='addr', rd=rd, imm=imm,
                        text=f'nds.addigp\t{ABI[rd]}, {_hx(imm)}')
        if sel == 0b10:
            imm = _sext(_gather(word, IMM_GP_LOAD), 18)
            return dict(mnem='nds.lbugp', kind='load', rd=rd, imm=imm,
                        text=f'nds.lbugp\t{ABI[rd]}, {_hx(imm)}')
        if sel == 0b11:
            imm = _sext(_gather(word, IMM_GP_STORE), 18)
            return dict(mnem='nds.sbgp', kind='store', rs2=rs2, imm=imm,
                        text=f'nds.sbgp\t{ABI[rs2]}, {_hx(imm)}')
        return None

    if op == 0x5b:                                    # custom-2: XAndesPerf
        f3 = (word >> 12) & 0x7
        if f3 == 0 and ((word >> 25) & 0x7f) == 0x05:      # nds.lea.h
            return dict(mnem='nds.lea.h', kind='alu', rd=rd, rs1=rs1, rs2=rs2,
                        text=f'nds.lea.h\t{ABI[rd]}, {ABI[rs1]}, {ABI[rs2]}')
        if f3 == 2:                                        # nds.bfoz
            msb = (word >> 26) & 0x1f
            lsb = (word >> 20) & 0x1f
            return dict(mnem='nds.bfoz', kind='alu', rd=rd, rs1=rs1,
                        msb=msb, lsb=lsb,
                        text=f'nds.bfoz\t{ABI[rd]}, {ABI[rs1]}, {_hx(msb)}, {_hx(lsb)}')
        if f3 in (5, 6):                                   # nds.beqc / nds.bnec
            cimm = _gather(word, BR_CIMM7)
            off  = _sext(_gather(word, BR_OFF), 10) << 1
            tgt  = (addr + off) & 0xffffffff
            mn   = 'nds.beqc' if f3 == 5 else 'nds.bnec'
            return dict(mnem=mn, kind='branch',
                        cond=('eq' if f3 == 5 else 'ne'),
                        rs1=rs1, cimm=cimm, target=tgt,
                        text=f'{mn}\t{ABI[rs1]}, {_hx(cimm)}, {tgt:#x}')
        if f3 == 7:                                        # nds.bbc / nds.bbs
            cimm  = _gather(word, BR_CIMM5)
            off   = _sext(_gather(word, BR_OFF), 10) << 1
            tgt   = (addr + off) & 0xffffffff
            isset = (word >> 30) & 1
            mn    = 'nds.bbs' if isset else 'nds.bbc'
            return dict(mnem=mn, kind='branch',
                        cond=('bs' if isset else 'bc'),
                        rs1=rs1, cimm=cimm, target=tgt,
                        text=f'{mn}\t{ABI[rs1]}, {_hx(cimm)}, {tgt:#x}')
        return None

    return None


# ---------------------------------------------------------------------------
# Token rendering
# ---------------------------------------------------------------------------
def _tokens(d):
    t = [InstructionTextToken(TT.InstructionToken, f"{d['mnem']:<11}")]

    def reg(name):
        return InstructionTextToken(TT.RegisterToken, name)

    def sep():
        return InstructionTextToken(TT.OperandSeparatorToken, ", ")

    def imm(v):
        return InstructionTextToken(TT.IntegerToken, _hx(v), v & 0xffffffff)

    k = d['kind']
    if d['mnem'] == 'nds.addigp' or d['mnem'] == 'nds.lbugp':
        t += [reg(ABI[d['rd']]), sep(), imm(d['imm'])]
    elif d['mnem'] == 'nds.sbgp':
        t += [reg(ABI[d['rs2']]), sep(), imm(d['imm'])]
    elif d['mnem'] == 'nds.lea.h':
        t += [reg(ABI[d['rd']]), sep(), reg(ABI[d['rs1']]), sep(), reg(ABI[d['rs2']])]
    elif d['mnem'] == 'nds.bfoz':
        t += [reg(ABI[d['rd']]), sep(), reg(ABI[d['rs1']]), sep(),
              imm(d['msb']), sep(), imm(d['lsb'])]
    elif k == 'branch':
        t += [reg(ABI[d['rs1']]), sep(), imm(d['cimm']), sep(),
              InstructionTextToken(TT.PossibleAddressToken, f"{d['target']:#x}", d['target'])]
    return t


# ---------------------------------------------------------------------------
# LLIL lifting
# ---------------------------------------------------------------------------
def _gp(il):
    return il.reg(4, 'gp')


# gp is __global_pointer$ -- a fixed link-time constant in this static-musl ABI.
# The symbol is stripped, but we recover its value by decoding the entry point's
# `auipc gp, hi; addi gp, gp, lo` pair. When known, gp-relative instructions lift
# to absolute const pointers so Binary Ninja resolves them to strings/symbols
# (e.g. getenv("REQUEST_METHOD") instead of getenv(gp - 0x2e74)). If gp cannot be
# recovered, we fall back to `gp + imm` (still correct, just not resolved).
_GP_CACHE = {}


def _recover_gp(bv):
    try:
        ep = bv.entry_point
        data = bv.read(ep, 8)
        if len(data) < 8:
            return None
        w0 = int.from_bytes(data[0:4], 'little')   # auipc gp, hi
        w1 = int.from_bytes(data[4:8], 'little')   # addi  gp, gp, lo
        if (w0 & 0x7f) != 0x17 or ((w0 >> 7) & 0x1f) != 3:
            return None
        if (w1 & 0x7f) != 0x13 or ((w1 >> 7) & 0x1f) != 3 or \
           ((w1 >> 15) & 0x1f) != 3 or ((w1 >> 12) & 7) != 0:
            return None
        gp = (ep + (w0 & 0xfffff000)) & 0xffffffff
        lo = (w1 >> 20) & 0xfff
        if lo & 0x800:
            lo -= 0x1000
        return (gp + lo) & 0xffffffff
    except Exception:
        return None


def _gp_value(il):
    try:
        bv = il.source_function.view
    except Exception:
        return None
    if bv is None:
        return None
    key = id(bv)
    if key not in _GP_CACHE:
        _GP_CACHE[key] = _recover_gp(bv)
    return _GP_CACHE[key]


def _gp_ea(il, imm):
    """Effective address gp+imm: absolute const pointer if gp is known, else gp+imm."""
    gp = _gp_value(il)
    if gp is not None:
        return il.const_pointer(4, (gp + imm) & 0xffffffff)
    return il.add(4, _gp(il), il.const(4, imm))


def _set_or_nop(il, rd, expr):
    if rd == 0:
        il.append(il.nop())
    else:
        il.append(il.set_reg(4, ABI[rd], expr))


def _lift(d, il, addr):
    m = d['mnem']
    if m == 'nds.addigp':
        _set_or_nop(il, d['rd'], _gp_ea(il, d['imm']))
    elif m == 'nds.lbugp':
        _set_or_nop(il, d['rd'], il.zero_extend(4, il.load(1, _gp_ea(il, d['imm']))))
    elif m == 'nds.sbgp':
        il.append(il.store(1, _gp_ea(il, d['imm']), il.reg(4, ABI[d['rs2']])))
    elif m == 'nds.lea.h':
        expr = il.add(4, il.reg(4, ABI[d['rs1']]),
                      il.shift_left(4, il.reg(4, ABI[d['rs2']]), il.const(1, 1)))
        _set_or_nop(il, d['rd'], expr)
    elif m == 'nds.bfoz':
        msb, lsb = d['msb'], d['lsb']
        if msb >= lsb:
            src = il.reg(4, ABI[d['rs1']])
            if lsb:
                src = il.logical_shift_right(4, src, il.const(1, lsb))
            mask = (1 << (msb - lsb + 1)) - 1
            _set_or_nop(il, d['rd'], il.and_expr(4, src, il.const(4, mask)))
        else:
            il.append(il.unimplemented())
    elif d['kind'] == 'branch':
        rs1 = il.reg(4, ABI[d['rs1']])
        if d['cond'] == 'eq':
            cond = il.compare_equal(4, rs1, il.const(4, d['cimm']))
        elif d['cond'] == 'ne':
            cond = il.compare_not_equal(4, rs1, il.const(4, d['cimm']))
        else:
            bit = il.and_expr(4, il.logical_shift_right(4, rs1, il.const(1, d['cimm'])),
                              il.const(4, 1))
            if d['cond'] == 'bc':      # branch if bit clear
                cond = il.compare_equal(4, bit, il.const(4, 0))
            else:                      # bs: branch if bit set
                cond = il.compare_not_equal(4, bit, il.const(4, 0))
        _cond_branch(il, cond, d['target'], addr + 4)


def _cond_branch(il, cond, taken, fallthrough):
    t = il.get_label_for_address(il.arch, taken)
    f = il.get_label_for_address(il.arch, fallthrough)
    mk_t = t is None
    mk_f = f is None
    if mk_t:
        t = LowLevelILLabel()
    if mk_f:
        f = LowLevelILLabel()
    il.append(il.if_expr(cond, t, f))
    if mk_t:
        il.mark_label(t)
        il.append(il.jump(il.const_pointer(4, taken)))
    if mk_f:
        il.mark_label(f)
        il.append(il.jump(il.const_pointer(4, fallthrough)))


# ---------------------------------------------------------------------------
# The architecture hook
# ---------------------------------------------------------------------------
class AndesXPerfHook(ArchitectureHook):
    def get_instruction_info(self, data, addr):
        if len(data) >= 4:
            d = decode(int.from_bytes(data[:4], 'little'), addr)
            if d is not None:
                info = InstructionInfo()
                info.length = 4
                if d['kind'] == 'branch':
                    info.add_branch(BranchType.TrueBranch, d['target'])
                    info.add_branch(BranchType.FalseBranch, addr + 4)
                return info
        return super().get_instruction_info(data, addr)

    def get_instruction_text(self, data, addr):
        if len(data) >= 4:
            d = decode(int.from_bytes(data[:4], 'little'), addr)
            if d is not None:
                return _tokens(d), 4
        return super().get_instruction_text(data, addr)

    # BN's linear/graph renderer uses the context-aware variant. ArchitectureHook
    # nulls this callback unless we override it, so it MUST be defined here too --
    # otherwise custom instructions render as "??" even though decode works.
    def get_instruction_text_with_context(self, data, addr, context):
        if len(data) >= 4:
            d = decode(int.from_bytes(data[:4], 'little'), addr)
            if d is not None:
                return _tokens(d), 4
        return super().get_instruction_text_with_context(data, addr, context)

    def get_instruction_low_level_il(self, data, addr, il):
        if len(data) >= 4:
            d = decode(int.from_bytes(data[:4], 'little'), addr)
            if d is not None:
                _lift(d, il, addr)
                return 4
        return super().get_instruction_low_level_il(data, addr, il)


def install():
    base = Architecture['rv32gc']
    AndesXPerfHook(base).register()
    log.log_info("XAndesPerf: hooked rv32gc for Andes custom instructions",
                 "andes_xperf")


install()
