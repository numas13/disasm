use core::fmt::{self, Write};

use alloc::borrow::Cow;

use disasm_core::{
    insn::Insn,
    operand::{Operand, OperandKind, Reg, RegClass},
    printer::{ArchPrinter, FormatterFn, PrinterExt, Separator},
};

use super::{consts::*, opcode, Size, X86Operand};

#[rustfmt::skip]
const GPR_NAME_BYTE: [&str; 20] = [
    "%al",
    "%cl",
    "%dl",
    "%bl",
    "%ah",
    "%ch",
    "%dh",
    "%bh",
    "%r8b",
    "%r9b",
    "%r10b",
    "%r11b",
    "%r12b",
    "%r13b",
    "%r14b",
    "%r15b",
    // only for rex
    "%spl",
    "%bpl",
    "%sil",
    "%dil",
];

#[rustfmt::skip]
const GPR_NAME_WORD: [&str; 16] = [
    "%ax",
    "%cx",
    "%dx",
    "%bx",
    "%sp",
    "%bp",
    "%si",
    "%di",
    "%r8w",
    "%r9w",
    "%r10w",
    "%r11w",
    "%r12w",
    "%r13w",
    "%r14w",
    "%r15w",
];

#[rustfmt::skip]
const GPR_NAME_LONG: [&str; 16] = [
    "%eax",
    "%ecx",
    "%edx",
    "%ebx",
    "%esp",
    "%ebp",
    "%esi",
    "%edi",
    "%r8d",
    "%r9d",
    "%r10d",
    "%r11d",
    "%r12d",
    "%r13d",
    "%r14d",
    "%r15d",
];

#[rustfmt::skip]
const GPR_NAME_QUAD: [&str; 16] = [
    "%rax",
    "%rcx",
    "%rdx",
    "%rbx",
    "%rsp",
    "%rbp",
    "%rsi",
    "%rdi",
    "%r8",
    "%r9",
    "%r10",
    "%r11",
    "%r12",
    "%r13",
    "%r14",
    "%r15",
];

#[rustfmt::skip]
const MM_NAME: [&str; 16] = [
    "%mm0",
    "%mm1",
    "%mm2",
    "%mm3",
    "%mm4",
    "%mm5",
    "%mm6",
    "%mm7",
    "%mm8",
    "%mm9",
    "%mm10",
    "%mm11",
    "%mm12",
    "%mm13",
    "%mm14",
    "%mm15",
];

#[rustfmt::skip]
const XMM_NAME: [&str; 32] = [
    "%xmm0",
    "%xmm1",
    "%xmm2",
    "%xmm3",
    "%xmm4",
    "%xmm5",
    "%xmm6",
    "%xmm7",
    "%xmm8",
    "%xmm9",
    "%xmm10",
    "%xmm11",
    "%xmm12",
    "%xmm13",
    "%xmm14",
    "%xmm15",
    "%xmm16",
    "%xmm17",
    "%xmm18",
    "%xmm19",
    "%xmm20",
    "%xmm21",
    "%xmm22",
    "%xmm23",
    "%xmm24",
    "%xmm25",
    "%xmm26",
    "%xmm27",
    "%xmm28",
    "%xmm29",
    "%xmm30",
    "%xmm31",
];

#[rustfmt::skip]
const YMM_NAME: [&str; 32] = [
    "%ymm0",
    "%ymm1",
    "%ymm2",
    "%ymm3",
    "%ymm4",
    "%ymm5",
    "%ymm6",
    "%ymm7",
    "%ymm8",
    "%ymm9",
    "%ymm10",
    "%ymm11",
    "%ymm12",
    "%ymm13",
    "%ymm14",
    "%ymm15",
    "%ymm16",
    "%ymm17",
    "%ymm18",
    "%ymm19",
    "%ymm20",
    "%ymm21",
    "%ymm22",
    "%ymm23",
    "%ymm24",
    "%ymm25",
    "%ymm26",
    "%ymm27",
    "%ymm28",
    "%ymm29",
    "%ymm30",
    "%ymm31",
];

#[rustfmt::skip]
const ZMM_NAME: [&str; 32] = [
    "%zmm0",
    "%zmm1",
    "%zmm2",
    "%zmm3",
    "%zmm4",
    "%zmm5",
    "%zmm6",
    "%zmm7",
    "%zmm8",
    "%zmm9",
    "%zmm10",
    "%zmm11",
    "%zmm12",
    "%zmm13",
    "%zmm14",
    "%zmm15",
    "%zmm16",
    "%zmm17",
    "%zmm18",
    "%zmm19",
    "%zmm20",
    "%zmm21",
    "%zmm22",
    "%zmm23",
    "%zmm24",
    "%zmm25",
    "%zmm26",
    "%zmm27",
    "%zmm28",
    "%zmm29",
    "%zmm30",
    "%zmm31",
];

#[rustfmt::skip]
const K_NAME: [&str; 8] = [
    "%k0",
    "%k1",
    "%k2",
    "%k3",
    "%k4",
    "%k5",
    "%k6",
    "%k7",
];

#[rustfmt::skip]
const BND_NAME: [&str; 4] = [
    "%bnd0",
    "%bnd1",
    "%bnd2",
    "%bnd3",
];

#[rustfmt::skip]
const SEGMENT_NAME: [&str; 6] = [
    "%es",
    "%cs",
    "%ss",
    "%ds",
    "%fs",
    "%gs",
];

#[rustfmt::skip]
const SEGMENT_PREFIX: [&str; 6] = [
    "es",
    "cs",
    "ss",
    "ds",
    "fs",
    "gs",
];

#[rustfmt::skip]
const ST_NAME: [&str; 8] = [
    "%st(0)",
    "%st(1)",
    "%st(2)",
    "%st(3)",
    "%st(4)",
    "%st(5)",
    "%st(6)",
    "%st(7)",
];

pub struct Printer {
    amd64: bool,
    att: bool,
}

impl Printer {
    pub fn new(_: &disasm_core::Options, opts_arch: &super::Options) -> Self {
        Self {
            amd64: opts_arch.ext.amd64,
            att: opts_arch.att,
        }
    }

    fn is_amd64(&self) -> bool {
        self.amd64
    }

    fn is_att(&self) -> bool {
        self.att
    }

    fn is_intel(&self) -> bool {
        !self.is_att()
    }

    fn strip_prefix<'a>(&self, name: &'a str) -> &'a str {
        if self.is_att() {
            name
        } else {
            &name[1..]
        }
    }

    fn register_name(&self, reg: Reg) -> Cow<'static, str> {
        match reg {
            super::NONE => "".into(),
            super::RIP => self.strip_prefix("%rip").into(),
            _ => {
                let index = reg.index();
                match reg.class() {
                    RegClass::INT => {
                        let (size, index) = Size::decode_gpr(index);
                        let name = match size {
                            Size::Byte => GPR_NAME_BYTE[index],
                            Size::Word => GPR_NAME_WORD[index],
                            Size::Long => GPR_NAME_LONG[index],
                            Size::Quad => GPR_NAME_QUAD[index],
                            _ => unreachable!(),
                        };
                        self.strip_prefix(name).into()
                    }
                    RegClass::VECTOR => {
                        let (size, index) = Size::decode_vec(index);
                        let name = match size {
                            Size::Mm => MM_NAME[index],
                            Size::Xmm => XMM_NAME[index],
                            Size::Ymm => YMM_NAME[index],
                            Size::Zmm => ZMM_NAME[index],
                            _ => unreachable!(),
                        };
                        self.strip_prefix(name).into()
                    }
                    reg_class::K | reg_class::K_MASK => {
                        let name = K_NAME[index as usize & 7];
                        self.strip_prefix(name).into()
                    }
                    reg_class::BND => {
                        let name = BND_NAME[index as usize];
                        self.strip_prefix(name).into()
                    }
                    reg_class::SEGMENT => {
                        let name = SEGMENT_NAME[index as usize];
                        self.strip_prefix(name).into()
                    }
                    _ => todo!(),
                }
            }
        }
    }

    fn print_segment<E: PrinterExt>(
        &self,
        fmt: &mut fmt::Formatter,
        ext: &E,
        operand: &Operand,
        force_ds: bool,
    ) -> fmt::Result {
        let name = match operand.flags().field(operand::FIELD_SEGMENT) {
            s if s != 0 => Some(SEGMENT_NAME[s as usize - 1]),
            0 if force_ds => Some(SEGMENT_NAME[insn::SEGMENT_DS as usize - 1]),
            _ => None,
        };
        if let Some(name) = name {
            ext.print_register(fmt, self.strip_prefix(name))?;
            fmt.write_char(':')?;
        }
        Ok(())
    }

    fn print_broadcast(&self, fmt: &mut fmt::Formatter, operand: &Operand) -> fmt::Result {
        let bcst = operand.flags().field(operand::FIELD_BCST) as u8;
        if bcst != operand::BROADCAST_NONE {
            let s = match bcst {
                operand::BROADCAST_1TO2 => "1to2",
                operand::BROADCAST_1TO4 => "1to4",
                operand::BROADCAST_1TO8 => "1to8",
                operand::BROADCAST_1TO16 => "1to16",
                operand::BROADCAST_1TO32 => "1to32",
                _ => unreachable!(),
            };
            fmt.write_char('{')?;
            fmt.write_str(s)?;
            fmt.write_char('}')?;
        }
        Ok(())
    }

    fn print_mem_access_intel(
        &self,
        fmt: &mut fmt::Formatter,
        insn: &Insn,
        operand: &Operand,
    ) -> fmt::Result {
        let size = operand.flags().field(operand::FIELD_MEM) as u8;
        if insn.opcode() != opcode::LEA && !operand.flags().any(operand::NO_PTR) {
            let prefix = match size {
                operand::SIZE_NONE => "",
                operand::SIZE_BYTE => "BYTE ",
                operand::SIZE_TBYTE => "TBYTE ",
                operand::SIZE_WORD => "WORD ",
                operand::SIZE_DWORD => "DWORD ",
                operand::SIZE_QWORD => "QWORD ",
                operand::SIZE_OWORD => "OWORD ",
                operand::SIZE_XMMWORD => "XMMWORD ",
                operand::SIZE_YMMWORD => "YMMWORD ",
                operand::SIZE_ZMMWORD => "ZMMWORD ",
                operand::SIZE_FWORD_48 | operand::SIZE_FWORD_80 => "FWORD ",
                _ => unreachable!("unexpected operand size {size}"),
            };
            fmt.write_str(prefix)?;
            let bcst = operand.flags().field(operand::FIELD_BCST) as u8;
            let ptr = if bcst != operand::BROADCAST_NONE {
                "BCST "
            } else {
                "PTR "
            };
            fmt.write_str(ptr)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn print_mem_intel<E: PrinterExt>(
        &self,
        fmt: &mut fmt::Formatter,
        ext: &E,
        insn: &Insn,
        operand: &Operand,
        base: &Reg,
        index: Option<(&Reg, u8)>,
        offset: Option<i64>,
    ) -> fmt::Result {
        self.print_mem_access_intel(fmt, insn, operand)?;
        self.print_segment(fmt, ext, operand, false)?;
        let base_name = self.register_name(*base);
        fmt.write_char('[')?;
        ext.print_register(fmt, &base_name)?;
        if let Some((index, scale)) = index {
            let index = self.register_name(*index);
            if !base_name.is_empty() {
                fmt.write_char('+')?;
            }
            ext.print_register(fmt, &index)?;
            fmt.write_char('*')?;
            ext.print_immediate(fmt, scale)?;
        }
        if let Some(offset) = offset {
            let (c, offset) = if *base != super::RIP && offset < 0 {
                ('-', -offset)
            } else {
                ('+', offset)
            };
            fmt.write_char(c)?;
            ext.print_address_offset(fmt, FormatterFn(|fmt| write!(fmt, "{offset:#x}")))?;
        }
        fmt.write_char(']')?;
        if operand.flags().any(operand::BCST_FORCE) {
            self.print_broadcast(fmt, operand)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn print_mem_att<E: PrinterExt>(
        &self,
        fmt: &mut fmt::Formatter,
        ext: &E,
        operand: &Operand,
        base: &Reg,
        index: Option<(&Reg, u8)>,
        offset: Option<i64>,
    ) -> fmt::Result {
        self.print_segment(fmt, ext, operand, false)?;
        if let Some(offset) = offset {
            let (s, offset) = if offset < 0 {
                ("-", -offset)
            } else {
                ("", offset)
            };
            ext.print_address_offset(fmt, FormatterFn(|fmt| write!(fmt, "{s}{offset:#x}")))?;
        }
        let base = self.register_name(*base);
        fmt.write_char('(')?;
        ext.print_register(fmt, base)?;
        if let Some((index, scale)) = index {
            let index = self.register_name(*index);
            fmt.write_char(',')?;
            ext.print_register(fmt, index)?;
            fmt.write_char(',')?;
            ext.print_immediate(fmt, scale)?;
        }
        fmt.write_char(')')?;
        self.print_broadcast(fmt, operand)?;
        Ok(())
    }
}

impl<E: PrinterExt> ArchPrinter<E> for Printer {
    fn mnemonic(&self, insn: &Insn) -> Option<(&'static str, &'static str)> {
        super::mnemonic(insn, self.is_amd64(), self.is_att())
    }

    fn register_name(&self, reg: Reg) -> Cow<'static, str> {
        self.register_name(reg)
    }

    fn print_mnemonic(
        &self,
        fmt: &mut fmt::Formatter,
        ext: &E,
        insn: &Insn,
        separator: bool,
    ) -> fmt::Result {
        let mut len = 0;

        let mut print_prefix = |flag: u32, prefix: &str| {
            if insn.flags().any(flag) {
                ext.print_mnemonic(fmt, prefix)?;
                len += prefix.len();
            }
            Ok(())
        };

        print_prefix(insn::LOCK, "lock ")?;
        print_prefix(insn::DATA16, "data16 ")?;
        print_prefix(insn::ADDR32, "addr32 ")?;
        print_prefix(insn::REX_W, "rex.W ")?;

        let segment = insn.flags().field(insn::FIELD_SEGMENT);
        if segment != 0 {
            let s = if segment == insn::SEGMENT_DS && insn.opcode() == opcode::JMP {
                "notrack"
            } else {
                SEGMENT_PREFIX[segment as usize - 1]
            };
            ext.print_mnemonic(fmt, s)?;
            fmt.write_char(' ')?;
            len += s.len() + 1;
        }

        let rep = insn.flags().field(insn::FIELD_REP);
        if rep != insn::REP_NONE {
            let s = match rep {
                insn::REP => "rep ",
                insn::REPZ => "repz ",
                insn::REPNZ => "repnz ",
                _ => unreachable!("unexpected repeat {rep}"),
            };
            ext.print_mnemonic(fmt, s)?;
            len += s.len();
        }

        let (mnemonic, _) =
            super::mnemonic(insn, self.is_amd64(), self.is_att()).unwrap_or(("<invalid>", ""));
        ext.print_mnemonic(fmt, mnemonic)?;
        len += mnemonic.len();

        if self.is_att() && insn.flags().any(insn::SUFFIX) {
            let suffix = match insn.flags().field(insn::FIELD_SUFFIX) {
                insn::SUFFIX_B => "b",
                insn::SUFFIX_W => "w",
                insn::SUFFIX_L => "l",
                insn::SUFFIX_Q => "q",
                insn::SUFFIX_FP_S => "s",
                insn::SUFFIX_FP_L => "l",
                insn::SUFFIX_FP_LL => "ll",
                insn::SUFFIX_FP_T => "t",
                _ => unreachable!(),
            };
            ext.print_mnemonic(fmt, suffix)?;
            len += suffix.len();
        }

        if separator && !insn.operands().is_empty() {
            <Self as ArchPrinter<E>>::insn_separator(self).print(fmt, len)?;
        }

        Ok(())
    }

    fn need_operand_separator(&self, i: usize, operand: &Operand) -> bool {
        match operand.kind() {
            OperandKind::Reg(reg) if reg.class() == reg_class::K_MASK => {
                return false;
            }
            OperandKind::ArchSpec(id, ..) if self.is_intel() => {
                match X86Operand::from_u64(*id).unwrap() {
                    X86Operand::Sae => return false,
                    X86Operand::SaeEr => return false,
                    _ => {}
                }
            }
            _ => {}
        }
        i != 0
    }

    fn print_operand(
        &self,
        fmt: &mut fmt::Formatter,
        ext: &E,
        insn: &Insn,
        operand: &Operand,
    ) -> fmt::Result {
        if self.is_att() && operand.flags().any(operand::INDIRECT) {
            fmt.write_char('*')?;
        }

        match operand.kind() {
            OperandKind::Reg(reg) => match reg.class() {
                reg_class::K_MASK => {
                    let name = self.register_name(*reg);
                    fmt.write_char('{')?;
                    ext.print_register(fmt, name)?;
                    fmt.write_char('}')?;
                    if reg.index() >= 8 {
                        fmt.write_str("{z}")?;
                    }
                    Ok(())
                }
                _ => self.print_operand_default(fmt, ext, insn, operand),
            },
            OperandKind::ArchSpec(id, x, _) => match X86Operand::from_u64(*id).unwrap() {
                X86Operand::ST => ext.print_register(fmt, self.strip_prefix("%st")),
                X86Operand::STI => ext.print_register(fmt, self.strip_prefix(ST_NAME[*x as usize])),
                X86Operand::Sae => fmt.write_str("{sae}"),
                X86Operand::SaeEr => {
                    let s = match x {
                        0 => "{rn-sae}",
                        1 => "{rd-sae}",
                        2 => "{ru-sae}",
                        3 => "{rz-sae}",
                        _ => unreachable!("unexpected rounding mode {x}"),
                    };
                    fmt.write_str(s)
                }
                X86Operand::MemOffset => {
                    self.print_segment(fmt, ext, operand, self.is_intel())?;
                    ext.print_address(fmt, FormatterFn(|fmt| write!(fmt, "{x:#x}")))
                }
            },
            OperandKind::Indirect(base) if self.is_intel() => {
                self.print_mem_intel(fmt, ext, insn, operand, base, None, None)
            }
            OperandKind::Relative(base, offset) if self.is_intel() => {
                self.print_mem_intel(fmt, ext, insn, operand, base, None, Some(*offset))
            }
            OperandKind::ScaledIndex(base, index, scale) if self.is_intel() => {
                self.print_mem_intel(fmt, ext, insn, operand, base, Some((index, *scale)), None)
            }
            OperandKind::ScaledIndexRelative(base, index, scale, offset) if self.is_intel() => self
                .print_mem_intel(
                    fmt,
                    ext,
                    insn,
                    operand,
                    base,
                    Some((index, *scale)),
                    Some(*offset as i64),
                ),
            OperandKind::Absolute(addr) => {
                let only_addr = operand.flags().any(operand::NO_PTR);
                if self.is_intel() {
                    self.print_mem_access_intel(fmt, insn, operand)?;
                    self.print_segment(fmt, ext, operand, !only_addr)?;
                } else {
                    self.print_segment(fmt, ext, operand, false)?;
                }
                ext.print_immediate(
                    fmt,
                    FormatterFn(|fmt| {
                        if only_addr {
                            write!(fmt, "{addr:x}")
                        } else {
                            write!(fmt, "{addr:#x}")
                        }
                    }),
                )?;
                self.print_symbol(fmt, ext, *addr)
            }
            OperandKind::Indirect(base) => self.print_mem_att(fmt, ext, operand, base, None, None),
            OperandKind::Relative(base, offset) => {
                self.print_mem_att(fmt, ext, operand, base, None, Some(*offset))
            }
            OperandKind::ScaledIndexRelative(base, index, scale, offset) if self.is_att() => self
                .print_mem_att(
                    fmt,
                    ext,
                    operand,
                    base,
                    Some((index, *scale)),
                    Some(*offset as i64),
                ),
            OperandKind::Imm(imm) if self.is_att() => {
                ext.print_immediate(fmt, FormatterFn(|fmt| write!(fmt, "${imm}")))
            }
            OperandKind::Uimm(imm) if self.is_att() => {
                ext.print_immediate(fmt, FormatterFn(|fmt| write!(fmt, "${imm:#x}")))
            }
            _ => self.print_operand_default(fmt, ext, insn, operand),
        }
    }

    fn reverse_operands(&self) -> bool {
        self.is_att()
    }

    fn insn_separator(&self) -> Separator {
        Separator::Width(7)
    }
}
