use core::fmt::{self, Write};

use alloc::borrow::Cow;

use disasm_core::{
    insn::Insn,
    operand::{Operand, OperandKind, Reg, RegClass},
    printer::{ArchPrinter, PrinterExt},
};

use super::{consts::*, Options, RiscvOperand};

#[rustfmt::skip]
const X_NAME: [&str; 32] = [
    "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
    "x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "x31",
];

#[rustfmt::skip]
const X_ABI_NAME: [&str; 32] = [
    "zero", "ra",   "sp",   "gp",   "tp",   "t0",   "t1",   "t2",
    "s0",   "s1",   "a0",   "a1",   "a2",   "a3",   "a4",   "a5",
    "a6",   "a7",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
    "s8",   "s9",   "s10",  "s11",  "t3",   "t4",   "t5",   "t6",
];

#[rustfmt::skip]
const F_NAME: [&str; 32] = [
    "f0",  "f1",  "f2",  "f3",  "f4",  "f5",  "f6",  "f7",
    "f8",  "f9",  "f10", "f11", "f12", "f13", "f14", "f15",
    "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23",
    "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31",
];

#[rustfmt::skip]
const F_ABI_NAME: [&str; 32] = [
    "ft0",  "ft1", "ft2",  "ft3",   "ft4",  "ft5", "ft6",  "ft7",
    "fs0",  "fs1", "fa0",  "fa1",   "fa2",  "fa3", "fa4",  "fa5",
    "fa6",  "fa7", "fs2",  "fs3",   "fs4",  "fs5", "fs6",  "fs7",
    "fs8",  "fs9", "fs10", "fs11",  "ft8",  "ft9", "ft10", "ft11",
];

struct Printer {
    abi_regs: bool,
}

impl Printer {
    fn new(opts: &disasm_core::Options, _: &Options) -> Self {
        Self {
            abi_regs: opts.abi_regs,
        }
    }
}

impl<E: PrinterExt> ArchPrinter<E> for Printer {
    fn mnemonic(&self, insn: &Insn) -> Option<(&'static str, &'static str)> {
        super::mnemonic(insn)
    }

    fn register_name(&self, reg: Reg) -> Cow<'static, str> {
        let index = reg.index() as usize;
        match reg.class() {
            RegClass::INT => {
                let names = if self.abi_regs { X_ABI_NAME } else { X_NAME };
                names[index].into()
            }
            RegClass::FLOAT => {
                let names = if self.abi_regs { F_ABI_NAME } else { F_NAME };
                names[index].into()
            }
            reg_class::CSR => match index {
                0x001 => "fflags",
                0x002 => "frm",
                0x003 => "fcsr",
                _ => return format!("csr:{index}").into(),
            }
            .into(),
            _ => todo!(),
        }
    }

    fn print_operand(
        &self,
        fmt: &mut fmt::Formatter,
        ext: &E,
        insn: &Insn,
        operand: &Operand,
    ) -> fmt::Result {
        if let &OperandKind::ArchSpec(id, value, _) = operand.kind() {
            match RiscvOperand::from_u64(id).unwrap() {
                RiscvOperand::Fence => {
                    let fence = ['w', 'r', 'o', 'i'];
                    for i in (0..4).rev() {
                        if value & (1 << i) != 0 {
                            fmt.write_char(fence[i])?;
                        }
                    }
                }
                RiscvOperand::RM => {
                    let s = match value as u8 {
                        operand::RM_RNE => "rne",
                        operand::RM_RTZ => "rtz",
                        operand::RM_RDN => "rdn",
                        operand::RM_RUP => "rup",
                        operand::RM_RMM => "rmm",
                        operand::RM_DYN => "dyn",
                        _ => "unknown",
                    };
                    fmt.write_str(s)?;
                }
            }
            Ok(())
        } else {
            self.print_operand_default(fmt, ext, insn, operand)
        }
    }
}

pub fn printer<E: PrinterExt>(
    opts: &disasm_core::Options,
    opts_arch: &super::Options,
) -> Box<dyn ArchPrinter<E>> {
    Box::new(Printer::new(opts, opts_arch))
}
