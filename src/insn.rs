#[cfg(feature = "print")]
use core::fmt;
use core::ops::Deref;

use alloc::vec::Vec;

#[cfg(feature = "print")]
use crate::PrinterInfo;
use crate::{Operand, Reg};

const INSN_ALIAS: u32 = 1 << 0;

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct Opcode(pub(crate) u32);

#[derive(Clone, Default)]
pub struct Insn {
    opcode: Opcode,
    flags: u32,
    operands: Vec<Operand>,
    slot: u16,
}

impl Insn {
    pub(crate) fn clear(&mut self) {
        self.opcode = Opcode(0);
        self.flags = 0;
        self.operands.clear();
        self.slot = 0;
    }

    pub(crate) fn flags(&self) -> u32 {
        self.flags
    }

    pub(crate) fn insert_flags(&mut self, cond: bool, flags: u32) {
        if cond {
            self.flags |= flags;
        }
    }

    pub fn is_alias(&self) -> bool {
        self.flags & INSN_ALIAS != 0
    }

    pub(crate) fn set_alias(&mut self) {
        self.insert_flags(true, INSN_ALIAS);
    }

    pub fn opcode(&self) -> Opcode {
        self.opcode
    }

    pub(crate) fn set_opcode(&mut self, opcode: Opcode) {
        self.opcode = opcode
    }

    #[cfg(feature = "mnemonic")]
    pub fn mnemonic(&self, disasm: &crate::Disasm) -> Option<(&'static str, &'static str)> {
        disasm.decoder.mnemonic(self)
    }

    pub fn operands(&self) -> &[Operand] {
        self.operands.as_slice()
    }

    pub(crate) fn push_operand(&mut self, operand: Operand) {
        self.operands.push(operand);
    }

    pub(crate) fn push_reg(&mut self, reg: Reg) {
        self.push_operand(Operand::Reg(reg));
    }

    pub(crate) fn push_offset(&mut self, reg: Reg, offset: i64) {
        self.push_operand(Operand::Offset(reg, offset));
    }

    pub(crate) fn push_imm(&mut self, value: i64) {
        self.push_operand(Operand::Imm(value));
    }

    pub(crate) fn push_uimm(&mut self, value: u64) {
        self.push_operand(Operand::Uimm(value));
    }

    pub(crate) fn push_addr(&mut self, addr: u64) {
        self.push_operand(Operand::Address(addr));
    }

    pub(crate) fn push_addr_reg(&mut self, reg: Reg) {
        self.push_operand(Operand::AddressReg(reg));
    }

    pub(crate) fn push_arch_spec(&mut self, val0: u64, val1: u64) {
        self.push_operand(Operand::ArchSpec(val0, val1));
    }

    #[cfg(feature = "print")]
    pub fn printer<'a, I>(&'a self, disasm: &'a crate::Disasm, info: I) -> Printer<'a, I>
    where
        I: PrinterInfo,
    {
        Printer(self, disasm, info)
    }
}

#[cfg(feature = "print")]
pub struct Printer<'a, I: PrinterInfo>(&'a Insn, &'a crate::Disasm, I);

#[cfg(feature = "print")]
impl<I> fmt::Display for Printer<'_, I>
where
    I: PrinterInfo,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let Printer(insn, disasm, info) = self;
        let (mnemonic, sub) = insn.mnemonic(disasm).unwrap_or(("<invalid>", ""));
        write!(fmt, "{mnemonic}")?;
        if !sub.is_empty() {
            write!(fmt, ".{sub}")?;
        }
        if !insn.operands().is_empty() {
            write!(fmt, "\t")?;
            for (i, operand) in insn
                .operands()
                .iter()
                .filter(|i| disasm.printer.print_operand_check(i))
                .enumerate()
            {
                if i != 0 {
                    write!(fmt, ",")?;
                }
                operand.printer(disasm).fmt(fmt)?;
                if let Operand::Address(addr) = operand {
                    if let Some((sym_addr, sym_name)) = info.get_symbol(*addr) {
                        write!(fmt, " <{sym_name}")?;
                        let diff = addr - sym_addr;
                        if diff != 0 {
                            write!(fmt, "+{diff:#x}")?;
                        }
                        write!(fmt, ">")?;
                    }
                }
            }
        }
        Ok(())
    }
}

pub struct Bundle {
    len: usize,
    insn: Box<[Insn]>,
}

impl Bundle {
    pub fn empty() -> Self {
        Self {
            len: 0,
            insn: Box::new([]),
        }
    }

    pub fn as_slice(&self) -> &[Insn] {
        &self.insn[..self.len]
    }

    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }

    /// Take instruction to decode
    pub(crate) fn peek(&mut self) -> &mut Insn {
        if self.insn.len() <= self.len {
            let mut vec = core::mem::take(&mut self.insn).into_vec();
            vec.resize(self.len + 1, Insn::default());
            self.insn = vec.into_boxed_slice();
        }
        let insn = &mut self.insn[self.len];
        insn.clear();
        insn
    }

    /// Previous peek was succesfull, advance to next instruction
    pub(crate) fn next(&mut self) {
        self.len += 1;
    }
}

impl Deref for Bundle {
    type Target = [Insn];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<'a> IntoIterator for &'a Bundle {
    type Item = &'a Insn;
    type IntoIter = core::slice::Iter<'a, Insn>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
