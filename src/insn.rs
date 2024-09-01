#[cfg(feature = "print")]
use core::fmt;
use core::ops::Deref;

use alloc::vec::Vec;

#[cfg(feature = "print")]
use crate::printer::{FormatterFn, PrinterExt};
use crate::{flags::Flags, Operand, OperandKind, Reg};

const INSN_ALIAS: u32 = 1 << 0;

#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct Opcode(pub(crate) u32);

impl std::ops::Add<u32> for Opcode {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        Self(self.0 + rhs)
    }
}

#[derive(Clone, Default)]
pub struct Insn {
    opcode: Opcode,
    flags: Flags,
    operands: Vec<Operand>,
    slot: u16,
}

impl Insn {
    pub(crate) fn clear(&mut self) {
        self.opcode = Opcode(0);
        self.flags = Flags::empty();
        self.operands.clear();
        self.slot = 0;
    }

    pub(crate) fn flags(&self) -> &Flags {
        &self.flags
    }

    pub(crate) fn flags_mut(&mut self) -> &mut Flags {
        &mut self.flags
    }

    pub fn is_alias(&self) -> bool {
        self.flags.any(INSN_ALIAS)
    }

    pub(crate) fn set_alias(&mut self) {
        self.flags.set(INSN_ALIAS);
    }

    pub fn opcode(&self) -> Opcode {
        self.opcode
    }

    pub(crate) fn set_opcode(&mut self, opcode: Opcode) {
        self.opcode = opcode
    }

    pub fn operands(&self) -> &[Operand] {
        self.operands.as_slice()
    }

    pub(crate) fn push_operand<T>(&mut self, operand: T)
    where
        T: Into<Operand>,
    {
        self.operands.push(operand.into());
    }

    pub(crate) fn push_operand_if_some<T>(&mut self, operand: Option<T>)
    where
        T: Into<Operand>,
    {
        if let Some(operand) = operand {
            self.operands.push(operand.into());
        }
    }

    pub(crate) fn push_reg(&mut self, reg: Reg) {
        self.push_operand(OperandKind::Reg(reg));
    }

    pub(crate) fn push_offset(&mut self, reg: Reg, offset: i64) {
        self.push_operand(OperandKind::Relative(reg, offset));
    }

    pub(crate) fn push_imm(&mut self, value: i64) {
        self.push_operand(OperandKind::Imm(value));
    }

    pub(crate) fn push_uimm(&mut self, value: u64) {
        self.push_operand(OperandKind::Uimm(value));
    }

    pub(crate) fn push_absolute(&mut self, addr: u64) {
        self.push_operand(OperandKind::Absolute(addr));
    }

    pub(crate) fn push_indirect(&mut self, reg: Reg) {
        self.push_operand(OperandKind::Indirect(reg));
    }

    pub(crate) fn push_arch_spec(&mut self, a: u64, b: u64, c: u64) {
        self.push_operand(OperandKind::ArchSpec(a, b, c));
    }

    #[cfg(feature = "print")]
    pub fn printer<'a, E>(&'a self, printer: &'a crate::Printer<E>) -> Printer<'a, E>
    where
        E: PrinterExt,
    {
        Printer(self, printer)
    }
}

#[cfg(feature = "print")]
pub struct Printer<'a, E: PrinterExt>(&'a Insn, &'a crate::Printer<E>);

#[cfg(feature = "print")]
impl<'a, E: PrinterExt> Printer<'a, E> {
    pub fn mnemonic(&self) -> impl fmt::Display + '_ {
        FormatterFn(|fmt| {
            let Printer(insn, printer) = self;
            printer
                .inner()
                .print_mnemonic(fmt, printer.ext(), insn, false)
        })
    }

    pub fn operands(&self) -> impl fmt::Display + '_ {
        FormatterFn(|fmt| {
            let Printer(insn, printer) = self;
            printer.inner().print_operands(fmt, printer.ext(), insn)
        })
    }
}

#[cfg(feature = "print")]
impl<E: PrinterExt> fmt::Display for Printer<'_, E> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let Printer(insn, printer) = self;
        printer.inner().print_insn(fmt, printer.ext(), insn)
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
