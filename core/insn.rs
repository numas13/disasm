use core::ops::{Add, Deref};

use alloc::{boxed::Box, vec::Vec};

use crate::{
    flags::Flags,
    operand::{Operand, OperandKind, Reg},
};

pub const INSN_ALIAS: u32 = 1 << 0;

#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct Opcode(pub u32);

impl Opcode {
    pub const INVALID: Self = Self(0);
}

impl Add<u32> for Opcode {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        Self(self.0 + rhs)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slot(u16);

impl Default for Slot {
    fn default() -> Self {
        Self::NONE
    }
}

impl Slot {
    pub const NONE: Self = Self::new(0xffff);

    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    pub const fn raw(&self) -> u16 {
        self.0
    }
}

#[derive(Clone, Default)]
pub struct Insn {
    opcode: Opcode,
    flags: Flags,
    operands: Vec<Operand>,
    slot: Slot,
}

impl Insn {
    pub fn clear(&mut self) {
        self.opcode = Opcode::INVALID;
        self.flags = Flags::empty();
        self.operands.clear();
        self.slot = Slot::NONE;
    }

    pub fn flags(&self) -> &Flags {
        &self.flags
    }

    pub fn flags_mut(&mut self) -> &mut Flags {
        &mut self.flags
    }

    pub fn is_alias(&self) -> bool {
        self.flags.any(INSN_ALIAS)
    }

    pub fn set_alias(&mut self) {
        self.flags.set(INSN_ALIAS);
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }

    pub fn set_slot(&mut self, slot: Slot) {
        self.slot = slot;
    }

    pub fn opcode(&self) -> Opcode {
        self.opcode
    }

    pub fn set_opcode(&mut self, opcode: Opcode) {
        self.opcode = opcode;
    }

    pub fn operands(&self) -> &[Operand] {
        self.operands.as_slice()
    }

    pub fn push_operand<T>(&mut self, operand: T)
    where
        T: Into<Operand>,
    {
        self.operands.push(operand.into());
    }

    pub fn push_operand_if_some<T>(&mut self, operand: Option<T>)
    where
        T: Into<Operand>,
    {
        if let Some(operand) = operand {
            self.operands.push(operand.into());
        }
    }

    pub fn push_reg(&mut self, reg: Reg) {
        self.push_operand(OperandKind::Reg(reg));
    }

    pub fn push_offset(&mut self, reg: Reg, offset: i64) {
        self.push_operand(OperandKind::Relative(reg, offset));
    }

    pub fn push_imm(&mut self, value: i64) {
        self.push_operand(OperandKind::Imm(value));
    }

    pub fn push_uimm(&mut self, value: u64) {
        self.push_operand(OperandKind::Uimm(value));
    }

    pub fn push_absolute(&mut self, addr: u64) {
        self.push_operand(OperandKind::Absolute(addr));
    }

    pub fn push_indirect(&mut self, reg: Reg) {
        self.push_operand(OperandKind::Indirect(reg));
    }

    pub fn push_pc_rel(&mut self, base: u64, offset: i64) {
        self.push_operand(OperandKind::PcRelative(base, offset));
    }

    pub fn push_arch_spec(&mut self, a: u64, b: u64, c: u64) {
        self.push_operand(OperandKind::ArchSpec(a, b, c));
    }

    pub fn push_arch_spec3(&mut self, a: impl Into<u64>, b: impl Into<u64>, c: impl Into<u64>) {
        self.push_arch_spec(a.into(), b.into(), c.into());
    }

    pub fn push_arch_spec2(&mut self, a: impl Into<u64>, b: impl Into<u64>) {
        self.push_arch_spec3(a, b, 0_u64);
    }

    pub fn push_arch_spec1(&mut self, a: impl Into<u64>) {
        self.push_arch_spec2(a, 0_u64);
    }
}

pub struct Bundle {
    len: usize,
    latency: u8,
    insn: Box<[Insn]>,
}

impl Bundle {
    pub fn empty() -> Self {
        Self {
            len: 0,
            latency: 1,
            insn: Box::new([]),
        }
    }

    #[inline]
    pub fn set_latency(&mut self, latency: u8) {
        self.latency = latency;
    }

    #[inline]
    pub fn latency(&self) -> usize {
        self.latency as usize
    }

    pub fn as_slice(&self) -> &[Insn] {
        &self.insn[..self.len]
    }

    pub fn clear(&mut self) {
        self.len = 0;
        self.latency = 1;
    }

    /// Take instruction to decode
    pub fn peek(&mut self) -> &mut Insn {
        if self.insn.len() <= self.len {
            let mut vec = core::mem::take(&mut self.insn).into_vec();
            vec.resize(self.len + 4, Insn::default());
            self.insn = vec.into_boxed_slice();
        }
        let insn = &mut self.insn[self.len];
        insn.clear();
        insn
    }

    /// Previous peek was succesfull, advance to next instruction
    pub fn next(&mut self) {
        self.len += 1;
    }

    pub fn push_with<F>(&mut self, opcode: Opcode, mut f: F)
    where
        F: FnMut(&mut Insn),
    {
        let insn = self.peek();
        insn.set_opcode(opcode);
        f(insn);
        self.next();
    }

    pub fn push(&mut self, opcode: Opcode) {
        self.push_with(opcode, |_| ());
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
