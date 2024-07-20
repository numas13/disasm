use core::fmt;

use crate::flags::Flags;
#[cfg(feature = "print")]
use crate::{Disasm, Insn, PrinterInfo};

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    ReadWrite,
}

impl Access {
    pub const fn is_read(&self) -> bool {
        !matches!(*self, Self::Write)
    }

    pub const fn is_write(&self) -> bool {
        !matches!(*self, Self::Read)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct RegClass(pub(crate) u16);

impl RegClass {
    pub const INT: Self = Self::new(0);
    pub const FLOAT: Self = Self::new(1);
    pub const VECTOR: Self = Self::new(2);

    pub const fn is_arch_specific(&self) -> bool {
        self.0 & (1 << 15) != 0
    }

    pub(crate) const fn new(class: u16) -> Self {
        Self(class)
    }

    pub(crate) const fn arch(class: u16) -> Self {
        Self(class | (1 << 15))
    }

    const fn to_arch_index(self) -> u16 {
        self.0 & ((1 << 15) - 1)
    }
}

impl fmt::Display for RegClass {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::INT => fmt.write_str("int"),
            Self::FLOAT => fmt.write_str("float"),
            Self::VECTOR => fmt.write_str("vector"),
            _ if self.is_arch_specific() => write!(fmt, "arch({})", self.to_arch_index()),
            _ => write!(fmt, "invalid({})", self.0),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Reg {
    raw: u64,
}

impl Reg {
    const INDEX_SIZE: u32 = 40;

    const READ_BIT: u64 = 1 << 40;
    const WRITE_BIT: u64 = 1 << 41;
    const IMPLICIT_BIT: u64 = 1 << 42;

    const CLASS_OFFSET: u32 = 48;

    pub(crate) const fn new(class: RegClass, index: u64) -> Self {
        assert!(index < (1 << Self::INDEX_SIZE));
        Self {
            raw: ((class.0 as u64) << Self::CLASS_OFFSET) | index,
        }
    }

    pub(crate) const fn read(mut self) -> Self {
        self.raw |= Self::READ_BIT;
        self
    }

    pub(crate) const fn read_if(mut self, cond: bool) -> Self {
        if cond {
            self.raw |= Self::READ_BIT;
        }
        self
    }

    pub(crate) const fn write(mut self) -> Self {
        self.raw |= Self::WRITE_BIT;
        self
    }

    pub(crate) const fn write_if(mut self, cond: bool) -> Self {
        if cond {
            self.raw |= Self::WRITE_BIT;
        }
        self
    }

    pub(crate) const fn access(self, access: Access) -> Self {
        self.read_if(access.is_read()).write_if(access.is_write())
    }

    pub(crate) const fn implicit(mut self) -> Self {
        self.raw |= Self::IMPLICIT_BIT;
        self
    }

    pub const fn class(&self) -> RegClass {
        RegClass((self.raw >> Self::CLASS_OFFSET) as u16)
    }

    pub const fn index(&self) -> u64 {
        self.raw & ((1 << Self::INDEX_SIZE) - 1)
    }

    pub const fn is_read(&self) -> bool {
        (self.raw & Self::READ_BIT) != 0
    }

    pub const fn is_write(&self) -> bool {
        (self.raw & Self::WRITE_BIT) != 0
    }

    pub const fn is_implicit(&self) -> bool {
        (self.raw & Self::IMPLICIT_BIT) != 0
    }
}

impl fmt::Debug for Reg {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "<{}:{}>", self.class(), self.index())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OperandKind {
    /// reg
    Reg(Reg),
    /// sign-extended immediate
    Imm(i64),
    /// zero-extended immediate
    Uimm(u64),
    /// base
    Indirect(Reg),
    /// base + offset
    Relative(Reg, i64),
    /// base + index
    Indexed(Reg, Reg),
    /// base + index + offset
    IndexedRelative(Reg, Reg, i32),
    /// base + index * scale
    ScaledIndex(Reg, Reg, u8),
    /// base + index * scale + offset
    ScaledIndexRelative(Reg, Reg, u8, i32),
    /// absolute address
    Absolute(u64),
    /// pc-relative address
    PcRelative(i64),
    /// architecture specific operand
    ArchSpec(u64, u64, u64),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Operand {
    kind: OperandKind,
    flags: Flags,
}

impl Operand {
    const NO_PRINT: u32 = 1;

    pub(crate) fn new(kind: OperandKind) -> Self {
        Self {
            kind,
            flags: Flags::empty(),
        }
    }

    pub(crate) fn reg(reg: Reg) -> Self {
        Self::new(OperandKind::Reg(reg))
    }

    pub(crate) fn arch(a: u64, b: u64, c: u64) -> Self {
        Self::new(OperandKind::ArchSpec(a, b, c))
    }

    pub(crate) fn non_printable(mut self, non_printable: bool) -> Self {
        self.flags.set_if(Self::NO_PRINT, non_printable);
        self
    }

    pub fn kind(&self) -> &OperandKind {
        &self.kind
    }

    pub fn is_printable(&self) -> bool {
        !self.flags.any(Self::NO_PRINT)
    }

    pub(crate) fn flags(&self) -> &Flags {
        &self.flags
    }

    pub(crate) fn flags_mut(&mut self) -> &mut Flags {
        &mut self.flags
    }

    #[cfg(feature = "print")]
    pub fn printer<'a>(
        &'a self,
        disasm: &'a Disasm,
        info: &'a dyn PrinterInfo,
        insn: &'a Insn,
    ) -> Printer<'a> {
        Printer(disasm, info, insn, self)
    }
}

impl From<OperandKind> for Operand {
    fn from(value: OperandKind) -> Self {
        Operand::new(value)
    }
}

#[cfg(feature = "print")]
pub struct Printer<'a>(&'a Disasm, &'a dyn PrinterInfo, &'a Insn, &'a Operand);

#[cfg(feature = "print")]
impl fmt::Display for Printer<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let Self(disasm, info, insn, operand) = self;
        disasm
            .printer
            .print_operand(fmt, disasm, *info, insn, operand)
    }
}
