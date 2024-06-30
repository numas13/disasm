use core::fmt;

#[cfg(feature = "print")]
use crate::Disasm;

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

    pub(crate) const fn write(mut self) -> Self {
        self.raw |= Self::WRITE_BIT;
        self
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
    /// reg + offset
    Offset(Reg, i64),
    /// sign-extended immediate
    Imm(i64),
    /// zero-extended immediate
    Uimm(u64),
    /// address
    Address(u64),
    /// address in reg
    AddressReg(Reg),
    /// architecture specific operand
    ArchSpec(u64, u64),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Operand {
    kind: OperandKind,
    printable: bool,
}

impl Operand {
    pub(crate) fn new(kind: OperandKind) -> Self {
        Self {
            kind,
            printable: true,
        }
    }

    pub(crate) fn reg(reg: Reg) -> Self {
        Self::new(OperandKind::Reg(reg))
    }

    pub(crate) fn non_printable(mut self, non_printable: bool) -> Self {
        self.printable = !non_printable;
        self
    }

    pub fn kind(&self) -> &OperandKind {
        &self.kind
    }

    pub fn is_printable(&self) -> bool {
        self.printable
    }

    #[cfg(feature = "print")]
    pub fn printer<'a>(&'a self, disasm: &'a Disasm) -> Printer<'a> {
        Printer(disasm, self)
    }
}

impl From<OperandKind> for Operand {
    fn from(value: OperandKind) -> Self {
        Operand::new(value)
    }
}

#[cfg(feature = "print")]
pub struct Printer<'a>(&'a Disasm, &'a Operand);

#[cfg(feature = "print")]
impl fmt::Display for Printer<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let Self(disasm, operand) = self;
        if !operand.is_printable() || disasm.printer.print_operand(fmt, operand)? {
            return Ok(());
        }
        match &operand.kind {
            OperandKind::Reg(reg) => {
                let reg_name = disasm.printer.register_name(*reg);
                fmt.write_str(&reg_name)?;
            }
            OperandKind::Offset(reg, imm) => {
                let reg_name = disasm.printer.register_name(*reg);
                write!(fmt, "{imm}({reg_name})")?;
            }
            OperandKind::Imm(imm) => {
                write!(fmt, "{imm}")?;
            }
            OperandKind::Uimm(imm) => {
                write!(fmt, "{imm:#x}")?;
            }
            OperandKind::Address(addr) => {
                write!(fmt, "{addr:x}")?;
            }
            OperandKind::AddressReg(reg) => {
                let reg_name = disasm.printer.register_name(*reg);
                write!(fmt, "({reg_name})")?;
            }
            OperandKind::ArchSpec(..) => todo!(),
        }
        Ok(())
    }
}
