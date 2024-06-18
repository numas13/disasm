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
    pub(crate) const fn new(class: RegClass, index: u64) -> Self {
        assert!(index < (1 << 48));
        Self {
            raw: ((class.0 as u64) << 48) | index,
        }
    }

    pub const fn class(&self) -> RegClass {
        RegClass((self.raw >> 48) as u16)
    }

    pub const fn index(&self) -> u64 {
        self.raw & ((1 << 48) - 1)
    }
}

impl fmt::Debug for Reg {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "<{}:{}>", self.class(), self.index())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Operand {
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

impl Operand {
    #[cfg(feature = "print")]
    pub fn printer<'a>(&'a self, disasm: &'a Disasm) -> Printer<'a> {
        Printer(disasm, self)
    }
}

#[cfg(feature = "print")]
pub struct Printer<'a>(&'a Disasm, &'a Operand);

#[cfg(feature = "print")]
impl fmt::Display for Printer<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let Self(disasm, operand) = self;
        if disasm.decoder.print_operand(fmt, operand)? {
            return Ok(());
        }
        match operand {
            Operand::Reg(reg) => {
                let reg = disasm.decoder.register_name(*reg);
                fmt.write_str(&reg)?;
            }
            Operand::Offset(reg, imm) => {
                let reg = disasm.decoder.register_name(*reg);
                write!(fmt, "{imm}({reg})")?;
            }
            Operand::Imm(imm) => {
                write!(fmt, "{imm}")?;
            }
            Operand::Uimm(imm) => {
                write!(fmt, "{imm:#x}")?;
            }
            Operand::Address(addr) => {
                write!(fmt, "{addr:x}")?;
            }
            Operand::AddressReg(reg) => {
                let reg = disasm.decoder.register_name(*reg);
                write!(fmt, "({reg})")?;
            }
            Operand::ArchSpec(..) => todo!(),
        }
        Ok(())
    }
}
