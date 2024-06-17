#[cfg(feature = "print")]
use core::fmt;

#[cfg(feature = "print")]
use crate::Disasm;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Operand {
    /// reg
    Reg(u16),
    /// reg + offset
    Offset(u16, i64),
    /// sign-extended immediate
    Imm(i64),
    /// zero-extended immediate
    Uimm(u64),
    /// address
    Address(u64),
    /// address in reg
    AddressReg(u16),
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
        match operand {
            Operand::Reg(reg) => {
                write!(fmt, "{}", disasm.decoder.register_name(*reg).unwrap())?;
            }
            Operand::Offset(reg, imm) => {
                write!(
                    fmt,
                    "{imm}({})",
                    disasm.decoder.register_name(*reg).unwrap()
                )?;
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
                write!(fmt, "({})", disasm.decoder.register_name(*reg).unwrap())?;
            }
        }
        Ok(())
    }
}
