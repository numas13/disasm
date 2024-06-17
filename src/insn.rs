#[cfg(feature = "print")]
use core::fmt;

use alloc::vec::Vec;

use crate::Operand;
#[cfg(feature = "print")]
use crate::PrinterInfo;

const INSN_ALIAS: u32 = 1 << 0;

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct Opcode(pub(crate) u32);

#[derive(Clone, Default)]
pub struct Insn {
    opcode: Opcode,
    flags: u32,
    operands: Vec<Operand>,
}

impl Insn {
    pub(crate) fn clear(&mut self) {
        self.opcode = Opcode(0);
        self.flags = 0;
        self.operands.clear();
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
            for (i, operand) in insn.operands().iter().enumerate() {
                if i != 0 {
                    write!(fmt, ",")?;
                }
                write!(fmt, "{}", operand.printer(disasm))?;
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
