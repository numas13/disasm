#[cfg(feature = "riscv")]
pub mod riscv;

#[cfg(feature = "print")]
use core::fmt;

use alloc::borrow::Cow;

use crate::{Bundle, Insn, Operand, Reg};

pub(crate) trait Decoder {
    fn decode(&mut self, address: u64, bytes: &[u8], out: &mut Bundle) -> Result<usize, usize>;

    #[cfg(feature = "print")]
    fn register_name(&self, reg: Reg) -> Cow<'static, str>;

    #[cfg(feature = "mnemonic")]
    fn mnemonic(&self, insn: &Insn) -> Option<(&'static str, &'static str)>;

    #[cfg(feature = "print")]
    #[allow(unused_variables)]
    fn print_operand_check(&self, operand: &Operand) -> bool {
        true
    }

    #[cfg(feature = "print")]
    #[allow(unused_variables)]
    fn print_operand(
        &self,
        fmt: &mut fmt::Formatter,
        operand: &Operand,
    ) -> Result<bool, fmt::Error> {
        Ok(true)
    }
}
