#[cfg(feature = "riscv")]
pub mod riscv;

use crate::{Bundle, Insn, Reg};

pub(crate) trait Decoder {
    fn decode(&mut self, address: u64, bytes: &[u8], out: &mut Bundle) -> Result<usize, usize>;

    #[cfg(feature = "print")]
    fn register_name(&self, reg: Reg) -> Option<&'static str>;

    #[cfg(feature = "mnemonic")]
    fn mnemonic(&self, insn: &Insn) -> Option<(&'static str, &'static str)>;
}
