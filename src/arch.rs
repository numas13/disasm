#[cfg(feature = "riscv")]
pub mod riscv;

use crate::Bundle;
#[cfg(feature = "mnemonic")]
use crate::Insn;

pub(crate) trait Decoder {
    fn decode(&mut self, address: u64, bytes: &[u8], out: &mut Bundle) -> Result<usize, usize>;

    #[cfg(feature = "mnemonic")]
    fn mnemonic(&self, insn: &Insn) -> Option<(&'static str, &'static str)>;

    fn insn_size_min(&self) -> u16;

    fn insn_size_max(&self) -> u16;

    fn insn_alignment(&self) -> u16 {
        self.insn_size_min()
    }
}
