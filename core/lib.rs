extern crate alloc;

pub mod bytes;
pub mod error;
pub mod flags;
pub mod insn;
pub mod macros;
pub mod operand;
pub mod utils;

#[cfg(feature = "print")]
pub mod printer;
#[cfg(feature = "print")]
pub mod symbols;

use crate::{error::Error, insn::Bundle};

pub trait ArchDecoder {
    fn decode(&mut self, address: u64, bytes: &[u8], out: &mut Bundle) -> Result<usize, Error>;
}

#[derive(Copy, Clone)]
pub struct Options {
    pub alias: bool,
    pub abi_regs: bool,
    pub decode_zeroes: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            alias: true,
            abi_regs: true,
            decode_zeroes: false,
        }
    }
}
