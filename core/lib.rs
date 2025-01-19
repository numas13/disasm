#![cfg_attr(not(feature = "std"), no_std)]

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
    /// Decode bundle from bytes.
    fn decode(&mut self, address: u64, bytes: &[u8], out: &mut Bundle) -> Result<usize, Error>;

    /// Decode bundle length from bytes.
    fn decode_len(&mut self, address: u64, bytes: &[u8], tmp: &mut Bundle) -> Result<usize, Error> {
        self.decode(address, bytes, tmp)
    }
}

#[derive(Copy, Clone)]
pub struct Options {
    pub alias: bool,
    pub abi_regs: bool,
    pub decode_zeroes: bool,
    pub show_raw_insn: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            alias: true,
            abi_regs: true,
            decode_zeroes: false,
            show_raw_insn: true,
        }
    }
}
