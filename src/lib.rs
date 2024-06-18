#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod arch;
mod insn;
mod operand;
mod utils;

use core::fmt;

use alloc::boxed::Box;

use crate::arch::Decoder;

pub use crate::insn::{Bundle, Insn, Opcode};
pub use crate::operand::{Operand, Reg};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Unsupported => write!(fmt, "Unsupported achitecture"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Arch {
    Riscv,
}

#[derive(Copy, Clone)]
pub struct Options {
    pub alias: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { alias: true }
    }
}

pub struct Disasm {
    address: u64,
    decoder: Box<dyn Decoder>,
}

impl Disasm {
    fn new_decoder(arch: Arch, opts: Options) -> Result<Box<dyn Decoder>, Error> {
        #[cfg(feature = "riscv")]
        if arch == Arch::Riscv {
            return Ok(Box::new(crate::arch::riscv::RiscvDecoder::new(opts)));
        }

        Err(Error::Unsupported)
    }

    pub fn new(arch: Arch, address: u64, opts: Options) -> Result<Self, Error> {
        Ok(Self {
            decoder: Self::new_decoder(arch, opts)?,
            address,
        })
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn decode(&mut self, bytes: &[u8], out: &mut Bundle) -> Result<usize, usize> {
        out.clear();
        match self.decoder.decode(self.address, bytes, out) {
            Ok(len) => {
                self.address += len as u64;
                Ok(len)
            }
            Err(len) => {
                self.address += len as u64;
                Err(len)
            }
        }
    }
}

#[cfg(feature = "print")]
pub trait PrinterInfo {
    fn get_symbol(&self, _address: u64) -> Option<(u64, &str)> {
        None
    }
}

#[cfg(feature = "print")]
impl PrinterInfo for () {}
