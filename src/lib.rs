#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod arch;
mod insn;
mod operand;
#[cfg(feature = "print")]
mod printer;
mod utils;

use core::fmt;

use alloc::boxed::Box;

use crate::arch::Decoder;
#[cfg(feature = "print")]
use crate::printer::Printer;

pub use crate::insn::{Bundle, Insn, Opcode};
pub use crate::operand::{Operand, OperandKind, Reg, RegClass};

#[cfg(feature = "print")]
pub use crate::printer::PrinterInfo;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Need more bits to decode an instruction.
    More(usize),
    /// Failed to decode an instruction.
    Failed(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::More(_) => fmt.write_str("Need more data"),
            Self::Failed(_) => fmt.write_str("Failed to decode"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[derive(Copy, Clone)]
pub enum Arch {
    #[cfg(feature = "riscv")]
    Riscv(crate::arch::riscv::Options),
}

impl Arch {
    pub fn bytes_per_line(&self) -> usize {
        match self {
            #[cfg(feature = "riscv")]
            Arch::Riscv(..) => 8,
        }
    }

    pub fn bytes_per_chunk(&self, len: usize) -> usize {
        match self {
            #[cfg(feature = "riscv")]
            Arch::Riscv(..) => len,
        }
    }

    pub fn skip_zeroes(&self) -> usize {
        match self {
            #[cfg(feature = "riscv")]
            Arch::Riscv(..) => 2,
        }
    }
}

#[derive(Copy, Clone)]
pub struct Options {
    pub alias: bool,
    pub abi_regs: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            alias: true,
            abi_regs: true,
        }
    }
}

pub struct Disasm {
    address: u64,
    insn_alignment: u16,
    insn_size_min: u16,
    insn_size_max: u16,
    decoder: Box<dyn Decoder>,
    #[cfg(feature = "print")]
    printer: Box<dyn Printer>,
}

impl Disasm {
    fn new_decoder(arch: Arch, opts: Options) -> Box<dyn Decoder> {
        use crate::arch::*;
        match arch {
            #[cfg(feature = "riscv")]
            Arch::Riscv(arch_opts) => riscv::decoder(opts, arch_opts),
        }
    }

    #[cfg(feature = "print")]
    fn new_printer(arch: Arch, opts: Options) -> Box<dyn Printer> {
        use crate::arch::*;
        match arch {
            #[cfg(feature = "riscv")]
            Arch::Riscv(arch_opts) => riscv::printer(opts, arch_opts),
        }
    }

    pub fn new(arch: Arch, address: u64, opts: Options) -> Self {
        let decoder = Self::new_decoder(arch, opts);
        #[cfg(feature = "print")]
        let printer = Self::new_printer(arch, opts);
        Self {
            address,
            insn_alignment: decoder.insn_alignment(),
            insn_size_min: decoder.insn_size_min(),
            insn_size_max: decoder.insn_size_max(),
            decoder,
            #[cfg(feature = "print")]
            printer,
        }
    }

    /// Current decoding address.
    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn decode(&mut self, bytes: &[u8], out: &mut Bundle) -> Result<usize, Error> {
        out.clear();
        match self.decoder.decode(self.address, bytes, out) {
            Ok(bits) => {
                assert!(bits & 7 == 0);
                let len = bits / 8;
                self.address += len as u64;
                Ok(len)
            }
            Err(Error::More(bits)) => Err(Error::More((bits + 7) / 8)),
            Err(Error::Failed(bits)) => {
                assert!(bits & 7 == 0);
                Err(Error::Failed(bits / 8))
            }
        }
    }

    /// Do not decode `size` bytes.
    pub fn skip(&mut self, size: usize) {
        self.address += size as u64;
    }

    pub fn insn_alignemt(&self) -> usize {
        self.insn_alignment as usize
    }

    pub fn insn_size_min(&self) -> usize {
        self.insn_size_min as usize
    }

    pub fn insn_size_max(&self) -> usize {
        self.insn_size_max as usize
    }
}
