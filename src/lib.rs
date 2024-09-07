#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod arch;
mod bytes;
mod flags;
mod insn;
mod operand;
mod utils;

#[cfg(feature = "print")]
mod printer;

use core::fmt;

use alloc::boxed::Box;

pub use crate::insn::{Bundle, Insn, Opcode, Slot};
pub use crate::operand::{Access, Operand, OperandKind, Reg, RegClass};

#[cfg(feature = "print")]
pub use crate::printer::{Printer, PrinterExt, Style, Symbols};

#[cfg(feature = "print")]
use crate::printer::ArchPrinter;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Need more bytes to decode an instruction.
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

#[non_exhaustive]
#[derive(Copy, Clone)]
pub enum Arch {
    #[cfg(feature = "e2k")]
    E2K(crate::arch::e2k::Options),
    #[cfg(feature = "riscv")]
    Riscv(crate::arch::riscv::Options),
    #[cfg(feature = "x86")]
    X86(crate::arch::x86::Options),
}

impl Arch {
    pub fn bytes_per_line(&self) -> usize {
        match self {
            #[cfg(feature = "e2k")]
            Arch::E2K(..) => 8,
            #[cfg(feature = "riscv")]
            Arch::Riscv(..) => 8,
            #[cfg(feature = "x86")]
            Arch::X86(..) => 7,
        }
    }

    #[allow(unused_variables)]
    pub fn bytes_per_chunk(&self, len: usize) -> usize {
        match self {
            #[cfg(feature = "e2k")]
            Arch::E2K(..) => 4,
            #[cfg(feature = "riscv")]
            Arch::Riscv(..) => len,
            #[cfg(feature = "x86")]
            Arch::X86(..) => 1,
        }
    }

    pub fn skip_zeroes(&self) -> usize {
        match self {
            #[cfg(feature = "e2k")]
            Arch::E2K(..) => 8,
            #[cfg(feature = "riscv")]
            Arch::Riscv(..) => 2,
            #[cfg(feature = "x86")]
            Arch::X86(..) => 8,
        }
    }

    pub fn addr_size(&self) -> usize {
        match self {
            #[cfg(feature = "e2k")]
            Arch::E2K(..) => 64, // TODO:
            #[cfg(feature = "riscv")]
            Arch::Riscv(opts) => match opts.xlen {
                arch::riscv::Xlen::X32 => 32,
                arch::riscv::Xlen::X64 => 64,
                arch::riscv::Xlen::X128 => 128,
            },
            #[cfg(feature = "x86")]
            Arch::X86(opts) => {
                if opts.ext.amd64 {
                    64
                } else {
                    32
                }
            }
        }
    }

    pub fn insn_size_min(&self) -> usize {
        match self {
            #[cfg(feature = "e2k")]
            Arch::E2K(..) => 8,
            #[cfg(feature = "riscv")]
            Arch::Riscv(opts) => {
                if opts.ext.c {
                    2
                } else {
                    4
                }
            }
            #[cfg(feature = "x86")]
            Arch::X86(..) => 1,
        }
    }

    pub fn insn_size_max(&self) -> usize {
        match self {
            #[cfg(feature = "e2k")]
            Arch::E2K(..) => 64,
            #[cfg(feature = "riscv")]
            Arch::Riscv(..) => 4,
            #[cfg(feature = "x86")]
            Arch::X86(..) => 15,
        }
    }

    pub fn insn_alignment(&self) -> usize {
        self.insn_size_min()
    }
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

trait ArchDecoder {
    fn decode(&mut self, address: u64, bytes: &[u8], out: &mut Bundle) -> Result<usize, Error>;
}

pub struct Decoder {
    address: u64,
    opts: Options,
    arch: Arch,
    bundle: Bundle,
    decoder: Box<dyn ArchDecoder>,
}

impl Decoder {
    pub fn new(arch: Arch, address: u64, opts: Options) -> Self {
        use crate::arch::*;

        let decoder = match arch {
            #[cfg(feature = "e2k")]
            Arch::E2K(arch_opts) => e2k::decoder(opts, arch_opts),
            #[cfg(feature = "riscv")]
            Arch::Riscv(arch_opts) => riscv::decoder(opts, arch_opts),
            #[cfg(feature = "x86")]
            Arch::X86(arch_opts) => x86::decoder(opts, arch_opts),
        };

        Self {
            address,
            opts,
            arch,
            bundle: Bundle::empty(),
            decoder,
        }
    }

    #[cfg(feature = "print")]
    pub fn printer<E: PrinterExt>(self, ext: E, section_name: &str) -> Printer<E> {
        Printer::new(self, ext, section_name)
    }

    /// Current decoding address.
    pub fn address(&self) -> u64 {
        self.address
    }

    // XXX: What to return the number of bytes or the number of bits?
    pub fn decode(&mut self, bytes: &[u8], out: &mut Bundle) -> Result<usize, Error> {
        match self.decoder.decode(self.address, bytes, out) {
            Ok(bits) => {
                debug_assert!(bits & 7 == 0);
                let len = bits / 8;
                self.address += len as u64;
                Ok(len)
            }
            Err(Error::More(bits)) => Err(Error::More((bits + 7) / 8)),
            Err(Error::Failed(bits)) => {
                debug_assert!(bits & 7 == 0);
                Err(Error::Failed(bits / 8))
            }
        }
    }

    // XXX: Same question as above.
    pub fn decode_len(&mut self, data: &[u8]) -> usize {
        let skip_zeroes = self.arch.skip_zeroes();
        let mut address = self.address;
        let mut cur = data;
        while !cur.is_empty() {
            if !self.opts.decode_zeroes {
                if cur.len() < skip_zeroes {
                    break;
                }
                if cur.iter().take(skip_zeroes).all(|i| *i == 0) {
                    let zeroes = match cur.iter().position(|i| *i != 0) {
                        Some(i) => i,
                        None => break,
                    };
                    if zeroes >= (skip_zeroes * 2 - 1) {
                        cur = &cur[zeroes & !(skip_zeroes - 1)..];
                        continue;
                    }
                }
            }
            self.bundle.clear();
            // TODO: optimize, backends know better how to detect instruction lengths
            // rather then decode instruction
            let bits = match self.decoder.decode(address, cur, &mut self.bundle) {
                Ok(bits) => bits,
                Err(Error::Failed(bits)) => bits,
                Err(Error::More(_)) => break,
            };
            debug_assert!(bits & 7 == 0);
            let len = bits / 8;
            cur = &cur[len..];
            address += len as u64;
        }

        data.len() - cur.len()
    }

    /// Do not decode `size` bytes.
    pub fn skip(&mut self, size: u64) {
        self.address += size;
    }
}
