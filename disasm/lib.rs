#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod arch;

use disasm_core::ArchDecoder;

#[cfg(feature = "print")]
mod printer;

use alloc::boxed::Box;

pub use disasm_core::{
    error::Error,
    insn::{Bundle, Insn, Opcode, Slot},
    operand::{Access, Operand, OperandKind, Reg, RegClass},
    Options,
};

#[cfg(feature = "print")]
pub use crate::printer::{Printer, PrinterExt, Style, Symbols, SymbolsInfo};

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
                use crate::arch::x86::AddrSize;
                match opts.addr_size {
                    AddrSize::Auto => {
                        if opts.ext.amd64 {
                            64
                        } else {
                            32
                        }
                    }
                    AddrSize::Addr32 => 32,
                    AddrSize::Addr64 => 64,
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

    pub fn only_first_chunk_address(&self) -> bool {
        match self {
            #[cfg(feature = "e2k")]
            Arch::E2K(..) => true,
            _ => false,
        }
    }
}

pub struct Decoder {
    address: u64,
    opts: Options,
    arch: Arch,
    tmp: Bundle,
    decoder: Box<dyn ArchDecoder>,
}

impl Decoder {
    pub fn new(arch: Arch, address: u64, opts: Options) -> Self {
        use crate::arch::*;

        fn wrap<T: 'static + ArchDecoder>(x: T) -> Box<dyn ArchDecoder> {
            Box::new(x)
        }

        let decoder = match arch {
            #[cfg(feature = "e2k")]
            Arch::E2K(arch_opts) => wrap(e2k::Decoder::new(&opts, &arch_opts)),
            #[cfg(feature = "riscv")]
            Arch::Riscv(arch_opts) => wrap(riscv::Decoder::new(&opts, &arch_opts)),
            #[cfg(feature = "x86")]
            Arch::X86(arch_opts) => wrap(x86::Decoder::new(&opts, &arch_opts)),
        };

        Self {
            address,
            opts,
            arch,
            tmp: Bundle::empty(),
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
            let bits = match self.decoder.decode_len(address, cur, &mut self.tmp) {
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
