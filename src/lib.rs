#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod arch;
mod bytes;
mod flags;
mod insn;
mod operand;
#[cfg(feature = "print")]
mod printer;
mod utils;

use core::fmt;

#[cfg(all(feature = "std", feature = "print"))]
use std::io::{self, Write};

use alloc::boxed::Box;

use crate::arch::Decoder;
#[cfg(feature = "print")]
use crate::printer::Printer;

pub use crate::insn::{Bundle, Insn, Opcode};
pub use crate::operand::{Access, Operand, OperandKind, Reg, RegClass};

#[cfg(feature = "print")]
pub use crate::printer::PrinterInfo;

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

#[cfg(all(feature = "std", feature = "print"))]
#[derive(Debug)]
pub enum PrintError {
    /// Need more bytes to decode an instruction.
    More(usize),
    /// Failed to decode an instruction.
    Io(io::Error),
}

#[cfg(all(feature = "std", feature = "print"))]
impl fmt::Display for PrintError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::More(_) => fmt.write_str("Need more data"),
            Self::Io(err) => err.fmt(fmt),
        }
    }
}

#[cfg(all(feature = "std", feature = "print"))]
impl std::error::Error for PrintError {}

#[cfg(all(feature = "std", feature = "print"))]
impl From<io::Error> for PrintError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

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
    arch: Arch,
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
            arch,
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

    #[cfg(all(feature = "std", feature = "print"))]
    fn print_impl<W, I>(
        &mut self,
        out: &mut W,
        data: &[u8],
        section_name: &str,
        info: &I,
        streaming: bool,
    ) -> Result<usize, PrintError>
    where
        W: Write,
        I: PrinterInfo,
    {
        let mut bundle = Bundle::empty();
        let mut symbol = None;

        let bytes_per_line = self.arch.bytes_per_line();
        let min_len = self.insn_size_min();
        let skip_zeroes = self.arch.skip_zeroes();

        let mut cur = data;
        while cur.len() >= min_len {
            let address = self.address();
            let new_symbol = info.get_symbol(address);
            if new_symbol != symbol {
                symbol = new_symbol;
                if let Some((_, name)) = symbol {
                    writeln!(out)?;
                    writeln!(out, "{address:016x} <{name}>:")?;
                } else {
                    writeln!(out, "{:016x} <{section_name}>:", self.address())?;
                }
            }

            if cur.len() >= skip_zeroes && cur.iter().take(skip_zeroes).all(|i| *i == 0) {
                let zeroes = cur.iter().position(|i| *i != 0).unwrap_or(cur.len());
                let sym = info.get_symbol(address + zeroes as u64);
                if sym != new_symbol || zeroes >= (skip_zeroes * 2 - 1) {
                    writeln!(out, "\t...")?;
                    let skip = zeroes & !(skip_zeroes - 1);
                    self.skip(skip);
                    cur = &cur[skip..];
                    continue;
                }
            }

            let (len, is_ok, mut err_msg) = match self.decode(cur, &mut bundle) {
                Ok(len) => (len, true, None),
                Err(err) => {
                    let len = match err {
                        Error::More(bits) => {
                            if streaming {
                                // ask user for more input
                                return Err(PrintError::More((bits + 7) / 8));
                            } else {
                                // or just print as fail
                                cur.len()
                            }
                        }
                        Error::Failed(len) => len,
                    };
                    (len, false, Some("failed to decode"))
                }
            };

            let addr_width = if address >= 0x1000 { 8 } else { 4 };
            let bytes_per_chunk = self.arch.bytes_per_chunk(len);
            let mut insns = bundle.iter();
            let mut chunks = cur[..len].chunks(bytes_per_chunk);
            let mut l = 0;
            loop {
                let insn = if is_ok { insns.next() } else { None };
                if l >= len && insn.is_none() {
                    break;
                }
                write!(out, "{:addr_width$x}:\t", address + l as u64)?;

                let mut p = 0;
                let mut c = 0;
                if l < len {
                    for _ in (0..bytes_per_line).step_by(bytes_per_chunk) {
                        c += 1;
                        if let Some(chunk) = chunks.next() {
                            for i in chunk.iter().rev() {
                                write!(out, "{i:02x}")?;
                            }
                            out.write_all(b" ")?;
                            p += chunk.len();
                            l += chunk.len();
                            c -= 1;
                        }
                    }
                }

                let width = (bytes_per_line - p) * 2 + c;

                if let Some(insn) = insn {
                    write!(out, "{:width$}\t{}", "", insn.printer(self, info))?;
                }

                if let Some(err) = err_msg.take() {
                    write!(out, "{:width$}\t{err}", "")?;
                }

                writeln!(out)?;
            }
            cur = &cur[len..];
        }

        Ok(data.len() - cur.len())
    }

    #[cfg(all(feature = "std", feature = "print"))]
    pub fn print<W, I>(
        &mut self,
        out: &mut W,
        data: &[u8],
        section_name: &str,
        info: &I,
    ) -> Result<(), io::Error>
    where
        W: Write,
        I: PrinterInfo,
    {
        // do not bother the user with an error wrapper
        match self.print_impl(out, data, section_name, info, false) {
            Ok(_) => Ok(()),
            Err(PrintError::Io(err)) => Err(err),
            _ => unreachable!(),
        }
    }

    #[cfg(all(feature = "std", feature = "print"))]
    pub fn print_streaming<W, I>(
        &mut self,
        out: &mut W,
        data: &[u8],
        section_name: &str,
        info: &I,
    ) -> Result<usize, PrintError>
    where
        W: Write,
        I: PrinterInfo,
    {
        self.print_impl(out, data, section_name, info, true)
    }
}
