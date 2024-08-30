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
pub use crate::printer::{PrinterInfo, Symbols};

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
    More(usize, usize),
    /// Failed to decode an instruction.
    Io(io::Error),
}

#[cfg(all(feature = "std", feature = "print"))]
impl fmt::Display for PrintError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::More(..) => fmt.write_str("Need more data"),
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

#[non_exhaustive]
#[derive(Copy, Clone)]
pub enum Arch {
    #[cfg(feature = "riscv")]
    Riscv(crate::arch::riscv::Options),
    #[cfg(feature = "x86")]
    X86(crate::arch::x86::Options),
}

impl Arch {
    pub fn bytes_per_line(&self) -> usize {
        match self {
            #[cfg(feature = "riscv")]
            Arch::Riscv(..) => 8,
            #[cfg(feature = "x86")]
            Arch::X86(..) => 7,
        }
    }

    #[allow(unused_variables)]
    pub fn bytes_per_chunk(&self, len: usize) -> usize {
        match self {
            #[cfg(feature = "riscv")]
            Arch::Riscv(..) => len,
            #[cfg(feature = "x86")]
            Arch::X86(..) => 1,
        }
    }

    pub fn skip_zeroes(&self) -> usize {
        match self {
            #[cfg(feature = "riscv")]
            Arch::Riscv(..) => 2,
            #[cfg(feature = "x86")]
            Arch::X86(..) => 8,
        }
    }

    pub fn addr_size(&self) -> usize {
        match self {
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

pub struct Disasm {
    address: u64,
    insn_alignment: u16,
    insn_size_min: u16,
    insn_size_max: u16,
    opts: Options,
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
            #[cfg(feature = "x86")]
            Arch::X86(arch_opts) => x86::decoder(opts, arch_opts),
        }
    }

    #[cfg(feature = "print")]
    fn new_printer(arch: Arch, opts: Options) -> Box<dyn Printer> {
        use crate::arch::*;
        match arch {
            #[cfg(feature = "riscv")]
            Arch::Riscv(arch_opts) => riscv::printer(opts, arch_opts),
            #[cfg(feature = "x86")]
            Arch::X86(arch_opts) => x86::printer(opts, arch_opts),
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
            opts,
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

    pub fn decode_len(&mut self, data: &[u8]) -> usize {
        let skip_zeroes = self.arch.skip_zeroes();
        let mut out = Bundle::empty();
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
            out.clear();
            // TODO: optimize, backends know better how to detect instruction lengths
            let bits = match self.decoder.decode(address, cur, &mut out) {
                Ok(bits) => bits,
                Err(Error::Failed(bits)) => bits,
                Err(Error::More(_)) => break,
            };
            assert!(bits & 7 == 0);
            let len = bits / 8;
            cur = &cur[len..];
            address += len as u64;
        }

        data.len() - cur.len()
    }

    /// Do not decode `size` bytes.
    pub fn skip(&mut self, size: usize) {
        // TODO: skip: u64
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
        first: bool,
        has_more: bool,
    ) -> Result<usize, PrintError>
    where
        W: Write,
        I: PrinterInfo,
    {
        let address = self.address();
        let mut next_symbol = info.get_symbol_after(address);
        let mut first_symbol = match info.get_symbol(address) {
            Some((addr, name)) if address == addr => Some((name, 0)),
            _ if first => match next_symbol {
                Some((addr, name)) => Some((name, addr - address)),
                _ => Some((section_name, 0)),
            },
            _ => None,
        };

        let width = self.arch.addr_size() / 4;
        let mut print_symbol = |out: &mut W, address, next_symbol: &mut _| -> io::Result<()> {
            if let Some((name, offset)) = first_symbol.take() {
                if offset != 0 {
                    writeln!(out, "\n{address:0width$x} <{name}-{offset:#x}>:")?;
                } else {
                    writeln!(out, "\n{address:0width$x} <{name}>:")?;
                }
            } else if let Some((addr, name)) = *next_symbol {
                if addr == address {
                    writeln!(out, "\n{address:0width$x} <{name}>:")?;
                    *next_symbol = info.get_symbol_after(address);
                }
            }
            Ok(())
        };

        let mut bundle = Bundle::empty();

        let bytes_per_line = self.arch.bytes_per_line();
        let min_len = self.insn_size_min();
        let skip_zeroes = self.arch.skip_zeroes();

        let mut cur = data;
        while has_more || cur.len() >= min_len {
            let address = self.address();

            let zeroes = if self.opts.decode_zeroes {
                // do not skip zeroes
                None
            } else if has_more {
                let offset = data.len() - cur.len();
                if cur.len() < skip_zeroes {
                    return Err(PrintError::More(offset, skip_zeroes));
                }
                if cur.iter().take(skip_zeroes).all(|i| *i == 0) {
                    let len = info
                        .get_symbol_after(address)
                        .map(|(addr, _)| (addr - address) as usize)
                        .unwrap_or(cur.len());
                    let zeroes = cur
                        .iter()
                        .take(len)
                        .position(|i| *i != 0)
                        .ok_or(PrintError::More(offset, len + 1))?;
                    Some((len, zeroes))
                } else {
                    None
                }
            } else if cur.len() >= skip_zeroes && cur.iter().take(skip_zeroes).all(|i| *i == 0) {
                let len = info
                    .get_symbol_after(address)
                    .map(|(addr, _)| (addr - address) as usize)
                    .unwrap_or(cur.len());
                let zeroes = cur.iter().take(len).position(|i| *i != 0).unwrap_or(len);
                Some((len, zeroes))
            } else {
                None
            };

            if let Some((len, zeroes)) = zeroes {
                if (len != 0 && zeroes == len) || zeroes >= (skip_zeroes * 2 - 1) {
                    print_symbol(out, address, &mut next_symbol)?;
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
                        Error::More(bits) if has_more => {
                            let offset = data.len() - cur.len();
                            return Err(PrintError::More(offset, (bits + 7) / 8));
                        }
                        Error::More(_) => cur.len(),
                        Error::Failed(len) => len,
                    };
                    (len, false, Some("failed to decode"))
                }
            };

            print_symbol(out, address, &mut next_symbol)?;

            // TODO: address width based on end address?
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
        first: bool,
    ) -> Result<(), io::Error>
    where
        W: Write,
        I: PrinterInfo,
    {
        // do not bother the user with an error wrapper
        match self.print_impl(out, data, section_name, info, first, false) {
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
        first: bool,
    ) -> Result<usize, PrintError>
    where
        W: Write,
        I: PrinterInfo,
    {
        self.print_impl(out, data, section_name, info, first, true)
    }

    #[cfg(all(feature = "std", feature = "print"))]
    pub fn print_to_string<I>(
        &mut self,
        data: &[u8],
        section_name: &str,
        info: &I,
        first: bool,
    ) -> Result<String, io::Error>
    where
        I: PrinterInfo,
    {
        use std::io::Cursor;

        let mut buf = Vec::new();
        let mut cur = Cursor::new(&mut buf);
        self.print(&mut cur, data, section_name, info, first)?;
        Ok(unsafe { String::from_utf8_unchecked(buf) })
    }
}
