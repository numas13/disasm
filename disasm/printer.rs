use std::{
    cmp,
    io::{self, Write},
    ops::{Deref, DerefMut},
    string::FromUtf8Error,
};

use crate::{Arch, Bundle, Decoder, Error};

pub use disasm_core::{
    printer::{ArchPrinter, FormatterFn, PrinterExt, Style},
    symbols::{Symbols, SymbolsInfo},
};

pub trait WriteExt: Write {
    fn write_u4_hex(&mut self, byte: u8) -> io::Result<()> {
        const MAP: [u8; 16] = *b"0123456789abcdef";
        let i = (byte as usize) & 15;
        self.write_all(&MAP[i..i + 1])
    }

    fn write_u8_hex(&mut self, byte: u8) -> io::Result<()> {
        self.write_u4_hex(byte >> 4)?;
        self.write_u4_hex(byte)
    }

    fn write_spaces(&mut self, mut width: usize) -> io::Result<()> {
        const BUF: [u8; 32] = [b' '; 32];
        while width > 0 {
            let len = cmp::min(width, BUF.len());
            self.write_all(&BUF[..len])?;
            width -= len;
        }
        Ok(())
    }

    fn write_zeroes(&mut self, mut width: usize) -> io::Result<()> {
        const BUF: [u8; 32] = [b'0'; 32];
        while width > 0 {
            let len = cmp::min(width, BUF.len());
            self.write_all(&BUF[..len])?;
            width -= len;
        }
        Ok(())
    }

    fn write_u64_hex(&mut self, value: u64, width: usize) -> io::Result<()> {
        for i in (0..width).rev() {
            self.write_u4_hex((value >> (i * 4)) as u8)?;
        }
        Ok(())
    }

    fn write_address(&mut self, address: u64, width: usize) -> io::Result<()> {
        let c = (64 + 3 - address.leading_zeros() as usize) / 4;
        if c < width {
            self.write_spaces(width - c)?;
        }
        self.write_u64_hex(address, c)
    }

    fn write_symbol_address(&mut self, address: u64, width: usize) -> io::Result<()> {
        let c = (64 + 3 - address.leading_zeros() as usize) / 4;
        if c < width {
            self.write_zeroes(width - c)?;
        }
        self.write_u64_hex(address, c)
    }

    fn write_symbol(
        &mut self,
        address: u64,
        width: usize,
        name: &str,
        offset: u64,
    ) -> io::Result<()> {
        self.write_all(b"\n")?;
        self.write_symbol_address(address, width)?;
        self.write_all(b" <")?;
        self.write_all(name.as_bytes())?;
        if offset != 0 {
            self.write_all(b"-")?;
            self.write_address(offset, 0)?;
        }
        self.write_all(b">:\n")
    }
}

impl<T: Write> WriteExt for T {}

pub struct Printer<E: PrinterExt = ()> {
    decoder: Decoder,
    bundle: Bundle,
    printer: Box<dyn ArchPrinter<E>>,
    ext: E,
    section_name: Box<str>,
}

impl<E: PrinterExt> Printer<E> {
    pub(crate) fn new(decoder: Decoder, ext: E, section_name: &str) -> Self {
        use crate::arch::*;

        let opts = &decoder.opts;
        let printer = match &decoder.arch {
            #[cfg(feature = "e2k")]
            Arch::E2K(arch_opts) => e2k::printer(opts, arch_opts),
            #[cfg(feature = "riscv")]
            Arch::Riscv(arch_opts) => riscv::printer(opts, arch_opts),
            #[cfg(feature = "x86")]
            Arch::X86(arch_opts) => x86::printer(opts, arch_opts),
        };

        Self {
            decoder,
            bundle: Bundle::empty(),
            printer,
            ext,
            section_name: section_name.to_owned().into_boxed_str(),
        }
    }

    fn print_impl<W: Write>(
        &mut self,
        out: &mut W,
        data: &[u8],
        first: bool,
        has_more: bool,
    ) -> io::Result<(usize, usize)> {
        let address = self.address();
        let mut next_symbol = self.ext.get_symbol_after(address);
        let mut first_symbol = match self.ext.get_symbol(address) {
            Some((addr, name)) if address == addr => Some((name, 0)),
            _ if first => match next_symbol {
                Some((addr, name)) => Some((name, addr - address)),
                _ => Some((self.section_name.as_ref(), 0)),
            },
            _ => None,
        };

        let width = self.arch.addr_size() / 4;
        let mut print_symbol = |out: &mut W, address, next_symbol: &mut _| -> io::Result<()> {
            if let Some((name, offset)) = first_symbol.take() {
                out.write_symbol(address, width, name, offset)?;
            } else if let Some((addr, name)) = *next_symbol {
                if addr == address {
                    out.write_symbol(address, width, name, 0)?;
                    *next_symbol = self.ext.get_symbol_after(address);
                }
            }
            Ok(())
        };

        let bytes_per_line = self.arch.bytes_per_line();
        let min_len = self.arch.insn_size_min();
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
                    return Ok((offset, skip_zeroes));
                }
                if cur.iter().take(skip_zeroes).all(|i| *i == 0) {
                    let len = self
                        .ext
                        .get_symbol_after(address)
                        .map(|(addr, _)| (addr - address) as usize)
                        .unwrap_or(cur.len());
                    match cur.iter().take(len).position(|i| *i != 0) {
                        Some(i) => Some((len, i)),
                        None => return Ok((offset, len + 1)),
                    }
                } else {
                    None
                }
            } else if cur.len() >= skip_zeroes && cur.iter().take(skip_zeroes).all(|i| *i == 0) {
                let len = self
                    .ext
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
                    out.write_all(b"\t...\n")?;
                    let skip = cmp::min(zeroes & !(skip_zeroes - 1), cur.len());
                    self.decoder.skip(skip as u64);
                    cur = &cur[skip..];
                    continue;
                }
            }

            let (len, is_ok, mut err_msg) = match self.decoder.decode(cur, &mut self.bundle) {
                Ok(len) => (len, true, None),
                Err(err) => {
                    let len = match err {
                        Error::More(len) if has_more => {
                            let offset = data.len() - cur.len();
                            return Ok((offset, len));
                        }
                        Error::More(_) => cur.len(),
                        Error::Failed(len) => len,
                    };

                    // make sure a user will see that failed bytes are handled
                    self.decoder.skip(len as u64);

                    (len, false, Some("failed to decode"))
                }
            };

            print_symbol(out, address, &mut next_symbol)?;

            // TODO: address width based on end address?
            let addr_width = if address >= 0x1000 { 8 } else { 4 };
            let bytes_per_chunk = self.arch.bytes_per_chunk(len);
            let mut insns = self.bundle.iter();
            let mut chunks = cur[..len].chunks(bytes_per_chunk);
            let mut l = 0;
            loop {
                let insn = if is_ok { insns.next() } else { None };
                if l >= len && insn.is_none() {
                    break;
                }
                let mut p = 0;
                let mut c = 0;
                if l < len {
                    out.write_address(address + l as u64, addr_width)?;
                    out.write_all(b":\t")?;

                    for _ in (0..bytes_per_line).step_by(bytes_per_chunk) {
                        c += 1;
                        if let Some(chunk) = chunks.next() {
                            for i in chunk.iter().rev() {
                                out.write_u8_hex(*i)?;
                            }
                            out.write_all(b" ")?;
                            p += chunk.len();
                            l += chunk.len();
                            c -= 1;
                        }
                    }
                } else {
                    out.write_spaces(addr_width + 1)?;
                    out.write_all(b"\t")?;
                }

                let width = (bytes_per_line - p) * 2 + c;
                if let Some(insn) = insn {
                    out.write_spaces(width)?;
                    let display = FormatterFn(|fmt| self.printer.print_insn(fmt, &self.ext, insn));
                    write!(out, "\t{display}")?;
                } else if let Some(err) = err_msg.take() {
                    out.write_spaces(width)?;
                    write!(out, "\t{err}")?;
                }

                out.write_all(b"\n")?;
            }
            cur = &cur[len..];
        }

        Ok((data.len() - cur.len(), 0))
    }

    pub fn print<W>(&mut self, out: &mut W, data: &[u8], first: bool) -> io::Result<()>
    where
        W: Write,
    {
        self.print_impl(out, data, first, false).map(|_| ())
    }

    pub fn print_streaming<W>(
        &mut self,
        out: &mut W,
        data: &[u8],
        first: bool,
    ) -> Result<(usize, usize), io::Error>
    where
        W: Write,
    {
        self.print_impl(out, data, first, true)
    }

    pub fn print_to_vec(&mut self, data: &[u8], first: bool) -> Vec<u8> {
        use std::io::Cursor;
        let mut cur = Cursor::default();
        self.print(&mut cur, data, first).unwrap();
        cur.into_inner()
    }

    pub fn print_to_string(&mut self, data: &[u8], first: bool) -> Result<String, FromUtf8Error> {
        String::from_utf8(self.print_to_vec(data, first))
    }
}

impl<E: PrinterExt> Deref for Printer<E> {
    type Target = Decoder;

    fn deref(&self) -> &Self::Target {
        &self.decoder
    }
}

impl<E: PrinterExt> DerefMut for Printer<E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.decoder
    }
}
