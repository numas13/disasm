use std::{
    borrow::Cow,
    cmp,
    fmt::{self, Write as _},
    io::{self, Write},
    ops::{Deref, DerefMut},
    string::FromUtf8Error,
};

use crate::{Arch, Bundle, Decoder, Error, Insn, Operand, OperandKind, Reg};

pub struct FormatterFn<F>(pub F)
where
    F: Fn(&mut fmt::Formatter) -> fmt::Result;

impl<F> fmt::Display for FormatterFn<F>
where
    F: Fn(&mut fmt::Formatter) -> fmt::Result,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.0(fmt)
    }
}

pub enum Separator {
    Tab,
    Char(char),
    Width(usize),
}

impl Separator {
    pub fn print(&self, fmt: &mut fmt::Formatter, mnemonic_len: usize) -> fmt::Result {
        match self {
            Separator::Tab => fmt.write_char('\t'),
            Separator::Char(c) => fmt.write_char(*c),
            Separator::Width(w) => {
                let w = w - std::cmp::min(*w, mnemonic_len);
                write!(fmt, "{:w$}", ' ')
            }
        }
    }
}

trait WriteExt: Write {
    fn write_u8_hex(&mut self, byte: u8) -> io::Result<()> {
        const MAP: [u8; 16] = *b"0123456789abcdef";
        let buf = [MAP[(byte >> 4) as usize & 15], MAP[byte as usize & 15]];
        self.write_all(&buf)
    }

    fn write_spaces(&mut self, mut width: usize) -> io::Result<()> {
        while width > 0 {
            const FILL: [u8; 32] = [b' '; 32];
            let len = cmp::min(width, FILL.len());
            self.write_all(&FILL[..len])?;
            width -= len;
        }
        Ok(())
    }
}

impl<T: Write> WriteExt for T {}

pub trait ArchPrinter<E: PrinterExt> {
    fn mnemonic(&self, insn: &Insn) -> Option<(&'static str, &'static str)>;

    fn register_name(&self, reg: Reg) -> Cow<'static, str>;

    fn insn_separator(&self) -> Separator {
        Separator::Tab
    }

    fn operand_separator(&self, _operand: &Operand) -> Separator {
        Separator::Char(',')
    }

    fn print_mnemonic_default(
        &self,
        fmt: &mut fmt::Formatter,
        ext: &E,
        insn: &Insn,
        separator: bool,
    ) -> fmt::Result {
        let (mnemonic, sub) = self.mnemonic(insn).unwrap_or(("<invalid>", ""));
        ext.print_mnemonic(fmt, mnemonic)?;
        let mut len = mnemonic.len();
        if !sub.is_empty() {
            ext.print_sub_mnemonic(
                fmt,
                FormatterFn(|fmt| {
                    fmt.write_char('.')?;
                    fmt.write_str(sub)
                }),
            )?;
            len += sub.len() + 1;
        }
        if separator && !insn.operands().is_empty() {
            self.insn_separator().print(fmt, len)?;
        }
        Ok(())
    }

    fn print_mnemonic(
        &self,
        fmt: &mut fmt::Formatter,
        ext: &E,
        insn: &Insn,
        separator: bool,
    ) -> fmt::Result {
        self.print_mnemonic_default(fmt, ext, insn, separator)
    }

    fn print_symbol(&self, fmt: &mut fmt::Formatter, ext: &E, addr: u64) -> fmt::Result {
        if let Some((sym_addr, sym_name)) = ext.get_symbol(addr) {
            fmt.write_str(" <")?;
            ext.print_symbol(fmt, sym_name)?;
            let diff = addr - sym_addr;
            if diff != 0 {
                fmt.write_char('+')?;
                ext.print_address_offset(fmt, FormatterFn(|fmt| write!(fmt, "{diff:#x}")))?;
            }
            fmt.write_char('>')?;
        }
        Ok(())
    }

    fn print_operand_default(
        &self,
        fmt: &mut fmt::Formatter,
        ext: &E,
        _: &Insn,
        operand: &Operand,
    ) -> fmt::Result {
        match operand.kind() {
            OperandKind::Reg(reg) => {
                let reg_name = self.register_name(*reg);
                ext.print_register(fmt, reg_name)?;
            }
            OperandKind::Imm(imm) => {
                ext.print_immediate(fmt, imm)?;
            }
            OperandKind::Uimm(imm) => {
                ext.print_immediate(fmt, FormatterFn(|fmt| write!(fmt, "{imm:#x}")))?;
            }
            OperandKind::Indirect(reg) => {
                fmt.write_char('(')?;
                ext.print_register(fmt, self.register_name(*reg))?;
                fmt.write_char(')')?;
            }
            OperandKind::Relative(reg, offset) => {
                ext.print_address_offset(fmt, offset)?;
                fmt.write_char('(')?;
                ext.print_register(fmt, self.register_name(*reg))?;
                fmt.write_char(')')?;
            }
            OperandKind::Indexed(base, index) => {
                fmt.write_char('(')?;
                ext.print_register(fmt, self.register_name(*base))?;
                fmt.write_char(',')?;
                ext.print_register(fmt, self.register_name(*index))?;
                fmt.write_char(')')?;
            }
            OperandKind::IndexedRelative(base, index, offset) => {
                ext.print_address_offset(fmt, FormatterFn(|fmt| write!(fmt, "{offset:#x}")))?;
                fmt.write_char('(')?;
                ext.print_register(fmt, self.register_name(*base))?;
                fmt.write_char(',')?;
                ext.print_register(fmt, self.register_name(*index))?;
                fmt.write_char(')')?;
            }
            OperandKind::ScaledIndex(base, index, scale) => {
                fmt.write_char('(')?;
                ext.print_register(fmt, self.register_name(*base))?;
                fmt.write_char(',')?;
                ext.print_register(fmt, self.register_name(*index))?;
                fmt.write_char(',')?;
                ext.print_immediate(fmt, scale)?;
                fmt.write_char(')')?;
            }
            OperandKind::ScaledIndexRelative(base, index, scale, offset) => {
                ext.print_address_offset(fmt, FormatterFn(|fmt| write!(fmt, "{offset:#x}")))?;
                fmt.write_char('(')?;
                ext.print_register(fmt, self.register_name(*base))?;
                fmt.write_char(',')?;
                ext.print_register(fmt, self.register_name(*index))?;
                fmt.write_char(',')?;
                ext.print_immediate(fmt, scale)?;
                fmt.write_char(')')?;
            }
            OperandKind::Absolute(addr) => {
                ext.print_address(fmt, FormatterFn(|fmt| write!(fmt, "{addr:x}")))?;
                self.print_symbol(fmt, ext, *addr)?;
            }
            OperandKind::PcRelative(_) => {
                todo!()
            }
            OperandKind::ArchSpec(a, b, c) => {
                unreachable!(
                    "arch-specific operand({a:#x}, {b:#x}, {c:#x}) must be handle by arch-printer"
                );
            }
        }
        Ok(())
    }

    fn print_operand(
        &self,
        fmt: &mut fmt::Formatter,
        ext: &E,
        insn: &Insn,
        operand: &Operand,
    ) -> fmt::Result {
        self.print_operand_default(fmt, ext, insn, operand)
    }

    fn need_operand_separator(&self, i: usize, _: &Operand) -> bool {
        i != 0
    }

    fn reverse_operands(&self) -> bool {
        false
    }

    fn print_operands_default(
        &self,
        fmt: &mut fmt::Formatter,
        ext: &E,
        insn: &Insn,
    ) -> fmt::Result {
        let operands = insn.operands().iter().filter(|i| i.is_printable());
        let mut print = |i: usize, operand: &Operand| {
            if self.need_operand_separator(i, operand) {
                self.operand_separator(operand).print(fmt, 0)?;
            }
            self.print_operand(fmt, ext, insn, operand)
        };
        if self.reverse_operands() {
            for (i, operand) in operands.rev().enumerate() {
                print(i, operand)?;
            }
        } else {
            for (i, operand) in operands.enumerate() {
                print(i, operand)?;
            }
        }
        Ok(())
    }

    fn print_operands(&self, fmt: &mut fmt::Formatter, ext: &E, insn: &Insn) -> fmt::Result {
        self.print_operands_default(fmt, ext, insn)
    }

    fn print_insn_start(&self, _fmt: &mut fmt::Formatter, _ext: &E, _insn: &Insn) -> fmt::Result {
        Ok(())
    }

    fn print_insn_end(&self, _fmt: &mut fmt::Formatter, _ext: &E, _insn: &Insn) -> fmt::Result {
        Ok(())
    }

    fn print_insn(&self, fmt: &mut fmt::Formatter, ext: &E, insn: &Insn) -> fmt::Result {
        self.print_insn_start(fmt, ext, insn)?;
        self.print_mnemonic(fmt, ext, insn, true)?;
        self.print_operands(fmt, ext, insn)?;
        self.print_insn_end(fmt, ext, insn)?;
        Ok(())
    }
}

pub enum Style {
    Slot,
    Mnemonic,
    SubMnemonic,
    Register,
    Immediate,
    Address,
    AddressOffset,
    Symbol,
    Comment,
    AssemblerDirective,
}

pub trait PrinterExt {
    /// Get symbol with address less then or equal to `address`.
    fn get_symbol(&self, address: u64) -> Option<(u64, &str)>;

    /// Get symbol with address greater then `address`.
    fn get_symbol_after(&self, address: u64) -> Option<(u64, &str)>;

    fn print_styled(
        &self,
        fmt: &mut fmt::Formatter,
        #[allow(unused_variables)] style: Style,
        display: impl fmt::Display,
    ) -> fmt::Result {
        display.fmt(fmt)
    }

    fn print_slot(&self, fmt: &mut fmt::Formatter, display: impl fmt::Display) -> fmt::Result {
        self.print_styled(fmt, Style::Slot, display)
    }

    fn print_mnemonic(&self, fmt: &mut fmt::Formatter, display: impl fmt::Display) -> fmt::Result {
        self.print_styled(fmt, Style::Mnemonic, display)
    }

    fn print_sub_mnemonic(
        &self,
        fmt: &mut fmt::Formatter,
        display: impl fmt::Display,
    ) -> fmt::Result {
        self.print_styled(fmt, Style::SubMnemonic, display)
    }

    fn print_register(&self, fmt: &mut fmt::Formatter, display: impl fmt::Display) -> fmt::Result {
        self.print_styled(fmt, Style::Register, display)
    }

    fn print_immediate(&self, fmt: &mut fmt::Formatter, display: impl fmt::Display) -> fmt::Result {
        self.print_styled(fmt, Style::Immediate, display)
    }

    fn print_address(&self, fmt: &mut fmt::Formatter, display: impl fmt::Display) -> fmt::Result {
        self.print_styled(fmt, Style::Address, display)
    }

    fn print_address_offset(
        &self,
        fmt: &mut fmt::Formatter,
        display: impl fmt::Display,
    ) -> fmt::Result {
        self.print_styled(fmt, Style::AddressOffset, display)
    }

    fn print_symbol(&self, fmt: &mut fmt::Formatter, display: impl fmt::Display) -> fmt::Result {
        self.print_styled(fmt, Style::Symbol, display)
    }

    fn print_comment(&self, fmt: &mut fmt::Formatter, display: impl fmt::Display) -> fmt::Result {
        self.print_styled(fmt, Style::Comment, display)
    }

    fn print_assembler_directive(
        &self,
        fmt: &mut fmt::Formatter,
        display: impl fmt::Display,
    ) -> fmt::Result {
        self.print_styled(fmt, Style::AssemblerDirective, display)
    }
}

impl PrinterExt for () {
    fn get_symbol(&self, _: u64) -> Option<(u64, &str)> {
        None
    }

    fn get_symbol_after(&self, _: u64) -> Option<(u64, &str)> {
        None
    }
}

impl<'a, T: PrinterExt> PrinterExt for &'a T {
    fn get_symbol(&self, address: u64) -> Option<(u64, &str)> {
        (*self).get_symbol(address)
    }

    fn get_symbol_after(&self, address: u64) -> Option<(u64, &str)> {
        (*self).get_symbol_after(address)
    }
}

#[derive(Clone, Default)]
pub struct Symbols {
    sorted: bool,
    list: Vec<(u64, String)>,
}

impl Symbols {
    pub fn push<S: Into<String>>(&mut self, address: u64, name: S) {
        self.sorted = false;
        self.list.push((address, name.into()));
    }

    pub fn as_slice(&self) -> &[(u64, String)] {
        &self.list
    }

    pub fn as_info(&mut self) -> SymbolsInfo {
        if !self.sorted {
            self.list.sort_by_key(|(addr, _)| *addr);
            self.sorted = true;
        }
        SymbolsInfo { list: &self.list }
    }
}

pub struct SymbolsInfo<'a> {
    list: &'a [(u64, String)],
}

impl PrinterExt for SymbolsInfo<'_> {
    fn get_symbol(&self, address: u64) -> Option<(u64, &str)> {
        let index = match self.list.binary_search_by_key(&address, |(addr, _)| *addr) {
            Ok(index) => index,
            Err(index) => index.checked_sub(1)?,
        };
        self.list
            .get(index)
            .map(|(addr, name)| (*addr, name.as_str()))
    }

    fn get_symbol_after(&self, address: u64) -> Option<(u64, &str)> {
        let symbol = match self.list.binary_search_by_key(&address, |(addr, _)| *addr) {
            Ok(index) => self
                .list
                .iter()
                .skip(index)
                .find(|(addr, _)| *addr != address),
            Err(index) => self.list.get(index),
        };
        symbol.map(|(addr, name)| (*addr, name.as_str()))
    }
}

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

    pub(crate) fn inner(&self) -> &dyn ArchPrinter<E> {
        self.printer.as_ref()
    }

    pub(crate) fn ext(&self) -> &E {
        &self.ext
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
                if offset != 0 {
                    writeln!(out, "\n{address:0width$x} <{name}-{offset:#x}>:")?;
                } else {
                    writeln!(out, "\n{address:0width$x} <{name}>:")?;
                }
            } else if let Some((addr, name)) = *next_symbol {
                if addr == address {
                    writeln!(out, "\n{address:0width$x} <{name}>:")?;
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
                    writeln!(out, "\t...")?;
                    let skip = zeroes & !(skip_zeroes - 1);
                    self.decoder.skip(skip as u64);
                    cur = &cur[cmp::min(skip, cur.len())..];
                    continue;
                }
            }

            let (len, is_ok, mut err_msg) = match self.decoder.decode(cur, &mut self.bundle) {
                Ok(len) => (len, true, None),
                Err(err) => {
                    let len = match err {
                        Error::More(bits) if has_more => {
                            let offset = data.len() - cur.len();
                            return Ok((offset, (bits + 7) / 8));
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
                    write!(out, "{:addr_width$x}:\t", address + l as u64)?;

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
                    write!(out, "\t{}", insn.printer(self))?;
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
