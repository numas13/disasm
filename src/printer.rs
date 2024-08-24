use core::fmt::{self, Write};

use alloc::borrow::Cow;

use crate::{Disasm, Insn, Operand, OperandKind, Reg};

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

pub trait Printer {
    fn register_name(&self, reg: Reg) -> Cow<'static, str>;

    fn insn_separator(&self) -> Separator {
        Separator::Tab
    }

    fn operand_separator(&self) -> Separator {
        Separator::Char(',')
    }

    fn print_mnemonic(
        &self,
        fmt: &mut fmt::Formatter,
        disasm: &Disasm,
        insn: &Insn,
        separator: bool,
    ) -> fmt::Result {
        let (mnemonic, sub) = insn.mnemonic(disasm).unwrap_or(("<invalid>", ""));
        fmt.write_str(mnemonic)?;
        let mut len = mnemonic.len();
        if !sub.is_empty() {
            fmt.write_char('.')?;
            len += 1;
            fmt.write_str(sub)?;
            len += sub.len();
        }
        if separator && !insn.operands().is_empty() {
            self.insn_separator().print(fmt, len)?;
        }
        Ok(())
    }

    fn print_symbol(
        &self,
        fmt: &mut fmt::Formatter,
        info: &dyn PrinterInfo,
        addr: u64,
    ) -> fmt::Result {
        if let Some((sym_addr, sym_name)) = info.get_symbol(addr) {
            write!(fmt, " <{sym_name}")?;
            let diff = addr - sym_addr;
            if diff != 0 {
                write!(fmt, "+{diff:#x}")?;
            }
            fmt.write_char('>')?;
        }
        Ok(())
    }

    fn print_operand_default(
        &self,
        fmt: &mut fmt::Formatter,
        disasm: &Disasm,
        info: &dyn PrinterInfo,
        _insn: &Insn,
        operand: &Operand,
    ) -> fmt::Result {
        match operand.kind() {
            OperandKind::Reg(reg) => {
                let reg_name = disasm.printer.register_name(*reg);
                fmt.write_str(&reg_name)?;
            }
            OperandKind::Imm(imm) => {
                write!(fmt, "{imm}")?;
            }
            OperandKind::Uimm(imm) => {
                write!(fmt, "{imm:#x}")?;
            }
            OperandKind::Indirect(reg) => {
                let reg_name = disasm.printer.register_name(*reg);
                write!(fmt, "({reg_name})")?;
            }
            OperandKind::Relative(reg, offset) => {
                let reg_name = disasm.printer.register_name(*reg);
                write!(fmt, "{offset}({reg_name})")?;
            }
            OperandKind::Indexed(base, index) => {
                let base = disasm.printer.register_name(*base);
                let index = disasm.printer.register_name(*index);
                write!(fmt, "({base},{index})")?;
            }
            OperandKind::IndexedRelative(base, index, offset) => {
                let base = disasm.printer.register_name(*base);
                let index = disasm.printer.register_name(*index);
                write!(fmt, "{offset:#x}({base},{index})")?;
            }
            OperandKind::ScaledIndex(base, index, scale) => {
                let base = disasm.printer.register_name(*base);
                let index = disasm.printer.register_name(*index);
                write!(fmt, "({base},{index},{scale})")?;
            }
            OperandKind::ScaledIndexRelative(base, index, scale, offset) => {
                let base = disasm.printer.register_name(*base);
                let index = disasm.printer.register_name(*index);
                write!(fmt, "{offset:#x}({base},{index},{scale})")?;
            }
            OperandKind::Absolute(addr) => {
                write!(fmt, "{addr:x}")?;
                self.print_symbol(fmt, info, *addr)?;
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
        disasm: &Disasm,
        info: &dyn PrinterInfo,
        insn: &Insn,
        operand: &Operand,
    ) -> fmt::Result {
        self.print_operand_default(fmt, disasm, info, insn, operand)
    }

    fn need_operand_separator(&self, i: usize, _operand: &Operand) -> bool {
        i != 0
    }

    fn reverse_operands(&self) -> bool {
        false
    }

    fn print_operands_default(
        &self,
        fmt: &mut fmt::Formatter,
        disasm: &Disasm,
        info: &dyn PrinterInfo,
        insn: &Insn,
    ) -> fmt::Result {
        let operands = insn.operands().iter().filter(|i| i.is_printable());
        let mut print = |i: usize, operand: &Operand| {
            if self.need_operand_separator(i, operand) {
                self.operand_separator().print(fmt, 0)?;
            }
            self.print_operand(fmt, disasm, info, insn, operand)
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

    fn print_operands(
        &self,
        fmt: &mut fmt::Formatter,
        disasm: &Disasm,
        info: &dyn PrinterInfo,
        insn: &Insn,
    ) -> fmt::Result {
        self.print_operands_default(fmt, disasm, info, insn)
    }

    fn print_insn(
        &self,
        fmt: &mut fmt::Formatter,
        disasm: &Disasm,
        info: &dyn PrinterInfo,
        insn: &Insn,
    ) -> fmt::Result {
        self.print_mnemonic(fmt, disasm, insn, true)?;
        self.print_operands(fmt, disasm, info, insn)
    }
}

pub trait PrinterInfo {
    /// Get symbol with address less then or equal to `address`.
    #[allow(unused_variables)]
    fn get_symbol(&self, address: u64) -> Option<(u64, &str)> {
        None
    }

    /// Get symbol with address greater then `address`.
    #[allow(unused_variables)]
    fn get_symbol_after(&self, address: u64) -> Option<(u64, &str)> {
        None
    }
}

impl PrinterInfo for () {}

impl<'a, T: PrinterInfo> PrinterInfo for &'a T {
    fn get_symbol(&self, address: u64) -> Option<(u64, &str)> {
        (*self).get_symbol(address)
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

impl PrinterInfo for SymbolsInfo<'_> {
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
