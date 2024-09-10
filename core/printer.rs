use std::{
    borrow::Cow,
    fmt::{self, Write},
};

use crate::{
    insn::Insn,
    operand::{Operand, OperandKind, Reg},
};

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

#[derive(Copy, Clone)]
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

#[derive(Copy, Clone)]
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
