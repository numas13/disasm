use std::{
    fmt::{self, Write},
    str::Lines,
};

use disasm_core::{
    insn::Bundle,
    printer::{ArchPrinter, FormatterFn},
    symbols::Symbols,
    ArchDecoder,
};

use super::utils::Diff;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParserError {
    file: String,
    line: usize,
    msg: String,
}

impl ParserError {
    fn new(file: &str, line: usize, msg: String) -> Self {
        Self {
            file: file.to_owned(),
            line,
            msg,
        }
    }
}

impl fmt::Display for ParserError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "error: {}, {}:{}", self.msg, self.file, self.line)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Test<'a> {
    pub line: usize,
    pub comment: &'a str,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub asm: Vec<&'a str>,
}

pub struct Parser<'a> {
    file: String,
    lines: Lines<'a>,
    line: usize,
    symbols: Symbols,
    bundle_end: &'a str,
}

impl<'a> Parser<'a> {
    pub fn new(file: &str, input: &'a str) -> Self {
        Self {
            file: file.to_owned(),
            lines: input.lines(),
            line: 0,
            symbols: Symbols::default(),
            bundle_end: "",
        }
    }

    pub fn set_bundle_end(mut self, s: &'a str) -> Self {
        self.bundle_end = s;
        self
    }

    fn error<T>(&self, msg: String) -> Result<T, String> {
        Err(ParserError::new(&self.file, self.line, msg).to_string())
    }

    pub fn symbols(self) -> Symbols {
        self.symbols
    }

    pub fn first_symbol_address(&self) -> Option<u64> {
        self.symbols.as_slice().first().map(|(addr, _)| *addr)
    }

    pub fn parse(&mut self, output: &mut Test<'a>) -> Result<bool, String> {
        output.bytes.clear();
        output.asm.clear();

        let mut empty_lines = true;
        let mut first = true;
        while let Some(line) = self.lines.next().map(|l| l.trim()) {
            self.line += 1;

            let (line, comment) = line.split_once('#').unwrap_or((line, ""));

            let mut cur = line.trim();
            if empty_lines && (cur.is_empty() || cur == "...") {
                continue;
            }
            empty_lines = false;

            if !self.bundle_end.is_empty() && cur.is_empty() {
                return Ok(true);
            }

            if first {
                first = false;
                output.comment = comment.trim();
                output.line = self.line;
            }

            // parse address
            output.address = 0;
            if let Some(pos) = cur.find(':') {
                let (head, tail) = cur.split_at(pos);
                if let Some(pos) = head.find('<') {
                    // parse symbol
                    let (head, tail) = head.split_at(pos);
                    let head = head.trim_end();
                    let tail = tail.trim();
                    let address = match u64::from_str_radix(head, 16) {
                        Ok(i) => i,
                        Err(_) => {
                            return self.error(format!("invalid symbol address \"{head}\""));
                        }
                    };
                    if !tail.ends_with('>') {
                        return self.error(format!("invalid symbol \"{tail}\""));
                    }
                    let tail = &tail[1..tail.len() - 1];
                    self.symbols.push(address, tail);
                    empty_lines = true;
                    continue;
                }
                if head.chars().count() < 17 {
                    match u64::from_str_radix(head, 16) {
                        Ok(i) => output.address = i,
                        Err(_) => {
                            return self.error(format!("invalid address \"{head}\""));
                        }
                    }
                    cur = tail[1..].trim_start();
                }
            }

            // '\' is an escape to asm
            if cur.starts_with('\\') {
                cur = cur.trim_start_matches('\\');
            } else {
                // parse bytes
                while !cur.is_empty() {
                    let stop = cur.chars().take_while(|c| c.is_whitespace()).count() > 1;
                    cur = cur.trim_start();
                    if stop {
                        break;
                    }
                    match cur.find(|c: char| !c.is_ascii_hexdigit()) {
                        Some(pos) if pos >= 2 => {
                            let (head, tail) = cur.split_at(pos);
                            if head.is_empty() {
                                break;
                            }
                            let raw = u64::from_str_radix(head, 16).unwrap();
                            let raw = &raw.to_le_bytes()[..(head.len() + 1) / 2];
                            output.bytes.extend_from_slice(raw);
                            cur = tail;
                        }
                        _ => break,
                    }
                }
            }

            if self.bundle_end.is_empty() && output.bytes.is_empty() {
                return self.error("no instruction bytes".to_owned());
            }

            output.asm.push(cur);

            if self.bundle_end.is_empty() || self.bundle_end == cur.trim() {
                return Ok(true);
            }
        }

        Ok(!output.bytes.is_empty())
    }

    pub fn parse_all(src: &str) -> Result<(u64, Vec<u8>, Symbols), String> {
        let mut parser = Parser::new("input", src);
        let mut test = Test::default();
        let mut start = 0;
        let mut address = 0;
        let mut data = vec![];
        loop {
            match parser.parse(&mut test) {
                Ok(true) => {
                    if address == 0 {
                        start = parser.first_symbol_address().unwrap_or(test.address);
                        address = start;
                    }
                    while address != test.address {
                        data.push(0);
                        address += 1;
                    }
                    data.extend_from_slice(&test.bytes);
                    address += test.bytes.len() as u64;
                }
                Ok(false) => break,
                Err(err) => panic!("error: {err}"),
            }
        }

        Ok((start, data, parser.symbols()))
    }
}

pub fn parse_flags(s: &str) -> impl Iterator<Item = (&str, bool)> {
    s.split_whitespace().filter_map(|i| {
        let state = match i.chars().next() {
            Some('+') => true,
            Some('-') => false,
            _ => return None,
        };
        let name = &i[1..];
        Some((name, state))
    })
}

fn push_insn(out: &mut String, s: &str) {
    for (i, s) in s.split_whitespace().enumerate() {
        if i != 0 {
            out.push(' ');
        }
        out.push_str(s);
    }
}

fn bundle_to_string(printer: &dyn ArchPrinter<()>, bundle: &Bundle) -> String {
    let mut out = String::new();
    let mut buf = String::new();
    for (i, insn) in bundle.iter().enumerate() {
        if i != 0 {
            out.push('\n');
        }
        buf.clear();
        write!(
            &mut buf,
            "{}",
            FormatterFn(|fmt| { printer.print_insn(fmt, &(), insn) })
        )
        .unwrap();
        push_insn(&mut out, &buf);
    }
    out
}

fn expect_to_string(expect: &[&str]) -> String {
    let mut out = String::new();
    for (i, asm) in expect.iter().enumerate() {
        if i != 0 {
            out.push('\n');
        }
        push_insn(&mut out, asm);
    }
    out
}

pub trait Runner<T: Copy> {
    fn create(&mut self, test: &Test) -> (Box<dyn ArchDecoder>, Box<dyn ArchPrinter<()>>);

    fn bundle_end(&self) -> &'static str {
        ""
    }

    fn run(&mut self, file: &str, tests: &str) -> Result<(), String> {
        let mut bundle = Bundle::empty();
        let mut test = Test::default();
        let mut parser = Parser::new(file, tests).set_bundle_end(self.bundle_end());
        let mut failed = 0;
        while parser.parse(&mut test)? {
            let (mut decoder, printer) = self.create(&test);
            let (len, result) = match decoder.decode(test.address, &test.bytes, &mut bundle) {
                Ok(len) => (len / 8, bundle_to_string(&*printer, &bundle)),
                Err(_) => (0, String::new()),
            };

            let expect_len = test.bytes.len();
            let expect = expect_to_string(&test.asm);
            if len == 0 || len != expect_len || result != expect {
                failed += 1;

                if len == 0 {
                    eprintln!("error: failed to decode, {}:{}", file, test.line);
                } else {
                    if len != expect_len {
                        eprintln!("error: invalid length, {}:{}", file, test.line);
                        eprintln!("  expect: {expect_len}");
                        eprintln!("  result: {len}");
                    }
                    if result != expect {
                        eprintln!("error: invalid output, {}:{}", file, test.line);
                    }
                }

                let diff = Diff::new(file, test.line, &test.bytes, &expect, &result);
                eprintln!("{diff}");
            }
        }
        if failed == 0 {
            Ok(())
        } else {
            Err(format!("failed {failed} tests"))
        }
    }
}
