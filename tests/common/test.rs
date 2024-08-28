use std::{fmt, str::Lines};

use disasm::{Arch, Bundle, Disasm, Options, Symbols};

use super::Bytes;

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
    pub asm: Vec<(&'a str, &'a str)>,
}

pub struct Parser<'a> {
    file: String,
    lines: Lines<'a>,
    line: usize,
    symbols: Symbols,
}

impl<'a> Parser<'a> {
    pub fn new(file: &str, input: &'a str) -> Self {
        Self {
            file: file.to_owned(),
            lines: input.lines(),
            line: 0,
            symbols: Symbols::default(),
        }
    }

    fn error<T>(&self, msg: String) -> Result<T, String> {
        Err(ParserError::new(&self.file, self.line, msg).to_string())
    }

    pub fn symbols(self) -> Symbols {
        self.symbols
    }

    pub fn first_symbol_address(&self) -> Option<u64> {
        self.symbols.as_slice().get(0).map(|(addr, _)| *addr)
    }

    pub fn parse(&mut self, output: &mut Test<'a>) -> Result<bool, String> {
        while let Some(line) = self.lines.next().map(|l| l.trim()) {
            self.line += 1;

            let (line, comment) = line.split_once('#').unwrap_or((line, ""));

            let mut cur = line.trim();
            if cur.is_empty() || cur == "..." {
                continue;
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

            // parse bytes
            output.bytes.clear();
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

            if output.bytes.is_empty() {
                return self.error(format!("no instruction bytes"));
            }

            // parse mnemonic
            let mnemonic = if cur.starts_with('"') {
                match cur[1..].split_once('"') {
                    Some((head, tail)) => {
                        cur = tail.trim_start();
                        head
                    }
                    None => {
                        return self.error(format!("missing closing '\"'"));
                    }
                }
            } else {
                let (head, tail) = cur
                    .split_once(|c: char| c.is_whitespace())
                    .unwrap_or((cur, ""));
                cur = tail.trim_start();
                head
            };

            output.comment = comment.trim();
            output.line = self.line;
            output.asm.clear();
            output.asm.push((mnemonic, cur));

            return Ok(true);
        }

        Ok(false)
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

struct ErrorReport<'a> {
    file: &'a str,
    test: &'a Test<'a>,
    msg: &'a str,
    result: Option<(&'a str, &'a str, usize)>,
}

impl<'a> ErrorReport<'a> {
    fn new(file: &'a str, test: &'a Test) -> Self {
        Self {
            file,
            test,
            msg: "unspecified fail",
            result: None,
        }
    }

    fn result(self, mnemonic: &'a str, operands: &'a str, len: usize) -> Self {
        Self {
            result: Some((mnemonic, operands, len)),
            ..self
        }
    }

    fn msg(self, msg: &'a str) -> Self {
        Self { msg, ..self }
    }
}

impl fmt::Display for ErrorReport<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let raw = Bytes(&self.test.bytes);
        let (m, o) = self.test.asm[0];
        let l1 = self.test.bytes.len();
        let match_len = self.result.map(|(_, _, l2)| l1 == l2).unwrap_or(true);
        writeln!(fmt, "error: {}, {}:{}", self.msg, self.file, self.test.line)?;
        writeln!(fmt, "    raw: {raw}")?;
        write!(fmt, "    expect: {m:?} {o:?}")?;
        if !match_len {
            write!(fmt, " ({l1} bytes)")?;
        }
        writeln!(fmt)?;
        if let Some((m, o, l2)) = self.result {
            write!(fmt, "    result: {m:?} {o:?}")?;
            if !match_len {
                write!(fmt, " ({l2} bytes)")?;
            }
            writeln!(fmt)?;
        }
        fmt.write_str("\n")
    }
}

pub fn run<F>(file: &str, tests: &str, init: F) -> Result<(), String>
where
    F: Fn(&Test) -> (Arch, Options),
{
    let mut bundle = Bundle::empty();
    let mut test = Test::default();
    let mut parser = Parser::new(file, tests);
    let mut failed = 0;
    while parser.parse(&mut test)? {
        let expect = test.asm[0];
        let (arch, opts) = init(&test);
        let mut disasm = Disasm::new(arch, test.address, opts);
        let report = ErrorReport::new(file, &test);
        if let Ok(len) = disasm.decode(&test.bytes, &mut bundle) {
            let printer = bundle[0].printer(&disasm, &());
            let mnemonic = printer.mnemonic().to_string();
            let operands = printer.operands().to_string();
            let report = report.result(&mnemonic, &operands, len);
            if mnemonic != expect.0 {
                eprint!("{}", report.msg("invalid mnemonic"));
                failed += 1;
            } else if operands != expect.1 {
                eprint!("{}", report.msg("invalid operands"));
                failed += 1;
            } else if len != test.bytes.len() {
                eprint!("{}", report.msg("invalid length"));
                failed += 1;
            }
        } else {
            eprint!("{}", report.msg("failed to decode"));
            failed += 1;
        }
    }
    if failed == 0 {
        Ok(())
    } else {
        Err(format!("failed {failed} tests"))
    }
}

pub fn parse_flags(s: &str) -> impl Iterator<Item = (bool, &str)> {
    s.split_whitespace().filter_map(|i| {
        let flag = match i.chars().next() {
            Some('+') => true,
            Some('-') => false,
            _ => return None,
        };
        let name = &i[1..];
        Some((flag, name))
    })
}
