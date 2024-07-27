use super::Bytes;
use disasm::{Arch, Bundle, Disasm, Options};
use std::{fmt, str::Lines};

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
}

impl<'a> Parser<'a> {
    pub fn new(file: &str, input: &'a str) -> Self {
        Self {
            file: file.to_owned(),
            lines: input.lines(),
            line: 0,
        }
    }

    fn error<T>(&self, msg: String) -> Result<T, String> {
        Err(ParserError::new(&self.file, self.line, msg).to_string())
    }

    pub fn parse(&mut self, output: &mut Test<'a>) -> Result<bool, String> {
        while let Some(line) = self.lines.next().map(|l| l.trim()) {
            self.line += 1;

            let (line, comment) = line.split_once('#').unwrap_or((line, ""));
            let mut cur = line.trim();
            if cur.is_empty() {
                continue;
            }

            // parse address
            output.address = 0;
            if let Some(pos) = cur.find(':') {
                let (head, tail) = cur.split_at(pos);
                match u64::from_str_radix(head, 16) {
                    Ok(i) => output.address = i,
                    Err(_) => {
                        return self.error(format!("invalid address \"{head}\""));
                    }
                }
                cur = tail[1..].trim_start();
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
}

pub fn run<F>(file: &str, tests: &str, init: F) -> Result<(), String>
where
    F: Fn(&Test) -> (Arch, Options),
{
    let mut bundle = Bundle::empty();
    let mut test = Test::default();
    let mut parser = Parser::new(file, tests);
    while parser.parse(&mut test)? {
        let expect = test.asm[0];
        let expect_len = test.bytes.len();
        let (arch, opts) = init(&test);
        let mut disasm = Disasm::new(arch, test.address, opts);
        if let Ok(len) = disasm.decode(&test.bytes, &mut bundle) {
            let printer = bundle[0].printer(&disasm, ());
            let mnemonic = printer.mnemonic().to_string();
            let operands = printer.operands().to_string();
            let result = (mnemonic.as_str(), operands.as_str());
            assert_eq!(
                len, expect_len,
                "decoded {len} bytes, expected {expect_len} bytes, {file}:{}",
                test.line
            );
            assert_eq!(result, expect, "invalid result, {file}:{}", test.line);
        } else {
            let raw = Bytes(&test.bytes);
            panic!("failed to decode {raw}, expected {expect:?}");
        }
    }

    Ok(())
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
