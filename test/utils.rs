use std::fmt::{self, Write as _};

struct Bytes<'a>(pub &'a [u8]);

impl fmt::Display for Bytes<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i != 0 {
                fmt.write_char(' ')?;
            }
            write!(fmt, "{b:02x}")?;
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug)]
struct Escape<'a>(pub &'a str);

impl std::ops::Deref for Escape<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl fmt::Display for Escape<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut width = 0;
        for line in self.0.lines() {
            for (i, c) in line.char_indices() {
                if line[i..].chars().all(|c| c.is_whitespace()) {
                    for c in line[i..].chars() {
                        width += 1;
                        match c {
                            '\t' => {
                                fmt.write_char('→')?;
                                while width & 7 != 0 {
                                    width += 1;
                                    fmt.write_char(' ')?;
                                }
                            }
                            ' ' => fmt.write_char('•')?,
                            _ => write!(fmt, "{}", c)?,
                        }
                    }
                    break;
                }
                width += 1;
                match c {
                    '\t' => {
                        fmt.write_char('→')?;
                        while width & 7 != 0 {
                            width += 1;
                            fmt.write_char(' ')?;
                        }
                    }
                    _ => write!(fmt, "{}", c)?,
                }
            }
        }
        Ok(())
    }
}

pub struct Diff<'a> {
    file: &'a str,
    line: usize,
    bytes: &'a [u8],
    expect: &'a str,
    result: &'a str,
}

impl<'a> Diff<'a> {
    pub fn new(
        file: &'a str,
        line: usize,
        bytes: &'a [u8],
        expect: &'a str,
        result: &'a str,
    ) -> Self {
        Self {
            file,
            line,
            bytes,
            expect,
            result,
        }
    }
}

impl fmt::Display for Diff<'_> {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        use diff::Result as E;
        let w = 5;
        if !self.file.is_empty() {
            writeln!(out, "{:w$}--> {}", ' ', self.file)?;
        }
        if !self.bytes.is_empty() {
            for (i, chunk) in self.bytes.chunks(8).enumerate() {
                let prefix = if i == 0 { "raw | " } else { "| " };
                writeln!(out, "{prefix:>8}{}", Bytes(chunk))?;
            }
            writeln!(out, "{:7}{:-<24}", ' ', ' ')?;
        }
        let mut ln = std::cmp::max(self.line, 1);
        let mut ln2 = ln;
        for diff in diff::lines(self.expect, self.result) {
            match diff {
                E::Left(l) => {
                    writeln!(out, "{ln:w$} - {}↴", Escape(l))?;
                    ln += 1;
                }
                E::Both(l, _) => {
                    writeln!(out, "{ln:w$} | {}↴", Escape(l))?;
                    ln += 1;
                    ln2 = ln;
                }
                E::Right(r) => {
                    writeln!(out, "{ln2:w$} + {}↴", Escape(r))?;
                    ln2 += 1;
                }
            }
        }
        Ok(())
    }
}

pub fn check(file: &str, line: usize, left: &str, right: &str) -> Result<(), String> {
    if left != right {
        let err = "invalid result";
        eprintln!("error: {err}");
        eprintln!("{}", Diff::new(file, line, &[], left, right));
        return Err(err.to_string());
    }
    Ok(())
}
