use std::fmt;

pub struct Bytes<'a>(pub &'a [u8]);

impl fmt::Display for Bytes<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("[")?;
        for (i, b) in self.0.iter().enumerate() {
            if i != 0 {
                fmt.write_str(", ")?;
            }
            write!(fmt, "{b:02x}")?;
        }
        fmt.write_str("]")
    }
}

#[derive(PartialEq, Eq, Debug)]
struct Escape<'a>(pub &'a str);

impl<'a> std::ops::Deref for Escape<'a> {
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
                                write!(fmt, "{}", '→')?;
                                while width & 7 != 0 {
                                    width += 1;
                                    write!(fmt, " ")?;
                                }
                            }
                            ' ' => write!(fmt, "•")?,
                            _ => write!(fmt, "{}", c)?,
                        }
                    }
                    break;
                }
                width += 1;
                match c {
                    '\t' => {
                        write!(fmt, "{}", '→')?;
                        while width & 7 != 0 {
                            width += 1;
                            write!(fmt, " ")?;
                        }
                    }
                    _ => write!(fmt, "{}", c)?,
                }
            }
        }
        Ok(())
    }
}

#[rustfmt::skip]
fn diff(file: &str, left: &str, right: &str) {
    use diff::Result as E;
    let w = std::cmp::max(left.lines().count(), right.lines().count()).ilog10() as usize + 2;
    eprintln!("{:w$}--> {file}", ' ');
    let mut ln = 1;
    for diff in diff::lines(left, right) {
        match diff {
            E::Left(l)    => eprintln!("{ln:w$} -{}↴", Escape(l)),
            E::Both(l, _) => eprintln!("{ln:w$} |{}↴", Escape(l)),
            E::Right(r)   => eprintln!("{ln:w$} +{}↴", Escape(r)),
        }
        if matches!(diff, E::Both(..) | E::Right(_)) {
            ln += 1;
        }
    }
}

pub fn check(file: &str, left: &str, right: &str) -> Result<(), String> {
    if left != right {
        let err = "invalid result";
        eprintln!("error: {err}");
        diff(file, left, &right);
        eprintln!();
        return Err(err.to_string());
    }
    Ok(())
}
