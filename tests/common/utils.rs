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
