use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Need more bytes to decode an instruction.
    More(usize),
    /// Failed to decode an instruction.
    Failed(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::More(_) => fmt.write_str("Need more data"),
            Self::Failed(_) => fmt.write_str("Failed to decode"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
