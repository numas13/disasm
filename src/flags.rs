use crate::utils::{deposit, zextract};

#[derive(Copy, Clone, Debug)]
pub struct Field {
    start: u8,
    len: u8,
}

impl Field {
    pub const fn new(start: u8, len: u8) -> Self {
        debug_assert!(len != 0 && start < 32 && (start + len) <= 32);
        Self { start, len }
    }

    pub const fn start(&self) -> u32 {
        self.start as u32
    }

    pub const fn len(&self) -> u32 {
        self.len as u32
    }
}

#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct Flags {
    raw: u32,
}

impl Flags {
    pub fn empty() -> Self {
        Self { raw: 0 }
    }

    pub fn clear(&mut self, flags: u32) -> &mut Self {
        self.raw &= !flags;
        self
    }

    pub fn set(&mut self, flags: u32) -> &mut Self {
        self.raw |= flags;
        self
    }

    pub fn set_if(&mut self, flags: u32, cond: bool) -> &mut Self {
        if cond {
            self.raw |= flags;
        } else {
            self.raw &= !flags;
        }
        self
    }

    pub fn any(&self, flags: u32) -> bool {
        self.raw & flags != 0
    }

    pub fn all(&self, flags: u32) -> bool {
        self.raw & flags == flags
    }

    pub fn field(&self, field: Field) -> u32 {
        zextract(self.raw, field.start(), field.len())
    }

    pub fn field_set(&mut self, field: Field, value: u32) -> &mut Self {
        self.raw = deposit(self.raw, field.start(), field.len(), value);
        self
    }
}
