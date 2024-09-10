use crate::utils::{deposit, zextract};

#[derive(Copy, Clone, Debug)]
pub struct Field {
    start: u8,
    size: u8,
}

impl Field {
    pub const fn new(start: u8, size: u8) -> Self {
        debug_assert!(size != 0 && start < 32 && (start + size) <= 32);
        Self { start, size }
    }

    pub const fn start(&self) -> u32 {
        self.start as u32
    }

    pub const fn size(&self) -> u32 {
        self.size as u32
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
        zextract(self.raw, field.start(), field.size())
    }

    pub fn field_set(&mut self, field: Field, value: u32) -> &mut Self {
        self.raw = deposit(self.raw, field.start(), field.size(), value);
        self
    }

    pub fn field_set_if(&mut self, field: Field, value: u32, cond: bool) -> &mut Self {
        if cond {
            self.raw = deposit(self.raw, field.start(), field.size(), value);
        }
        self
    }
}
