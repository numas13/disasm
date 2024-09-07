use core::cmp;

use crate::Error;

pub struct Bytes<'a> {
    data: &'a [u8],
    offset: usize,
}

#[allow(dead_code)]
impl<'a> Bytes<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn as_slice(&self) -> &'a [u8] {
        self.data
    }

    pub fn tail(&self) -> &'a [u8] {
        &self.data[self.offset..]
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    pub fn advance(&mut self, count: usize) {
        self.offset += count;
    }

    pub fn peek_u8(&self) -> Option<u8> {
        self.data.get(self.offset).copied()
    }

    /// Returns a slice up to `max_len` bytes.
    pub fn peek_slice(&self, max_len: usize) -> &'a [u8] {
        let len = cmp::min(max_len, self.remaining());
        &self.tail()[..len]
    }

    /// Returns an array filled with up to `N` bytes.
    pub fn peek_array<const N: usize>(&self) -> (usize, [u8; N]) {
        let slice = self.peek_slice(N);
        let mut array = [0; N];
        array[..slice.len()].copy_from_slice(slice);
        (slice.len(), array)
    }

    pub fn read(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if self.offset + len > self.data.len() {
            return Err(Error::More((self.offset + len) * 8));
        }
        let bytes = &self.data[self.offset..self.offset + len];
        self.offset += len;
        Ok(bytes)
    }

    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut raw = [0; N];
        raw.copy_from_slice(self.read(N)?);
        Ok(raw)
    }

    pub fn read_u8(&mut self) -> Result<u8, Error> {
        Ok(self.read_array::<1>()?[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }

    pub fn read_u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    pub fn read_u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    pub fn read_i8(&mut self) -> Result<i8, Error> {
        Ok(self.read_u8()? as i8)
    }

    pub fn read_i16(&mut self) -> Result<i16, Error> {
        Ok(self.read_u16()? as i16)
    }

    pub fn read_i32(&mut self) -> Result<i32, Error> {
        Ok(self.read_u32()? as i32)
    }

    pub fn read_i64(&mut self) -> Result<i64, Error> {
        Ok(self.read_u64()? as i64)
    }
}
