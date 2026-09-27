use crate::{
    error::{CodecError, Result},
    varint::VarInt,
};

#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    pub const fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }

    pub const fn consumed(&self) -> usize {
        self.offset
    }

    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn get_u8(&mut self) -> Result<u8> {
        let value = *self
            .input
            .get(self.offset)
            .ok_or(CodecError::UnexpectedEnd)?;
        self.offset += 1;
        Ok(value)
    }

    pub fn get_u16(&mut self) -> Result<u16> {
        let bytes = self.get_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn get_u32(&mut self) -> Result<u32> {
        let bytes = self.get_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn get_u64(&mut self) -> Result<u64> {
        let bytes = self.get_bytes(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub fn get_var(&mut self) -> Result<VarInt> {
        let (value, consumed) = VarInt::decode(&self.input[self.offset..])?;
        self.offset += consumed;
        Ok(value)
    }

    pub fn get_var_minimal(&mut self) -> Result<VarInt> {
        let (value, consumed) = VarInt::decode_minimal(&self.input[self.offset..])?;
        self.offset += consumed;
        Ok(value)
    }

    pub fn get_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(CodecError::UnexpectedEnd)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(CodecError::UnexpectedEnd)?;
        self.offset = end;
        Ok(bytes)
    }
}

#[derive(Debug, Default, Clone)]
pub struct Writer {
    output: Vec<u8>,
}

impl Writer {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            output: Vec::with_capacity(capacity),
        }
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) fn from_vec(output: Vec<u8>) -> Self {
        Self { output }
    }

    pub fn put_u8(&mut self, value: u8) {
        self.output.push(value);
    }

    pub fn put_u16(&mut self, value: u16) {
        self.output.extend_from_slice(&value.to_be_bytes());
    }

    pub fn put_u32(&mut self, value: u32) {
        self.output.extend_from_slice(&value.to_be_bytes());
    }

    pub fn put_u64(&mut self, value: u64) {
        self.output.extend_from_slice(&value.to_be_bytes());
    }

    pub fn put_var(&mut self, value: VarInt) {
        value.encode(&mut self.output);
    }

    pub fn put_bytes(&mut self, bytes: &[u8]) {
        self.output.extend_from_slice(bytes);
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.output
    }
}
