use core::fmt;

use crate::error::{CodecError, Result};

pub const MAX_CONNECTION_ID_LEN: usize = 20;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId {
    len: u8,
    bytes: [u8; MAX_CONNECTION_ID_LEN],
}

impl ConnectionId {
    pub const EMPTY: Self = Self {
        len: 0,
        bytes: [0; MAX_CONNECTION_ID_LEN],
    };

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CONNECTION_ID_LEN {
            return Err(CodecError::ValueOutOfBounds);
        }
        let mut cid = Self::EMPTY;
        cid.len = bytes.len() as u8;
        cid.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(cid)
    }

    pub fn decode_fixed(bytes: &[u8]) -> Result<Self> {
        Self::from_slice(bytes)
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConnectionId(")?;
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}
