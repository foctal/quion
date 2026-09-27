//! Explicit Congestion Notification metadata.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnCodepoint {
    Ect0,
    Ect1,
    Ce,
}

impl EcnCodepoint {
    pub const fn bits(self) -> u8 {
        match self {
            Self::Ect0 => 0b10,
            Self::Ect1 => 0b01,
            Self::Ce => 0b11,
        }
    }

    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0b11 {
            0b10 => Some(Self::Ect0),
            0b01 => Some(Self::Ect1),
            0b11 => Some(Self::Ce),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcnCapabilities {
    pub read: bool,
    pub write: bool,
}

impl EcnCapabilities {
    pub const NONE: Self = Self {
        read: false,
        write: false,
    };

    pub const fn new(read: bool, write: bool) -> Self {
        Self { read, write }
    }
}
