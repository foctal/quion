#[cfg(feature = "datagram")]
pub mod datagram {
    use crate::varint::VarInt;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DatagramConfig {
        pub max_frame_size: Option<VarInt>,
    }
}

#[cfg(feature = "unstable-multipath")]
pub mod multipath {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MultipathCapability;
}

#[cfg(feature = "unstable-address-discovery")]
pub mod address_discovery {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AddressDiscoveryCapability;
}

#[cfg(feature = "unstable-nat-traversal")]
pub mod nat_traversal {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NatTraversalCapability;
}
