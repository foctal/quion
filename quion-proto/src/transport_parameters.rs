use std::collections::BTreeMap;

use crate::{
    cid::ConnectionId,
    coding::{Reader, Writer},
    config::TransportConfig,
    error::{CodecError, Result},
    transport_error::TransportErrorCode,
    varint::VarInt,
};

pub mod ids {
    pub const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    pub const STATELESS_RESET_TOKEN: u64 = 0x02;
    pub const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
    pub const INITIAL_MAX_DATA: u64 = 0x04;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    pub const ACK_DELAY_EXPONENT: u64 = 0x0a;
    pub const MAX_ACK_DELAY: u64 = 0x0b;
    pub const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
    pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
    pub const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
    pub const RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;
    pub const RESET_STREAM_AT: u64 = 0x1d;
    pub const MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;
    pub const MIN_ACK_DELAY: u64 = 0xff04_de1b;
}

const MAX_ACK_DELAY_LIMIT_MS: u64 = 16_383;
const MAX_STREAM_COUNT: u64 = 1 << 60;
/// Maximum encoded peer transport-parameter bytes retained during a
/// handshake.
pub const MAX_TRANSPORT_PARAMETERS_BYTES: usize = 16 * 1024;
/// Maximum number of distinct peer transport parameters retained.
pub const MAX_TRANSPORT_PARAMETERS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParameters {
    values: BTreeMap<u64, Vec<u8>>,
}

impl Default for TransportParameters {
    fn default() -> Self {
        let mut params = Self {
            values: BTreeMap::new(),
        };
        params.set_var(ids::MAX_UDP_PAYLOAD_SIZE, VarInt::from_u32(65_527));
        params.set_var(ids::ACK_DELAY_EXPONENT, VarInt::from_u32(3));
        params.set_var(ids::MAX_ACK_DELAY, VarInt::from_u32(25));
        params.set_var(ids::ACTIVE_CONNECTION_ID_LIMIT, VarInt::from_u32(2));
        params
    }
}

impl TransportParameters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_config(
        config: &TransportConfig,
        initial_source_cid: &ConnectionId,
        original_destination_cid: Option<&ConnectionId>,
        retry_source_cid: Option<&ConnectionId>,
        max_datagram_frame_size: Option<VarInt>,
        stateless_reset_token: Option<[u8; 16]>,
    ) -> Self {
        let mut params = Self::default();
        params.set_var(ids::MAX_IDLE_TIMEOUT, config.max_idle_timeout_ms);
        params.set_var(
            ids::ACTIVE_CONNECTION_ID_LIMIT,
            config.active_connection_id_limit,
        );
        params.set_var(ids::INITIAL_MAX_DATA, config.initial_max_data);
        params.set_var(
            ids::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            config.initial_max_stream_data_bidi_local,
        );
        params.set_var(
            ids::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            config.initial_max_stream_data_bidi_remote,
        );
        params.set_var(
            ids::INITIAL_MAX_STREAM_DATA_UNI,
            config.initial_max_stream_data_uni,
        );
        params.set_var(
            ids::INITIAL_MAX_STREAMS_BIDI,
            config.initial_max_streams_bidi,
        );
        params.set_var(ids::INITIAL_MAX_STREAMS_UNI, config.initial_max_streams_uni);
        if let Some(min_ack_delay) = config.min_ack_delay {
            params.set_var(ids::MIN_ACK_DELAY, min_ack_delay);
        }
        params.set_bytes(
            ids::INITIAL_SOURCE_CONNECTION_ID,
            initial_source_cid.as_bytes().to_vec(),
        );
        if let Some(cid) = original_destination_cid {
            params.set_bytes(
                ids::ORIGINAL_DESTINATION_CONNECTION_ID,
                cid.as_bytes().to_vec(),
            );
        }
        if let Some(cid) = retry_source_cid {
            params.set_bytes(ids::RETRY_SOURCE_CONNECTION_ID, cid.as_bytes().to_vec());
        }
        if let Some(max_datagram_frame_size) =
            max_datagram_frame_size.or(config.max_datagram_frame_size)
        {
            params.set_var(ids::MAX_DATAGRAM_FRAME_SIZE, max_datagram_frame_size);
        }
        if config.reset_stream_at {
            params.set_bytes(ids::RESET_STREAM_AT, []);
        }
        if config.disable_active_migration {
            params.set_bytes(ids::DISABLE_ACTIVE_MIGRATION, []);
        }
        if let Some(stateless_reset_token) = stateless_reset_token {
            params.set_bytes(ids::STATELESS_RESET_TOKEN, stateless_reset_token);
        }
        params
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        Self::decode_inner(input).map_err(|error| match error {
            CodecError::DuplicateTransportParameter(_) => error,
            CodecError::Transport(TransportErrorCode::TransportParameterError) => error,
            _ => CodecError::MalformedTransportParameter,
        })
    }

    fn decode_inner(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_TRANSPORT_PARAMETERS_BYTES {
            return Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError,
            ));
        }
        let mut r = Reader::new(input);
        let mut values = BTreeMap::new();
        while !r.is_empty() {
            if values.len() >= MAX_TRANSPORT_PARAMETERS {
                return Err(CodecError::Transport(
                    TransportErrorCode::TransportParameterError,
                ));
            }
            let id = r.get_var()?.into_inner();
            let len = r.get_var()?.into_inner() as usize;
            let value = r.get_bytes(len)?.to_vec();
            if values.insert(id, value).is_some() {
                return Err(CodecError::DuplicateTransportParameter(id));
            }
        }
        Ok(Self { values })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.values.len() * 8);
        for (id, value) in &self.values {
            w.put_var(VarInt::new(*id).unwrap_or(VarInt::MAX));
            w.put_var(VarInt::new(value.len() as u64).unwrap_or(VarInt::MAX));
            w.put_bytes(value);
        }
        w.into_vec()
    }

    pub fn get(&self, id: u64) -> Option<&[u8]> {
        self.values.get(&id).map(Vec::as_slice)
    }

    pub fn get_var(&self, id: u64) -> Result<Option<VarInt>> {
        self.get(id)
            .map(|bytes| Reader::new(bytes).get_var())
            .transpose()
    }

    pub fn validate_quic_basics(&self) -> Result<()> {
        for id in [
            ids::MAX_IDLE_TIMEOUT,
            ids::MAX_UDP_PAYLOAD_SIZE,
            ids::INITIAL_MAX_DATA,
            ids::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            ids::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            ids::INITIAL_MAX_STREAM_DATA_UNI,
            ids::INITIAL_MAX_STREAMS_BIDI,
            ids::INITIAL_MAX_STREAMS_UNI,
            ids::ACK_DELAY_EXPONENT,
            ids::MAX_ACK_DELAY,
            ids::ACTIVE_CONNECTION_ID_LIMIT,
            ids::MAX_DATAGRAM_FRAME_SIZE,
            ids::MIN_ACK_DELAY,
        ] {
            validate_varint_parameter(self, id)?;
        }
        if self
            .get_var(ids::MAX_UDP_PAYLOAD_SIZE)?
            .is_some_and(|value| value.into_inner() < 1200)
        {
            return Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError,
            ));
        }
        if self
            .get_var(ids::ACK_DELAY_EXPONENT)?
            .is_some_and(|value| value.into_inner() > 20)
        {
            return Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError,
            ));
        }
        if self
            .get_var(ids::ACTIVE_CONNECTION_ID_LIMIT)?
            .is_some_and(|value| value.into_inner() < 2)
        {
            return Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError,
            ));
        }
        validate_connection_id_parameter(self, ids::ORIGINAL_DESTINATION_CONNECTION_ID)?;
        validate_connection_id_parameter(self, ids::INITIAL_SOURCE_CONNECTION_ID)?;
        validate_connection_id_parameter(self, ids::RETRY_SOURCE_CONNECTION_ID)?;
        validate_zero_length_parameter(self, ids::DISABLE_ACTIVE_MIGRATION)?;
        validate_zero_length_parameter(self, ids::RESET_STREAM_AT)?;
        validate_max_ack_delay(self)?;
        validate_min_ack_delay(self)?;
        validate_datagram_parameter(self)?;
        validate_stream_count_parameter(self, ids::INITIAL_MAX_STREAMS_BIDI)?;
        validate_stream_count_parameter(self, ids::INITIAL_MAX_STREAMS_UNI)?;
        Ok(())
    }

    pub fn validate_server_parameters(
        &self,
        original_destination_cid: &ConnectionId,
        initial_source_cid: &ConnectionId,
        retry_source_cid: Option<&ConnectionId>,
    ) -> Result<()> {
        self.validate_quic_basics()?;
        require_connection_id_parameter(
            self,
            ids::ORIGINAL_DESTINATION_CONNECTION_ID,
            original_destination_cid,
        )?;
        require_connection_id_parameter(
            self,
            ids::INITIAL_SOURCE_CONNECTION_ID,
            initial_source_cid,
        )?;
        match retry_source_cid {
            Some(expected) => {
                require_connection_id_parameter(self, ids::RETRY_SOURCE_CONNECTION_ID, expected)?;
            }
            None => {
                reject_parameter(self, ids::RETRY_SOURCE_CONNECTION_ID)?;
            }
        }
        validate_stateless_reset_token(self)?;
        Ok(())
    }

    pub fn validate_client_parameters(&self, initial_source_cid: &ConnectionId) -> Result<()> {
        self.validate_quic_basics()?;
        require_connection_id_parameter(
            self,
            ids::INITIAL_SOURCE_CONNECTION_ID,
            initial_source_cid,
        )?;
        reject_parameter(self, ids::ORIGINAL_DESTINATION_CONNECTION_ID)?;
        reject_parameter(self, ids::RETRY_SOURCE_CONNECTION_ID)?;
        reject_parameter(self, ids::STATELESS_RESET_TOKEN)?;
        Ok(())
    }

    pub fn validate_zero_rtt_compatibility(&self, cached: &Self) -> Result<()> {
        const MONOTONIC_PARAMETERS: [u64; 8] = [
            ids::ACTIVE_CONNECTION_ID_LIMIT,
            ids::INITIAL_MAX_DATA,
            ids::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            ids::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            ids::INITIAL_MAX_STREAM_DATA_UNI,
            ids::INITIAL_MAX_STREAMS_BIDI,
            ids::INITIAL_MAX_STREAMS_UNI,
            ids::MAX_DATAGRAM_FRAME_SIZE,
        ];
        for id in MONOTONIC_PARAMETERS {
            let current = self.get_var(id)?.unwrap_or(VarInt::ZERO);
            let cached = cached.get_var(id)?.unwrap_or(VarInt::ZERO);
            if current < cached {
                return Err(CodecError::Transport(TransportErrorCode::ProtocolViolation));
            }
        }
        Ok(())
    }

    pub fn set_bytes(&mut self, id: u64, value: impl Into<Vec<u8>>) {
        self.values.insert(id, value.into());
    }

    pub fn set_var(&mut self, id: u64, value: VarInt) {
        let mut bytes = Vec::new();
        value.encode(&mut bytes);
        self.set_bytes(id, bytes);
    }

    pub fn remove(&mut self, id: u64) -> Option<Vec<u8>> {
        self.values.remove(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.values
            .iter()
            .map(|(id, value)| (*id, value.as_slice()))
    }
}

fn validate_connection_id_parameter(params: &TransportParameters, id: u64) -> Result<()> {
    if params.get(id).is_some_and(|value| value.len() > 20) {
        return Err(CodecError::Transport(
            TransportErrorCode::TransportParameterError,
        ));
    }
    Ok(())
}

fn require_connection_id_parameter(
    params: &TransportParameters,
    id: u64,
    expected: &ConnectionId,
) -> Result<()> {
    if params.get(id) != Some(expected.as_bytes()) {
        return Err(CodecError::Transport(
            TransportErrorCode::TransportParameterError,
        ));
    }
    Ok(())
}

fn reject_parameter(params: &TransportParameters, id: u64) -> Result<()> {
    if params.get(id).is_some() {
        return Err(CodecError::Transport(
            TransportErrorCode::TransportParameterError,
        ));
    }
    Ok(())
}

fn validate_max_ack_delay(params: &TransportParameters) -> Result<()> {
    if params
        .get_var(ids::MAX_ACK_DELAY)?
        .is_some_and(|value| value.into_inner() > MAX_ACK_DELAY_LIMIT_MS)
    {
        return Err(CodecError::Transport(
            TransportErrorCode::TransportParameterError,
        ));
    }
    Ok(())
}

fn validate_min_ack_delay(params: &TransportParameters) -> Result<()> {
    let Some(min_ack_delay) = params.get_var(ids::MIN_ACK_DELAY)? else {
        return Ok(());
    };
    let max_ack_delay_ms = params
        .get_var(ids::MAX_ACK_DELAY)?
        .unwrap_or(VarInt::from_u32(25))
        .into_inner();
    if min_ack_delay.into_inner() > max_ack_delay_ms.saturating_mul(1_000) {
        return Err(CodecError::Transport(
            TransportErrorCode::TransportParameterError,
        ));
    }
    Ok(())
}

fn validate_zero_length_parameter(params: &TransportParameters, id: u64) -> Result<()> {
    if params.get(id).is_some_and(|value| !value.is_empty()) {
        return Err(CodecError::Transport(
            TransportErrorCode::TransportParameterError,
        ));
    }
    Ok(())
}

fn validate_varint_parameter(params: &TransportParameters, id: u64) -> Result<()> {
    let Some(bytes) = params.get(id) else {
        return Ok(());
    };
    let mut reader = Reader::new(bytes);
    reader
        .get_var()
        .map_err(|_| CodecError::Transport(TransportErrorCode::TransportParameterError))?;
    if !reader.is_empty() {
        return Err(CodecError::Transport(
            TransportErrorCode::TransportParameterError,
        ));
    }
    Ok(())
}

fn validate_stream_count_parameter(params: &TransportParameters, id: u64) -> Result<()> {
    if params
        .get_var(id)?
        .is_some_and(|value| value.into_inner() > MAX_STREAM_COUNT)
    {
        return Err(CodecError::Transport(
            TransportErrorCode::TransportParameterError,
        ));
    }
    Ok(())
}

fn validate_datagram_parameter(params: &TransportParameters) -> Result<()> {
    // Zero explicitly disables DATAGRAM reception and is a valid value.
    params.get_var(ids::MAX_DATAGRAM_FRAME_SIZE)?;
    Ok(())
}

fn validate_stateless_reset_token(params: &TransportParameters) -> Result<()> {
    if params
        .get(ids::STATELESS_RESET_TOKEN)
        .is_some_and(|value| value.len() != 16)
    {
        return Err(CodecError::Transport(
            TransportErrorCode::TransportParameterError,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn roundtrip_parameters() {
        let mut params = TransportParameters::new();
        params.set_var(ids::INITIAL_MAX_DATA, VarInt::from_u32(1024));
        params.set_bytes(ids::INITIAL_SOURCE_CONNECTION_ID, b"cid".to_vec());
        let encoded = params.encode();
        let decoded = TransportParameters::decode(&encoded).unwrap();
        assert_eq!(decoded, params);
        assert_eq!(
            decoded.get_var(ids::INITIAL_MAX_DATA).unwrap(),
            Some(VarInt::from_u32(1024))
        );
    }

    #[test]
    fn rejects_duplicate_parameter() {
        let mut encoded = Vec::new();
        VarInt::from_u32(ids::MAX_IDLE_TIMEOUT as u32).encode(&mut encoded);
        VarInt::ZERO.encode(&mut encoded);
        VarInt::from_u32(ids::MAX_IDLE_TIMEOUT as u32).encode(&mut encoded);
        VarInt::ZERO.encode(&mut encoded);
        assert_eq!(
            TransportParameters::decode(&encoded),
            Err(CodecError::DuplicateTransportParameter(
                ids::MAX_IDLE_TIMEOUT
            ))
        );
    }

    #[test]
    fn accepts_non_minimal_transport_parameter_integers() {
        let encoded = [
            0x40, 0x01, // non-minimal parameter ID 1
            0x40, 0x00, // non-minimal zero-length value
        ];

        let decoded = TransportParameters::decode(&encoded).unwrap();
        assert_eq!(decoded.get(1), Some(&[][..]));
    }

    #[test]
    fn truncated_transport_parameter_maps_to_transport_parameter_error() {
        let error = TransportParameters::decode(&[0x01, 0x40]).unwrap_err();

        assert_eq!(error, CodecError::MalformedTransportParameter);
        assert_eq!(
            error.transport_code(),
            TransportErrorCode::TransportParameterError
        );
    }

    #[test]
    fn bounds_peer_transport_parameter_count_and_bytes() {
        let mut too_many = Vec::new();
        for id in 0..=MAX_TRANSPORT_PARAMETERS {
            VarInt::new(1_000 + id as u64)
                .unwrap()
                .encode(&mut too_many);
            VarInt::ZERO.encode(&mut too_many);
        }
        assert_eq!(
            TransportParameters::decode(&too_many),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );

        let oversized = vec![0; MAX_TRANSPORT_PARAMETERS_BYTES + 1];
        assert_eq!(
            TransportParameters::decode(&oversized),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );
    }

    #[test]
    fn builds_transport_parameters_from_config() {
        let config = TransportConfig {
            keep_alive_interval: None,
            max_stream_metadata_entries: 16_384,
            congestion_algorithm: crate::congestion::CongestionAlgorithm::NewReno,
            initial_mtu: 1200,
            mtu_discovery: Some(crate::mtud::MtuDiscoveryConfig::default()),
            initial_max_data: VarInt::from_u32(42_000),
            initial_max_stream_data_bidi_local: VarInt::from_u32(1_000),
            initial_max_stream_data_bidi_remote: VarInt::from_u32(2_000),
            initial_max_stream_data_uni: VarInt::from_u32(3_000),
            initial_max_streams_bidi: VarInt::from_u32(4),
            initial_max_streams_uni: VarInt::from_u32(5),
            max_idle_timeout_ms: VarInt::from_u32(10_000),
            min_ack_delay: Some(VarInt::from_u32(1_000)),
            ack_frequency_config: None,
            active_connection_id_limit: VarInt::from_u32(7),
            max_datagram_frame_size: None,
            reset_stream_at: true,
            max_queued_datagrams: TransportConfig::default().max_queued_datagrams,
            max_queued_datagram_bytes: TransportConfig::default().max_queued_datagram_bytes,
            max_queued_control_frames: TransportConfig::default().max_queued_control_frames,
            max_ack_ranges_per_space: TransportConfig::default().max_ack_ranges_per_space,
            max_crypto_buffered_data: TransportConfig::default().max_crypto_buffered_data,
            max_send_buffered_stream_data: TransportConfig::default().max_send_buffered_stream_data,
            max_recv_buffered_stream_data: TransportConfig::default().max_recv_buffered_stream_data,
            max_recv_buffered_stream_data_per_connection: TransportConfig::default()
                .max_recv_buffered_stream_data_per_connection,
            disable_active_migration: true,
            connection_id_length: 0,
        };
        let initial_source = ConnectionId::from_slice(b"initial").unwrap();
        let original = ConnectionId::from_slice(b"original").unwrap();
        let retry = ConnectionId::from_slice(b"retry").unwrap();

        let params = TransportParameters::from_config(
            &config,
            &initial_source,
            Some(&original),
            Some(&retry),
            Some(VarInt::from_u32(1200)),
            Some([9; 16]),
        );

        assert_eq!(
            params.get_var(ids::INITIAL_MAX_DATA).unwrap(),
            Some(VarInt::from_u32(42_000))
        );
        assert_eq!(
            params.get(ids::INITIAL_SOURCE_CONNECTION_ID),
            Some(initial_source.as_bytes())
        );
        assert_eq!(
            params.get(ids::ORIGINAL_DESTINATION_CONNECTION_ID),
            Some(original.as_bytes())
        );
        assert_eq!(
            params.get(ids::RETRY_SOURCE_CONNECTION_ID),
            Some(retry.as_bytes())
        );
        assert_eq!(params.get(ids::STATELESS_RESET_TOKEN), Some(&[9; 16][..]));
        assert_eq!(
            params.get_var(ids::MAX_DATAGRAM_FRAME_SIZE).unwrap(),
            Some(VarInt::from_u32(1200))
        );
        assert_eq!(params.get(ids::DISABLE_ACTIVE_MIGRATION), Some(&[][..]));
        assert_eq!(params.get(ids::RESET_STREAM_AT), Some(&[][..]));
        assert_eq!(
            params.get_var(ids::ACTIVE_CONNECTION_ID_LIMIT).unwrap(),
            Some(VarInt::from_u32(7))
        );
        assert_eq!(
            params.get_var(ids::MIN_ACK_DELAY).unwrap(),
            Some(VarInt::from_u32(1_000))
        );
        params.validate_quic_basics().unwrap();
    }

    #[test]
    fn transport_parameters_can_leave_active_migration_enabled() {
        let config = TransportConfig {
            disable_active_migration: false,
            ..TransportConfig::default()
        };
        let initial_source = ConnectionId::from_slice(b"initial").unwrap();

        let params =
            TransportParameters::from_config(&config, &initial_source, None, None, None, None);

        assert_eq!(params.get(ids::DISABLE_ACTIVE_MIGRATION), None);
    }

    #[test]
    fn rejects_invalid_transport_parameter_basics() {
        let mut params = TransportParameters::default();
        params.set_var(ids::MAX_UDP_PAYLOAD_SIZE, VarInt::from_u32(1199));
        assert_eq!(
            params.validate_quic_basics(),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );

        let mut params = TransportParameters::default();
        params.set_var(ids::ACK_DELAY_EXPONENT, VarInt::from_u32(21));
        assert_eq!(
            params.validate_quic_basics(),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );

        let mut params = TransportParameters::default();
        params.set_var(ids::ACTIVE_CONNECTION_ID_LIMIT, VarInt::from_u32(1));
        assert_eq!(
            params.validate_quic_basics(),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );

        for id in [ids::INITIAL_MAX_STREAMS_BIDI, ids::INITIAL_MAX_STREAMS_UNI] {
            let mut params = TransportParameters::default();
            params.set_var(id, VarInt::new(MAX_STREAM_COUNT + 1).unwrap());
            assert_eq!(
                params.validate_quic_basics(),
                Err(CodecError::Transport(
                    TransportErrorCode::TransportParameterError
                ))
            );
        }

        let mut params = TransportParameters::default();
        params.set_var(ids::MAX_ACK_DELAY, VarInt::from_u32(16_384));
        assert_eq!(
            params.validate_quic_basics(),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );

        let mut params = TransportParameters::default();
        params.set_var(ids::MIN_ACK_DELAY, VarInt::from_u32(25_001));
        assert_eq!(
            params.validate_quic_basics(),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );

        let mut params = TransportParameters::default();
        params.set_var(ids::MAX_DATAGRAM_FRAME_SIZE, VarInt::ZERO);
        params.validate_quic_basics().unwrap();

        let mut params = TransportParameters::default();
        params.set_var(ids::MAX_UDP_PAYLOAD_SIZE, VarInt::from_u32(1200));
        params.set_var(ids::MAX_DATAGRAM_FRAME_SIZE, VarInt::from_u32(1201));
        params.validate_quic_basics().unwrap();

        let mut params = TransportParameters::default();
        params.set_bytes(ids::DISABLE_ACTIVE_MIGRATION, [1]);
        assert_eq!(
            params.validate_quic_basics(),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );

        let mut params = TransportParameters::default();
        params.set_bytes(ids::MAX_IDLE_TIMEOUT, [0x40, 0x00, 0x00]);
        assert_eq!(
            params.validate_quic_basics(),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );
    }

    #[test]
    fn rejects_non_empty_reset_stream_at_parameter() {
        let mut params = TransportParameters::default();
        params.set_bytes(ids::RESET_STREAM_AT, [1]);
        assert_eq!(
            params.validate_quic_basics(),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );
    }

    #[test]
    fn duplicate_and_malformed_transport_parameters_map_to_transport_parameter_error() {
        let mut encoded = Vec::new();
        VarInt::from_u32(ids::MAX_IDLE_TIMEOUT as u32).encode(&mut encoded);
        VarInt::from_u32(1).encode(&mut encoded);
        encoded.push(0);
        VarInt::from_u32(ids::MAX_IDLE_TIMEOUT as u32).encode(&mut encoded);
        VarInt::from_u32(1).encode(&mut encoded);
        encoded.push(0);
        let err = TransportParameters::decode(&encoded).unwrap_err();
        assert_eq!(
            err.transport_code(),
            TransportErrorCode::TransportParameterError
        );

        let mut malformed = TransportParameters::default();
        malformed.set_bytes(ids::INITIAL_MAX_DATA, [0x40]);
        let err = malformed.validate_quic_basics().unwrap_err();
        assert_eq!(
            err.transport_code(),
            TransportErrorCode::TransportParameterError
        );

        for id in [
            ids::MAX_UDP_PAYLOAD_SIZE,
            ids::ACK_DELAY_EXPONENT,
            ids::ACTIVE_CONNECTION_ID_LIMIT,
            ids::MAX_ACK_DELAY,
            ids::MAX_DATAGRAM_FRAME_SIZE,
            ids::MIN_ACK_DELAY,
        ] {
            let mut malformed = TransportParameters::default();
            malformed.set_bytes(id, [0x40]);
            let err = malformed.validate_quic_basics().unwrap_err();
            assert_eq!(
                err.transport_code(),
                TransportErrorCode::TransportParameterError
            );
        }
    }

    #[test]
    fn validates_server_role_transport_parameters() {
        let original = ConnectionId::from_slice(b"original").unwrap();
        let server_initial = ConnectionId::from_slice(b"server-initial").unwrap();
        let retry = ConnectionId::from_slice(b"retry").unwrap();
        let params = TransportParameters::from_config(
            &TransportConfig::default(),
            &server_initial,
            Some(&original),
            Some(&retry),
            None,
            None,
        );

        params
            .validate_server_parameters(&original, &server_initial, Some(&retry))
            .unwrap();
        let mut with_reset = params.clone();
        with_reset.set_bytes(ids::STATELESS_RESET_TOKEN, [7; 16]);
        with_reset
            .validate_server_parameters(&original, &server_initial, Some(&retry))
            .unwrap();
        let mut bad_reset = params.clone();
        bad_reset.set_bytes(ids::STATELESS_RESET_TOKEN, [7; 15]);
        assert_eq!(
            bad_reset.validate_server_parameters(&original, &server_initial, Some(&retry)),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );
        assert_eq!(
            params.validate_server_parameters(&original, &server_initial, None),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );

        let mut missing_original = params.clone();
        missing_original.remove(ids::ORIGINAL_DESTINATION_CONNECTION_ID);
        assert_eq!(
            missing_original.validate_server_parameters(&original, &server_initial, Some(&retry)),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );

        let wrong_initial = ConnectionId::from_slice(b"wrong").unwrap();
        assert_eq!(
            params.validate_server_parameters(&original, &wrong_initial, Some(&retry)),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );
    }

    #[test]
    fn validates_client_role_transport_parameters() {
        let client_initial = ConnectionId::from_slice(b"client-initial").unwrap();
        let params = TransportParameters::from_config(
            &TransportConfig::default(),
            &client_initial,
            None,
            None,
            None,
            None,
        );

        params.validate_client_parameters(&client_initial).unwrap();

        let mut forbidden_original = params.clone();
        forbidden_original.set_bytes(ids::ORIGINAL_DESTINATION_CONNECTION_ID, b"original");
        assert_eq!(
            forbidden_original.validate_client_parameters(&client_initial),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );

        let mut forbidden_reset = params.clone();
        forbidden_reset.set_bytes(ids::STATELESS_RESET_TOKEN, [9; 16]);
        assert_eq!(
            forbidden_reset.validate_client_parameters(&client_initial),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );

        let mut missing_initial = params.clone();
        missing_initial.remove(ids::INITIAL_SOURCE_CONNECTION_ID);
        assert_eq!(
            missing_initial.validate_client_parameters(&client_initial),
            Err(CodecError::Transport(
                TransportErrorCode::TransportParameterError
            ))
        );
    }

    #[test]
    fn validates_zero_rtt_transport_limits_against_cached_values() {
        let monotonic = [
            ids::ACTIVE_CONNECTION_ID_LIMIT,
            ids::INITIAL_MAX_DATA,
            ids::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            ids::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            ids::INITIAL_MAX_STREAM_DATA_UNI,
            ids::INITIAL_MAX_STREAMS_BIDI,
            ids::INITIAL_MAX_STREAMS_UNI,
            ids::MAX_DATAGRAM_FRAME_SIZE,
        ];

        for id in monotonic {
            let mut cached = TransportParameters::default();
            cached.set_var(id, VarInt::from_u32(10));

            let mut equal = TransportParameters::default();
            equal.set_var(id, VarInt::from_u32(10));
            equal.validate_zero_rtt_compatibility(&cached).unwrap();

            let mut increased = TransportParameters::default();
            increased.set_var(id, VarInt::from_u32(11));
            increased.validate_zero_rtt_compatibility(&cached).unwrap();

            let mut reduced = TransportParameters::default();
            reduced.set_var(id, VarInt::from_u32(9));
            assert_eq!(
                reduced.validate_zero_rtt_compatibility(&cached),
                Err(CodecError::Transport(TransportErrorCode::ProtocolViolation))
            );
        }
    }

    proptest! {
        #[test]
        fn var_parameter_roundtrips(
            id in 0u64..4096,
            value in 0u64..=crate::varint::MAX_VARINT,
        ) {
            let mut params = TransportParameters {
                values: BTreeMap::new(),
            };
            let value = VarInt::new(value).unwrap();
            params.set_var(id, value);
            let decoded = TransportParameters::decode(&params.encode()).unwrap();
            prop_assert_eq!(decoded.get_var(id).unwrap(), Some(value));
        }
    }
}
