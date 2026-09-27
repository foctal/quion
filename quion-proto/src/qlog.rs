use crate::{crypto::EncryptionLevel, frame::Frame, varint::VarInt};

#[cfg(feature = "qlog")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "qlog", derive(Serialize, Deserialize))]
pub enum QlogEvent {
    ConnectionStateUpdated {
        state: &'static str,
    },
    EndpointStateUpdated {
        state: &'static str,
        packet_type: &'static str,
    },
    TransportParametersSet {
        owner: &'static str,
        initial_max_data: Option<u64>,
        initial_max_stream_data_bidi_local: Option<u64>,
        initial_max_stream_data_bidi_remote: Option<u64>,
        initial_max_stream_data_uni: Option<u64>,
        initial_max_streams_bidi: Option<u64>,
        initial_max_streams_uni: Option<u64>,
        max_idle_timeout_ms: Option<u64>,
        max_datagram_frame_size: Option<u64>,
    },
    PacketReceived {
        level: &'static str,
        bytes: u64,
    },
    PacketSent {
        level: &'static str,
        packet_number: u64,
        bytes: u64,
        ack_eliciting: bool,
        frame_type: &'static str,
    },
    PacketLost {
        level: &'static str,
        packet_number: u64,
    },
    PacketProtectionUpdated {
        operation: &'static str,
        level: &'static str,
        key_phase: Option<bool>,
        bytes: usize,
    },
    AckProcessed {
        level: &'static str,
        largest_acked: u64,
        ack_range_count: usize,
    },
    StreamDataQueued {
        stream_id: u64,
        offset: u64,
        len: usize,
        fin: bool,
    },
    StreamStateUpdated {
        stream_id: u64,
        state: &'static str,
        error_code: Option<u64>,
        final_size: Option<u64>,
    },
    DatagramStateUpdated {
        state: &'static str,
        len: usize,
    },
    FlowControlUpdated {
        scope: &'static str,
        stream_id: Option<u64>,
        maximum: u64,
    },
    RecoveryStateUpdated {
        state: &'static str,
        level: &'static str,
        packet_count: usize,
    },
    RecoveryMetricsUpdated {
        latest_rtt_us: u64,
        min_rtt_us: u64,
        smoothed_rtt_us: u64,
        rtt_variance_us: u64,
    },
    PathStateUpdated {
        state: &'static str,
    },
}

impl QlogEvent {
    #[cfg(feature = "qlog")]
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

pub fn encryption_level_name(level: EncryptionLevel) -> &'static str {
    match level {
        EncryptionLevel::Initial => "initial",
        EncryptionLevel::ZeroRtt => "0rtt",
        EncryptionLevel::Handshake => "handshake",
        EncryptionLevel::OneRtt => "1rtt",
    }
}

pub fn frame_type_name(frame: &Frame) -> &'static str {
    match frame {
        Frame::Padding => "padding",
        Frame::Ping => "ping",
        Frame::Ack { .. } => "ack",
        Frame::ResetStream { .. } => "reset_stream",
        Frame::ResetStreamAt { .. } => "reset_stream_at",
        Frame::StopSending { .. } => "stop_sending",
        Frame::Crypto { .. } => "crypto",
        Frame::NewToken(_) => "new_token",
        Frame::Stream { .. } => "stream",
        Frame::MaxData(_) => "max_data",
        Frame::MaxStreamData { .. } => "max_stream_data",
        Frame::MaxStreamsBidi(_) => "max_streams_bidi",
        Frame::MaxStreamsUni(_) => "max_streams_uni",
        Frame::DataBlocked(_) => "data_blocked",
        Frame::StreamDataBlocked { .. } => "stream_data_blocked",
        Frame::StreamsBlockedBidi(_) => "streams_blocked_bidi",
        Frame::StreamsBlockedUni(_) => "streams_blocked_uni",
        Frame::NewConnectionId { .. } => "new_connection_id",
        Frame::RetireConnectionId(_) => "retire_connection_id",
        Frame::PathChallenge(_) => "path_challenge",
        Frame::PathResponse(_) => "path_response",
        Frame::ConnectionClose { .. } => "connection_close",
        Frame::ApplicationClose { .. } => "application_close",
        Frame::HandshakeDone => "handshake_done",
        Frame::AckFrequency { .. } => "ack_frequency",
        Frame::ImmediateAck => "immediate_ack",
        Frame::Datagram { .. } => "datagram",
    }
}

pub fn varint_inner(value: VarInt) -> u64 {
    value.into_inner()
}
