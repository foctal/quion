use quion_proto::{
    VarInt,
    cid::ConnectionId,
    connection::{Connection, RecvMeta},
    crypto::EncryptionLevel,
    endpoint::Endpoint,
    error::CodecError,
    frame::Frame,
    packet::{Header, decode_retry_packet},
    streams::StreamInitiator,
    token::{RetryTokenKey, RetryTokenManager},
    transport_error::TransportErrorCode,
    transport_parameters::TransportParameters,
};
use web_time::Duration;

#[test]
fn malformed_parser_and_receive_matrix_never_panics() {
    let mut state = 0x6a09_e667_f3bc_c909u64;
    let now = web_time::Instant::now();
    let mut connection = Connection::new();
    let original_dst_cid = ConnectionId::from_slice(&[0x11; 8]).unwrap();
    let original_src_cid = ConnectionId::from_slice(&[0x22; 8]).unwrap();
    let remote = "127.0.0.1:4433".parse().unwrap();
    let token_manager =
        RetryTokenManager::new(RetryTokenKey::new(7, [0x33; 32]), Duration::from_secs(30));

    for len in 0..=2048 {
        let mut input = vec![0u8; len];
        for byte in &mut input {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }

        if let Ok((header, consumed)) = Header::decode(&input, 8) {
            assert!(consumed <= input.len());
            let _ = Endpoint::validate_version_negotiation(
                &header,
                &original_dst_cid,
                &original_src_cid,
                1,
                &[1],
            );
        }
        let _ = ConnectionId::decode_fixed(&input);
        if let Ok((_, consumed)) = VarInt::decode(&input) {
            assert!(consumed <= input.len());
        }
        if let Ok((_, consumed)) = Frame::decode(&input) {
            assert!(consumed <= input.len());
        }
        let _ = decode_retry_packet(&input, &original_dst_cid);
        let _ = token_manager.validate(&input, remote, 1_000);
        let _ = TransportParameters::decode(&input);
        let _ = connection.recv(&input, RecvMeta { ecn: None }, now);
    }
}

#[test]
fn every_truncated_valid_encoding_has_bounded_consumption() {
    let frame = Frame::Stream {
        stream_id: quion_proto::VarInt::from_u32(1),
        offset: quion_proto::VarInt::from_u32(42),
        fin: true,
        data: vec![0x5a; 512].into(),
    }
    .encode();

    for end in 0..=frame.len() {
        if let Ok((_, consumed)) = Frame::decode(&frame[..end]) {
            assert!(consumed <= end);
        }
    }
}

#[test]
fn authenticated_parser_errors_map_to_required_transport_errors() {
    assert_eq!(
        Frame::decode(&[0x40, 0x01]),
        Err(CodecError::Transport(TransportErrorCode::ProtocolViolation))
    );
    assert_eq!(
        Frame::decode(&[0x07, 0x00]),
        Err(CodecError::Transport(
            TransportErrorCode::FrameEncodingError
        ))
    );

    let mut server = Connection::new();
    server.configure_inbound_stream_limits(StreamInitiator::Server, 0, 0);
    assert_eq!(
        server
            .handle_frame(
                EncryptionLevel::OneRtt,
                Frame::NewToken(vec![1]),
                web_time::Instant::now(),
            )
            .unwrap_err(),
        CodecError::Transport(TransportErrorCode::ProtocolViolation)
    );

    let error = TransportParameters::decode(&[0x01, 0x40]).unwrap_err();
    assert_eq!(
        error.transport_code(),
        TransportErrorCode::TransportParameterError
    );
}
