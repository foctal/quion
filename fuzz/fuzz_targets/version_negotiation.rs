#![cfg_attr(feature = "fuzzing", no_main)]

#[cfg(feature = "fuzzing")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "fuzzing")]
fuzz_target!(|data: &[u8]| {
    let Ok((header, _)) = quion_proto::packet::Header::decode(data, 8) else {
        return;
    };
    let original_dst_cid = quion_proto::cid::ConnectionId::from_slice(b"original-dcid")
        .expect("static connection ID must fit");
    let original_src_cid = quion_proto::cid::ConnectionId::from_slice(b"original-scid")
        .expect("static connection ID must fit");
    let _ = quion_proto::endpoint::Endpoint::validate_version_negotiation(
        &header,
        &original_dst_cid,
        &original_src_cid,
        quion_proto::packet::QUIC_VERSION_1,
        &[
            quion_proto::packet::QUIC_VERSION_1,
            quion_proto::packet::QUIC_VERSION_2,
        ],
    );
});

#[cfg(not(feature = "fuzzing"))]
fn main() {}
