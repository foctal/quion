#![cfg_attr(feature = "fuzzing", no_main)]

#[cfg(feature = "fuzzing")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "fuzzing")]
fuzz_target!(|data: &[u8]| {
    let dcid = quion_proto::cid::ConnectionId::from_slice(b"fuzz-dcid")
        .expect("static connection ID must fit");
    let Ok(keys) = quion_proto::crypto::initial::InitialKeys::derive(
        quion_proto::packet::QUIC_VERSION_1,
        &dcid,
    ) else {
        return;
    };
    let Ok(protector) = quion_proto::crypto::initial::InitialPacketProtector::new(
        &keys,
        quion_proto::crypto::Side::Server,
    ) else {
        return;
    };
    let mut packet = data.to_vec();
    let _ = quion_proto::crypto::packet::CryptoPacketOpener::open_initial(
        &protector,
        &mut packet,
        None,
    );
});

#[cfg(not(feature = "fuzzing"))]
fn main() {}
