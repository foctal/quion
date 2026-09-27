#![cfg_attr(feature = "fuzzing", no_main)]

#[cfg(feature = "fuzzing")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "fuzzing")]
fuzz_target!(|data: &[u8]| {
    let mut buffer = quion_proto::crypto::stream::CryptoRecvBuffer::new(
        quion_proto::crypto::EncryptionLevel::Initial,
    );
    for chunk in data.chunks(9) {
        if chunk.len() < 8 {
            break;
        }
        let offset = u64::from_be_bytes(chunk[..8].try_into().expect("chunk has eight bytes"));
        let _ = buffer.insert(offset, &chunk[8..]);
        let _ = buffer.read_contiguous(64);
    }
});

#[cfg(not(feature = "fuzzing"))]
fn main() {}
