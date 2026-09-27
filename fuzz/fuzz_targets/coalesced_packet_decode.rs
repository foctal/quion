#![cfg_attr(feature = "fuzzing", no_main)]

#[cfg(feature = "fuzzing")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "fuzzing")]
fuzz_target!(|data: &[u8]| {
    let mut remaining = data;
    for _ in 0..64 {
        let Ok((header, header_len)) = quion_proto::packet::Header::decode(remaining, 8) else {
            break;
        };
        let packet_len = match header {
            quion_proto::packet::Header::Long(header) => {
                let Some(payload_len) = header.length else {
                    break;
                };
                let Ok(payload_len) = usize::try_from(payload_len.into_inner()) else {
                    break;
                };
                let Some(packet_len) = header_len.checked_add(payload_len) else {
                    break;
                };
                packet_len
            }
            quion_proto::packet::Header::Short(_)
            | quion_proto::packet::Header::VersionNegotiation { .. } => {
                break;
            }
        };
        if packet_len == 0 || packet_len > remaining.len() {
            break;
        }
        remaining = &remaining[packet_len..];
        if remaining.is_empty() {
            break;
        }
    }
});

#[cfg(not(feature = "fuzzing"))]
fn main() {}
