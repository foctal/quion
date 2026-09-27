#![cfg_attr(feature = "fuzzing", no_main)]

#[cfg(feature = "fuzzing")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "fuzzing")]
fuzz_target!(|data: &[u8]| {
    let _ = quion_proto::packet::Header::decode(data, 8);
});

#[cfg(not(feature = "fuzzing"))]
fn main() {}
