#![cfg_attr(feature = "fuzzing", no_main)]

#[cfg(feature = "fuzzing")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "fuzzing")]
fuzz_target!(|data: &[u8]| {
    let _ = quion_proto::frame::Frame::decode(data);
});

#[cfg(not(feature = "fuzzing"))]
fn main() {}
