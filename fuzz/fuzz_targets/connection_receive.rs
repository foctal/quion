#![cfg_attr(feature = "fuzzing", no_main)]

#[cfg(feature = "fuzzing")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "fuzzing")]
fuzz_target!(|data: &[u8]| {
    let mut connection = quion_proto::connection::Connection::new();
    let _ = connection.recv(
        data,
        quion_proto::connection::RecvMeta { ecn: None },
        web_time::Instant::now(),
    );
});

#[cfg(not(feature = "fuzzing"))]
fn main() {}
