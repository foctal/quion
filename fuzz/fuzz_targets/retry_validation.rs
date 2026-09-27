#![cfg_attr(feature = "fuzzing", no_main)]

#[cfg(feature = "fuzzing")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "fuzzing")]
fuzz_target!(|data: &[u8]| {
    let manager = quion_proto::token::RetryTokenManager::new(
        quion_proto::token::RetryTokenKey::new(1, [0x5a; 32]),
        std::time::Duration::from_secs(30),
    );
    let remote = "127.0.0.1:4433"
        .parse()
        .expect("static socket address must parse");
    let _ = manager.validate(data, remote, 1_000_000);
});

#[cfg(not(feature = "fuzzing"))]
fn main() {}
