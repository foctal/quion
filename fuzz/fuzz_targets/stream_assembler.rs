#![cfg_attr(feature = "fuzzing", no_main)]

#[cfg(feature = "fuzzing")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "fuzzing")]
fuzz_target!(|data: &[u8]| {
    let mut assembler = quion_proto::streams::RecvAssembler::default();
    let mut read_offset = 0;
    for chunk in data.chunks(10) {
        if chunk.len() < 9 {
            break;
        }
        let offset = u64::from_be_bytes(chunk[..8].try_into().expect("chunk has eight bytes"));
        let _ = assembler.insert(offset, chunk[9..].to_vec(), chunk[8] & 1 != 0);
        let _ = assembler.read_ordered(&mut read_offset, 64);
        let _ = assembler.read_unordered(64);
    }
});

#[cfg(not(feature = "fuzzing"))]
fn main() {}
