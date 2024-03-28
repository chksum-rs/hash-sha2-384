#![no_main]

use chksum_hash_sha2_384 as sha2_384;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sha2_384::hash(data);
});
