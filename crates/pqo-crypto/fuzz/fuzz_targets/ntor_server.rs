// Tinta de fuzzing pentru parserul de CREATE2 al releului.
// Invariant: pentru ORICE input, `server_respond` intoarce Result, nu panica.
//
//   cargo install cargo-fuzz && cargo fuzz run ntor_server -- -max_total_time=86400
#![no_main]
use libfuzzer_sys::fuzz_target;
use pqo_crypto::{server_respond, RelayKeys, Variant, X25519Kem};
use rand_core::OsRng;

fuzz_target!(|data: &[u8]| {
    let mut rng = OsRng;
    let keys = RelayKeys::<X25519Kem>::generate([0u8; 32], Variant::Transitional, &mut rng);
    let _ = server_respond::<X25519Kem>(&keys, data, &mut rng);
});
