// Invariant: decriptarea la client nu poate produce panica pentru nicio celula,
// si nu poate raporta un hop inexistent.
/*
Simuleaza un client Tor, fuzzer-ul genereaza pachete corupte sau modificate prin retea si verifica daca decriptarea
crapa sau daca raporteaza un nod invalid(hop >= 1 && hop <=3)

rustup toolchain install nightly
cargo install cargo-fuzz
cd crates/pqo-crypto

cargo +nightly fuzz run cgo_client
-> Am trimis peste 4,19 milioane de pachete -> cu o procesare de date de 113k executii pe secunda

Funcția decrypt_inbound a trecut cu succes prin mai mult de 4 milioane de încercări de spargere/date corupte fără să crape
 și fără să returneze hop-uri inexistente în afara intervalului 1..=3. Logica de decriptare este robustă la fuzzing.
*/
#![no_main]
use libfuzzer_sys::fuzz_target;
use pqo_crypto::cgo::{ClientCircuit, MSG_LEN};
use pqo_crypto::KeySeed;

fuzz_target!(|data: &[u8]| {
    if data.len() < MSG_LEN + 1 {
        return;
    }
    let mut c = ClientCircuit::new();
    for i in 0..3u8 {
        c.add_hop(&KeySeed::new([i + 1; 32]));
    }
    let ad = data[0];
    let mut cell = [0u8; MSG_LEN];
    cell.copy_from_slice(&data[1..1 + MSG_LEN]);
    if let Ok((hop, _body)) = c.decrypt_inbound(ad, &cell) {
        assert!(hop >= 1 && hop <= 3);
    }
});
