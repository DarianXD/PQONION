// Invariant: Cell::decode nu poate produce panica pentru niciun flux de octeti.
// Acopera si cazul in care un peer trimite antete cu lungimi absurde.
#![no_main]
use libfuzzer_sys::fuzz_target;
use pqo_wire::Cell;

fuzz_target!(|data: &[u8]| {
    // Decodeaza in bucla, ca un canal real care primeste celule lipite.
    let mut off = 0usize;
    while off < data.len() {
        match Cell::decode(&data[off..]) {
            Ok(Some((_cell, n))) if n > 0 => off += n,
            _ => break,
        }
    }
});
