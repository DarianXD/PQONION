// Invariant: reasamblatorul nu poate produce panica si nu poate depasi limitele
// de memorie, oricare ar fi secventa de fragmente primite.
#![no_main]
use libfuzzer_sys::fuzz_target;
use pqo_wire::{Reassembler, CELL_PAYLOAD_LEN, MAX_MESSAGE_LEN};

fuzz_target!(|data: &[u8]| {
    let mut r = Reassembler::new();
    for chunk in data.chunks(CELL_PAYLOAD_LEN) {
        match r.push(chunk) {
            Ok(Some(msg)) => assert!(msg.body.len() <= MAX_MESSAGE_LEN),
            Ok(None) => {}
            Err(_) => r.reset(),
        }
    }
});
