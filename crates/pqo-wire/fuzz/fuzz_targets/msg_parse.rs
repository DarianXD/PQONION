// Invariant: parserele de mesaje sunt totale.
#![no_main]
use libfuzzer_sys::fuzz_target;
use pqo_wire::{Create2, Created2, Extend2};

fuzz_target!(|data: &[u8]| {
    let _ = Create2::parse(data);
    let _ = Created2::parse(data);
    let _ = Extend2::parse(data);
});
