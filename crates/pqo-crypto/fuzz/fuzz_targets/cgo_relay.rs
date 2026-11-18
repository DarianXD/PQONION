// Invariant: procesarea la releu nu poate produce panica.

/*
Simuleaza un nod intermediar, testeaza daca procesarea unui pachet arbitrar din exterior poate bloca nodul.
Exec va fi preluata de motorul intern al libFuzzer.
se genereaza octeti complet aleatoriu, data., 
Testul nu verifica succesul decriptarii/procesarii, functia trebuie sa gestioneze orice octet malformat fara sa arunce vreun panic!

Scopul acestui test e pt a garanta ca un nod intermediar(relay) NU poate fi scos din functiune de catre un atacator care trimite date malitioase sau deformate prin retea.
Protectie impotriva (DOS), testam functia process_outbound.(mesaje trimise de tine client pe internet) - inbound sunt testate in cgo_client.rs prin decrypt inbound.
Releul are nevoie de protecție la fuzzing în primul rând pe suprafața unde primește date de la clienți necunoscuți și le interpretează structural (process_outbound).
*/

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqo_crypto::cgo::{RelayCircuit, MSG_LEN};
use pqo_crypto::KeySeed;

fuzz_target!(|data: &[u8]| {
    if data.len() < MSG_LEN + 1 {
        return;
    }
    let mut r = RelayCircuit::new(&KeySeed::new([9u8; 32]));
    let mut cell = [0u8; MSG_LEN];
    cell.copy_from_slice(&data[1..1 + MSG_LEN]); //copiaza exact MSG_LEN, din octetii generati aleatori, pt a simula o celula venita in retea
    let _ = r.process_outbound(data[0], &cell); //trimite celula generata catre logica nodului de releu.data[0] - tip de comanda random, &corpul celulei de procesat
});
