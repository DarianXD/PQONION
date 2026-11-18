//! Costul real, in celule si octeti pe fir, al construirii unui circuit.
//!
//!     cargo run -p pqo-wire --example cost_circuit
//!
//! Cifrele sunt calculate din formatele de mesaj definite in acest crate si din
//! dimensiunile FIPS 203, nu scrise de mana. Daca schimbi formatul, tabelul se
//! actualizeaza singur — exact ce vrei intr-un capitol de evaluare.

use pqo_wire::{cell, relay, Create2, Extend2, HandshakeType, LinkSpec};

/// Dimensiunile handshake-ului, per schema de KEM.
struct Schema {
    nume: &'static str,
    /// Lungimea cheii de incapsulare serializate.
    ek: usize,
    /// Lungimea ciphertext-ului serializat.
    ct: usize,
}

/// Mesajul client -> releu, conform `pqo_crypto::client_init`:
/// `ID(32) | B(32) | X(32) | ek [| static_ct]`
fn hs_client(s: &Schema, fullpq: bool) -> usize {
    32 + 32 + 32 + s.ek + if fullpq { s.ct } else { 0 }
}

/// Mesajul releu -> client: `Y(32) | ct | auth(32)`
fn hs_server(s: &Schema) -> usize {
    32 + s.ct + 32
}

fn celule(octeti: usize) -> usize {
    if octeti == 0 {
        1
    } else {
        octeti.div_ceil(relay::RELAY_DATA_LEN)
    }
}

fn main() {
    let scheme = [
        Schema {
            nume: "X25519 (NU e PQ)",
            ek: 32,
            ct: 32,
        },
        Schema {
            nume: "ML-KEM-768",
            ek: 1184,
            ct: 1088,
        },
        Schema {
            nume: "X25519+ML-KEM-768",
            ek: 32 + 1184,
            ct: 32 + 1088,
        },
    ];

    // Overhead-ul de incadrare, masurat pe mesaje reale, nu presupus.
    let ext_overhead = Extend2 {
        specs: vec![
            LinkSpec::Ipv4 {
                addr: [0; 4],
                port: 0,
            },
            LinkSpec::RelayId([0; 32]),
        ],
        htype: HandshakeType::PqNtorTransitional,
        data: vec![],
    }
    .encode()
    .len();
    let create_overhead = Create2 {
        htype: HandshakeType::PqNtorTransitional,
        data: vec![],
    }
    .encode()
    .len();

    println!("Cost de constructie a unui circuit de 3 hop-uri\n");
    println!(
        "Overhead de incadrare: EXTEND2 = {ext_overhead} octeti, CREATE2 = {create_overhead} octeti"
    );
    println!(
        "Celula fixa = {}B pe fir -> {}B payload -> {}B corp dupa tag-ul CGO -> {}B utili",
        cell::CELL_LEN,
        cell::CELL_PAYLOAD_LEN,
        relay::RELAY_BODY_LEN,
        relay::RELAY_DATA_LEN
    );
    println!();

    println!(
        "{:<22} {:<14} {:>7} {:>7} {:>9} {:>8} {:>11}",
        "schema", "varianta", "EXT2", "EXTD2", "cel. E/R", "total", "octeti fir"
    );
    println!("{}", "-".repeat(86));

    for s in &scheme {
        for (eticheta, fullpq) in [("Transitional", false), ("FullPq", true)] {
            let ext2 = ext_overhead + hs_client(s, fullpq);
            let extd2 = 2 + hs_server(s);
            let c_out = celule(ext2);
            let c_in = celule(extd2);

            // Hop 1 merge in celule variabile CREATE2/CREATED2 (nu se fragmenteaza).
            let hop1_fir = (cell::CELL_HEADER_LEN + 2 + create_overhead + hs_client(s, fullpq))
                + (cell::CELL_HEADER_LEN + 2 + 2 + hs_server(s));
            // Hop 2 si 3 merg in celule RELAY fixe.
            let hop23_fir = 2 * (c_out + c_in) * cell::CELL_LEN;

            let total_cel = 2 * (c_out + c_in);

            println!(
                "{:<22} {:<14} {:>7} {:>7} {:>9} {:>8} {:>11}",
                s.nume,
                eticheta,
                ext2,
                extd2,
                format!("{c_out}/{c_in}"),
                total_cel,
                hop1_fir + hop23_fir
            );
        }
    }

    // Referinta Tor, pentru comparatie.
    let ntor_ext2 = ext_overhead + 84;
    let ntor_extd2 = 2 + 64;
    let ntor_cel = 2 * (celule(ntor_ext2) + celule(ntor_extd2));
    println!("{}", "-".repeat(86));
    println!(
        "{:<22} {:<14} {:>7} {:>7} {:>9} {:>8} {:>11}",
        "ntor clasic (Tor)",
        "—",
        ntor_ext2,
        ntor_extd2,
        format!("{}/{}", celule(ntor_ext2), celule(ntor_extd2)),
        ntor_cel,
        ntor_cel * cell::CELL_LEN + 2 * (cell::CELL_LEN)
    );

    println!("\nNota: la noi hop-ul 1 foloseste celule variabile, la Tor celule fixe de 514B.");
    println!("De aceea randul X25519 iese sub Tor: cand handshake-ul e mic, celula variabila");
    println!("economiseste octeti. Castigul dispare complet la dimensiuni post-cuantice.");
    println!("\nColoana 'cel. E/R' = celule pentru EXTEND2 / EXTENDED2, per hop extins.");
    println!("Coloana 'total'    = celule RELAY pentru hop-urile 2 si 3.");
    println!("Coloana 'octeti fir' include si celulele variabile ale hop-ului 1.");
}
