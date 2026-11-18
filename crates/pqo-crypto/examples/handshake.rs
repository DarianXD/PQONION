//! Demonstratie de handshake + tabelul de dimensiuni
//!
//! Ruleaza cu:
//!     cargo run --example handshake                # X25519 (nu e PQ)
//!     cargo run --example handshake --features pq  # X25519 + ML-KEM-768 real
//!
//! Cifrele afisate sunt calculate din constantele trait-ului `Kem`, deci sunt
//! automat corecte pentru orice schema pe care o conectezi.
//! 
//Scop: simuleze intregul ciclu de viata al handshake-ului pq-ntor-v1 si sa calculeze overhead-ul pe fir. Aratand daca pachetele post cuantice incap intr-o singura celula sau cer fragmentare.
//Handshake-ul se face per hop(relay) o singura data la initializarea circuitului.
//In exemplul de fata se face doar pt un hop, restul sunt identice, la handshake cele 2 parti deriva un seed initial(acel CGO_KEY_MATERIAL), dupa fiecare celula procesata, starea interna a CGO se actualizeaza automat printr-un mecanism num ratchet(KDF- functie de derivare rapida, pur simetrica -> forward secrecy)
//KEM -> Key Encapsulation Mechanism -> e o metoda prin care 2 calculatoare convin asupra unei chei secrete comune folosind criptografie asimetrica. Din acest secret comun vor face chei simetrice partile, si se vor updata constant simultan fara sa mai comunice. (K1 - timp x, K2 - timp y, ...) - (K1 - timp x, K2 - timp y,...) asta va permite forward secrecy.

use pqo_crypto::kem::Kem;
use pqo_crypto::{client_finish, client_init, ntor, server_respond, Hybrid, RelayKeys, Variant, X25519Kem};
use rand_core::OsRng;

/// Numarul de octeti de material de cheie ceruti de CGO per hop:
/// 2 seed-uri + 4 chei (bloc + CTR, fwd + bwd) + 2 chei de hash polinomial.
const CGO_KEY_MATERIAL: usize = 288;

/// Payload-ul util al unei celule, dupa antet.
const CELL_PAYLOAD: usize = 509;

fn ruleaza<K: Kem>(eticheta: &str, variant: Variant) {
    let mut rng = OsRng;
    let keys = RelayKeys::<K>::generate([0xAB; ntor::ID_LEN], variant, &mut rng); //genereaza o identitate determinista[0xAB], si perechile de chei corespunzatoare variantei (Transational sau FullPQ).
    let public = keys.public();

    //ciclu complet de handshake(3 pasi)
    let (state, msg1) = client_init::<K>(&public, variant, &mut rng).expect("client_init"); //genereaza material efemer si trimite msg1(CREATE2). Genereaza o pereche de chei efemere si trimite cheia publica de incapsulare catre releu.
    let (msg2, srv) = server_respond::<K>(&keys, &msg1, &mut rng).expect("server_respond"); //releul proceseaza msg1, incapsuleaza cheia partajata si returneaza msg2(CREATED2) alaturi de starea sa srv. Releul foloseste
    let cli = client_finish::<K>(state, &msg2).expect("client_finish"); // clientul decapsuleaza datele din msg2 si ajunge la starea finala cli.

    //se asigura ca ambele parti au ajuns la aceeasi cheie simetrica finala derivata din transcript.!!!
    assert_eq!(
        cli.key_seed.expand_vec(CGO_KEY_MATERIAL),
        srv.key_seed.expand_vec(CGO_KEY_MATERIAL),
        "material de cheie divergent"
    );

    let c2s = msg1.len();
    let s2c = msg2.len();
    let total = c2s + s2c;
    let celule_c2s = c2s.div_ceil(CELL_PAYLOAD);
    let celule_s2c = s2c.div_ceil(CELL_PAYLOAD);

    println!(
        "{:<46} {:>6} {:>6} {:>7} {:>6} {:>6}",
        format!("{eticheta} / {variant:?}"),
        c2s,
        s2c,
        total,
        celule_c2s,
        celule_s2c
    );
}

fn main() {
    println!("pq-ntor-v1 — dimensiuni de handshake (octeti, per hop)\n");
    println!(
        "{:<46} {:>6} {:>6} {:>7} {:>6} {:>6}",
        "schema / varianta", "C->R", "R->C", "total", "cel.C", "cel.R"
    );
    println!("{}", "-".repeat(80));

    // Referinta: ntor clasic din Tor, pentru comparatie.
    println!(
        "{:<46} {:>6} {:>6} {:>7} {:>6} {:>6}",
        "ntor clasic (referinta Tor)", 84, 64, 148, 1, 1
    );

    ruleaza::<X25519Kem>("X25519 (NU e post-cuantic)", Variant::Transitional);
    ruleaza::<X25519Kem>("X25519 (NU e post-cuantic)", Variant::FullPq);
    ruleaza::<Hybrid<X25519Kem, X25519Kem>>("Hybrid<X25519,X25519> (test)", Variant::Transitional);

    //compilare cu suport post cuantic, ruleaza schema hibrida Hybrid<X25519Kem, Mlkem768>.
    #[cfg(feature = "pq")] 
    {
        use pqo_crypto::MlKem768;
        ruleaza::<MlKem768>("ML-KEM-768", Variant::Transitional);
        ruleaza::<MlKem768>("ML-KEM-768", Variant::FullPq);
        ruleaza::<Hybrid<X25519Kem, MlKem768>>("X-Wing-like (X25519+MLKEM768)", Variant::Transitional);
        ruleaza::<Hybrid<X25519Kem, MlKem768>>("X-Wing-like (X25519+MLKEM768)", Variant::FullPq);
    }

    #[cfg(not(feature = "pq"))]
    {
        println!("\n[ML-KEM-768 nu e compilat. Ruleaza cu --features pq (necesita Rust >= 1.81).]");
        println!("Proiectie pentru Hybrid<X25519, ML-KEM-768>, calculata din FIPS 203:");
        let ek = 32 + 1184;
        let ct = 32 + 1088;
        for (v, extra) in [("Transitional", 0usize), ("FullPq", ct)] {
            let c2s = 32 + 32 + 32 + ek + extra;
            let s2c = 32 + ct + 32;
            println!(
                "{:<46} {:>6} {:>6} {:>7} {:>6} {:>6}",
                format!("  (proiectie) X25519+MLKEM768 / {v}"),
                c2s,
                s2c,
                c2s + s2c,
                c2s.div_ceil(CELL_PAYLOAD),
                s2c.div_ceil(CELL_PAYLOAD)
            );
        }
    }

    println!("\nCircuit de 3 hop-uri = 3x totalul de mai sus.");
    println!("Coloanele 'cel.' arata de cate celule de {CELL_PAYLOAD}B e nevoie: orice valoare > 1");
    println!("inseamna ca handshake-ul NU incape intr-o celula si ai nevoie de fragmentare.");
}



/*
fn construieste_circuit_3_hopuri<K: Kem>(variant: Variant) {
    let mut rng = OsRng;
    let mut circuit_client = ClientCircuit::new();

    // 1. Simulam 3 servere fizice diferite din retea (Guard, Middle, Exit)
    let relay_guard  = RelayKeys::<K>::generate([1u8; ntor::ID_LEN], variant, &mut rng);
    let relay_middle = RelayKeys::<K>::generate([2u8; ntor::ID_LEN], variant, &mut rng);
    let relay_exit   = RelayKeys::<K>::generate([3u8; ntor::ID_LEN], variant, &mut rng);

    let relee = [&relay_guard, &relay_middle, &relay_exit];

    // 2. Clientul face handshake-ul pe rand cu fiecare releu
    for (i, relay) in relee.iter().enumerate() {
        // Pas A: Clientul pregateste mesajul pentru releul curent (Hop i + 1)
        let (state, msg1) = client_init::<K>(&relay.public(), variant, &mut rng).expect("init");

        // [In realitate, pentru Hop 2 si Hop 3, msg1 si msg2 calatoresc
        // deja criptate prin hop-urile anterioare prin celule EXTEND2]

        // Pas B: Releul proceseaza cererea si raspunde
        let (msg2, srv_state) = server_respond::<K>(relay, &msg1, &mut rng).expect("respond");

        // Pas C: Clientul finalizeaza handshake-ul si extrage cheia
        let cli_state = client_finish::<K>(state, &msg2).expect("finish");

        // Pas D: Clientul inregistreaza noul strat de chei in circuitul sau
        circuit_client.add_hop(&cli_state.key_seed);

        println!("Hop {} negociat cu succes!", i + 1);
    }

    // In acest moment circuit_client contine cele 3 straturi si este gata sa cripteze celule de date.
}


*/