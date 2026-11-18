//! Ciclul de viata al unui serviciu ascuns, de la samanta la adresa publicabila.
//!
//!     cargo run -p pqo-hs --example serviciu

use pqo_crypto::sig::{Ed25519, Sig};
use pqo_hs::desc::{Descriptor, IntroPoint};
use pqo_hs::hsdir::{responsible_nodes, N_REPLICAS, N_STORE};
use pqo_hs::{blinded_id, MasterSeed, OnionAddress, TimePeriod, PERIOD_LENGTH};
use rand_core::OsRng;

type S = Ed25519;

fn main() {
    let mut rng = OsRng;
    let seed = MasterSeed::random(&mut rng);
    let (_sk, pk) = seed.identity_key::<S>();
    let addr = OnionAddress::from_identity::<S>(&pk);

    println!("Serviciu ascuns\n");
    println!("Adresa:            {addr}");
    println!("  lungime:         {} caractere (Tor v3: 62)", addr.to_string().len());
    println!("  identitate:      {} ({} octeti cheie publica)", S::NAME, S::PK_LEN);
    println!("  adresa = SHAKE256(cheia), nu cheia insasi");

    let now = 1_700_000_000u64;
    let p = TimePeriod::at(now);
    println!("\nPerioada curenta:  {} (lungime {PERIOD_LENGTH}s)", p.0);
    println!("Se publica pentru: {:?}", p.published().map(|x| x.0));

    for q in p.published() {
        let b = blinded_id(addr.id(), q);
        println!("  perioada {} -> index {}", q.0, hex8(&b));
    }
    println!("  indecsii nu se pot lega intre ei fara adresa");

    let ips: Vec<IntroPoint> = (0..3)
        .map(|i| IntroPoint {
            relay_id: [i; 32],
            onion_x25519: [i + 1; 32],
            onion_kem: Some(vec![i; 1184]),
            svc_x25519: [0u8; 32],
            auth_key: vec![i + 2; S::PK_LEN],
        })
        .collect();

    let doc = Descriptor::build::<S>(&seed, &addr, p, 1, ips).expect("descriptor");
    let d = Descriptor::parse_and_verify::<S>(&doc).expect("verificare");
    let inner = d.open_inner::<S>(&addr).expect("decriptare");

    println!("\nDescriptor:");
    println!("  total:           {} octeti", doc.len());
    println!("  strat criptat:   {} octeti", d.encrypted.len());
    println!("  puncte introd.:  {}", inner.intro_points.len());
    println!("  HSDir vede doar stratul exterior si nu il poate decripta");

    let noduri: Vec<[u8; 32]> = (0..60u64)
        .map(|i| {
            let mut fp = [0u8; 32];
            fp[..8].copy_from_slice(&i.to_le_bytes());
            fp
        })
        .collect();
    let srv = [0x5A; 32];
    let r = responsible_nodes(&noduri, &blinded_id(addr.id(), p), p, &srv);
    println!(
        "\nNoduri responsabile: {} din 60 ({} replici x {} noduri)",
        r.len(),
        N_REPLICAS,
        N_STORE
    );

    println!("\nProiectie cu identitate ML-DSA-44:");
    println!("  cheie publica:   1312 octeti (nu incape in adresa)");
    println!("  adresa ramane:   62 caractere, pentru ca e hash");
    println!("  descriptor:      ~{} octeti", doc.len() + 2 * (2420 - 64) + (1312 - 32));
}

fn hex8(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}
