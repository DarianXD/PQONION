//! Simuleaza un ciclu orar de consens intre 5 autoritati.
//!
//!     cargo run -p pqo-dirauth --example consens

use pqo_crypto::sig::{Ed25519, Sig};
use pqo_dirauth::compute_consensus;
use pqo_dirproto::netdoc::{Consensus, Flags, RelayStatus, Validity, Vote};
use rand_core::OsRng;

type S = Ed25519;
const N_AUT: usize = 5;
const N_RELEE: usize = 12;

fn main() {
    let mut rng = OsRng;
    let chei: Vec<_> = (0..N_AUT).map(|_| S::keygen(&mut rng)).collect();
    let publice: Vec<Vec<u8>> = chei.iter().map(|(_, p)| p.clone()).collect();

    // Fiecare autoritate vede reteaua putin diferit: banda masurata difera, si
    // doar doua dintre ele vad ultimul releu (tocmai a pornit), sub pragul de 3.
    let voturi: Vec<Vote> = (0..N_AUT)
        .map(|a| {
            let mut v = Vote {
                authority: publice[a].clone(),
                validity: Validity {
                    valid_after: 1_700_000_000,
                    fresh_until: 1_700_003_600,
                    valid_until: 1_700_010_800,
                },
                params: vec![("circwindow".into(), 1000)],
                relays: (0..N_RELEE)
                    .filter(|i| !(*i == N_RELEE - 1 && a >= 2))
                    .map(|i| RelayStatus {
                        fingerprint: [i as u8; 32],
                        address: format!("10.0.{}.{}", i / 256, i % 256),
                        or_port: 9001,
                        bandwidth: 1000 + (i as u64 * 100) + (a as u64 * 7),
                        flags: Flags::from_names(if i % 3 == 0 {
                            ["Guard", "Fast", "Valid"].iter().copied()
                        } else {
                            ["Exit", "Fast", "Valid"].iter().copied()
                        })
                        .unwrap(),
                        pq_full: i % 2 == 0,
                    })
                    .collect(),
            };
            v.canonicalize();
            v
        })
        .collect();

    println!("Ciclu de consens: {N_AUT} autoritati, {N_RELEE} relee\n");

    // Fiecare autoritate calculeaza independent.
    let mut corpuri = Vec::new();
    let mut semnaturi = Vec::new();
    for (sk, pk) in &chei {
        let mut c = compute_consensus(&voturi).expect("consens");
        corpuri.push(c.body());
        c.add_signature::<S>(pk, sk);
        semnaturi.push(c.signatures[0].clone());
    }
    let identice = corpuri.windows(2).all(|w| w[0] == w[1]);
    println!(
        "Toate autoritatile au calculat acelasi corp: {}",
        if identice { "DA" } else { "NU" }
    );
    assert!(identice);

    let mut finalul = compute_consensus(&voturi).unwrap();
    finalul.signatures = semnaturi;
    finalul.signatures.sort_by_key(|(fp, _)| *fp);
    let doc = finalul.encode();

    let verificat = Consensus::parse_and_verify::<S>(&doc, &publice).expect("verificare");
    println!("Relee in consens: {} din {}", verificat.relays.len(), N_RELEE);
    println!(
        "  (ultimul e exclus: vazut de doar 2 din {} autoritati, sub pragul de {})",
        N_AUT,
        N_AUT / 2 + 1
    );
    assert_eq!(verificat.relays.len(), N_RELEE - 1);
    println!("Semnaturi valide:  {}", verificat.signatures.len());
    println!("Marime document:   {} octeti", doc.len());
    println!(
        "  ~{} octeti per releu, {} per semnatura",
        doc.len() / verificat.relays.len().max(1),
        S::SIG_LEN
    );

    println!("\nPrimele linii ale consensului:");
    for l in doc.lines().take(6) {
        println!("  {l}");
    }
    println!("  ...");

    // Proiectie pentru semnaturi post-cuantice.
    let corp = finalul.body().len();
    println!("\nProiectie pentru semnaturi hibride Ed25519 + ML-DSA-65:");
    for (nume, siglen) in [("Ed25519", 64usize), ("Ed25519+ML-DSA-65", 64 + 3309)] {
        let b64 = siglen.div_ceil(3) * 4;
        let total = corp + N_AUT * (b64 + 70);
        println!("  {nume:<20} consens = {total} octeti");
    }
}
