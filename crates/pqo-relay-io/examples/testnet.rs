//! Porneste o retea de relee pe localhost si construieste un circuit prin ea.
//!
//!     cargo run -p pqo-relay-io --example testnet

use std::sync::Arc;
use std::time::Instant;

use pqo_crypto::kem::{Hybrid, X25519Kem};
use pqo_crypto::sig::{Ed25519, Sig};
use pqo_crypto::{ntor, RelayKeys, Variant};
use pqo_relay_io::client::Circuit;
use pqo_relay::stream::ExitPolicy;
use pqo_relay_io::node::{spawn, NodeConfig};
use rand_core::OsRng;

type K = Hybrid<X25519Kem, X25519Kem>;
type S = Ed25519;

const N: usize = 5;

#[tokio::main]
async fn main() {
    let mut rng = OsRng;
    println!("Pornesc {N} relee pe localhost\n");

    let mut relee = Vec::new();
    for i in 0..N {
        let keys = RelayKeys::<K>::generate([i as u8 + 1; ntor::ID_LEN], Variant::Transitional, &mut rng);
        let public = keys.public();
        let (sk, pk) = S::keygen(&mut rng);
        let h = spawn::<K, S>(NodeConfig {
            circuit_keys: keys,
            id_sk: Arc::new(sk),
            id_pk: pk,
            listen: "127.0.0.1:0".parse().unwrap(),
            // Ultimul releu e exit; restul nu. Implicit nu iese nimic pe nicaieri.
            exit_policy: if i == N - 1 {
                ExitPolicy::allow_ports(&[80, 443]).allow_private_for_testing()
            } else {
                ExitPolicy::reject_all()
            },
            dir_store: Arc::new(std::sync::Mutex::new(pqo_dirproto::dirreq::DirStore::new())),
            hs_store: None,
            metrici: Default::default(),
            transport: std::sync::Arc::new(pqo_relay_io::node::Transport::Plaintext),
        })
        .await
        .unwrap();
        println!("  releu {} -> {}", i + 1, h.addr());
        relee.push((h, public));
    }

    let (cli_sk, cli_pk) = S::keygen(&mut rng);
    println!("\nConstruiesc un circuit de 3 hop-uri...");
    let t0 = Instant::now();

    let mut c = Circuit::connect::<K, S>(
        relee[0].0.addr(),
        &relee[0].1,
        Variant::Transitional,
        Arc::new(cli_sk),
        &cli_pk,
    )
    .await
    .unwrap();
    let t_hop1 = t0.elapsed();
    println!("  hop 1 (CREATE2):  {:>7.2?}", t_hop1);

    for (i, (handle, public)) in relee.iter().enumerate().take(3).skip(1) {
        let t = Instant::now();
        c.extend::<K>(
            public,
            [127, 0, 0, 1],
            handle.addr().port(),
            Variant::Transitional,
        )
        .await
        .unwrap();
        println!("  hop {} (EXTEND2): {:>7.2?}", i + 1, t.elapsed());
    }

    println!("\nCircuit deschis: {} hop-uri in {:.2?}", c.hops(), t0.elapsed());
    println!("\nReleele 2 si 3 nu stiu ca exista un client. Fiecare vede doar vecinul.");

    for (h, _) in relee {
        h.shutdown();
    }
}
