//! Un circuit complet peste TLS.
//!
//! Testele din `tls_legare.rs` verifica handshake-ul de legatura. Aici verificam
//! ca releul chiar **foloseste** TLS: pana la aceasta versiune modulul exista si
//! era testat, dar nodul deschidea TCP simplu.

#![cfg(feature = "tls")]

use std::sync::Arc;
use std::time::Duration;

use pqo_crypto::kem::{Hybrid, X25519Kem};
use pqo_crypto::sig::{Ed25519, Sig};
use pqo_crypto::{ntor, RelayKeys, Variant};
use pqo_dirproto::dirreq::DirStore;
use pqo_relay::stream::ExitPolicy;
use pqo_relay_io::client::Circuit;
use pqo_relay_io::node::{spawn, NodeConfig, Transport, TlsTransport};
use rand_core::OsRng;

type K = Hybrid<X25519Kem, X25519Kem>;
type S = Ed25519;

/// Porneste un releu peste TLS si intoarce adresa, cheile si transportul.
async fn releu_tls(
    id: u8,
    exit: Option<u16>,
) -> (
    std::net::SocketAddr,
    pqo_crypto::RelayPublic,
    Arc<TlsTransport>,
    pqo_relay_io::NodeHandle,
) {
    let mut rng = OsRng;
    let keys = RelayKeys::<K>::generate([id; ntor::ID_LEN], Variant::Transitional, &mut rng);
    let public = keys.public();
    let (sk, pk) = S::keygen(&mut rng);
    let t = Arc::new(TlsTransport::nou().expect("certificat efemer"));

    let handle = spawn::<K, S>(NodeConfig {
        circuit_keys: keys,
        id_sk: Arc::new(sk),
        id_pk: pk,
        listen: "127.0.0.1:0".parse().unwrap(),
        exit_policy: match exit {
            Some(p) => ExitPolicy::allow_ports(&[p]).allow_private_for_testing(),
            None => ExitPolicy::reject_all(),
        },
        dir_store: Arc::new(std::sync::Mutex::new(DirStore::new())),
        hs_store: None,
        metrici: Default::default(),
        transport: Arc::new(Transport::Tls(Arc::clone(&t))),
    })
    .await
    .expect("releul trebuie sa porneasca");

    (handle.addr(), public, t, handle)
}

/// Un server care intoarce ce primeste.
async fn server_ecou() -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn circuit_de_doua_hopuri_peste_tls() {
    let (a1, p1, t1, h1) = releu_tls(1, None).await;
    let (a2, p2, _t2, h2) = releu_tls(2, None).await;

    let (sk, pk) = S::keygen(&mut OsRng);
    let mut c = Circuit::connect_tls::<K, S>(
        a1,
        &p1,
        Variant::Transitional,
        Arc::new(sk),
        &pk,
        &t1.connector,
    )
    .await
    .expect("primul hop peste TLS");
    assert_eq!(c.hops(), 1);

    tokio::time::timeout(
        Duration::from_secs(15),
        c.extend::<K>(&p2, [127, 0, 0, 1], a2.port(), Variant::Transitional),
    )
    .await
    .expect("extinderea nu trebuie sa expire")
    .expect("al doilea hop");
    assert_eq!(c.hops(), 2, "circuitul trece prin doua relee, peste TLS");

    h1.shutdown();
    h2.shutdown();
}

#[tokio::test]
async fn trafic_prin_circuit_tls() {
    let tinta = server_ecou().await;
    let (a1, p1, t1, h1) = releu_tls(1, None).await;
    let (a2, p2, _t2, h2) = releu_tls(2, Some(tinta.port())).await;

    let (sk, pk) = S::keygen(&mut OsRng);
    let mut c = Circuit::connect_tls::<K, S>(
        a1,
        &p1,
        Variant::Transitional,
        Arc::new(sk),
        &pk,
        &t1.connector,
    )
    .await
    .unwrap();
    c.extend::<K>(&p2, [127, 0, 0, 1], a2.port(), Variant::Transitional)
        .await
        .unwrap();

    let id = tokio::time::timeout(
        Duration::from_secs(15),
        c.begin("127.0.0.1", tinta.port()),
    )
    .await
    .expect("BEGIN nu trebuie sa expire")
    .expect("stream deschis");

    let mesaj = b"octeti prin doua straturi de TLS si doua de CGO";
    c.write_stream(id, mesaj).await.unwrap();
    let primit = tokio::time::timeout(Duration::from_secs(15), c.read_stream(id))
        .await
        .expect("raspunsul nu trebuie sa expire")
        .unwrap()
        .expect("stream deschis");
    assert_eq!(&primit[..], mesaj);

    h1.shutdown();
    h2.shutdown();
}

#[tokio::test]
async fn un_client_fara_tls_nu_ajunge_la_un_releu_cu_tls() {
    // Daca ar merge, transportul ar fi optional in fapt, nu doar in configuratie.
    let (a1, p1, _t, h1) = releu_tls(1, None).await;
    let (sk, pk) = S::keygen(&mut OsRng);

    let r = tokio::time::timeout(
        Duration::from_secs(5),
        Circuit::connect::<K, S>(a1, &p1, Variant::Transitional, Arc::new(sk), &pk),
    )
    .await;
    assert!(
        r.is_err() || r.unwrap().is_err(),
        "un client care vorbeste TCP simplu nu are ce cauta pe un releu cu TLS"
    );
    h1.shutdown();
}
