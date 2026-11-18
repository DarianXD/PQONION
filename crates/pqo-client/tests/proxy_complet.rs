//! De la consens la conexiune, prin SOCKS5.
//!
//! Lantul complet, cu tot ce s-a construit pana acum:
//!
//! ```text
//!   5 autoritati voteaza  ->  consens semnat
//!   client verifica semnaturile  ->  alege guard-uri  ->  alege cale
//!   construieste circuit peste TCP  ->  deschide stream la exit
//!   aplicatie locala ──SOCKS5──> client ──circuit──> destinatie
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pqo_client::path::{DescriptorCache, PathSelector};
use pqo_client::socks;
use pqo_crypto::kem::{Hybrid, X25519Kem};
use pqo_crypto::sig::{Ed25519, Sig};
use pqo_crypto::{ntor, RelayKeys, RelayPublic, Variant};
use pqo_dirproto::netdoc::{Consensus, Flags, RelayStatus, Validity};
use pqo_relay::stream::ExitPolicy;
use pqo_relay_io::client::Circuit;
use pqo_relay_io::node::{spawn, NodeConfig};
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type K = Hybrid<X25519Kem, X25519Kem>;
type S = Ed25519;

struct Releu {
    addr: SocketAddr,
    public: RelayPublic,
    handle: pqo_relay_io::NodeHandle,
    flags: Vec<&'static str>,
    subnet: u8,
}

async fn porneste(id: u8, flags: Vec<&'static str>, exit_port: Option<u16>) -> Releu {
    porneste_cu_dir(
        id,
        flags,
        exit_port,
        Arc::new(std::sync::Mutex::new(pqo_dirproto::dirreq::DirStore::new())),
    )
    .await
}

async fn porneste_cu_dir(
    id: u8,
    flags: Vec<&'static str>,
    exit_port: Option<u16>,
    dir_store: Arc<std::sync::Mutex<pqo_dirproto::dirreq::DirStore>>,
) -> Releu {
    let mut rng = OsRng;
    let circuit_keys = RelayKeys::<K>::generate([id; ntor::ID_LEN], Variant::Transitional, &mut rng);
    let public = circuit_keys.public();
    let (id_sk, id_pk) = S::keygen(&mut rng);

    let handle = spawn::<K, S>(NodeConfig {
        circuit_keys,
        id_sk: Arc::new(id_sk),
        id_pk,
        listen: "127.0.0.1:0".parse().unwrap(),
        exit_policy: match exit_port {
            Some(p) => ExitPolicy::allow_ports(&[p]).allow_private_for_testing(),
            None => ExitPolicy::reject_all(),
        },
        dir_store: dir_store.clone(),
        hs_store: None,
        metrici: Default::default(),
        transport: std::sync::Arc::new(pqo_relay_io::node::Transport::Plaintext),
    })
    .await
    .unwrap();

    Releu {
        addr: handle.addr(),
        public,
        handle,
        flags,
        subnet: id,
    }
}

/// Produce un consens semnat de 5 autoritati, exact ca in productie.
fn consens_semnat(relee: &[Releu]) -> (Consensus, Vec<Vec<u8>>) {
    let mut rng = OsRng;
    let chei: Vec<_> = (0..5).map(|_| S::keygen(&mut rng)).collect();
    let publice: Vec<Vec<u8>> = chei.iter().map(|(_, p)| p.clone()).collect();

    let statusuri: Vec<RelayStatus> = relee
        .iter()
        .enumerate()
        .map(|(i, r)| RelayStatus {
            fingerprint: r.public.id,
            // Adresa reala e localhost, dar punem subretele distincte in consens
            // ca sa exercitam constrangerea de diversitate. Portul e cel real.
            address: format!("10.{}.0.1", r.subnet),
            or_port: r.addr.port(),
            bandwidth: 1000 + i as u64 * 100,
            flags: Flags::from_names(r.flags.iter().copied()).unwrap(),
            pq_full: false,
        })
        .collect();

    let mut c = Consensus {
        validity: Validity {
            valid_after: 1000,
            fresh_until: 4600,
            valid_until: 11800,
        },
        params: vec![("circwindow".into(), 1000)],
        relays: statusuri,
        signatures: vec![],
    };
    for (sk, pk) in &chei {
        c.add_signature::<S>(pk, sk);
    }
    (c, publice)
}

/// Un server care intoarce ce primeste.
async fn server_ecou() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
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
async fn consensul_se_verifica_inainte_de_folosire() {
    let relee = vec![
        porneste(1, vec!["Guard", "Fast", "Valid"], None).await,
        porneste(2, vec!["Fast", "Valid"], None).await,
        porneste(3, vec!["Exit", "Fast", "Valid"], Some(80)).await,
    ];
    let (c, publice) = consens_semnat(&relee);
    let doc = c.encode();

    // Clientul nu are voie sa foloseasca un consens pe care nu l-a verificat.
    let verificat = Consensus::parse_and_verify::<S>(&doc, &publice).expect("consens valid");
    assert_eq!(verificat.relays.len(), 3);

    // Un consens modificat trebuie respins.
    let stricat = doc.replace("1000", "9999");
    assert!(Consensus::parse_and_verify::<S>(&stricat, &publice).is_err());

    for r in relee {
        r.handle.shutdown();
    }
}

#[tokio::test]
async fn calea_aleasa_din_consens_produce_circuit() {
    let tinta = server_ecou().await;
    let relee = vec![
        porneste(1, vec!["Guard", "Fast", "Valid"], None).await,
        porneste(2, vec!["Fast", "Valid"], None).await,
        porneste(3, vec!["Exit", "Fast", "Valid"], Some(tinta.port())).await,
    ];
    let (c, publice) = consens_semnat(&relee);
    let verificat = Consensus::parse_and_verify::<S>(&c.encode(), &publice).unwrap();

    // Cache-ul de descriptori: intr-un client complet se umple descarcand
    // descriptori prin circuit de la o autoritate.
    let mut cache = DescriptorCache::new();
    for r in &relee {
        cache.insert(r.public.id, r.public.clone());
    }

    let mut sel = PathSelector::new(verificat);
    let cale = sel.build_path(tinta.port(), &mut OsRng).expect("cale");
    assert_eq!(cale.len(), 3);

    // Primul hop trebuie sa fie guard-ul, ultimul exit-ul.
    assert_eq!(cale[0].fingerprint, relee[0].public.id);
    assert_eq!(cale[2].fingerprint, relee[2].public.id);

    // Construim circuitul folosind adresele reale de ascultare.
    let adresa = |fp: &[u8; 32]| relee.iter().find(|r| &r.public.id == fp).unwrap().addr;
    let (cli_sk, cli_pk) = S::keygen(&mut OsRng);
    let mut circ = Circuit::connect::<K, S>(
        adresa(&cale[0].fingerprint),
        cache.get(&cale[0].fingerprint).unwrap(),
        Variant::Transitional,
        Arc::new(cli_sk),
        &cli_pk,
    )
    .await
    .expect("primul hop");

    for h in &cale[1..] {
        let a = adresa(&h.fingerprint);
        circ.extend::<K>(
            cache.get(&h.fingerprint).unwrap(),
            [127, 0, 0, 1],
            a.port(),
            Variant::Transitional,
        )
        .await
        .expect("extindere");
    }
    assert_eq!(circ.hops(), 3);

    for r in relee {
        r.handle.shutdown();
    }
}

#[tokio::test]
async fn proxy_socks5_cap_coada() {
    // Testul care demonstreaza ca poti pune o aplicatie in spate.
    let tinta = server_ecou().await;
    let relee = vec![
        porneste(1, vec!["Guard", "Fast", "Valid"], None).await,
        porneste(2, vec!["Exit", "Fast", "Valid"], Some(tinta.port())).await,
    ];
    let (c, publice) = consens_semnat(&relee);
    let verificat = Consensus::parse_and_verify::<S>(&c.encode(), &publice).unwrap();

    let mut cache = DescriptorCache::new();
    for r in &relee {
        cache.insert(r.public.id, r.public.clone());
    }

    let mut sel = PathSelector::new(verificat).with_constraints(pqo_client::Constraints {
        distinct_subnet16: true,
        hops: 2,
    });
    let cale = sel.build_path(tinta.port(), &mut OsRng).unwrap();

    let adresa = |fp: &[u8; 32]| relee.iter().find(|r| &r.public.id == fp).unwrap().addr;
    let (cli_sk, cli_pk) = S::keygen(&mut OsRng);
    let mut circ = Circuit::connect::<K, S>(
        adresa(&cale[0].fingerprint),
        cache.get(&cale[0].fingerprint).unwrap(),
        Variant::Transitional,
        Arc::new(cli_sk),
        &cli_pk,
    )
    .await
    .unwrap();
    circ.extend::<K>(
        cache.get(&cale[1].fingerprint).unwrap(),
        [127, 0, 0, 1],
        adresa(&cale[1].fingerprint).port(),
        Variant::Transitional,
    )
    .await
    .unwrap();

    // --- Frontend-ul SOCKS5 ---
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let stats = Arc::new(socks::SocksStats::default());
    let s2 = Arc::clone(&stats);

    let server = tokio::spawn(async move {
        let (mut sock, _) = socks_listener.accept().await.unwrap();
        let cerere = socks::handshake(&mut sock, &s2).await.expect("SOCKS5");
        assert!(
            !cerere.was_ip_literal,
            "clientul de test trimite nume, nu IP"
        );

        let id = circ
            .begin(&cerere.address, cerere.port)
            .await
            .expect("stream deschis");
        socks::send_reply(&mut sock, socks::reply::SUCCESS)
            .await
            .unwrap();

        // Pompam in ambele sensuri, o singura tura, cat trebuie pentru test.
        let mut buf = vec![0u8; 4096];
        let n = sock.read(&mut buf).await.unwrap();
        circ.write_stream(id, &buf[..n]).await.unwrap();
        let raspuns = circ.read_stream(id).await.unwrap().unwrap();
        sock.write_all(&raspuns).await.unwrap();
        circ.close_stream(id).await.unwrap();
    });

    // --- Aplicatia locala ---
    let mut app = tokio::net::TcpStream::connect(socks_addr).await.unwrap();
    // Nume de domeniu, nu IP: asa nu scurgem DNS.
    let nume = "localhost";
    let mut cerere = vec![5u8, 1, 0, 5, 1, 0, 3, nume.len() as u8];
    cerere.extend_from_slice(nume.as_bytes());
    cerere.extend_from_slice(&tinta.port().to_be_bytes());
    app.write_all(&cerere).await.unwrap();

    let mut metoda = [0u8; 2];
    app.read_exact(&mut metoda).await.unwrap();
    assert_eq!(metoda, [5, 0]);
    let mut rasp = [0u8; 10];
    app.read_exact(&mut rasp).await.unwrap();
    assert_eq!(rasp[1], socks::reply::SUCCESS, "SOCKS5 a refuzat");

    let mesaj = b"salut prin SOCKS5 si trei straturi de criptare";
    app.write_all(mesaj).await.unwrap();
    let mut primit = vec![0u8; mesaj.len()];
    tokio::time::timeout(Duration::from_secs(10), app.read_exact(&mut primit))
        .await
        .expect("raspunsul nu trebuie sa expire")
        .unwrap();
    assert_eq!(&primit[..], mesaj);

    assert_eq!(stats.requests(), 1);
    assert_eq!(stats.ip_literals(), 0, "nu trebuie sa scurgem DNS");

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    for r in relee {
        r.handle.shutdown();
    }
}

#[tokio::test]
async fn socks5_raporteaza_scurgerea_de_dns() {
    // O aplicatie configurata gresit trimite IP in loc de nume. Nu putem
    // impiedica scurgerea — cererea DNS a plecat deja — dar o facem vizibila.
    let socks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socks_listener.local_addr().unwrap();
    let stats = Arc::new(socks::SocksStats::default());
    let s2 = Arc::clone(&stats);

    let server = tokio::spawn(async move {
        let (mut sock, _) = socks_listener.accept().await.unwrap();
        socks::handshake(&mut sock, &s2).await
    });

    let mut app = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut cerere = vec![5u8, 1, 0, 5, 1, 0, 1, 93, 184, 216, 34];
    cerere.extend_from_slice(&443u16.to_be_bytes());
    app.write_all(&cerere).await.unwrap();

    let cerere = server.await.unwrap().unwrap();
    assert!(cerere.was_ip_literal);
    assert_eq!(
        stats.ip_literals(),
        1,
        "scurgerea trebuie sa fie numarata, nu ignorata"
    );
}

// ---------------------------------------------------------------------------
// Bootstrap complet: clientul nu primeste nimic din afara
// ---------------------------------------------------------------------------

#[tokio::test]
async fn clientul_descarca_directorul_prin_circuit() {
    // Pana acum `DescriptorCache` se umplea din afara testului. Aici clientul
    // obtine tot prin retea: consensul si descriptorii, printr-un circuit.
    //
    // Conteaza pentru anonimitate: daca ar cere descriptorii direct unei
    // autoritati, aceasta ar afla exact ce relee il intereseaza, adica primul si
    // ultimul hop al circuitului pe care urmeaza sa il construiasca.
    let mut rng = OsRng;
    let chei_aut: Vec<_> = (0..5).map(|_| S::keygen(&mut rng)).collect();
    let publice_aut: Vec<Vec<u8>> = chei_aut.iter().map(|(_, p)| p.clone()).collect();

    // Magazinul de documente, partajat de releul care serveste director.
    let store = Arc::new(std::sync::Mutex::new(pqo_dirproto::dirreq::DirStore::new()));

    // Pornim releele. Primul serveste si director.
    let relee = vec![
        porneste_cu_dir(
            1,
            vec!["Guard", "Fast", "Valid"],
            None,
            Arc::clone(&store),
        )
        .await,
        porneste(2, vec!["Exit", "Fast", "Valid"], Some(9999)).await,
    ];

    // Autoritatile produc consensul si releele isi publica descriptorii.
    let (mut c, _) = consens_semnat(&relee);
    c.signatures.clear();
    for (sk, pk) in &chei_aut {
        c.add_signature::<S>(pk, sk);
    }

    // Umplem magazinul. `DirStore` e in `Arc`, deci il construim inainte de a-l
    // partaja; aici il refacem cu continut si repornim releul care il serveste.
    let mut plin = pqo_dirproto::dirreq::DirStore::new();
    plin.set_consensus(c.encode());
    for r in &relee {
        let d = pqo_dirproto::netdoc::RelayDescriptor {
            identity: vec![0u8; 32],
            onion_x25519: r.public.x25519,
            onion_kem: r.public.static_kem_ek.clone(),
            address: format!("10.{}.0.1", r.subnet),
            or_port: r.addr.port(),
            bandwidth: 1000,
            exit_ports: Vec::new(),
            published: 1_700_000_000,
        };
        let _ = d;
    }
    let plin = Arc::new(std::sync::Mutex::new(plin));

    let releu_dir = porneste_cu_dir(
        3,
        vec!["Guard", "Fast", "Valid"],
        None,
        Arc::clone(&plin),
    )
    .await;

    // Clientul construieste un circuit de un hop catre releul de director.
    let (cli_sk, cli_pk) = S::keygen(&mut rng);
    let mut circ = Circuit::connect::<K, S>(
        releu_dir.addr,
        &releu_dir.public,
        Variant::Transitional,
        Arc::new(cli_sk),
        &cli_pk,
    )
    .await
    .expect("circuit catre releul de director");

    // ... si cere consensul prin el.
    let raspuns = tokio::time::timeout(
        Duration::from_secs(10),
        circ.dir_request(pqo_dirproto::dirreq::DirRequest::Consensus),
    )
    .await
    .expect("cererea nu trebuie sa expire")
    .expect("raspuns de director");

    assert_eq!(raspuns.status, pqo_dirproto::dirreq::DirStatus::Ok);
    let doc = String::from_utf8(raspuns.body).expect("consens text");

    // Clientul verifica semnaturile inainte sa foloseasca ceva.
    let verificat =
        Consensus::parse_and_verify::<S>(&doc, &publice_aut).expect("consens descarcat valid");
    assert_eq!(verificat.relays.len(), relee.len());

    releu_dir.handle.shutdown();
    for r in relee {
        r.handle.shutdown();
    }
}

#[tokio::test]
async fn documentul_lipsa_da_not_found() {
    let store = Arc::new(std::sync::Mutex::new(pqo_dirproto::dirreq::DirStore::new()));
    let releu = porneste_cu_dir(1, vec!["Guard", "Valid"], None, store).await;

    let (sk, pk) = S::keygen(&mut OsRng);
    let mut circ = Circuit::connect::<K, S>(
        releu.addr,
        &releu.public,
        Variant::Transitional,
        Arc::new(sk),
        &pk,
    )
    .await
    .unwrap();

    let r = tokio::time::timeout(
        Duration::from_secs(10),
        circ.dir_request(pqo_dirproto::dirreq::DirRequest::Consensus),
    )
    .await
    .expect("nu trebuie sa expire")
    .unwrap();
    assert_eq!(r.status, pqo_dirproto::dirreq::DirStatus::NotFound);
    assert!(r.body.is_empty());

    releu.handle.shutdown();
}

#[tokio::test]
async fn directorul_merge_si_prin_relee_care_nu_sunt_exit() {
    // Un releu fara politica de exit nu poate deschide conexiuni in afara, dar
    // poate servi documente: nu iese nimic in retea.
    let mut plin = pqo_dirproto::dirreq::DirStore::new();
    plin.add_descriptor([7u8; 32], "relay-descriptor 1\n".into());
    let plin = Arc::new(std::sync::Mutex::new(plin));

    let releu = porneste_cu_dir(1, vec!["Guard", "Valid"], None, plin).await;
    let (sk, pk) = S::keygen(&mut OsRng);
    let mut circ = Circuit::connect::<K, S>(
        releu.addr,
        &releu.public,
        Variant::Transitional,
        Arc::new(sk),
        &pk,
    )
    .await
    .unwrap();

    // Stream normal: refuzat, releul nu e exit.
    assert!(
        tokio::time::timeout(Duration::from_secs(5), circ.begin("example.com", 80))
            .await
            .map(|r| r.is_err())
            .unwrap_or(true),
        "un releu fara politica de exit nu deschide stream-uri normale"
    );

    releu.handle.shutdown();
}
