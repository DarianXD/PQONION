//! Cat costa anonimatul, in milisecunde.
//!
//!     cargo run --release -p pqo-bin --example latenta
//!
//! Masoara patru scenarii pe aceeasi masina, ca diferentele sa reflecte
//! protocolul, nu reteaua:
//!
//!   1. TCP direct              — linia de referinta
//!   2. circuit de 3 hopuri     — costul rutarii onion
//!   3. serviciu ascuns, complet — descriptor, introducere, rendezvous
//!   4. cerere ulterioara prin tunelul deja deschis
//!
//! Al patrulea e cifra care conteaza pentru un utilizator: costul de pornire se
//! plateste o data, iar cererile de dupa merg prin tunelul existent.
//!
//! # De ce pe localhost
//!
//! Pe o retea reala, latenta de transport ar domina si ar ascunde exact ce vrem
//! sa masuram. Aici toate nodurile sunt pe aceeasi masina, deci cifrele arata
//! costul **protocolului**: handshake-uri, criptare pe straturi, celule
//! suplimentare. Intr-un deployment real se adauga latenta fiecarei legaturi,
//! de trei ori pentru un circuit obisnuit si de sase ori pentru un serviciu
//! ascuns, pentru ca traficul trece prin doua circuite.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pqo_crypto::kdf::ShakeRng;
use pqo_crypto::kem::{Hybrid, Kem, X25519Kem};
use pqo_crypto::sig::{Ed25519, Sig};
use pqo_crypto::{client_finish, client_init, server_respond, RelayKeys, Variant};
use pqo_dirproto::dirreq::DirStore;
use pqo_hs::desc::IntroPoint;
use pqo_hs::rend::{auth_key_id, new_cookie, IntroPayload, Introduce};
use pqo_relay::stream::ExitPolicy;
use pqo_relay_io::client::TransportClient;
use pqo_relay_io::node::{spawn, NodeConfig, Transport};
use pqo_relay_io::tunnel::Tunnel;
use pqo_wire::{RelayCmd, RelayMessage, StreamId};
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "pq")]
type K = Hybrid<X25519Kem, pqo_crypto::MlKem768>;
#[cfg(not(feature = "pq"))]
type K = Hybrid<X25519Kem, X25519Kem>;
type S = Ed25519;

/// Cate masuratori facem pentru fiecare scenariu.
const RULARI: usize = 12;
/// Cate aruncam de la inceput, ca sa nu masuram incalzirea alocatorului.
const INCALZIRE: usize = 2;

/// Rezumatul unei serii de masuratori.
struct Statistica {
    mediana: f64,
    minim: f64,
    maxim: f64,
}

impl Statistica {
    fn din(mut v: Vec<f64>) -> Self {
        v.sort_by(|a, b| a.partial_cmp(b).expect("fara NaN"));
        // Mediana, nu media: o singura rulare lenta — o pauza de planificare, o
        // colectare de memorie in alt proces — ar deplasa media fara sa spuna
        // nimic despre protocol.
        Statistica {
            mediana: v[v.len() / 2],
            minim: v[0],
            maxim: v[v.len() - 1],
        }
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

// ---------------------------------------------------------------------------

/// Un server care intoarce imediat ce primeste.
async fn server_ecou() -> SocketAddr {
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

/// Porneste `n` relee cu semintele de testnet.
async fn retea(n: u8, exit_port: u16) -> (Vec<SocketAddr>, Vec<pqo_relay_io::NodeHandle>) {
    let mut adrese = Vec::new();
    let mut mane = Vec::new();
    for i in 0..n {
        let seed = pqo_bin::testnet_seed(i);
        let mut r_id = ShakeRng::new(b"pqonion-relay-identity-v1", &[&seed]);
        let (id_sk, id_pk) = S::keygen(&mut r_id);
        let mut r_onion = ShakeRng::new(b"pqonion-relay-onion-v1", &[&seed]);
        let keys = RelayKeys::<K>::generate(
            pqo_dirproto::netdoc::fingerprint(&id_pk),
            Variant::Transitional,
            &mut r_onion,
        );
        let h = spawn::<K, S>(NodeConfig {
            circuit_keys: keys,
            id_sk: Arc::new(id_sk),
            id_pk,
            listen: "127.0.0.1:0".parse().unwrap(),
            // Toate releele pot fi exit, ca sa nu conteze care e ultimul.
            exit_policy: ExitPolicy::allow_ports(&[exit_port]).allow_private_for_testing(),
            dir_store: Arc::new(std::sync::Mutex::new(DirStore::new())),
            hs_store: None,
            metrici: Default::default(),
            transport: Arc::new(Transport::Plaintext),
        })
        .await
        .expect("releul trebuie sa porneasca");
        adrese.push(h.addr());
        mane.push(h);
    }
    (adrese, mane)
}

// ---------------------------------------------------------------------------

/// 1. TCP direct: linia de referinta.
async fn masoara_direct(tinta: SocketAddr) -> Statistica {
    let mut v = Vec::new();
    for i in 0..RULARI {
        let t = Instant::now();
        let mut s = tokio::net::TcpStream::connect(tinta).await.unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        if i >= INCALZIRE {
            v.push(ms(t.elapsed()));
        }
    }
    Statistica::din(v)
}

/// 2. Circuit de 3 hopuri: construire plus prima cerere.
async fn masoara_circuit(relee: &[SocketAddr], tinta: SocketAddr) -> (Statistica, Statistica) {
    let mut constructie = Vec::new();
    let mut cerere = Vec::new();

    for i in 0..RULARI {
        let (sk, pk) = S::keygen(&mut OsRng);
        let t = Instant::now();
        let mut c = pqo_bin::circuit_catre::<K, S>(
            relee,
            2,
            Arc::new(sk),
            &pk,
            TransportClient::Plaintext,
        )
        .await
        .expect("circuit");
        let dupa_constructie = t.elapsed();

        let t2 = Instant::now();
        let id = c.begin("127.0.0.1", tinta.port()).await.expect("BEGIN");
        c.write_stream(id, b"ping").await.unwrap();
        let _ = c.read_stream(id).await.unwrap();
        let dupa_cerere = t2.elapsed();

        if i >= INCALZIRE {
            constructie.push(ms(dupa_constructie));
            cerere.push(ms(dupa_cerere));
        }
    }
    (Statistica::din(constructie), Statistica::din(cerere))
}

/// Rezultatul unei conexiuni complete la un serviciu ascuns.
struct Etape {
    total: f64,
    rendezvous: f64,
    introducere: f64,
    prima_cerere: f64,
}

/// 3 si 4. Serviciu ascuns: conexiune completa, apoi cerere prin tunel.
async fn masoara_serviciu_ascuns(
    relee: &[SocketAddr],
    tinta: SocketAddr,
) -> (Vec<Etape>, Statistica) {
    let mut rng = OsRng;
    let mut etape = Vec::new();
    let mut ulterioare = Vec::new();

    // Cheile serviciului, fixe pe toata durata masuratorii.
    let hs_keys = RelayKeys::<K>::generate([0xAA; 32], Variant::Transitional, &mut rng);
    let hs_public = hs_keys.public();
    let (intro_dk, intro_ek) = K::keygen(&mut rng);
    let (auth_sk, auth_pk) = S::keygen(&mut rng);

    // Serviciul se anunta o singura data la punctul de introducere, ca in
    // realitate: costul asta nu se plateste per conexiune.
    let (ssk, spk) = S::keygen(&mut rng);
    let ssk = Arc::new(ssk);
    let mut serv_la_ip = pqo_bin::circuit_catre::<K, S>(
        relee,
        0,
        Arc::clone(&ssk),
        &spk,
        TransportClient::Plaintext,
    )
    .await
    .expect("circuit catre punctul de introducere");
    serv_la_ip
        .establish_intro::<S>(&auth_sk, &auth_pk)
        .await
        .expect("ESTABLISH_INTRO");

    let ip_desc = IntroPoint {
        relay_id: pqo_bin::testnet_relay_public::<K, S>(0).id,
        onion_x25519: intro_ek[..32].try_into().unwrap(),
        onion_kem: Some(intro_ek[32..].to_vec()),
        svc_x25519: hs_public.x25519,
        auth_key: auth_pk.clone(),
    };

    for i in 0..RULARI {
        let (csk, cpk) = S::keygen(&mut rng);
        let csk = Arc::new(csk);
        let t0 = Instant::now();

        // --- clientul stabileste un punct de rendezvous ---
        let cookie = new_cookie(&mut rng);
        let mut cli_rp = pqo_bin::circuit_catre::<K, S>(
            relee,
            1,
            Arc::clone(&csk),
            &cpk,
            TransportClient::Plaintext,
        )
        .await
        .expect("circuit catre rendezvous");
        cli_rp.establish_rendezvous(&cookie).await.expect("RP");
        let t_rendezvous = t0.elapsed();

        // --- clientul trimite cererea de introducere ---
        let t1 = Instant::now();
        let (state, hs_client) =
            client_init::<K>(&hs_public, Variant::Transitional, &mut rng).unwrap();
        let payload = IntroPayload {
            cookie,
            rp_relay_id: pqo_bin::testnet_relay_public::<K, S>(1).id,
            rp_address: "127.0.0.1".into(),
            rp_port: relee[1].port(),
            handshake: hs_client,
        };
        let intro = Introduce::seal::<K>(&ip_desc, &payload, &mut rng).unwrap();
        let mut corp = auth_key_id(&auth_pk).to_vec();
        corp.extend_from_slice(&intro.encode());

        let mut cli_ip = pqo_bin::circuit_catre::<K, S>(
            relee,
            0,
            Arc::clone(&csk),
            &cpk,
            TransportClient::Plaintext,
        )
        .await
        .expect("circuit catre punctul de introducere");
        cli_ip.send_introduce(corp).await.expect("INTRODUCE1");

        // --- serviciul raspunde ---
        let primit = serv_la_ip.wait_introduce2().await.expect("INTRODUCE2");
        let intro2 = Introduce::parse(&primit[32..]).unwrap();
        let p = intro2.open::<K>(&intro_dk).unwrap();
        let (hs_server, res_serv) =
            server_respond::<K>(&hs_keys, &p.handshake, &mut rng).unwrap();

        let mut serv_la_rp = pqo_bin::circuit_catre::<K, S>(
            relee,
            1,
            Arc::clone(&ssk),
            &spk,
            TransportClient::Plaintext,
        )
        .await
        .expect("circuit serviciu-rendezvous");
        serv_la_rp
            .send_rendezvous1(&p.cookie, &hs_server)
            .await
            .expect("RENDEZVOUS1");
        let r2 = cli_rp.wait_rendezvous2().await.expect("RENDEZVOUS2");
        let res_cli = client_finish::<K>(state, &r2).unwrap();
        let t_introducere = t1.elapsed();

        // --- tunelul e deschis; prima cerere ---
        let t2 = Instant::now();
        let mut tun_cli = Tunnel::client(cli_rp, &res_cli.key_seed);
        let mut tun_serv = Tunnel::service(serv_la_rp, &res_serv.key_seed);

        let stream = StreamId(1);
        tun_cli
            .send(&RelayMessage::new(RelayCmd::Data, stream, b"ping".to_vec()).unwrap())
            .await
            .unwrap();
        let m = tun_serv.recv().await.unwrap();
        tun_serv
            .send(&RelayMessage::new(RelayCmd::Data, stream, m.body).unwrap())
            .await
            .unwrap();
        let _ = tun_cli.recv().await.unwrap();
        let t_prima = t2.elapsed();

        // --- cereri ulterioare prin tunelul deja deschis ---
        let t3 = Instant::now();
        tun_cli
            .send(&RelayMessage::new(RelayCmd::Data, stream, b"ping".to_vec()).unwrap())
            .await
            .unwrap();
        let m = tun_serv.recv().await.unwrap();
        tun_serv
            .send(&RelayMessage::new(RelayCmd::Data, stream, m.body).unwrap())
            .await
            .unwrap();
        let _ = tun_cli.recv().await.unwrap();
        let t_ulterioara = t3.elapsed();

        if i >= INCALZIRE {
            etape.push(Etape {
                total: ms(t0.elapsed()),
                rendezvous: ms(t_rendezvous),
                introducere: ms(t_introducere),
                prima_cerere: ms(t_prima),
            });
            ulterioare.push(ms(t_ulterioara));
        }
        let _ = tinta;
    }

    (etape, Statistica::din(ulterioare))
}

// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    println!("Latenta: cat costa anonimatul");
    println!();
    if cfg!(debug_assertions) {
        println!("  ATENTIE: build de dezvoltare. Ruleaza cu --release pentru cifre utile.");
        println!();
    }
    println!(
        "  {} rulari per scenariu, primele {} aruncate ca incalzire.",
        RULARI, INCALZIRE
    );
    println!("  Toate nodurile pe aceeasi masina: cifrele arata costul protocolului,");
    println!("  nu al retelei. Vezi nota din antetul fisierului.");
    println!();

    let tinta = server_ecou().await;
    let (relee, mane) = retea(3, tinta.port()).await;

    let direct = masoara_direct(tinta).await;
    let (constructie, cerere_circuit) = masoara_circuit(&relee, tinta).await;
    let (etape, ulterioare) = masoara_serviciu_ascuns(&relee, tinta).await;

    let stat = |f: fn(&Etape) -> f64| Statistica::din(etape.iter().map(f).collect());
    let med = |f: fn(&Etape) -> f64| stat(f).mediana;

    println!("{:<44} {:>9} {:>9} {:>9}", "scenariu", "mediana", "min", "max");
    println!("{}", "-".repeat(74));
    println!(
        "{:<44} {:>8.2} {:>8.2} {:>8.2}",
        "1. TCP direct (referinta)", direct.mediana, direct.minim, direct.maxim
    );
    println!(
        "{:<44} {:>8.2} {:>8.2} {:>8.2}",
        "2. circuit de 3 hopuri, construire", constructie.mediana, constructie.minim, constructie.maxim
    );
    println!(
        "{:<44} {:>8.2} {:>8.2} {:>8.2}",
        "   + prima cerere prin circuit",
        cerere_circuit.mediana,
        cerere_circuit.minim,
        cerere_circuit.maxim
    );
    println!("{}", "-".repeat(74));
    println!(
        "{:<44} {:>8.2}",
        "3. serviciu ascuns, conexiune completa",
        med(|e| e.total)
    );
    for (eticheta, f) in [
        ("   din care: rendezvous", (|e: &Etape| e.rendezvous) as fn(&Etape) -> f64),
        ("   din care: introducere + handshake", |e: &Etape| e.introducere),
        ("   din care: prima cerere prin tunel", |e: &Etape| e.prima_cerere),
    ] {
        let st = stat(f);
        println!(
            "{:<44} {:>8.2} {:>8.2} {:>8.2}",
            eticheta, st.mediana, st.minim, st.maxim
        );
    }
    println!("{}", "-".repeat(74));
    println!(
        "{:<44} {:>8.2} {:>8.2} {:>8.2}",
        "4. cerere ulterioara prin tunelul deschis",
        ulterioare.mediana,
        ulterioare.minim,
        ulterioare.maxim
    );
    println!();

    let factor_circuit = cerere_circuit.mediana / direct.mediana;
    let factor_hs = ulterioare.mediana / direct.mediana;
    println!("Interpretare");
    println!(
        "  O cerere prin circuit costa {:.1}x fata de una directa.",
        factor_circuit
    );
    println!(
        "  O cerere prin serviciu ascuns costa {:.1}x, dupa ce tunelul e deschis.",
        factor_hs
    );
    println!(
        "  Deschiderea tunelului costa {:.0} ms, o singura data per conexiune.",
        med(|e| e.total)
    );
    println!();
    println!("  Serviciul ascuns e mai scump decat un circuit obisnuit pentru ca");
    println!("  traficul trece prin doua circuite — al clientului si al serviciului —");
    println!("  care se intalnesc la punctul de rendezvous. Aici sunt 6 relee in total.");
    if !cfg!(feature = "pq") {
        println!();
        println!("  Compilat FARA 'pq': cifrele nu includ costul ML-KEM.");
    }

    for h in mane {
        h.shutdown();
    }
}
