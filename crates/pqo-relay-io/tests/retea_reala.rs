//! Trei relee care ruleaza efectiv pe TCP, si un client care construieste un
//! circuit de trei hop-uri prin ele.
//!
//! Primul test din tot proiectul in care octetii trec printr-un socket. Tot ce a
//! fost pana acum a rulat in proces.
//!
//! ```text
//!   client ──TCP──> releu1 ──TCP──> releu2 ──TCP──> releu3
//!            CREATE2         EXTEND2         EXTEND2
//! ```
//!
//! Releele 2 si 3 nu stiu ca exista un client: fiecare vede doar vecinul lui.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pqo_crypto::kem::{Hybrid, X25519Kem};
use pqo_crypto::sig::{Ed25519, Sig};
use pqo_crypto::{ntor, RelayKeys, RelayPublic, Variant};
use pqo_relay_io::client::Circuit;
use pqo_relay::stream::ExitPolicy;
use pqo_relay_io::node::{spawn, NodeConfig};
use pqo_wire::{ChanCmd, RelayCmd, RelayMessage, StreamId};
use rand_core::OsRng;

type K = Hybrid<X25519Kem, X25519Kem>;
type S = Ed25519;

/// Un releu pornit, cu tot ce trebuie ca sa fie tinta unui EXTEND2.
struct Releu {
    addr: SocketAddr,
    public: RelayPublic,
    handle: pqo_relay_io::NodeHandle,
}

async fn porneste(id: u8) -> Releu {
    porneste_cu(id, ExitPolicy::reject_all()).await
}

async fn porneste_cu(id: u8, exit_policy: ExitPolicy) -> Releu {
    let mut rng = OsRng;
    let circuit_keys = RelayKeys::<K>::generate([id; ntor::ID_LEN], Variant::Transitional, &mut rng);
    let public = circuit_keys.public();
    let (id_sk, id_pk) = S::keygen(&mut rng);

    let handle = spawn::<K, S>(NodeConfig {
        circuit_keys,
        id_sk: Arc::new(id_sk),
        id_pk,
        listen: "127.0.0.1:0".parse().unwrap(),
        exit_policy,
        dir_store: Arc::new(std::sync::Mutex::new(pqo_dirproto::dirreq::DirStore::new())),
        hs_store: None,
        metrici: Default::default(),
        transport: std::sync::Arc::new(pqo_relay_io::node::Transport::Plaintext),
    })
    .await
    .expect("releul trebuie sa porneasca");

    Releu {
        addr: handle.addr(),
        public,
        handle,
    }
}

/// Construieste un circuit de `n` hop-uri prin releele date.
async fn circuit(relee: &[Releu], n: usize) -> Circuit<tokio::net::TcpStream> {
    let mut rng = OsRng;
    let (cli_sk, cli_pk) = S::keygen(&mut rng);

    let mut c = Circuit::connect::<K, S>(
        relee[0].addr,
        &relee[0].public,
        Variant::Transitional,
        Arc::new(cli_sk),
        &cli_pk,
    )
    .await
    .expect("primul hop");
    assert_eq!(c.hops(), 1);

    for r in relee.iter().take(n).skip(1) {
        c.extend::<K>(&r.public, [127, 0, 0, 1], r.addr.port(), Variant::Transitional)
            .await
            .expect("extindere");
    }
    assert_eq!(c.hops(), n);
    c
}

#[tokio::test]
async fn un_singur_hop_peste_tcp() {
    let relee = vec![porneste(1).await];
    let c = circuit(&relee, 1).await;
    assert_eq!(c.hops(), 1);
    for r in relee {
        r.handle.shutdown();
    }
}

#[tokio::test]
async fn doua_hopuri_peste_tcp() {
    let relee = vec![porneste(1).await, porneste(2).await];
    let c = tokio::time::timeout(Duration::from_secs(10), circuit(&relee, 2))
        .await
        .expect("extinderea nu trebuie sa expire");
    assert_eq!(c.hops(), 2);
    for r in relee {
        r.handle.shutdown();
    }
}

#[tokio::test]
async fn trei_hopuri_peste_tcp() {
    // Testul central: un circuit complet, cu octeti reali prin trei socket-uri.
    let relee = vec![porneste(1).await, porneste(2).await, porneste(3).await];
    let c = tokio::time::timeout(Duration::from_secs(10), circuit(&relee, 3))
        .await
        .expect("constructia nu trebuie sa expire");
    assert_eq!(c.hops(), 3);
    for r in relee {
        r.handle.shutdown();
    }
}

#[tokio::test]
async fn circuite_multiple_simultan() {
    // Mai multi clienti pe aceleasi relee. Verifica ca nucleul nu amesteca
    // starile de circuit intre conexiuni.
    let relee = Arc::new(vec![porneste(1).await, porneste(2).await]);

    let mut sarcini = Vec::new();
    for _ in 0..8 {
        let r = Arc::clone(&relee);
        sarcini.push(tokio::spawn(async move {
            let c = circuit(&r, 2).await;
            assert_eq!(c.hops(), 2);
        }));
    }
    for s in sarcini {
        tokio::time::timeout(Duration::from_secs(15), s)
            .await
            .expect("niciun circuit nu trebuie sa expire")
            .expect("niciun circuit nu trebuie sa cada");
    }
}

#[tokio::test]
async fn extindere_catre_adresa_moarta_esueaza_curat() {
    // Releul 1 primeste EXTEND2 catre un port pe care nu asculta nimeni.
    // Circuitul trebuie sa cada, nu sa atarne.
    let relee = vec![porneste(1).await];
    let mut c = circuit(&relee, 1).await;

    let mort = RelayKeys::<K>::generate([9; ntor::ID_LEN], Variant::Transitional, &mut OsRng);
    let r = tokio::time::timeout(
        Duration::from_secs(10),
        c.extend::<K>(&mort.public(), [127, 0, 0, 1], 1, Variant::Transitional),
    )
    .await;

    assert!(
        r.is_err() || r.unwrap().is_err(),
        "extinderea catre o adresa moarta trebuie sa esueze"
    );
    for r in relee {
        r.handle.shutdown();
    }
}

#[tokio::test]
async fn extend2_fara_relay_early_e_refuzat() {
    // Trimitem EXTEND2 intr-o celula RELAY normala. Releul trebuie sa inchida
    // circuitul: fara regula asta, plafonul de lungime n-ar avea efect.
    let relee = vec![porneste(1).await, porneste(2).await];
    let mut c = circuit(&relee, 1).await;

    let mut rng = OsRng;
    let (_st, hs) =
        pqo_crypto::client_init::<K>(&relee[1].public, Variant::Transitional, &mut rng).unwrap();
    let msg = RelayMessage::new(
        RelayCmd::Extend2,
        StreamId::CONTROL,
        pqo_wire::Extend2 {
            specs: vec![
                pqo_wire::LinkSpec::Ipv4 {
                    addr: [127, 0, 0, 1],
                    port: relee[1].addr.port(),
                },
                pqo_wire::LinkSpec::RelayId(relee[1].public.id),
            ],
            htype: pqo_wire::HandshakeType::PqNtorTransitional,
            data: hs,
        }
        .encode(),
    )
    .unwrap();

    c.send(1, &msg, ChanCmd::Relay).await.unwrap();

    let r = tokio::time::timeout(Duration::from_secs(5), c.recv()).await;
    assert!(
        r.is_err() || r.unwrap().is_err(),
        "EXTEND2 fara RELAY_EARLY trebuie sa duca la inchiderea circuitului"
    );
    for r in relee {
        r.handle.shutdown();
    }
}

#[tokio::test]
async fn caderea_unui_releu_din_mijloc_inchide_circuitul() {
    let relee = vec![porneste(1).await, porneste(2).await, porneste(3).await];
    let mut c = tokio::time::timeout(Duration::from_secs(10), circuit(&relee, 3))
        .await
        .expect("constructia nu trebuie sa expire");

    // Oprim releul din mijloc.
    let mut it = relee.into_iter();
    let r1 = it.next().unwrap();
    it.next().unwrap().handle.shutdown();
    let r3 = it.next().unwrap();

    // Orice mesaj catre hop-ul 3 trebuie sa esueze, nu sa atarne.
    let date = RelayMessage::new(RelayCmd::Data, StreamId(1), vec![1u8; 50]).unwrap();
    let _ = c.send(3, &date, ChanCmd::Relay).await;
    let r = tokio::time::timeout(Duration::from_secs(5), c.recv()).await;
    assert!(r.is_err() || r.unwrap().is_err());

    r1.handle.shutdown();
    r3.handle.shutdown();
}

// ---------------------------------------------------------------------------
// Proxy cap-coada
// ---------------------------------------------------------------------------

/// Un server TCP care intoarce ce primeste, cu un antet.
async fn server_ecou() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

/// Politica de exit pentru testnet: portul serverului, si adrese private permise.
fn politica_test(port: u16) -> ExitPolicy {
    ExitPolicy::allow_ports(&[port]).allow_private_for_testing()
}

#[tokio::test]
async fn proxy_cap_coada_prin_trei_hopuri() {
    // Testul care demonstreaza ca stiva chiar transporta trafic util.
    let tinta = server_ecou().await;
    let relee = vec![
        porneste(1).await,
        porneste(2).await,
        porneste_cu(3, politica_test(tinta.port())).await,
    ];
    let mut c = tokio::time::timeout(Duration::from_secs(10), circuit(&relee, 3))
        .await
        .expect("constructia nu trebuie sa expire");

    let id = tokio::time::timeout(
        Duration::from_secs(10),
        c.begin("127.0.0.1", tinta.port()),
    )
    .await
    .expect("BEGIN nu trebuie sa expire")
    .expect("stream deschis");

    let mesaj = b"salut prin trei hop-uri";
    c.write_stream(id, mesaj).await.unwrap();

    let primit = tokio::time::timeout(Duration::from_secs(10), c.read_stream(id))
        .await
        .expect("raspunsul nu trebuie sa expire")
        .unwrap()
        .expect("stream deschis");
    assert_eq!(&primit[..], mesaj, "ecoul difera de ce am trimis");

    c.close_stream(id).await.unwrap();
    for r in relee {
        r.handle.shutdown();
    }
}

#[tokio::test]
async fn transfer_mare_cu_control_de_flux() {
    // Peste fereastra initiala de 500 de celule. Fara SENDME-uri, transferul se
    // opreste pe la ~240 KB si testul expira.
    let tinta = server_ecou().await;
    let relee = vec![
        porneste(1).await,
        porneste_cu(2, politica_test(tinta.port())).await,
    ];
    let mut c = tokio::time::timeout(Duration::from_secs(10), circuit(&relee, 2))
        .await
        .unwrap();

    let id = c.begin("127.0.0.1", tinta.port()).await.unwrap();

    // 400 KB depaseste fereastra initiala (500 celule x 487 B ~ 243 KB), deci
    // transferul nu se poate incheia fara SENDME-uri functionale.
    const N: usize = 400 * 1024;
    const BUCATA: usize = 16 * 1024;
    let date: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();

    // Scriem si citim intercalat, cum face un proxy real. Un client care ar
    // scrie tot si abia apoi ar citi e un client care nu consuma, si releul il
    // deconecteaza pe buna dreptate — vezi `coada_plina_inchide_streamul`.
    let mut trimis = 0usize;
    let mut primit = 0usize;
    while primit < N {
        if trimis < N {
            let capat = (trimis + BUCATA).min(N);
            c.write_stream(id, &date[trimis..capat]).await.unwrap();
            trimis = capat;
        }
        let bucata = tokio::time::timeout(Duration::from_secs(20), c.read_stream(id))
            .await
            .expect("transferul nu trebuie sa se blocheze")
            .unwrap()
            .expect("stream deschis");
        assert_eq!(
            &bucata[..],
            &date[primit..primit + bucata.len()],
            "date corupte la offset {primit}"
        );
        primit += bucata.len();
    }
    assert_eq!(primit, N);
    assert!(
        primit > 243 * 1024,
        "transferul trebuie sa depaseasca fereastra initiala"
    );

    for r in relee {
        r.handle.shutdown();
    }
}

#[tokio::test]
async fn politica_de_exit_refuza_portul_nepermis() {
    let tinta = server_ecou().await;
    let relee = vec![porneste_cu(1, politica_test(tinta.port())).await];
    let mut c = circuit(&relee, 1).await;

    // Alt port decat cel permis.
    let r = c.begin("127.0.0.1", tinta.port().wrapping_add(1)).await;
    assert!(r.is_err(), "portul nepermis trebuie refuzat");
    for r in relee {
        r.handle.shutdown();
    }
}

#[tokio::test]
async fn un_releu_care_nu_e_exit_nu_deschide_streamuri() {
    let tinta = server_ecou().await;
    let relee = vec![porneste(1).await];
    let mut c = circuit(&relee, 1).await;

    let r = tokio::time::timeout(Duration::from_secs(5), c.begin("127.0.0.1", tinta.port())).await;
    assert!(
        r.is_err() || r.unwrap().is_err(),
        "un releu fara politica de exit nu are voie sa deschida stream-uri"
    );
    for r in relee {
        r.handle.shutdown();
    }
}

#[tokio::test]
async fn streamuri_multiple_pe_acelasi_circuit() {
    let tinta = server_ecou().await;
    let relee = vec![
        porneste(1).await,
        porneste_cu(2, politica_test(tinta.port())).await,
    ];
    let mut c = tokio::time::timeout(Duration::from_secs(10), circuit(&relee, 2))
        .await
        .unwrap();

    let mut ids = Vec::new();
    for _ in 0..4 {
        ids.push(c.begin("127.0.0.1", tinta.port()).await.unwrap());
    }
    // Toate trebuie sa aiba numere distincte.
    let mut sortate = ids.clone();
    sortate.sort();
    sortate.dedup();
    assert_eq!(sortate.len(), ids.len());

    for (i, id) in ids.iter().enumerate() {
        let m = format!("stream {i}");
        c.write_stream(*id, m.as_bytes()).await.unwrap();
        let r = tokio::time::timeout(Duration::from_secs(10), c.read_stream(*id))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(r, m.as_bytes(), "stream-urile s-au amestecat");
    }

    for r in relee {
        r.handle.shutdown();
    }
}

/// Un server care trimite un bloc mare imediat ce se conecteaza cineva.
async fn server_torent(octeti: usize) -> SocketAddr {
    use tokio::io::AsyncWriteExt;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let date: Vec<u8> = (0..octeti).map(|i| (i % 251) as u8).collect();
                let _ = s.write_all(&date).await;
                let _ = s.flush().await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn client_lent_nu_pierde_date() {
    // Regresia care a stat la baza unei curse de sincronizare.
    //
    // Destinatia trimite cat de repede poate, clientul citeste incet. Varianta
    // veche citea din socket fara oprire si tinea datele intr-o coada; coada se
    // umplea la ~124 KB si stream-ul se inchidea. Aparea doar cand clientul era
    // mai lent decat destinatia, deci depindea de viteza masinii — acelasi test
    // trecea cu ML-KEM activat si pica fara.
    //
    // Acum task-ul de citire cere un permis inainte de fiecare citire, iar
    // permisele vin doar din SENDME-urile clientului. Daca clientul incetineste,
    // incetineste si citirea din socket, si presiunea ajunge la server prin
    // fereastra TCP.
    const N: usize = 300 * 1024;
    let tinta = server_torent(N).await;
    let relee = vec![
        porneste(1).await,
        porneste_cu(2, politica_test(tinta.port())).await,
    ];
    let mut c = tokio::time::timeout(Duration::from_secs(10), circuit(&relee, 2))
        .await
        .unwrap();

    let id = c.begin("127.0.0.1", tinta.port()).await.unwrap();

    let asteptat: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();
    let mut primit = 0usize;
    let mut pas = 0usize;

    while primit < N {
        let bucata = tokio::time::timeout(Duration::from_secs(30), c.read_stream(id))
            .await
            .expect("transferul nu trebuie sa se blocheze")
            .unwrap()
            .expect("stream-ul nu are voie sa se inchida pentru ca suntem lenti");
        assert_eq!(
            &bucata[..],
            &asteptat[primit..primit + bucata.len()],
            "date pierdute sau reordonate la offset {primit}"
        );
        primit += bucata.len();

        // Incetinim deliberat la fiecare 50 de bucati.
        pas += 1;
        if pas % 50 == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    assert_eq!(primit, N);

    for r in relee {
        r.handle.shutdown();
    }
}

#[tokio::test]
async fn un_nume_care_rezolva_la_localhost_e_refuzat() {
    // Gaura pe care politica de iesire nu o putea prinde singura: ea vede doar
    // literalele din cerere. Un domeniu care indica spre 127.0.0.1 trecea de ea.
    // Acum adresa se verifica si dupa rezolvare.
    let tinta = server_ecou().await;
    // Exit fara `--permite-adrese-private`, dar cu portul permis.
    let relee = vec![porneste_cu(1, ExitPolicy::allow_ports(&[tinta.port()])).await];
    let mut c = circuit(&relee, 1).await;

    // "localhost" e un nume, nu un literal, deci trece de prima verificare.
    let r = tokio::time::timeout(Duration::from_secs(10), c.begin("localhost", tinta.port())).await;
    assert!(
        r.is_err() || r.unwrap().is_err(),
        "un nume care rezolva la loopback trebuie refuzat dupa rezolvare"
    );

    for r in relee {
        r.handle.shutdown();
    }
}
