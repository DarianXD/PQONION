//! Rendezvous complet, prin socket-uri reale.
//!
//! Ultima bucata de protocol care rula doar in proces. Aici clientul si
//! serviciul ascuns ajung sa comunice fara sa se cunoasca adresele:
//!
//! ```text
//!   serviciu ──circuit──> IP    ESTABLISH_INTRO
//!   client   ──circuit──> RP    ESTABLISH_RENDEZVOUS (cookie)
//!   client   ──circuit──> IP    INTRODUCE1  (criptat catre serviciu)
//!   IP       ──circuit──> serv  INTRODUCE2
//!   serv     ──circuit──> RP    RENDEZVOUS1 (cookie + handshake)
//!   RP       ──circuit──> cli   RENDEZVOUS2 (doar handshake)
//!   ambele                      hop virtual criptat cu CGO
//! ```
//!
//! Punctul de rendezvous vede doua circuite si un cookie. Punctul de introducere
//! vede o cerere pe care nu o poate citi. Niciunul nu stie cine sunt partile.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pqo_crypto::cgo::{ClientCircuit, Outbound, RelayCircuit};
use pqo_crypto::kem::{Hybrid, Kem, X25519Kem};
use pqo_crypto::sig::{Ed25519, Sig};
use pqo_crypto::{
    client_finish, client_init, ntor, server_respond, RelayKeys, RelayPublic, Variant,
};
use pqo_dirproto::dirreq::DirStore;
use pqo_hs::desc::IntroPoint;
use pqo_hs::rend::{auth_key_id, new_cookie, IntroPayload, Introduce};
use pqo_relay::stream::ExitPolicy;
use pqo_relay_io::client::Circuit;
use pqo_relay_io::node::{spawn, NodeConfig};
use rand_core::OsRng;

type K = Hybrid<X25519Kem, X25519Kem>;
type S = Ed25519;

const AD: u8 = 3;

struct Nod {
    addr: SocketAddr,
    public: RelayPublic,
    handle: pqo_relay_io::NodeHandle,
}

async fn porneste(id: u8) -> Nod {
    let mut rng = OsRng;
    let keys = RelayKeys::<K>::generate([id; ntor::ID_LEN], Variant::Transitional, &mut rng);
    let public = keys.public();
    let (sk, pk) = S::keygen(&mut rng);
    let handle = spawn::<K, S>(NodeConfig {
        circuit_keys: keys,
        id_sk: Arc::new(sk),
        id_pk: pk,
        listen: "127.0.0.1:0".parse().unwrap(),
        exit_policy: ExitPolicy::reject_all(),
        dir_store: Arc::new(std::sync::Mutex::new(DirStore::new())),
        hs_store: None,
        metrici: Default::default(),
        transport: std::sync::Arc::new(pqo_relay_io::node::Transport::Plaintext),
    })
    .await
    .expect("releul trebuie sa porneasca");
    Nod {
        addr: handle.addr(),
        public,
        handle,
    }
}

async fn circuit_catre(n: &Nod) -> Circuit<tokio::net::TcpStream> {
    let (sk, pk) = S::keygen(&mut OsRng);
    Circuit::connect::<K, S>(n.addr, &n.public, Variant::Transitional, Arc::new(sk), &pk)
        .await
        .expect("circuit")
}

/// Cele doua capete ale unui rendezvous reusit.
struct Tunel {
    client_circ: Circuit<tokio::net::TcpStream>,
    client_cgo: ClientCircuit,
    client_seed: pqo_crypto::KeySeed,
    serv_circ: Circuit<tokio::net::TcpStream>,
    serv_cgo: RelayCircuit,
    serv_seed: pqo_crypto::KeySeed,
}

/// Ruleaza fluxul complet si intoarce tunelul deschis.
async fn rendezvous(ip: &Nod, rp: &Nod) -> Tunel {
    let mut rng = OsRng;

    // --- Serviciul isi pregateste cheile si se anunta la punctul de introducere ---
    // Cheia de handshake a serviciului. Serviciul e in rol de RELEU pe hop-ul
    // virtual, deci foloseste `RelayKeys`.
    let hs_keys = RelayKeys::<K>::generate([0xAA; ntor::ID_LEN], Variant::Transitional, &mut rng);
    let hs_public = hs_keys.public();
    // Cheia separata cu care clientul cripteaza corpul INTRODUCE.
    let (intro_dk, intro_ek) = K::keygen(&mut rng);
    let (auth_sk, auth_pk) = S::keygen(&mut rng);

    let mut serv_la_ip = circuit_catre(ip).await;
    serv_la_ip
        .establish_intro::<S>(&auth_sk, &auth_pk)
        .await
        .expect("ESTABLISH_INTRO");

    // --- Clientul stabileste un punct de rendezvous ---
    let cookie = new_cookie(&mut rng);
    let mut cli_la_rp = circuit_catre(rp).await;
    cli_la_rp
        .establish_rendezvous(&cookie)
        .await
        .expect("ESTABLISH_RENDEZVOUS");

    // --- Clientul trimite INTRODUCE1 prin punctul de introducere ---
    let ip_desc = IntroPoint {
        relay_id: ip.public.id,
        onion_x25519: intro_ek[..32].try_into().unwrap(),
        onion_kem: Some(intro_ek[32..].to_vec()),
        svc_x25519: [0u8; 32],
        auth_key: auth_pk.clone(),
    };
    let (state, hs_client) =
        client_init::<K>(&hs_public, Variant::Transitional, &mut rng).expect("client_init");
    let payload = IntroPayload {
        cookie,
        rp_relay_id: rp.public.id,
        rp_address: rp.addr.ip().to_string(),
        rp_port: rp.addr.port(),
        handshake: hs_client,
    };
    let intro = Introduce::seal::<K>(&ip_desc, &payload, &mut rng).expect("seal");

    // Corpul de pe fir incepe cu identificatorul cheii, ca releul sa stie unde
    // sa retransmita. Restul e criptat catre serviciu.
    let mut corp = auth_key_id(&auth_pk).to_vec();
    corp.extend_from_slice(&intro.encode());

    let mut cli_la_ip = circuit_catre(ip).await;
    cli_la_ip.send_introduce(corp).await.expect("INTRODUCE1");

    // --- Serviciul primeste INTRODUCE2 si deschide handshake-ul ---
    let primit = tokio::time::timeout(Duration::from_secs(10), serv_la_ip.wait_introduce2())
        .await
        .expect("INTRODUCE2 nu trebuie sa expire")
        .expect("INTRODUCE2");
    assert!(primit.len() > 32);
    let intro2 = Introduce::parse(&primit[32..]).expect("parse INTRODUCE2");
    let payload = intro2.open::<K>(&intro_dk).expect("doar serviciul poate citi");
    assert_eq!(payload.cookie, cookie);

    let (hs_server, res_serv) =
        server_respond::<K>(&hs_keys, &payload.handshake, &mut rng).expect("server_respond");

    // --- Serviciul ajunge la punctul de rendezvous ---
    let mut serv_la_rp = circuit_catre(rp).await;
    serv_la_rp
        .send_rendezvous1(&payload.cookie, &hs_server)
        .await
        .expect("RENDEZVOUS1");

    // --- Clientul finalizeaza ---
    let r2 = tokio::time::timeout(Duration::from_secs(10), cli_la_rp.wait_rendezvous2())
        .await
        .expect("RENDEZVOUS2 nu trebuie sa expire")
        .expect("RENDEZVOUS2");
    let res_cli = client_finish::<K>(state, &r2).expect("client_finish");

    assert_eq!(
        res_cli.key_seed.expand_vec(160),
        res_serv.key_seed.expand_vec(160),
        "cele doua capete trebuie sa derive acelasi material de cheie"
    );

    // Hop-ul virtual: serviciul e RELEU, clientul e CLIENT. Vezi asimetria CGO.
    let mut client_cgo = ClientCircuit::new();
    client_cgo.add_hop(&res_cli.key_seed);
    let serv_cgo = RelayCircuit::new(&res_serv.key_seed);

    // Pastram si semintele: testele care folosesc `Tunnel` isi construiesc
    // propria stare din ele.
    let client_seed = pqo_crypto::KeySeed::new(*res_cli.key_seed.as_bytes());
    let serv_seed = pqo_crypto::KeySeed::new(*res_serv.key_seed.as_bytes());

    Tunel {
        client_circ: cli_la_rp,
        client_cgo,
        client_seed,
        serv_circ: serv_la_rp,
        serv_cgo,
        serv_seed,
    }
}

impl Tunel {
    /// Client -> serviciu, prin hop-ul virtual si punctul de rendezvous.
    async fn client_trimite(&mut self, corp: &[u8; pqo_crypto::cgo::LEN_XR]) -> Vec<u8> {
        let cell = self.client_cgo.encrypt_outbound(1, AD, corp).unwrap();
        self.client_circ.send_tunnel(cell.as_slice()).await.unwrap();

        let primit = tokio::time::timeout(Duration::from_secs(10), self.serv_circ.recv_tunnel())
            .await
            .expect("celula nu trebuie sa expire")
            .unwrap();
        let c: &[u8; pqo_crypto::cgo::MSG_LEN] = primit.as_slice().try_into().unwrap();
        match self.serv_cgo.process_outbound(AD, c) {
            Outbound::Recognized(b) => b.to_vec(),
            Outbound::Forward(_) => panic!("serviciul trebuia sa recunoasca celula"),
        }
    }

    /// Serviciu -> client.
    async fn serviciu_trimite(&mut self, corp: &[u8; pqo_crypto::cgo::LEN_XR]) -> Vec<u8> {
        let cell = self.serv_cgo.originate_inbound(AD, corp);
        self.serv_circ.send_tunnel(cell.as_slice()).await.unwrap();

        let primit = tokio::time::timeout(Duration::from_secs(10), self.client_circ.recv_tunnel())
            .await
            .expect("celula nu trebuie sa expire")
            .unwrap();
        let c: &[u8; pqo_crypto::cgo::MSG_LEN] = primit.as_slice().try_into().unwrap();
        let (hop, b) = self.client_cgo.decrypt_inbound(AD, c).unwrap();
        assert_eq!(hop, 1);
        b.to_vec()
    }
}

fn corp(v: u8) -> [u8; pqo_crypto::cgo::LEN_XR] {
    let mut b = [0u8; pqo_crypto::cgo::LEN_XR];
    for (i, x) in b.iter_mut().enumerate() {
        *x = v.wrapping_add((i % 251) as u8);
    }
    b
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn rendezvous_complet_prin_retea() {
    let ip = porneste(1).await;
    let rp = porneste(2).await;
    let t = tokio::time::timeout(Duration::from_secs(20), rendezvous(&ip, &rp))
        .await
        .expect("rendezvous-ul nu trebuie sa expire");
    drop(t);
    ip.handle.shutdown();
    rp.handle.shutdown();
}

#[tokio::test]
async fn trafic_bidirectional_prin_tunel() {
    let ip = porneste(1).await;
    let rp = porneste(2).await;
    let mut t = tokio::time::timeout(Duration::from_secs(20), rendezvous(&ip, &rp))
        .await
        .expect("rendezvous");

    for runda in 0..10u8 {
        let m = corp(runda);
        assert_eq!(t.client_trimite(&m).await, m.to_vec(), "runda {runda}");

        let r = corp(runda.wrapping_add(128));
        assert_eq!(t.serviciu_trimite(&r).await, r.to_vec(), "runda {runda}");
    }

    ip.handle.shutdown();
    rp.handle.shutdown();
}

#[tokio::test]
async fn punctul_de_rendezvous_poate_fi_acelasi_cu_cel_de_introducere() {
    // Un releu poate juca ambele roluri simultan, pe circuite diferite.
    let n = porneste(1).await;
    let t = tokio::time::timeout(Duration::from_secs(20), rendezvous(&n, &n))
        .await
        .expect("rendezvous");
    drop(t);
    n.handle.shutdown();
}

#[tokio::test]
async fn cookie_gresit_nu_imperecheaza() {
    let rp = porneste(1).await;
    let mut cli = circuit_catre(&rp).await;
    cli.establish_rendezvous(&[1u8; 20]).await.unwrap();

    // Serviciul soseste cu alt cookie: nu se imperecheaza nimic.
    let mut serv = circuit_catre(&rp).await;
    serv.send_rendezvous1(&[2u8; 20], b"handshake").await.unwrap();

    let r = tokio::time::timeout(Duration::from_secs(3), cli.wait_rendezvous2()).await;
    assert!(r.is_err(), "clientul nu trebuie sa primeasca nimic");
    rp.handle.shutdown();
}

#[tokio::test]
async fn introducere_catre_cheie_neinregistrata_e_refuzata() {
    let ip = porneste(1).await;
    let mut cli = circuit_catre(&ip).await;

    let mut corp = [0xFFu8; 32].to_vec();
    corp.extend_from_slice(&[0u8; 100]);
    let r = tokio::time::timeout(Duration::from_secs(5), cli.send_introduce(corp)).await;
    assert!(
        r.is_err() || r.unwrap().is_err(),
        "o cheie neinregistrata trebuie refuzata"
    );
    ip.handle.shutdown();
}

#[tokio::test]
async fn punctul_de_introducere_nu_poate_citi_cererea() {
    // Releul retransmite corpul neschimbat; doar cine are cheia de decapsulare
    // il poate deschide.
    let mut rng = OsRng;
    let (dk, ek) = K::keygen(&mut rng);
    let (_ask, apk) = S::keygen(&mut rng);
    let ipd = IntroPoint {
        relay_id: [1; 32],
        onion_x25519: ek[..32].try_into().unwrap(),
        onion_kem: Some(ek[32..].to_vec()),
        svc_x25519: [0u8; 32],
        auth_key: apk,
    };
    let p = IntroPayload {
        cookie: [7u8; 20],
        rp_relay_id: [9u8; 32],
        rp_address: "127.0.0.1".into(),
        rp_port: 9001,
        handshake: vec![1u8; 100],
    };
    let m = Introduce::seal::<K>(&ipd, &p, &mut rng).unwrap();

    // O cheie straina nu deschide nimic.
    let (alta, _ek2) = K::keygen(&mut rng);
    assert!(m.open::<K>(&alta).is_err());
    assert_eq!(m.open::<K>(&dk).unwrap(), p);
}

#[tokio::test]
async fn caderea_unui_capat_inchide_tunelul() {
    let ip = porneste(1).await;
    let rp = porneste(2).await;
    let mut t = tokio::time::timeout(Duration::from_secs(20), rendezvous(&ip, &rp))
        .await
        .expect("rendezvous");

    // O runda ca sa confirmam ca tunelul chiar merge.
    let m = corp(1);
    assert_eq!(t.client_trimite(&m).await, m.to_vec());

    // Clientul dispare; serviciul nu trebuie sa ramana blocat la nesfarsit.
    drop(t.client_circ);
    let r = tokio::time::timeout(Duration::from_secs(5), t.serv_circ.recv_tunnel()).await;
    assert!(
        r.is_err() || r.unwrap().is_err(),
        "serviciul trebuie sa observe caderea"
    );

    ip.handle.shutdown();
    rp.handle.shutdown();
}

// ---------------------------------------------------------------------------
// Conexiune completa la un serviciu ascuns, cu stream-uri peste tunel
// ---------------------------------------------------------------------------

use pqo_relay::stream::{StreamAction, StreamTable};
use pqo_relay_io::tunnel::Tunnel;
use pqo_wire::{RelayCmd, RelayMessage, StreamId};

/// Un server care intoarce ce primeste.
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
async fn conexiune_completa_la_serviciu_ascuns() {
    // Fluxul pe care il vede un utilizator: cere o adresa, primeste octetii
    // serviciului. Intre timp trec doua circuite, un rendezvous si un tunel.
    let tinta = server_ecou().await;
    let ip = porneste(1).await;
    let rp = porneste(2).await;

    let t = tokio::time::timeout(Duration::from_secs(20), rendezvous(&ip, &rp))
        .await
        .expect("rendezvous");

    // Cele doua capete devin tuneluri care transporta mesaje relay.
    let seed_cli = t.client_seed;
    let seed_serv = t.serv_seed;
    let mut cli = Tunnel::client(t.client_circ, &seed_cli);
    let mut serv = Tunnel::service(t.serv_circ, &seed_serv);

    // Serviciul isi deschide o tabela de stream-uri catre tinta lui locala.
    // Politica permite exact portul serverului si adrese private: e chiar
    // serviciul pe care il expune, nu o iesire generala in internet.
    let mut tabela = StreamTable::new(
        ExitPolicy::allow_ports(&[tinta.port()]).allow_private_for_testing(),
    );

    // --- Clientul cere o conexiune ---
    let id = StreamId(1);
    let begin = RelayMessage::new(
        RelayCmd::Begin,
        id,
        pqo_wire::stream::Begin {
            address: "127.0.0.1".into(),
            port: tinta.port(),
        }
        .encode()
        .unwrap(),
    )
    .unwrap();
    cli.send(&begin).await.unwrap();

    // --- Serviciul primeste si deschide conexiunea locala ---
    let m = tokio::time::timeout(Duration::from_secs(10), serv.recv())
        .await
        .expect("BEGIN nu trebuie sa expire")
        .unwrap();
    assert_eq!(m.cmd, RelayCmd::Begin);

    let actiuni = tabela.on_begin(m.stream, &m.body).unwrap();
    let (adresa, port) = match &actiuni[0] {
        StreamAction::Connect { address, port, .. } => (address.clone(), *port),
        a => panic!("asteptam Connect, am primit {a:?}"),
    };
    let mut sock = tokio::net::TcpStream::connect((adresa.as_str(), port))
        .await
        .expect("conexiune locala");

    for a in tabela.on_connected(m.stream, [127, 0, 0, 1]) {
        if let StreamAction::ToClient { stream, cmd, body } = a {
            serv.send(&RelayMessage::new(cmd, stream, body).unwrap())
                .await
                .unwrap();
        }
    }

    // --- Clientul primeste confirmarea ---
    let m = tokio::time::timeout(Duration::from_secs(10), cli.recv())
        .await
        .expect("CONNECTED nu trebuie sa expire")
        .unwrap();
    assert_eq!(m.cmd, RelayCmd::Connected);

    // --- Date dus-intors ---
    let mesaj = b"salut printr-un serviciu ascuns";
    cli.send(&RelayMessage::new(RelayCmd::Data, id, mesaj.to_vec()).unwrap())
        .await
        .unwrap();

    let m = serv.recv().await.unwrap();
    assert_eq!(m.cmd, RelayCmd::Data);
    for a in tabela.on_data(m.stream, &m.body).unwrap() {
        if let StreamAction::Write { data, .. } = a {
            use tokio::io::AsyncWriteExt;
            sock.write_all(&data).await.unwrap();
        }
    }

    // Serverul raspunde; serviciul trimite inapoi prin tunel.
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(10), sock.read(&mut buf))
        .await
        .expect("ecoul nu trebuie sa expire")
        .unwrap();
    for a in tabela.data_to_client(id, buf[..n].to_vec()) {
        if let StreamAction::ToClient { stream, cmd, body } = a {
            serv.send(&RelayMessage::new(cmd, stream, body).unwrap())
                .await
                .unwrap();
        }
    }

    let m = tokio::time::timeout(Duration::from_secs(10), cli.recv())
        .await
        .expect("raspunsul nu trebuie sa expire")
        .unwrap();
    assert_eq!(m.cmd, RelayCmd::Data);
    assert_eq!(m.body, mesaj, "octetii nu au ajuns intacti");

    // --- Cat dureaza un dus-intors prin tunelul deja deschis ---
    //
    // Prag larg, ca sa prinda o regresie catastrofala — un dus-intors care ar
    // trece de 40 ms din cauza interactiunii dintre algoritmul Nagle si
    // confirmarile intarziate.
    //
    // **Ce NU acopera acest test.** Configuratia de aici are circuite de un
    // singur hop, deci gruparea celulelor la scriere ascunde problema chiar si
    // cand `TCP_NODELAY` lipseste. Am verificat: scotand optiunea, testul trece
    // in continuare. Defectul real s-a manifestat pe calea completa, cu sase
    // relee, si a fost masurat de `cargo run --release -p pqo-bin --example
    // latenta` — 88 ms per dus-intors, de zece ori mai mult decat construirea
    // unui circuit intreg.
    //
    // Exemplul e detectorul; acesta e doar o plasa de siguranta.
    let mut durate = Vec::new();
    for _ in 0..5 {
        let t = std::time::Instant::now();
        cli.send(&RelayMessage::new(RelayCmd::Data, id, mesaj.to_vec()).unwrap())
            .await
            .unwrap();
        let m = tokio::time::timeout(Duration::from_secs(10), serv.recv())
            .await
            .expect("cererea nu trebuie sa expire")
            .unwrap();
        serv.send(&RelayMessage::new(RelayCmd::Data, m.stream, m.body).unwrap())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), cli.recv())
            .await
            .expect("raspunsul nu trebuie sa expire")
            .unwrap();
        durate.push(t.elapsed());
    }
    durate.sort();
    let mediana = durate[durate.len() / 2];
    assert!(
        mediana < Duration::from_millis(20),
        "un dus-intors prin tunel a durat {mediana:?}. Peste ~40 ms inseamna ca \
         lipseste TCP_NODELAY de pe un capat sau ca celulele se scriu separat."
    );

    ip.handle.shutdown();
    rp.handle.shutdown();
}

#[tokio::test]
async fn tunelul_detecteaza_celule_modificate() {
    // Un punct de rendezvous ostil schimba un octet. Serviciul nu trebuie sa
    // accepte celula: hop-ul virtual are propria autentificare.
    let ip = porneste(1).await;
    let rp = porneste(2).await;
    let t = tokio::time::timeout(Duration::from_secs(20), rendezvous(&ip, &rp))
        .await
        .expect("rendezvous");

    let mut cgo = ClientCircuit::new();
    cgo.add_hop(&t.client_seed);
    let mut serv_cgo = RelayCircuit::new(&t.serv_seed);

    let corp = corp(0x5A);
    let mut cell = cgo.encrypt_outbound(1, AD, &corp).unwrap();
    cell[200] ^= 0x01;

    match serv_cgo.process_outbound(AD, &cell) {
        Outbound::Forward(_) => {}
        Outbound::Recognized(_) => panic!("modificarea nu a fost detectata"),
    }

    ip.handle.shutdown();
    rp.handle.shutdown();
}

#[tokio::test]
async fn nu_poti_ocupa_slotul_cu_cheia_altcuiva() {
    // Cheia de autentificare a unui serviciu e PUBLICA: apare in descriptorul
    // lui. Fara semnatura, oricine il citeste ar putea sa se inregistreze primul
    // la punctul de introducere si sa faca serviciul inaccesibil.
    let ip = porneste(1).await;
    let mut rng = OsRng;

    // Cheia victimei, asa cum ar aparea in descriptor.
    let (_victima_sk, victima_pk) = S::keygen(&mut rng);
    // Atacatorul are cheia publica, dar nu si privata.
    let (atac_sk, _atac_pk) = S::keygen(&mut rng);

    let mut c = circuit_catre(&ip).await;
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        // Semneaza cu cheia lui, dar pretinde cheia victimei.
        c.establish_intro::<S>(&atac_sk, &victima_pk),
    )
    .await;
    assert!(
        r.is_err() || r.unwrap().is_err(),
        "o semnatura care nu corespunde cheii trebuie refuzata"
    );

    ip.handle.shutdown();
}

#[tokio::test]
async fn semnatura_corecta_e_acceptata() {
    let ip = porneste(1).await;
    let (sk, pk) = S::keygen(&mut OsRng);
    let mut c = circuit_catre(&ip).await;
    tokio::time::timeout(Duration::from_secs(10), c.establish_intro::<S>(&sk, &pk))
        .await
        .expect("nu trebuie sa expire")
        .expect("semnatura corecta trebuie acceptata");
    ip.handle.shutdown();
}
