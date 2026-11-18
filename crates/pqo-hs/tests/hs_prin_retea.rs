//! Serviciul ascuns, prin retea reala.
//!
//! Pana acum `pqo-hs` rula doar in proces: descriptorii treceau din mana in mana
//! intre structuri. Aici trec prin socket-uri, circuite si celule criptate.
//!
//! ```text
//!   serviciu ──circuit──> HSDir    (HS_UPLOAD)
//!   client   ──circuit──> HSDir    (HS_FETCH)
//!   client verifica ca hash(cheia master) == adresa
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pqo_crypto::kem::{Hybrid, X25519Kem};
use pqo_crypto::sig::{Ed25519, Sig};
use pqo_crypto::{ntor, RelayKeys, RelayPublic, Variant};
use pqo_dirproto::dirreq::{DirRequest, DirStatus, DirStore};
use pqo_hs::desc::{Descriptor, IntroPoint};
use pqo_hs::hsdir::SharedDescStore;
use pqo_hs::publish::{fetch_targets, PublishPlan, ServiceKeys};
use pqo_hs::OnionAddress;
use pqo_relay::stream::ExitPolicy;
use pqo_relay_io::client::Circuit;
use pqo_relay_io::node::{spawn, NodeConfig};
use rand_core::OsRng;

type K = Hybrid<X25519Kem, X25519Kem>;
type S = Ed25519;

const SRV: [u8; 32] = [0x5A; 32];
const ACUM: u64 = 1_700_000_000;

struct Nod {
    addr: SocketAddr,
    public: RelayPublic,
    fp: [u8; 32],
    hs: Arc<SharedDescStore>,
    handle: pqo_relay_io::NodeHandle,
}

async fn porneste_hsdir(id: u8) -> Nod {
    let mut rng = OsRng;
    let keys = RelayKeys::<K>::generate([id; ntor::ID_LEN], Variant::Transitional, &mut rng);
    let public = keys.public();
    let fp = public.id;
    let (sk, pk) = S::keygen(&mut rng);
    let hs = Arc::new(SharedDescStore::new());

    let handle = spawn::<K, S>(NodeConfig {
        circuit_keys: keys,
        id_sk: Arc::new(sk),
        id_pk: pk,
        listen: "127.0.0.1:0".parse().unwrap(),
        exit_policy: ExitPolicy::reject_all(),
        dir_store: Arc::new(std::sync::Mutex::new(DirStore::new())),
        hs_store: Some(hs.clone()),
        metrici: Default::default(),
        transport: std::sync::Arc::new(pqo_relay_io::node::Transport::Plaintext),
    })
    .await
    .expect("HSDir pornit");

    Nod {
        addr: handle.addr(),
        public,
        fp,
        hs,
        handle,
    }
}

async fn circuit_catre(n: &Nod) -> Circuit<tokio::net::TcpStream> {
    let (sk, pk) = S::keygen(&mut OsRng);
    Circuit::connect::<K, S>(
        n.addr,
        &n.public,
        Variant::Transitional,
        Arc::new(sk),
        &pk,
    )
    .await
    .expect("circuit")
}

fn intro(n: u8) -> IntroPoint {
    IntroPoint {
        relay_id: [n; 32],
        onion_x25519: [n.wrapping_add(1); 32],
        onion_kem: None,
        svc_x25519: [0u8; 32],
        auth_key: vec![n.wrapping_add(2); 32],
    }
}

#[tokio::test]
async fn serviciul_publica_si_clientul_gaseste() {
    // Testul central: nimic nu trece prin memorie partajata intre serviciu si
    // client. Doar prin socket-uri.
    let noduri: Vec<Nod> = {
        let mut v = Vec::new();
        for i in 1..=6u8 {
            v.push(porneste_hsdir(i).await);
        }
        v
    };
    let fps: Vec<[u8; 32]> = noduri.iter().map(|n| n.fp).collect();

    // --- Serviciul isi calculeaza planul si publica ---
    let keys = ServiceKeys::from_seed::<S>([0x11; 32]);
    let adresa_text = keys.address().to_string();

    let plan = PublishPlan::build::<S>(
        &keys,
        ACUM,
        1,
        &[intro(1), intro(2), intro(3)],
        &fps,
        &SRV,
    )
    .expect("plan de publicare");
    assert_eq!(plan.targets.len(), 2, "doua perioade");

    let mut incarcate = 0;
    for t in &plan.targets {
        for fp in &t.nodes {
            let nod = noduri.iter().find(|n| &n.fp == fp).expect("nod cunoscut");
            let mut c = circuit_catre(nod).await;
            let st = tokio::time::timeout(
                Duration::from_secs(10),
                c.dir_publish(DirRequest::HsUpload(t.document.as_bytes().to_vec())),
            )
            .await
            .expect("incarcarea nu trebuie sa expire")
            .expect("raspuns");
            assert_eq!(st, DirStatus::Ok, "HSDir a refuzat descriptorul");
            incarcate += 1;
        }
    }
    assert!(incarcate >= 6, "prea putine incarcari: {incarcate}");

    // --- Clientul porneste doar de la sirul adresei ---
    let addr = OnionAddress::parse(&adresa_text).expect("adresa valida");
    let cautari = fetch_targets(&addr, ACUM, &fps, &SRV);

    let mut gasit = None;
    'cautare: for (bid, nod_uri) in &cautari {
        for fp in nod_uri {
            let nod = noduri.iter().find(|n| &n.fp == fp).unwrap();
            let mut c = circuit_catre(nod).await;
            let r = tokio::time::timeout(
                Duration::from_secs(10),
                c.dir_request(DirRequest::HsFetch(*bid)),
            )
            .await
            .expect("cautarea nu trebuie sa expire")
            .expect("raspuns");
            if r.status == DirStatus::Ok {
                gasit = Some(r.body);
                break 'cautare;
            }
        }
    }
    let doc = String::from_utf8(gasit.expect("descriptorul trebuie gasit")).unwrap();

    // --- Verificarea completa la client ---
    let d = Descriptor::parse_and_verify::<S>(&doc).expect("strat exterior valid");
    let inner = d.open_inner::<S>(&addr).expect("strat interior");
    assert_eq!(inner.intro_points.len(), 3);
    assert!(
        addr.matches::<S>(&inner.master_key),
        "hash-ul cheii master trebuie sa fie chiar adresa"
    );

    for n in noduri {
        n.handle.shutdown();
    }
}

#[tokio::test]
async fn hsdirul_refuza_un_descriptor_stricat() {
    let nod = porneste_hsdir(1).await;
    let keys = ServiceKeys::from_seed::<S>([0x22; 32]);
    let plan =
        PublishPlan::build::<S>(&keys, ACUM, 1, &[intro(1)], &[nod.fp], &SRV).unwrap();

    // Modificam un octet: semnatura stratului exterior nu mai verifica.
    let stricat = plan.targets[0].document.replace("revision 1", "revision 2");
    assert_ne!(stricat, plan.targets[0].document);

    let mut c = circuit_catre(&nod).await;
    let st = tokio::time::timeout(
        Duration::from_secs(10),
        c.dir_publish(DirRequest::HsUpload(stricat.into_bytes())),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(st, DirStatus::Rejected, "descriptorul stricat a fost acceptat");
    assert!(nod.hs.is_empty());

    nod.handle.shutdown();
}

#[tokio::test]
async fn un_atacator_nu_poate_suprascrie_slotul() {
    // Cineva care stie adresa incearca sa publice descriptorul lui la acelasi
    // index. HSDir-ul refuza: slotul e ocupat de alta cheie de perioada.
    let nod = porneste_hsdir(1).await;

    let victima = ServiceKeys::from_seed::<S>([0x33; 32]);
    let plan =
        PublishPlan::build::<S>(&victima, ACUM, 1, &[intro(1)], &[nod.fp], &SRV).unwrap();
    let doc_bun = plan.targets[0].document.clone();

    let mut c = circuit_catre(&nod).await;
    assert_eq!(
        c.dir_publish(DirRequest::HsUpload(doc_bun.as_bytes().to_vec()))
            .await
            .unwrap(),
        DirStatus::Ok
    );

    // Atacatorul are alta samanta, deci alta cheie de perioada.
    let atac = ServiceKeys::from_seed::<S>([0xFF; 32]);
    let mut fals = Descriptor::parse_and_verify::<S>(&doc_bun).unwrap();
    let fals_doc = Descriptor::build::<S>(
        atac.seed(),
        victima.address(),
        fals.period,
        u64::MAX,
        vec![intro(9)],
    );
    fals.revision = u64::MAX;

    if let Ok(fd) = fals_doc {
        let mut c2 = circuit_catre(&nod).await;
        let st = c2
            .dir_publish(DirRequest::HsUpload(fd.into_bytes()))
            .await
            .unwrap();
        assert_eq!(
            st,
            DirStatus::Rejected,
            "un atacator nu are voie sa ocupe slotul altcuiva"
        );
    }

    // Descriptorul original e intact.
    let mut c3 = circuit_catre(&nod).await;
    let r = c3
        .dir_request(DirRequest::HsFetch(plan.targets[0].blinded_id))
        .await
        .unwrap();
    assert_eq!(r.status, DirStatus::Ok);
    assert_eq!(String::from_utf8(r.body).unwrap(), doc_bun);

    nod.handle.shutdown();
}

#[tokio::test]
async fn descriptorul_lipsa_da_not_found() {
    let nod = porneste_hsdir(1).await;
    let mut c = circuit_catre(&nod).await;
    let r = c
        .dir_request(DirRequest::HsFetch([0xAB; 32]))
        .await
        .unwrap();
    assert_eq!(r.status, DirStatus::NotFound);
    nod.handle.shutdown();
}

#[tokio::test]
async fn un_releu_care_nu_e_hsdir_refuza() {
    // Fara `hs_store`, releul nu accepta si nu serveste descriptori de servicii.
    let mut rng = OsRng;
    let keys = RelayKeys::<K>::generate([9; ntor::ID_LEN], Variant::Transitional, &mut rng);
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
    .unwrap();

    let (csk, cpk) = S::keygen(&mut rng);
    let mut c = Circuit::connect::<K, S>(
        handle.addr(),
        &public,
        Variant::Transitional,
        Arc::new(csk),
        &cpk,
    )
    .await
    .unwrap();

    assert_eq!(
        c.dir_request(DirRequest::HsFetch([1u8; 32]))
            .await
            .unwrap()
            .status,
        DirStatus::NotFound
    );
    handle.shutdown();
}

#[tokio::test]
async fn releul_isi_publica_descriptorul() {
    // Cealalta bucla: un releu isi publica descriptorul, iar destinatarul il
    // valideaza inainte sa il stocheze.
    let store = Arc::new(std::sync::Mutex::new(DirStore::new()));
    let mut rng = OsRng;
    let keys = RelayKeys::<K>::generate([1; ntor::ID_LEN], Variant::Transitional, &mut rng);
    let public = keys.public();
    let (sk, pk) = S::keygen(&mut rng);

    let handle = spawn::<K, S>(NodeConfig {
        circuit_keys: keys,
        id_sk: Arc::new(sk),
        id_pk: pk,
        listen: "127.0.0.1:0".parse().unwrap(),
        exit_policy: ExitPolicy::reject_all(),
        dir_store: store.clone(),
        hs_store: None,
        metrici: Default::default(),
        transport: std::sync::Arc::new(pqo_relay_io::node::Transport::Plaintext),
    })
    .await
    .unwrap();

    // Un releu oarecare isi construieste si semneaza descriptorul.
    let (dsk, dpk) = S::keygen(&mut rng);
    let d = pqo_dirproto::netdoc::RelayDescriptor {
        identity: dpk,
        onion_x25519: [7u8; 32],
        onion_kem: None,
        address: "10.0.0.7".into(),
        or_port: 9001,
        bandwidth: 5000,
        exit_ports: Vec::new(),
        published: ACUM,
    };
    let doc = d.sign::<S>(&dsk);

    let (csk, cpk) = S::keygen(&mut rng);
    let mut c = Circuit::connect::<K, S>(
        handle.addr(),
        &public,
        Variant::Transitional,
        Arc::new(csk),
        &cpk,
    )
    .await
    .unwrap();

    assert_eq!(
        c.dir_publish(DirRequest::Publish(doc.as_bytes().to_vec()))
            .await
            .unwrap(),
        DirStatus::Ok
    );
    assert_eq!(store.lock().unwrap().len(), 1);

    // Se poate descarca inapoi.
    let r = c
        .dir_request(DirRequest::Descriptor(d.fingerprint()))
        .await
        .unwrap();
    assert_eq!(r.status, DirStatus::Ok);
    assert_eq!(String::from_utf8(r.body).unwrap(), doc);

    // Un descriptor stricat e refuzat, iar magazinul nu creste.
    let stricat = doc.replace("bandwidth 5000", "bandwidth 999999");
    assert_eq!(
        c.dir_publish(DirRequest::Publish(stricat.into_bytes()))
            .await
            .unwrap(),
        DirStatus::Rejected
    );
    assert_eq!(store.lock().unwrap().len(), 1);

    handle.shutdown();
}
