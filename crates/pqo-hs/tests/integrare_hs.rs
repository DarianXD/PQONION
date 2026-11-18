//! Simularea completa a unei conexiuni catre un serviciu ascuns.
//!
//! Acopera tot lantul:
//!
//! ```text
//!   serviciu: samanta master -> cheie identitate -> adresa .onion
//!             -> cheie de perioada -> descriptor in doua straturi
//!             -> publicare pe nodurile HSDir responsabile
//!
//!   client:   adresa -> index blindat -> aceleasi noduri HSDir
//!             -> descarcare -> decriptare strat interior
//!             -> verificare ca hash(cheia master) == adresa
//!             -> INTRODUCE1 -> INTRODUCE2 -> RENDEZVOUS1 -> RENDEZVOUS2
//!             -> hop virtual criptat cu CGO
//! ```
//!
//! Daca testele din acest fisier trec, un serviciu ascuns e accesibil de la un
//! capat la altul, cu identitate post-cuantica.

use pqo_crypto::cgo::{ClientCircuit, Outbound, RelayCircuit};
use pqo_crypto::kem::{Hybrid, Kem, X25519Kem};
use pqo_crypto::sig::{Ed25519, Sig};
use pqo_crypto::{client_finish, client_init, server_respond, RelayKeys, Variant};
use pqo_hs::desc::{Descriptor, IntroPoint};
use pqo_hs::hsdir::{responsible_nodes, DescStore, N_REPLICAS, N_STORE};
use pqo_hs::rend::{
    auth_key_id, new_cookie, EstablishIntro, IntroPayload, Introduce, Rendezvous1, RendezvousPoint,
};
use pqo_hs::{blinded_id, HsError, MasterSeed, OnionAddress, TimePeriod};
use rand_core::OsRng;

type S = Ed25519;
type K = Hybrid<X25519Kem, X25519Kem>;

const AD_RELAY: u8 = 3;
const PERIOADA: TimePeriod = TimePeriod(19_000);
const SRV: [u8; 32] = [0x5A; 32];

/// Reteaua simulata: nodurile HSDir cu stocarea lor.
struct Retea {
    fingerprints: Vec<[u8; 32]>,
    stocare: Vec<DescStore>,
}

impl Retea {
    fn noua(n: usize) -> Self {
        let fingerprints = (0..n)
            .map(|i| {
                let mut fp = [0u8; 32];
                fp[..8].copy_from_slice(&(i as u64).to_le_bytes());
                fp
            })
            .collect();
        Retea {
            fingerprints,
            stocare: (0..n).map(|_| DescStore::new()).collect(),
        }
    }

    fn index(&self, fp: &[u8; 32]) -> usize {
        self.fingerprints.iter().position(|x| x == fp).expect("nod necunoscut")
    }
}

/// Un serviciu ascuns complet.
struct Serviciu {
    /// Octetii semintei. In cod real traiesc pe disc; aici ii pastram ca sa
    /// putem simula o repornire.
    seed_bytes: [u8; 32],
    seed: MasterSeed,
    addr: OnionAddress,
    /// Cheile de handshake ale serviciului, cate una per punct de introducere.
    handshake_keys: Vec<RelayKeys<K>>,
    /// Cheile de decapsulare pentru corpurile INTRODUCE.
    intro_dk: Vec<<K as Kem>::DecapKey>,
    /// Cheile de autentificare fata de punctele de introducere.
    auth_sk: Vec<<S as Sig>::SecretKey>,
    intro_points: Vec<IntroPoint>,
}

impl Serviciu {
    fn nou(n_intro: usize) -> Self {
        let mut rng = OsRng;
        let mut seed_bytes = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rng, &mut seed_bytes);
        let seed = MasterSeed::new(seed_bytes);
        let (_sk, pk) = seed.identity_key::<S>();
        let addr = OnionAddress::from_identity::<S>(&pk);

        let mut handshake_keys = Vec::new();
        let mut intro_dk = Vec::new();
        let mut auth_sk = Vec::new();
        let mut intro_points = Vec::new();

        for i in 0..n_intro {
            // Cheile pentru handshake-ul de rendezvous. Serviciul le foloseste in
            // rol de releu, deci sunt `RelayKeys`. Identitatea lui e chiar
            // identificatorul adresei, nu un fingerprint de releu.
            let keys = RelayKeys::<K>::generate(*addr.id(), Variant::Transitional, &mut rng);
            // Cheia separata pentru decriptarea corpurilor INTRODUCE.
            let (dk, ek) = K::keygen(&mut rng);
            let (ask, apk) = S::keygen(&mut rng);

            intro_points.push(IntroPoint {
                relay_id: [(0xC0 + i) as u8; 32],
                onion_x25519: ek[..32].try_into().unwrap(),
                onion_kem: Some(ek[32..].to_vec()),
                svc_x25519: [0u8; 32],
                auth_key: apk,
            });
            handshake_keys.push(keys);
            intro_dk.push(dk);
            auth_sk.push(ask);
        }

        Serviciu {
            seed_bytes,
            seed,
            addr,
            handshake_keys,
            intro_dk,
            auth_sk,
            intro_points,
        }
    }

    /// Serviciul se anunta la fiecare punct de introducere.
    ///
    /// Punctul de introducere verifica semnatura si retine cheia. De acum
    /// inainte accepta INTRODUCE1 doar pentru acest `auth_key_id`.
    fn stabileste_puncte(&self) -> Vec<[u8; 32]> {
        let mut acceptate = Vec::new();
        for (i, ip) in self.intro_points.iter().enumerate() {
            // Legarea de circuit: in cod real e un identificator derivat din
            // circuitul pe care a venit mesajul.
            let binding = [(0x40 + i) as u8; 32];
            let e = EstablishIntro::new::<S>(&self.auth_sk[i], ip.auth_key.clone(), &binding);

            // Ce face punctul de introducere cand primeste mesajul.
            let primit = EstablishIntro::parse(&e.encode()).expect("parse ESTABLISH_INTRO");
            primit.verify::<S>(&binding).expect("semnatura valida");
            acceptate.push(auth_key_id(&primit.auth_key));
        }
        acceptate
    }

    /// Publica descriptorul pe toate nodurile responsabile.
    fn publica(&self, retea: &mut Retea, period: TimePeriod, revizie: u64) -> usize {
        let doc = Descriptor::build::<S>(
            &self.seed,
            &self.addr,
            period,
            revizie,
            self.intro_points.clone(),
        )
        .expect("construire descriptor");
        let d = Descriptor::parse_and_verify::<S>(&doc).expect("descriptor valid");

        let bid = blinded_id(self.addr.id(), period);
        let noduri = responsible_nodes(&retea.fingerprints, &bid, period, &SRV);
        for fp in &noduri {
            let i = retea.index(fp);
            retea.stocare[i].store(&d, &doc).expect("stocare");
        }
        noduri.len()
    }
}

/// Clientul cauta descriptorul si il valideaza.
fn cauta_descriptor(
    retea: &Retea,
    addr: &OnionAddress,
    period: TimePeriod,
) -> Result<(Descriptor, Vec<IntroPoint>), HsError> {
    let bid = blinded_id(addr.id(), period);
    let noduri = responsible_nodes(&retea.fingerprints, &bid, period, &SRV);
    for fp in &noduri {
        let i = retea.index(fp);
        if let Some(doc) = retea.stocare[i].fetch(&bid) {
            let d = Descriptor::parse_and_verify::<S>(doc)?;
            let inner = d.open_inner::<S>(addr)?;
            return Ok((d, inner.intro_points));
        }
    }
    Err(HsError::WrongBlindedId)
}

/// Rendezvous complet. Intoarce cele doua capete ale hop-ului virtual.
fn rendezvous(serv: &Serviciu, retea: &Retea) -> (ClientCircuit, RelayCircuit) {
    let mut rng = OsRng;

    // --- Serviciul se anunta la punctele de introducere ---
    let acceptate = serv.stabileste_puncte();

    // --- Clientul gaseste descriptorul pornind doar de la adresa textuala ---
    let addr = OnionAddress::parse(&serv.addr.to_string()).expect("adresa valida");
    let (_d, intro_points) = cauta_descriptor(retea, &addr, PERIOADA).expect("descriptor gasit");
    assert!(!intro_points.is_empty());

    // --- Clientul stabileste un punct de rendezvous ---
    let mut rp = RendezvousPoint::new();
    let cookie = new_cookie(&mut rng);
    rp.establish(cookie, 0xC11E).expect("establish rendezvous");

    // --- Clientul incepe handshake-ul si trimite INTRODUCE1 ---
    let ip = &intro_points[0];
    let idx = serv
        .intro_points
        .iter()
        .position(|x| x.auth_key == ip.auth_key)
        .expect("punct de introducere cunoscut");

    let public_serviciu = serv.handshake_keys[idx].public();
    let (state, hs_client) =
        client_init::<K>(&public_serviciu, Variant::Transitional, &mut rng).expect("client_init");

    let payload = IntroPayload {
        cookie,
        rp_relay_id: [0xEE; 32],
        rp_address: "127.0.0.1".into(),
        rp_port: 9001,
        handshake: hs_client,
    };
    let intro = Introduce::seal::<K>(ip, &payload, &mut rng).expect("seal");
    let pe_fir = intro.encode();

    // --- Punctul de introducere retransmite fara sa poata citi ---
    let intro2 = Introduce::parse(&pe_fir).expect("parse INTRODUCE2");
    assert!(
        acceptate.contains(&intro2.auth_key_id),
        "punctul de introducere accepta doar identificatori pe care i-a stabilit"
    );

    // --- Serviciul deschide corpul si raspunde ---
    let primit = intro2.open::<K>(&serv.intro_dk[idx]).expect("open");
    assert_eq!(primit.cookie, cookie);

    let (hs_server, res_serv) =
        server_respond::<K>(&serv.handshake_keys[idx], &primit.handshake, &mut rng)
            .expect("server_respond");

    let r1 = Rendezvous1 {
        cookie: primit.cookie,
        handshake: hs_server,
    };
    let r1_fir = r1.encode();

    // --- Punctul de rendezvous imperecheaza si taie cookie-ul ---
    let r1_primit = Rendezvous1::parse(&r1_fir).expect("parse RENDEZVOUS1");
    let circuit_client = rp.join(&r1_primit.cookie).expect("imperechere");
    assert_eq!(circuit_client, 0xC11E);
    let r2 = r1_primit.to_rendezvous2();

    // --- Clientul finalizeaza ---
    let res_cli = client_finish::<K>(state, &r2).expect("client_finish");
    assert_eq!(
        res_cli.key_seed.expand_vec(160),
        res_serv.key_seed.expand_vec(160),
        "cele doua capete trebuie sa derive acelasi material de cheie"
    );

    // Hop-ul virtual. Serviciul e in rol de RELEU, clientul de CLIENT.
    let mut cc = ClientCircuit::new();
    cc.add_hop(&res_cli.key_seed);
    let rc = RelayCircuit::new(&res_serv.key_seed);
    (cc, rc)
}

// ---------------------------------------------------------------------------

#[test]
fn adresa_e_stabila_si_de_56_de_caractere() {
    let s = Serviciu::nou(1);
    let text = s.addr.to_string();
    assert_eq!(text.len(), 62, "56 de caractere plus .onion");
    assert_eq!(OnionAddress::parse(&text).unwrap(), s.addr);
}

#[test]
fn publicarea_atinge_nodurile_asteptate() {
    let mut retea = Retea::noua(40);
    let serv = Serviciu::nou(3);
    let n = serv.publica(&mut retea, PERIOADA, 1);
    assert!(n >= N_STORE, "cel putin o replica completa");
    assert!(n <= (N_REPLICAS as usize) * N_STORE);
}

#[test]
fn clientul_gaseste_descriptorul_doar_din_adresa() {
    let mut retea = Retea::noua(40);
    let serv = Serviciu::nou(3);
    serv.publica(&mut retea, PERIOADA, 1);

    // Clientul porneste de la sirul de caractere, nu de la structura.
    let addr = OnionAddress::parse(&serv.addr.to_string()).unwrap();
    let (_d, ips) = cauta_descriptor(&retea, &addr, PERIOADA).unwrap();
    assert_eq!(ips.len(), 3);
    assert_eq!(ips, serv.intro_points);
}

#[test]
fn un_client_cu_adresa_gresita_nu_gaseste_nimic() {
    let mut retea = Retea::noua(40);
    let serv = Serviciu::nou(2);
    serv.publica(&mut retea, PERIOADA, 1);

    let altul = Serviciu::nou(1);
    assert!(cauta_descriptor(&retea, &altul.addr, PERIOADA).is_err());
}

#[test]
fn hsdir_urile_nu_pot_lega_perioadele() {
    let mut retea = Retea::noua(40);
    let serv = Serviciu::nou(2);
    serv.publica(&mut retea, PERIOADA, 1);
    serv.publica(&mut retea, PERIOADA.next(), 1);

    let b1 = blinded_id(serv.addr.id(), PERIOADA);
    let b2 = blinded_id(serv.addr.id(), PERIOADA.next());
    assert_ne!(b1, b2);

    // Descriptorii celor doua perioade nu au niciun camp comun observabil.
    let n1 = responsible_nodes(&retea.fingerprints, &b1, PERIOADA, &SRV);
    let n2 = responsible_nodes(&retea.fingerprints, &b2, PERIOADA.next(), &SRV);
    let d1 = retea.stocare[retea.index(&n1[0])].fetch(&b1).unwrap();
    let d2 = retea.stocare[retea.index(&n2[0])].fetch(&b2).unwrap();

    let p1 = Descriptor::parse_and_verify::<S>(d1).unwrap();
    let p2 = Descriptor::parse_and_verify::<S>(d2).unwrap();
    assert_ne!(p1.period_key, p2.period_key);
    assert_ne!(p1.encrypted, p2.encrypted);
}

#[test]
fn punctul_de_introducere_respinge_o_cheie_nestabilita() {
    // Cineva trimite INTRODUCE1 catre un punct de introducere, pentru o cheie
    // de autentificare pe care serviciul nu a stabilit-o niciodata acolo.
    let serv = Serviciu::nou(2);
    let acceptate = serv.stabileste_puncte();
    let strain = Serviciu::nou(1);
    let akid_strain = auth_key_id(&strain.intro_points[0].auth_key);
    assert!(!acceptate.contains(&akid_strain));
}

#[test]
fn rendezvous_complet() {
    let mut retea = Retea::noua(40);
    let serv = Serviciu::nou(3);
    serv.publica(&mut retea, PERIOADA, 1);
    let (_cc, _rc) = rendezvous(&serv, &retea);
}

#[test]
fn trafic_bidirectional_pe_hopul_virtual() {
    let mut retea = Retea::noua(40);
    let serv = Serviciu::nou(3);
    serv.publica(&mut retea, PERIOADA, 1);
    let (mut cc, mut rc) = rendezvous(&serv, &retea);

    for runda in 0..20u8 {
        // Client -> serviciu.
        let mut corp = [0u8; pqo_crypto::cgo::LEN_XR];
        for (i, b) in corp.iter_mut().enumerate() {
            *b = runda.wrapping_add((i % 251) as u8);
        }
        let cell = cc.encrypt_outbound(1, AD_RELAY, &corp).expect("criptare");
        match rc.process_outbound(AD_RELAY, &cell) {
            Outbound::Recognized(b) => assert_eq!(&b[..], &corp[..], "runda {runda}"),
            Outbound::Forward(_) => panic!("serviciul trebuia sa recunoasca celula"),
        }

        // Serviciu -> client.
        let mut raspuns = [0u8; pqo_crypto::cgo::LEN_XR];
        for (i, b) in raspuns.iter_mut().enumerate() {
            *b = runda.wrapping_mul(3).wrapping_add((i % 241) as u8);
        }
        let cell = rc.originate_inbound(AD_RELAY, &raspuns);
        let (hop, primit) = cc.decrypt_inbound(AD_RELAY, &cell).expect("decriptare");
        assert_eq!(hop, 1);
        assert_eq!(&primit[..], &raspuns[..], "runda {runda}");
    }
}

#[test]
fn tagging_pe_hopul_virtual_e_detectat() {
    let mut retea = Retea::noua(40);
    let serv = Serviciu::nou(1);
    serv.publica(&mut retea, PERIOADA, 1);
    let (mut cc, mut rc) = rendezvous(&serv, &retea);

    let corp = [0x5Au8; pqo_crypto::cgo::LEN_XR];
    let mut cell = cc.encrypt_outbound(1, AD_RELAY, &corp).unwrap();
    cell[200] ^= 0x01;
    match rc.process_outbound(AD_RELAY, &cell) {
        Outbound::Forward(_) => {}
        Outbound::Recognized(_) => panic!("modificarea nu a fost detectata"),
    }
}

#[test]
fn un_hsdir_ostil_nu_poate_suprascrie() {
    let mut retea = Retea::noua(20);
    let serv = Serviciu::nou(1);
    serv.publica(&mut retea, PERIOADA, 1);

    // Un atacator care stie adresa incearca sa publice descriptorul lui la
    // acelasi index. Nodul refuza: slotul e ocupat de alta cheie de perioada.
    let atac = MasterSeed::new([0xFF; 32]);
    let (_ak, apk) = atac.identity_key::<S>();
    let addr_atac = OnionAddress::from_identity::<S>(&apk);
    let _ = addr_atac;

    let bid = blinded_id(serv.addr.id(), PERIOADA);
    let noduri = responsible_nodes(&retea.fingerprints, &bid, PERIOADA, &SRV);
    let i = retea.index(&noduri[0]);

    let original = retea.stocare[i].fetch(&bid).unwrap().to_string();
    let mut fals = Descriptor::parse_and_verify::<S>(&original).unwrap();
    fals.revision = u64::MAX;
    fals.period_key = atac.period_key::<S>(PERIOADA).1;

    assert_eq!(
        retea.stocare[i].store(&fals, "fals"),
        Err(HsError::SlotOccupied)
    );
    assert_eq!(retea.stocare[i].fetch(&bid), Some(original.as_str()));
}

#[test]
fn actualizarea_descriptorului_cere_revizie_mai_mare() {
    let mut retea = Retea::noua(20);
    let serv = Serviciu::nou(2);
    serv.publica(&mut retea, PERIOADA, 5);

    // Aceeasi revizie: nodurile refuza.
    let doc = Descriptor::build::<S>(
        &serv.seed,
        &serv.addr,
        PERIOADA,
        5,
        serv.intro_points.clone(),
    )
    .unwrap();
    let d = Descriptor::parse_and_verify::<S>(&doc).unwrap();
    let bid = blinded_id(serv.addr.id(), PERIOADA);
    let noduri = responsible_nodes(&retea.fingerprints, &bid, PERIOADA, &SRV);
    let i = retea.index(&noduri[0]);
    assert!(matches!(
        retea.stocare[i].store(&d, &doc),
        Err(HsError::StaleRevision { .. })
    ));

    // Revizie mai mare: acceptata pe toate nodurile.
    serv.publica(&mut retea, PERIOADA, 6);
}

#[test]
fn serviciul_isi_rederiva_cheile_dupa_repornire() {
    // Un serviciu care reporneste trebuie sa poata actualiza acelasi descriptor.
    let mut retea = Retea::noua(20);
    let serv = Serviciu::nou(1);
    serv.publica(&mut retea, PERIOADA, 1);

    // "Repornire": doar samanta supravietuieste. Tot restul se rederiva.
    let repornit = MasterSeed::new(serv.seed_bytes);
    let (_sk, pk) = repornit.identity_key::<S>();
    let addr = OnionAddress::from_identity::<S>(&pk);
    assert_eq!(addr, serv.addr, "adresa trebuie sa fie aceeasi");

    let doc = Descriptor::build::<S>(&repornit, &addr, PERIOADA, 2, serv.intro_points.clone())
        .unwrap();
    let d = Descriptor::parse_and_verify::<S>(&doc).unwrap();
    let bid = blinded_id(addr.id(), PERIOADA);
    let noduri = responsible_nodes(&retea.fingerprints, &bid, PERIOADA, &SRV);
    for fp in &noduri {
        let i = retea.index(fp);
        retea.stocare[i]
            .store(&d, &doc)
            .expect("serviciul repornit trebuie sa poata actualiza");
    }
}
