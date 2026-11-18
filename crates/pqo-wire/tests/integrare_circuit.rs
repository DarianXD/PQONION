//! Simularea completa a unui circuit de 3 hop-uri.
//!
//! Acopera tot lantul construit pana acum:
//!
//! ```text
//!   pq-ntor handshake  ->  KEY_SEED  ->  chei CGO
//!   mesaj de protocol  ->  fragmentare  ->  corpuri de 493B
//!   corp  ->  CGO encrypt_outbound  ->  celula de 509B  ->  celula de fir de 514B
//!   ... prin relee, fiecare cu process_outbound ...
//!   hop destinatie: Recognized  ->  reasamblare  ->  mesaj de protocol
//! ```
//!
//! Daca testele din acest fisier trec, ai un circuit functional: handshake
//! post-cuantic, transport fragmentat si criptare onion cu autentificare.

use pqo_crypto::cgo::{ClientCircuit, Outbound, RelayCircuit};
use pqo_crypto::{
    client_finish, client_init, ntor, server_respond, Hybrid, KeySeed, RelayKeys, Variant,
    X25519Kem,
};
use pqo_wire::{
    Cell, ChanCmd, CircId, Create2, Created2, Extend2, Extended2, HandshakeType, LinkSpec,
    Reassembler, RelayCmd, RelayMessage, StreamId,
};
use rand_core::OsRng;

type K = Hybrid<X25519Kem, X25519Kem>;

const AD_RELAY: u8 = ChanCmd::Relay as u8;
const AD_EARLY: u8 = ChanCmd::RelayEarly as u8;

fn htype(v: Variant) -> HandshakeType {
    match v {
        Variant::Transitional => HandshakeType::PqNtorTransitional,
        Variant::FullPq => HandshakeType::PqNtorFullPq,
    }
}

/// Un releu din simulare: cheile lui de lunga durata, plus starea CGO si
/// reasamblatorul pentru circuitul curent.
struct Releu {
    keys: RelayKeys<K>,
    cgo: Option<RelayCircuit>,
    reasm: Reassembler,
}

impl Releu {
    fn nou(id: u8, v: Variant) -> Self {
        Releu {
            keys: RelayKeys::<K>::generate([id; ntor::ID_LEN], v, &mut OsRng),
            cgo: None,
            reasm: Reassembler::new(),
        }
    }

    /// Raspunde la un handshake si isi initializeaza starea CGO.
    fn accepta(&mut self, hs: &[u8]) -> Vec<u8> {
        let (raspuns, res) = server_respond::<K>(&self.keys, hs, &mut OsRng).expect("handshake");
        self.cgo = Some(RelayCircuit::new(&res.key_seed));
        raspuns
    }
}

/// Un circuit construit, gata de folosit.
struct Circuit {
    client: ClientCircuit,
    relee: Vec<Releu>,
    client_reasm: Reassembler,
}

impl Circuit {
    /// Trimite un mesaj relay catre hop-ul `d` (1-indexat), trecandu-l prin
    /// fragmentare, criptare CGO si prin fiecare releu intermediar.
    fn trimite(&mut self, d: usize, ad: u8, msg: &RelayMessage) -> RelayMessage {
        let mut primit = None;

        for corp in msg.fragment(&mut OsRng) {
            let mut cell = self
                .client
                .encrypt_outbound(d, ad, &corp)
                .expect("criptare");

            // Ambalare in celula de fir si despachetare, ca sa verificam si
            // formatul de nivel canal pe drum.
            let fir = Cell::fixed(CircId(0x8000_0001), ChanCmd::Relay, cell.as_slice()).unwrap();
            let mut buf = Vec::new();
            fir.encode(&mut buf);
            assert_eq!(buf.len(), pqo_wire::CELL_LEN);
            let (dec, _) = Cell::decode(&buf).unwrap().unwrap();
            cell.copy_from_slice(dec.payload());

            for i in 0..d {
                let r = &mut self.relee[i];
                let actiune = r
                    .cgo
                    .as_mut()
                    .expect("CGO neinitializat")
                    .process_outbound(ad, &cell);
                match actiune {
                    Outbound::Recognized(body) => {
                        assert_eq!(i + 1, d, "hop-ul gresit a recunoscut celula");
                        if let Some(m) = r.reasm.push(body.as_slice()).expect("reasamblare") {
                            assert!(primit.is_none(), "un singur mesaj complet");
                            primit = Some(m);
                        }
                        break;
                    }
                    Outbound::Forward(next) => {
                        assert!(i + 1 < d, "hop-ul {} trebuia sa recunoasca", i + 1);
                        cell = next;
                    }
                }
            }
        }
        primit.expect("mesajul nu s-a completat la destinatie")
    }

    /// Raspunde de la hop-ul `d` catre client, prin `ENC_OR` si `PROC_OR`.
    fn raspunde(&mut self, d: usize, ad: u8, msg: &RelayMessage) -> RelayMessage {
        let mut primit = None;

        for corp in msg.fragment(&mut OsRng) {
            let mut cell = self.relee[d - 1]
                .cgo
                .as_mut()
                .expect("CGO neinitializat")
                .originate_inbound(ad, &corp);

            for i in (0..d - 1).rev() {
                cell = self.relee[i]
                    .cgo
                    .as_mut()
                    .expect("CGO neinitializat")
                    .relay_inbound(ad, &cell);
            }

            let (hop, body) = self.client.decrypt_inbound(ad, &cell).expect("decriptare");
            assert_eq!(hop, d, "clientul a identificat gresit hop-ul sursa");
            if let Some(m) = self.client_reasm.push(body.as_slice()).expect("reasamblare") {
                assert!(primit.is_none());
                primit = Some(m);
            }
        }
        primit.expect("mesajul nu s-a completat la client")
    }
}

/// Construieste un circuit de `n` hop-uri: CREATE2 pentru primul, apoi cate un
/// EXTEND2 criptat si fragmentat pentru fiecare hop urmator.
fn construieste(n: usize, v: Variant) -> Circuit {
    assert!(n >= 1);
    let relee: Vec<Releu> = (0..n).map(|i| Releu::nou(0x10 + i as u8, v)).collect();
    let mut client = ClientCircuit::new();
    let mut relee = relee;

    // --- Hop 1: CREATE2 / CREATED2 in celule variabile de nivel canal ---
    let (state, hs) = client_init::<K>(&relee[0].keys.public(), v, &mut OsRng).unwrap();
    let cell = Cell::var(
        CircId(0x8000_0001),
        ChanCmd::Create2,
        Create2 {
            htype: htype(v),
            data: hs,
        }
        .encode(),
    )
    .unwrap();
    let mut buf = Vec::new();
    cell.encode(&mut buf);
    let (primita, _) = Cell::decode(&buf).unwrap().unwrap();

    let create = Create2::parse(primita.payload()).unwrap();
    let raspuns = relee[0].accepta(&create.data);
    let cell = Cell::var(
        CircId(0x8000_0001),
        ChanCmd::Created2,
        Created2 { data: raspuns }.encode(),
    )
    .unwrap();
    let mut buf = Vec::new();
    cell.encode(&mut buf);
    let (primita, _) = Cell::decode(&buf).unwrap().unwrap();

    let created = Created2::parse(primita.payload()).unwrap();
    let res = client_finish::<K>(state, &created.data).unwrap();
    client.add_hop(&res.key_seed);

    let mut circ = Circuit {
        client,
        relee,
        client_reasm: Reassembler::new(),
    };

    // --- Hop-urile 2..n: EXTEND2 criptat si fragmentat ---
    for h in 2..=n {
        let tinta = circ.relee[h - 1].keys.public();
        let (state, hs) = client_init::<K>(&tinta, v, &mut OsRng).unwrap();

        let extend = Extend2 {
            specs: vec![
                LinkSpec::Ipv4 {
                    addr: [10, 0, 0, h as u8],
                    port: 9001,
                },
                LinkSpec::RelayId(tinta.id),
            ],
            htype: htype(v),
            data: hs,
        };
        let msg =
            RelayMessage::new(RelayCmd::Extend2, StreamId::CONTROL, extend.encode()).unwrap();

        // EXTEND2 merge in celule RELAY_EARLY, catre hop-ul h-1.
        let primit = circ.trimite(h - 1, AD_EARLY, &msg);
        assert_eq!(primit.cmd, RelayCmd::Extend2);

        let extend = Extend2::parse(&primit.body).unwrap();
        assert_eq!(extend.relay_id(), Some(tinta.id));

        // Hop-ul h-1 deschide un canal catre hop-ul h si ii trimite CREATE2.
        let raspuns = circ.relee[h - 1].accepta(&extend.data);

        // ... si impacheteaza raspunsul intr-un EXTENDED2 catre client.
        let msg = RelayMessage::new(
            RelayCmd::Extended2,
            StreamId::CONTROL,
            Extended2 { data: raspuns }.encode(),
        )
        .unwrap();
        let primit = circ.raspunde(h - 1, AD_RELAY, &msg);

        let extended = Extended2::parse(&primit.body).unwrap();
        let res = client_finish::<K>(state, &extended.data).unwrap();
        circ.client.add_hop(&res.key_seed);
    }

    assert_eq!(circ.client.len(), n);
    circ
}

// ---------------------------------------------------------------------------

#[test]
fn constantele_celor_doua_crate_uri_coincid() {
    // `pqo-wire` nu depinde de `pqo-crypto`, deci constantele sunt duplicate.
    // Aici verificam ca nu au divergat.
    assert_eq!(pqo_wire::CGO_TAG_LEN, pqo_crypto::cgo::BLK_LEN);
    assert_eq!(pqo_wire::RELAY_BODY_LEN, pqo_crypto::cgo::LEN_XR);
    assert_eq!(pqo_wire::CELL_PAYLOAD_LEN, pqo_crypto::cgo::MSG_LEN);
}

#[test]
fn circuit_de_trei_hopuri_tranzitional() {
    construieste(3, Variant::Transitional);
}

#[test]
fn circuit_de_trei_hopuri_fullpq() {
    construieste(3, Variant::FullPq);
}

#[test]
fn circuit_de_un_hop() {
    construieste(1, Variant::Transitional);
}

#[test]
fn circuit_de_cinci_hopuri() {
    // Circuitele de rendezvous ajung la 6 hop-uri. Verificam ca stiva tine.
    construieste(5, Variant::Transitional);
}

#[test]
fn trafic_bidirectional_dupa_construire() {
    let mut c = construieste(3, Variant::Transitional);

    for runda in 0..20u8 {
        // Cerere de la client catre exit, suficient de mare cat sa se fragmenteze.
        let date: Vec<u8> = (0..1500).map(|i| (i as u8).wrapping_add(runda)).collect();
        let cerere = RelayMessage::new(RelayCmd::Data, StreamId(1), date.clone()).unwrap();
        assert!(cerere.cell_count() > 1, "mesajul trebuia sa se fragmenteze");
        let primit = c.trimite(3, AD_RELAY, &cerere);
        assert_eq!(primit.body, date, "cerere corupta la runda {runda}");

        // Raspuns de la exit catre client.
        let date: Vec<u8> = (0..2000)
            .map(|i| (i as u8).wrapping_mul(3).wrapping_add(runda))
            .collect();
        let raspuns = RelayMessage::new(RelayCmd::Data, StreamId(1), date.clone()).unwrap();
        let primit = c.raspunde(3, AD_RELAY, &raspuns);
        assert_eq!(primit.body, date, "raspuns corupt la runda {runda}");
    }
}

#[test]
fn trafic_catre_fiecare_hop() {
    // Mesaje catre hop-uri diferite, intercalate. Starile CGO nu trebuie sa se
    // contamineze intre ele.
    let mut c = construieste(3, Variant::Transitional);
    for runda in 0..10u8 {
        for d in 1..=3usize {
            let date = vec![runda.wrapping_add(d as u8); 100];
            let m = RelayMessage::new(RelayCmd::Data, StreamId(d as u16), date.clone()).unwrap();
            assert_eq!(c.trimite(d, AD_RELAY, &m).body, date);

            let m = RelayMessage::new(RelayCmd::Sendme, StreamId(d as u16), date.clone()).unwrap();
            assert_eq!(c.raspunde(d, AD_RELAY, &m).body, date);
        }
    }
}

#[test]
fn releu_ostil_care_modifica_o_celula_e_detectat() {
    // Hop-ul 1 flipuie un bit intr-o celula in drum spre hop-ul 3.
    let mut c = construieste(3, Variant::Transitional);
    let corp = [0x5Au8; pqo_crypto::cgo::LEN_XR];
    let mut cell = c.client.encrypt_outbound(3, AD_RELAY, &corp).unwrap();

    cell = match c.relee[0]
        .cgo
        .as_mut()
        .unwrap()
        .process_outbound(AD_RELAY, &cell)
    {
        Outbound::Forward(x) => x,
        _ => panic!("hop 1 nu trebuia sa recunoasca"),
    };
    cell[250] ^= 0x01; // aici loveste atacatorul

    cell = match c.relee[1]
        .cgo
        .as_mut()
        .unwrap()
        .process_outbound(AD_RELAY, &cell)
    {
        Outbound::Forward(x) => x,
        _ => panic!("hop 2 nu trebuia sa recunoasca"),
    };
    match c.relee[2]
        .cgo
        .as_mut()
        .unwrap()
        .process_outbound(AD_RELAY, &cell)
    {
        Outbound::Forward(_) => {}
        Outbound::Recognized(_) => panic!("tagging-ul nu a fost detectat"),
    }
}

#[test]
fn handshake_modificat_pe_drum_e_respins() {
    let v = Variant::Transitional;
    let keys = RelayKeys::<K>::generate([0x99; ntor::ID_LEN], v, &mut OsRng);
    let (state, hs) = client_init::<K>(&keys.public(), v, &mut OsRng).unwrap();
    let (mut raspuns, _) = server_respond::<K>(&keys, &hs, &mut OsRng).unwrap();
    raspuns[10] ^= 0x01;

    let msg = RelayMessage::new(
        RelayCmd::Extended2,
        StreamId::CONTROL,
        Extended2 { data: raspuns }.encode(),
    )
    .unwrap();
    // Trece prin fragmentare intacta; abia verificarea tag-ului ntor prinde.
    let mut r = Reassembler::new();
    let mut primit = None;
    for corp in msg.fragment(&mut OsRng) {
        if let Some(m) = r.push(&corp).unwrap() {
            primit = Some(m);
        }
    }
    let extended = Extended2::parse(&primit.unwrap().body).unwrap();
    assert!(
        client_finish::<K>(state, &extended.data).is_err(),
        "modificarea handshake-ului trebuia detectata"
    );
}

#[test]
fn materialul_de_cheie_ajunge_pentru_cgo() {
    let seed = KeySeed::new([0x77; 32]);
    let m = seed.expand_vec(pqo_crypto::cgo::KEY_MATERIAL_LEN);
    assert_eq!(m.len(), 160);
    // Doua directii x (cheie UIV de 64 + nonce de 16).
    assert_eq!(pqo_crypto::cgo::KEY_MATERIAL_LEN, 2 * (64 + 16));
}
