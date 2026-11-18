//! Stratul onion al CGO — nivelul 4 din propunerea 359.
//!
//! # Asimetria care conteaza
//!
//! In `tor1` nu exista nicio diferenta intre ce face clientul si ce face releul:
//! ambele aplicau AES-CTR. In CGO, clientul foloseste **mereu** `DEC_UIV` si
//! releul **mereu** `ENC_UIV`, in ambele directii. Motivul: `ENC_UIV` e
//! nemaleabil, `DEC_UIV` nu e. Compunerea iese corecta pentru ca operatiile sunt
//! inverse una alteia, iar asezarea lor astfel pune partea nemaleabila exact
//! acolo unde un releu ostil ar incerca sa introduca un tag.
//!
//! Consecinta practica, de retinut pentru serviciile ascunse: pe hop-ul virtual
//! dintre client si serviciu, **serviciul joaca rolul de releu** ([`RelayCircuit`]),
//! nu de client. Pe restul circuitului sau, serviciul e client obisnuit.
//!
//! # Recunoasterea celulei
//!
//! Nu mai exista camp `recognized`. Un hop stie ca celula ii e adresata daca,
//! dupa aplicarea UIV, tag-ul rezultat e egal cu nonce-ul sau curent `N`. Asta
//! e in acelasi timp verificarea de integritate pe 128 de biti. Comparatia se
//! face in timp constant.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::primitives::{
    dec_uiv, enc_uiv, update_uiv, UivKey, BLK_LEN, HLEN_UIV, KLEN_UIV, LEN_XR, MSG_LEN,
};
use crate::kdf::KeySeed;

/// Cati octeti de material de cheie consuma un hop: doua directii, fiecare cu
/// o cheie UIV+ de 64 de octeti si un nonce de 16.
pub const KEY_MATERIAL_LEN: usize = 2 * (KLEN_UIV + BLK_LEN); // 160

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgoError {
    /// Indice de hop invalid (0 sau mai mare decat lungimea circuitului).
    BadHop,
    /// Nicio pozitie din circuit nu a recunoscut celula: a fost modificata.
    NotRecognized,
    /// Circuit fara niciun hop.
    EmptyCircuit,
}

impl core::fmt::Display for CgoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CgoError::BadHop => f.write_str("indice de hop invalid"),
            CgoError::NotRecognized => f.write_str("celula nerecunoscuta sau modificata"),
            CgoError::EmptyCircuit => f.write_str("circuit fara hop-uri"),
        }
    }
}

impl std::error::Error for CgoError {}

/// Starea CGO pentru un hop, intr-o singura directie: `(K, N, T')`.
struct HopState {
    k: UivKey,
    n: [u8; BLK_LEN],
    t_prime: [u8; BLK_LEN],
}

impl Drop for HopState {
    fn drop(&mut self) {
        self.n.zeroize();
        self.t_prime.zeroize();
    }
}

impl HopState {
    /// `T'` se initializeaza cu zero, `K` si `N` din KDF-ul handshake-ului.
    fn new(k: [u8; KLEN_UIV], n: [u8; BLK_LEN]) -> Self {
        HopState {
            k: UivKey::from_bytes(k),
            n,
            t_prime: [0u8; BLK_LEN],
        }
    }

    #[inline]
    fn tweak(&self, ad: u8) -> [u8; HLEN_UIV] {
        let mut h = [0u8; HLEN_UIV];
        h[..BLK_LEN].copy_from_slice(&self.t_prime);
        h[BLK_LEN] = ad;
        h
    }
}

/// Perechea de stari (inainte / inapoi) pentru un hop.
struct HopPair {
    fwd: HopState,
    bwd: HopState,
}

impl HopPair {
    /// Deriva ambele directii din `KEY_SEED`-ul handshake-ului.
    ///
    /// Aranjament: `K_fwd(64) | N_fwd(16) | K_bwd(64) | N_bwd(16)`.
    fn from_seed(seed: &KeySeed) -> Self {
        let mut m = seed.expand_vec(KEY_MATERIAL_LEN);
        let mut kf = [0u8; KLEN_UIV];
        let mut nf = [0u8; BLK_LEN];
        let mut kb = [0u8; KLEN_UIV];
        let mut nb = [0u8; BLK_LEN];
        kf.copy_from_slice(&m[0..64]);
        nf.copy_from_slice(&m[64..80]);
        kb.copy_from_slice(&m[80..144]);
        nb.copy_from_slice(&m[144..160]);
        m.zeroize();
        HopPair {
            fwd: HopState::new(kf, nf),
            bwd: HopState::new(kb, nb),
        }
    }
}

/// Ce trebuie sa faca un releu cu o celula primita dinspre client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// Celula ne e adresata noua. Contine corpul de 493 de octeti.
    Recognized(Box<[u8; LEN_XR]>),
    /// Celula merge mai departe, in forma data.
    Forward(Box<[u8; MSG_LEN]>),
}

// ---------------------------------------------------------------------------
// Client (algoritmii `*_OP`)
// ---------------------------------------------------------------------------

/// Starea criptografica a unui circuit, din perspectiva clientului.
pub struct ClientCircuit {
    hops: Vec<HopPair>,
}

impl core::fmt::Debug for ClientCircuit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ClientCircuit({} hop-uri)", self.hops.len())
    }
}

impl Default for ClientCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientCircuit {
    pub fn new() -> Self {
        ClientCircuit { hops: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.hops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// Adauga un hop dupa un handshake `pq-ntor` reusit.
    pub fn add_hop(&mut self, seed: &KeySeed) {
        self.hops.push(HopPair::from_seed(seed));
    }

    /// `ENC_OP_MID` — un strat de "impachetare" la hop-ul `i` (0-indexat intern).
    fn op_mid(st: &mut HopState, ad: u8, cell: &mut [u8; MSG_LEN]) {
        let h = st.tweak(ad);
        // `T'` devine tag-ul de INTRARE, inainte de transformare.
        st.t_prime.copy_from_slice(&cell[..BLK_LEN]);
        dec_uiv(&st.k, &h, cell);
    }

    /// Cripteaza un corp de 493 de octeti pentru hop-ul `d` (1-indexat).
    ///
    /// Implementeaza `ENC_OP`: mai intai `ENC_OP_DEST` la hop-ul destinatie,
    /// apoi cate un `ENC_OP_MID` pentru fiecare hop dinaintea lui, in ordine
    /// inversa.
    pub fn encrypt_outbound(
        &mut self,
        d: usize,
        ad: u8,
        body: &[u8; LEN_XR],
    ) -> Result<Box<[u8; MSG_LEN]>, CgoError> {
        if d == 0 || d > self.hops.len() {
            return Err(CgoError::BadHop);
        }
        let mut cell = Box::new([0u8; MSG_LEN]);

        // ENC_OP_DEST: T initializat cu N_d, C initializat cu M.
        {
            let st = &mut self.hops[d - 1].fwd;
            cell[..BLK_LEN].copy_from_slice(&st.n);
            cell[BLK_LEN..].copy_from_slice(body);
            Self::op_mid(st, ad, &mut cell);
            // Pasul de actualizare foloseste nonce-ul VECHI.
            let n = st.n;
            st.n = update_uiv(&mut st.k, &n);
        }

        // Straturile hop-urilor dinainte, de la d-1 in jos la 1.
        for i in (0..d - 1).rev() {
            Self::op_mid(&mut self.hops[i].fwd, ad, &mut cell);
        }
        Ok(cell)
    }

    /// `DEC_OP` — decripteaza o celula sosita dinspre circuit.
    ///
    /// Intoarce indicele hop-ului (1-indexat) care a originat celula si corpul.
    /// Daca niciun hop nu recunoaste tag-ul, celula a fost modificata pe drum.
    pub fn decrypt_inbound(
        &mut self,
        ad: u8,
        cell: &[u8; MSG_LEN],
    ) -> Result<(usize, Box<[u8; LEN_XR]>), CgoError> {
        if self.hops.is_empty() {
            return Err(CgoError::EmptyCircuit);
        }
        let mut cur = *cell;

        for i in 0..self.hops.len() {
            let st = &mut self.hops[i].bwd;
            let h = st.tweak(ad);

            // Tag-ul de intrare la acest hop, pastrat pentru actualizarea starii.
            let mut t_in = [0u8; BLK_LEN];
            t_in.copy_from_slice(&cur[..BLK_LEN]);

            let mut next = cur;
            dec_uiv(&st.k, &h, &mut next);
            let t_out: [u8; BLK_LEN] = next[..BLK_LEN].try_into().expect("lungime fixa");

            let recunoscut: bool = t_out.ct_eq(&st.n).into();
            st.t_prime = t_in;

            if recunoscut {
                st.n = update_uiv(&mut st.k, &t_in);
                let mut body = Box::new([0u8; LEN_XR]);
                body.copy_from_slice(&next[BLK_LEN..]);
                cur.zeroize();
                return Ok((i + 1, body));
            }
            cur = next;
        }
        cur.zeroize();
        Err(CgoError::NotRecognized)
    }
}

// ---------------------------------------------------------------------------
// Releu (algoritmii `*_OR`)
// ---------------------------------------------------------------------------

/// Starea criptografica a unui circuit, din perspectiva unui releu.
///
/// Serviciile ascunse folosesc acelasi tip pentru hop-ul virtual catre client.
pub struct RelayCircuit {
    hop: HopPair,
}

impl core::fmt::Debug for RelayCircuit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RelayCircuit(redacted)")
    }
}

impl RelayCircuit {
    pub fn new(seed: &KeySeed) -> Self {
        RelayCircuit {
            hop: HopPair::from_seed(seed),
        }
    }

    /// `DEC_OR` — proceseaza o celula venita dinspre client.
    pub fn process_outbound(&mut self, ad: u8, cell: &[u8; MSG_LEN]) -> Outbound {
        let st = &mut self.hop.fwd;
        let h = st.tweak(ad);

        let mut out = *cell;
        enc_uiv(&st.k, &h, &mut out);
        let t: [u8; BLK_LEN] = out[..BLK_LEN].try_into().expect("lungime fixa");

        let recunoscut: bool = t.ct_eq(&st.n).into();
        st.t_prime = t;

        if recunoscut {
            let n = st.n;
            st.n = update_uiv(&mut st.k, &n);
            let mut body = Box::new([0u8; LEN_XR]);
            body.copy_from_slice(&out[BLK_LEN..]);
            out.zeroize();
            Outbound::Recognized(body)
        } else {
            Outbound::Forward(Box::new(out))
        }
    }

    /// `ENC_OR` — originează o celula catre client.
    pub fn originate_inbound(&mut self, ad: u8, body: &[u8; LEN_XR]) -> Box<[u8; MSG_LEN]> {
        let st = &mut self.hop.bwd;
        let h = st.tweak(ad);

        let mut cell = Box::new([0u8; MSG_LEN]);
        cell[..BLK_LEN].copy_from_slice(&st.n);
        cell[BLK_LEN..].copy_from_slice(body);
        enc_uiv(&st.k, &h, &mut cell);

        let t: [u8; BLK_LEN] = cell[..BLK_LEN].try_into().expect("lungime fixa");
        // Aici actualizarea foloseste tag-ul NOU, nu nonce-ul vechi.
        st.n = update_uiv(&mut st.k, &t);
        st.t_prime = t;
        cell
    }

    /// `PROC_OR` — retransmite catre client o celula venita din adancul circuitului.
    pub fn relay_inbound(&mut self, ad: u8, cell: &[u8; MSG_LEN]) -> Box<[u8; MSG_LEN]> {
        let st = &mut self.hop.bwd;
        let h = st.tweak(ad);

        let mut out = Box::new(*cell);
        enc_uiv(&st.k, &h, &mut out);
        st.t_prime.copy_from_slice(&out[..BLK_LEN]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::KeySeed;

    const AD: u8 = 3; // comanda RELAY

    fn seed(v: u8) -> KeySeed {
        KeySeed::new([v; 32])
    }

    fn corp(v: u8) -> [u8; LEN_XR] {
        let mut b = [0u8; LEN_XR];
        for (i, x) in b.iter_mut().enumerate() {
            *x = v.wrapping_add((i % 251) as u8);
        }
        b
    }

    /// Construieste un circuit de `n` hop-uri: clientul plus starile releelor.
    fn circuit(n: usize) -> (ClientCircuit, Vec<RelayCircuit>) {
        let mut c = ClientCircuit::new();
        let mut r = Vec::new();
        for i in 0..n {
            let s = seed(i as u8 + 1);
            c.add_hop(&s);
            r.push(RelayCircuit::new(&s));
        }
        (c, r)
    }

    #[test]
    fn material_de_cheie_are_lungimea_asteptata() {
        assert_eq!(KEY_MATERIAL_LEN, 160);
    }

    /// Client -> hop d. Releele dinainte trebuie sa dea `Forward`, hop-ul d
    /// trebuie sa dea `Recognized` cu exact corpul original.
    fn dus(n: usize, d: usize) {
        let (mut cli, mut rel) = circuit(n);
        let m = corp(0xA0);
        let mut cell = cli.encrypt_outbound(d, AD, &m).unwrap();

        for (i, r) in rel.iter_mut().enumerate().take(d) {
            match r.process_outbound(AD, &cell) {
                Outbound::Recognized(body) => {
                    assert_eq!(i + 1, d, "hop-ul gresit a recunoscut celula");
                    assert_eq!(&body[..], &m[..], "corpul difera");
                    return;
                }
                Outbound::Forward(next) => {
                    assert!(i + 1 < d, "hop-ul {} ar fi trebuit sa recunoasca", i + 1);
                    cell = next;
                }
            }
        }
        panic!("niciun hop nu a recunoscut celula");
    }

    #[test]
    fn dus_toate_combinatiile() {
        for n in 1..=4 {
            for d in 1..=n {
                dus(n, d);
            }
        }
    }

    /// Hop d -> client, trecand prin releele dinainte cu `PROC_OR`.
    fn intors(n: usize, d: usize) {
        let (mut cli, mut rel) = circuit(n);
        let m = corp(0xB0);

        let mut cell = rel[d - 1].originate_inbound(AD, &m);
        for i in (0..d - 1).rev() {
            cell = rel[i].relay_inbound(AD, &cell);
        }

        let (hop, body) = cli.decrypt_inbound(AD, &cell).unwrap();
        assert_eq!(hop, d, "clientul a identificat gresit hop-ul sursa");
        assert_eq!(&body[..], &m[..], "corpul difera");
    }

    #[test]
    fn intors_toate_combinatiile() {
        for n in 1..=4 {
            for d in 1..=n {
                intors(n, d);
            }
        }
    }

    #[test]
    fn conversatie_lunga_pastreaza_sincronizarea() {
        // Ratchet-ul avanseaza la fiecare celula recunoscuta. Daca cele doua
        // parti nu actualizeaza identic, sincronizarea se pierde dupa cateva
        // celule. 50 de dus-intors verifica asta.
        let (mut cli, mut rel) = circuit(3);
        for k in 0..50u8 {
            let m = corp(k);
            let mut cell = cli.encrypt_outbound(3, AD, &m).unwrap();
            cell = match rel[0].process_outbound(AD, &cell) {
                Outbound::Forward(c) => c,
                _ => panic!("hop 1 nu trebuia sa recunoasca la runda {k}"),
            };
            cell = match rel[1].process_outbound(AD, &cell) {
                Outbound::Forward(c) => c,
                _ => panic!("hop 2 nu trebuia sa recunoasca la runda {k}"),
            };
            match rel[2].process_outbound(AD, &cell) {
                Outbound::Recognized(b) => assert_eq!(&b[..], &m[..]),
                _ => panic!("hop 3 trebuia sa recunoasca la runda {k}"),
            }

            let raspuns = corp(k.wrapping_add(128));
            let mut c = rel[2].originate_inbound(AD, &raspuns);
            c = rel[1].relay_inbound(AD, &c);
            c = rel[0].relay_inbound(AD, &c);
            let (hop, body) = cli.decrypt_inbound(AD, &c).unwrap();
            assert_eq!(hop, 3);
            assert_eq!(&body[..], &raspuns[..], "divergenta la runda {k}");
        }
    }

    #[test]
    fn hop_uri_diferite_alternat() {
        // Trafic catre hop-uri diferite, intercalat: starile nu trebuie sa se
        // contamineze intre ele.
        let (mut cli, mut rel) = circuit(3);
        for k in 0..10u8 {
            for d in 1..=3usize {
                let m = corp(k.wrapping_add(d as u8));
                let mut cell = cli.encrypt_outbound(d, AD, &m).unwrap();
                let mut gasit = false;
                for (i, r) in rel.iter_mut().enumerate().take(d) {
                    match r.process_outbound(AD, &cell) {
                        Outbound::Recognized(b) => {
                            assert_eq!(i + 1, d);
                            assert_eq!(&b[..], &m[..]);
                            gasit = true;
                            break;
                        }
                        Outbound::Forward(c) => cell = c,
                    }
                }
                assert!(gasit, "pierdut la runda {k}, hop {d}");
            }
        }
    }

    #[test]
    fn tagging_e_detectat() {
        // Un releu ostil modifica un bit. Hop-ul destinatie nu trebuie sa
        // recunoasca celula.
        for poz in [0usize, 15, 16, 200, MSG_LEN - 1] {
            let (mut cli, mut rel) = circuit(2);
            let m = corp(0xC0);
            let mut cell = cli.encrypt_outbound(2, AD, &m).unwrap();
            cell = match rel[0].process_outbound(AD, &cell) {
                Outbound::Forward(c) => c,
                _ => panic!("hop 1 nu trebuia sa recunoasca"),
            };
            cell[poz] ^= 0x01;
            match rel[1].process_outbound(AD, &cell) {
                Outbound::Forward(_) => {}
                Outbound::Recognized(_) => {
                    panic!("modificarea la pozitia {poz} nu a fost detectata")
                }
            }
        }
    }

    #[test]
    fn celula_modificata_pe_retur_e_respinsa() {
        let (mut cli, mut rel) = circuit(3);
        let m = corp(0xD0);
        let mut cell = rel[2].originate_inbound(AD, &m);
        cell = rel[1].relay_inbound(AD, &cell);
        cell = rel[0].relay_inbound(AD, &cell);
        cell[100] ^= 0x01;
        assert_eq!(
            cli.decrypt_inbound(AD, &cell).err(),
            Some(CgoError::NotRecognized)
        );
    }

    #[test]
    fn ad_diferit_rupe_decriptarea() {
        // `AD` distinge RELAY de RELAY_EARLY. Daca un atacator schimba comanda
        // celulei, celula devine nedecriptabila.
        let (mut cli, mut rel) = circuit(1);
        let m = corp(0xE0);
        let cell = cli.encrypt_outbound(1, AD, &m).unwrap();
        match rel[0].process_outbound(AD ^ 0x0C, &cell) {
            Outbound::Forward(_) => {}
            Outbound::Recognized(_) => panic!("AD schimbat nu a fost detectat"),
        }
    }

    #[test]
    fn forward_secrecy_imediata() {
        // Dupa ce o celula a fost procesata, aceeasi celula retrimisa nu mai
        // poate fi recunoscuta: cheia s-a schimbat. Asta e si apararea contra
        // reluarii.
        let (mut cli, mut rel) = circuit(1);
        let m = corp(0xF0);
        let cell = cli.encrypt_outbound(1, AD, &m).unwrap();
        assert!(matches!(
            rel[0].process_outbound(AD, &cell),
            Outbound::Recognized(_)
        ));
        assert!(
            matches!(rel[0].process_outbound(AD, &cell), Outbound::Forward(_)),
            "reluarea aceleiasi celule ar fi trebuit respinsa"
        );
    }

    #[test]
    fn hop_invalid_e_respins() {
        let (mut cli, _) = circuit(2);
        let m = corp(1);
        assert_eq!(cli.encrypt_outbound(0, AD, &m).err(), Some(CgoError::BadHop));
        assert_eq!(cli.encrypt_outbound(3, AD, &m).err(), Some(CgoError::BadHop));
    }

    #[test]
    fn circuit_gol() {
        let mut cli = ClientCircuit::new();
        assert!(cli.is_empty());
        assert_eq!(
            cli.decrypt_inbound(AD, &[0u8; MSG_LEN]).err(),
            Some(CgoError::EmptyCircuit)
        );
    }

    #[test]
    fn debug_nu_scurge_nimic() {
        let (cli, rel) = circuit(2);
        assert_eq!(format!("{cli:?}"), "ClientCircuit(2 hop-uri)");
        assert_eq!(format!("{:?}", rel[0]), "RelayCircuit(redacted)");
    }
}
