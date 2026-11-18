//! Introducere si rendezvous.
//!
//! # Fluxul
//!
//! ```text
//!   serviciu -> IP    ESTABLISH_INTRO      (isi anunta cheia de autentificare)
//!   client   -> RP    ESTABLISH_RENDEZVOUS (lasa un cookie)
//!   client   -> IP    INTRODUCE1           (criptat pentru serviciu)
//!   IP       -> serv  INTRODUCE2           (acelasi corp, retransmis)
//!   serv     -> RP    RENDEZVOUS1          (cookie + partea de server a handshake-ului)
//!   RP       -> cli   RENDEZVOUS2          (doar partea de server)
//! ```
//!
//! Dupa RENDEZVOUS2 ambele parti au acelasi `KEY_SEED` si construiesc un hop
//! virtual peste circuitele deja existente. Rezulta o cale de sase hop-uri.
//!
//! # Cine e clientul si cine e releul
//!
//! Pe hop-ul virtual, **serviciul joaca rolul de releu**, nu de client. E
//! consecinta directa a asimetriei CGO: `ENC_UIV` e nemaleabil, `DEC_UIV` nu e,
//! iar partea nemaleabila trebuie sa fie la capatul care raspunde. Serviciul
//! foloseste `pqo_crypto::cgo::RelayCircuit`, clientul `ClientCircuit`. Daca
//! inversezi, totul compileaza si roundtrip-ul trece — dar pierzi rezistenta la
//! tagging exact pe segmentul cel mai sensibil.
//!
//! # De ce nu e nevoie de un PROTOID separat
//!
//! Handshake-ul e acelasi `pq-ntor` folosit la extinderea de circuit. Separarea
//! de domeniu vine din campul de identitate care intra in transcript: pentru un
//! releu e `SHAKE256("pqonion-fingerprint-v1" ‖ pk)`, pentru un serviciu ascuns
//! e identificatorul adresei, derivat cu eticheta `"pqonion-hs-addr-v1"`.
//! Etichetele fiind distincte, o valoare nu poate aparea in ambele roluri.

use pqo_crypto::kdf;
use pqo_crypto::kem::Kem;
use pqo_crypto::sig::Sig;
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;

use crate::desc::IntroPoint;
use crate::HsError;

/// Lungimea cookie-ului de rendezvous.
///
/// 20 de octeti din generator criptografic. Punctul de rendezvous il stocheaza
/// fara sa stie cine e clientul si fara sa poata lega cele doua circuite decat
/// prin el.
pub const COOKIE_LEN: usize = 20;
/// Lungimea tag-ului de autentificare al corpului INTRODUCE.
pub const TAG_LEN: usize = 32;

pub type Cookie = [u8; COOKIE_LEN];

/// Cheia de incapsulare a unui punct de introducere.
///
/// Aranjamentul `x25519 ‖ kem` coincide exact cu forma serializata a lui
/// `pqo_crypto::kem::Hybrid`, deci se poate pasa direct lui `K::encapsulate`.
pub fn intro_enc_key(ip: &IntroPoint) -> Vec<u8> {
    let mut v = ip.onion_x25519.to_vec();
    if let Some(k) = &ip.onion_kem {
        v.extend_from_slice(k);
    }
    v
}

/// Identificatorul unui punct de introducere, derivat din cheia lui de autentificare.
pub fn auth_key_id(auth_key: &[u8]) -> [u8; 32] {
    kdf::hash(b"pqonion-hs-authkeyid-v1", &[auth_key])
}

/// Citeste un camp prefixat cu lungimea pe doi octeti.
fn take_lp(buf: &[u8]) -> Result<(&[u8], &[u8]), HsError> {
    if buf.len() < 2 {
        return Err(HsError::BadRendMessage);
    }
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + n {
        return Err(HsError::BadRendMessage);
    }
    Ok((&buf[2..2 + n], &buf[2 + n..]))
}

// ---------------------------------------------------------------------------
// ESTABLISH_INTRO
// ---------------------------------------------------------------------------

/// Serviciul isi anunta prezenta la un punct de introducere.
///
/// Semnatura leaga cheia de autentificare de circuitul curent. Fara legare, un
/// atacator ar putea relua mesajul pe alt circuit si ar prelua rolul.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishIntro {
    pub auth_key: Vec<u8>,
    pub sig: Vec<u8>,
}

fn establish_body(auth_key: &[u8], circuit_binding: &[u8]) -> [u8; 32] {
    kdf::hash(
        b"pqonion-hs-establish-intro-v1",
        &[auth_key, circuit_binding],
    )
}

impl EstablishIntro {
    pub fn new<S: Sig>(sk: &S::SecretKey, auth_key: Vec<u8>, circuit_binding: &[u8]) -> Self {
        let sig = S::sign(sk, &establish_body(&auth_key, circuit_binding));
        EstablishIntro { auth_key, sig }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.auth_key.len() + self.sig.len());
        out.extend_from_slice(&(self.auth_key.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.auth_key);
        out.extend_from_slice(&(self.sig.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    pub fn parse(buf: &[u8]) -> Result<Self, HsError> {
        let (auth_key, rest) = take_lp(buf)?;
        let (sig, rest) = take_lp(rest)?;
        if !rest.is_empty() {
            return Err(HsError::BadRendMessage);
        }
        Ok(EstablishIntro {
            auth_key: auth_key.to_vec(),
            sig: sig.to_vec(),
        })
    }

    /// Verificarea pe care o face punctul de introducere.
    pub fn verify<S: Sig>(&self, circuit_binding: &[u8]) -> Result<(), HsError> {
        S::verify(
            &self.auth_key,
            &establish_body(&self.auth_key, circuit_binding),
            &self.sig,
        )
        .map_err(|_| HsError::BadSignature)
    }
}

// ---------------------------------------------------------------------------
// INTRODUCE1 / INTRODUCE2
// ---------------------------------------------------------------------------

/// Ce ii spune clientul serviciului, criptat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntroPayload {
    pub cookie: Cookie,
    /// Fingerprint-ul releului ales ca punct de rendezvous.
    pub rp_relay_id: [u8; 32],
    /// Unde se afla punctul de rendezvous.
    ///
    /// Fara adresa, serviciul ar sti *pe cine* sa contacteze dar nu si *unde*,
    /// si ar trebui sa caute in consens — ceea ce ar cere ca serviciul sa aiba
    /// mereu un consens proaspat. Clientul a ales deja releul, deci stie adresa;
    /// o trimite. Tor face la fel, prin link specifiers.
    pub rp_address: String,
    pub rp_port: u16,
    /// Partea de client a handshake-ului `pq-ntor`.
    pub handshake: Vec<u8>,
}

impl IntroPayload {
    fn encode(&self) -> Vec<u8> {
        let a = self.rp_address.as_bytes();
        let mut out = Vec::with_capacity(COOKIE_LEN + 32 + 5 + a.len() + self.handshake.len());
        out.extend_from_slice(&self.cookie);
        out.extend_from_slice(&self.rp_relay_id);
        out.extend_from_slice(&(a.len() as u16).to_be_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(&self.rp_port.to_be_bytes());
        out.extend_from_slice(&(self.handshake.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.handshake);
        out
    }

    fn parse(buf: &[u8]) -> Result<Self, HsError> {
        if buf.len() < COOKIE_LEN + 32 {
            return Err(HsError::BadRendMessage);
        }
        let cookie: Cookie = buf[..COOKIE_LEN].try_into().expect("lungime verificata");
        let rp_relay_id: [u8; 32] = buf[COOKIE_LEN..COOKIE_LEN + 32]
            .try_into()
            .expect("lungime verificata");
        let (adr, rest) = take_lp(&buf[COOKIE_LEN + 32..])?;
        let rp_address = core::str::from_utf8(adr)
            .map_err(|_| HsError::BadRendMessage)?
            .to_string();
        // Adresa ajunge intr-un apel de conectare; caracterele de control n-au
        // ce cauta acolo.
        if rp_address.is_empty()
            || rp_address.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(HsError::BadRendMessage);
        }
        if rest.len() < 2 {
            return Err(HsError::BadRendMessage);
        }
        let rp_port = u16::from_be_bytes([rest[0], rest[1]]);
        if rp_port == 0 {
            return Err(HsError::BadRendMessage);
        }
        let (handshake, rest) = take_lp(&rest[2..])?;
        if !rest.is_empty() {
            return Err(HsError::BadRendMessage);
        }
        Ok(IntroPayload {
            cookie,
            rp_relay_id,
            rp_address,
            rp_port,
            handshake: handshake.to_vec(),
        })
    }
}

/// Mesajul care circula de la client la punctul de introducere, si de acolo mai
/// departe la serviciu sub numele INTRODUCE2. Corpul e identic; doar comanda de
/// pe fir difera.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Introduce {
    pub auth_key_id: [u8; 32],
    /// Ciphertext-ul KEM catre cheia punctului de introducere.
    pub kem_ct: Vec<u8>,
    /// `tag ‖ ciphertext` al corpului.
    pub sealed: Vec<u8>,
}

fn intro_keys(ss: &[u8], akid: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut k = [0u8; 64];
    kdf::hash_xof(b"pqonion-hs-intro-key-v1", &[ss, akid], &mut k);
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&k[..32]);
    mac.copy_from_slice(&k[32..]);
    (enc, mac)
}

impl Introduce {
    /// Construieste INTRODUCE1, incapsuland catre cheia punctului de introducere.
    ///
    /// `K` trebuie sa fie acelasi KEM pe care il anunta descriptorul: `X25519Kem`
    /// daca `onion_kem` lipseste, hibridul altfel.
    pub fn seal<K: Kem>(
        ip: &IntroPoint,
        payload: &IntroPayload,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, HsError> {
        let akid = auth_key_id(&ip.auth_key);
        let (kem_ct, ss) =
            K::encapsulate(&intro_enc_key(ip), rng).map_err(|_| HsError::BadRendMessage)?;
        let (enc, mac) = intro_keys(ss.as_bytes(), &akid);

        let plain = payload.encode();
        let mut ct = vec![0u8; plain.len()];
        kdf::hash_xof(b"pqonion-hs-intro-stream-v1", &[&enc], &mut ct);
        for (c, p) in ct.iter_mut().zip(&plain) {
            *c ^= p;
        }
        let tag = kdf::hash(b"pqonion-hs-intro-mac-v1", &[&mac, &ct]);

        let mut sealed = Vec::with_capacity(TAG_LEN + ct.len());
        sealed.extend_from_slice(&tag);
        sealed.extend_from_slice(&ct);
        Ok(Introduce {
            auth_key_id: akid,
            kem_ct,
            sealed,
        })
    }

    /// Deschide corpul. Doar serviciul poate: are cheia de decapsulare.
    pub fn open<K: Kem>(&self, dk: &K::DecapKey) -> Result<IntroPayload, HsError> {
        if self.sealed.len() < TAG_LEN {
            return Err(HsError::BadRendMessage);
        }
        let ss = K::decapsulate(dk, &self.kem_ct).map_err(|_| HsError::BadRendMessage)?;
        let (enc, mac) = intro_keys(ss.as_bytes(), &self.auth_key_id);

        let (tag_primit, ct) = self.sealed.split_at(TAG_LEN);
        let tag = kdf::hash(b"pqonion-hs-intro-mac-v1", &[&mac, ct]);
        if !bool::from(tag.ct_eq(tag_primit)) {
            return Err(HsError::BadInnerTag);
        }
        let mut plain = vec![0u8; ct.len()];
        kdf::hash_xof(b"pqonion-hs-intro-stream-v1", &[&enc], &mut plain);
        for (p, c) in plain.iter_mut().zip(ct) {
            *p ^= c;
        }
        IntroPayload::parse(&plain)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + self.kem_ct.len() + self.sealed.len());
        out.extend_from_slice(&self.auth_key_id);
        out.extend_from_slice(&(self.kem_ct.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.kem_ct);
        out.extend_from_slice(&(self.sealed.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.sealed);
        out
    }

    pub fn parse(buf: &[u8]) -> Result<Self, HsError> {
        if buf.len() < 32 {
            return Err(HsError::BadRendMessage);
        }
        let auth_key_id: [u8; 32] = buf[..32].try_into().expect("lungime verificata");
        let (kem_ct, rest) = take_lp(&buf[32..])?;
        let (sealed, rest) = take_lp(rest)?;
        if !rest.is_empty() {
            return Err(HsError::BadRendMessage);
        }
        Ok(Introduce {
            auth_key_id,
            kem_ct: kem_ct.to_vec(),
            sealed: sealed.to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// Rendezvous
// ---------------------------------------------------------------------------

/// Genereaza un cookie de rendezvous.
pub fn new_cookie(rng: &mut impl CryptoRngCore) -> Cookie {
    let mut c = [0u8; COOKIE_LEN];
    rng.fill_bytes(&mut c);
    c
}

/// Punctul de rendezvous: imperecheaza doua circuite dupa cookie.
///
/// Nu afla nimic despre cine sunt cele doua parti. Vede doua circuite si un
/// cookie de 20 de octeti care se potriveste. Asta e tot rolul lui.
#[derive(Debug, Default)]
pub struct RendezvousPoint {
    asteptare: Vec<(Cookie, u64)>,
}

impl RendezvousPoint {
    /// Cate circuite in asteptare accepta. Fara plafon, oricine poate epuiza
    /// memoria trimitand ESTABLISH_RENDEZVOUS la nesfarsit.
    pub const MAX_PENDING: usize = 1024;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn pending(&self) -> usize {
        self.asteptare.len()
    }

    /// Clientul lasa un cookie si asteapta.
    pub fn establish(&mut self, cookie: Cookie, circuit: u64) -> Result<(), HsError> {
        if self.asteptare.len() >= Self::MAX_PENDING {
            return Err(HsError::StoreFull);
        }
        // Un cookie deja folosit nu se suprascrie: altfel oricine poate deturna
        // rendezvous-ul altcuiva reluand un cookie observat.
        if self
            .asteptare
            .iter()
            .any(|(c, _)| bool::from(c.ct_eq(&cookie)))
        {
            return Err(HsError::SlotOccupied);
        }
        self.asteptare.push((cookie, circuit));
        Ok(())
    }

    /// Serviciul soseste cu RENDEZVOUS1. Intoarce circuitul clientului.
    pub fn join(&mut self, cookie: &Cookie) -> Result<u64, HsError> {
        let pos = self
            .asteptare
            .iter()
            .position(|(c, _)| bool::from(c.ct_eq(cookie)))
            .ok_or(HsError::BadCookie)?;
        Ok(self.asteptare.remove(pos).1)
    }
}

/// RENDEZVOUS1: de la serviciu catre punctul de rendezvous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendezvous1 {
    pub cookie: Cookie,
    /// Partea de server a handshake-ului `pq-ntor`.
    pub handshake: Vec<u8>,
}

impl Rendezvous1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COOKIE_LEN + self.handshake.len());
        out.extend_from_slice(&self.cookie);
        out.extend_from_slice(&self.handshake);
        out
    }

    pub fn parse(buf: &[u8]) -> Result<Self, HsError> {
        if buf.len() <= COOKIE_LEN {
            return Err(HsError::BadRendMessage);
        }
        Ok(Rendezvous1 {
            cookie: buf[..COOKIE_LEN].try_into().expect("lungime verificata"),
            handshake: buf[COOKIE_LEN..].to_vec(),
        })
    }

    /// RENDEZVOUS2 e RENDEZVOUS1 fara cookie: punctul de rendezvous il taie
    /// inainte sa retransmita, ca sa nu ajunga inapoi la client.
    pub fn to_rendezvous2(&self) -> Vec<u8> {
        self.handshake.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqo_crypto::kem::{Hybrid, X25519Kem};
    use pqo_crypto::sig::Ed25519;
    use rand_core::OsRng;

    type S = Ed25519;
    type K = Hybrid<X25519Kem, X25519Kem>;

    fn punct(rng: &mut impl CryptoRngCore) -> (IntroPoint, <K as Kem>::DecapKey) {
        let (dk, ek) = K::keygen(rng);
        let (_ask, apk) = S::keygen(rng);
        let ip = IntroPoint {
            relay_id: [3u8; 32],
            onion_x25519: ek[..32].try_into().unwrap(),
            onion_kem: Some(ek[32..].to_vec()),
            svc_x25519: [0u8; 32],
            auth_key: apk,
        };
        (ip, dk)
    }

    fn payload() -> IntroPayload {
        IntroPayload {
            cookie: [7u8; COOKIE_LEN],
            rp_relay_id: [9u8; 32],
            rp_address: "10.0.0.5".into(),
            rp_port: 9001,
            handshake: vec![0xAB; 1312],
        }
    }

    #[test]
    fn adresa_de_rendezvous_e_validata() {
        let mut rng = OsRng;
        let (ip, dk) = punct(&mut rng);
        for rea in ["", "a b", "a\nb"] {
            let mut p = payload();
            p.rp_address = rea.into();
            let m = Introduce::seal::<K>(&ip, &p, &mut rng).unwrap();
            assert!(m.open::<K>(&dk).is_err(), "acceptat: {rea:?}");
        }
        let mut p = payload();
        p.rp_port = 0;
        let m = Introduce::seal::<K>(&ip, &p, &mut rng).unwrap();
        assert!(m.open::<K>(&dk).is_err(), "portul zero trebuie respins");
    }

    #[test]
    fn cheia_de_incapsulare_are_forma_hibrida() {
        let mut rng = OsRng;
        let (ip, _dk) = punct(&mut rng);
        assert_eq!(intro_enc_key(&ip).len(), K::EK_LEN);
    }

    #[test]
    fn introduce_roundtrip() {
        let mut rng = OsRng;
        let (ip, dk) = punct(&mut rng);
        let p = payload();
        let m = Introduce::seal::<K>(&ip, &p, &mut rng).unwrap();
        assert_eq!(m.open::<K>(&dk).unwrap(), p);
    }

    #[test]
    fn introduce_roundtrip_pe_fir() {
        let mut rng = OsRng;
        let (ip, dk) = punct(&mut rng);
        let p = payload();
        let m = Introduce::seal::<K>(&ip, &p, &mut rng).unwrap();
        let refacut = Introduce::parse(&m.encode()).unwrap();
        assert_eq!(refacut, m);
        assert_eq!(refacut.open::<K>(&dk).unwrap(), p);
    }

    #[test]
    fn punctul_de_introducere_nu_poate_citi_corpul() {
        // Punctul de introducere are cheia de autentificare, dar nu si cheia de
        // decapsulare a serviciului. Retransmite fara sa afle nimic.
        let mut rng = OsRng;
        let (ip, _dk) = punct(&mut rng);
        let (alt_dk, _ek) = K::keygen(&mut rng);
        let m = Introduce::seal::<K>(&ip, &payload(), &mut rng).unwrap();
        assert!(m.open::<K>(&alt_dk).is_err());
    }

    #[test]
    fn corp_modificat_e_respins() {
        let mut rng = OsRng;
        let (ip, dk) = punct(&mut rng);
        let mut m = Introduce::seal::<K>(&ip, &payload(), &mut rng).unwrap();
        let n = m.sealed.len();
        m.sealed[n - 1] ^= 0x01;
        assert_eq!(m.open::<K>(&dk), Err(HsError::BadInnerTag));
    }

    #[test]
    fn establish_intro_roundtrip() {
        let mut rng = OsRng;
        let (sk, pk) = S::keygen(&mut rng);
        let binding = [0x5Au8; 32];
        let e = EstablishIntro::new::<S>(&sk, pk, &binding);
        let refacut = EstablishIntro::parse(&e.encode()).unwrap();
        assert_eq!(refacut, e);
        refacut.verify::<S>(&binding).unwrap();
    }

    #[test]
    fn establish_intro_pe_alt_circuit_e_respins() {
        // Reluarea mesajului pe alt circuit trebuie sa esueze.
        let mut rng = OsRng;
        let (sk, pk) = S::keygen(&mut rng);
        let e = EstablishIntro::new::<S>(&sk, pk, &[1u8; 32]);
        assert_eq!(
            e.verify::<S>(&[2u8; 32]),
            Err(HsError::BadSignature),
            "legarea de circuit trebuie sa impiedice reluarea"
        );
    }

    #[test]
    fn rendezvous_imperecheaza_dupa_cookie() {
        let mut rng = OsRng;
        let mut rp = RendezvousPoint::new();
        let c = new_cookie(&mut rng);
        rp.establish(c, 42).unwrap();
        assert_eq!(rp.pending(), 1);
        assert_eq!(rp.join(&c).unwrap(), 42);
        assert_eq!(rp.pending(), 0);
        assert_eq!(rp.join(&c), Err(HsError::BadCookie));
    }

    #[test]
    fn cookie_gresit_nu_imperecheaza() {
        let mut rng = OsRng;
        let mut rp = RendezvousPoint::new();
        rp.establish(new_cookie(&mut rng), 1).unwrap();
        assert_eq!(rp.join(&[0u8; COOKIE_LEN]), Err(HsError::BadCookie));
    }

    #[test]
    fn cookie_duplicat_nu_deturneaza() {
        let mut rp = RendezvousPoint::new();
        let c = [1u8; COOKIE_LEN];
        rp.establish(c, 1).unwrap();
        assert_eq!(rp.establish(c, 2), Err(HsError::SlotOccupied));
        assert_eq!(rp.join(&c).unwrap(), 1, "primul ramane");
    }

    #[test]
    fn rendezvous_are_plafon() {
        let mut rp = RendezvousPoint::new();
        for i in 0..RendezvousPoint::MAX_PENDING {
            let mut c = [0u8; COOKIE_LEN];
            c[..8].copy_from_slice(&(i as u64).to_le_bytes());
            rp.establish(c, i as u64).unwrap();
        }
        assert_eq!(rp.establish([0xFF; COOKIE_LEN], 0), Err(HsError::StoreFull));
    }

    #[test]
    fn rendezvous1_roundtrip() {
        let r = Rendezvous1 {
            cookie: [4u8; COOKIE_LEN],
            handshake: vec![0xCD; 1184],
        };
        let refacut = Rendezvous1::parse(&r.encode()).unwrap();
        assert_eq!(refacut, r);
        assert_eq!(refacut.to_rendezvous2(), r.handshake);
    }

    #[test]
    fn niciun_prefix_nu_produce_panica() {
        let mut rng = OsRng;
        let (ip, _dk) = punct(&mut rng);
        let m = Introduce::seal::<K>(&ip, &payload(), &mut rng).unwrap();
        let (sk, pk) = S::keygen(&mut rng);
        let e = EstablishIntro::new::<S>(&sk, pk, &[0u8; 32]);
        let r = Rendezvous1 {
            cookie: [1u8; COOKIE_LEN],
            handshake: vec![2u8; 100],
        };
        for buf in [m.encode(), e.encode(), r.encode()] {
            for n in 0..=buf.len() {
                let _ = Introduce::parse(&buf[..n]);
                let _ = EstablishIntro::parse(&buf[..n]);
                let _ = Rendezvous1::parse(&buf[..n]);
            }
        }
    }
}
