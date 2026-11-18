//! Derivare de chei si hashing cu separare de domeniu.
//!
//! # De ce tuple-hashing si nu concatenare simpla
//!
//! ntor-ul clasic din Tor hash-uieste `secret_input` ca simpla concatenare de
//! campuri. Asta e sigur *doar* pentru ca toate campurile au lungime fixa si
//! cunoscuta (32 de octeti fiecare), deci codarea e injectiva implicit.
//!
//! In momentul in care introducem un KEM post-cuantic, invariantul cade:
//! ciphertext-ul si cheia de incapsulare au lungimi care depind de schema
//! (ML-KEM-768 -> 1088 / 1184 octeti, X25519 -> 32). Daca am concatena naiv,
//! doua tuple diferite de campuri ar putea produce acelasi flux de octeti, deci
//! acelasi `KEY_SEED`. Asta e o clasa reala de atac, nu paranoia teoretica.
//!
//! Solutia: fiecare component se prefixeaza cu lungimea lui pe 8 octeti
//! little-endian. Codarea rezultata e injectiva pentru orice tuplu de secvente
//! de octeti, deci nu exista coliziuni intre tuple distincte.
//!
//! Eticheta de domeniu se prefixeaza la fel, ceea ce garanteaza ca doua
//! utilizari diferite ale aceleiasi functii (ex. `t_key` vs `t_mac`) nu pot
//! produce niciodata aceeasi iesire pentru aceeasi intrare.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::Zeroize;

/// Prefixul global de protocol. Schimbarea lui invalideaza toate handshake-urile
/// vechi, deci functioneaza ca versionare criptografica.
pub const PROTOID: &[u8] = b"pqonion-ntor-v1";

/// Etichete de domeniu. Fiecare are un scop unic; nu le refolosi.
pub mod label {
    pub const KEY_SEED: &[u8] = b"pqonion-ntor-v1:key_seed";
    pub const VERIFY: &[u8] = b"pqonion-ntor-v1:verify";
    pub const AUTH: &[u8] = b"pqonion-ntor-v1:auth";
    pub const EXPAND: &[u8] = b"pqonion-ntor-v1:expand";
    pub const KEM_COMBINE: &[u8] = b"pqonion-kem-combine-v1";
}

/// Lungimea standard a unei iesiri de hash in acest protocol.
pub const HASH_LEN: usize = 32;

/// Scrie `len(part) || part` in absorber.
#[inline]
fn absorb_framed(h: &mut Shake256, part: &[u8]) {
    h.update(&(part.len() as u64).to_le_bytes());
    h.update(part);
}

/// Tuple-hash cu separare de domeniu, iesire de lungime arbitrara.
///
/// Codarea absorbita este `len(label) || label || len(p0) || p0 || ...`,
/// care e injectiva in `(label, parts)`.
pub fn hash_xof(label: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake256::default();
    absorb_framed(&mut h, label);
    for p in parts {
        absorb_framed(&mut h, p);
    }
    h.finalize_xof().read(out);
}

/// Tuple-hash cu separare de domeniu, iesire de 32 de octeti.
pub fn hash(label: &[u8], parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    hash_xof(label, parts, &mut out);
    out
}

/// Material de cheie derivat dintr-un handshake reusit.
///
/// Se zeroizeaza la `Drop`. Nu implementeaza `Clone` intentionat: daca ai nevoie
/// de o copie a materialului de cheie, aproape sigur ai o problema de design.
#[derive(Zeroize, zeroize::ZeroizeOnDrop)]
pub struct KeySeed(pub(crate) [u8; HASH_LEN]);

impl KeySeed {
    /// Construieste un `KeySeed` din octeti bruti.
    ///
    /// In flux normal, seed-urile vin doar din `pq-ntor`. Constructorul e public
    /// pentru teste si pentru cazul serviciilor ascunse, unde cheia hop-ului
    /// virtual e derivata separat.
    pub fn new(bytes: [u8; HASH_LEN]) -> Self {
        KeySeed(bytes)
    }

    /// Expandeaza seed-ul in `out.len()` octeti de material de cheie.
    ///
    /// Aici se taie cheile pentru stratul de criptare al celulelor (forward /
    /// backward, chei de bloc, chei CTR, chei de hash polinomial pentru CGO).
    pub fn expand(&self, out: &mut [u8]) {
        hash_xof(label::EXPAND, &[&self.0], out);
    }

    /// Expandeaza intr-un vector de lungime data.
    pub fn expand_vec(&self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.expand(&mut v);
        v
    }

    /// Acces la octetii bruti. Folosit doar in teste si la derivarea interna.
    #[doc(hidden)]
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for KeySeed {
    /// Nu scurge niciodata material de cheie in loguri. Vezi politica de logging
    /// din documentul de arhitectura, §6.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeySeed(redacted)")
    }
}

/// Generator determinist de numere aleatoare, construit peste SHAKE256.
///
/// Exista pentru un singur motiv: serviciile ascunse au nevoie sa **rederive**
/// aceeasi cheie de semnare pentru o perioada de timp data, pornind de la o
/// samanta master. Fara asta, un serviciu care reporneste ar pierde controlul
/// descriptorului publicat.
///
/// E `CryptoRng` pentru ca SHAKE256 e un XOF criptografic: iesirea e
/// indistinctibila de aleator pentru cine nu cunoaste samanta. Dar **nu il
/// folosi niciodata cu o samanta care nu e ea insasi secreta si de entropie
/// completa** — determinismul care il face util aici il face catastrofal
/// oriunde altundeva.
pub struct ShakeRng(<Shake256 as ExtendableOutput>::Reader);

impl core::fmt::Debug for ShakeRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ShakeRng(redacted)")
    }
}

impl ShakeRng {
    /// Construieste un generator din eticheta si componente, cu aceeasi codare
    /// injectiva ca [`hash`].
    pub fn new(label: &[u8], parts: &[&[u8]]) -> Self {
        let mut h = Shake256::default();
        absorb_framed(&mut h, label);
        for p in parts {
            absorb_framed(&mut h, p);
        }
        ShakeRng(h.finalize_xof())
    }
}

impl rand_core::RngCore for ShakeRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.read(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.read(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.read(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for ShakeRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separarea_de_domeniu_functioneaza() {
        let a = hash(label::KEY_SEED, &[b"acelasi input"]);
        let b = hash(label::VERIFY, &[b"acelasi input"]);
        assert_ne!(a, b, "etichete diferite trebuie sa dea iesiri diferite");
    }

    #[test]
    fn codarea_e_injectiva() {
        // Fara framing, ("ab", "c") si ("a", "bc") ar produce acelasi flux.
        let a = hash(label::KEY_SEED, &[b"ab", b"c"]);
        let b = hash(label::KEY_SEED, &[b"a", b"bc"]);
        assert_ne!(a, b, "framing-ul pe lungime trebuie sa separe tuplele");

        // Si cazul degenerat: sir vid vs. absenta campului.
        let c = hash(label::KEY_SEED, &[b"x", b""]);
        let d = hash(label::KEY_SEED, &[b"x"]);
        assert_ne!(c, d);
    }

    #[test]
    fn expand_e_determinist_si_de_lungime_arbitrara() {
        let seed = KeySeed::new([7u8; 32]);
        let a = seed.expand_vec(128);
        let b = seed.expand_vec(128);
        assert_eq!(a, b);
        // Prefixul unei iesiri mai lungi trebuie sa coincida (proprietate XOF).
        let lung = seed.expand_vec(256);
        assert_eq!(&lung[..128], &a[..]);
    }

    #[test]
    fn shake_rng_e_determinist() {
        use rand_core::RngCore;
        let mut a = ShakeRng::new(b"test", &[b"samanta"]);
        let mut b = ShakeRng::new(b"test", &[b"samanta"]);
        let mut x = [0u8; 64];
        let mut y = [0u8; 64];
        a.fill_bytes(&mut x);
        b.fill_bytes(&mut y);
        assert_eq!(x, y);

        // Samanta diferita da flux diferit.
        let mut c = ShakeRng::new(b"test", &[b"alta"]);
        let mut z = [0u8; 64];
        c.fill_bytes(&mut z);
        assert_ne!(x, z);

        // Eticheta diferita, la fel.
        let mut d = ShakeRng::new(b"altceva", &[b"samanta"]);
        let mut w = [0u8; 64];
        d.fill_bytes(&mut w);
        assert_ne!(x, w);
    }

    #[test]
    fn shake_rng_nu_se_repeta() {
        use rand_core::RngCore;
        let mut r = ShakeRng::new(b"test", &[b"s"]);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        r.fill_bytes(&mut a);
        r.fill_bytes(&mut b);
        assert_ne!(a, b, "apeluri succesive trebuie sa dea octeti noi");
    }

    #[test]
    fn debug_nu_scurge_cheia() {
        let seed = KeySeed::new([0xAB; 32]);
        let s = format!("{:?}", seed);
        assert!(!s.contains("ab") && !s.contains("AB"));
        assert!(s.contains("redacted"));
    }
}
