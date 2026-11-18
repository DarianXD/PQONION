//! Adresa `.onion` post-cuantica.
//!
//! # De ce hash si nu cheia insasi
//!
//! Tor v3 pune cheia publica Ed25519 completa in adresa: 32 de octeti, 56 de
//! caractere base32. Asta ii da trei lucruri simultan, prin blinding algebric:
//! HSDir poate verifica cine detine slotul, HSDir nu poate lega perioadele, si
//! clientul poate calcula cheia blindata doar din adresa.
//!
//! Cu ML-DSA cheia publica are 1312 de octeti. Pusa in adresa ar da ~2100 de
//! caractere — inutilizabil. Deci adresa contine **hash-ul** cheii.
//!
//! # Ce castigam si ce pierdem
//!
//! Castigam: adresa ramane de 56 de caractere, iar impersonarea sub un
//! calculator cuantic devine imposibila — ca sa produci un descriptor valid
//! pentru o adresa data ai nevoie de o preimagine SHAKE256 sau de o falsificare
//! ML-DSA.
//!
//! Pierdem: HSDir nu mai poate verifica ca cine publica detine slotul, pentru ca
//! nu are cheia publica cu care sa verifice. Vezi [`crate::desc`] pentru cum
//! limitam consecinta la refuz de serviciu, nu la impersonare.
//!
//! # Varianta respinsa
//!
//! Am considerat si o varianta hibrida in care adresa e cheia Ed25519, ca in Tor
//! v3, cu identitatea ML-DSA legata in interiorul descriptorului. **E
//! insuficienta**: un atacator cuantic recupereaza cheia privata Ed25519 direct
//! din adresa si publica descriptori care trec verificarea HSDir. Nu e degradare
//! partiala, e preluare completa a serviciului.

use pqo_crypto::kdf;
use pqo_crypto::sig::Sig;

use crate::HsError;

/// Versiunea formatului de adresa.
pub const ADDR_VERSION: u8 = 3;
/// Lungimea identificatorului derivat prin hash.
pub const ADDR_ID_LEN: usize = 32;
/// Octetii bruti dinaintea codarii: id + suma de control + versiune.
pub const ADDR_RAW_LEN: usize = ADDR_ID_LEN + 2 + 1;
/// Lungimea partii codate, fara sufixul `.onion`.
pub const ADDR_B32_LEN: usize = 56;

/// Identificatorul unui serviciu ascuns: `SHAKE256` al cheii lui de identitate.
pub type AddrId = [u8; ADDR_ID_LEN];

// ---------------------------------------------------------------------------
// Base32, RFC 4648, alfabet mic, fara umplutura
// ---------------------------------------------------------------------------

mod b32 {
    use crate::HsError;

    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for &b in data {
            acc = (acc << 8) | b as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(ALPHABET[((acc >> bits) & 0x1F) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((acc << (5 - bits)) & 0x1F) as usize] as char);
        }
        out
    }

    fn val(c: u8) -> Option<u32> {
        match c {
            b'a'..=b'z' => Some((c - b'a') as u32),
            b'2'..=b'7' => Some((c - b'2') as u32 + 26),
            _ => None,
        }
    }

    /// Decodare stricta: doar litere mici, si bitii de umplutura de la final
    /// trebuie sa fie zero.
    ///
    /// Fara verificarea bitilor de umplutura, mai multe siruri ar decoda la
    /// aceiasi octeti si o adresa ar avea mai multe forme valide. Pentru un
    /// identificator care serveste drept ancora de incredere, asta e inacceptabil.
    pub fn decode(s: &str) -> Result<Vec<u8>, HsError> {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len() * 5 / 8);
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for &c in b {
            acc = (acc << 5) | val(c).ok_or(HsError::BadAddress)?;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        if bits >= 5 || (acc & ((1 << bits) - 1)) != 0 {
            return Err(HsError::BadAddress);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Adresa
// ---------------------------------------------------------------------------

/// O adresa `.onion` validata.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OnionAddress {
    id: AddrId,
}

impl core::fmt::Debug for OnionAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Adresa e publica, dar o afisam trunchiat: intr-un log, o adresa
        // completa leaga observatorul de serviciul vizitat.
        write!(f, "OnionAddress({}…)", &self.to_string()[..8])
    }
}

impl core::fmt::Display for OnionAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut raw = [0u8; ADDR_RAW_LEN];
        raw[..ADDR_ID_LEN].copy_from_slice(&self.id);
        raw[ADDR_ID_LEN..ADDR_ID_LEN + 2].copy_from_slice(&checksum(&self.id));
        raw[ADDR_RAW_LEN - 1] = ADDR_VERSION;
        write!(f, "{}.onion", b32::encode(&raw))
    }
}

fn checksum(id: &AddrId) -> [u8; 2] {
    let h = kdf::hash(b"pqonion-hs-check-v1", &[id, &[ADDR_VERSION]]);
    [h[0], h[1]]
}

impl OnionAddress {
    /// Deriva adresa din cheia publica de identitate a serviciului.
    ///
    /// Numele schemei intra in hash: doua servicii cu chei diferite ca schema nu
    /// pot ajunge la aceeasi adresa, chiar daca octetii cheilor ar coincide.
    pub fn from_identity<S: Sig>(pk: &[u8]) -> Self {
        OnionAddress {
            id: kdf::hash(b"pqonion-hs-addr-v1", &[S::NAME.as_bytes(), pk]),
        }
    }

    pub fn id(&self) -> &AddrId {
        &self.id
    }

    /// Verifica daca o cheie publica corespunde acestei adrese.
    ///
    /// Asta e verificarea care leaga descriptorul de adresa. Fara ea, tot restul
    /// schemei nu inseamna nimic.
    pub fn matches<S: Sig>(&self, pk: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        let derivat = kdf::hash(b"pqonion-hs-addr-v1", &[S::NAME.as_bytes(), pk]);
        derivat.ct_eq(&self.id).into()
    }

    /// Parseaza o adresa textuala, verificand suma de control si versiunea.
    pub fn parse(s: &str) -> Result<Self, HsError> {
        let base = s.strip_suffix(".onion").unwrap_or(s);
        if base.len() != ADDR_B32_LEN {
            return Err(HsError::BadAddress);
        }
        let raw = b32::decode(base)?;
        if raw.len() != ADDR_RAW_LEN {
            return Err(HsError::BadAddress);
        }
        if raw[ADDR_RAW_LEN - 1] != ADDR_VERSION {
            return Err(HsError::BadAddressVersion(raw[ADDR_RAW_LEN - 1]));
        }
        let id: AddrId = raw[..ADDR_ID_LEN].try_into().map_err(|_| HsError::BadAddress)?;
        let asteptat = checksum(&id);
        if raw[ADDR_ID_LEN..ADDR_ID_LEN + 2] != asteptat {
            return Err(HsError::BadChecksum);
        }
        Ok(OnionAddress { id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqo_crypto::sig::Ed25519;
    use rand_core::OsRng;

    type S = Ed25519;

    #[test]
    fn rfc4648_base32_vectori() {
        // Vectorii din RFC 4648 sectiunea 10, cu alfabet mic si fara umplutura.
        for (plain, enc) in [
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ] {
            assert_eq!(b32::encode(plain.as_bytes()), enc, "codare {plain:?}");
            assert_eq!(b32::decode(enc).unwrap(), plain.as_bytes(), "decodare {enc:?}");
        }
    }

    #[test]
    fn base32_roundtrip() {
        for n in 0..80usize {
            let v: Vec<u8> = (0..n).map(|i| (i * 41 % 256) as u8).collect();
            assert_eq!(b32::decode(&b32::encode(&v)).unwrap(), v, "lungime {n}");
        }
    }

    #[test]
    fn base32_respinge_forme_necanonice() {
        assert!(b32::decode("MZXW6").is_err(), "litere mari");
        assert!(b32::decode("mzxw0").is_err(), "cifra invalida");
        assert!(b32::decode("mz").is_err(), "biti de umplutura nenuli");
    }

    #[test]
    fn adresa_are_56_de_caractere() {
        let mut rng = OsRng;
        let (_sk, pk) = S::keygen(&mut rng);
        let a = OnionAddress::from_identity::<S>(&pk);
        let s = a.to_string();
        assert!(s.ends_with(".onion"));
        assert_eq!(
            s.len(),
            ADDR_B32_LEN + 6,
            "adresa trebuie sa aiba aceeasi lungime ca in Tor v3: {s}"
        );
    }

    #[test]
    fn adresa_roundtrip() {
        let mut rng = OsRng;
        for _ in 0..20 {
            let (_sk, pk) = S::keygen(&mut rng);
            let a = OnionAddress::from_identity::<S>(&pk);
            assert_eq!(OnionAddress::parse(&a.to_string()).unwrap(), a);
            // Si fara sufix.
            let fara = a.to_string().replace(".onion", "");
            assert_eq!(OnionAddress::parse(&fara).unwrap(), a);
        }
    }

    #[test]
    fn adresa_leaga_cheia() {
        let mut rng = OsRng;
        let (_sk, pk) = S::keygen(&mut rng);
        let (_sk2, pk2) = S::keygen(&mut rng);
        let a = OnionAddress::from_identity::<S>(&pk);
        assert!(a.matches::<S>(&pk));
        assert!(!a.matches::<S>(&pk2), "o alta cheie nu are voie sa se potriveasca");
    }

    #[test]
    fn suma_de_control_prinde_greselile_de_tastare() {
        let mut rng = OsRng;
        let (_sk, pk) = S::keygen(&mut rng);
        let bun = OnionAddress::from_identity::<S>(&pk).to_string();

        let mut gresite = 0;
        for i in 0..ADDR_B32_LEN {
            let mut c: Vec<char> = bun.chars().collect();
            // Schimba un caracter cu urmatorul din alfabet.
            c[i] = match c[i] {
                'z' => 'a',
                '7' => '2',
                x => (x as u8 + 1) as char,
            };
            let stricat: String = c.into_iter().collect();
            if OnionAddress::parse(&stricat).is_err() {
                gresite += 1;
            }
        }
        // Suma de control are 16 biti, deci prinde practic toate greselile de un
        // caracter. Nu toate: ultimele caractere codeaza chiar suma.
        assert!(
            gresite >= ADDR_B32_LEN - 4,
            "prea putine greseli prinse: {gresite} din {ADDR_B32_LEN}"
        );
    }

    #[test]
    fn lungimi_gresite_sunt_respinse() {
        let mut rng = OsRng;
        let (_sk, pk) = S::keygen(&mut rng);
        let bun = OnionAddress::from_identity::<S>(&pk).to_string();
        for n in 0..bun.len() {
            let _ = OnionAddress::parse(&bun[..n]);
        }
        assert!(OnionAddress::parse("").is_err());
        assert!(OnionAddress::parse("aaa.onion").is_err());
    }

    #[test]
    fn versiunea_gresita_e_respinsa() {
        let mut rng = OsRng;
        let (_sk, pk) = S::keygen(&mut rng);
        let a = OnionAddress::from_identity::<S>(&pk);
        let mut raw = [0u8; ADDR_RAW_LEN];
        raw[..ADDR_ID_LEN].copy_from_slice(a.id());
        raw[ADDR_ID_LEN..ADDR_ID_LEN + 2].copy_from_slice(&checksum(a.id()));
        raw[ADDR_RAW_LEN - 1] = 4; // versiune viitoare
        let s = format!("{}.onion", b32::encode(&raw));
        assert_eq!(
            OnionAddress::parse(&s),
            Err(HsError::BadAddressVersion(4))
        );
    }

    #[test]
    fn debug_trunchiaza_adresa() {
        let mut rng = OsRng;
        let (_sk, pk) = S::keygen(&mut rng);
        let a = OnionAddress::from_identity::<S>(&pk);
        let d = format!("{a:?}");
        assert!(d.len() < 30, "adresa completa nu trebuie logata: {d}");
    }
}
