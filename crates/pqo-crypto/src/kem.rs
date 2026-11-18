//! Abstractia de KEM si implementarile ei.
//!
//! Handshake-ul `pq-ntor` e generic peste acest trait. Motivul e cel din
//! propunerea 269 a Tor: nu vrem sa rescriem protocolul cand se schimba schema
//! post-cuantica, si vrem sa putem degrada in siguranta la o schema clasica
//! daca apare o problema in cea cu latice.
//!
//! Implementari disponibile:
//!   - [`X25519Kem`]  — clasic, mereu disponibil, folosit si ca jumatate clasica
//!     a combiner-ului hibrid
//!   - [`MlKem768`]   — post-cuantic (FIPS 203), in spatele feature-ului `pq`
//!   - [`Hybrid`]     — combinator stil X-Wing peste oricare doua KEM-uri

use core::fmt;

use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::kdf;

/// Secret partajat produs de un KEM. Se zeroizeaza la `Drop`.
// Memoria alocata vectorului este stearsa la Drop si inlocuita cu zerouri ca un atacator sa nu isi poata da seama din mem RAM de chei ramase prin ceva exploit-uri.
#[derive(Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SharedSecret(Vec<u8>);

impl SharedSecret {
    pub fn new(bytes: Vec<u8>) -> Self {
        SharedSecret(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(redacted)")
    }
}

/// Comparatie in timp constant, pentru teste si pentru verificari de protocol.
impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for SharedSecret {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemError {
    /// Lungime gresita pentru o cheie de incapsulare sau un ciphertext.
    BadLength { expected: usize, got: usize },
    /// Cheie publica invalida (ex. punct de ordin mic pe Curve25519).
    InvalidKey,
    /// Decapsulare esuata.
    DecapFailed,
}

impl fmt::Display for KemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KemError::BadLength { expected, got } => {
                write!(f, "lungime invalida: asteptat {expected}, primit {got}")
            }
            KemError::InvalidKey => f.write_str("cheie publica invalida"),
            KemError::DecapFailed => f.write_str("decapsulare esuata"),
        }
    }
}

impl std::error::Error for KemError {}

/// Un mecanism de incapsulare de chei.
///
/// Formele serializate sunt `Vec<u8>` in loc de array-uri cu const generics
/// pentru a nu impune `hybrid-array` (care ridica MSRV-ul la 1.81). Alocarea nu
/// conteaza aici: handshake-ul ruleaza o data per hop, nu per celula. Calea
/// fierbinte e stratul de criptare al celulelor, care nu foloseste trait-ul asta.
pub trait Kem {
    /// Nume folosit in separarea de domeniu. Trebuie sa fie unic per schema. 
    const NAME: &'static str;
    /// Lungimea cheii de incapsulare (publice), serializata.
    const EK_LEN: usize;
    /// Lungimea ciphertext-ului, serializat.
    const CT_LEN: usize;
    /// Lungimea secretului partajat.
    const SS_LEN: usize;

    /// Cheia de decapsulare (privata). Trebuie sa se zeroizeze la `Drop`.
    type DecapKey;

    /// Genereaza o pereche. Intoarce `(cheie de decapsulare, cheie de incapsulare serializata)`.
    //
    fn keygen(rng: &mut impl CryptoRngCore) -> (Self::DecapKey, Vec<u8>);

    /// Incapsuleaza catre `ek`. Intoarce `(ciphertext, secret partajat)`.
    fn encapsulate(
        ek: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, SharedSecret), KemError>;

    /// Decapsuleaza `ct` cu cheia privata.
    fn decapsulate(dk: &Self::DecapKey, ct: &[u8]) -> Result<SharedSecret, KemError>;
}

// ---------------------------------------------------------------------------
// X25519 ca KEM
// ---------------------------------------------------------------------------

/// X25519 vazut ca KEM: `encapsulate` genereaza o pereche efemera si intoarce
/// cheia publica efemera drept ciphertext.
///
/// Nu e post-cuantic. Rolul lui e dublu: jumatatea clasica a combiner-ului
/// hibrid, si KEM de test pentru logica de protocol.
#[derive(Debug)]
pub struct X25519Kem;

/// Wrapper peste `StaticSecret` care se zeroizeaza la drop.
pub struct X25519Decap(XSecret);

impl fmt::Debug for X25519Decap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519Decap(redacted)")
    }
}

// `StaticSecret` se zeroizeaza singur la Drop prin feature-ul `zeroize` al
// crate-ului x25519-dalek, activat in Cargo.toml.

impl Kem for X25519Kem {
    const NAME: &'static str = "X25519";
    const EK_LEN: usize = 32;
    const CT_LEN: usize = 32;
    const SS_LEN: usize = 32;

    type DecapKey = X25519Decap;

    fn keygen(rng: &mut impl CryptoRngCore) -> (Self::DecapKey, Vec<u8>) {
        let sk = XSecret::random_from_rng(rng);
        let pk = XPublic::from(&sk);
        (X25519Decap(sk), pk.as_bytes().to_vec())
    }

    fn encapsulate(
        ek: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, SharedSecret), KemError> {
        let ek: [u8; 32] = ek.try_into().map_err(|_| KemError::BadLength {
            expected: 32,
            got: ek.len(),
        })?;
        let their_pk = XPublic::from(ek);
        let eph = XSecret::random_from_rng(rng);
        let ct = XPublic::from(&eph);
        let ss = eph.diffie_hellman(&their_pk);
        // Respinge punctele de ordin mic: un `ek` malitios poate forta un secret
        // partajat previzibil (tot zero). Tor face aceeasi verificare in ntor.
        if !ss.was_contributory() {
            return Err(KemError::InvalidKey);
        }
        Ok((
            ct.as_bytes().to_vec(),
            SharedSecret::new(ss.as_bytes().to_vec()),
        ))
    }

    fn decapsulate(dk: &Self::DecapKey, ct: &[u8]) -> Result<SharedSecret, KemError> {
        let ct: [u8; 32] = ct.try_into().map_err(|_| KemError::BadLength {
            expected: 32,
            got: ct.len(),
        })?;
        let ss = dk.0.diffie_hellman(&XPublic::from(ct));
        if !ss.was_contributory() {
            return Err(KemError::InvalidKey);
        }
        Ok(SharedSecret::new(ss.as_bytes().to_vec()))
    }
}

// ---------------------------------------------------------------------------
// ML-KEM-768 (FIPS 203)
// ---------------------------------------------------------------------------

/// ML-KEM-768 conform FIPS 203.
///
/// NOTA: crate-ul `ml-kem` din RustCrypto **nu a fost auditat independent**.

#[cfg(feature = "pq")]
#[derive(Debug)]
pub struct MlKem768;

#[cfg(feature = "pq")]
mod mlkem_impl {
    use super::*;
    use ml_kem::kem::{Decapsulate, Encapsulate};
    use ml_kem::{EncodedSizeUser, KemCore, MlKem768 as Inner};

    pub struct MlKemDecap(pub(super) <Inner as KemCore>::DecapsulationKey);

    impl core::fmt::Debug for MlKemDecap {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("MlKemDecap(redacted)")
        }
    }

    impl Kem for super::MlKem768 {
        const NAME: &'static str = "ML-KEM-768";
        const EK_LEN: usize = 1184;
        const CT_LEN: usize = 1088;
        const SS_LEN: usize = 32;

        type DecapKey = MlKemDecap;

        fn keygen(rng: &mut impl CryptoRngCore) -> (Self::DecapKey, Vec<u8>) {
            let (dk, ek) = Inner::generate(rng);
            (MlKemDecap(dk), ek.as_bytes().to_vec())
        }

        fn encapsulate(
            ek: &[u8],
            rng: &mut impl CryptoRngCore,
        ) -> Result<(Vec<u8>, SharedSecret), KemError> {
            if ek.len() != Self::EK_LEN {
                return Err(KemError::BadLength {
                    expected: Self::EK_LEN,
                    got: ek.len(),
                });
            }
            let encoded =
                ml_kem::Encoded::<<Inner as KemCore>::EncapsulationKey>::try_from(ek)
                    .map_err(|_| KemError::InvalidKey)?;
            let ek = <Inner as KemCore>::EncapsulationKey::from_bytes(&encoded);
            let (ct, ss) = ek.encapsulate(rng).map_err(|_| KemError::InvalidKey)?;
            Ok((ct.to_vec(), SharedSecret::new(ss.to_vec())))
        }

        fn decapsulate(dk: &Self::DecapKey, ct: &[u8]) -> Result<SharedSecret, KemError> {
            if ct.len() != Self::CT_LEN {
                return Err(KemError::BadLength {
                    expected: Self::CT_LEN,
                    got: ct.len(),
                });
            }
            let ct = ml_kem::Ciphertext::<Inner>::try_from(ct)
                .map_err(|_| KemError::BadLength {
                    expected: Self::CT_LEN,
                    got: ct.len(),
                })?;
            let ss = dk.0.decapsulate(&ct).map_err(|_| KemError::DecapFailed)?;
            Ok(SharedSecret::new(ss.to_vec()))
        }
    }
}

// ---------------------------------------------------------------------------
// Combiner hibrid (stil X-Wing)
// ---------------------------------------------------------------------------

/// Combina doua KEM-uri astfel incat rezultatul e sigur daca *cel putin unul*
/// dintre ele e sigur.
///
/// Structura urmeaza X-Wing (eprint 2024/039): secretul final e un hash peste
/// ambele secrete partiale, plus ciphertext-ul si cheia publica ale partii
/// clasice. Includerea `ctX ‖ pkX` e ceea ce face constructia sigura fara sa
/// hash-uim si ciphertext-ul post-cuantic (care e mare si costa).
///
/// Diferente fata de X-Wing standard, de documentat in lucrare:
///   1. Combiner-ul e generic peste orice doua KEM-uri, nu fixat pe
///      X25519 + ML-KEM-768.
///   2. Foloseste tuple-hash-ul cu framing din [`crate::kdf`], nu SHA3-256 pe
///      concatenare bruta.
///   3. Nu include `pkX` in hash. X-Wing il include pentru un pas specific din
///      demonstratia lui in ROM. Aici legarea la transcript o face handshake-ul
///      ntor, care hash-uieste oricum `ek`, `ct`, `X`, `Y`, `B` si `ID_R` in
///      `secret_input`. Consecinta: nu esti interoperabil cu X-Wing standard.
///      Daca vrei interoperabilitate, foloseste direct crate-ul `x-wing`.
pub struct Hybrid<A: Kem, B: Kem>(core::marker::PhantomData<(A, B)>);

impl<A: Kem, B: Kem> fmt::Debug for Hybrid<A, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hybrid<{}, {}>", A::NAME, B::NAME)
    }
}

pub struct HybridDecap<A: Kem, B: Kem> {
    a: A::DecapKey,
    b: B::DecapKey,
}

impl<A: Kem, B: Kem> fmt::Debug for HybridDecap<A, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridDecap(redacted)")
    }
}

impl<A: Kem, B: Kem> Kem for Hybrid<A, B> {
    const NAME: &'static str = "Hybrid";
    const EK_LEN: usize = A::EK_LEN + B::EK_LEN;
    const CT_LEN: usize = A::CT_LEN + B::CT_LEN;
    const SS_LEN: usize = kdf::HASH_LEN;

    type DecapKey = HybridDecap<A, B>;

    fn keygen(rng: &mut impl CryptoRngCore) -> (Self::DecapKey, Vec<u8>) {
        let (dk_a, ek_a) = A::keygen(rng);
        let (dk_b, ek_b) = B::keygen(rng);
        let mut ek = Vec::with_capacity(Self::EK_LEN);
        ek.extend_from_slice(&ek_a);
        ek.extend_from_slice(&ek_b);
        (HybridDecap { a: dk_a, b: dk_b }, ek)
    }

    fn encapsulate(
        ek: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, SharedSecret), KemError> {
        if ek.len() != Self::EK_LEN {
            return Err(KemError::BadLength {
                expected: Self::EK_LEN,
                got: ek.len(),
            });
        }
        let (ek_a, ek_b) = ek.split_at(A::EK_LEN);
        let (ct_a, ss_a) = A::encapsulate(ek_a, rng)?;
        let (ct_b, ss_b) = B::encapsulate(ek_b, rng)?;

        let mut ct = Vec::with_capacity(Self::CT_LEN);
        ct.extend_from_slice(&ct_a);
        ct.extend_from_slice(&ct_b);

        let ss = combine::<A, B>(&ss_a, &ss_b, &ct_b);
        Ok((ct, ss))
    }

    fn decapsulate(dk: &Self::DecapKey, ct: &[u8]) -> Result<SharedSecret, KemError> {
        if ct.len() != Self::CT_LEN {
            return Err(KemError::BadLength {
                expected: Self::CT_LEN,
                got: ct.len(),
            });
        }
        let (ct_a, ct_b) = ct.split_at(A::CT_LEN);
        let ss_a = A::decapsulate(&dk.a, ct_a)?;
        let ss_b = B::decapsulate(&dk.b, ct_b)?;
        let ss = combine::<A, B>(&ss_a, &ss_b, ct_b);
        Ok(ss)
    }
}

/// Combinatorul propriu-zis. Este un PRF peste ambele secrete: daca oricare din
/// ele e indistinctibil de aleator, iesirea e indistinctibila de aleator.
fn combine<A: Kem, B: Kem>(ss_a: &SharedSecret, ss_b: &SharedSecret, ct_b: &[u8]) -> SharedSecret {
    let out = kdf::hash(
        kdf::label::KEM_COMBINE,
        &[
            A::NAME.as_bytes(),
            B::NAME.as_bytes(),
            ss_a.as_bytes(),
            ss_b.as_bytes(),
            ct_b,
        ],
    );
    let v = Zeroizing::new(out);
    SharedSecret::new(v.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn roundtrip<K: Kem>() {
        let mut rng = OsRng;
        let (dk, ek) = K::keygen(&mut rng);
        assert_eq!(ek.len(), K::EK_LEN, "{}: EK_LEN gresit", K::NAME);
        let (ct, ss_send) = K::encapsulate(&ek, &mut rng).expect("encapsulare");
        assert_eq!(ct.len(), K::CT_LEN, "{}: CT_LEN gresit", K::NAME);
        let ss_recv = K::decapsulate(&dk, &ct).expect("decapsulare");
        assert_eq!(ss_send, ss_recv, "{}: secretele nu coincid", K::NAME);
        assert_eq!(ss_send.as_bytes().len(), K::SS_LEN);
    }

    #[test]
    fn x25519_roundtrip() {
        roundtrip::<X25519Kem>();
    }

    #[test]
    fn hybrid_roundtrip() {
        roundtrip::<Hybrid<X25519Kem, X25519Kem>>();
    }

    #[cfg(feature = "pq")]
    #[test]
    fn mlkem_roundtrip() {
        roundtrip::<MlKem768>();
    }

    #[cfg(feature = "pq")]
    #[test]
    fn hibrid_real_roundtrip() {
        roundtrip::<Hybrid<X25519Kem, MlKem768>>();
    }

    #[test]
    fn respinge_punct_de_ordin_mic() {
        let mut rng = OsRng;
        // u = 0 este un punct de ordin mic; DH-ul cu el da secret tot-zero.
        let ek_rau = [0u8; 32];
        let r = X25519Kem::encapsulate(&ek_rau, &mut rng);
        assert_eq!(r.err(), Some(KemError::InvalidKey));
    }

    #[test]
    fn respinge_lungimi_gresite() {
        let mut rng = OsRng;
        let (dk, _ek) = X25519Kem::keygen(&mut rng);
        assert!(matches!(
            X25519Kem::encapsulate(&[0u8; 31], &mut rng),
            Err(KemError::BadLength { .. })
        ));
        assert!(matches!(
            X25519Kem::decapsulate(&dk, &[0u8; 33]),
            Err(KemError::BadLength { .. })
        ));
    }

    #[test]
    fn ciphertext_modificat_da_secret_diferit() {
        let mut rng = OsRng;
        let (dk, ek) = X25519Kem::keygen(&mut rng);
        let (mut ct, ss) = X25519Kem::encapsulate(&ek, &mut rng).unwrap();
        ct[0] ^= 0x01;
        // Un KEM DH nu are verificare de integritate proprie: decapsularea
        // reuseste dar produce alt secret. De aceea handshake-ul ntor *trebuie*
        // sa aiba un tag de autentificare peste transcript. Vezi ntor.rs.
        if let Ok(ss2) = X25519Kem::decapsulate(&dk, &ct) {
            assert_ne!(ss, ss2);
        }
    }

    #[test]
    fn secretul_nu_apare_in_debug() {
        let ss = SharedSecret::new(vec![0xDE; 32]);
        assert!(format!("{:?}", ss).contains("redacted"));
    }
}
