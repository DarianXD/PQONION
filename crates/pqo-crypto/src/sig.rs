//! Abstractia de semnatura digitala si implementarile ei.
//!
//! Simetrica cu [`crate::kem`], si din acelasi motiv: schema post-cuantica se
//! poate schimba, iar protocolul nu trebuie rescris.
//!
//! Implementari:
//!   - [`Ed25519`]   — clasic, mereu disponibil
//!   - [`MlDsa44`], [`MlDsa65`] — FIPS 204, in spatele feature-ului `pq`
//!   - [`HybridSig`] — semneaza cu ambele, verificarea le cere pe amandoua
//!
//! # De ce hibrid si nu doar post-cuantic
//!
//! Un hibrid care cere *ambele* semnaturi valide e mai sigur decat oricare
//! componenta singura: un fals necesita spargerea amandurora. Costul e
//! dimensiunea. Pentru chei de autoritate, care semneaza un consens pe ora,
//! costul e irelevant; pentru descriptori de releu, publicati des, conteaza mai
//! mult si poti alege doar ML-DSA-44.
//!
//! Atentie la diferenta fata de KEM: la [`crate::kem::Hybrid`], combinatorul e
//! sigur daca *macar una* dintre scheme e sigura. La semnaturi e invers — cerem
//! ca *amandoua* sa verifice. Sunt proprietati duale si e usor sa le confunzi.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::CryptoRngCore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigError {
    BadLength { expected: usize, got: usize },
    /// Cheie publica malformata.
    InvalidKey,
    /// Semnatura nu verifica.
    Invalid,
}

impl fmt::Display for SigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigError::BadLength { expected, got } => {
                write!(f, "lungime invalida: asteptat {expected}, primit {got}")
            }
            SigError::InvalidKey => f.write_str("cheie publica invalida"),
            SigError::Invalid => f.write_str("semnatura invalida"),
        }
    }
}

impl std::error::Error for SigError {}

/// O schema de semnatura digitala.
pub trait Sig {
    /// Nume, folosit in separarea de domeniu si in documente.
    const NAME: &'static str;
    /// Lungimea cheii publice serializate.
    const PK_LEN: usize;
    /// Lungimea semnaturii serializate.
    const SIG_LEN: usize;

    /// Cheia privata. Trebuie sa se zeroizeze la `Drop`. si e obligat sa cenzureze datele in Debug(redacted) pt a respecta invariantul imptotriva scurgerilor accidentale in jurnale.
    type SecretKey;

    fn keygen(rng: &mut impl CryptoRngCore) -> (Self::SecretKey, Vec<u8>);
    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Vec<u8>;
    fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), SigError>;
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Ed25519;

pub struct Ed25519Secret(SigningKey);

impl fmt::Debug for Ed25519Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519Secret(redacted)")
    }
}

impl Sig for Ed25519 {
    const NAME: &'static str = "ed25519";
    const PK_LEN: usize = 32;
    const SIG_LEN: usize = 64;
    type SecretKey = Ed25519Secret;

    fn keygen(rng: &mut impl CryptoRngCore) -> (Self::SecretKey, Vec<u8>) {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes().to_vec();
        (Ed25519Secret(sk), pk)
    }

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Vec<u8> {
        sk.0.sign(msg).to_bytes().to_vec()
    }

    fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), SigError> {
        let pk: [u8; 32] = pk.try_into().map_err(|_| SigError::BadLength {
            expected: 32,
            got: pk.len(),
        })?;
        let sig: [u8; 64] = sig.try_into().map_err(|_| SigError::BadLength {
            expected: 64,
            got: sig.len(),
        })?;
        let vk = VerifyingKey::from_bytes(&pk).map_err(|_| SigError::InvalidKey)?;
        vk.verify(msg, &Signature::from_bytes(&sig))
            .map_err(|_| SigError::Invalid)
    }
}

// ---------------------------------------------------------------------------
// ML-DSA (FIPS 204)
// ---------------------------------------------------------------------------

/// ML-DSA-44: cheie publica 1312 B, semnatura 2420 B. Pentru descriptori de releu.
#[cfg(feature = "pq")]
#[derive(Debug)]
pub struct MlDsa44;

/// ML-DSA-65: cheie publica 1952 B, semnatura 3309 B. Pentru autoritati.
#[cfg(feature = "pq")]
#[derive(Debug)]
pub struct MlDsa65;

#[cfg(feature = "pq")]
mod mldsa_impl {
    use super::*;
    use ml_dsa::{EncodedVerifyingKey, KeyGen, MlDsa44 as In44, MlDsa65 as In65};

    macro_rules! impl_mldsa {
        ($outer:ty, $inner:ty, $name:expr, $pklen:expr, $siglen:expr, $secret:ident) => {
            pub struct $secret(pub(super) ml_dsa::SigningKey<$inner>);

            impl core::fmt::Debug for $secret {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.write_str(concat!(stringify!($secret), "(redacted)"))
                }
            }

            impl Sig for $outer {
                const NAME: &'static str = $name;
                const PK_LEN: usize = $pklen;
                const SIG_LEN: usize = $siglen;
                type SecretKey = $secret;

                fn keygen(rng: &mut impl CryptoRngCore) -> (Self::SecretKey, Vec<u8>) {
                    let kp = <$inner>::key_gen(rng);
                    let pk = kp.verifying_key().encode().to_vec();
                    ($secret(kp.signing_key().clone()), pk)
                }

                fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Vec<u8> {
                    sk.0.sign(msg).encode().to_vec()
                }

                fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), SigError> {
                    if pk.len() != Self::PK_LEN {
                        return Err(SigError::BadLength {
                            expected: Self::PK_LEN,
                            got: pk.len(),
                        });
                    }
                    if sig.len() != Self::SIG_LEN {
                        return Err(SigError::BadLength {
                            expected: Self::SIG_LEN,
                            got: sig.len(),
                        });
                    }
                    let enc = EncodedVerifyingKey::<$inner>::try_from(pk)
                        .map_err(|_| SigError::InvalidKey)?;
                    let vk = ml_dsa::VerifyingKey::<$inner>::decode(&enc);
                    let s = ml_dsa::Signature::<$inner>::decode(
                        &sig.try_into().map_err(|_| SigError::Invalid)?,
                    )
                    .ok_or(SigError::Invalid)?;
                    vk.verify(msg, &s).map_err(|_| SigError::Invalid)
                }
            }
        };
    }

    impl_mldsa!(super::MlDsa44, In44, "ml-dsa-44", 1312, 2420, MlDsa44Secret);
    impl_mldsa!(super::MlDsa65, In65, "ml-dsa-65", 1952, 3309, MlDsa65Secret);
}

// ---------------------------------------------------------------------------
// Semnatura hibrida
// ---------------------------------------------------------------------------

/// Combina doua scheme: se semneaza cu ambele, verificarea le cere pe amandoua.
///
/// Formatul serializat e simpla concatenare: `pk_a | pk_b`, `sig_a | sig_b`.
/// Lungimile sunt fixe pentru fiecare schema, deci despartirea e neambigua.
pub struct HybridSig<A: Sig, B: Sig>(core::marker::PhantomData<(A, B)>);

impl<A: Sig, B: Sig> fmt::Debug for HybridSig<A, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridSig<{}, {}>", A::NAME, B::NAME)
    }
}

pub struct HybridSecret<A: Sig, B: Sig> {
    a: A::SecretKey,
    b: B::SecretKey,
}

impl<A: Sig, B: Sig> fmt::Debug for HybridSecret<A, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridSecret(redacted)")
    }
}

impl<A: Sig, B: Sig> Sig for HybridSig<A, B> {
    const NAME: &'static str = "hybrid";
    const PK_LEN: usize = A::PK_LEN + B::PK_LEN;
    const SIG_LEN: usize = A::SIG_LEN + B::SIG_LEN;
    type SecretKey = HybridSecret<A, B>;

    fn keygen(rng: &mut impl CryptoRngCore) -> (Self::SecretKey, Vec<u8>) {
        let (sa, pa) = A::keygen(rng);
        let (sb, pb) = B::keygen(rng);
        let mut pk = Vec::with_capacity(Self::PK_LEN);
        pk.extend_from_slice(&pa);
        pk.extend_from_slice(&pb);
        (HybridSecret { a: sa, b: sb }, pk)
    }

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SIG_LEN);
        out.extend_from_slice(&A::sign(&sk.a, msg));
        out.extend_from_slice(&B::sign(&sk.b, msg));
        out
    }

    fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), SigError> {
        if pk.len() != Self::PK_LEN {
            return Err(SigError::BadLength {
                expected: Self::PK_LEN,
                got: pk.len(),
            });
        }
        if sig.len() != Self::SIG_LEN {
            return Err(SigError::BadLength {
                expected: Self::SIG_LEN,
                got: sig.len(),
            });
        }
        let (pa, pb) = pk.split_at(A::PK_LEN);
        let (sa, sb) = sig.split_at(A::SIG_LEN);
        // Amandoua trebuie sa verifice. Nu scurtcircuitam: costul e neglijabil
        // fata de o verificare de semnatura, iar comportamentul e uniform.
        let ra = A::verify(pa, msg, sa);
        let rb = B::verify(pb, msg, sb);
        ra.and(rb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn roundtrip<S: Sig>() {
        let mut rng = OsRng;
        let (sk, pk) = S::keygen(&mut rng);
        assert_eq!(pk.len(), S::PK_LEN, "{}: PK_LEN gresit", S::NAME);
        let msg = b"consens valid-after 1700000000";
        let sig = S::sign(&sk, msg);
        assert_eq!(sig.len(), S::SIG_LEN, "{}: SIG_LEN gresit", S::NAME);
        S::verify(&pk, msg, &sig).expect("semnatura proprie trebuie sa verifice");

        // Mesaj modificat.
        assert_eq!(S::verify(&pk, b"alt mesaj", &sig), Err(SigError::Invalid));

        // Semnatura modificata.
        let mut rea = sig.clone();
        rea[0] ^= 0x01;
        assert!(S::verify(&pk, msg, &rea).is_err());

        // Cheie straina.
        let (_sk2, pk2) = S::keygen(&mut rng);
        assert!(S::verify(&pk2, msg, &sig).is_err());
    }

    #[test]
    fn ed25519_roundtrip() {
        roundtrip::<Ed25519>();
    }

    #[test]
    fn hibrid_test_roundtrip() {
        roundtrip::<HybridSig<Ed25519, Ed25519>>();
    }

    #[cfg(feature = "pq")]
    #[test]
    fn mldsa44_roundtrip() {
        roundtrip::<MlDsa44>();
    }

    #[cfg(feature = "pq")]
    #[test]
    fn mldsa65_roundtrip() {
        roundtrip::<MlDsa65>();
    }

    #[cfg(feature = "pq")]
    #[test]
    fn hibrid_real_roundtrip() {
        roundtrip::<HybridSig<Ed25519, MlDsa65>>();
    }

    #[test]
    fn hibridul_cere_ambele_componente() {
        // Proprietatea care il face mai sigur decat oricare parte: daca doar una
        // dintre semnaturi e valida, verificarea trebuie sa esueze.
        type H = HybridSig<Ed25519, Ed25519>;
        let mut rng = OsRng;
        let (sk, pk) = H::keygen(&mut rng);
        let msg = b"document";
        let bun = H::sign(&sk, msg);

        // Stricam doar a doua componenta.
        let mut stricat = bun.clone();
        stricat[Ed25519::SIG_LEN] ^= 0x01;
        assert!(H::verify(&pk, msg, &stricat).is_err(), "a doua componenta");

        // Stricam doar prima.
        let mut stricat = bun.clone();
        stricat[0] ^= 0x01;
        assert!(H::verify(&pk, msg, &stricat).is_err(), "prima componenta");
    }

    #[test]
    fn lungimi_gresite_sunt_respinse() {
        let mut rng = OsRng;
        let (sk, pk) = Ed25519::keygen(&mut rng);
        let sig = Ed25519::sign(&sk, b"x");
        assert!(matches!(
            Ed25519::verify(&pk[..31], b"x", &sig),
            Err(SigError::BadLength { .. })
        ));
        assert!(matches!(
            Ed25519::verify(&pk, b"x", &sig[..63]),
            Err(SigError::BadLength { .. })
        ));
    }

    #[test]
    fn debug_nu_scurge_cheia() {
        let mut rng = OsRng;
        let (sk, _) = Ed25519::keygen(&mut rng);
        assert!(format!("{sk:?}").contains("redacted"));
    }
}
