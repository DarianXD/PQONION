//! Nucleul criptografic al platformei de comunicatii anonime post-cuantice.
//!
//! Acest crate nu implementeaza primitive criptografice. Le compune. Toate
//! primitivele vin din biblioteci verificate: `sha3` si `x25519-dalek` din
//! RustCrypto/dalek, `ml-kem` (sau `libcrux-ml-kem`) pentru partea PQ.
//!
//! Ce implementeaza acest crate:
//!   - [`kdf`]   — derivare de chei cu separare de domeniu si codare injectiva
//!   - [`kem`]   — abstractia de KEM, X25519-ca-KEM, ML-KEM-768, combiner hibrid
//!   - [`ntor`]  — handshake-ul de extindere de circuit `pq-ntor-v1`
//!
//! # Invariante
//!
//! 1. Nu exista `unsafe` in acest crate. Verificat de compilator, mai jos.
//! 2. Niciun tip care contine material de cheie nu implementeaza `Clone` sau
//!    afiseaza continut real in `Debug`.
//! 3. Toate comparatiile de valori secrete sunt in timp constant (`subtle`).
//! 4. Toate parserele intorc `Result`; niciunul nu poate produce panica pe
//!    input arbitrar. Vezi testul `lungimi_gresite_sunt_respinse_fara_panica`.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod cgo;
pub mod kdf;
pub mod kem;
pub mod ntor;
pub mod sig;

pub use kdf::{KeySeed, ShakeRng};
pub use kem::{Hybrid, Kem, KemError, SharedSecret, X25519Kem};
pub use sig::{Ed25519, HybridSig, Sig, SigError};
pub use ntor::{
    client_finish, client_init, server_respond, ClientState, HandshakeResult, NtorError,
    RelayKeys, RelayPublic, Variant,
};

#[cfg(feature = "pq")]
pub use kem::MlKem768;
#[cfg(feature = "pq")]
pub use sig::{MlDsa44, MlDsa65};

/// KEM-ul recomandat implicit pentru productie: X25519 + ML-KEM-768.
#[cfg(feature = "pq")]
pub type DefaultKem = Hybrid<X25519Kem, MlKem768>;

/// Semnatura recomandata pentru autoritatile de director: Ed25519 + ML-DSA-65.
#[cfg(feature = "pq")]
pub type AuthoritySig = HybridSig<Ed25519, MlDsa65>;

/// Semnatura recomandata pentru descriptorii de releu: Ed25519 + ML-DSA-44.
#[cfg(feature = "pq")]
pub type RelaySig = HybridSig<Ed25519, MlDsa44>;

/// Fara feature-ul `pq`, cade la X25519 pur. **Nu e post-cuantic.**
/// Exista pentru a putea testa logica de protocol fara dependente PQ.
#[cfg(not(feature = "pq"))]
pub type DefaultKem = X25519Kem;

/// Fara `pq`, cad la Ed25519 pur. **Nu sunt post-cuantice.**
#[cfg(not(feature = "pq"))]
pub type AuthoritySig = Ed25519;
/// Fara `pq`, cad la Ed25519 pur. **Nu sunt post-cuantice.**
#[cfg(not(feature = "pq"))]
pub type RelaySig = Ed25519;
