//! Formatele de document ale sistemului de director.
//!
//! Invariantul central al acestui crate e **canonicitatea**: aceeasi informatie
//! trebuie sa produca exact aceiasi octeti, la fiecare autoritate, de fiecare
//! data. Fara asta semnaturile nu se potrivesc si consensul nu se formeaza.
//!
//! Canonicitatea se impune in trei locuri, si toate trei sunt necesare:
//!   1. La serializare — sortari fixe, ordine fixa a campurilor.
//!   2. La parsare — orice forma necanonica e respinsa, nu normalizata.
//!   3. La verificare — semnatura se verifica pe prefixul **recalculat** din
//!      structura parsata, nu pe textul primit. Astfel, orice camp pe care
//!      parserul l-ar interpreta altfel decat serializatorul duce la esec.
//!
//! Punctul 3 e cel care inchide clasa de atacuri "parser differential": doua
//! implementari care citesc acelasi document diferit nu pot ajunge amandoua sa
//! creada ca semnatura e valida.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod dirreq;
pub mod doc;
pub mod netdoc;

pub use dirreq::{DirRequest, DirResponse, DirStatus, DirStore, HsDirStore, HsUploadError};
pub use doc::{b64_decode, b64_encode, hex_decode, hex_encode};
pub use netdoc::{
    fingerprint, Consensus, Fingerprint, Flags, RelayDescriptor, RelayStatus, Validity, Vote,
    ALL_FLAGS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirError {
    /// Camp obligatoriu lipsa.
    Missing,
    /// Structura invalida: camp neparsabil, lungime gresita.
    Malformed,
    /// Versiune de document nesuportata.
    BadVersion,
    /// Un cuvant cheie apare de mai multe ori.
    Duplicate,
    /// Documentul e valid semantic dar nu e in forma canonica.
    ///
    /// Respins intentionat: daca am accepta, un atacator ar putea produce doua
    /// reprezentari ale aceluiasi consens, ceea ce sparge cache-urile si
    /// deschide un canal ascuns.
    NotCanonical,
    BadBase64,
    BadHex,
    /// Flag necunoscut.
    UnknownFlag,
    /// `valid_after < fresh_until <= valid_until` nu e respectat.
    BadValidity,
    /// Semnatura nu verifica.
    BadSignature,
    /// Sub pragul de semnaturi de autoritate.
    NotEnoughSignatures { got: usize, need: usize },
    /// Lista de autoritati de incredere e goala.
    NoAuthorities,
}

impl core::fmt::Display for DirError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use DirError::*;
        match self {
            Missing => f.write_str("camp obligatoriu lipsa"),
            Malformed => f.write_str("document malformat"),
            BadVersion => f.write_str("versiune nesuportata"),
            Duplicate => f.write_str("cuvant cheie duplicat"),
            NotCanonical => f.write_str("document necanonic"),
            BadBase64 => f.write_str("base64 invalid"),
            BadHex => f.write_str("hex invalid"),
            UnknownFlag => f.write_str("flag necunoscut"),
            BadValidity => f.write_str("interval de valabilitate invalid"),
            BadSignature => f.write_str("semnatura invalida"),
            NotEnoughSignatures { got, need } => {
                write!(f, "doar {got} semnaturi valide, sunt necesare {need}")
            }
            NoAuthorities => f.write_str("nicio autoritate de incredere"),
        }
    }
}

impl std::error::Error for DirError {}
