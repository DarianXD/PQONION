//! Servicii ascunse cu identitate post-cuantica.
//!
//! # Ce e diferit fata de Tor v3
//!
//! Tor v3 obtine trei proprietati simultan din blinding-ul algebric Ed25519:
//! HSDir poate verifica cine detine slotul, HSDir nu poate lega perioadele, si
//! clientul poate calcula cheia blindata doar din adresa. ML-DSA nu are operatia
//! de grup care face asta posibil.
//!
//! Schema de aici pastreaza a doua si a treia proprietate, si o pierde pe prima:
//!
//! | Proprietate | Tor v3 | aici |
//! |---|---|---|
//! | Lungime adresa | 56 caractere | 56 caractere |
//! | Client calculeaza indexul din adresa | da | da |
//! | HSDir nu poate lega perioadele | da | da, si post-cuantic |
//! | HSDir verifica proprietatea slotului | da | **nu** |
//! | Impersonare sub calculator cuantic | posibila | imposibila |
//!
//! Pierderea e limitata la refuz de serviciu, si e atenuata prin contor de
//! revizie, regula primului publicator si replicare. Vezi [`hsdir::DescStore`].
//!
//! # Ordinea de citire
//!
//! [`addr`] — de unde vine adresa. [`blind`] — cum se deriva indexul si cheile
//! per perioada. [`desc`] — cele doua straturi ale descriptorului. [`hsdir`] —
//! unde se stocheaza. [`rend`] — cum se ajunge la o conexiune.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod addr;
pub mod blind;
pub mod desc;
pub mod hsdir;
pub mod publish;
pub mod rend;

pub use addr::OnionAddress;
pub use blind::{blinded_id, MasterSeed, TimePeriod, PERIOD_LENGTH};
pub use desc::{Descriptor, InnerDescriptor, IntroPoint};
pub use hsdir::{responsible_nodes, DescStore, SharedDescStore};
pub use publish::{PublishPlan, ServiceKeys};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsError {
    /// Adresa nu e valida: lungime, alfabet, sau biti de umplutura nenuli.
    BadAddress,
    /// Suma de control nu se potriveste. Aproape sigur o greseala de tastare.
    BadChecksum,
    BadAddressVersion(u8),
    BadDescVersion,
    /// Structura de document invalida.
    Malformed,
    /// Documentul e valid semantic dar nu e in forma canonica.
    NotCanonical,
    /// Eroare din stratul de documente.
    Doc(pqo_dirproto::DirError),
    /// Semnatura stratului exterior nu verifica.
    BadSignature,
    /// Tag-ul stratului criptat nu verifica: modificat, sau adresa e gresita.
    BadInnerTag,
    /// Indexul blindat nu corespunde adresei si perioadei cerute.
    WrongBlindedId,
    /// Hash-ul cheii master nu e adresa. Incercare de impersonare.
    AddressMismatch,
    /// Certificatul nu leaga cheia perioadei de identitatea master.
    BadPeriodCert,
    NoIntroPoints,
    TooManyIntroPoints,
    /// Autorizare ceruta, dar fara nicio cheie de client.
    NoAuthorizedClients,
    /// Prea multi clienti autorizati.
    TooManyAuthorizedClients,
    /// O cheie de client nu are forma asteptata de mecanismul de incapsulare.
    BadClientKey,
    /// Descriptorul cere autorizare, iar clientul nu are cheia potrivita.
    NotAuthorized,
    TooLarge,
    /// Slotul e ocupat de alta cheie de perioada in aceasta perioada.
    SlotOccupied,
    StaleRevision { got: u64, have: u64 },
    StoreFull,
    /// Cookie-ul de rendezvous nu se potriveste.
    BadCookie,
    /// Mesaj de introducere sau rendezvous malformat.
    BadRendMessage,
}

impl core::fmt::Display for HsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use HsError::*;
        match self {
            NoAuthorizedClients => f.write_str("autorizare ceruta fara nicio cheie de client"),
            TooManyAuthorizedClients => f.write_str("prea multi clienti autorizati"),
            BadClientKey => f.write_str("cheie de client invalida"),
            NotAuthorized => {
                f.write_str("descriptorul cere autorizare; nicio cheie nu se potriveste")
            }
            BadAddress => f.write_str("adresa invalida"),
            BadChecksum => f.write_str("suma de control gresita"),
            BadAddressVersion(v) => write!(f, "versiune de adresa nesuportata: {v}"),
            BadDescVersion => f.write_str("versiune de descriptor nesuportata"),
            Malformed => f.write_str("document malformat"),
            NotCanonical => f.write_str("document necanonic"),
            Doc(e) => write!(f, "document: {e}"),
            BadSignature => f.write_str("semnatura invalida"),
            BadInnerTag => f.write_str("stratul criptat nu se autentifica"),
            WrongBlindedId => f.write_str("index blindat nepotrivit"),
            AddressMismatch => f.write_str("cheia master nu corespunde adresei"),
            BadPeriodCert => f.write_str("certificat de perioada invalid"),
            NoIntroPoints => f.write_str("niciun punct de introducere"),
            TooManyIntroPoints => f.write_str("prea multe puncte de introducere"),
            TooLarge => f.write_str("descriptor prea mare"),
            SlotOccupied => f.write_str("slot ocupat in aceasta perioada"),
            StaleRevision { got, have } => {
                write!(f, "revizie {got} nu depaseste {have}")
            }
            StoreFull => f.write_str("stocare plina"),
            BadCookie => f.write_str("cookie de rendezvous gresit"),
            BadRendMessage => f.write_str("mesaj de rendezvous malformat"),
        }
    }
}

impl std::error::Error for HsError {}
