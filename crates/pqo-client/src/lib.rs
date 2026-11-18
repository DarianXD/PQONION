//! Clientul: de la consens la o conexiune proxy.
//!
//! Doua module, cu roluri clar separate:
//!
//! [`path`] — alege pe unde merge circuitul. Aici traiesc deciziile de
//! securitate: ponderarea dupa banda, guard-urile persistente, constrangerile de
//! diversitate. Tot codul e sincron si testabil fara retea.
//!
//! [`socks`] — traduce cererile aplicatiilor locale. Aici traieste singura
//! problema de anonimitate pe care clientul nu o poate rezolva singur: daca
//! aplicatia rezolva numele local, DNS-ul a plecat deja in clar.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod path;
pub mod socks;

pub use path::{Constraints, DescriptorCache, Hop, PathSelector, N_GUARDS};
pub use socks::{Request, SocksStats};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientError {
    /// Consensul nu contine niciun releu cu flag-ul Guard.
    NoGuards,
    /// Nu exista releu de iesire potrivit.
    NoExit,
    /// Nu se poate construi o cale care sa respecte constrangerile.
    NoPath,
    /// Lungime de cale invalida.
    BadPathLength,
    /// Lipseste descriptorul unui releu ales.
    MissingDescriptor,
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use ClientError::*;
        match self {
            NoGuards => f.write_str("niciun guard disponibil"),
            NoExit => f.write_str("niciun releu de iesire potrivit"),
            NoPath => f.write_str("nicio cale care sa respecte constrangerile"),
            BadPathLength => f.write_str("lungime de cale invalida"),
            MissingDescriptor => f.write_str("lipseste descriptorul unui releu"),
        }
    }
}

impl std::error::Error for ClientError {}
