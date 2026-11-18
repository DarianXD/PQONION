//! Nucleul unui releu, fara I/O.
//!
//! # Arhitectura sans-io
//!
//! Nimic din acest crate nu deschide socket-uri, nu foloseste `async`, si nu
//! depinde de un runtime. Fiecare metoda are forma
//! `(stare, eveniment) -> Vec<Action>`. Coaja de I/O — tokio plus rustls — se
//! ocupa doar sa pompeze octeti si sa execute actiunile.
//!
//! Motivele, in ordinea importantei:
//!
//! 1. **Calea critica nu are async.** Verificarea semnaturilor, decizia de
//!    rutare si actualizarea starii CGO se intampla in cod sincron. Nu pot
//!    exista curse pe starea criptografica, pentru ca nu exista `.await` intre
//!    citirea si scrierea ei.
//! 2. **Testele sunt deterministe.** Fiecare scenariu de eroare — ordine
//!    gresita, circuit necunoscut, canal cazut la mijlocul unei extinderi — se
//!    verifica fara retea si fara timeout-uri. Niciun test nu pica aleator.
//! 3. **Runtime-ul e inlocuibil.** Daca tokio devine o problema, se schimba
//!    coaja fara sa se atinga protocolul.
//!
//! Costul: coaja de I/O trebuie sa tina evidenta canalelor si sa traduca intre
//! identificatorii ei si [`circuit::ChannelId`]. E cod plictisitor, dar e cod
//! plictisitor **izolat**.
//!
//! # Module
//!
//! [`link`] — handshake-ul de legatura ca masina de stari.
//! [`circuit`] — tabela de circuite si rutarea celulelor.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod circuit;
pub mod link;
pub mod service;
pub mod stream;

pub use circuit::{Action, ChannelId, Endpoint, RelayNode};
pub use link::{AuthMode, LinkHandshake, Role, Stage};
pub use service::{ServiceAction, ServiceTable, RENDEZVOUS_STREAM};
pub use stream::{ExitPolicy, StreamAction, StreamTable};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    /// Mesaj de legatura malformat sau de lungime gresita.
    BadLinkMessage,
    /// Mesaj primit intr-o etapa in care nu are ce cauta.
    BadLinkState,
    /// Semnatura de legatura nu verifica.
    BadLinkAuth,
    /// Nicio versiune de protocol comuna.
    NoCommonVersion,
    /// Identificator de circuit invalid (zero).
    BadCircId,
    /// Numarul de circuit e deja folosit pe acest canal.
    CircuitExists,
    /// Circuitul nu exista.
    UnknownCircuit,
    /// Celula a venit din sensul gresit al circuitului.
    WrongDirection,
    /// Prea multe circuite deschise.
    TooManyCircuits,
    /// CREATED2 primit fara sa fi cerut o extindere.
    UnexpectedCreated2,
    /// Token de extindere necunoscut.
    UnknownToken,
    /// EXTEND2 fara identitatea releului tinta.
    NoRelayId,
    /// EXTEND2 fara adresa utilizabila.
    NoAddress,
    /// Payload-ul celulei nu are dimensiunea de celula fixa.
    BadCellSize,
    /// Stream necunoscut pe acest circuit.
    UnknownStream,
    /// Eroare din stratul de fir.
    Wire(pqo_wire::WireError),
    /// Handshake-ul de circuit a esuat.
    Ntor(pqo_crypto::NtorError),
}

impl core::fmt::Display for RelayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use RelayError::*;
        match self {
            BadLinkMessage => f.write_str("mesaj de legatura malformat"),
            BadLinkState => f.write_str("mesaj in etapa gresita"),
            BadLinkAuth => f.write_str("autentificare de legatura esuata"),
            NoCommonVersion => f.write_str("nicio versiune comuna"),
            BadCircId => f.write_str("identificator de circuit invalid"),
            CircuitExists => f.write_str("circuitul exista deja"),
            UnknownCircuit => f.write_str("circuit necunoscut"),
            WrongDirection => f.write_str("celula din sensul gresit"),
            TooManyCircuits => f.write_str("prea multe circuite"),
            UnexpectedCreated2 => f.write_str("CREATED2 neasteptat"),
            UnknownToken => f.write_str("token de extindere necunoscut"),
            NoRelayId => f.write_str("EXTEND2 fara identitate de releu"),
            NoAddress => f.write_str("EXTEND2 fara adresa"),
            BadCellSize => f.write_str("dimensiune de celula gresita"),
            UnknownStream => f.write_str("stream necunoscut"),
            Wire(e) => write!(f, "fir: {e}"),
            Ntor(e) => write!(f, "handshake: {e}"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<pqo_wire::WireError> for RelayError {
    fn from(e: pqo_wire::WireError) -> Self {
        RelayError::Wire(e)
    }
}

impl From<pqo_crypto::NtorError> for RelayError {
    fn from(e: pqo_crypto::NtorError) -> Self {
        RelayError::Ntor(e)
    }
}
