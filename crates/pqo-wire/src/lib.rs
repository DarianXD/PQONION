//! Formatul de fir al platformei: celule, mesaje relay, fragmentare.
//!
//! Acest crate nu contine criptografie. Contine parsere. De aceea invariantul
//! lui central e: **niciun parser nu poate produce panica pentru niciun input.**
//! Toate intra prin `Result`, toate accesele in buffer sunt verificate, si
//! fiecare parser are o tinta de fuzzing.
//!
//! Straturile, de jos in sus:
//!   - [`cell`]  — celule de nivel canal, fixe (514B) si variabile
//!   - [`relay`] — mesaje relay in interiorul celulelor RELAY, cu fragmentare
//!   - [`msg`]   — mesajele tipizate de protocol (CREATE2, EXTEND2, ...)

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod cell;
pub mod msg;
pub mod relay;
pub mod stream;

pub use cell::{Cell, ChanCmd, CircId, CELL_HEADER_LEN, CELL_LEN, CELL_PAYLOAD_LEN};
pub use msg::{Create2, Created2, Extend2, Extended2, HandshakeType, LinkSpec};
pub use stream::{
    Begin, Connected, End, EndReason, FlowWindow, Sendme, CIRC_WINDOW_INC, CIRC_WINDOW_START,
    STREAM_WINDOW_INC, STREAM_WINDOW_START,
};
pub use relay::{
    Reassembler, RelayCmd, RelayMessage, StreamId, CGO_TAG_LEN, MAX_MESSAGE_LEN, RELAY_BODY_LEN,
    RELAY_DATA_LEN,
};

/// Plafonul pentru payload-ul unei celule variabile.
///
/// Cel mai mare mesaj legitim e un CREATED2/CREATE2 cu handshake FullPq hibrid
/// (~2.5 KB) sau o celula CERTS cu certificate ML-DSA (~8 KB). 16 KB lasa marja
/// si plafoneaza alocarea pe care o poate cere un peer inainte de autentificare.
pub const MAX_VAR_CELL_LEN: usize = 16 * 1024;

/// Erorile stratului de fir.
///
/// Toate sunt fatale pentru celula sau canalul in cauza. Niciuna nu contine
/// date din input: un mesaj de eroare care ecoueaza continut devine oracol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    UnknownChanCmd(u8),
    UnknownRelayCmd(u8),
    /// Comanda ceruta cu forma gresita de celula (fixa vs variabila).
    WrongCellForm,
    PayloadTooLong {
        max: usize,
        got: usize,
    },
    MessageTooLong {
        max: usize,
        got: usize,
    },
    /// Payload de celula relay de lungime gresita, sau camp de lungime invalid.
    BadFragment,
    /// Fragment non-final care nu e plin. Canal ascuns potential.
    ShortNonFinalFragment,
    /// Biti rezervati setati in campul de flag-uri.
    ReservedBitsSet,
    /// Comanda s-a schimbat la mijlocul unui mesaj fragmentat.
    InconsistentFragment,
    TooManyPartials,
    /// Comanda de control pe stream de date, sau invers.
    StreamMismatch,
    /// Structura de mesaj invalida (camp lipsa, lungime inconsistenta).
    Malformed,
    /// Tip de handshake nerecunoscut.
    UnknownHandshake(u16),
    /// Tip de link specifier nerecunoscut sau de lungime gresita.
    BadLinkSpec,
    /// Incalcare de control de flux: fereastra epuizata sau SENDME in exces.
    FlowControl,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use WireError::*;
        match self {
            UnknownChanCmd(c) => write!(f, "comanda de canal necunoscuta: {c}"),
            UnknownRelayCmd(c) => write!(f, "comanda relay necunoscuta: {c}"),
            WrongCellForm => f.write_str("forma de celula nepotrivita cu comanda"),
            PayloadTooLong { max, got } => write!(f, "payload {got} > maxim {max}"),
            MessageTooLong { max, got } => write!(f, "mesaj {got} > maxim {max}"),
            BadFragment => f.write_str("fragment invalid"),
            ShortNonFinalFragment => f.write_str("fragment non-final incomplet"),
            ReservedBitsSet => f.write_str("biti rezervati setati"),
            InconsistentFragment => f.write_str("comanda inconsistenta intre fragmente"),
            TooManyPartials => f.write_str("prea multe mesaje partiale"),
            StreamMismatch => f.write_str("comanda nepotrivita cu tipul de stream"),
            Malformed => f.write_str("mesaj malformat"),
            UnknownHandshake(t) => write!(f, "tip de handshake necunoscut: {t}"),
            BadLinkSpec => f.write_str("link specifier invalid"),
            FlowControl => f.write_str("incalcare de control de flux"),
        }
    }
}

impl std::error::Error for WireError {}
