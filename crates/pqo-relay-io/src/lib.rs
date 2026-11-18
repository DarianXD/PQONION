//! Coaja de I/O peste [`pqo_relay`].
//!
//! `pqo-relay` decide *ce* trebuie facut; acest crate se ocupa *sa se intample*.
//! Separarea nu e cosmetica: tot codul cu `async` traieste aici, iar protocolul
//! ramane sincron si determinist.
//!
//! # Transportul
//!
//! Generic peste `AsyncRead + AsyncWrite`, deci acelasi cod serveste TCP simplu
//! si TLS. Alegerea se face la rulare, prin [`node::Transport`].
//!
//! Peste TCP simplu, [`ChannelBinding::insecure_plaintext_tcp`] marcheaza faptul
//! ca nu exista nimic de legat — numele tipului o spune raspicat. Cu TLS, legarea
//! vine din exportul de material de cheie (RFC 8446 §7.5) si impiedica mutarea
//! unui handshake valid pe alta conexiune.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod client;
pub mod codec;
pub mod metrici;
pub mod node;
#[cfg(feature = "tls")]
pub mod tls;
pub mod tunnel;

pub use codec::CellStream;
pub use metrici::{Instantaneu, Metrici};
pub use node::{spawn, NodeConfig, NodeHandle};
pub use tunnel::Tunnel;

/// Legarea handshake-ului de conexiunea pe care circula.
///
/// Semnatura de legatura acopera aceasta valoare. Rolul ei e sa impiedice un
/// atacator sa mute un handshake valid, observat pe o conexiune, pe alta
/// conexiune pe care o controleaza — atac de tip unknown key share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelBinding(Vec<u8>);

impl ChannelBinding {
    /// Din exportul TLS (RFC 8446 §7.5). **Singura varianta sigura.**
    ///
    /// Ambele capete deriva aceeasi valoare din secretele sesiunii TLS, iar un
    /// tert nu o poate calcula.
    pub fn from_tls_exporter(bytes: Vec<u8>) -> Self {
        ChannelBinding(bytes)
    }

    /// Fara legare reala. **Nu ofera nicio protectie.**
    ///
    /// Peste TCP simplu nu exista niciun secret partajat de care sa legam
    /// handshake-ul. Exista doar ca sa putem rula si testa restul stivei inainte
    /// de a integra TLS. Numele e lung si urat intentionat: daca il vezi
    /// intr-un binar de productie, ai o problema.
    pub fn insecure_plaintext_tcp() -> Self {
        ChannelBinding(b"pqonion-INSECURE-no-tls-binding".to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Adevarat daca legarea e cea nesigura.
    pub fn is_insecure(&self) -> bool {
        self.0 == b"pqonion-INSECURE-no-tls-binding"
    }
}
