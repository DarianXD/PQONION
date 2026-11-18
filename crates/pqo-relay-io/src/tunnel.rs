//! Tunelul hop-ului virtual.
//!
//! Dupa rendezvous, clientul si serviciul impart o cheie. Peste ea circula
//! **mesaje relay obisnuite** — BEGIN, DATA, END — exact ca pe un circuit
//! normal. Asta inseamna ca serviciul poate refolosi [`pqo_relay::StreamTable`]
//! si clientul poate refolosi acelasi cod de stream.
//!
//! # De ce se potriveste dimensiunea
//!
//! `RelayMessage::fragment` produce corpuri de 493 de octeti, exact cat are
//! `LEN_XR` la CGO. Deci un fragment intra direct intr-o celula a hop-ului
//! virtual, fara umplutura si fara taiere suplimentara.
//!
//! Celula rezultata are 509 octeti si calatoreste ca mesaj DATA pe stream-ul
//! rezervat al circuitului de rendezvous — unde intra in doua celule relay,
//! pentru ca 509 > 487. Vezi nota din [`pqo_relay::service`].
//!
//! # Asimetria, din nou
//!
//! Clientul foloseste [`ClientCircuit`], serviciul [`RelayCircuit`]. Nu e o
//! alegere: `ENC_UIV` e nemaleabil, `DEC_UIV` nu e, iar partea nemaleabila
//! trebuie sa fie la capatul care raspunde. Daca inversezi, totul compileaza si
//! roundtrip-ul trece, dar pierzi rezistenta la tagging exact pe segmentul cel
//! mai sensibil.

use std::io;

use pqo_crypto::cgo::{ClientCircuit, Outbound, RelayCircuit};
use pqo_crypto::KeySeed;
use pqo_wire::{Reassembler, RelayMessage};
use rand_core::OsRng;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::Circuit;

/// Capatul de care apartine tunelul.
enum VirtualHop {
    /// Clientul: aplica `DEC_UIV`.
    Client(Box<ClientCircuit>),
    /// Serviciul: aplica `ENC_UIV`.
    Service(Box<RelayCircuit>),
}

/// Un tunel deschis peste un circuit de rendezvous.
pub struct Tunnel<T> {
    circ: Circuit<T>,
    hop: VirtualHop,
    reasm: Reassembler,
}

impl<T> core::fmt::Debug for Tunnel<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let rol = match self.hop {
            VirtualHop::Client(_) => "client",
            VirtualHop::Service(_) => "serviciu",
        };
        write!(f, "Tunnel({rol})")
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Tunnel<T> {
    /// Capatul de client, dupa ce a primit RENDEZVOUS2.
    pub fn client(circ: Circuit<T>, seed: &KeySeed) -> Self {
        let mut c = ClientCircuit::new();
        c.add_hop(seed);
        Tunnel {
            circ,
            hop: VirtualHop::Client(Box::new(c)),
            reasm: Reassembler::new(),
        }
    }

    /// Capatul de serviciu, dupa ce a trimis RENDEZVOUS1.
    pub fn service(circ: Circuit<T>, seed: &KeySeed) -> Self {
        Tunnel {
            circ,
            hop: VirtualHop::Service(Box::new(RelayCircuit::new(seed))),
            reasm: Reassembler::new(),
        }
    }

    /// Trimite un mesaj relay prin tunel.
    pub async fn send(&mut self, msg: &RelayMessage) -> io::Result<()> {
        // `AD` e comanda de celula sub care circula: la hop-ul virtual e mereu
        // RELAY, pentru ca nu exista extindere de circuit peste rendezvous.
        const AD: u8 = pqo_wire::ChanCmd::Relay as u8;

        for corp in msg.fragment(&mut OsRng) {
            let cell = match &mut self.hop {
                VirtualHop::Client(c) => c
                    .encrypt_outbound(1, AD, &corp)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?,
                VirtualHop::Service(s) => s.originate_inbound(AD, &corp),
            };
            self.circ.send_tunnel(cell.as_slice()).await?;
        }
        Ok(())
    }

    /// Asteapta un mesaj relay complet.
    pub async fn recv(&mut self) -> io::Result<RelayMessage> {
        const AD: u8 = pqo_wire::ChanCmd::Relay as u8;

        loop {
            let brut = self.circ.recv_tunnel().await?;
            let cell: &[u8; pqo_crypto::cgo::MSG_LEN] = brut
                .as_slice()
                .try_into()
                .map_err(|_| bad("celula de tunel de dimensiune gresita"))?;

            let corp = match &mut self.hop {
                VirtualHop::Client(c) => {
                    let (_hop, b) = c
                        .decrypt_inbound(AD, cell)
                        .map_err(|e| bad(&e.to_string()))?;
                    b.to_vec()
                }
                VirtualHop::Service(s) => match s.process_outbound(AD, cell) {
                    Outbound::Recognized(b) => b.to_vec(),
                    // Nu exista hop urmator: o celula nerecunoscuta inseamna ca
                    // a fost modificata pe drum.
                    Outbound::Forward(_) => {
                        return Err(bad("celula de tunel modificata sau nerecunoscuta"))
                    }
                },
            };

            if let Some(m) = self.reasm.push(&corp).map_err(|e| bad(&e.to_string()))? {
                return Ok(m);
            }
        }
    }

    /// Circuitul pe care se sprijina tunelul.
    pub fn circuit_mut(&mut self) -> &mut Circuit<T> {
        &mut self.circ
    }
}

fn bad(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.to_string())
}

#[cfg(test)]
mod tests {
    use pqo_wire::{RelayCmd, RelayMessage, StreamId, RELAY_DATA_LEN};

    /// Verifica potrivirea de dimensiuni pe care se sprijina tot modulul.
    #[test]
    fn fragmentul_intra_exact_intr_o_celula_virtuala() {
        assert_eq!(
            pqo_wire::RELAY_BODY_LEN,
            pqo_crypto::cgo::LEN_XR,
            "corpul unui fragment relay trebuie sa fie exact cat LEN_XR"
        );
        let m = RelayMessage::new(RelayCmd::Data, StreamId(1), vec![0u8; RELAY_DATA_LEN]).unwrap();
        let f = m.fragment(&mut rand_core::OsRng);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].len(), pqo_crypto::cgo::LEN_XR);
    }

    /// Cifra de suprapunere, ca sa fie in teste, nu doar in comentarii.
    #[test]
    fn o_celula_virtuala_costa_doua_celule_relay() {
        let virtuala = pqo_crypto::cgo::MSG_LEN;
        let util = RELAY_DATA_LEN;
        assert_eq!(virtuala, 509);
        assert_eq!(util, 487);
        assert_eq!(virtuala.div_ceil(util), 2);
    }
}
