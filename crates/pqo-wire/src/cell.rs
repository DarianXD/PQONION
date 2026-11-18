//! Celulele de nivel legatura (link layer), schimbate intre doua noduri prin TLS.
//!
//! # Decizia centrala: CREATE2 / CREATED2 sunt celule *variabile*
//!
//! In Tor, CREATE2 si CREATED2 sunt celule de dimensiune fixa (514 octeti), iar
//! handshake-ul ntor (84 / 64 octeti) incape confortabil. Handshake-ul nostru are
//! 1312–2432 de octeti, deci nu incape.
//!
//! Am ales sa le facem celule variabile, si nu sa le fragmentam. Justificarea, de
//! pus in lucrare:
//!
//!   1. Sunt **hop-by-hop**, nu end-to-end. Circula doar intre client si primul
//!      releu, in interiorul unei conexiuni TLS deja stabilite.
//!   2. Primul releu **stie oricum** ca se creeaza un circuit — el e cel care
//!      raspunde. Lungimea nu ii spune nimic ce nu stia deja.
//!   3. Un observator extern vede doar trafic TLS. Lungimea inregistrarii TLS
//!      scurge ceva, dar asta e o problema de padding la nivel TLS, ortogonala.
//!
//! In schimb, EXTEND2 / EXTENDED2 **raman in celule RELAY de dimensiune fixa** si
//! se fragmenteaza (vezi [`crate::relay`]). Acolo dimensiunea chiar conteaza: un
//! releu din mijloc care ar vedea celule de lungime variabila ar afla imediat ca
//! se extinde un circuit, cate hop-uri mai sunt, si ce varianta de handshake se
//! foloseste. Exact informatia pe care onion routing trebuie sa o ascunda.
//!
//! Ăsta e motivul pentru care fragmentarea nu e optionala.

use crate::{WireError, MAX_VAR_CELL_LEN};

/// Lungimea totala a unei celule fixe pe fir.
pub const CELL_LEN: usize = 514;
/// Payload-ul util al unei celule fixe.
pub const CELL_PAYLOAD_LEN: usize = 509;
/// Lungimea identificatorului de circuit.
pub const CIRCID_LEN: usize = 4;
/// Antetul comun: CircID (4) + Command (1).
pub const CELL_HEADER_LEN: usize = CIRCID_LEN + 1;

/// Identificator de circuit, unic per conexiune (canal), nu global.
///
/// Bitul cel mai semnificativ indica cine a initiat circuitul, ca sa nu existe
/// coliziuni intre cele doua capete ale unui canal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CircId(pub u32);

impl CircId {
    /// CircID 0 e rezervat pentru mesaje care nu apartin niciunui circuit
    /// (VERSIONS, NETINFO, PADDING).
    pub const NONE: CircId = CircId(0);

    pub fn is_none(self) -> bool {
        self.0 == 0
    }
}

/// Comenzile de nivel canal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChanCmd {
    /// Umplutura, celula fixa. Ignorata la receptie.
    Padding = 0,
    /// Transporta un mesaj relay criptat. Celula fixa. Calea fierbinte.
    Relay = 3,
    /// Distruge circuitul. Celula fixa.
    Destroy = 4,
    /// Ca Relay, dar numarata separat: limiteaza cate EXTEND-uri poate face un
    /// client, ca aparare impotriva atacurilor de tip circuit infinit.
    RelayEarly = 9,
    /// Negociere de versiuni. Variabila.
    Versions = 7,
    /// Umplutura variabila, pentru mascarea tiparelor de lungime.
    VPadding = 128,
    /// Certificate de identitate. Variabila.
    Certs = 129,
    /// Provocare de autentificare. Variabila.
    AuthChallenge = 130,
    /// Raspuns de autentificare. Variabila.
    Authenticate = 131,
    /// Informatii de retea si timp. Celula fixa.
    Netinfo = 8,
    /// Creare de circuit. **Variabila** — vezi nota de modul.
    Create2 = 10,
    /// Raspuns la creare. **Variabila** — vezi nota de modul.
    Created2 = 11,
}

impl ChanCmd {
    pub fn from_u8(v: u8) -> Result<Self, WireError> {
        use ChanCmd::*;
        Ok(match v {
            0 => Padding,
            3 => Relay,
            4 => Destroy,
            7 => Versions,
            8 => Netinfo,
            9 => RelayEarly,
            10 => Create2,
            11 => Created2,
            128 => VPadding,
            129 => Certs,
            130 => AuthChallenge,
            131 => Authenticate,
            other => return Err(WireError::UnknownChanCmd(other)),
        })
    }

    /// Adevarat daca aceasta comanda foloseste formatul variabil.
    pub fn is_variable(self) -> bool {
        use ChanCmd::*;
        matches!(
            self,
            Versions | VPadding | Certs | AuthChallenge | Authenticate | Create2 | Created2
        )
    }
}

/// O celula de nivel canal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cell {
    /// Celula de dimensiune fixa: 514 octeti pe fir, mereu.
    Fixed {
        circ: CircId,
        cmd: ChanCmd,
        payload: Box<[u8; CELL_PAYLOAD_LEN]>,
    },
    /// Celula de dimensiune variabila.
    Var {
        circ: CircId,
        cmd: ChanCmd,
        payload: Vec<u8>,
    },
}

impl Cell {
    pub fn circ(&self) -> CircId {
        match self {
            Cell::Fixed { circ, .. } | Cell::Var { circ, .. } => *circ,
        }
    }

    pub fn cmd(&self) -> ChanCmd {
        match self {
            Cell::Fixed { cmd, .. } | Cell::Var { cmd, .. } => *cmd,
        }
    }

    pub fn payload(&self) -> &[u8] {
        match self {
            Cell::Fixed { payload, .. } => payload.as_slice(),
            Cell::Var { payload, .. } => payload.as_slice(),
        }
    }

    /// Construieste o celula fixa dintr-un payload de cel mult 509 octeti.
    /// Restul se completeaza cu zero — apelantul e responsabil sa puna umplutura
    /// aleatoare daca payload-ul nu e deja criptat.
    pub fn fixed(circ: CircId, cmd: ChanCmd, data: &[u8]) -> Result<Self, WireError> {
        if cmd.is_variable() {
            return Err(WireError::WrongCellForm);
        }
        if data.len() > CELL_PAYLOAD_LEN {
            return Err(WireError::PayloadTooLong {
                max: CELL_PAYLOAD_LEN,
                got: data.len(),
            });
        }
        let mut payload = Box::new([0u8; CELL_PAYLOAD_LEN]);
        payload[..data.len()].copy_from_slice(data);
        Ok(Cell::Fixed { circ, cmd, payload })
    }

    /// Construieste o celula variabila.
    pub fn var(circ: CircId, cmd: ChanCmd, data: Vec<u8>) -> Result<Self, WireError> {
        if !cmd.is_variable() {
            return Err(WireError::WrongCellForm);
        }
        if data.len() > MAX_VAR_CELL_LEN {
            return Err(WireError::PayloadTooLong {
                max: MAX_VAR_CELL_LEN,
                got: data.len(),
            });
        }
        Ok(Cell::Var {
            circ,
            cmd,
            payload: data,
        })
    }

    /// Serializeaza in `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Cell::Fixed { circ, cmd, payload } => {
                out.extend_from_slice(&circ.0.to_be_bytes());
                out.push(*cmd as u8);
                out.extend_from_slice(payload.as_slice());
            }
            Cell::Var { circ, cmd, payload } => {
                out.extend_from_slice(&circ.0.to_be_bytes());
                out.push(*cmd as u8);
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
            }
        }
    }

    pub fn encoded_len(&self) -> usize {
        match self {
            Cell::Fixed { .. } => CELL_LEN,
            Cell::Var { payload, .. } => CELL_HEADER_LEN + 2 + payload.len(),
        }
    }

    /// Incearca sa decodeze o celula de la inceputul lui `buf`.
    ///
    /// Intoarce:
    ///   - `Ok(Some((cell, n)))` — s-a decodat o celula care ocupa `n` octeti
    ///   - `Ok(None)`            — nu sunt destui octeti inca, mai asteapta
    ///   - `Err(_)`              — flux invalid, inchide canalul
    ///
    /// Aceasta e semnatura de care are nevoie un `tokio_util::codec::Decoder`.
    /// **Nu poate produce panica pentru niciun input.** Vezi testul de fuzzing.
    pub fn decode(buf: &[u8]) -> Result<Option<(Cell, usize)>, WireError> {
        if buf.len() < CELL_HEADER_LEN {
            return Ok(None);
        }
        let circ = CircId(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]));
        let cmd = ChanCmd::from_u8(buf[4])?;

        if cmd.is_variable() {
            if buf.len() < CELL_HEADER_LEN + 2 {
                return Ok(None);
            }
            let len = u16::from_be_bytes([buf[5], buf[6]]) as usize;
            if len > MAX_VAR_CELL_LEN {
                return Err(WireError::PayloadTooLong {
                    max: MAX_VAR_CELL_LEN,
                    got: len,
                });
            }
            let total = CELL_HEADER_LEN + 2 + len;
            if buf.len() < total {
                return Ok(None);
            }
            let payload = buf[CELL_HEADER_LEN + 2..total].to_vec();
            Ok(Some((Cell::Var { circ, cmd, payload }, total)))
        } else {
            if buf.len() < CELL_LEN {
                return Ok(None);
            }
            let mut payload = Box::new([0u8; CELL_PAYLOAD_LEN]);
            payload.copy_from_slice(&buf[CELL_HEADER_LEN..CELL_LEN]);
            Ok(Some((Cell::Fixed { circ, cmd, payload }, CELL_LEN)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_celula_fixa() {
        let c = Cell::fixed(CircId(0x1234_5678), ChanCmd::Relay, b"salut").unwrap();
        let mut buf = Vec::new();
        c.encode(&mut buf);
        assert_eq!(buf.len(), CELL_LEN);
        let (d, n) = Cell::decode(&buf).unwrap().unwrap();
        assert_eq!(n, CELL_LEN);
        assert_eq!(c, d);
        assert_eq!(&d.payload()[..5], b"salut");
    }

    #[test]
    fn roundtrip_celula_variabila() {
        let big = vec![0xAAu8; 2432];
        let c = Cell::var(CircId(7), ChanCmd::Create2, big.clone()).unwrap();
        let mut buf = Vec::new();
        c.encode(&mut buf);
        assert_eq!(buf.len(), 5 + 2 + 2432);
        let (d, n) = Cell::decode(&buf).unwrap().unwrap();
        assert_eq!(n, buf.len());
        assert_eq!(d.payload(), &big[..]);
    }

    #[test]
    fn decodare_incrementala() {
        // Simuleaza sosirea octetilor bucata cu bucata dintr-un socket.
        let c = Cell::var(CircId(1), ChanCmd::Create2, vec![9u8; 1312]).unwrap();
        let mut buf = Vec::new();
        c.encode(&mut buf);
        for n in 0..buf.len() {
            assert_eq!(
                Cell::decode(&buf[..n]).unwrap(),
                None,
                "prefixul de {n} octeti nu trebuie sa produca o celula"
            );
        }
        assert!(Cell::decode(&buf).unwrap().is_some());
    }

    #[test]
    fn doua_celule_lipite() {
        let a = Cell::fixed(CircId(1), ChanCmd::Relay, b"a").unwrap();
        let b = Cell::var(CircId(2), ChanCmd::Versions, vec![1, 2, 3]).unwrap();
        let mut buf = Vec::new();
        a.encode(&mut buf);
        b.encode(&mut buf);

        let (c1, n1) = Cell::decode(&buf).unwrap().unwrap();
        let (c2, n2) = Cell::decode(&buf[n1..]).unwrap().unwrap();
        assert_eq!(c1, a);
        assert_eq!(c2, b);
        assert_eq!(n1 + n2, buf.len());
    }

    #[test]
    fn forma_gresita_e_respinsa() {
        assert!(matches!(
            Cell::fixed(CircId(1), ChanCmd::Create2, b"x"),
            Err(WireError::WrongCellForm)
        ));
        assert!(matches!(
            Cell::var(CircId(1), ChanCmd::Relay, vec![1]),
            Err(WireError::WrongCellForm)
        ));
    }

    #[test]
    fn payload_prea_lung_e_respins() {
        assert!(Cell::fixed(CircId(1), ChanCmd::Relay, &[0u8; 510]).is_err());
        assert!(Cell::var(CircId(1), ChanCmd::Certs, vec![0u8; MAX_VAR_CELL_LEN + 1]).is_err());
    }

    #[test]
    fn comanda_necunoscuta_e_respinsa() {
        // O comanda necunoscuta nu se ignora tacit: ar deveni canal ascuns.
        let mut buf = vec![0, 0, 0, 1, 200];
        buf.extend_from_slice(&[0u8; 509]);
        assert!(matches!(
            Cell::decode(&buf),
            Err(WireError::UnknownChanCmd(200))
        ));
    }

    #[test]
    fn lungime_variabila_absurda_e_respinsa() {
        // Antet care pretinde 65535 de octeti: trebuie respins, nu alocat.
        let buf = vec![0, 0, 0, 1, ChanCmd::Certs as u8, 0xFF, 0xFF];
        assert!(matches!(
            Cell::decode(&buf),
            Err(WireError::PayloadTooLong { .. })
        ));
    }
}
