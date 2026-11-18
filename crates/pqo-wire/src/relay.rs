//! Mesajele relay: formatul din interiorul unei celule RELAY, plus fragmentarea.
//!
//! # Formatul celulei relay
//!
//! Payload-ul de 509 octeti al unei celule RELAY se imparte in tag-ul CGO de 16
//! octeti si un corp de 493. Acest modul lucreaza pe corp; tag-ul e treaba
//! stratului de criptare. Structura corpului, dupa decriptare:
//!
//! ```text
//! +0  Command  : u8       comanda relay
//! +1  StreamID : u16 BE   0 pentru mesaje de control (EXTEND2, SENDME de circuit)
//! +3  Flags    : u8       bit 0 = MORE (mai urmeaza fragmente)
//! +4  FragLen  : u16 BE   octeti utili in ACEASTA celula
//! +6  Data     : [u8; 503]
//! ```
//!
//! Diferenta fata de Tor: **nu exista camp `Digest` si nici `Recognized`.**
//! In tor1, cei 4 octeti de digest SHA-1 trunchiat serveau simultan la
//! integritate end-to-end si la recunoasterea hop-ului destinatie. CGO ofera un
//! autentificator de 16 octeti la nivelul stratului de criptare, deci campul e
//! redundant si il eliminam. Castigam 6 octeti de payload util per celula si
//! scapam de SHA-1.
//!
//! Consecinta de documentat: recunoasterea hop-ului nu se mai face prin
//! `recognized == 0`, ci prin reusita verificarii autentificatorului CGO. Asta
//! schimba si semantica "leaky pipe" (capacitatea de a livra un mesaj la un hop
//! intermediar), pe care o pierdem. Nu o folosim in MVP.
//!
//! # De ce fragmentele non-finale trebuie sa fie pline
//!
//! Un fragment cu MORE setat **trebuie** sa aiba `FragLen == RELAY_DATA_LEN`.
//! Daca am permite fragmente scurte la mijloc, lungimile ar deveni un canal
//! ascuns: un releu malitios ar putea codifica informatie in tiparul de lungimi
//! si un complice de la celalalt capat l-ar citi. Regula e verificata la
//! reasamblare si e o aparare, nu o optimizare.

use rand_core::RngCore;

use crate::cell::CELL_PAYLOAD_LEN;
use crate::WireError;

/// Lungimea tag-ului de autentificare CGO, la inceputul fiecarei celule.
///
/// Trebuie sa fie egala cu `pqo_crypto::cgo::BLK_LEN`. Nu importam constanta ca
/// sa nu inversam stratificarea (formatul de fir nu depinde de criptografie);
/// egalitatea e verificata de un test in `tests/integrare_circuit.rs`.
pub const CGO_TAG_LEN: usize = 16;

/// Corpul unei celule relay, dupa tag-ul CGO. Egal cu `pqo_crypto::cgo::LEN_XR`.
pub const RELAY_BODY_LEN: usize = CELL_PAYLOAD_LEN - CGO_TAG_LEN; // 493

/// Antetul mesajului relay.
pub const RELAY_HEADER_LEN: usize = 6;

/// Octeti de date utili per celula relay.
///
/// Scazut de la 503 la 487 cand am adaugat CGO: tag-ul de 16 octeti consuma din
/// payload. Compensam partial fata de `tor1` prin eliminarea campului `Digest`
/// de 4 octeti si a lui `Recognized` de 2, care erau redundante — vezi nota de
/// mai jos. Net: -10 octeti utili per celula, in schimbul unui autentificator
/// de patru ori mai lung si al forward secrecy imediate.
pub const RELAY_DATA_LEN: usize = RELAY_BODY_LEN - RELAY_HEADER_LEN; // 487

/// Lungimea maxima a unui mesaj relay reasamblat.
///
/// Cel mai mare mesaj legitim e un EXTEND2 cu handshake FullPq hibrid:
/// ~2432 (handshake) + ~80 (link specifiers) + 4 = ~2.5 KB. Limita de 16 KB
/// lasa marja pentru descriptori de servicii ascunse, dar plafoneaza memoria pe
/// care o poate consuma un peer malitios trimitand fragmente la nesfarsit.
pub const MAX_MESSAGE_LEN: usize = 16 * 1024;

/// Cate mesaje partiale poate avea un circuit in acelasi timp.
///
/// Fiecare stream isi poate reasambla propriul mesaj. Limita opreste un atac in
/// care cineva deschide mii de stream-uri si trimite cate un fragment in fiecare.
pub const MAX_PARTIAL_MESSAGES: usize = 8;

/// Bitul de continuare.
pub const FLAG_MORE: u8 = 0x01;

/// Identificator de stream in cadrul unui circuit. 0 = mesaj de control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(pub u16);

impl StreamId {
    pub const CONTROL: StreamId = StreamId(0);
    pub fn is_control(self) -> bool {
        self.0 == 0
    }
}

/// Comenzile de nivel relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayCmd {
    Begin = 1,
    Data = 2,
    End = 3,
    Connected = 4,
    Sendme = 5,
    Truncate = 8,
    Truncated = 9,
    Drop = 10,
    /// Deschide un stream catre serviciul de director al releului insusi.
    ///
    /// Spre deosebire de BEGIN, nu deschide nicio conexiune in exterior: releul
    /// raspunde din propriile documente.
    BeginDir = 13,
    Extend2 = 14,
    Extended2 = 15,
    // Servicii ascunse
    EstablishIntro = 32,
    EstablishRendezvous = 33,
    Introduce1 = 34,
    Introduce2 = 35,
    Rendezvous1 = 36,
    Rendezvous2 = 37,
    IntroEstablished = 38,
    RendezvousEstablished = 39,
    IntroduceAck = 40,
}

impl RelayCmd {
    pub fn from_u8(v: u8) -> Result<Self, WireError> {
        use RelayCmd::*;
        Ok(match v {
            1 => Begin,
            2 => Data,
            3 => End,
            4 => Connected,
            5 => Sendme,
            8 => Truncate,
            9 => Truncated,
            10 => Drop,
            13 => BeginDir,
            14 => Extend2,
            15 => Extended2,
            32 => EstablishIntro,
            33 => EstablishRendezvous,
            34 => Introduce1,
            35 => Introduce2,
            36 => Rendezvous1,
            37 => Rendezvous2,
            38 => IntroEstablished,
            39 => RendezvousEstablished,
            40 => IntroduceAck,
            other => return Err(WireError::UnknownRelayCmd(other)),
        })
    }

    /// Pe ce fel de stream are voie sa apara aceasta comanda.
    ///
    /// Verificarea inchide o clasa de confuzii intre planul de control si cel de
    /// date — de exemplu un EXTEND2 injectat pe un stream de date.
    ///
    /// [`StreamKind::Either`] exista pentru SENDME, care e **legitim pe ambele
    /// niveluri**: pe stream-ul de control confirma fereastra circuitului, pe un
    /// stream de date confirma fereastra acelui stream. O verificare rigida
    /// control-sau-date ar face controlul de flux imposibil de exprimat.
    pub fn stream_kind(self) -> StreamKind {
        use RelayCmd::*;
        match self {
            Extend2 | Extended2 | Truncate | Truncated | Drop | EstablishIntro
            | EstablishRendezvous | Introduce1 | Introduce2 | Rendezvous1 | Rendezvous2
            | IntroEstablished | RendezvousEstablished | IntroduceAck => StreamKind::Control,
            Sendme => StreamKind::Either,
            Begin | BeginDir | Data | End | Connected => StreamKind::Data,
        }
    }

    /// Verifica potrivirea dintre comanda si stream.
    pub fn check_stream(self, stream: StreamId) -> Result<(), WireError> {
        match (self.stream_kind(), stream.is_control()) {
            (StreamKind::Control, false) | (StreamKind::Data, true) => {
                Err(WireError::StreamMismatch)
            }
            _ => Ok(()),
        }
    }
}

/// Pe ce fel de stream poate aparea o comanda.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// Doar pe stream-ul de control (ID 0).
    Control,
    /// Doar pe un stream de date (ID != 0).
    Data,
    /// Pe oricare. Vezi nota de la [`RelayCmd::stream_kind`].
    Either,
}

/// Un mesaj relay complet, dupa reasamblare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayMessage {
    pub cmd: RelayCmd,
    pub stream: StreamId,
    pub body: Vec<u8>,
}

impl RelayMessage {
    pub fn new(cmd: RelayCmd, stream: StreamId, body: Vec<u8>) -> Result<Self, WireError> {
        if body.len() > MAX_MESSAGE_LEN {
            return Err(WireError::MessageTooLong {
                max: MAX_MESSAGE_LEN,
                got: body.len(),
            });
        }
        cmd.check_stream(stream)?;
        Ok(RelayMessage { cmd, stream, body })
    }

    /// Cate celule ocupa acest mesaj.
    pub fn cell_count(&self) -> usize {
        if self.body.is_empty() {
            1
        } else {
            self.body.len().div_ceil(RELAY_DATA_LEN)
        }
    }

    /// Imparte mesajul in payload-uri de celula de exact 509 octeti.
    ///
    /// Ultimul fragment se completeaza cu **umplutura aleatoare**, nu cu zerouri.
    /// Zerourile ar fi distinctibile dupa criptare doar daca cifrul ar fi slab,
    /// dar mai important: umplutura deterministă e un vector de atac cu text
    /// clar cunoscut. Costul unei surse de aleator e neglijabil aici.
    pub fn fragment(&self, rng: &mut impl RngCore) -> Vec<[u8; RELAY_BODY_LEN]> {
        let mut out = Vec::with_capacity(self.cell_count());
        let mut rest: &[u8] = &self.body;

        loop {
            let take = rest.len().min(RELAY_DATA_LEN);
            let more = rest.len() > take;

            let mut cell = [0u8; RELAY_BODY_LEN];
            rng.fill_bytes(&mut cell);

            cell[0] = self.cmd as u8;
            cell[1..3].copy_from_slice(&self.stream.0.to_be_bytes());
            cell[3] = if more { FLAG_MORE } else { 0 };
            cell[4..6].copy_from_slice(&(take as u16).to_be_bytes());
            cell[RELAY_HEADER_LEN..RELAY_HEADER_LEN + take].copy_from_slice(&rest[..take]);

            out.push(cell);
            rest = &rest[take..];
            if !more {
                break;
            }
        }
        out
    }
}

/// Un fragment decodat dintr-un payload de celula.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fragment<'a> {
    cmd: RelayCmd,
    stream: StreamId,
    more: bool,
    data: &'a [u8],
}

fn parse_fragment(payload: &[u8]) -> Result<Fragment<'_>, WireError> {
    if payload.len() != RELAY_BODY_LEN {
        return Err(WireError::BadFragment);
    }
    let cmd = RelayCmd::from_u8(payload[0])?;
    let stream = StreamId(u16::from_be_bytes([payload[1], payload[2]]));
    let flags = payload[3];
    // Bitii nefolositi trebuie sa fie zero. Altfel devin canal ascuns.
    if flags & !FLAG_MORE != 0 {
        return Err(WireError::ReservedBitsSet);
    }
    let more = flags & FLAG_MORE != 0;
    let len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if len > RELAY_DATA_LEN {
        return Err(WireError::BadFragment);
    }
    // Un fragment non-final trebuie sa fie plin. Vezi nota de modul.
    if more && len != RELAY_DATA_LEN {
        return Err(WireError::ShortNonFinalFragment);
    }
    cmd.check_stream(stream)?;
    Ok(Fragment {
        cmd,
        stream,
        more,
        data: &payload[RELAY_HEADER_LEN..RELAY_HEADER_LEN + len],
    })
}

struct Partial {
    cmd: RelayCmd,
    buf: Vec<u8>,
}

/// Reasambleaza mesaje relay fragmentate, cu limite stricte de memorie.
///
/// Cate o instanta per circuit si per directie. Nu e `Clone`: doua reasamblatoare
/// care impart aceeasi stare ar putea accepta fragmente intretesute din surse
/// diferite.
#[derive(Default)]
pub struct Reassembler {
    partials: Vec<(StreamId, Partial)>,
}

impl core::fmt::Debug for Reassembler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Reassembler({} partiale)", self.partials.len())
    }
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Numarul de mesaje partiale in curs. Util pentru metrici, fara continut.
    pub fn pending(&self) -> usize {
        self.partials.len()
    }

    /// Consuma un payload de celula relay decriptat.
    ///
    /// Intoarce `Ok(Some(msg))` cand un mesaj s-a completat, `Ok(None)` cand
    /// asteapta fragmente in plus.
    pub fn push(&mut self, payload: &[u8]) -> Result<Option<RelayMessage>, WireError> {
        let frag = parse_fragment(payload)?;

        // Cazul rapid: mesaj de o singura celula, fara stare.
        let idx = self.partials.iter().position(|(s, _)| *s == frag.stream);
        if idx.is_none() && !frag.more {
            return Ok(Some(RelayMessage {
                cmd: frag.cmd,
                stream: frag.stream,
                body: frag.data.to_vec(),
            }));
        }

        match idx {
            None => {
                if self.partials.len() >= MAX_PARTIAL_MESSAGES {
                    return Err(WireError::TooManyPartials);
                }
                self.partials.push((
                    frag.stream,
                    Partial {
                        cmd: frag.cmd,
                        buf: frag.data.to_vec(),
                    },
                ));
                Ok(None)
            }
            Some(i) => {
                // Comanda nu are voie sa se schimbe la mijlocul unui mesaj.
                if self.partials[i].1.cmd != frag.cmd {
                    self.partials.remove(i);
                    return Err(WireError::InconsistentFragment);
                }
                if self.partials[i].1.buf.len() + frag.data.len() > MAX_MESSAGE_LEN {
                    self.partials.remove(i);
                    return Err(WireError::MessageTooLong {
                        max: MAX_MESSAGE_LEN,
                        got: self.partials.len(),
                    });
                }
                self.partials[i].1.buf.extend_from_slice(frag.data);
                if frag.more {
                    Ok(None)
                } else {
                    let (stream, partial) = self.partials.remove(i);
                    Ok(Some(RelayMessage {
                        cmd: partial.cmd,
                        stream,
                        body: partial.buf,
                    }))
                }
            }
        }
    }

    /// Abandoneaza toate mesajele partiale. De apelat la inchiderea circuitului.
    pub fn reset(&mut self) {
        self.partials.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn rt(cmd: RelayCmd, stream: StreamId, n: usize) {
        let body: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        let msg = RelayMessage::new(cmd, stream, body.clone()).unwrap();
        let cells = msg.fragment(&mut OsRng);

        assert_eq!(cells.len(), msg.cell_count(), "numar de celule gresit");
        for c in &cells {
            assert_eq!(c.len(), RELAY_BODY_LEN, "toate corpurile au 493 octeti");
        }

        let mut r = Reassembler::new();
        let mut got = None;
        for (i, c) in cells.iter().enumerate() {
            let res = r.push(c).expect("push");
            if i + 1 == cells.len() {
                got = res;
            } else {
                assert!(
                    res.is_none(),
                    "mesaj complet prea devreme la fragmentul {i}"
                );
            }
        }
        let got = got.expect("mesajul trebuia sa se completeze");
        assert_eq!(got.body, body);
        assert_eq!(got.cmd, cmd);
        assert_eq!(got.stream, stream);
        assert_eq!(r.pending(), 0, "nu trebuie sa ramana stare");
    }

    #[test]
    fn mesaj_gol() {
        rt(RelayCmd::Sendme, StreamId(5), 0);
    }

    #[test]
    fn mesaj_intr_o_celula() {
        rt(RelayCmd::Data, StreamId(5), 100);
    }

    #[test]
    fn exact_o_celula_plina() {
        rt(RelayCmd::Data, StreamId(5), RELAY_DATA_LEN);
    }

    #[test]
    fn cu_un_octet_peste_o_celula() {
        rt(RelayCmd::Data, StreamId(5), RELAY_DATA_LEN + 1);
    }

    #[test]
    fn handshake_pq_tranzitional() {
        // EXTEND2 cu handshake hibrid X25519+MLKEM768, varianta tranzitionala.
        rt(RelayCmd::Extend2, StreamId::CONTROL, 1312 + 80);
    }

    #[test]
    fn handshake_pq_fullpq() {
        rt(RelayCmd::Extend2, StreamId::CONTROL, 2432 + 80);
    }

    #[test]
    fn mesaj_maxim() {
        rt(RelayCmd::Data, StreamId(1), MAX_MESSAGE_LEN);
    }

    #[test]
    fn toate_lungimile_pana_la_trei_celule() {
        for n in 0..(3 * RELAY_DATA_LEN + 2) {
            rt(RelayCmd::Data, StreamId(9), n);
        }
    }

    #[test]
    fn umplutura_e_aleatoare() {
        let msg = RelayMessage::new(RelayCmd::Data, StreamId(1), vec![0u8; 10]).unwrap();
        let a = msg.fragment(&mut OsRng)[0];
        let b = msg.fragment(&mut OsRng)[0];
        // Antetul si datele coincid; umplutura nu.
        assert_eq!(&a[..16], &b[..16]);
        assert_ne!(&a[100..], &b[100..], "umplutura trebuie sa fie aleatoare");
    }

    #[test]
    fn streamuri_intretesute() {
        // Doua mesaje lungi pe stream-uri diferite, fragmente intercalate.
        let m1 = RelayMessage::new(RelayCmd::Data, StreamId(1), vec![0xAA; 1200]).unwrap();
        let m2 = RelayMessage::new(RelayCmd::Data, StreamId(2), vec![0xBB; 1200]).unwrap();
        let c1 = m1.fragment(&mut OsRng);
        let c2 = m2.fragment(&mut OsRng);
        assert_eq!(c1.len(), 3);

        let mut r = Reassembler::new();
        let mut done = Vec::new();
        for i in 0..3 {
            if let Some(m) = r.push(&c1[i]).unwrap() {
                done.push(m);
            }
            if let Some(m) = r.push(&c2[i]).unwrap() {
                done.push(m);
            }
        }
        assert_eq!(done.len(), 2);
        assert_eq!(done[0].body, m1.body);
        assert_eq!(done[1].body, m2.body);
    }

    #[test]
    fn fragment_non_final_scurt_e_respins() {
        let mut c = [0u8; RELAY_BODY_LEN];
        c[0] = RelayCmd::Data as u8;
        c[1..3].copy_from_slice(&1u16.to_be_bytes());
        c[3] = FLAG_MORE;
        c[4..6].copy_from_slice(&10u16.to_be_bytes()); // scurt, dar MORE setat
        let mut r = Reassembler::new();
        assert!(matches!(r.push(&c), Err(WireError::ShortNonFinalFragment)));
    }

    #[test]
    fn biti_rezervati_sunt_respinsi() {
        let mut c = [0u8; RELAY_BODY_LEN];
        c[0] = RelayCmd::Data as u8;
        c[1..3].copy_from_slice(&1u16.to_be_bytes());
        c[3] = 0x80; // bit rezervat
        let mut r = Reassembler::new();
        assert!(matches!(r.push(&c), Err(WireError::ReservedBitsSet)));
    }

    #[test]
    fn confuzie_control_date_e_respinsa() {
        // EXTEND2 pe un stream de date: interzis.
        assert!(matches!(
            RelayMessage::new(RelayCmd::Extend2, StreamId(7), vec![]),
            Err(WireError::StreamMismatch)
        ));
        // DATA pe stream-ul de control: la fel.
        assert!(matches!(
            RelayMessage::new(RelayCmd::Data, StreamId::CONTROL, vec![]),
            Err(WireError::StreamMismatch)
        ));
    }

    #[test]
    fn sendme_e_valid_pe_ambele_niveluri() {
        // Controlul de flux are doua niveluri: SENDME pe stream-ul de control
        // confirma fereastra circuitului, pe un stream de date confirma
        // fereastra acelui stream. Prima versiune interzicea unul dintre cazuri
        // si facea transferurile mari imposibile.
        assert!(RelayMessage::new(RelayCmd::Sendme, StreamId::CONTROL, vec![1]).is_ok());
        assert!(RelayMessage::new(RelayCmd::Sendme, StreamId(7), vec![1]).is_ok());
        assert_eq!(RelayCmd::Sendme.stream_kind(), StreamKind::Either);
    }

    #[test]
    fn prea_multe_mesaje_partiale() {
        let mut r = Reassembler::new();
        let mut c = [0u8; RELAY_BODY_LEN];
        c[0] = RelayCmd::Data as u8;
        c[3] = FLAG_MORE;
        c[4..6].copy_from_slice(&(RELAY_DATA_LEN as u16).to_be_bytes());
        for s in 1..=MAX_PARTIAL_MESSAGES {
            c[1..3].copy_from_slice(&(s as u16).to_be_bytes());
            assert!(r.push(&c).unwrap().is_none());
        }
        c[1..3].copy_from_slice(&999u16.to_be_bytes());
        assert!(matches!(r.push(&c), Err(WireError::TooManyPartials)));
    }

    #[test]
    fn mesaj_prea_lung_e_oprit() {
        let mut r = Reassembler::new();
        let mut c = [0u8; RELAY_BODY_LEN];
        c[0] = RelayCmd::Data as u8;
        c[1..3].copy_from_slice(&1u16.to_be_bytes());
        c[3] = FLAG_MORE;
        c[4..6].copy_from_slice(&(RELAY_DATA_LEN as u16).to_be_bytes());
        // Trimite fragmente pline la nesfarsit; trebuie oprit sub limita.
        let mut n = 0;
        loop {
            match r.push(&c) {
                Ok(_) => {
                    n += 1;
                    assert!(n < 100, "reasamblatorul nu s-a oprit");
                }
                Err(WireError::MessageTooLong { .. }) => break,
                Err(e) => panic!("eroare neasteptata: {e:?}"),
            }
        }
        assert_eq!(r.pending(), 0, "starea trebuie curatata la eroare");
    }

    #[test]
    fn comanda_schimbata_la_mijloc_e_respinsa() {
        let mut r = Reassembler::new();
        let mut c = [0u8; RELAY_BODY_LEN];
        c[0] = RelayCmd::Data as u8;
        c[1..3].copy_from_slice(&1u16.to_be_bytes());
        c[3] = FLAG_MORE;
        c[4..6].copy_from_slice(&(RELAY_DATA_LEN as u16).to_be_bytes());
        assert!(r.push(&c).unwrap().is_none());
        c[0] = RelayCmd::End as u8;
        c[3] = 0;
        c[4..6].copy_from_slice(&5u16.to_be_bytes());
        assert!(matches!(r.push(&c), Err(WireError::InconsistentFragment)));
    }

    #[test]
    fn lungime_gresita_de_payload_e_respinsa() {
        let mut r = Reassembler::new();
        for n in [0usize, 1, 492, 494, 1024] {
            let v = vec![0u8; n];
            assert!(matches!(r.push(&v), Err(WireError::BadFragment)));
        }
    }
}
