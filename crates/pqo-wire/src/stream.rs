//! Mesajele care deschid, alimenteaza si inchid un stream.
//!
//! Un circuit transporta mai multe stream-uri simultan, multiplexate dupa
//! [`crate::StreamId`]. Un stream corespunde de obicei unei conexiuni TCP pe care
//! releul de iesire o deschide catre destinatie.
//!
//! ```text
//!   client -> exit   BEGIN(adresa, port)
//!   exit   -> client CONNECTED(ip, ttl)   sau   END(motiv)
//!   ambele            DATA(...)
//!   ambele            SENDME               control de flux
//!   ambele            END(motiv)
//! ```

use crate::WireError;

/// Cat de lunga poate fi adresa dintr-un BEGIN.
///
/// Un nume de domeniu are cel mult 253 de caractere; plafonul de 255 vine din
/// campul de lungime pe un octet si e suficient.
pub const MAX_ADDR_LEN: usize = 255;

/// De ce s-a inchis un stream.
///
/// Motivul ajunge la client si il ajuta sa decida daca sa reincerce pe alt
/// circuit. Un exit care refuza din politica e altceva decat unul care nu a
/// putut rezolva numele.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EndReason {
    /// Motiv nespecificat.
    Misc = 1,
    /// Numele nu s-a putut rezolva.
    ResolveFailed = 2,
    /// Destinatia a refuzat conexiunea.
    ConnectRefused = 3,
    /// Politica de iesire a releului nu permite destinatia.
    ExitPolicy = 4,
    /// Circuitul se inchide.
    Destroy = 5,
    /// Inchidere normala, ambele capete au terminat.
    Done = 6,
    /// Conexiunea nu s-a stabilit in timp util.
    Timeout = 7,
    /// Nicio ruta catre destinatie.
    NoRoute = 8,
}

impl EndReason {
    pub fn from_u8(v: u8) -> Result<Self, WireError> {
        use EndReason::*;
        Ok(match v {
            1 => Misc,
            2 => ResolveFailed,
            3 => ConnectRefused,
            4 => ExitPolicy,
            5 => Destroy,
            6 => Done,
            7 => Timeout,
            8 => NoRoute,
            _ => return Err(WireError::Malformed),
        })
    }
}

/// Cere releului de iesire sa deschida o conexiune.
///
/// Format: `len u8 | adresa | port u16`
///
/// Adresa ramane **text** si se rezolva la exit, nu la client. Daca clientul ar
/// rezolva numele local, cererea DNS ar pleca prin reteaua lui si ar dezvalui ce
/// site viziteaza — exact scurgerea pe care onion routing trebuie sa o inchida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Begin {
    pub address: String,
    pub port: u16,
}

impl Begin {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let a = self.address.as_bytes();
        if a.is_empty() || a.len() > MAX_ADDR_LEN {
            return Err(WireError::Malformed);
        }
        let mut out = Vec::with_capacity(3 + a.len());
        out.push(a.len() as u8);
        out.extend_from_slice(a);
        out.extend_from_slice(&self.port.to_be_bytes());
        Ok(out)
    }

    pub fn parse(buf: &[u8]) -> Result<Self, WireError> {
        let n = *buf.first().ok_or(WireError::Malformed)? as usize;
        if n == 0 || buf.len() != 1 + n + 2 {
            return Err(WireError::Malformed);
        }
        let address = core::str::from_utf8(&buf[1..1 + n])
            .map_err(|_| WireError::Malformed)?
            .to_string();
        // Adresa devine argument pentru un rezolver; caracterele de control sau
        // spatiile ar putea fi folosite pentru injectie in stratul de deasupra.
        if address
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(WireError::Malformed);
        }
        let port = u16::from_be_bytes([buf[1 + n], buf[2 + n]]);
        if port == 0 {
            return Err(WireError::Malformed);
        }
        Ok(Begin { address, port })
    }
}

/// Confirmarea ca s-a deschis conexiunea.
///
/// Format: `ipv4 (4) | ttl u32`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connected {
    pub addr: [u8; 4],
    pub ttl: u32,
}

impl Connected {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&self.addr);
        out.extend_from_slice(&self.ttl.to_be_bytes());
        out
    }

    pub fn parse(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() != 8 {
            return Err(WireError::Malformed);
        }
        Ok(Connected {
            addr: buf[..4].try_into().expect("lungime verificata"),
            ttl: u32::from_be_bytes(buf[4..].try_into().expect("lungime verificata")),
        })
    }
}

/// Inchiderea unui stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct End {
    pub reason: EndReason,
}

impl End {
    pub fn encode(&self) -> Vec<u8> {
        vec![self.reason as u8]
    }

    pub fn parse(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() != 1 {
            return Err(WireError::Malformed);
        }
        Ok(End {
            reason: EndReason::from_u8(buf[0])?,
        })
    }
}

/// Confirmare de control de flux.
///
/// Format: `version u8`. Versiunea 1 nu poarta alte campuri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sendme {
    pub version: u8,
}

impl Sendme {
    pub const V1: Sendme = Sendme { version: 1 };

    pub fn encode(&self) -> Vec<u8> {
        vec![self.version]
    }

    pub fn parse(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() != 1 || buf[0] != 1 {
            return Err(WireError::Malformed);
        }
        Ok(Sendme::V1)
    }
}

// ---------------------------------------------------------------------------
// Control de flux
// ---------------------------------------------------------------------------

/// Fereastra initiala a unui circuit, in celule DATA.
pub const CIRC_WINDOW_START: i32 = 1000;
/// Cate celule primite declanseaza un SENDME de circuit.
pub const CIRC_WINDOW_INC: i32 = 100;
/// Fereastra initiala a unui stream.
pub const STREAM_WINDOW_START: i32 = 500;
/// Cate celule primite declanseaza un SENDME de stream.
pub const STREAM_WINDOW_INC: i32 = 50;

/// O fereastra de control de flux, intr-un singur sens.
///
/// # De ce e necesara
///
/// Fara ea, un releu de iesire care descarca rapid ar trimite celule mai repede
/// decat le poate consuma clientul. Celulele s-ar aduna in cozile releelor
/// intermediare, care ar consuma memorie pentru trafic care nu e al lor. Cu
/// destui clienti, asta e un atac de epuizare a memoriei deghizat in trafic
/// normal.
///
/// Ferestrele exista pe doua niveluri: per circuit si per stream. Cel de circuit
/// impiedica un singur circuit sa monopolizeze un releu; cel de stream
/// impiedica un singur stream sa monopolizeze circuitul.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowWindow {
    /// Cate celule mai putem trimite fara confirmare.
    send: i32,
    /// Cate am primit de la ultimul SENDME emis.
    recv: i32,
    increment: i32,
    max: i32,
}

impl FlowWindow {
    pub fn circuit() -> Self {
        FlowWindow {
            send: CIRC_WINDOW_START,
            recv: 0,
            increment: CIRC_WINDOW_INC,
            max: CIRC_WINDOW_START,
        }
    }

    pub fn stream() -> Self {
        FlowWindow {
            send: STREAM_WINDOW_START,
            recv: 0,
            increment: STREAM_WINDOW_INC,
            max: STREAM_WINDOW_START,
        }
    }

    /// Cate celule mai putem trimite acum.
    pub fn available(&self) -> i32 {
        self.send
    }

    /// Adevarat daca mai putem trimite.
    pub fn can_send(&self) -> bool {
        self.send > 0
    }

    /// Consuma o unitate la trimitere.
    pub fn on_send(&mut self) -> Result<(), WireError> {
        if self.send <= 0 {
            return Err(WireError::FlowControl);
        }
        self.send -= 1;
        Ok(())
    }

    /// Inregistreaza o celula primita. Intoarce `true` daca trebuie emis SENDME.
    pub fn on_recv(&mut self) -> bool {
        self.recv += 1;
        if self.recv >= self.increment {
            self.recv -= self.increment;
            true
        } else {
            false
        }
    }

    /// Proceseaza un SENDME primit.
    ///
    /// Respinge SENDME-uri in exces: un peer care ar trimite mai multe decat i se
    /// cuvin ar putea umfla fereastra la nesfarsit si ar anula tot mecanismul.
    pub fn on_sendme(&mut self) -> Result<(), WireError> {
        if self.send + self.increment > self.max {
            return Err(WireError::FlowControl);
        }
        self.send += self.increment;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_roundtrip() {
        let b = Begin {
            address: "example.com".into(),
            port: 443,
        };
        assert_eq!(Begin::parse(&b.encode().unwrap()).unwrap(), b);
    }

    #[test]
    fn begin_respinge_input_invalid() {
        // Adresa goala.
        assert!(Begin {
            address: String::new(),
            port: 80
        }
        .encode()
        .is_err());
        // Prea lunga.
        assert!(Begin {
            address: "a".repeat(MAX_ADDR_LEN + 1),
            port: 80
        }
        .encode()
        .is_err());
        // Port zero.
        let mut e = Begin {
            address: "a.com".into(),
            port: 1,
        }
        .encode()
        .unwrap();
        let n = e.len();
        e[n - 2] = 0;
        e[n - 1] = 0;
        assert!(Begin::parse(&e).is_err());
        // Octeti in plus dupa campul declarat.
        let mut e = Begin {
            address: "a.com".into(),
            port: 80,
        }
        .encode()
        .unwrap();
        e.push(0);
        assert!(Begin::parse(&e).is_err());
    }

    #[test]
    fn begin_respinge_caractere_de_control() {
        // Adresa ajunge la un rezolver; spatiile si caracterele de control ar
        // putea fi folosite pentru injectie in stratul de deasupra.
        for rea in ["a.com\n", "a b.com", "a\0.com", "a\t.com"] {
            let mut e = vec![rea.len() as u8];
            e.extend_from_slice(rea.as_bytes());
            e.extend_from_slice(&80u16.to_be_bytes());
            assert!(Begin::parse(&e).is_err(), "acceptat: {rea:?}");
        }
    }

    #[test]
    fn connected_end_sendme_roundtrip() {
        let c = Connected {
            addr: [1, 2, 3, 4],
            ttl: 300,
        };
        assert_eq!(Connected::parse(&c.encode()).unwrap(), c);

        let e = End {
            reason: EndReason::ConnectRefused,
        };
        assert_eq!(End::parse(&e.encode()).unwrap(), e);

        assert_eq!(Sendme::parse(&Sendme::V1.encode()).unwrap(), Sendme::V1);
        assert!(Sendme::parse(&[2]).is_err(), "versiune necunoscuta");
        assert!(End::parse(&[99]).is_err(), "motiv necunoscut");
    }

    #[test]
    fn niciun_prefix_nu_produce_panica() {
        let cazuri = [
            Begin {
                address: "example.com".into(),
                port: 443,
            }
            .encode()
            .unwrap(),
            Connected {
                addr: [1, 2, 3, 4],
                ttl: 1,
            }
            .encode(),
            End {
                reason: EndReason::Done,
            }
            .encode(),
            Sendme::V1.encode(),
        ];
        for c in &cazuri {
            for n in 0..=c.len() {
                let _ = Begin::parse(&c[..n]);
                let _ = Connected::parse(&c[..n]);
                let _ = End::parse(&c[..n]);
                let _ = Sendme::parse(&c[..n]);
            }
        }
    }

    #[test]
    fn fereastra_se_epuizeaza() {
        let mut w = FlowWindow::stream();
        for _ in 0..STREAM_WINDOW_START {
            w.on_send().unwrap();
        }
        assert!(!w.can_send());
        assert_eq!(w.on_send(), Err(WireError::FlowControl));
    }

    #[test]
    fn sendme_redeschide_fereastra() {
        let mut w = FlowWindow::stream();
        for _ in 0..STREAM_WINDOW_INC {
            w.on_send().unwrap();
        }
        let inainte = w.available();
        w.on_sendme().unwrap();
        assert_eq!(w.available(), inainte + STREAM_WINDOW_INC);
    }

    #[test]
    fn sendme_in_exces_e_respins() {
        // Un peer care trimite SENDME-uri nesolicitate ar umfla fereastra la
        // nesfarsit si ar anula tot mecanismul.
        let mut w = FlowWindow::stream();
        assert_eq!(w.on_sendme(), Err(WireError::FlowControl));
    }

    #[test]
    fn receptia_declanseaza_sendme_periodic() {
        let mut w = FlowWindow::circuit();
        let mut emise = 0;
        for _ in 0..(CIRC_WINDOW_INC * 3) {
            if w.on_recv() {
                emise += 1;
            }
        }
        assert_eq!(emise, 3, "cate un SENDME la fiecare {CIRC_WINDOW_INC} celule");
    }

    #[test]
    fn ciclu_complet_de_flux() {
        // Emitatorul trimite pana se blocheaza, receptorul confirma, emitatorul
        // continua. Fara pierderi si fara depasire.
        let mut tx = FlowWindow::circuit();
        let mut rx = FlowWindow::circuit();
        let mut trimise = 0;

        for _ in 0..5000 {
            if !tx.can_send() {
                break;
            }
            tx.on_send().unwrap();
            trimise += 1;
            if rx.on_recv() {
                tx.on_sendme().unwrap();
            }
        }
        assert!(
            trimise > CIRC_WINDOW_START,
            "SENDME-urile trebuie sa permita depasirea ferestrei initiale"
        );
        assert!(tx.available() <= CIRC_WINDOW_START, "fereastra nu se umfla");
    }
}
