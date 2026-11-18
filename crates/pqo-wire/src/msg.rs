//! Mesajele tipizate de protocol.
//!
//! Aici se leaga stratul de fir de stratul criptografic: campul `data` al unui
//! [`Create2`] este exact iesirea lui `pqo_crypto::client_init`, iar campul
//! `data` al unui [`Created2`] este exact intrarea lui `client_finish`.
//!
//! Toate parserele sunt totale: pentru orice secventa de octeti intorc `Ok` sau
//! `Err`, niciodata panica.

use crate::WireError;

/// Tipul de handshake negociat.
///
/// Numerotarea porneste de la 0x0100 ca sa nu se suprapuna cu valorile Tor
/// (0=TAP, 1=reserved, 2=ntor, 3=ntor-v3). Un releu care primeste un tip
/// necunoscut respinge celula in loc sa incerce sa ghiceasca.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HandshakeType {
    /// `pq-ntor-v1`, varianta tranzitionala: confidentialitate PQ, autentificare clasica.
    PqNtorTransitional = 0x0100,
    /// `pq-ntor-v1`, varianta FullPq: si autentificarea e post-cuantica.
    PqNtorFullPq = 0x0101,
}

impl HandshakeType {
    pub fn from_u16(v: u16) -> Result<Self, WireError> {
        match v {
            0x0100 => Ok(HandshakeType::PqNtorTransitional),
            0x0101 => Ok(HandshakeType::PqNtorFullPq),
            other => Err(WireError::UnknownHandshake(other)),
        }
    }
}

/// Cum se identifica urmatorul releu intr-un EXTEND2.
///
/// Diferenta fata de Tor: identitatea e hash-ul cheii ML-DSA, nu o cheie Ed25519
/// bruta. Cheia ML-DSA-44 are 1312 de octeti si nu are ce cauta aici; legarea
/// dintre hash si cheia reala se verifica la validarea descriptorului.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkSpec {
    /// IPv4 + port.
    Ipv4 { addr: [u8; 4], port: u16 },
    /// IPv6 + port.
    Ipv6 { addr: [u8; 16], port: u16 },
    /// Hash-ul cheii de identitate a releului (SHAKE256 al cheii ML-DSA).
    RelayId([u8; 32]),
}

impl LinkSpec {
    const T_IPV4: u8 = 0;
    const T_IPV6: u8 = 1;
    const T_ID: u8 = 3;

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            LinkSpec::Ipv4 { addr, port } => {
                out.push(Self::T_IPV4);
                out.push(6);
                out.extend_from_slice(addr);
                out.extend_from_slice(&port.to_be_bytes());
            }
            LinkSpec::Ipv6 { addr, port } => {
                out.push(Self::T_IPV6);
                out.push(18);
                out.extend_from_slice(addr);
                out.extend_from_slice(&port.to_be_bytes());
            }
            LinkSpec::RelayId(id) => {
                out.push(Self::T_ID);
                out.push(32);
                out.extend_from_slice(id);
            }
        }
    }

    /// Parseaza un link specifier, intorcand si cati octeti a consumat.
    fn parse(buf: &[u8]) -> Result<(Self, usize), WireError> {
        if buf.len() < 2 {
            return Err(WireError::BadLinkSpec);
        }
        let t = buf[0];
        let len = buf[1] as usize;
        let total = 2 + len;
        if buf.len() < total {
            return Err(WireError::BadLinkSpec);
        }
        let body = &buf[2..total];
        let ls = match (t, len) {
            (Self::T_IPV4, 6) => LinkSpec::Ipv4 {
                addr: body[..4].try_into().map_err(|_| WireError::BadLinkSpec)?,
                port: u16::from_be_bytes([body[4], body[5]]),
            },
            (Self::T_IPV6, 18) => LinkSpec::Ipv6 {
                addr: body[..16].try_into().map_err(|_| WireError::BadLinkSpec)?,
                port: u16::from_be_bytes([body[16], body[17]]),
            },
            (Self::T_ID, 32) => {
                LinkSpec::RelayId(body.try_into().map_err(|_| WireError::BadLinkSpec)?)
            }
            _ => return Err(WireError::BadLinkSpec),
        };
        Ok((ls, total))
    }
}

/// CREATE2: cere crearea primului hop al unui circuit.
///
/// Format: `HandshakeType (u16) | Len (u16) | Data`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Create2 {
    pub htype: HandshakeType,
    pub data: Vec<u8>,
}

impl Create2 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.extend_from_slice(&(self.htype as u16).to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    pub fn parse(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() < 4 {
            return Err(WireError::Malformed);
        }
        let htype = HandshakeType::from_u16(u16::from_be_bytes([buf[0], buf[1]]))?;
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        // Lungime declarata trebuie sa se potriveasca exact. Octeti in plus la
        // final ar fi un canal ascuns.
        if buf.len() != 4 + len {
            return Err(WireError::Malformed);
        }
        Ok(Create2 {
            htype,
            data: buf[4..].to_vec(),
        })
    }
}

/// CREATED2 / EXTENDED2: raspunsul releului.
///
/// Format: `Len (u16) | Data`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Created2 {
    pub data: Vec<u8>,
}

impl Created2 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.data.len());
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    pub fn parse(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() < 2 {
            return Err(WireError::Malformed);
        }
        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if buf.len() != 2 + len {
            return Err(WireError::Malformed);
        }
        Ok(Created2 {
            data: buf[2..].to_vec(),
        })
    }
}

/// EXTENDED2 e identic ca format cu CREATED2.
pub type Extended2 = Created2;

/// EXTEND2: cere hop-ului curent sa extinda circuitul catre urmatorul releu.
///
/// Format: `NSpec (u8) | LinkSpec* | HandshakeType (u16) | Len (u16) | Data`
///
/// Asta e mesajul care **nu incape intr-o celula** cu handshake post-cuantic si
/// care forteaza fragmentarea. Vezi [`crate::relay`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extend2 {
    pub specs: Vec<LinkSpec>,
    pub htype: HandshakeType,
    pub data: Vec<u8>,
}

impl Extend2 {
    /// Cate link specifiers acceptam. Suficient pentru IPv4 + IPv6 + identitate.
    pub const MAX_SPECS: usize = 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.data.len());
        out.push(self.specs.len() as u8);
        for s in &self.specs {
            s.encode(&mut out);
        }
        out.extend_from_slice(&(self.htype as u16).to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    pub fn parse(buf: &[u8]) -> Result<Self, WireError> {
        let n = *buf.first().ok_or(WireError::Malformed)? as usize;
        if n > Self::MAX_SPECS {
            return Err(WireError::BadLinkSpec);
        }
        let mut off = 1usize;
        let mut specs = Vec::with_capacity(n);
        for _ in 0..n {
            let rest = buf.get(off..).ok_or(WireError::Malformed)?;
            let (ls, used) = LinkSpec::parse(rest)?;
            specs.push(ls);
            off += used;
        }
        let tail = buf.get(off..).ok_or(WireError::Malformed)?;
        if tail.len() < 4 {
            return Err(WireError::Malformed);
        }
        let htype = HandshakeType::from_u16(u16::from_be_bytes([tail[0], tail[1]]))?;
        let len = u16::from_be_bytes([tail[2], tail[3]]) as usize;
        if tail.len() != 4 + len {
            return Err(WireError::Malformed);
        }
        Ok(Extend2 {
            specs,
            htype,
            data: tail[4..].to_vec(),
        })
    }

    /// Releul care primeste EXTEND2 trebuie sa stie catre cine sa se extinda.
    /// Fara identitate nu poate verifica cu cine vorbeste, deci refuzam.
    pub fn relay_id(&self) -> Option<[u8; 32]> {
        self.specs.iter().find_map(|s| match s {
            LinkSpec::RelayId(id) => Some(*id),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extend2_exemplu(n: usize) -> Extend2 {
        Extend2 {
            specs: vec![
                LinkSpec::Ipv4 {
                    addr: [10, 0, 0, 7],
                    port: 9001,
                },
                LinkSpec::RelayId([0x5A; 32]),
            ],
            htype: HandshakeType::PqNtorTransitional,
            data: (0..n).map(|i| (i % 251) as u8).collect(),
        }
    }

    #[test]
    fn roundtrip_create2() {
        let m = Create2 {
            htype: HandshakeType::PqNtorFullPq,
            data: vec![7u8; 2432],
        };
        assert_eq!(Create2::parse(&m.encode()).unwrap(), m);
    }

    #[test]
    fn roundtrip_created2() {
        let m = Created2 {
            data: vec![3u8; 1184],
        };
        assert_eq!(Created2::parse(&m.encode()).unwrap(), m);
    }

    #[test]
    fn roundtrip_extend2() {
        let m = extend2_exemplu(1312);
        let e = m.encode();
        assert_eq!(Extend2::parse(&e).unwrap(), m);
        assert_eq!(m.relay_id(), Some([0x5A; 32]));
    }

    #[test]
    fn extend2_pq_nu_incape_intr_o_celula() {
        // Rezultatul care justifica tot modulul de fragmentare.
        let t = extend2_exemplu(1312).encode().len();
        let f = extend2_exemplu(2432).encode().len();
        assert!(t > crate::RELAY_DATA_LEN, "tranzitional: {t} octeti");
        assert!(f > crate::RELAY_DATA_LEN, "fullpq: {f} octeti");

        // Overhead-ul EXTEND2 peste handshake-ul propriu-zis:
        //   1 (nspec) + 8 (LinkSpec IPv4) + 34 (LinkSpec RelayId)
        // + 2 (HandshakeType) + 2 (Len) = 47 octeti.
        const OVERHEAD: usize = 1 + 8 + 34 + 2 + 2;
        assert_eq!(t, 1312 + OVERHEAD);
        assert_eq!(f, 2432 + OVERHEAD);

        // Numarul de celule necesare — cifra din capitolul de evaluare.
        let cel = |n: usize| n.div_ceil(crate::RELAY_DATA_LEN);
        // Cu CGO, datele utile per celula sunt 487, nu 503: tag-ul de 16 octeti
        // consuma din payload. FullPq a trecut astfel de la 5 celule la 6.
        assert_eq!(cel(t), 3, "EXTEND2 tranzitional ocupa 3 celule");
        assert_eq!(cel(f), 6, "EXTEND2 FullPq ocupa 6 celule");
    }

    #[test]
    fn octeti_in_plus_sunt_respinsi() {
        // Un canal ascuns clasic: date dupa campul declarat de lungime.
        let mut e = Create2 {
            htype: HandshakeType::PqNtorTransitional,
            data: vec![1, 2, 3],
        }
        .encode();
        e.push(0xFF);
        assert!(matches!(Create2::parse(&e), Err(WireError::Malformed)));

        let mut e2 = extend2_exemplu(10).encode();
        e2.push(0xFF);
        assert!(matches!(Extend2::parse(&e2), Err(WireError::Malformed)));
    }

    #[test]
    fn handshake_necunoscut_e_respins() {
        let mut e = Create2 {
            htype: HandshakeType::PqNtorTransitional,
            data: vec![],
        }
        .encode();
        e[0] = 0xFF;
        e[1] = 0xFF;
        assert!(matches!(
            Create2::parse(&e),
            Err(WireError::UnknownHandshake(0xFFFF))
        ));
    }

    #[test]
    fn prea_multe_link_specs() {
        let mut e = vec![255u8]; // pretinde 255 de specificatori
        e.extend_from_slice(&[0u8; 64]);
        assert!(matches!(Extend2::parse(&e), Err(WireError::BadLinkSpec)));
    }

    #[test]
    fn link_spec_cu_lungime_gresita() {
        // Tip IPv4 dar lungime 32: trebuie respins, nu interpretat.
        let e = vec![1u8, LinkSpec::T_IPV4, 32, 0, 0, 0, 0];
        assert!(matches!(Extend2::parse(&e), Err(WireError::BadLinkSpec)));
    }

    #[test]
    fn niciun_prefix_nu_produce_panica() {
        // Invariantul central al acestui crate.
        let cazuri = [
            extend2_exemplu(1312).encode(),
            Create2 {
                htype: HandshakeType::PqNtorFullPq,
                data: vec![9u8; 300],
            }
            .encode(),
            Created2 {
                data: vec![4u8; 300],
            }
            .encode(),
        ];
        for c in &cazuri {
            for n in 0..=c.len() {
                let _ = Extend2::parse(&c[..n]);
                let _ = Create2::parse(&c[..n]);
                let _ = Created2::parse(&c[..n]);
            }
        }
    }
}
