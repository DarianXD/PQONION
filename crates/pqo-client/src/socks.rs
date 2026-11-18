//! Frontend SOCKS5.
//!
//! Traduce cererile unei aplicatii locale in stream-uri prin circuit. Cu asta
//! poti pune un browser in spate.
//!
//! # Regula care conteaza pentru anonimitate
//!
//! Aplicatia trebuie sa trimita **numele de domeniu**, nu adresa IP. SOCKS5
//! permite ambele: `ATYP=3` e nume, `ATYP=1` e IPv4.
//!
//! Daca aplicatia trimite un IP, inseamna ca a rezolvat deja numele — iar cererea
//! DNS a plecat prin reteaua locala, in clar, catre rezolverul furnizorului. Tot
//! circuitul devine inutil: nu mai conteaza pe unde trece traficul daca operatorul
//! retelei stie deja ce site ai cautat. In Firefox e
//! `network.proxy.socks_remote_dns = true`; in `curl` e `--socks5-hostname`, nu
//! `--socks5`.
//!
//! Nu putem impune asta din server — cererea a plecat deja. Dar o **numaram** si
//! o raportam prin [`SocksStats::ip_literals`], ca sa fie vizibila.
//!
//! # Ce nu implementeaza
//!
//! Doar `CONNECT`. `BIND` si `UDP ASSOCIATE` nu au sens peste circuite: primul
//! cere conexiuni de intrare, al doilea trafic UDP, iar circuitele transporta doar
//! fluxuri TCP.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Versiunea protocolului.
const VER: u8 = 5;
/// Metoda „fara autentificare".
const NO_AUTH: u8 = 0;
/// Nicio metoda acceptabila.
const NO_METHOD: u8 = 0xFF;
/// Comanda CONNECT.
const CMD_CONNECT: u8 = 1;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

/// Coduri de raspuns SOCKS5.
pub mod reply {
    pub const SUCCESS: u8 = 0;
    pub const GENERAL_FAILURE: u8 = 1;
    pub const NOT_ALLOWED: u8 = 2;
    pub const HOST_UNREACHABLE: u8 = 4;
    pub const CONNECTION_REFUSED: u8 = 5;
    pub const CMD_NOT_SUPPORTED: u8 = 7;
    pub const ATYP_NOT_SUPPORTED: u8 = 8;
}

/// Ce a cerut aplicatia.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub address: String,
    pub port: u16,
    /// Adevarat daca aplicatia a trimis o adresa IP in loc de nume.
    ///
    /// Inseamna ca a facut deja o cerere DNS in clar. Vezi nota de modul.
    pub was_ip_literal: bool,
}

/// Contoare, pentru diagnostic.
#[derive(Debug, Default)]
pub struct SocksStats {
    cereri: AtomicU64,
    ip_literals: AtomicU64,
}

impl SocksStats {
    pub fn requests(&self) -> u64 {
        self.cereri.load(Ordering::Relaxed)
    }

    /// Cate cereri au sosit cu adresa IP in loc de nume.
    ///
    /// Orice valoare peste zero inseamna ca aplicatia scurge DNS.
    pub fn ip_literals(&self) -> u64 {
        self.ip_literals.load(Ordering::Relaxed)
    }
}

/// Ruleaza partea de negociere SOCKS5 si intoarce ce s-a cerut.
///
/// Dupa asta apelantul deschide stream-ul si cheama [`send_reply`].
pub async fn handshake<T>(sock: &mut T, stats: &Arc<SocksStats>) -> io::Result<Request>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // --- Alegerea metodei de autentificare ---
    let mut cap = [0u8; 2];
    sock.read_exact(&mut cap).await?;
    if cap[0] != VER {
        return Err(bad("versiune SOCKS nesuportata"));
    }
    let n = cap[1] as usize;
    if n == 0 {
        return Err(bad("nicio metoda propusa"));
    }
    let mut metode = vec![0u8; n];
    sock.read_exact(&mut metode).await?;

    if !metode.contains(&NO_AUTH) {
        sock.write_all(&[VER, NO_METHOD]).await?;
        return Err(bad("clientul nu accepta conectare fara autentificare"));
    }
    sock.write_all(&[VER, NO_AUTH]).await?;

    // --- Cererea propriu-zisa ---
    let mut antet = [0u8; 4];
    sock.read_exact(&mut antet).await?;
    if antet[0] != VER {
        return Err(bad("versiune SOCKS nesuportata"));
    }
    if antet[1] != CMD_CONNECT {
        send_reply(sock, reply::CMD_NOT_SUPPORTED).await?;
        return Err(bad("doar CONNECT e suportat"));
    }

    let (address, was_ip_literal) = match antet[3] {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await?;
            (
                format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
                true,
            )
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            if len[0] == 0 {
                return Err(bad("nume gol"));
            }
            let mut d = vec![0u8; len[0] as usize];
            sock.read_exact(&mut d).await?;
            let s = String::from_utf8(d).map_err(|_| bad("nume invalid"))?;
            // Numele ajunge la exit, care il da unui rezolver. Caracterele de
            // control sau spatiile n-au ce cauta acolo.
            if s.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err(bad("nume cu caractere invalide"));
            }
            (s, false)
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await?;
            let ip = std::net::Ipv6Addr::from(a);
            (ip.to_string(), true)
        }
        _ => {
            send_reply(sock, reply::ATYP_NOT_SUPPORTED).await?;
            return Err(bad("tip de adresa nesuportat"));
        }
    };

    let mut p = [0u8; 2];
    sock.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);
    if port == 0 {
        return Err(bad("port zero"));
    }

    stats.cereri.fetch_add(1, Ordering::Relaxed);
    if was_ip_literal {
        stats.ip_literals.fetch_add(1, Ordering::Relaxed);
    }

    Ok(Request {
        address,
        port,
        was_ip_literal,
    })
}

/// Trimite raspunsul SOCKS5.
///
/// Adresa raportata e mereu `0.0.0.0:0`. Adresa reala a exit-ului nu il priveste
/// pe client, si oricum nu o stie: circuitul e tot rostul.
pub async fn send_reply<T>(sock: &mut T, code: u8) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    sock.write_all(&[VER, code, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
}

fn bad(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn negociaza(cerere: &[u8]) -> (io::Result<Request>, Vec<u8>, Arc<SocksStats>) {
        let (mut client, mut server) = duplex(4096);
        let stats = Arc::new(SocksStats::default());
        let s2 = Arc::clone(&stats);

        let h = tokio::spawn(async move { handshake(&mut server, &s2).await });
        client.write_all(cerere).await.unwrap();

        let r = h.await.unwrap();
        // Citim ce a raspuns serverul.
        let mut out = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            client.read_to_end(&mut out),
        )
        .await;
        (r, out, stats)
    }

    fn cerere_domeniu(nume: &str, port: u16) -> Vec<u8> {
        let mut v = vec![VER, 1, NO_AUTH, VER, CMD_CONNECT, 0, ATYP_DOMAIN, nume.len() as u8];
        v.extend_from_slice(nume.as_bytes());
        v.extend_from_slice(&port.to_be_bytes());
        v
    }

    #[tokio::test]
    async fn cerere_cu_nume_de_domeniu() {
        let (r, out, stats) = negociaza(&cerere_domeniu("example.com", 443)).await;
        let r = r.unwrap();
        assert_eq!(r.address, "example.com");
        assert_eq!(r.port, 443);
        assert!(!r.was_ip_literal);
        assert_eq!(&out[..2], &[VER, NO_AUTH], "metoda aleasa");
        assert_eq!(stats.ip_literals(), 0);
    }

    #[tokio::test]
    async fn cerere_cu_ip_e_marcata() {
        // Un IP inseamna ca aplicatia a rezolvat deja numele in clar.
        let mut v = vec![VER, 1, NO_AUTH, VER, CMD_CONNECT, 0, ATYP_IPV4, 93, 184, 216, 34];
        v.extend_from_slice(&443u16.to_be_bytes());
        let (r, _out, stats) = negociaza(&v).await;
        let r = r.unwrap();
        assert_eq!(r.address, "93.184.216.34");
        assert!(r.was_ip_literal);
        assert_eq!(
            stats.ip_literals(),
            1,
            "scurgerea de DNS trebuie sa fie vizibila in contoare"
        );
    }

    #[tokio::test]
    async fn ipv6_e_acceptat_dar_marcat() {
        let mut v = vec![VER, 1, NO_AUTH, VER, CMD_CONNECT, 0, ATYP_IPV6];
        v.extend_from_slice(&[0u8; 15]);
        v.push(1);
        v.extend_from_slice(&80u16.to_be_bytes());
        let (r, _o, stats) = negociaza(&v).await;
        assert!(r.unwrap().was_ip_literal);
        assert_eq!(stats.ip_literals(), 1);
    }

    #[tokio::test]
    async fn versiune_gresita_e_respinsa() {
        let (r, _o, _s) = negociaza(&[4, 1, NO_AUTH]).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn fara_metoda_acceptabila() {
        // Clientul cere doar autentificare cu parola.
        let (r, out, _s) = negociaza(&[VER, 1, 2]).await;
        assert!(r.is_err());
        assert_eq!(&out[..2], &[VER, NO_METHOD]);
    }

    #[tokio::test]
    async fn bind_si_udp_sunt_refuzate() {
        for cmd in [2u8, 3u8] {
            let mut v = vec![VER, 1, NO_AUTH, VER, cmd, 0, ATYP_IPV4, 1, 2, 3, 4];
            v.extend_from_slice(&80u16.to_be_bytes());
            let (r, out, _s) = negociaza(&v).await;
            assert!(r.is_err(), "comanda {cmd} ar fi trebuit refuzata");
            // Raspunsul contine intai selectia metodei (2 octeti), apoi raspunsul
            // la CONNECT: codul e al doilea octet al celui de-al doilea mesaj.
            assert_eq!(out[3], reply::CMD_NOT_SUPPORTED, "cod de eroare gresit");
        }
    }

    #[tokio::test]
    async fn tip_de_adresa_necunoscut() {
        let v = vec![VER, 1, NO_AUTH, VER, CMD_CONNECT, 0, 9];
        let (r, out, _s) = negociaza(&v).await;
        assert!(r.is_err());
        assert_eq!(out[3], reply::ATYP_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn nume_invalid_e_respins() {
        for rau in ["a b.com", "a\nb.com", "a\0b.com"] {
            let (r, _o, _s) = negociaza(&cerere_domeniu(rau, 80)).await;
            assert!(r.is_err(), "acceptat: {rau:?}");
        }
        // Nume gol.
        let v = vec![VER, 1, NO_AUTH, VER, CMD_CONNECT, 0, ATYP_DOMAIN, 0];
        let (r, _o, _s) = negociaza(&v).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn portul_zero_e_respins() {
        let (r, _o, _s) = negociaza(&cerere_domeniu("a.com", 0)).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn cerere_trunchiata_nu_produce_panica() {
        let plina = cerere_domeniu("example.com", 443);
        for n in 0..plina.len() {
            let (mut client, mut server) = duplex(4096);
            let stats = Arc::new(SocksStats::default());
            let h = tokio::spawn(async move { handshake(&mut server, &stats).await });
            client.write_all(&plina[..n]).await.unwrap();
            drop(client);
            assert!(h.await.unwrap().is_err(), "prefix de {n} octeti acceptat");
        }
    }

    #[tokio::test]
    async fn raspunsul_nu_dezvaluie_adresa_exitului() {
        let (mut a, mut b) = duplex(64);
        send_reply(&mut a, reply::SUCCESS).await.unwrap();
        let mut out = [0u8; 10];
        b.read_exact(&mut out).await.unwrap();
        assert_eq!(out, [VER, 0, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]);
    }
}
