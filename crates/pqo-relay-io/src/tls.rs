//! Transport TLS pentru legaturile dintre noduri.
//!
//! # Ce aduce si ce nu aduce
//!
//! TLS **nu** autentifica nodurile aici. Autentificarea o face handshake-ul de
//! legatura din [`pqo_relay::link`], care demonstreaza posesia cheii de
//! identitate publicate in consens. TLS aduce doua lucruri:
//!
//! 1. **Confidentialitate si integritate pe fir.** Fara el, oricine vede reteaua
//!    citeste antetele de celula, numarul de circuite si tiparele de lungime —
//!    chiar daca payload-ul e criptat cu CGO.
//! 2. **Legarea de canal.** Exportul TLS (RFC 8446 §7.5) da ambelor capete o
//!    valoare pe care un tert nu o poate calcula. Handshake-ul de legatura o
//!    semneaza, deci un handshake valid observat pe o conexiune nu poate fi mutat
//!    pe alta — atacul de tip unknown key share.
//!
//! # De ce certificate auto-semnate
//!
//! Un releu nu are nume de domeniu si nu are de ce sa ceara un certificat de la
//! o autoritate de certificare. Increderea vine din consens, nu din PKI-ul web.
//! Certificatul e doar plicul in care circula cheia efemera de TLS; il generam la
//! pornire si nu il verificam la celalalt capat.
//!
//! **Consecinta pe care trebuie sa o intelegi:** un atacator care sta la mijloc
//! poate incheia TLS-ul cu ambele parti. Nu castiga nimic — nu poate produce
//! semnatura de legatura, pentru ca nu are cheia de identitate, iar legarea de
//! canal face ca semnatura sa nu poata fi copiata dintr-o conexiune in alta. Dar
//! inseamna ca TLS-ul singur nu ofera nicio garantie aici.
//!
//! # Versiuni
//!
//! Codul e scris pentru `rustls 0.21`, singura serie care compileaza pe
//! toolchain-ul in care a fost dezvoltat. Pe `rustls 0.23` interfata difera:
//! `ServerConfig::builder()` nu mai cere `with_safe_defaults()`, iar grupul
//! hibrid `X25519MLKEM768` se activeaza cu feature-ul `prefer-post-quantum`.
//! **Migrarea la 0.23 e recomandata**, tocmai pentru grupul post-cuantic —
//! altfel cheia de sesiune TLS ramane clasica, chiar daca circuitele nu sunt.

use std::io;
use std::sync::Arc;

use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ClientConfig, PrivateKey, ServerConfig, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::ChannelBinding;

/// Eticheta de export, ca legarea sa nu poata fi confundata cu alt scop.
const EXPORTER_LABEL: &[u8] = b"pqonion-link-binding-v1";
/// Cati octeti extragem din exportul TLS.
const EXPORTER_LEN: usize = 32;

/// Nume folosit in certificat si la conectare.
///
/// Nu are nicio semnificatie: nu verificam certificatul. Exista pentru ca TLS
/// cere un nume de server la handshake.
const NUME: &str = "pqonion.invalid";

/// Verificator care accepta orice certificat.
///
/// Nu e o scurtatura de comoditate. Increderea in acest sistem vine din consens
/// si din handshake-ul de legatura, nu din PKI. Un verificator care ar cere
/// certificate valide ar face reteaua imposibil de rulat fara nume de domeniu
/// pentru fiecare releu, si n-ar adauga nicio garantie.
struct AcceptaOrice;

impl ServerCertVerifier for AcceptaOrice {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

/// Un certificat efemer, generat la pornire.
///
/// Nu se salveaza pe disc: identitatea de lunga durata a nodului e cheia din
/// consens, nu certificatul TLS. Regenerarea la fiecare pornire e chiar de
/// dorit — cu cat traieste mai putin o cheie, cu atat mai putin conteaza daca
/// se scurge.
pub struct TlsKeys {
    cert: Vec<Certificate>,
    key: PrivateKey,
}

impl core::fmt::Debug for TlsKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TlsKeys(redacted)")
    }
}

impl TlsKeys {
    pub fn generate() -> io::Result<Self> {
        let c = rcgen::generate_simple_self_signed(vec![NUME.to_string()])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let cert = vec![Certificate(
            c.serialize_der()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?,
        )];
        let key = PrivateKey(c.serialize_private_key_der());
        Ok(TlsKeys { cert, key })
    }
}

/// Configuratia de server, pentru nodul care asculta.
pub fn acceptor(keys: &TlsKeys) -> io::Result<TlsAcceptor> {
    let cfg = ServerConfig::builder()
        .with_safe_defaults()
        // Nu cerem certificate de la client: clientii trebuie sa ramana anonimi,
        // iar releele se autentifica prin handshake-ul de legatura.
        .with_no_client_auth()
        .with_single_cert(keys.cert.clone(), keys.key.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Tipul conectorului, reexportat ca binarele sa nu depinda direct de
/// `tokio-rustls`.
pub type Conector = TlsConnector;

/// Configuratia de client, pentru nodul care initiaza.
pub fn connector() -> TlsConnector {
    let cfg = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(AcceptaOrice))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(cfg))
}

/// Acceptorul si conectorul intorc fluxul plus legarea de canal.
pub struct TlsConexiune<T> {
    pub stream: T,
    pub binding: ChannelBinding,
}

impl<T> core::fmt::Debug for TlsConexiune<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TlsConexiune")
    }
}

/// Accepta o conexiune TLS de la un peer.
pub async fn accept(
    acceptor: &TlsAcceptor,
    sock: TcpStream,
) -> io::Result<TlsConexiune<tokio_rustls::server::TlsStream<TcpStream>>> {
    let stream = acceptor.accept(sock).await?;
    let b = exporter_server(stream.get_ref().1)?;
    Ok(TlsConexiune {
        stream,
        binding: b,
    })
}

/// Deschide o conexiune TLS catre un peer.
pub async fn connect(
    connector: &TlsConnector,
    sock: TcpStream,
) -> io::Result<TlsConexiune<tokio_rustls::client::TlsStream<TcpStream>>> {
    let nume = ServerName::try_from(NUME)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let stream = connector.connect(nume, sock).await?;
    let b = exporter_client(stream.get_ref().1)?;
    Ok(TlsConexiune {
        stream,
        binding: b,
    })
}

/// Citeste exportul dintr-o conexiune de server.
fn exporter_server(conn: &rustls::ServerConnection) -> io::Result<ChannelBinding> {
    let mut out = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, None)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(ChannelBinding::from_tls_exporter(out.to_vec()))
}

/// Citeste exportul dintr-o conexiune de client.
fn exporter_client(conn: &rustls::ClientConnection) -> io::Result<ChannelBinding> {
    let mut out = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, None)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(ChannelBinding::from_tls_exporter(out.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn legarea_de_canal_coincide_la_cele_doua_capete() {
        // Proprietatea centrala: ambele parti deriva aceeasi valoare, si un tert
        // nu o poate calcula.
        let keys = TlsKeys::generate().unwrap();
        let acc = acceptor(&keys).unwrap();
        let con = connector();

        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = l.accept().await.unwrap();
            let c = accept(&acc, sock).await.unwrap();
            c.binding
        });

        let sock = TcpStream::connect(addr).await.unwrap();
        let client = connect(&con, sock).await.unwrap();
        let b_server = server.await.unwrap();

        assert_eq!(
            client.binding, b_server,
            "cele doua capete trebuie sa derive aceeasi legare"
        );
        assert!(
            !client.binding.is_insecure(),
            "legarea din TLS nu are voie sa fie cea nesigura"
        );
    }

    #[tokio::test]
    async fn doua_conexiuni_dau_legari_diferite() {
        // Daca legarea ar fi aceeasi, un handshake observat pe o conexiune ar
        // putea fi mutat pe alta. Asta e exact ce trebuie sa impiedice.
        let keys = TlsKeys::generate().unwrap();
        let acc = acceptor(&keys).unwrap();
        let con = connector();

        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let acc2 = acc.clone();
        let server = tokio::spawn(async move {
            let mut b = Vec::new();
            for _ in 0..2 {
                let (sock, _) = l.accept().await.unwrap();
                b.push(accept(&acc2, sock).await.unwrap().binding);
            }
            b
        });

        let mut legari = Vec::new();
        for _ in 0..2 {
            let sock = TcpStream::connect(addr).await.unwrap();
            legari.push(connect(&con, sock).await.unwrap().binding);
        }
        let ale_serverului = server.await.unwrap();

        assert_ne!(legari[0], legari[1], "doua conexiuni, doua legari");
        assert_eq!(legari[0], ale_serverului[0]);
        assert_eq!(legari[1], ale_serverului[1]);
    }

    #[tokio::test]
    async fn datele_trec_criptat() {
        let keys = TlsKeys::generate().unwrap();
        let acc = acceptor(&keys).unwrap();
        let con = connector();

        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = l.accept().await.unwrap();
            let mut c = accept(&acc, sock).await.unwrap();
            let mut buf = [0u8; 16];
            c.stream.read_exact(&mut buf).await.unwrap();
            c.stream.write_all(&buf).await.unwrap();
            c.stream.flush().await.unwrap();
        });

        let sock = TcpStream::connect(addr).await.unwrap();
        let mut c = connect(&con, sock).await.unwrap();
        c.stream.write_all(b"salut prin TLS!!").await.unwrap();
        c.stream.flush().await.unwrap();
        let mut buf = [0u8; 16];
        c.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"salut prin TLS!!");
        server.await.unwrap();
    }

    #[test]
    fn cheile_nu_apar_in_debug() {
        let k = TlsKeys::generate().unwrap();
        assert!(format!("{k:?}").contains("redacted"));
    }
}
