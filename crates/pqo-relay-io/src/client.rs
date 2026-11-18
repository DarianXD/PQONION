//! Client minimal: construieste un circuit peste un transport real.
//!
//! Nu e `pqo-client` complet — lipsesc selectia de cale, guard-urile persistente
//! si frontend-ul SOCKS5. E exact cat trebuie ca sa demonstram ca stiva
//! functioneaza cap-coada peste socket-uri, si ca sa avem cu ce testa releele.

use std::io;
use std::sync::Arc;

use pqo_crypto::cgo::ClientCircuit;
use pqo_crypto::kem::Kem;
use pqo_crypto::sig::Sig;
use pqo_crypto::{client_finish, client_init, RelayPublic, Variant};
use pqo_relay::link::{AuthMode, Role};
use pqo_relay::service::RENDEZVOUS_STREAM;
use pqo_wire::stream::{Begin, End, EndReason, FlowWindow, Sendme};
use pqo_wire::{
    Cell, ChanCmd, CircId, Create2, Created2, Extend2, Extended2, HandshakeType, LinkSpec,
    Reassembler, RelayCmd, RelayMessage, StreamId,
};
use rand_core::OsRng;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::codec::CellStream;

/// Un circuit in constructie sau deschis, din perspectiva clientului.
pub struct Circuit<T> {
    stream: CellStream<T>,
    circ: CircId,
    crypto: ClientCircuit,
    reasm: Reassembler,
    /// Fereastra de circuit pentru ce primim. Emitem SENDME cand se umple.
    circ_recv: FlowWindow,
    /// Ferestrele per stream, pentru ce primim.
    stream_recv: Vec<(StreamId, FlowWindow)>,
    next_stream: u16,
}

impl<T> core::fmt::Debug for Circuit<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Circuit({} hop-uri)", self.crypto.len())
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Circuit<T> {
    /// Cate hop-uri are circuitul.
    pub fn hops(&self) -> usize {
        self.crypto.len()
    }

    /// Deschide primul hop pe un transport deja stabilit si autentificat.
    pub async fn create<K: Kem>(
        mut stream: CellStream<T>,
        guard: &RelayPublic,
        variant: Variant,
    ) -> io::Result<Self> {
        let mut rng = OsRng;
        // Bitul cel mai semnificativ marcheaza cine a initiat circuitul, ca sa
        // nu existe coliziuni de numere pe acelasi canal.
        let circ = CircId(0x8000_0001);

        let (state, hs) = client_init::<K>(guard, variant, &mut rng).map_err(bad)?;
        let cell = Cell::var(
            circ,
            ChanCmd::Create2,
            Create2 {
                htype: htype(variant),
                data: hs,
            }
            .encode(),
        )
        .map_err(bad)?;
        stream.write_cell(&cell).await?;

        let raspuns = stream
            .read_cell()
            .await?
            .ok_or_else(|| eof("canalul s-a inchis inainte de CREATED2"))?;
        if raspuns.cmd() != ChanCmd::Created2 || raspuns.circ() != circ {
            return Err(bad("raspuns neasteptat la CREATE2"));
        }
        let created = Created2::parse(raspuns.payload()).map_err(bad)?;
        let res = client_finish::<K>(state, &created.data).map_err(bad)?;

        let mut crypto = ClientCircuit::new();
        crypto.add_hop(&res.key_seed);
        Ok(Circuit {
            stream,
            circ,
            crypto,
            reasm: Reassembler::new(),
            circ_recv: FlowWindow::circuit(),
            stream_recv: Vec::new(),
            next_stream: 1,
        })
    }

    /// Extinde circuitul cu un hop.
    pub async fn extend<K: Kem>(
        &mut self,
        tinta: &RelayPublic,
        address: [u8; 4],
        port: u16,
        variant: Variant,
    ) -> io::Result<()> {
        let mut rng = OsRng;
        let d = self.crypto.len();

        let (state, hs) = client_init::<K>(tinta, variant, &mut rng).map_err(bad)?;
        let msg = RelayMessage::new(
            RelayCmd::Extend2,
            StreamId::CONTROL,
            Extend2 {
                specs: vec![
                    LinkSpec::Ipv4 {
                        addr: address,
                        port,
                    },
                    LinkSpec::RelayId(tinta.id),
                ],
                htype: htype(variant),
                data: hs,
            }
            .encode(),
        )
        .map_err(bad)?;

        // EXTEND2 circula obligatoriu in RELAY_EARLY: altfel releul il refuza,
        // pentru ca altfel plafonul de lungime de circuit n-ar avea efect.
        self.send(d, &msg, ChanCmd::RelayEarly).await?;

        let raspuns = self.recv().await?;
        if raspuns.cmd != RelayCmd::Extended2 {
            return Err(bad("asteptam EXTENDED2"));
        }
        let e = Extended2::parse(&raspuns.body).map_err(bad)?;
        let res = client_finish::<K>(state, &e.data).map_err(bad)?;
        self.crypto.add_hop(&res.key_seed);
        Ok(())
    }

    /// Trimite un mesaj relay catre hop-ul `d` (1-indexat).
    pub async fn send(
        &mut self,
        d: usize,
        msg: &RelayMessage,
        cmd: ChanCmd,
    ) -> io::Result<()> {
        let mut rng = OsRng;
        let mut cells = Vec::new();
        for corp in msg.fragment(&mut rng) {
            let c = self
                .crypto
                .encrypt_outbound(d, cmd as u8, &corp)
                .map_err(bad)?;
            cells.push(Cell::fixed(self.circ, cmd, c.as_slice()).map_err(bad)?);
        }
        self.stream.write_cells(&cells).await
    }

    /// Deschide un stream catre `address:port` prin ultimul hop.
    ///
    /// Adresa se trimite ca **text** si se rezolva la exit. Daca am rezolva-o
    /// aici, cererea DNS ar pleca prin reteaua locala si ar dezvalui ce site
    /// vizitam — exact scurgerea pe care circuitul trebuie sa o inchida.
    pub async fn begin(&mut self, address: &str, port: u16) -> io::Result<StreamId> {
        let id = StreamId(self.next_stream);
        self.next_stream = self.next_stream.wrapping_add(1).max(1);
        self.stream_recv.push((id, FlowWindow::stream()));

        let body = Begin {
            address: address.to_string(),
            port,
        }
        .encode()
        .map_err(bad)?;
        let d = self.crypto.len();
        self.send(d, &RelayMessage::new(RelayCmd::Begin, id, body).map_err(bad)?, ChanCmd::Relay)
            .await?;

        loop {
            let m = self.recv().await?;
            if m.stream != id {
                continue;
            }
            match m.cmd {
                RelayCmd::Connected => return Ok(id),
                RelayCmd::End => {
                    let e = End::parse(&m.body).map_err(bad)?;
                    return Err(io::Error::new(
                        match e.reason {
                            EndReason::ConnectRefused => io::ErrorKind::ConnectionRefused,
                            EndReason::Timeout => io::ErrorKind::TimedOut,
                            _ => io::ErrorKind::Other,
                        },
                        format!("exit a refuzat: {:?}", e.reason),
                    ))
                }
                _ => continue,
            }
        }
    }

    /// Deschide un stream catre serviciul de director al ultimului hop.
    ///
    /// Spre deosebire de [`Self::begin`], nu se deschide nicio conexiune in
    /// exterior: releul raspunde din propriile documente. De aceea merge si
    /// catre relee care nu sunt exit.
    pub async fn begin_dir(&mut self) -> io::Result<StreamId> {
        let id = StreamId(self.next_stream);
        self.next_stream = self.next_stream.wrapping_add(1).max(1);
        self.stream_recv.push((id, FlowWindow::stream()));

        let d = self.crypto.len();
        self.send(
            d,
            &RelayMessage::new(RelayCmd::BeginDir, id, Vec::new()).map_err(bad)?,
            ChanCmd::Relay,
        )
        .await?;

        loop {
            let m = self.recv().await?;
            if m.stream != id {
                continue;
            }
            match m.cmd {
                RelayCmd::Connected => return Ok(id),
                RelayCmd::End => {
                    return Err(bad("releul nu serveste director"));
                }
                _ => continue,
            }
        }
    }

    /// Cere un document de director si asteapta raspunsul complet.
    ///
    /// Lungimea vine din antetul raspunsului, nu din inchiderea stream-ului:
    /// altfel un releu ostil ar putea tine conexiunea deschisa la nesfarsit si
    /// clientul ar astepta degeaba.
    pub async fn dir_request(
        &mut self,
        req: pqo_dirproto::dirreq::DirRequest,
    ) -> io::Result<pqo_dirproto::dirreq::DirResponse> {
        use pqo_dirproto::dirreq::DirResponse;

        let id = self.begin_dir().await?;
        self.write_stream(id, &req.encode_framed()).await?;

        let mut buf: Vec<u8> = Vec::new();
        let mut asteptat: Option<usize> = None;
        loop {
            match self.read_stream(id).await? {
                Some(b) => buf.extend_from_slice(&b),
                None => break,
            }
            if asteptat.is_none() {
                match DirResponse::expected_len(&buf) {
                    Some(Ok(n)) => asteptat = Some(n),
                    Some(Err(_)) => return Err(bad("raspuns de director absurd de mare")),
                    None => continue,
                }
            }
            if let Some(n) = asteptat {
                if buf.len() >= n {
                    buf.truncate(n);
                    break;
                }
            }
        }
        let _ = self.close_stream(id).await;
        DirResponse::parse(&buf).map_err(bad)
    }

    /// Asteapta un mesaj relay de o anumita comanda, ignorandu-le pe celelalte.
    ///
    /// Mesajele care nu sunt asteptate se **arunca**, nu se pun la coada. E
    /// suficient pentru fluxurile de rendezvous, unde ordinea e determinata de
    /// protocol; un client complet ar avea o coada per stream.
    async fn asteapta(&mut self, cmd: RelayCmd) -> io::Result<RelayMessage> {
        for _ in 0..64 {
            let m = self.recv().await?;
            if m.cmd == cmd {
                return Ok(m);
            }
        }
        Err(bad("prea multe mesaje neasteptate"))
    }

    // -----------------------------------------------------------------------
    // Rendezvous, partea de client
    // -----------------------------------------------------------------------

    /// Lasa un cookie la ultimul hop, care devine punct de rendezvous.
    pub async fn establish_rendezvous(&mut self, cookie: &[u8; 20]) -> io::Result<()> {
        let d = self.crypto.len();
        let m = RelayMessage::new(
            RelayCmd::EstablishRendezvous,
            StreamId::CONTROL,
            cookie.to_vec(),
        )
        .map_err(bad)?;
        self.send(d, &m, ChanCmd::Relay).await?;
        self.asteapta(RelayCmd::RendezvousEstablished).await?;
        Ok(())
    }

    /// Trimite o cerere de introducere prin ultimul hop, care e punct de
    /// introducere.
    ///
    /// `body` incepe cu identificatorul cheii de autentificare, ca releul sa
    /// stie catre ce circuit sa retransmita; restul e criptat catre serviciu.
    pub async fn send_introduce(&mut self, body: Vec<u8>) -> io::Result<()> {
        let d = self.crypto.len();
        let m = RelayMessage::new(RelayCmd::Introduce1, StreamId::CONTROL, body).map_err(bad)?;
        self.send(d, &m, ChanCmd::Relay).await?;

        let ack = self.asteapta(RelayCmd::IntroduceAck).await?;
        match ack.body.first() {
            Some(0) => Ok(()),
            // Punctul de introducere nu spune de ce a refuzat, ca sa nu poata fi
            // folosit ca sa enumeri serviciile gazduite.
            _ => Err(bad("punctul de introducere a refuzat cererea")),
        }
    }

    /// Asteapta partea de server a handshake-ului, prin punctul de rendezvous.
    pub async fn wait_rendezvous2(&mut self) -> io::Result<Vec<u8>> {
        Ok(self.asteapta(RelayCmd::Rendezvous2).await?.body)
    }

    // -----------------------------------------------------------------------
    // Rendezvous, partea de serviciu
    // -----------------------------------------------------------------------

    /// Anunta o cheie de autentificare la ultimul hop, care devine punct de
    /// introducere.
    ///
    /// Semnatura dovedeste posesia cheii private. E obligatorie: cheia publica
    /// apare in descriptorul serviciului, deci oricine il citeste ar putea
    /// altfel ocupa slotul si face serviciul inaccesibil.
    ///
    /// LIMITARE: semnatura nu e legata de circuit, pentru ca serviciul si releul
    /// nu au un identificator comun pentru el. Un atacator care observa mesajul
    /// il poate relua pe circuitul lui — dar doar dupa ce circuitul serviciului
    /// cade, pentru ca o cheie deja inregistrata nu se muta.
    pub async fn establish_intro<S: pqo_crypto::sig::Sig>(
        &mut self,
        sk: &S::SecretKey,
        auth_key: &[u8],
    ) -> io::Result<()> {
        let corp = pqo_crypto::kdf::hash(b"pqonion-hs-establish-intro-v2", &[auth_key]);
        let sig = S::sign(sk, &corp);

        let mut body = Vec::with_capacity(4 + auth_key.len() + sig.len());
        body.extend_from_slice(&(auth_key.len() as u16).to_be_bytes());
        body.extend_from_slice(auth_key);
        body.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        body.extend_from_slice(&sig);

        let d = self.crypto.len();
        let m = RelayMessage::new(RelayCmd::EstablishIntro, StreamId::CONTROL, body).map_err(bad)?;
        self.send(d, &m, ChanCmd::Relay).await?;
        self.asteapta(RelayCmd::IntroEstablished).await?;
        Ok(())
    }

    /// Asteapta o cerere de introducere retransmisa de punctul de introducere.
    pub async fn wait_introduce2(&mut self) -> io::Result<Vec<u8>> {
        Ok(self.asteapta(RelayCmd::Introduce2).await?.body)
    }

    /// Trimite partea de server a handshake-ului la punctul de rendezvous.
    pub async fn send_rendezvous1(
        &mut self,
        cookie: &[u8; 20],
        handshake: &[u8],
    ) -> io::Result<()> {
        let d = self.crypto.len();
        let mut body = Vec::with_capacity(20 + handshake.len());
        body.extend_from_slice(cookie);
        body.extend_from_slice(handshake);
        let m = RelayMessage::new(RelayCmd::Rendezvous1, StreamId::CONTROL, body).map_err(bad)?;
        self.send(d, &m, ChanCmd::Relay).await
    }

    // -----------------------------------------------------------------------
    // Tunelul hop-ului virtual
    // -----------------------------------------------------------------------

    /// Trimite o celula a hop-ului virtual prin circuit.
    ///
    /// Celula are 509 octeti si corpul util al unui mesaj relay e 487, deci
    /// fiecare celula virtuala consuma **doua** celule relay. Vezi nota din
    /// `pqo_relay::service`.
    pub async fn send_tunnel(&mut self, cell: &[u8]) -> io::Result<()> {
        let d = self.crypto.len();
        let m = RelayMessage::new(RelayCmd::Data, RENDEZVOUS_STREAM, cell.to_vec())
            .map_err(bad)?;
        self.send(d, &m, ChanCmd::Relay).await
    }

    /// Asteapta o celula a hop-ului virtual.
    pub async fn recv_tunnel(&mut self) -> io::Result<Vec<u8>> {
        loop {
            let m = self.recv().await?;
            if m.cmd == RelayCmd::Data && m.stream == RENDEZVOUS_STREAM {
                return Ok(m.body);
            }
        }
    }

    /// Publica un document prin circuit si asteapta confirmarea.
    ///
    /// Folosit de relee ca sa isi publice descriptorii si de serviciile ascunse
    /// ca sa isi incarce descriptorii la HSDir. In ambele cazuri, documentul e
    /// autosemnat si destinatarul il verifica: nimeni nu se autentifica.
    pub async fn dir_publish(
        &mut self,
        req: pqo_dirproto::dirreq::DirRequest,
    ) -> io::Result<pqo_dirproto::dirreq::DirStatus> {
        Ok(self.dir_request(req).await?.status)
    }

    /// Scrie date pe un stream deschis.
    pub async fn write_stream(&mut self, id: StreamId, data: &[u8]) -> io::Result<()> {
        let d = self.crypto.len();
        for bucata in data.chunks(pqo_wire::RELAY_DATA_LEN) {
            let m = RelayMessage::new(RelayCmd::Data, id, bucata.to_vec()).map_err(bad)?;
            self.send(d, &m, ChanCmd::Relay).await?;
        }
        Ok(())
    }

    /// Inchide un stream.
    pub async fn close_stream(&mut self, id: StreamId) -> io::Result<()> {
        let d = self.crypto.len();
        let m = RelayMessage::new(
            RelayCmd::End,
            id,
            End {
                reason: EndReason::Done,
            }
            .encode(),
        )
        .map_err(bad)?;
        self.stream_recv.retain(|(s, _)| *s != id);
        self.send(d, &m, ChanCmd::Relay).await
    }

    /// Asteapta date pe un stream. Intoarce `None` cand stream-ul s-a inchis.
    ///
    /// Emite automat SENDME-urile de control de flux: fara ele, exit-ul se
    /// blocheaza dupa 500 de celule si transferul se opreste.
    pub async fn read_stream(&mut self, id: StreamId) -> io::Result<Option<Vec<u8>>> {
        loop {
            let m = self.recv().await?;
            if m.stream != id && !m.stream.is_control() {
                continue;
            }
            match m.cmd {
                RelayCmd::Data => {
                    let d = self.crypto.len();
                    // Confirmam la nivel de circuit si de stream.
                    if self.circ_recv.on_recv() {
                        let s = RelayMessage::new(
                            RelayCmd::Sendme,
                            StreamId::CONTROL,
                            Sendme::V1.encode(),
                        )
                        .map_err(bad)?;
                        self.send(d, &s, ChanCmd::Relay).await?;
                    }
                    if let Some((_, w)) = self.stream_recv.iter_mut().find(|(s, _)| *s == id) {
                        if w.on_recv() {
                            let s =
                                RelayMessage::new(RelayCmd::Sendme, id, Sendme::V1.encode())
                                    .map_err(bad)?;
                            self.send(d, &s, ChanCmd::Relay).await?;
                        }
                    }
                    return Ok(Some(m.body));
                }
                RelayCmd::End => {
                    self.stream_recv.retain(|(s, _)| *s != id);
                    return Ok(None);
                }
                _ => continue,
            }
        }
    }

    /// Asteapta un mesaj relay complet.
    pub async fn recv(&mut self) -> io::Result<RelayMessage> {
        loop {
            let cell = self
                .stream
                .read_cell()
                .await?
                .ok_or_else(|| eof("canalul s-a inchis"))?;
            match cell.cmd() {
                ChanCmd::Relay => {}
                ChanCmd::Destroy => return Err(bad("circuitul a fost distrus")),
                _ => continue,
            }
            if cell.circ() != self.circ {
                continue;
            }
            let payload: &[u8; pqo_crypto::cgo::MSG_LEN] =
                cell.payload().try_into().map_err(|_| bad("dimensiune"))?;
            let (_hop, corp) = self
                .crypto
                .decrypt_inbound(ChanCmd::Relay as u8, payload)
                .map_err(bad)?;
            if let Some(m) = self.reasm.push(corp.as_slice()).map_err(bad)? {
                return Ok(m);
            }
        }
    }
}

/// Un flux pe care poate circula un circuit, indiferent de transport.
///
/// Exista pentru binare: ele aleg transportul dintr-un flag, deci nu pot fixa
/// tipul la compilare. Un `Box<dyn Flux>` costa o indirectare pe operatie de
/// I/O, ceea ce e neglijabil fata de criptografia de pe fiecare celula.
pub trait Flux: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Flux for T {}

/// Ce transport foloseste un client.
pub enum TransportClient<'a> {
    /// TCP simplu. **Fara confidentialitate pe fir.**
    Plaintext,
    #[cfg(feature = "tls")]
    Tls(&'a tokio_rustls::TlsConnector),
    /// Varianta fantoma, ca tipul sa aiba mereu parametrul de viata.
    #[doc(hidden)]
    _Neatins(core::marker::PhantomData<&'a ()>),
}

impl core::fmt::Debug for TransportClient<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransportClient::Plaintext | TransportClient::_Neatins(_) => {
                f.write_str("TransportClient::Plaintext")
            }
            #[cfg(feature = "tls")]
            // Fara continut: configuratia TLS include material de cheie.
            TransportClient::Tls(_) => f.write_str("TransportClient::Tls"),
        }
    }
}

impl Circuit<Box<dyn Flux>> {
    /// Se conecteaza la un guard, alegand transportul la rulare.
    pub async fn connect_dyn<K: Kem, S: Sig>(
        addr: std::net::SocketAddr,
        guard: &RelayPublic,
        variant: Variant,
        id_sk: Arc<S::SecretKey>,
        id_pk: &[u8],
        transport: TransportClient<'_>,
    ) -> io::Result<Self> {
        let sock = TcpStream::connect(addr).await?;
        let _ = sock.set_nodelay(true);
        let (flux, binding): (Box<dyn Flux>, crate::ChannelBinding) = match transport {
            TransportClient::Plaintext | TransportClient::_Neatins(_) => (
                Box::new(sock),
                crate::ChannelBinding::insecure_plaintext_tcp(),
            ),
            #[cfg(feature = "tls")]
            TransportClient::Tls(c) => {
                let t = crate::tls::connect(c, sock).await?;
                (Box::new(t.stream), t.binding)
            }
        };

        let mut stream = CellStream::new(flux);
        // `ResponderOnly`: clientul nu se autentifica. Asta e tot rostul.
        crate::node::link_handshake_cu_legare::<S, _>(
            &mut stream,
            Role::Initiator,
            AuthMode::ResponderOnly,
            id_sk,
            id_pk,
            binding,
        )
        .await?;
        Self::create::<K>(stream, guard, variant).await
    }
}

impl Circuit<TcpStream> {
    /// Se conecteaza la un guard peste TCP simplu.
    ///
    /// **Fara confidentialitate pe fir.** Vezi [`Self::connect_tls`].
    pub async fn connect<K: Kem, S: Sig>(
        addr: std::net::SocketAddr,
        guard: &RelayPublic,
        variant: Variant,
        id_sk: Arc<S::SecretKey>,
        id_pk: &[u8],
    ) -> io::Result<Self> {
        let sock = TcpStream::connect(addr).await?;
        let _ = sock.set_nodelay(true);
        let mut stream = CellStream::new(sock);
        // `ResponderOnly`: clientul nu se autentifica. Asta e tot rostul.
        crate::node::link_handshake_cu_legare::<S, _>(
            &mut stream,
            Role::Initiator,
            AuthMode::ResponderOnly,
            id_sk,
            id_pk,
            crate::ChannelBinding::insecure_plaintext_tcp(),
        )
        .await?;
        Self::create::<K>(stream, guard, variant).await
    }
}

#[cfg(feature = "tls")]
impl Circuit<tokio_rustls::client::TlsStream<TcpStream>> {
    /// Se conecteaza la un guard peste TLS.
    ///
    /// Legarea de canal vine din exportul TLS, deci handshake-ul nu poate fi
    /// mutat pe alta conexiune.
    pub async fn connect_tls<K: Kem, S: Sig>(
        addr: std::net::SocketAddr,
        guard: &RelayPublic,
        variant: Variant,
        id_sk: Arc<S::SecretKey>,
        id_pk: &[u8],
        connector: &tokio_rustls::TlsConnector,
    ) -> io::Result<Self> {
        let sock = TcpStream::connect(addr).await?;
        let _ = sock.set_nodelay(true);
        let c = crate::tls::connect(connector, sock).await?;
        let mut stream = CellStream::new(c.stream);
        crate::node::link_handshake_cu_legare::<S, _>(
            &mut stream,
            Role::Initiator,
            AuthMode::ResponderOnly,
            id_sk,
            id_pk,
            c.binding,
        )
        .await?;
        Self::create::<K>(stream, guard, variant).await
    }
}

fn htype(v: Variant) -> HandshakeType {
    match v {
        Variant::Transitional => HandshakeType::PqNtorTransitional,
        Variant::FullPq => HandshakeType::PqNtorFullPq,
    }
}

fn bad<E: core::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

fn eof(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, m)
}
