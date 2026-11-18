//! Nodul releu care ruleaza efectiv pe socket-uri.
//!
//! # Structura
//!
//! Un task **nucleu** detine [`pqo_relay::RelayNode`] si registrul de canale.
//! Cate un task per canal citeste din socket si trimite celulele nucleului
//! printr-un canal `mpsc`; acelasi task scrie inapoi ce ii trimite nucleul.
//!
//! ```text
//!    socket <──> [task canal] ──mpsc──> [NUCLEU] ──mpsc──> [task canal] <──> socket
//!                                          │
//!                                      RelayNode
//!                                 (stare CGO, circuite)
//! ```
//!
//! Nucleul e **singurul** care atinge starea criptografica, si o atinge dintr-un
//! singur task. Nu exista `Mutex` pe starea de circuit, deci nici posibilitatea
//! ca doua fire sa ajunga simultan la `update_uiv` — cazul care ar duce la
//! refolosirea aceluiasi flux de chei.
//!
//! # Ce nu face inca
//!
//! Fara TLS (vezi [`crate::ChannelBinding`]), fara timeout-uri pe handshake,
//! fara limite de rata, si fara tratarea mesajelor livrate la exit. Toate patru
//! sunt necesare inainte de orice deployment.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use pqo_crypto::kem::Kem;
use pqo_crypto::sig::Sig;
use pqo_crypto::RelayKeys;
use pqo_relay::circuit::{Action, ChannelId, Endpoint, RelayNode};
use pqo_relay::link::{AuthMode, LinkHandshake, Role};
use pqo_dirproto::dirreq::{DirRequest, DirResponse, DirStatus, DirStore, HsDirStore};
use pqo_relay::service::{ServiceAction, ServiceTable, COOKIE_LEN, RENDEZVOUS_STREAM};
use pqo_relay::stream::{ExitPolicy, StreamAction, StreamTable};
use pqo_wire::stream::EndReason;
use pqo_wire::{Cell, ChanCmd, CircId, RelayCmd, RelayMessage, StreamId};
use rand_core::OsRng;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::codec::CellStream;
use crate::ChannelBinding;

/// Cate celule pot astepta pe coada de scriere a unui canal.
///
/// Trebuie sa fie **mai mare decat fereastra de circuit** (1000 de celule):
/// controlul de flux garanteaza ca nu pot fi mai multe celule DATA in zbor decat
/// atat, deci coada nu se umple niciodata in functionare normala.
///
/// # De ce nu putem arunca celule cand se umple
///
/// Prima versiune facea `try_send` si ignora esecul, cu justificarea ca e
/// backpressure. E gresit: CGO actualizeaza cheile dupa **fiecare** celula
/// procesata. Daca releul a procesat celula N si aceasta nu ajunge la client,
/// starea celor doua capete diverge si tot ce urmeaza devine gunoi. O celula
/// pierduta nu inseamna degradare, inseamna corupere silentioasa a fluxului.
///
/// Simptomul a fost date reordonate la ~128 KB intr-un transfer mare.
///
/// Daca totusi coada se umple, peer-ul e blocat sau ostil: inchidem canalul.
const WRITE_QUEUE: usize = 2048;

/// Cate evenimente pot astepta la nucleu.
const CORE_QUEUE: usize = 1024;

/// Configuratia unui releu.
pub struct NodeConfig<K: Kem, S: Sig> {
    /// Cheile pentru handshake-ul de circuit.
    pub circuit_keys: RelayKeys<K>,
    /// Cheia de identitate, pentru handshake-ul de legatura.
    pub id_sk: Arc<S::SecretKey>,
    pub id_pk: Vec<u8>,
    /// Adresa pe care ascultam. Portul 0 inseamna „alege tu".
    pub listen: SocketAddr,
    /// Ce are voie sa iasa prin acest releu.
    ///
    /// Implicit `reject_all`: un releu devine exit doar daca operatorul cere
    /// explicit. Alegerea inversa ar transforma orice releu pornit din greseala
    /// intr-un proxy deschis.
    pub exit_policy: ExitPolicy,
    /// Documentele pe care le serveste acest releu prin BEGIN_DIR.
    ///
    /// Orice releu poate servi director, inclusiv unul care nu e exit: nu se
    /// deschide nicio conexiune in exterior.
    ///
    /// `Mutex` pentru ca publicarile modifica starea. Blocarea e scurta si nu
    /// face I/O, deci nu blocheaza nucleul in mod semnificativ.
    pub dir_store: Arc<std::sync::Mutex<DirStore>>,
    /// Stocarea de descriptori de servicii ascunse, daca releul e HSDir.
    ///
    /// `None` inseamna ca releul nu accepta si nu serveste descriptori de
    /// servicii ascunse.
    pub hs_store: Option<Arc<dyn HsDirStore>>,
    /// Contoarele agregate. Vezi [`crate::metrici`] pentru ce se masoara si de ce.
    pub metrici: Arc<crate::metrici::Metrici>,
    /// Pe ce circula celulele. Vezi [`Transport`].
    pub transport: Arc<Transport>,
}

impl<K: Kem, S: Sig> core::fmt::Debug for NodeConfig<K, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NodeConfig(listen={})", self.listen)
    }
}

/// Ce ajunge la nucleu.
enum Event {
    Inbound {
        chan: ChannelId,
        cell: Cell,
    },
    ChannelUp {
        chan: ChannelId,
        tx: mpsc::Sender<Vec<Cell>>,
    },
    ChannelDown {
        chan: ChannelId,
    },
    ConnectDone {
        token: u64,
        chan: Option<ChannelId>,
        tx: Option<mpsc::Sender<Vec<Cell>>>,
    },
    /// Exit: conexiunea catre destinatie s-a deschis.
    StreamUp {
        key: StreamKey,
        addr: [u8; 4],
        tx: mpsc::Sender<Vec<u8>>,
        /// Permisele de citire ale task-ului care citeste de la destinatie.
        ///
        /// Vezi nota despre backpressure de la [`exit_connect`].
        permits: Arc<tokio::sync::Semaphore>,
    },
    /// Exit: conexiunea catre destinatie nu s-a putut deschide.
    StreamFailed { key: StreamKey, reason: EndReason },
    /// Exit: date sosite de la destinatie, de trimis clientului.
    StreamData { key: StreamKey, data: Vec<u8> },
    /// Exit: destinatia a inchis conexiunea.
    StreamEof { key: StreamKey },
}

/// Identifica un stream: pe ce circuit, cu ce numar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub chan: ChannelId,
    pub circ: CircId,
    pub stream: StreamId,
}

/// Pe ce circula celulele intre noduri.
///
/// TLS nu autentifica nimic aici — asta o face handshake-ul de legatura. Aduce
/// doua lucruri: confidentialitate pe fir, si legarea de canal care impiedica
/// mutarea unui handshake valid pe alta conexiune.
///
/// Fara el, un observator vede antetele de celula, numarul de circuite si
/// tiparele de lungime. Payload-ul ramane criptat cu CGO, dar metadatele nu.
pub enum Transport {
    /// TCP simplu. **Fara confidentialitate si fara legare de canal.**
    ///
    /// Util pentru dezvoltare si pentru capturile care arata ce se vede fara
    /// TLS. Nu se foloseste in productie.
    Plaintext,
    /// TLS, cu certificat efemer generat la pornire.
    #[cfg(feature = "tls")]
    Tls(Arc<TlsTransport>),
}

impl core::fmt::Debug for Transport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Transport::Plaintext => f.write_str("Transport::Plaintext"),
            #[cfg(feature = "tls")]
            Transport::Tls(_) => f.write_str("Transport::Tls"),
        }
    }
}

/// Ce trebuie unui nod ca sa vorbeasca TLS in ambele sensuri.
#[cfg(feature = "tls")]
pub struct TlsTransport {
    pub acceptor: tokio_rustls::TlsAcceptor,
    pub connector: tokio_rustls::TlsConnector,
}

#[cfg(feature = "tls")]
impl core::fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Fara continut: configuratia TLS include material de cheie.
        f.write_str("TlsTransport")
    }
}

#[cfg(feature = "tls")]
impl TlsTransport {
    /// Genereaza un certificat efemer si construieste ambele capete.
    pub fn nou() -> io::Result<Self> {
        let chei = crate::tls::TlsKeys::generate()?;
        Ok(TlsTransport {
            acceptor: crate::tls::acceptor(&chei)?,
            connector: crate::tls::connector(),
        })
    }
}

/// Ce e comun tuturor circuitelor unui releu si nu se schimba dupa pornire.
///
/// Exista ca sa nu plimbam cinci parametri prin fiecare functie. Gruparea nu e
/// doar cosmetica: face evident ce e configuratie fixa si ce e stare care se
/// modifica — vezi [`ExitState`].
struct NodeCtx<S: Sig> {
    metrici: Arc<crate::metrici::Metrici>,
    transport: Arc<Transport>,
    id_sk: Arc<S::SecretKey>,
    id_pk: Vec<u8>,
    exit_policy: ExitPolicy,
    dir_store: Arc<std::sync::Mutex<DirStore>>,
    hs_store: Option<Arc<dyn HsDirStore>>,
}

/// Starea stream-urilor de iesire si de director, per releu.
///
/// Traieste doar in nucleu, deci nu are nevoie de sincronizare.
#[derive(Default)]
struct ExitState {
    /// Tabelele de stream, cate una per circuit.
    tables: HashMap<(ChannelId, CircId), StreamTable>,
    /// Cozile catre conexiunile deschise spre destinatie.
    writers: HashMap<StreamKey, mpsc::Sender<Vec<u8>>>,
    /// Permisele de citire, care realizeaza backpressure-ul catre destinatie.
    permits: HashMap<StreamKey, Arc<tokio::sync::Semaphore>>,
    /// Cereri de director partiale, acumulate pana cand prefixul de lungime
    /// spune ca sunt complete.
    dir_partial: HashMap<StreamKey, Vec<u8>>,
    /// Rolurile de punct de introducere si de rendezvous.
    service: ServiceTable,
}

impl ExitState {
    /// Elibereaza tot ce tine de un stream.
    fn drop_stream(&mut self, key: &StreamKey) {
        self.writers.remove(key);
        self.permits.remove(key);
        self.dir_partial.remove(key);
    }
}

/// Legatura catre un releu care ruleaza.
#[derive(Debug)]
pub struct NodeHandle {
    addr: SocketAddr,
    core: tokio::task::JoinHandle<()>,
    accept: tokio::task::JoinHandle<()>,
}

impl NodeHandle {
    /// Adresa pe care asculta efectiv. Utila cand ai cerut portul 0.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Opreste releul.
    pub fn shutdown(self) {
        self.core.abort();
        self.accept.abort();
    }
}

/// Alocator de identificatori de canal, unic per proces.
fn next_channel_id() -> ChannelId {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    ChannelId(N.fetch_add(1, Ordering::Relaxed))
}

/// Porneste un releu. Intoarce cand socket-ul de ascultare e gata.
pub async fn spawn<K, S>(cfg: NodeConfig<K, S>) -> io::Result<NodeHandle>
where
    K: Kem + Send + 'static,
    K::DecapKey: Send,
    S: Sig + Send + Sync + 'static,
    S::SecretKey: Send + Sync + 'static,
{
    let listener = TcpListener::bind(cfg.listen).await?;
    let addr = listener.local_addr()?;

    let (ev_tx, ev_rx) = mpsc::channel::<Event>(CORE_QUEUE);

    let ctx = Arc::new(NodeCtx::<S> {
        metrici: Arc::clone(&cfg.metrici),
        transport: Arc::clone(&cfg.transport),
        id_sk: Arc::clone(&cfg.id_sk),
        id_pk: cfg.id_pk.clone(),
        exit_policy: cfg.exit_policy,
        dir_store: cfg.dir_store,
        hs_store: cfg.hs_store,
    });

    let core = tokio::spawn(core_loop::<K, S>(
        RelayNode::new(cfg.circuit_keys),
        ev_rx,
        ev_tx.clone(),
        Arc::clone(&ctx),
    ));
    let accept = tokio::spawn(accept_loop::<S>(
        listener,
        ev_tx,
        cfg.id_sk,
        cfg.id_pk,
        cfg.metrici,
        cfg.transport,
    ));

    Ok(NodeHandle {
        addr,
        core,
        accept,
    })
}

async fn accept_loop<S>(
    listener: TcpListener,
    ev_tx: mpsc::Sender<Event>,
    id_sk: Arc<S::SecretKey>,
    id_pk: Vec<u8>,
    metrici: Arc<crate::metrici::Metrici>,
    transport: Arc<Transport>,
) where
    S: Sig + Send + Sync + 'static,
    S::SecretKey: Send + Sync + 'static,
{
    while let Ok((sock, _peer)) = listener.accept().await {
        // Fara asta, o scriere mica urmata de asteptare — cazul obisnuit pe
        // drumul de intoarcere al unui circuit — asteapta confirmarea celei
        // anterioare. Masurat pe RENDEZVOUS2: 36 ms in loc de sub 1 ms.
        //
        // Conteaza pe **ambele** capete. Prima incercare a pus optiunea doar pe
        // conexiunile initiate, iar intarzierea a ramas exact pe directia in
        // care nu era pusa.
        let _ = sock.set_nodelay(true);
        let ev_tx = ev_tx.clone();
        let id_sk = Arc::clone(&id_sk);
        let id_pk = id_pk.clone();
        let metrici = Arc::clone(&metrici);
        let transport = Arc::clone(&transport);
        tokio::spawn(async move {
            // Cine asculta accepta si relee autentificate, si clienti anonimi:
            // nu stie dinainte cine se conecteaza.
            match &*transport {
                Transport::Plaintext => {
                    let mut stream = CellStream::new(sock);
                    if link_handshake_cu_legare::<S, _>(
                        &mut stream,
                        Role::Responder,
                        AuthMode::Optional,
                        id_sk,
                        &id_pk,
                        ChannelBinding::insecure_plaintext_tcp(),
                    )
                    .await
                    .is_err()
                    {
                        metrici.handshake_esuat();
                        return;
                    }
                    porneste_canal(stream, ev_tx).await;
                }
                #[cfg(feature = "tls")]
                Transport::Tls(t) => {
                    let Ok(c) = crate::tls::accept(&t.acceptor, sock).await else {
                        metrici.handshake_esuat();
                        return;
                    };
                    let mut stream = CellStream::new(c.stream);
                    if link_handshake_cu_legare::<S, _>(
                        &mut stream,
                        Role::Responder,
                        AuthMode::Optional,
                        id_sk,
                        &id_pk,
                        c.binding,
                    )
                    .await
                    .is_err()
                    {
                        metrici.handshake_esuat();
                        return;
                    }
                    porneste_canal(stream, ev_tx).await;
                }
            }
        });
    }
}

/// Ruleaza handshake-ul de legatura pe un flux.
///
/// Toata logica de protocol vine din `pqo-relay`; aici doar se muta octeti.
/// Daca vrei sa intelegi handshake-ul, citeste acolo, nu aici.
///
/// Peste TCP simplu, foloseste legarea nesigura. Cu TLS, apeleaza
/// [`link_handshake_cu_legare`] si paseaza exportul.
pub async fn link_handshake<S, T>(
    stream: &mut CellStream<T>,
    role: Role,
    mode: AuthMode,
    id_sk: Arc<S::SecretKey>,
    id_pk: &[u8],
) -> io::Result<()>
where
    S: Sig,
    T: AsyncRead + AsyncWrite + Unpin,
{
    link_handshake_cu_legare::<S, T>(
        stream,
        role,
        mode,
        id_sk,
        id_pk,
        ChannelBinding::insecure_plaintext_tcp(),
    )
    .await
}

/// Ca [`link_handshake`], dar cu o legare de canal data.
///
/// Legarea vine din exportul TLS si e ceea ce impiedica mutarea unui handshake
/// valid pe alta conexiune.
pub async fn link_handshake_cu_legare<S, T>(
    stream: &mut CellStream<T>,
    role: Role,
    mode: AuthMode,
    id_sk: Arc<S::SecretKey>,
    id_pk: &[u8],
    binding: ChannelBinding,
) -> io::Result<()>
where
    S: Sig,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs =
        LinkHandshake::<S>::new_shared(role, mode, id_sk, id_pk.to_vec(), binding.into_bytes());
    let mut rng = OsRng;

    if role == Role::Initiator {
        let out = hs.start().map_err(bad)?;
        stream.write_cells(&out).await?;
    }

    while !hs.is_open() {
        let Some(cell) = stream.read_cell().await? else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "conexiune inchisa in timpul handshake-ului",
            ));
        };
        let out = hs.handle(&cell, &mut rng).map_err(bad)?;
        if !out.is_empty() {
            stream.write_cells(&out).await?;
        }
        if hs.needs_netinfo() {
            let ni = hs.send_netinfo().map_err(bad)?;
            stream.write_cells(&ni).await?;
        }
    }
    Ok(())
}

fn bad<E: core::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// Inregistreaza un canal nou si porneste bucla de pompare.
///
/// Extrasa ca sa nu fie duplicata intre ramurile de transport: singura diferenta
/// dintre ele e tipul fluxului, iar restul e identic.
async fn porneste_canal<T>(stream: CellStream<T>, ev_tx: mpsc::Sender<Event>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let chan = next_channel_id();
    let (out_tx, out_rx) = mpsc::channel::<Vec<Cell>>(WRITE_QUEUE);
    if ev_tx
        .send(Event::ChannelUp { chan, tx: out_tx })
        .await
        .is_err()
    {
        return;
    }
    pump(chan, stream, out_rx, ev_tx).await;
}

/// Bucla care muta celule in ambele sensuri pe un canal.
async fn pump<T>(
    chan: ChannelId,
    mut stream: CellStream<T>,
    mut out_rx: mpsc::Receiver<Vec<Cell>>,
    ev_tx: mpsc::Sender<Event>,
) where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        tokio::select! {
            r = stream.read_cell() => match r {
                Ok(Some(cell)) => {
                    if ev_tx.send(Event::Inbound { chan, cell }).await.is_err() {
                        break;
                    }
                }
                _ => break,
            },
            m = out_rx.recv() => match m {
                Some(mut cells) => {
                    // Golim si restul cozii inainte de scriere. Celulele ajung
                    // aici cate una — fiecare sosire produce un eveniment
                    // separat in nucleu — iar un mesaj relay fragmentat inseamna
                    // doua celule consecutive.
                    //
                    // Scrise separat, a doua asteapta confirmarea primei.
                    // Masurat: 40 ms per mesaj fragmentat, adica de zece ori
                    // mai mult decat construirea unui circuit de trei hopuri.
                    while let Ok(mut alte) = out_rx.try_recv() {
                        cells.append(&mut alte);
                        if cells.len() >= 64 {
                            break;
                        }
                    }
                    if stream.write_cells(&cells).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
        }
    }
    let _ = ev_tx.send(Event::ChannelDown { chan }).await;
}

/// Nucleul: singurul loc care atinge starea criptografica.
async fn core_loop<K, S>(
    mut node: RelayNode<K>,
    mut ev_rx: mpsc::Receiver<Event>,
    ev_tx: mpsc::Sender<Event>,
    ctx: Arc<NodeCtx<S>>,
) where
    K: Kem + Send + 'static,
    K::DecapKey: Send,
    S: Sig + Send + Sync + 'static,
    S::SecretKey: Send + Sync + 'static,
{
    let mut channels: HashMap<ChannelId, mpsc::Sender<Vec<Cell>>> = HashMap::new();
    let mut st = ExitState::default();
    let mut rng = OsRng;

    while let Some(ev) = ev_rx.recv().await {
        let actions: Vec<Action> = match ev {
            Event::ChannelUp { chan, tx } => {
                channels.insert(chan, tx);
                ctx.metrici.canal_deschis();
                Vec::new()
            }
            Event::ChannelDown { chan } => {
                channels.remove(&chan);
                ctx.metrici.canal_inchis();
                let mut out = node.on_channel_closed(chan);
                for pereche in st.service.on_channel_closed(chan) {
                    out.extend(node.on_destroy(pereche.chan, pereche.circ));
                }
                out
            }
            Event::ConnectDone { token, chan, tx } => match (chan, tx) {
                (Some(c), Some(t)) => {
                    channels.insert(c, t);
                    node.on_channel_ready(token, c).unwrap_or_default()
                }
                _ => node.on_channel_failed(token).unwrap_or_default(),
            },
            Event::StreamUp {
                key,
                addr,
                tx,
                permits: p,
            } => {
                st.writers.insert(key, tx);
                st.permits.insert(key, p);
                let sa = st
                    .tables
                    .get_mut(&(key.chan, key.circ))
                    .map(|t| t.on_connected(key.stream, addr))
                    .unwrap_or_default();
                exec_stream::<K, S>(&mut node, &ctx, key, sa, &mut st, &ev_tx)
            }
            Event::StreamFailed { key, reason } => {
                st.drop_stream(&key);
                let sa = st
                    .tables
                    .get_mut(&(key.chan, key.circ))
                    .map(|t| t.on_connect_failed(key.stream, reason))
                    .unwrap_or_default();
                exec_stream::<K, S>(&mut node, &ctx, key, sa, &mut st, &ev_tx)
            }
            Event::StreamData { key, data } => {
                let sa = st
                    .tables
                    .get_mut(&(key.chan, key.circ))
                    .map(|t| t.data_to_client(key.stream, data))
                    .unwrap_or_default();
                exec_stream::<K, S>(&mut node, &ctx, key, sa, &mut st, &ev_tx)
            }
            Event::StreamEof { key } => {
                st.drop_stream(&key);
                let sa = st
                    .tables
                    .get_mut(&(key.chan, key.circ))
                    .map(|t| t.on_remote_closed(key.stream, EndReason::Done))
                    .unwrap_or_default();
                exec_stream::<K, S>(&mut node, &ctx, key, sa, &mut st, &ev_tx)
            }
            Event::Inbound { chan, cell } => {
                let circ = cell.circ();
                let r = match cell.cmd() {
                    ChanCmd::Create2 => {
                        let r = node.on_create2(chan, circ, cell.payload(), &mut rng);
                        if r.is_ok() {
                            ctx.metrici.circuit_creat();
                        }
                        r
                    }
                    ChanCmd::Created2 => node.on_created2(chan, circ, cell.payload(), &mut rng),
                    ChanCmd::Relay | ChanCmd::RelayEarly => {
                        ctx.metrici.celula();
                        // Un circuit are doua capete. Incercam intai sensul
                        // dinspre client; daca celula a venit din celalalt
                        // sens, `WrongDirection` ne spune sa incercam invers.
                        match node.on_relay_forward(chan, circ, &cell, &mut rng) {
                            Err(pqo_relay::RelayError::WrongDirection) => {
                                node.on_relay_backward(chan, circ, &cell)
                            }
                            other => other,
                        }
                    }
                    ChanCmd::Destroy => Ok(node.on_destroy(chan, circ)),
                    _ => Ok(Vec::new()),
                };
                // O eroare pe un circuit nu doboara canalul: celelalte circuite
                // de pe aceeasi conexiune continua.
                r.unwrap_or_default()
            }
        };

        let mut actions = actions;
        let mut i = 0;
        while i < actions.len() {
            let a = actions[i].clone();
            i += 1;
            match a {
                Action::Send { chan, cell } => {
                    // Adunam celulele consecutive catre acelasi canal si le
                    // trimitem impreuna: `write_cells` face o singura scriere,
                    // deci nucleul nu mai produce rafale de scrieri mici.
                    let mut grup = vec![cell];
                    while let Some(Action::Send { chan: c2, cell: n }) = actions.get(i) {
                        if *c2 != chan {
                            break;
                        }
                        grup.push(n.clone());
                        i += 1;
                    }
                    if let Some(tx) = channels.get(&chan) {
                        if tx.try_send(grup).is_err() {
                            // Coada plina sau scriitor mort. Nu avem voie sa
                            // pierdem celula, deci inchidem canalul si lasam
                            // circuitele sa fie curatate corect.
                            channels.remove(&chan);
                            actions.extend(node.on_channel_closed(chan));
                        }
                    }
                }
                Action::Connect {
                    address,
                    port,
                    token,
                    ..
                } => {
                    let ev_tx2 = ev_tx.clone();
                    let id_sk = Arc::clone(&ctx.id_sk);
                    let id_pk = ctx.id_pk.clone();
                    let transport = Arc::clone(&ctx.transport);
                    tokio::spawn(async move {
                        let ev = dial::<S>(
                            Destinatie {
                                address: &address,
                                port,
                                token,
                                id_sk,
                                id_pk: &id_pk,
                            },
                            &ev_tx2,
                            &transport,
                        )
                        .await;
                        let _ = ev_tx2.send(ev).await;
                    });
                }
                Action::CircuitClosed { chan, circ } => {
                    ctx.metrici.circuit_inchis();
                    // Daca circuitul era imperecheat, cade si perechea: un tunel
                    // cu un singur capat nu mai are ce transporta.
                    if let Some(pereche) = st.service.on_circuit_closed(Endpoint { chan, circ }) {
                        actions.extend(node.on_destroy(pereche.chan, pereche.circ));
                    }
                    if let Some(mut t) = st.tables.remove(&(chan, circ)) {
                        for a in t.close_all() {
                            if let StreamAction::Close { stream } = a {
                                st.drop_stream(&StreamKey { chan, circ, stream });
                            }
                        }
                    }
                }
                Action::Deliver { chan, circ, msg } => {
                    // Mesajele de servicii ascunse se trateaza inainte de
                    // stream-uri: nu deschid conexiuni si nu depind de politica
                    // de iesire.
                    let ep = Endpoint { chan, circ };
                    if let Some(noi) =
                        trateaza_serviciu::<K, S>(&mut node, &mut st, ep, &msg, &mut rng)
                    {
                        actions.extend(noi);
                        continue;
                    }
                    // Stream-urile de director se servesc de orice releu; cele
                    // de iesire, doar de unul cu politica de exit.
                    let e_dir = msg.cmd == RelayCmd::BeginDir;
                    if !ctx.exit_policy.is_exit() && !e_dir && !st.tables.contains_key(&(chan, circ))
                    {
                        continue;
                    }
                    let t = st
                        .tables
                        .entry((chan, circ))
                        .or_insert_with(|| StreamTable::new(ctx.exit_policy.clone()));
                    let id = msg.stream;
                    let sa = match msg.cmd {
                        RelayCmd::Begin => t.on_begin(id, &msg.body).unwrap_or_default(),
                        RelayCmd::BeginDir => t.on_begin_dir(id).unwrap_or_default(),
                        RelayCmd::Data => t.on_data(id, &msg.body).unwrap_or_default(),
                        RelayCmd::End => t.on_end(id),
                        RelayCmd::Sendme => {
                            let a = t.on_sendme(id).unwrap_or_default();
                            // Fereastra s-a largit: task-ul de citire are voie
                            // sa mai aduca date de la destinatie. Asta e locul
                            // unde backpressure-ul se propaga inapoi in TCP.
                            if !id.is_control() {
                                if let Some(sem) = st.permits.get(&StreamKey {
                                    chan,
                                    circ,
                                    stream: id,
                                }) {
                                    sem.add_permits(pqo_wire::STREAM_WINDOW_INC as usize);
                                }
                            }
                            a
                        }
                        _ => Vec::new(),
                    };
                    let key = StreamKey {
                        chan,
                        circ,
                        stream: id,
                    };
                    // Actiunile produse aici (celule catre client) se adauga la
                    // coada curenta, ca sa fie executate in aceeasi trecere.
                    let noi =
                        exec_stream::<K, S>(&mut node, &ctx, key, sa, &mut st, &ev_tx);
                    actions.extend(noi);
                }
            }
        }
    }
}

/// Executa actiunile de stream produse de o tabela de exit.
///
/// Cele care merg catre client se traduc in mesaje relay si intra inapoi in
/// `RelayNode`, care le cripteaza si produce celule. Cele care merg catre
/// destinatie ajung la task-ul de conexiune.
fn exec_stream<K: Kem, S: Sig>(
    node: &mut RelayNode<K>,
    ctx: &NodeCtx<S>,
    key: StreamKey,
    actions: Vec<StreamAction>,
    st: &mut ExitState,
    ev_tx: &mpsc::Sender<Event>,
) -> Vec<Action> {
    // `OsRng` nu are stare: nu are rost sa il plimbam prin semnatura.
    let rng = &mut OsRng;
    let mut out = Vec::new();
    for a in actions {
        match a {
            StreamAction::Connect {
                stream,
                address,
                port,
            } => {
                ctx.metrici.stream_deschis();
                let k = StreamKey { stream, ..key };
                let ev = ev_tx.clone();
                let privat = ctx.exit_policy.allows_private();
                tokio::spawn(async move { exit_connect(k, address, port, privat, ev).await });
            }
            StreamAction::Write { stream, data } => {
                let k = StreamKey { stream, ..key };
                if let Some(tx) = st.writers.get(&k) {
                    // Ca la celule: nu avem voie sa pierdem octeti. Un `try_send`
                    // esuat ar taia o bucata din mijlocul fluxului TCP, iar
                    // destinatia ar primi date corupte fara sa observe nimeni.
                    if tx.try_send(data).is_err() {
                        st.drop_stream(&k);
                        if let Ok(msg) = RelayMessage::new(
                            RelayCmd::End,
                            stream,
                            pqo_wire::stream::End {
                                reason: EndReason::Misc,
                            }
                            .encode(),
                        ) {
                            if let Ok(a) = node.deliver_to_client(key.chan, key.circ, &msg, rng) {
                                out.extend(a);
                            }
                        }
                    }
                }
            }
            StreamAction::Close { stream } => {
                st.drop_stream(&StreamKey { stream, ..key });
            }
            StreamAction::DirRequest { stream, request } => {
                let k = StreamKey { stream, ..key };
                let buf = st.dir_partial.entry(k).or_default();
                buf.extend_from_slice(&request);

                // Asteptam pana cand prefixul de lungime spune ca cererea e
                // completa. O cerere de publicare are cateva kiloocteti, deci
                // soseste in mai multe celule.
                let total = match DirRequest::framed_len(buf) {
                    None => continue,
                    Some(Err(_)) => {
                        st.dir_partial.remove(&k);
                        buf_raspuns(
                            node,
                            key,
                            stream,
                            DirResponse::error(DirStatus::BadRequest),
                            rng,
                            &mut out,
                        );
                        continue;
                    }
                    Some(Ok(n)) => n,
                };
                if buf.len() < total {
                    continue;
                }
                let complet = st.dir_partial.remove(&k).unwrap_or_default();

                // Raspunsul se produce local, din documente deja semnate. Releul
                // nu semneaza nimic: clientul verifica singur.
                let raspuns = match DirRequest::parse_framed(&complet[..total]) {
                    Err(_) => DirResponse::error(DirStatus::BadRequest),
                    // Publicarea de descriptor: se valideaza inainte de stocare.
                    // Semnatura se verifica in `accept_descriptor`, deci un
                    // document fals nu intra oricine l-ar fi trimis.
                    Ok(DirRequest::Publish(doc)) => match ctx.dir_store.lock() {
                        Ok(mut st) => match st.accept_descriptor::<S>(&doc) {
                            Ok(_) => DirResponse::ok(Vec::new()),
                            Err(_) => DirResponse::error(DirStatus::Rejected),
                        },
                        Err(_) => DirResponse::error(DirStatus::Rejected),
                    },
                    Ok(DirRequest::HsUpload(doc)) => match ctx.hs_store.as_ref() {
                        Some(h) => match h.upload(&doc) {
                            Ok(()) => DirResponse::ok(Vec::new()),
                            Err(_) => DirResponse::error(DirStatus::Rejected),
                        },
                        None => DirResponse::error(DirStatus::NotFound),
                    },
                    Ok(DirRequest::HsFetch(id)) => match ctx.hs_store.as_ref().and_then(|h| h.fetch(&id)) {
                        Some(d) => DirResponse::ok(d),
                        None => DirResponse::error(DirStatus::NotFound),
                    },
                    Ok(r) => match ctx.dir_store.lock() {
                        Ok(st) => st.serve(&r),
                        Err(_) => DirResponse::error(DirStatus::BadRequest),
                    },
                };
                ctx.metrici.cerere_director();
                buf_raspuns(node, key, stream, raspuns, rng, &mut out);
            }
            StreamAction::ToClient { stream, cmd, body } => {
                if let Ok(msg) = RelayMessage::new(cmd, stream, body) {
                    if let Ok(a) = node.deliver_to_client(key.chan, key.circ, &msg, rng) {
                        out.extend(a);
                    }
                }
            }
        }
    }
    out
}

/// Citeste un camp prefixat cu lungimea pe doi octeti.
fn camp_lp(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + n {
        return None;
    }
    Some((&buf[2..2 + n], &buf[2 + n..]))
}

/// Trateaza mesajele de servicii ascunse.
///
/// Intoarce `None` daca mesajul nu e de competenta ei, ca apelantul sa il duca
/// mai departe la stratul de stream-uri.
fn trateaza_serviciu<K: Kem, S: Sig>(
    node: &mut RelayNode<K>,
    st: &mut ExitState,
    ep: Endpoint,
    msg: &RelayMessage,
    rng: &mut OsRng,
) -> Option<Vec<Action>> {
    let actiuni = match msg.cmd {
        RelayCmd::EstablishIntro => {
            // Corpul e `len(cheie) | cheie | len(semnatura) | semnatura`.
            //
            // Semnatura e obligatorie, si releul o verifica. Fara ea, oricine
            // citeste descriptorul unui serviciu — unde cheia de autentificare e
            // **publica** — ar putea ocupa slotul la punctul de introducere si ar
            // face serviciul inaccesibil.
            let (cheie, rest) = camp_lp(&msg.body)?;
            let (sig, rest) = camp_lp(rest)?;
            if !rest.is_empty() {
                return Some(Vec::new());
            }
            let corp = pqo_crypto::kdf::hash(b"pqonion-hs-establish-intro-v2", &[cheie]);
            if S::verify(cheie, &corp, sig).is_err() {
                return Some(Vec::new());
            }
            let akid = pqo_crypto::kdf::hash(b"pqonion-hs-authkeyid-v1", &[cheie]);
            st.service.on_establish_intro(ep, akid).ok()?
        }
        RelayCmd::Introduce1 => {
            // Primii 32 de octeti sunt identificatorul cheii; restul e corpul
            // criptat, pe care releul nu il poate citi.
            if msg.body.len() < 32 {
                return Some(Vec::new());
            }
            let akid: [u8; 32] = msg.body[..32].try_into().ok()?;
            st.service
                .on_introduce1(ep, &akid, msg.body.clone())
                .ok()?
        }
        RelayCmd::EstablishRendezvous => {
            let cookie: [u8; COOKIE_LEN] = msg.body.as_slice().try_into().ok()?;
            st.service.on_establish_rendezvous(ep, cookie).ok()?
        }
        RelayCmd::Rendezvous1 => {
            if msg.body.len() <= COOKIE_LEN {
                return Some(Vec::new());
            }
            let cookie: [u8; COOKIE_LEN] = msg.body[..COOKIE_LEN].try_into().ok()?;
            st.service
                .on_rendezvous1(ep, &cookie, msg.body[COOKIE_LEN..].to_vec())
                .ok()?
        }
        // Dupa imperechere, mesajele de pe stream-ul rezervat se copiaza pe
        // circuitul pereche fara sa fie atinse.
        RelayCmd::Data if msg.stream == RENDEZVOUS_STREAM => {
            st.service.relay_rendezvous(ep, msg.body.clone())
        }
        _ => return None,
    };

    let mut out = Vec::new();
    for a in actiuni {
        if let ServiceAction::Send { target, cmd, body } = a {
            let stream = if cmd == RelayCmd::Data {
                RENDEZVOUS_STREAM
            } else {
                StreamId::CONTROL
            };
            if let Ok(m) = RelayMessage::new(cmd, stream, body) {
                if let Ok(acts) = node.deliver_to_client(target.chan, target.circ, &m, rng) {
                    out.extend(acts);
                }
            }
        }
    }
    Some(out)
}

/// Trimite un raspuns de director inapoi clientului, taiat in celule.
fn buf_raspuns<K: Kem>(
    node: &mut RelayNode<K>,
    key: StreamKey,
    stream: StreamId,
    raspuns: DirResponse,
    rng: &mut OsRng,
    out: &mut Vec<Action>,
) {
    let corp = raspuns.encode();
    for bucata in corp.chunks(pqo_wire::RELAY_DATA_LEN) {
        if let Ok(msg) = RelayMessage::new(RelayCmd::Data, stream, bucata.to_vec()) {
            if let Ok(a) = node.deliver_to_client(key.chan, key.circ, &msg, rng) {
                out.extend(a);
            }
        }
    }
    if let Ok(msg) = RelayMessage::new(
        RelayCmd::End,
        stream,
        pqo_wire::stream::End {
            reason: EndReason::Done,
        }
        .encode(),
    ) {
        if let Ok(a) = node.deliver_to_client(key.chan, key.circ, &msg, rng) {
            out.extend(a);
        }
    }
}

/// Deschide o conexiune catre destinatie si pompeaza date in ambele sensuri.
async fn exit_connect(
    key: StreamKey,
    address: String,
    port: u16,
    allow_private: bool,
    ev: mpsc::Sender<Event>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Rezolvarea se face explicit, ca sa putem verifica **rezultatul**, nu doar
    // ce a cerut clientul. Fara pasul asta, oricine poate inregistra un domeniu
    // care indica spre 127.0.0.1 si poate ajunge la serviciile locale ale
    // operatorului — verificarea din politica vede doar literale.
    //
    // Efect secundar util: pe sisteme dual-stack, alegem explicit adresa in loc
    // sa depindem de ordinea in care le intoarce rezolverul.
    let rezolvate = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::lookup_host((address.as_str(), port)),
    )
    .await
    {
        Ok(Ok(it)) => it.collect::<Vec<_>>(),
        _ => {
            let _ = ev
                .send(Event::StreamFailed {
                    key,
                    reason: EndReason::ResolveFailed,
                })
                .await;
            return;
        }
    };

    let permise: Vec<std::net::SocketAddr> = rezolvate
        .into_iter()
        .filter(|a| allow_private || !pqo_relay::stream::is_private_addr(&a.ip()))
        .collect();
    if permise.is_empty() {
        let _ = ev
            .send(Event::StreamFailed {
                key,
                reason: EndReason::ExitPolicy,
            })
            .await;
        return;
    }

    let conectare = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(&permise[..]),
    )
    .await;

    let sock = match conectare {
        Ok(Ok(s)) => {
            // Si catre destinatie: un raspuns HTTP mic urmat de asteptare ar
            // suferi de aceeasi intarziere.
            let _ = s.set_nodelay(true);
            s
        }
        // Distingem motivele: clientul decide altfel daca destinatia refuza
        // fata de cazul in care numele nu se rezolva.
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
            let _ = ev
                .send(Event::StreamFailed {
                    key,
                    reason: EndReason::ConnectRefused,
                })
                .await;
            return;
        }
        Ok(Err(_)) => {
            let _ = ev
                .send(Event::StreamFailed {
                    key,
                    reason: EndReason::ResolveFailed,
                })
                .await;
            return;
        }
        Err(_) => {
            let _ = ev
                .send(Event::StreamFailed {
                    key,
                    reason: EndReason::Timeout,
                })
                .await;
            return;
        }
    };

    let addr = match sock.peer_addr() {
        Ok(std::net::SocketAddr::V4(a)) => a.ip().octets(),
        _ => [0, 0, 0, 0],
    };
    // Coada catre destinatie. Trebuie sa depaseasca fereastra de stream (500),
    // ca sa nu se umple in functionare normala — vezi nota de la `WRITE_QUEUE`.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
    // Un permis = dreptul de a citi o bucata de la destinatie.
    //
    // Numarul initial e chiar fereastra de stream, iar nucleul adauga permise
    // doar cand primeste SENDME de la client. Astfel numarul de bucati citite
    // din socket nu poate depasi niciodata cate putem trimite mai departe.
    let permits = Arc::new(tokio::sync::Semaphore::new(
        pqo_wire::STREAM_WINDOW_START as usize,
    ));
    if ev
        .send(Event::StreamUp {
            key,
            addr,
            tx,
            permits: Arc::clone(&permits),
        })
        .await
        .is_err()
    {
        return;
    }

    let (mut r, mut w) = sock.into_split();
    let ev2 = ev.clone();
    tokio::spawn(async move {
        // Bucata maxima pe care o poate purta o celula, ca sa nu fragmentam
        // inutil mesajele de date.
        let mut buf = vec![0u8; pqo_wire::RELAY_DATA_LEN];
        loop {
            // Fara permis nu citim. Socket-ul se umple, fereastra TCP se
            // inchide, si presiunea ajunge pana la serverul de origine —
            // singurul loc unde chiar are efect.
            //
            // Varianta anterioara citea cat de repede putea si tinea datele
            // intr-o coada. Coada se umplea, iar stream-ul se inchidea. Aparea
            // doar cand clientul era mai lent decat destinatia, deci depindea de
            // viteza masinii: acelasi test trecea cu ML-KEM activat (mai lent)
            // si pica fara.
            let Ok(p) = permits.acquire().await else {
                break;
            };
            p.forget();

            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ev2
                        .send(Event::StreamData {
                            key,
                            data: buf[..n].to_vec(),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = ev2.send(Event::StreamEof { key }).await;
    });

    while let Some(d) = rx.recv().await {
        if w.write_all(&d).await.is_err() {
            break;
        }
    }
}

/// Deschide un canal catre un alt releu si ruleaza handshake-ul ca initiator.
/// Unde si cu ce identitate deschidem un canal.
struct Destinatie<'a, S: Sig> {
    address: &'a str,
    port: u16,
    token: u64,
    id_sk: Arc<S::SecretKey>,
    id_pk: &'a [u8],
}

async fn dial<S>(
    d: Destinatie<'_, S>,
    ev_tx: &mpsc::Sender<Event>,
    transport: &Transport,
) -> Event
where
    S: Sig + Send + Sync + 'static,
    S::SecretKey: Send + Sync + 'static,
{
    let Destinatie {
        address,
        port,
        token,
        id_sk,
        id_pk,
    } = d;
    let esec = Event::ConnectDone {
        token,
        chan: None,
        tx: None,
    };
    let Ok(sock) = TcpStream::connect((address, port)).await else {
        return esec;
    };
    let _ = sock.set_nodelay(true);

    // Intre relee autentificarea e reciproca.
    let chan = next_channel_id();
    let (out_tx, out_rx) = mpsc::channel::<Vec<Cell>>(WRITE_QUEUE);
    let ev2 = ev_tx.clone();

    match transport {
        Transport::Plaintext => {
            let mut stream = CellStream::new(sock);
            if link_handshake_cu_legare::<S, _>(
                &mut stream,
                Role::Initiator,
                AuthMode::Mutual,
                id_sk,
                id_pk,
                ChannelBinding::insecure_plaintext_tcp(),
            )
            .await
            .is_err()
            {
                return esec;
            }
            tokio::spawn(async move { pump(chan, stream, out_rx, ev2).await });
        }
        #[cfg(feature = "tls")]
        Transport::Tls(t) => {
            let Ok(c) = crate::tls::connect(&t.connector, sock).await else {
                return esec;
            };
            let mut stream = CellStream::new(c.stream);
            if link_handshake_cu_legare::<S, _>(
                &mut stream,
                Role::Initiator,
                AuthMode::Mutual,
                id_sk,
                id_pk,
                c.binding,
            )
            .await
            .is_err()
            {
                return esec;
            }
            tokio::spawn(async move { pump(chan, stream, out_rx, ev2).await });
        }
    }

    Event::ConnectDone {
        token,
        chan: Some(chan),
        tx: Some(out_tx),
    }
}
