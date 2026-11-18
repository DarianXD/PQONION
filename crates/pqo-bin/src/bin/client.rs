//! Clientul cu frontend SOCKS5, ca proces.
//!
//! ```text
//! pqonion-client --socks 127.0.0.1:9050 --guard 127.0.0.1:9001 --exit 127.0.0.1:9003
//! ```
//!
//! # Cum se foloseste
//!
//! ```text
//! curl --socks5-hostname 127.0.0.1:9050 http://example.com/
//! ```
//!
//! Atentie la `--socks5-hostname`, nu `--socks5`: al doilea rezolva numele local,
//! deci cererea DNS pleaca in clar prin reteaua ta si tot circuitul devine
//! inutil. In Firefox, echivalentul e `network.proxy.socks_remote_dns = true`.
//!
//! # Adrese `.onion`
//!
//! O cerere catre o adresa `.onion` nu merge prin releul de iesire. Clientul
//! descarca descriptorul de la HSDir, alege un punct de introducere, stabileste
//! un rendezvous si comunica prin tunel. Totul prin circuite.
//!
//! # Ce nu face inca
//!
//! Nu descarca consensul si nu alege calea singur: releele se dau explicit in
//! linia de comanda. Codul de selectie exista in `pqo-client::path`, dar are
//! nevoie de descriptori, care se descarca prin circuit — vezi `dir_request`.

use std::net::SocketAddr;
use std::sync::Arc;

use pqo_bin::{clamp_level, load_or_create_seed, log, Args, Level, SetupError};
use pqo_client::socks;
use pqo_crypto::kdf::ShakeRng;
use pqo_crypto::sig::Sig;
use pqo_crypto::{RelayPublic, Variant};
use pqo_dirproto::dirreq::{DirRequest, DirStatus};
use pqo_hs::desc::Descriptor;
use pqo_hs::publish::fetch_targets;
use pqo_hs::rend::{auth_key_id, new_cookie, IntroPayload, Introduce};
use pqo_hs::OnionAddress;
use pqo_relay_io::client::{Circuit, Flux, TransportClient};
use pqo_relay_io::tunnel::Tunnel;
use pqo_wire::{RelayCmd, RelayMessage, StreamId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "pq")]
type K = pqo_crypto::Hybrid<pqo_crypto::X25519Kem, pqo_crypto::MlKem768>;
#[cfg(not(feature = "pq"))]
type K = pqo_crypto::Hybrid<pqo_crypto::X25519Kem, pqo_crypto::X25519Kem>;

#[cfg(feature = "pq")]
type S = pqo_crypto::HybridSig<pqo_crypto::Ed25519, pqo_crypto::MlDsa44>;
#[cfg(not(feature = "pq"))]
type S = pqo_crypto::Ed25519;

const AJUTOR: &str = "\
pqonion-client — proxy SOCKS5 peste circuite

  --socks ADRESA:PORT   unde asculta SOCKS5   (implicit 127.0.0.1:9050)
  --guard ADRESA:PORT   primul hop            (obligatoriu)
  --middle ADRESA:PORT  al doilea hop         (optional)
  --exit ADRESA:PORT    ultimul hop           (obligatoriu)
  --hsdir ADRESE        HSDir-uri pentru .onion (lista separata prin virgula)
  --data-dir CALE       unde tine starea      (implicit ./date-client)
  --tls                 legaturi criptate cu TLS
                        (trebuie sa se potriveasca cu releele)
  --log NIVEL           error|warn|info       (implicit info)
  --help                acest mesaj

Foloseste 'curl --socks5-hostname', nu '--socks5': al doilea scurge DNS.
";

/// Deschide un circuit de un hop catre releul cu indexul de testnet dat.
/// Un circuit de trei hopuri care se termina la releul cu indexul dat.
///
/// Numele vechi era `circuit_direct` si facea exact ce spunea: conexiune directa.
/// Asta insemna ca punctul de rendezvous vedea adresa reala a clientului — vezi
/// nota de la [`pqo_bin::circuit_catre`].
async fn circuit_catre_releu(
    relee: &[SocketAddr],
    index: u8,
    sk: Arc<<S as Sig>::SecretKey>,
    pk: &[u8],
    tls: bool,
) -> std::io::Result<Circuit<Box<dyn Flux>>> {
    pqo_bin::circuit_catre::<K, S>(relee, index, sk, pk, transport(tls)).await
}

/// Transportul cerut, sau o eroare clara daca binarul nu a fost compilat cu el.
fn transport(tls: bool) -> TransportClient<'static> {
    if tls {
        #[cfg(feature = "tls")]
        {
            // Conectorul e acelasi pentru toate conexiunile; il construim o
            // singura data si il tinem cat traieste procesul.
            static CONECTOR: std::sync::OnceLock<pqo_relay_io::tls::Conector> =
                std::sync::OnceLock::new();
            return TransportClient::Tls(
                CONECTOR.get_or_init(pqo_relay_io::tls::connector),
            );
        }
        #[cfg(not(feature = "tls"))]
        {
            // Verificat la pornire; aici nu se mai ajunge.
            unreachable!("--tls fara feature-ul tls");
        }
    } else {
        TransportClient::Plaintext
    }
}

/// Ce ii trebuie clientului ca sa ajunga la un serviciu ascuns.
///
/// Grupate ca sa nu circule cinci parametri prin fiecare apel — si ca sa fie
/// evident ca sunt configuratie, nu stare.
struct ContextOnion {
    /// Unde se cauta descriptorii si unde stau punctele de introducere.
    hsdirs: Vec<SocketAddr>,
    /// Releul ales ca punct de rendezvous.
    rp_addr: SocketAddr,
    rp_index: u8,
    sk: Arc<<S as Sig>::SecretKey>,
    pk: Vec<u8>,
    tls: bool,
}

/// Se conecteaza la un serviciu ascuns si intoarce tunelul deschis.
///
/// Traseul: descriptor de la HSDir, rendezvous la un releu, introducere prin
/// punctul anuntat in descriptor, apoi hop virtual.
async fn conecteaza_onion(
    adresa: &str,
    ctx: &ContextOnion,
    nivel: Level,
) -> std::io::Result<Tunnel<Box<dyn Flux>>> {
    let ContextOnion {
        hsdirs,
        rp_addr,
        rp_index,
        sk,
        pk,
        tls,
    } = ctx;
    let tls = *tls;
    let (rp_addr, rp_index) = (*rp_addr, *rp_index);
    let mut rng = rand_core::OsRng;
    let addr = OnionAddress::parse(adresa)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;

    // --- Descriptorul ---
    let acum = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let fps: Vec<[u8; 32]> = (0..hsdirs.len() as u8)
        .map(|i| pqo_bin::testnet_relay_public::<K, S>(i).id)
        .collect();

    let mut doc = None;
    'cautare: for (bid, noduri) in fetch_targets(&addr, acum, &fps, &[0x5A; 32]) {
        for fp in &noduri {
            let Some(i) = fps.iter().position(|f| f == fp) else {
                continue;
            };
            let Ok(mut c) = circuit_catre_releu(hsdirs, i as u8, Arc::clone(sk), pk, tls).await else {
                continue;
            };
            if let Ok(r) = c.dir_request(DirRequest::HsFetch(bid)).await {
                if r.status == DirStatus::Ok {
                    doc = Some(r.body);
                    break 'cautare;
                }
            }
        }
    }
    let doc = String::from_utf8(
        doc.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "descriptor negasit"))?,
    )
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "descriptor"))?;

    // Verificarea completa: semnatura stratului exterior, apoi ca hash-ul cheii
    // master e chiar adresa ceruta.
    let d = Descriptor::parse_and_verify::<pqo_crypto::Ed25519>(&doc)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let inner = d
        .open_inner::<pqo_crypto::Ed25519>(&addr)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let ip = inner
        .intro_points
        .first()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "fara puncte"))?;
    log(Level::Info, nivel, "descriptor gasit si verificat");

    // --- Rendezvous ---
    let cookie = new_cookie(&mut rng);
    // Circuit de trei hopuri catre punctul de rendezvous. `rp_addr` ramane in
    // payload-ul INTRODUCE, ca serviciul sa stie unde sa vina.
    let mut cli_rp = circuit_catre_releu(hsdirs, rp_index, Arc::clone(sk), pk, tls).await?;
    cli_rp.establish_rendezvous(&cookie).await?;

    // --- Introducere ---
    let ip_index = pqo_bin::testnet_index_by_id::<K, S>(&ip.relay_id).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "punct de introducere necunoscut")
    })?;

    // Serviciul e in rol de releu pe hop-ul virtual, deci construim handshake-ul
    // catre cheile lui anuntate in descriptor.
    // Cheia de handshake a serviciului, nu cea de criptare a introducerii.
    let serviciu = pqo_crypto::RelayPublic {
        id: *addr.id(),
        x25519: ip.svc_x25519,
        static_kem_ek: None,
    };
    let (state, hs_client) = pqo_crypto::client_init::<K>(&serviciu, Variant::Transitional, &mut rng)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let payload = IntroPayload {
        cookie,
        rp_relay_id: pqo_bin::testnet_relay_public::<K, S>(rp_index).id,
        rp_address: rp_addr.ip().to_string(),
        rp_port: rp_addr.port(),
        handshake: hs_client,
    };
    let intro = Introduce::seal::<K>(ip, &payload, &mut rng)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let mut corp = auth_key_id(&ip.auth_key).to_vec();
    corp.extend_from_slice(&intro.encode());

    let mut cli_ip = circuit_catre_releu(hsdirs, ip_index, Arc::clone(sk), pk, tls).await?;
    cli_ip.send_introduce(corp).await?;

    // --- Finalizare ---
    let r2 = cli_rp.wait_rendezvous2().await?;
    let res = pqo_crypto::client_finish::<K>(state, &r2)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    log(Level::Info, nivel, "rendezvous reusit");

    Ok(Tunnel::client(cli_rp, &res.key_seed))
}

/// Muta octeti intre o conexiune locala si un tunel de serviciu ascuns.
async fn pompeaza_tunel(
    mut tun: Tunnel<Box<dyn Flux>>,
    sock: tokio::net::TcpStream,
    stream: StreamId,
) {
    let (mut r, mut w) = sock.into_split();
    let mut buf = vec![0u8; pqo_wire::RELAY_DATA_LEN];
    loop {
        tokio::select! {
            n = r.read(&mut buf) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let Ok(m) = RelayMessage::new(RelayCmd::Data, stream, buf[..n].to_vec()) else {
                        break;
                    };
                    if tun.send(&m).await.is_err() { break; }
                }
            },
            m = tun.recv() => match m {
                Ok(m) if m.cmd == RelayCmd::Data => {
                    if w.write_all(&m.body).await.is_err() { break; }
                }
                Ok(m) if m.cmd == RelayCmd::End => break,
                Ok(_) => {}
                Err(_) => break,
            },
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = ruleaza().await {
        eprintln!("[EROARE] {e}");
        std::process::exit(1);
    }
}

async fn ruleaza() -> Result<(), SetupError> {
    let args = Args::parse(std::env::args().skip(1))?;
    if args.has("help") {
        print!("{AJUTOR}");
        return Ok(());
    }
    // O optiune scrisa gresit opreste pornirea. Alternativa — sa o ignoram —
    // inseamna un proces care pare ca merge dar nu face ce i s-a cerut.
    args.verifica(&["socks","guard","middle","exit","hsdir","data-dir","log","help","tls"])?;

    let nivel = clamp_level(
        Level::parse(&args.get_or("log", "info"))
            .ok_or_else(|| SetupError::BadArgument("--log".into()))?,
    );
    let socks_addr: SocketAddr = args
        .get_or("socks", "127.0.0.1:9050")
        .parse()
        .map_err(|_| SetupError::BadArgument("--socks".into()))?;

    let foloseste_tls = args.has("tls");
    if foloseste_tls && !cfg!(feature = "tls") {
        return Err(SetupError::BadArgument(
            "--tls cere un build cu --features tls".into(),
        ));
    }

    let mut cale: Vec<SocketAddr> = Vec::new();
    for nume in ["guard", "middle", "exit"] {
        if let Some(v) = args.get(nume) {
            cale.push(
                v.parse()
                    .map_err(|_| SetupError::BadArgument(format!("--{nume} {v}")))?,
            );
        }
    }
    if cale.len() < 2 {
        return Err(SetupError::BadArgument(
            "sunt necesare cel putin --guard si --exit".into(),
        ));
    }

    let data_dir = std::path::PathBuf::from(args.get_or("data-dir", "./date-client"));
    let seed = load_or_create_seed(&data_dir.join("client.key"))?;
    let mut rng = ShakeRng::new(b"pqonion-client-identity-v1", &[&seed]);
    let (id_sk, id_pk) = S::keygen(&mut rng);
    let id_sk = Arc::new(id_sk);

    // HSDir-urile pentru adresele .onion. Fara ele, cererile .onion se refuza.
    let hsdirs: Vec<SocketAddr> = args
        .get_or("hsdir", "")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.trim()
                .parse()
                .map_err(|_| SetupError::BadArgument(format!("--hsdir {s}")))
        })
        .collect::<Result<_, _>>()?;

    let listener = tokio::net::TcpListener::bind(socks_addr)
        .await
        .map_err(SetupError::Io)?;
    log(
        Level::Info,
        nivel,
        &format!("SOCKS5 pe {}", listener.local_addr().map_err(SetupError::Io)?),
    );
    log(
        Level::Info,
        nivel,
        &format!("cale de {} hop-uri", cale.len()),
    );
    if !cfg!(feature = "pq") {
        log(
            Level::Warn,
            nivel,
            "compilat FARA feature-ul 'pq': criptografia NU e post-cuantica",
        );
    }
    log(
        Level::Warn,
        nivel,
        "foloseste 'curl --socks5-hostname'; '--socks5' scurge DNS",
    );

    let stats = Arc::new(socks::SocksStats::default());

    loop {
        let (mut sock, _) = tokio::select! {
            r = listener.accept() => r.map_err(SetupError::Io)?,
            _ = tokio::signal::ctrl_c() => {
                log(Level::Info, nivel, "oprire");
                return Ok(());
            }
        };

        let cale = cale.clone();
        let hsdirs = hsdirs.clone();
        let id_sk = Arc::clone(&id_sk);
        let id_pk = id_pk.clone();
        let stats = Arc::clone(&stats);

        // Cate un circuit nou per conexiune. Un client real ar refolosi
        // circuitele o vreme; aici prioritatea e claritatea.
        tokio::spawn(async move {
            let cerere = match socks::handshake(&mut sock, &stats).await {
                Ok(c) => c,
                Err(_) => return,
            };
            if cerere.was_ip_literal {
                log(
                    Level::Warn,
                    nivel,
                    "cerere cu adresa IP: aplicatia a rezolvat numele local si a scurs DNS",
                );
            }

            // Adresele .onion nu ies prin releul de iesire: se rezolva prin
            // rendezvous cu serviciul.
            if cerere.address.ends_with(".onion") {
                if hsdirs.is_empty() {
                    log(Level::Warn, nivel, "cerere .onion dar --hsdir lipseste");
                    let _ = socks::send_reply(&mut sock, socks::reply::NOT_ALLOWED).await;
                    return;
                }
                let ctx = ContextOnion {
                    hsdirs: hsdirs.clone(),
                    rp_addr: *cale.last().expect("cale nevida"),
                    rp_index: (cale.len() - 1) as u8,
                    sk: Arc::clone(&id_sk),
                    pk: id_pk.clone(),
                    tls: foloseste_tls,
                };
                let mut tun = match conecteaza_onion(&cerere.address, &ctx, nivel).await {
                    Ok(t) => t,
                    Err(e) => {
                        log(Level::Warn, nivel, &format!("conectare .onion esuata: {e}"));
                        let _ = socks::send_reply(&mut sock, socks::reply::HOST_UNREACHABLE).await;
                        return;
                    }
                };

                // Adresa din BEGIN e ignorata de serviciu: el expune ce vrea.
                let stream = StreamId(1);
                let begin = pqo_wire::stream::Begin {
                    address: "onion".into(),
                    port: cerere.port,
                }
                .encode()
                .expect("adresa valida");
                if tun
                    .send(&RelayMessage::new(RelayCmd::Begin, stream, begin).unwrap())
                    .await
                    .is_err()
                {
                    let _ = socks::send_reply(&mut sock, socks::reply::GENERAL_FAILURE).await;
                    return;
                }
                match tun.recv().await {
                    Ok(m) if m.cmd == RelayCmd::Connected => {}
                    _ => {
                        let _ = socks::send_reply(&mut sock, socks::reply::CONNECTION_REFUSED).await;
                        return;
                    }
                }
                if socks::send_reply(&mut sock, socks::reply::SUCCESS)
                    .await
                    .is_err()
                {
                    return;
                }
                pompeaza_tunel(tun, sock, stream).await;
                return;
            }

            let publice: Vec<RelayPublic> = (0..cale.len() as u8)
                .map(pqo_bin::testnet_relay_public::<K, S>)
                .collect();
            let mut circ = match Circuit::connect_dyn::<K, S>(
                cale[0],
                &publice[0],
                Variant::Transitional,
                id_sk,
                &id_pk,
                transport(foloseste_tls),
            )
            .await
            {
                Ok(c) => c,
                Err(_) => {
                    let _ = socks::send_reply(&mut sock, socks::reply::HOST_UNREACHABLE).await;
                    return;
                }
            };
            for (i, a) in cale.iter().enumerate().skip(1) {
                let o = a.ip().to_string();
                let octeti: Vec<u8> = o.split('.').filter_map(|x| x.parse().ok()).collect();
                if octeti.len() != 4 {
                    let _ = socks::send_reply(&mut sock, socks::reply::GENERAL_FAILURE).await;
                    return;
                }
                if circ
                    .extend::<K>(
                        &publice[i],
                        [octeti[0], octeti[1], octeti[2], octeti[3]],
                        a.port(),
                        Variant::Transitional,
                    )
                    .await
                    .is_err()
                {
                    let _ = socks::send_reply(&mut sock, socks::reply::HOST_UNREACHABLE).await;
                    return;
                }
            }

            let id = match circ.begin(&cerere.address, cerere.port).await {
                Ok(i) => i,
                Err(e) => {
                    let cod = match e.kind() {
                        std::io::ErrorKind::ConnectionRefused => socks::reply::CONNECTION_REFUSED,
                        std::io::ErrorKind::TimedOut => socks::reply::HOST_UNREACHABLE,
                        _ => socks::reply::NOT_ALLOWED,
                    };
                    let _ = socks::send_reply(&mut sock, cod).await;
                    return;
                }
            };
            if socks::send_reply(&mut sock, socks::reply::SUCCESS)
                .await
                .is_err()
            {
                return;
            }

            // Pompam in ambele sensuri pana cand unul dintre capete se inchide.
            let (mut r, mut w) = sock.into_split();
            let mut buf = vec![0u8; pqo_wire::RELAY_DATA_LEN];
            loop {
                tokio::select! {
                    n = r.read(&mut buf) => match n {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if circ.write_stream(id, &buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    },
                    d = circ.read_stream(id) => match d {
                        Ok(Some(d)) => {
                            if w.write_all(&d).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    },
                }
            }
            let _ = circ.close_stream(id).await;
        });
    }
}
