//! Serviciul ascuns, ca proces.
//!
//! ```text
//! pqonion-hs --data-dir ./date-hs --hsdir 127.0.0.1:9001 --target 127.0.0.1:8080
//! ```
//!
//! Afiseaza adresa `.onion` la pornire si publica descriptorul la HSDir-urile
//! date. Adresa se pastreaza intre porniri: se deriva din samanta salvata pe disc.
//!
//! # Ce face si ce nu face
//!
//! Publica descriptorul si serveste ca demonstratie a lantului complet: adresa
//! derivata prin hash, descriptor in doua straturi, publicare prin circuit.
//!
//! Publica descriptorul, deschide puncte de introducere si serveste conexiuni.
//!
//! # Ce face cu BEGIN
//!
//! Adresa ceruta de client se **ignora**: serviciul se conecteaza intotdeauna la
//! `--target`. Asa functioneaza si Tor — un serviciu ascuns expune ce vrea el,
//! nu ce cere clientul. Daca am onora adresa, serviciul ar deveni un proxy
//! deschis pentru oricine ii stie adresa `.onion`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use pqo_bin::{clamp_level, load_or_create_seed, log, Args, Level, SetupError};
use pqo_crypto::kdf::ShakeRng;
use pqo_crypto::sig::Sig;
use pqo_crypto::{RelayKeys, Variant};
use pqo_dirproto::dirreq::{DirRequest, DirStatus};
use pqo_hs::desc::IntroPoint;
use pqo_hs::publish::{PublishPlan, ServiceKeys};
use pqo_crypto::kem::Kem;
use pqo_hs::rend::Introduce;
use pqo_relay_io::client::{Circuit, Flux, TransportClient};
use pqo_relay_io::tunnel::Tunnel;
use pqo_wire::{RelayCmd, RelayMessage, StreamId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "pq")]
type K = pqo_crypto::Hybrid<pqo_crypto::X25519Kem, pqo_crypto::MlKem768>;
#[cfg(not(feature = "pq"))]
type K = pqo_crypto::Hybrid<pqo_crypto::X25519Kem, pqo_crypto::X25519Kem>;

// Descriptorii de servicii ascunse sunt semnati cu Ed25519 si in build cu `pq`:
// `SharedDescStore` valideaza cu schema asta, deci trebuie sa coincida.
type S = pqo_crypto::Ed25519;

#[cfg(feature = "pq")]
type SLink = pqo_crypto::HybridSig<pqo_crypto::Ed25519, pqo_crypto::MlDsa44>;
#[cfg(not(feature = "pq"))]
type SLink = pqo_crypto::Ed25519;

const AJUTOR: &str = "\
pqonion-hs — serviciu ascuns

  --data-dir CALE        unde tine samanta      (implicit ./date-hs)
  --hsdir ADRESA:PORT    HSDir unde publica     (se poate repeta prin virgula)
  --target ADRESA:PORT   ce serviciu expune     (implicit 127.0.0.1:8080)
  --adresa-doar          afiseaza adresa si iese
  --tls                  legaturi criptate cu TLS
                         (trebuie sa se potriveasca cu releele)
  --log NIVEL            error|warn|info        (implicit info)
  --help                 acest mesaj
";

/// Transportul cerut. Trebuie sa se potriveasca cu ce vorbesc releele.
fn transport(tls: bool) -> TransportClient<'static> {
    if tls {
        #[cfg(feature = "tls")]
        {
            static CONECTOR: std::sync::OnceLock<pqo_relay_io::tls::Conector> =
                std::sync::OnceLock::new();
            return TransportClient::Tls(CONECTOR.get_or_init(pqo_relay_io::tls::connector));
        }
        #[cfg(not(feature = "tls"))]
        {
            unreachable!("--tls fara feature-ul tls");
        }
    } else {
        TransportClient::Plaintext
    }
}

/// Cheile pe care un serviciu le foloseste la un punct de introducere.
///
/// Toate se deriva din samanta, deci supravietuiesc repornirii — altfel
/// descriptorul publicat ar deveni invalid dupa fiecare restart.
struct CheiIntro {
    /// Cheia de autentificare fata de punctul de introducere.
    auth_sk: <SLink as Sig>::SecretKey,
    auth_pk: Vec<u8>,
    /// Cheia catre care clientul cripteaza corpul INTRODUCE1.
    intro_dk: <K as Kem>::DecapKey,
    intro_ek: Vec<u8>,
}

fn chei_intro(seed: &[u8; 32], index: u8) -> CheiIntro {
    let mut r1 = ShakeRng::new(b"pqonion-hs-introauth-v1", &[seed, &[index]]);
    let (auth_sk, auth_pk) = SLink::keygen(&mut r1);
    let mut r2 = ShakeRng::new(b"pqonion-hs-introenc-v1", &[seed, &[index]]);
    let (intro_dk, intro_ek) = K::keygen(&mut r2);
    CheiIntro {
        auth_sk,
        auth_pk,
        intro_dk,
        intro_ek,
    }
}

/// Cheile de handshake ale serviciului pentru hop-ul virtual.
///
/// Serviciul e in rol de **releu** pe hop-ul virtual, deci foloseste `RelayKeys`.
/// Vezi asimetria CGO.
fn chei_handshake(seed: &[u8; 32], addr_id: &[u8; 32]) -> RelayKeys<K> {
    let mut rng = ShakeRng::new(b"pqonion-hs-handshake-v1", &[seed]);
    RelayKeys::<K>::generate(*addr_id, Variant::Transitional, &mut rng)
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
    args.verifica(&["data-dir","hsdir","target","adresa-doar","log","help","tls"])?;

    let nivel = clamp_level(
        Level::parse(&args.get_or("log", "info"))
            .ok_or_else(|| SetupError::BadArgument("--log".into()))?,
    );
    let data_dir = PathBuf::from(args.get_or("data-dir", "./date-hs"));
    let tls = args.has("tls");
    if tls && !cfg!(feature = "tls") {
        return Err(SetupError::BadArgument(
            "--tls cere un build cu --features tls".into(),
        ));
    }

    // Adresa se deriva din samanta, deci supravietuieste repornirii. Un serviciu
    // care si-ar schimba adresa la fiecare pornire ar fi inutilizabil: nimeni nu
    // ar putea sa il gaseasca de doua ori.
    let seed = load_or_create_seed(&data_dir.join("serviciu.key"))?;
    let keys = ServiceKeys::from_seed::<S>(seed);

    println!("{}", keys.address());
    if args.has("adresa-doar") {
        return Ok(());
    }

    log(
        Level::Info,
        nivel,
        &format!("serviciu ascuns, adresa {}", keys.address()),
    );
    if let Some(t) = args.get("target") {
        log(Level::Info, nivel, &format!("expune {t}"));
    }


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

    if hsdirs.is_empty() {
        log(Level::Warn, nivel, "niciun HSDir dat: nu se publica nimic");
        return Ok(());
    }

    // Cate un set de chei per punct de introducere. Cheile de criptare sunt ale
    // **serviciului**, nu ale releului: clientul incapsuleaza catre ele, iar
    // punctul de introducere retransmite fara sa poata citi.
    let n_intro = hsdirs.len().min(3);
    let chei: Vec<CheiIntro> = (0..n_intro as u8).map(|i| chei_intro(&seed, i)).collect();

    // Cheia cu care serviciul raspunde la handshake-ul de rendezvous. Una
    // singura pentru toate punctele de introducere; se deriva din samanta, deci
    // supravietuieste repornirii.
    let handshake_keys = Arc::new(chei_handshake(&seed, keys.address().id()));
    let svc_x25519 = handshake_keys.public().x25519;

    let intro: Vec<IntroPoint> = (0..n_intro)
        .map(|i| {
            let releu = pqo_bin::testnet_relay_public::<K, SLink>(i as u8);
            IntroPoint {
                relay_id: releu.id,
                onion_x25519: chei[i].intro_ek[..32].try_into().expect("lungime fixa"),
                onion_kem: Some(chei[i].intro_ek[32..].to_vec()),
                svc_x25519,
                auth_key: chei[i].auth_pk.clone(),
            }
        })
        .collect();

    let acum = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let fps: Vec<[u8; 32]> = (0..hsdirs.len() as u8)
        .map(|i| pqo_bin::testnet_relay_public::<K, SLink>(i).id)
        .collect();
    let plan = PublishPlan::build::<S>(&keys, acum, 1, &intro, &fps, &[0x5A; 32])
        .map_err(|e| SetupError::BadArgument(e.to_string()))?;

    log(
        Level::Info,
        nivel,
        &format!(
            "publicare pentru {} perioade, {} incarcari",
            plan.targets.len(),
            plan.upload_count()
        ),
    );

    let (cli_sk, cli_pk) = SLink::keygen(&mut rand_core::OsRng);
    let cli_sk = Arc::new(cli_sk);
    let mut reusite = 0;

    for t in &plan.targets {
        for fp in &t.nodes {
            let Some(i) = fps.iter().position(|f| f == fp) else {
                continue;
            };
            let public = pqo_bin::testnet_relay_public::<K, SLink>(i as u8);
            // Publicarea merge prin circuit: HSDir-ul vede descriptorul, dar nu
            // si de unde vine.
            let mut c = match Circuit::connect_dyn::<K, SLink>(
                hsdirs[i],
                &public,
                Variant::Transitional,
                Arc::clone(&cli_sk),
                &cli_pk,
                transport(tls),
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    log(
                        Level::Warn,
                        nivel,
                        &format!("nu m-am putut conecta la HSDir {}: {e}", hsdirs[i]),
                    );
                    continue;
                }
            };
            match c
                .dir_publish(DirRequest::HsUpload(t.document.as_bytes().to_vec()))
                .await
            {
                Ok(DirStatus::Ok) => reusite += 1,
                Ok(st) => log(
                    Level::Warn,
                    nivel,
                    &format!("HSDir {} a refuzat: {st:?}", hsdirs[i]),
                ),
                Err(e) => log(Level::Warn, nivel, &format!("publicare esuata: {e}")),
            }
        }
    }

    log(
        Level::Info,
        nivel,
        &format!("{reusite} incarcari reusite din {}", plan.upload_count()),
    );
    if reusite == 0 {
        return Err(SetupError::BadArgument(
            "nicio publicare nu a reusit".into(),
        ));
    }

    // --- Punctele de introducere ---
    let target: SocketAddr = args
        .get_or("target", "127.0.0.1:8080")
        .parse()
        .map_err(|_| SetupError::BadArgument("--target".into()))?;

    let chei = Arc::new(chei);

    for (i, _ip) in intro.iter().enumerate() {
        let adresa = hsdirs[i];
        let chei = Arc::clone(&chei);
        let hk = Arc::clone(&handshake_keys);
        // Toata lista, ca bucla sa poata construi cai de trei hopuri.
        let relee = hsdirs.clone();
        tokio::spawn(async move {
            if let Err(e) = bucla_intro(
                ConfigIntro {
                    index: i,
                    adresa,
                    relee: relee.clone(),
                    chei,
                    handshake_keys: hk,
                    target,
                    tls,
                },
                nivel,
            ).await {
                log(
                    Level::Warn,
                    nivel,
                    &format!("punctul de introducere {adresa} s-a inchis: {e}"),
                );
            }
        });
    }
    log(
        Level::Info,
        nivel,
        &format!(
            "{} puncte de introducere deschise; expun {target}",
            intro.len()
        ),
    );
    log(Level::Info, nivel, "gata; Ctrl-C ca sa opresc");

    tokio::signal::ctrl_c().await.map_err(SetupError::Io)?;
    Ok(())
}

/// Tine un circuit catre un punct de introducere si trateaza cererile.
/// Ce ii trebuie unei bucle de punct de introducere.
struct ConfigIntro {
    index: usize,
    adresa: SocketAddr,
    /// Toate releele cunoscute, ca sa putem construi o cale.
    relee: Vec<SocketAddr>,
    chei: Arc<Vec<CheiIntro>>,
    handshake_keys: Arc<RelayKeys<K>>,
    target: SocketAddr,
    tls: bool,
}

async fn bucla_intro(cfg: ConfigIntro, nivel: Level) -> std::io::Result<()> {
    let ConfigIntro {
        index,
        adresa,
        relee,
        chei,
        handshake_keys,
        target,
        tls,
    } = cfg;
    let (sk, pk) = SLink::keygen(&mut rand_core::OsRng);
    let sk = Arc::new(sk);

    // Circuit de trei hopuri **catre** punctul de introducere, nu conexiune
    // directa: altfel releul de la capat vede adresa reala a serviciului.
    let mut c = pqo_bin::circuit_catre::<K, SLink>(
        &relee,
        index as u8,
        Arc::clone(&sk),
        &pk,
        transport(tls),
    )
    .await?;
    let _ = adresa;
    c.establish_intro::<SLink>(&chei[index].auth_sk, &chei[index].auth_pk)
        .await?;
    log(
        Level::Info,
        nivel,
        &format!("punct de introducere activ la {adresa}"),
    );

    loop {
        let corp = c.wait_introduce2().await?;
        if corp.len() <= 32 {
            continue;
        }
        let Ok(intro) = Introduce::parse(&corp[32..]) else {
            continue;
        };
        let Ok(payload) = intro.open::<K>(&chei[index].intro_dk) else {
            // Un corp pe care nu il putem deschide inseamna ca cineva a trimis
            // gunoi, sau ca punctul de introducere a fost preluat. In ambele
            // cazuri il ignoram si asteptam mai departe.
            continue;
        };

        let hk = Arc::clone(&handshake_keys);
        let sk = Arc::clone(&sk);
        let pk = pk.clone();
        let relee = relee.clone();
        tokio::spawn(async move {
            let _ = deserveste(
                payload,
                ConfigDeservire {
                    handshake_keys: hk,
                    sk,
                    pk,
                    target,
                    tls,
                    relee,
                },
                nivel,
            ).await;
        });
    }
}

/// Raspunde unei cereri de introducere: rendezvous, apoi proxy catre tinta.
/// Ce ii trebuie unei cereri de introducere ca sa fie deservita.
struct ConfigDeservire {
    handshake_keys: Arc<RelayKeys<K>>,
    sk: Arc<<SLink as Sig>::SecretKey>,
    pk: Vec<u8>,
    target: SocketAddr,
    tls: bool,
    relee: Vec<SocketAddr>,
}

async fn deserveste(
    payload: pqo_hs::rend::IntroPayload,
    cfg: ConfigDeservire,
    nivel: Level,
) -> std::io::Result<()> {
    let ConfigDeservire {
        handshake_keys,
        sk,
        pk,
        target,
        tls,
        relee,
    } = cfg;
    let mut rng = rand_core::OsRng;
    let (hs_server, res) = pqo_crypto::server_respond::<K>(&handshake_keys, &payload.handshake, &mut rng)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    // Clientul ne-a spus unde e punctul de rendezvous; il credem pe cuvant, dar
    // adresa e validata la parsare.
    let rp_addr: SocketAddr = format!("{}:{}", payload.rp_address, payload.rp_port)
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "adresa RP"))?;
    let rp_index = pqo_bin::testnet_index_by_id::<K, SLink>(&payload.rp_relay_id)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "RP necunoscut"))?;
    let _ = rp_addr;

    // Tot trei hopuri: punctul de rendezvous vede ultimul releu al caii, nu
    // serviciul.
    let mut c =
        pqo_bin::circuit_catre::<K, SLink>(&relee, rp_index, sk, &pk, transport(tls)).await?;
    c.send_rendezvous1(&payload.cookie, &hs_server).await?;

    let mut tun = Tunnel::service(c, &res.key_seed);
    log(Level::Info, nivel, "conexiune noua prin rendezvous");

    // Prima cerere trebuie sa fie BEGIN. Adresa se ignora: expunem `--target`,
    // nu ce cere clientul.
    let m = tun.recv().await?;
    if m.cmd != RelayCmd::Begin {
        return Ok(());
    }
    let stream = m.stream;

    let sock = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(target),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            let _ = tun
                .send(
                    &RelayMessage::new(
                        RelayCmd::End,
                        stream,
                        pqo_wire::stream::End {
                            reason: pqo_wire::stream::EndReason::ConnectRefused,
                        }
                        .encode(),
                    )
                    .unwrap(),
                )
                .await;
            return Ok(());
        }
    };

    tun.send(
        &RelayMessage::new(
            RelayCmd::Connected,
            stream,
            pqo_wire::stream::Connected {
                addr: [127, 0, 0, 1],
                ttl: 60,
            }
            .encode(),
        )
        .unwrap(),
    )
    .await?;

    pompeaza(tun, sock, stream).await
}

/// Muta octeti intre tunel si o conexiune TCP, pana cade unul dintre capete.
async fn pompeaza(
    mut tun: Tunnel<Box<dyn Flux>>,
    sock: tokio::net::TcpStream,
    stream: StreamId,
) -> std::io::Result<()> {
    let (mut r, mut w) = sock.into_split();
    let mut buf = vec![0u8; pqo_wire::RELAY_DATA_LEN];
    loop {
        tokio::select! {
            n = r.read(&mut buf) => match n {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let m = RelayMessage::new(RelayCmd::Data, stream, buf[..n].to_vec())
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
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
    Ok(())
}
