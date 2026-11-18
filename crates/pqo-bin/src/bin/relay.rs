//! Releul, ca proces.
//!
//! ```text
//! pqonion-relay --listen 0.0.0.0:9001 --data-dir ./date [--exit-ports 80,443]
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use pqo_bin::{clamp_level, load_or_create_seed, log, Args, Level, SetupError};
use pqo_crypto::kdf::ShakeRng;
use pqo_crypto::kem::Kem;
use pqo_crypto::sig::Sig;
use pqo_crypto::{ntor, RelayKeys, Variant};
use pqo_dirproto::dirreq::DirStore;
use pqo_relay::stream::ExitPolicy;
use pqo_relay_io::client::Circuit;
use pqo_relay_io::node::{spawn, NodeConfig};

#[cfg(feature = "pq")]
type K = pqo_crypto::Hybrid<pqo_crypto::X25519Kem, pqo_crypto::MlKem768>;
#[cfg(not(feature = "pq"))]
type K = pqo_crypto::Hybrid<pqo_crypto::X25519Kem, pqo_crypto::X25519Kem>;

#[cfg(feature = "pq")]
type S = pqo_crypto::HybridSig<pqo_crypto::Ed25519, pqo_crypto::MlDsa44>;
#[cfg(not(feature = "pq"))]
type S = pqo_crypto::Ed25519;

const AJUTOR: &str = "\
pqonion-relay — releu al retelei

  --listen ADRESA:PORT   unde asculta            (implicit 0.0.0.0:9001)
  --data-dir CALE        unde tine cheile        (implicit ./date-releu)
  --exit-ports 80,443    devine releu de iesire  (implicit: nu iese nimic)
  --permite-adrese-private   DOAR PENTRU TESTNET: permite iesire catre
                             localhost si retele private
  --adresa-publica IP    adresa pe care o publica in descriptor
                         (implicit: cea din --listen)
  --tls                  cripteaza legaturile cu TLS
                         (cere build cu --features tls)
  --hsdir                stocheaza descriptori de servicii ascunse
  --dirauth ADRESE       autoritati unde isi publica descriptorul
                         (lista separata prin virgula)
  --consola ADRESA:PORT  consola web, doar de citit
                         (implicit oprita; foloseste 127.0.0.1)
  --log NIVEL            error|warn|info         (implicit info)
  --help                 acest mesaj
";

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
    args.verifica(&["listen","data-dir","exit-ports","permite-adrese-private","hsdir","adresa-publica","dirauth","consola","log","help","tls"])?;

    let nivel = clamp_level(
        Level::parse(&args.get_or("log", "info"))
            .ok_or_else(|| SetupError::BadArgument("--log".into()))?,
    );
    let listen: std::net::SocketAddr = args
        .get_or("listen", "0.0.0.0:9001")
        .parse()
        .map_err(|_| SetupError::BadArgument("--listen".into()))?;
    let data_dir = PathBuf::from(args.get_or("data-dir", "./date-releu"));

    // Adresa pe care o publicam poate diferi de cea pe care ascultam. Un releu
    // care asculta pe 0.0.0.0 — in container, sau pe o masina cu mai multe
    // interfete — nu are cum sa deduca singur pe ce adresa il vad ceilalti.
    let adresa_publica: std::net::IpAddr = match args.get("adresa-publica") {
        Some(a) => a
            .parse()
            .map_err(|_| SetupError::BadArgument(format!("--adresa-publica {a}")))?,
        None => listen.ip(),
    };

    // Cheile se deriva determinist din samanta, deci identitatea releului
    // supravietuieste repornirilor. Fara asta, un releu ar aparea ca nod nou
    // dupa fiecare restart si nu ar acumula niciodata reputatie in consens.
    let seed = load_or_create_seed(&data_dir.join("identitate.key"))?;
    let mut rng_id = ShakeRng::new(b"pqonion-relay-identity-v1", &[&seed]);
    let (id_sk, id_pk) = S::keygen(&mut rng_id);
    let mut rng_circ = ShakeRng::new(b"pqonion-relay-onion-v1", &[&seed]);
    let circuit_keys = RelayKeys::<K>::generate(
        pqo_dirproto::netdoc::fingerprint(&id_pk),
        Variant::Transitional,
        &mut rng_circ,
    );
    let fp = circuit_keys.id;

    let porturi = args.ports("exit-ports")?;
    let privat = args.has("permite-adrese-private");
    let exit_policy = if porturi.is_empty() {
        ExitPolicy::reject_all()
    } else if privat {
        ExitPolicy::allow_ports(&porturi).allow_private_for_testing()
    } else {
        ExitPolicy::allow_ports(&porturi)
    };

    // Stocarea de servicii ascunse e optionala: un releu o activeaza explicit.
    let hs_store: Option<Arc<dyn pqo_dirproto::dirreq::HsDirStore>> = if args.has("hsdir") {
        Some(Arc::new(pqo_hs::hsdir::SharedDescStore::new()))
    } else {
        None
    };

    let metrici: Arc<pqo_relay_io::Metrici> = Arc::new(pqo_relay_io::Metrici::new());
    let circuit_public = circuit_keys.public();
    let id_sk_pub = Arc::new(id_sk);
    let id_pk_pub = id_pk.clone();

    // Transportul. Fara TLS, un observator vede antetele de celula si tiparele
    // de lungime — payload-ul ramane criptat cu CGO, dar metadatele nu.
    let transport = if args.has("tls") {
        #[cfg(feature = "tls")]
        {
            Arc::new(pqo_relay_io::node::Transport::Tls(Arc::new(
                pqo_relay_io::node::TlsTransport::nou().map_err(SetupError::Io)?,
            )))
        }
        #[cfg(not(feature = "tls"))]
        {
            return Err(SetupError::BadArgument(
                "--tls cere un build cu --features tls".into(),
            ));
        }
    } else {
        Arc::new(pqo_relay_io::node::Transport::Plaintext)
    };

    let handle = spawn::<K, S>(NodeConfig {
        circuit_keys,
        id_sk: Arc::clone(&id_sk_pub),
        id_pk,
        listen,
        exit_policy,
        dir_store: Arc::new(std::sync::Mutex::new(DirStore::new())),
        hs_store,
        metrici: Arc::clone(&metrici),
        transport,
    })
    .await
    .map_err(SetupError::Io)?;

    log(
        Level::Info,
        nivel,
        &format!("releu pornit pe {}", handle.addr()),
    );
    log(
        Level::Info,
        nivel,
        &format!(
            "fingerprint {}",
            pqo_dirproto::hex_encode(&fp)
        ),
    );
    log(
        Level::Info,
        nivel,
        &{
            let iesire = if porturi.is_empty() {
                "nu e releu de iesire".to_string()
            } else {
                format!("iesire pe porturile {porturi:?}")
            };
            format!(
                "handshake {} / semnatura {} / {iesire}",
                <K as Kem>::NAME,
                <S as Sig>::NAME
            )
        },
    );
    if args.has("hsdir") {
        log(Level::Info, nivel, "stocheaza descriptori de servicii ascunse");
    }
    if privat {
        log(
            Level::Warn,
            nivel,
            "iesire permisa catre adrese private: clientii pot atinge reteaua ta interna",
        );
    }
    if !args.has("tls") {
        log(
            Level::Warn,
            nivel,
            "fara TLS: un observator vede antetele de celula si tiparele de lungime",
        );
    }
    if !cfg!(feature = "pq") {
        log(
            Level::Warn,
            nivel,
            "compilat FARA feature-ul 'pq': criptografia NU e post-cuantica",
        );
    }
    let _ = ntor::ID_LEN;

    // --- Inregistrarea la autoritati ---
    let autoritati: Vec<std::net::SocketAddr> = args
        .get_or("dirauth", "")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.trim()
                .parse()
                .map_err(|_| SetupError::BadArgument(format!("--dirauth {s}")))
        })
        .collect::<Result<_, _>>()?;

    if adresa_publica.is_unspecified() && !autoritati.is_empty() {
        log(
            Level::Warn,
            nivel,
            "publici adresa 0.0.0.0: nimeni nu te va putea contacta. \
             Foloseste --adresa-publica cu adresa pe care te vad ceilalti",
        );
    }
    if autoritati.is_empty() {
        log(
            Level::Warn,
            nivel,
            "fara --dirauth: releul nu apare in consens si clientii nu il vor alege",
        );
    } else {
        let public = circuit_public.clone();
        let id_sk2 = Arc::clone(&id_sk_pub);
        let id_pk2 = id_pk_pub.clone();
        let porturi2 = porturi.clone();
        tokio::spawn(async move {
            bucla_publicare(
                ConfigPublicare {
                    autoritati,
                    public,
                    id_sk: id_sk2,
                    id_pk: id_pk2,
                    adresa_publica,
                    or_port: listen.port(),
                    exit_ports: porturi2,
                },
                nivel,
            )
            .await;
        });
    }

    // --- Consola web ---
    if let Some(c) = args.get("consola") {
        let addr: std::net::SocketAddr = c
            .parse()
            .map_err(|_| SetupError::BadArgument("--consola".into()))?;
        if !addr.ip().is_loopback() {
            log(
                Level::Warn,
                nivel,
                "consola e legata pe o adresa publica si NU are autentificare: \
                 oricine poate vedea cat trafic duce releul",
            );
        }
        let id = pqo_bin::consola::Identitate {
            fingerprint: pqo_dirproto::hex_encode(&fp),
            adresa: handle.addr().to_string(),
            e_exit: !porturi.is_empty(),
            e_hsdir: args.has("hsdir"),
            post_cuantic: cfg!(feature = "pq"),
            schema_kem: <K as Kem>::NAME,
            schema_sig: <S as Sig>::NAME,
        };
        match pqo_bin::consola::porneste(addr, id, Arc::clone(&metrici)).await {
            Ok(a) => log(Level::Info, nivel, &format!("consola pe http://{a}/")),
            Err(e) => log(Level::Warn, nivel, &format!("consola nu a pornit: {e}")),
        }
    }

    // Marcaj de final al pornirii.
    //
    // Portul se leaga in `spawn`, deci un test care asteapta doar sa se poata
    // conecta poate ajunge sa citeasca log-urile la jumatate. Linia asta spune
    // ca tot ce trebuia scris la pornire s-a scris.
    log(Level::Info, nivel, "gata");

    tokio::signal::ctrl_c().await.map_err(SetupError::Io)?;
    log(Level::Info, nivel, "oprire");
    handle.shutdown();
    Ok(())
}

/// Cat de des isi republica un releu descriptorul.
///
/// Trebuie sa fie mai scurt decat perioada de valabilitate a consensului, altfel
/// releul dispare din el intre doua publicari.
const INTERVAL_PUBLICARE: u64 = 300;

/// Cat asteptam dupa o publicare complet esuata, inainte de prima reincercare.
///
/// Cazul obisnuit: releul porneste inaintea autoritatii. Cu intervalul normal,
/// releul ar lipsi din consens cinci minute dintr-un motiv care se rezolva in
/// cateva secunde.
const INTERVAL_REINCERCARE: u64 = 5;

/// Ce ii trebuie unui releu ca sa se anunte.
struct ConfigPublicare {
    autoritati: Vec<std::net::SocketAddr>,
    public: pqo_crypto::RelayPublic,
    id_sk: Arc<<S as Sig>::SecretKey>,
    id_pk: Vec<u8>,
    /// Adresa anuntata in descriptor, nu neaparat cea pe care ascultam.
    adresa_publica: std::net::IpAddr,
    or_port: u16,
    exit_ports: Vec<u16>,
}

/// Publica periodic descriptorul la autoritati.
///
/// Republicarea nu e optionala: o autoritate care reporneste isi pierde
/// descriptorii, iar un releu care nu revine ar disparea din consens fara sa fi
/// pierdut conexiunea.
async fn bucla_publicare(cfg: ConfigPublicare, nivel: Level) {
    let ConfigPublicare {
        autoritati,
        public,
        id_sk,
        id_pk,
        adresa_publica,
        or_port,
        exit_ports,
    } = cfg;
    // Ultimul rezultat raportat. Republicarea reuseste de obicei de fiecare
    // data, iar o linie la fiecare cinci minute ineaca log-ul si ascunde exact
    // ce ar trebui sa se vada: momentul in care ceva se strica.
    let mut ultim: Option<usize> = None;
    let mut asteptare_esec = INTERVAL_REINCERCARE;

    loop {
        let acum = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let d = pqo_dirproto::netdoc::RelayDescriptor {
            identity: id_pk.clone(),
            onion_x25519: public.x25519,
            onion_kem: public.static_kem_ek.clone(),
            address: adresa_publica.to_string(),
            or_port,
            // Banda auto-raportata: autoritatea o plafoneaza, dar nu o verifica.
            // Vezi limitarea documentata in `pqo-dirauth`.
            bandwidth: 1_000_000,
            exit_ports: exit_ports.clone(),
            published: acum,
        };
        let doc = d.sign::<S>(&id_sk);

        let mut reusite = 0;
        for a in &autoritati {
            // Publicarea merge printr-un circuit de un hop catre autoritate.
            // Nu e anonima si nici nu trebuie sa fie: releul se anunta pe sine.
            match Circuit::connect::<K, S>(
                *a,
                // Autoritatea isi deriva cheile de circuit din aceeasi samanta
                // ca identitatea; clientul nu le stie dinainte, deci in testnet
                // le reconstruim din indexul ei.
                &public_autoritate(*a, &autoritati),
                Variant::Transitional,
                Arc::clone(&id_sk),
                &id_pk,
            )
            .await
            {
                Ok(mut c) => {
                    match c
                        .dir_publish(pqo_dirproto::dirreq::DirRequest::Publish(
                            doc.as_bytes().to_vec(),
                        ))
                        .await
                    {
                        Ok(pqo_dirproto::dirreq::DirStatus::Ok) => reusite += 1,
                        Ok(st) => log(
                            Level::Warn,
                            nivel,
                            &format!("autoritatea {a} a refuzat descriptorul: {st:?}"),
                        ),
                        Err(e) => {
                            log(Level::Warn, nivel, &format!("publicare esuata la {a}: {e}"))
                        }
                    }
                }
                Err(e) => log(Level::Warn, nivel, &format!("nu ajung la {a}: {e}")),
            }
        }
        if ultim != Some(reusite) {
            let nivel_mesaj = if reusite == autoritati.len() {
                Level::Info
            } else {
                Level::Warn
            };
            log(
                nivel_mesaj,
                nivel,
                &format!("descriptor publicat la {reusite}/{} autoritati", autoritati.len()),
            );
            ultim = Some(reusite);
        }

        // Dupa un esec total reincercam repede, apoi tot mai rar, pana la
        // intervalul normal. Asa un releu pornit inaintea autoritatii intra in
        // consens in cateva secunde, nu in cinci minute — dar un releu care nu
        // ajunge deloc la autoritati nu o inunda cu incercari.
        let pauza = if reusite == 0 {
            let p = asteptare_esec.max(INTERVAL_REINCERCARE);
            asteptare_esec = (p * 2).min(INTERVAL_PUBLICARE);
            p
        } else {
            asteptare_esec = INTERVAL_REINCERCARE;
            INTERVAL_PUBLICARE
        };
        tokio::time::sleep(std::time::Duration::from_secs(pauza)).await;
    }
}

/// Cheile publice ale autoritatii de la pozitia data in lista.
fn public_autoritate(
    a: std::net::SocketAddr,
    toate: &[std::net::SocketAddr],
) -> pqo_crypto::RelayPublic {
    let index = toate.iter().position(|x| *x == a).unwrap_or(0);
    pqo_bin::testnet_authority_public::<K, S>(index as u8)
}
