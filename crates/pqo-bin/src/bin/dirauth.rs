//! Autoritatea de director, ca proces.
//!
//! ```text
//! pqonion-dirauth --data-dir ./date-aut --interval 3600
//! ```
//!
//! # Ce face
//!
//! Asculta, primeste descriptori publicati de relee, si la fiecare interval
//! construieste un vot din ei, calculeaza consensul si il semneaza. Consensul
//! ajunge si in magazinul propriu, deci clientii il pot descarca prin circuit.
//!
//! # Ce nu face
//!
//! **Schimbul de voturi intre autoritati nu e implementat pe retea.** Aici
//! consensul se calculeaza din propriul vot, ceea ce e corect pentru un testnet
//! cu o singura autoritate. Cu mai multe, fiecare ar produce un consens al ei si
//! niciunul n-ar atinge pragul de semnaturi.

use std::path::PathBuf;

use pqo_bin::{clamp_level, load_or_create_seed, log, Args, Level, SetupError};
use pqo_crypto::kdf::ShakeRng;
use pqo_crypto::sig::Sig;
use pqo_dirauth::{build_vote, compute_consensus};
use pqo_dirproto::dirreq::DirStore;
use pqo_dirproto::netdoc::Validity;
use pqo_relay::stream::ExitPolicy;
use pqo_relay_io::node::{spawn, NodeConfig};
use std::sync::Arc;

#[cfg(feature = "pq")]
type K = pqo_crypto::Hybrid<pqo_crypto::X25519Kem, pqo_crypto::MlKem768>;
#[cfg(not(feature = "pq"))]
type K = pqo_crypto::Hybrid<pqo_crypto::X25519Kem, pqo_crypto::X25519Kem>;

/// Schema cu care autoritatea **semneaza consensul**.
///
/// ML-DSA-65: consensul se semneaza o data pe ora si se descarca de toti
/// clientii, deci marja de securitate conteaza mai mult decat dimensiunea.
/// Autoritatea alege liber, pentru ca ea e singura care semneaza cu ea.
#[cfg(feature = "pq")]
type SConsens = pqo_crypto::HybridSig<pqo_crypto::Ed25519, pqo_crypto::MlDsa65>;
/// Fara `pq`, tot o schema **distincta** de cea a releelor.
///
/// Nu `Ed25519` pur: daca ambele tipuri ar fi identice in build-ul de test,
/// distinctia dintre ele ar disparea si nicio nepotrivire de scheme n-ar putea
/// fi prinsa fara ML-KEM. Exact asta s-a intamplat: doua erori au trecut de
/// suita de teste si s-au vazut abia in build-ul cu `pq`.
///
/// Build-ul fara `pq` trebuie sa pastreze **forma** celui cu `pq`, nu doar sa
/// compileze.
#[cfg(not(feature = "pq"))]
type SConsens = pqo_crypto::HybridSig<pqo_crypto::Ed25519, pqo_crypto::Ed25519>;

/// Schema **de identitate a releelor**.
///
/// Un releu are o singura identitate, si o foloseste in doua locuri: la
/// handshake-ul de legatura, si ca sa isi semneze descriptorul. Autoritatea are
/// nevoie de ea in ambele — ca sa vorbeasca cu releele, si ca sa le verifice
/// descriptorii inainte de a-i pune in vot.
///
/// **Nu e o alegere libera**, spre deosebire de [`SConsens`]: schema face parte
/// din protocol, deci trebuie sa fie identica la relee si la autoritati.
///
/// Am gresit de doua ori aici, si de fiecare data pentru ca numele nu spuneau
/// ce semneaza fiecare:
///
/// 1. Autoritatea trimitea o cheie ML-DSA-65 in CERTS, releul astepta ML-DSA-44
///    → `mesaj de legatura malformat`.
/// 2. Autoritatea verifica descriptorii releelor cu schema consensului
///    → `0 relee din 3 descriptori`, fara niciun mesaj de eroare.
///
/// Al doilea e mai periculos: esecul era tacut. Un descriptor care nu se
/// verifica e sarit, nu raportat — corect ca politica, dar inseamna ca o
/// nepotrivire de scheme arata exact ca „nu a publicat nimeni".
#[cfg(feature = "pq")]
type SRelay = pqo_crypto::HybridSig<pqo_crypto::Ed25519, pqo_crypto::MlDsa44>;
#[cfg(not(feature = "pq"))]
type SRelay = pqo_crypto::Ed25519;

const AJUTOR: &str = "\
pqonion-dirauth — autoritate de director

  --listen ADRESA:PORT  unde asculta          (implicit 127.0.0.1:9030)
  --data-dir CALE     unde tine cheile        (implicit ./date-autoritate)
  --interval SECUNDE  cat dureaza un ciclu    (implicit 3600)
  --cicluri N         cate cicluri, apoi iese (implicit: la nesfarsit)
  --log NIVEL         error|warn|info         (implicit info)
  --help              acest mesaj
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
    args.verifica(&["data-dir","listen","interval","cicluri","log","help"])?;

    let nivel = clamp_level(
        Level::parse(&args.get_or("log", "info"))
            .ok_or_else(|| SetupError::BadArgument("--log".into()))?,
    );
    let interval: u64 = args.parse_or("interval", 3600u64)?;
    let listen: std::net::SocketAddr = args
        .get_or("listen", "127.0.0.1:9030")
        .parse()
        .map_err(|_| SetupError::BadArgument("--listen".into()))?;
    let cicluri: u64 = args.parse_or("cicluri", 0u64)?;
    let data_dir = PathBuf::from(args.get_or("data-dir", "./date-autoritate"));

    // Cheia de semnare se deriva din samanta: o autoritate care isi schimba
    // cheia la repornire invalideaza toate consensurile semnate anterior.
    let seed = load_or_create_seed(&data_dir.join("autoritate.key"))?;
    let mut rng = ShakeRng::new(b"pqonion-dirauth-signing-v1", &[&seed]);
    let (sk, pk) = SConsens::keygen(&mut rng);
    let fp = pqo_dirproto::netdoc::fingerprint(&pk);

    log(Level::Info, nivel, "autoritate de director pornita");
    log(
        Level::Info,
        nivel,
        &format!("fingerprint {}", pqo_dirproto::hex_encode(&fp)),
    );
    log(
        Level::Info,
        nivel,
        &format!(
            "consens semnat cu {}, identitate de retea {}",
            <SConsens as Sig>::NAME,
            <SRelay as Sig>::NAME
        ),
    );
    log(
        Level::Warn,
        nivel,
        "schimbul de voturi intre autoritati nu e implementat pe retea",
    );

    // Autoritatea e un nod ca oricare altul: releele ii publica descriptorii
    // printr-un circuit, iar clientii ii descarca consensul tot asa.
    let store = Arc::new(std::sync::Mutex::new(DirStore::new()));

    // Identitatea de legatura, separata de cea de semnare a documentelor.
    let mut r_link = ShakeRng::new(b"pqonion-dirauth-link-v1", &[&seed]);
    let (link_sk, link_pk) = SRelay::keygen(&mut r_link);

    let circuit_keys = {
        let mut r = ShakeRng::new(b"pqonion-dirauth-onion-v1", &[&seed]);
        pqo_crypto::RelayKeys::<K>::generate(
            pqo_dirproto::netdoc::fingerprint(&link_pk),
            pqo_crypto::Variant::Transitional,
            &mut r,
        )
    };
    let handle = spawn::<K, SRelay>(NodeConfig {
        circuit_keys,
        id_sk: Arc::new(link_sk),
        id_pk: link_pk.clone(),
        listen,
        exit_policy: ExitPolicy::reject_all(),
        dir_store: Arc::clone(&store),
        hs_store: None,
        metrici: Default::default(),
        transport: std::sync::Arc::new(pqo_relay_io::node::Transport::Plaintext),
    })
    .await
    .map_err(SetupError::Io)?;
    log(
        Level::Info,
        nivel,
        &format!("ascult pe {}", handle.addr()),
    );



    let mut n = 0u64;
    loop {
        let acum = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Descriptorii primiti de la relee de la ultima rulare incoace.
        let descriptori: Vec<String> = match store.lock() {
            Ok(s) => s.all_descriptors().map(|(_, d)| d.to_string()).collect(),
            Err(_) => Vec::new(),
        };

        let vot = build_vote::<SRelay>(
            pk.clone(),
            Validity {
                valid_after: acum,
                fresh_until: acum + interval,
                valid_until: acum + 3 * interval,
            },
            vec![("circwindow".into(), 1000)],
            &descriptori,
        );

        match compute_consensus(&[vot]) {
            Ok(mut c) => {
                c.add_signature::<SConsens>(&pk, &sk);
                let doc = c.encode();
                let cale = data_dir.join("consens.txt");
                std::fs::write(&cale, &doc)?;
                // Si in magazin, ca sa il poata descarca clientii prin circuit.
                if let Ok(mut s) = store.lock() {
                    s.set_consensus(doc.clone());
                }
                log(
                    Level::Info,
                    nivel,
                    &format!(
                        "consens: {} relee din {} descriptori, {} octeti -> {}",
                        c.relays.len(),
                        descriptori.len(),
                        doc.len(),
                        cale.display()
                    ),
                );
            }
            Err(e) => log(Level::Error, nivel, &format!("consens esuat: {e}")),
        }

        n += 1;
        if cicluri != 0 && n >= cicluri {
            handle.shutdown();
            return Ok(());
        }
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(interval)) => {}
            _ = tokio::signal::ctrl_c() => {
                log(Level::Info, nivel, "oprire");
                handle.shutdown();
                return Ok(());
            }
        }
    }
}
