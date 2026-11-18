//! Infrastructura comuna a executabilelor: configuratie, chei, logging, consola.
//!
//! # Politica de logging
//!
//! Intr-un sistem de anonimitate, logging-ul e o vulnerabilitate, nu o
//! comoditate. Un releu care scrie „circuit 0x1234 de la 192.0.2.5 catre exit
//! 198.51.100.7" a distrus anonimitatea pentru oricine ii ia discul.
//!
//! De aceea nivelurile care ar putea scurge identificatori nu exista in build de
//! release: sunt compilate afara prin `cfg(debug_assertions)`. Nu sunt „oprite
//! implicit" — nu se pot activa deloc.
//!
//! | Nivel | Ce se scrie | In release |
//! |---|---|---|
//! | ERROR | erori de protocol, fara identificatori de peer | da |
//! | WARN  | handshake-uri esuate, agregat | da |
//! | INFO  | statistici agregate: circuite/ora, celule/s | da |
//! | DEBUG | ID-uri de circuit, fingerprint-uri | **nu** |
//! | TRACE | continut de celule, material de cheie | **nu** |

pub mod consola;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Nivelurile de logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    fn eticheta(self) -> &'static str {
        match self {
            Level::Error => "EROARE",
            Level::Warn => "ATENTIE",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }

    /// Adevarat daca nivelul poate scurge identificatori care leaga circuite.
    pub fn is_sensitive(self) -> bool {
        matches!(self, Level::Debug | Level::Trace)
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "error" => Some(Level::Error),
            "warn" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" => Some(Level::Debug),
            "trace" => Some(Level::Trace),
            _ => None,
        }
    }
}

/// Nivelul maxim care poate fi activat in acest build.
///
/// In release, orice cerere de DEBUG sau TRACE se reduce la INFO. Nu e o
/// politica pe care o poate schimba operatorul din configuratie.
pub const fn max_level() -> Level {
    #[cfg(debug_assertions)]
    {
        Level::Trace
    }
    #[cfg(not(debug_assertions))]
    {
        Level::Info
    }
}

/// Aplica plafonul de build peste nivelul cerut.
pub fn clamp_level(cerut: Level) -> Level {
    if cerut > max_level() {
        max_level()
    } else {
        cerut
    }
}

/// Scrie o linie de log daca nivelul o permite.
pub fn log(nivel: Level, activ: Level, mesaj: &str) {
    if nivel > activ {
        return;
    }
    let _ = writeln!(std::io::stderr(), "[{}] {}", nivel.eticheta(), mesaj);
}

// ---------------------------------------------------------------------------
// Persistenta cheilor
// ---------------------------------------------------------------------------

/// Erori de pornire.
#[derive(Debug)]
pub enum SetupError {
    Io(std::io::Error),
    /// Fisierul de chei are dimensiune gresita sau continut invalid.
    BadKeyFile(PathBuf),
    /// Permisiuni prea largi pe un fisier cu chei private.
    InsecurePermissions(PathBuf),
    /// Argument de linie de comanda invalid.
    BadArgument(String),
}

impl core::fmt::Display for SetupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SetupError::Io(e) => write!(f, "eroare de fisier: {e}"),
            SetupError::BadKeyFile(p) => write!(f, "fisier de chei invalid: {}", p.display()),
            SetupError::InsecurePermissions(p) => write!(
                f,
                "permisiuni prea largi pe {}: cheile private trebuie sa fie 0600",
                p.display()
            ),
            SetupError::BadArgument(a) => write!(f, "argument invalid: {a}"),
        }
    }
}

impl std::error::Error for SetupError {}

impl From<std::io::Error> for SetupError {
    fn from(e: std::io::Error) -> Self {
        SetupError::Io(e)
    }
}

/// Citeste o samanta de 32 de octeti, sau o genereaza la prima pornire.
///
/// # Permisiuni
///
/// Fisierul se creeaza cu `0600` si se verifica la fiecare citire. Un fisier de
/// chei private lizibil de alti utilizatori nu e o problema teoretica: pe o
/// masina partajata, oricine il poate copia si apoi impersona releul.
pub fn load_or_create_seed(path: &Path) -> Result<[u8; 32], SetupError> {
    if path.exists() {
        verifica_permisiuni(path)?;
        let b = fs::read(path)?;
        if b.len() != 32 {
            return Err(SetupError::BadKeyFile(path.to_path_buf()));
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(&b);
        return Ok(s);
    }

    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    let mut s = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut s);
    scrie_privat(path, &s)?;
    Ok(s)
}

/// Scrie un fisier cu permisiuni restrictive de la creare.
///
/// Ordinea conteaza: daca am crea fisierul si abia apoi i-am schimba
/// permisiunile, ar exista o fereastra in care e lizibil de oricine.
#[cfg(unix)]
fn scrie_privat(path: &Path, date: &[u8]) -> Result<(), SetupError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(date)?;
    f.sync_all()?;
    Ok(())
}

/// Varianta pentru platforme fara permisiuni POSIX.
///
/// **Nu ofera aceeasi protectie:** fisierul se creeaza cu permisiunile implicite
/// ale sistemului. Pe Windows ar trebui folosite ACL-uri.
#[cfg(not(unix))]
fn scrie_privat(path: &Path, date: &[u8]) -> Result<(), SetupError> {
    let mut f = fs::File::create(path)?;
    f.write_all(date)?;
    f.sync_all()?;
    Ok(())
}

fn verifica_permisiuni(path: &Path) -> Result<(), SetupError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = fs::metadata(path)?.permissions().mode();
        // Orice bit pentru grup sau pentru altii e prea mult.
        if m & 0o077 != 0 {
            return Err(SetupError::InsecurePermissions(path.to_path_buf()));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Salveaza guard-urile clientului, ca sa fie aceleasi la urmatoarea pornire.
///
/// Un client care isi pierde guard-urile la fiecare repornire pierde tocmai
/// apararea pe care guard-urile o ofera. Fisierul e text hexazecimal, cate un
/// fingerprint pe linie.
pub fn save_guards(path: &Path, guards: &[[u8; 32]]) -> Result<(), SetupError> {
    let mut out = String::new();
    for g in guards {
        for b in g {
            out.push_str(&format!("{b:02x}"));
        }
        out.push('\n');
    }
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    fs::write(path, out)?;
    Ok(())
}

/// Incarca guard-urile salvate. Un fisier lipsa nu e eroare: e prima pornire.
pub fn load_guards(path: &Path) -> Result<Vec<[u8; 32]>, SetupError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for linie in text.lines() {
        let l = linie.trim();
        if l.is_empty() {
            continue;
        }
        if l.len() != 64 {
            return Err(SetupError::BadKeyFile(path.to_path_buf()));
        }
        let mut fp = [0u8; 32];
        for (i, chunk) in l.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(chunk)
                .map_err(|_| SetupError::BadKeyFile(path.to_path_buf()))?;
            fp[i] = u8::from_str_radix(s, 16)
                .map_err(|_| SetupError::BadKeyFile(path.to_path_buf()))?;
        }
        out.push(fp);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Chei de testnet
// ---------------------------------------------------------------------------

/// Samanta releului cu indexul dat, intr-un testnet.
///
/// **DOAR PENTRU TESTNET.** Intr-un deployment real fiecare releu isi genereaza
/// samanta la prima pornire, iar clientii afla cheile din descriptori, descarcati
/// prin circuit. Aici semintele sunt fixe si cunoscute de toata lumea, ca sa
/// putem porni o retea completa dintr-un script fara sistem de director complet.
pub fn testnet_seed(index: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = index.wrapping_add(1);
    s
}

/// Cheile publice ale releului cu indexul dat. **DOAR PENTRU TESTNET.**
///
/// Exista aici, si nu duplicata in fiecare binar, pentru ca derivarea trebuie sa
/// fie identica peste tot: o singura eticheta gresita si releul are alt
/// fingerprint decat cel pe care il asteapta clientul, iar eroarea apare abia la
/// handshake.
pub fn testnet_relay_public<K, S>(index: u8) -> pqo_crypto::RelayPublic
where
    K: pqo_crypto::kem::Kem,
    S: pqo_crypto::sig::Sig,
{
    use pqo_crypto::kdf::ShakeRng;

    let seed = testnet_seed(index);
    let mut rng_id = ShakeRng::new(b"pqonion-relay-identity-v1", &[&seed]);
    let (_sk, id_pk) = S::keygen(&mut rng_id);
    let mut rng_circ = ShakeRng::new(b"pqonion-relay-onion-v1", &[&seed]);
    pqo_crypto::RelayKeys::<K>::generate(
        pqo_dirproto::netdoc::fingerprint(&id_pk),
        pqo_crypto::Variant::Transitional,
        &mut rng_circ,
    )
    .public()
}

/// Samanta autoritatii cu indexul dat, intr-un testnet.
///
/// Prefix diferit de al releelor, ca sa nu existe coliziuni de fingerprint intre
/// cele doua roluri.
pub fn testnet_authority_seed(index: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0xA0u8.wrapping_add(index);
    s
}

/// Cheile publice de circuit ale unei autoritati. **DOAR PENTRU TESTNET.**
///
/// Intr-un deployment real, cheile autoritatilor sunt **cablate in binar**: sunt
/// singurul punct de plecare al increderii, si orice alt mecanism ar fi
/// vulnerabil la un atac la prima pornire. Aici le derivam din index, ca sa nu
/// avem nevoie de un fisier de configurare separat in testnet.
pub fn testnet_authority_public<K, S>(index: u8) -> pqo_crypto::RelayPublic
where
    K: pqo_crypto::kem::Kem,
    S: pqo_crypto::sig::Sig,
{
    use pqo_crypto::kdf::ShakeRng;

    let seed = testnet_authority_seed(index);
    // Identitatea de **legatura**, nu cea de semnare a documentelor. `S` aici e
    // schema de legatura, aceeasi la relee si autoritati.
    let mut r_link = ShakeRng::new(b"pqonion-dirauth-link-v1", &[&seed]);
    let (_sk, pk) = S::keygen(&mut r_link);
    let mut r_onion = ShakeRng::new(b"pqonion-dirauth-onion-v1", &[&seed]);
    pqo_crypto::RelayKeys::<K>::generate(
        pqo_dirproto::netdoc::fingerprint(&pk),
        pqo_crypto::Variant::Transitional,
        &mut r_onion,
    )
    .public()
}

/// Cate hopuri are un circuit catre un punct de introducere sau de rendezvous.
///
/// Trei, ca la traficul obisnuit. **Nu e un parametru de acordat**: un circuit
/// de un hop face ca releul de la capat sa vada adresa reala a celui care il
/// deschide, ceea ce anuleaza tocmai proprietatea pentru care exista serviciile
/// ascunse.
pub const HOPURI_SERVICIU: usize = 3;

/// Cat de putine relee accepta o retea ca sa poata construi cai.
///
/// Cu mai putine de patru, orice cale de trei hopuri catre un releu anume ar
/// folosi toate celelalte relee, deci alegerea nu mai e o alegere. Testnet-ul
/// merge si cu trei, dar il marcam ca fiind exact la limita.
pub const MIN_RELEE: usize = 3;

/// Construieste un circuit de [`HOPURI_SERVICIU`] hopuri care se **termina** la
/// releul cu indexul dat.
///
/// # De ce nu o conexiune directa
///
/// Un punct de introducere sau de rendezvous e capatul unui circuit, nu un nod
/// prin care treci. Daca te conectezi direct la el, vede adresa ta reala.
///
/// Prima versiune a binarelor facea exact asta: `Circuit::connect` direct la
/// releu, apoi `establish_intro`. Mesajele erau corecte, semantica de protocol
/// era corecta, si toate cele 490 de teste treceau — pentru ca verificau ca
/// rendezvous-ul **functioneaza**, nu **prin cate relee trece**.
///
/// S-a vazut abia intr-o captura de trafic: nu exista nicio conexiune
/// releu-releu, doar client-releu si serviciu-releu. De aceea exista acum
/// [`Circuit::hops`] verificat in teste.
pub async fn circuit_catre<K, S>(
    relee: &[std::net::SocketAddr],
    tinta: u8,
    id_sk: std::sync::Arc<S::SecretKey>,
    id_pk: &[u8],
    transport: pqo_relay_io::client::TransportClient<'_>,
) -> std::io::Result<pqo_relay_io::client::Circuit<Box<dyn pqo_relay_io::client::Flux>>>
where
    K: pqo_crypto::kem::Kem,
    S: pqo_crypto::sig::Sig,
{
    use pqo_relay_io::client::Circuit;

    if relee.len() < MIN_RELEE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "reteaua are {} relee; sunt necesare cel putin {MIN_RELEE} \
                 pentru circuite de {HOPURI_SERVICIU} hopuri",
                relee.len()
            ),
        ));
    }
    let tinta_idx = tinta as usize;
    if tinta_idx >= relee.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("releul {tinta} nu e in lista"),
        ));
    }

    // Intermediarii: oricare in afara de tinta. Un releu nu poate aparea de doua
    // ori pe aceeasi cale — altfel ar vedea doua pozitii si ar putea corela.
    let intermediari: Vec<usize> = (0..relee.len())
        .filter(|i| *i != tinta_idx)
        .take(HOPURI_SERVICIU - 1)
        .collect();
    if intermediari.len() < HOPURI_SERVICIU - 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "prea putine relee distincte pentru o cale completa",
        ));
    }

    // Primul hop.
    let g = intermediari[0];
    let mut c = Circuit::connect_dyn::<K, S>(
        relee[g],
        &testnet_relay_public::<K, S>(g as u8),
        pqo_crypto::Variant::Transitional,
        id_sk,
        id_pk,
        transport,
    )
    .await?;

    // Restul, plus tinta la final.
    for idx in intermediari[1..].iter().copied().chain(core::iter::once(tinta_idx)) {
        let a = relee[idx];
        let octeti = match a.ip() {
            std::net::IpAddr::V4(v) => v.octets(),
            std::net::IpAddr::V6(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "extinderea cere o adresa IPv4",
                ))
            }
        };
        c.extend::<K>(
            &testnet_relay_public::<K, S>(idx as u8),
            octeti,
            a.port(),
            pqo_crypto::Variant::Transitional,
        )
        .await?;
    }

    debug_assert_eq!(
        c.hops(),
        HOPURI_SERVICIU,
        "un circuit de serviciu ascuns trebuie sa aiba exact {HOPURI_SERVICIU} hopuri"
    );
    Ok(c)
}

/// Cauta un releu de testnet dupa fingerprint. **DOAR PENTRU TESTNET.**
///
/// Intr-un client real, maparea fingerprint -> adresa vine din consens.
pub fn testnet_relay_public_by_id<K, S>(fp: &[u8; 32]) -> Option<pqo_crypto::RelayPublic>
where
    K: pqo_crypto::kem::Kem,
    S: pqo_crypto::sig::Sig,
{
    (0..8u8)
        .map(testnet_relay_public::<K, S>)
        .find(|p| &p.id == fp)
}

/// Indexul de testnet al unui releu, dupa fingerprint.
pub fn testnet_index_by_id<K, S>(fp: &[u8; 32]) -> Option<u8>
where
    K: pqo_crypto::kem::Kem,
    S: pqo_crypto::sig::Sig,
{
    (0..8u8).find(|i| &testnet_relay_public::<K, S>(*i).id == fp)
}

// ---------------------------------------------------------------------------
// Argumente de linie de comanda
// ---------------------------------------------------------------------------

/// Un parser minimal de argumente `--cheie valoare`.
///
/// Nu folosim `clap`: ar aduce zeci de dependente tranzitive intr-un proiect care
/// are nevoie de sase optiuni. Fiecare dependenta in plus e cod pe care nu l-am
/// citit si care ruleaza cu privilegiile releului.
#[derive(Debug, Default)]
pub struct Args {
    perechi: Vec<(String, String)>,
    flaguri: Vec<String>,
}

impl Args {
    /// Acceptă atât `--cheie valoare` cât și `--cheie=valoare`.
    ///
    /// A doua forma nu e un moft: e forma standard GNU, si e singura pe care o
    /// poti scrie natural intr-o lista YAML de `docker compose`. Prima versiune
    /// o trata ca pe un flag cu numele `cheie=valoare`, deci optiunea era
    /// **ignorata in tacere** — releele porneau pe valorile implicite si pareau
    /// ca merg.
    pub fn parse<I: IntoIterator<Item = String>>(it: I) -> Result<Self, SetupError> {
        let mut a = Args::default();
        let mut v: Vec<String> = it.into_iter().collect();
        let mut i = 0;
        while i < v.len() {
            let arg = core::mem::take(&mut v[i]);
            let Some(nume) = arg.strip_prefix("--") else {
                return Err(SetupError::BadArgument(arg));
            };
            if nume.is_empty() {
                return Err(SetupError::BadArgument(arg));
            }

            if let Some((k, val)) = nume.split_once('=') {
                if k.is_empty() {
                    return Err(SetupError::BadArgument(arg));
                }
                a.perechi.push((k.to_string(), val.to_string()));
                i += 1;
                continue;
            }

            // O optiune urmata de alta optiune e un flag.
            if i + 1 < v.len() && !v[i + 1].starts_with("--") {
                a.perechi
                    .push((nume.to_string(), core::mem::take(&mut v[i + 1])));
                i += 2;
            } else {
                a.flaguri.push(nume.to_string());
                i += 1;
            }
        }
        Ok(a)
    }

    /// Verifica ca toate optiunile date sunt cunoscute.
    ///
    /// Un binar care ignora in tacere o optiune data de operator e mai periculos
    /// decat unul care refuza sa porneasca: releul pare ca merge, dar nu face ce
    /// i s-a cerut. Exact asta s-a intamplat prima data in Docker — `--dirauth`
    /// ajungea flag, era ignorat, iar releul nu se inregistra la nicio autoritate.
    pub fn verifica(&self, cunoscute: &[&str]) -> Result<(), SetupError> {
        for nume in self.perechi.iter().map(|(k, _)| k).chain(self.flaguri.iter()) {
            if !cunoscute.contains(&nume.as_str()) {
                return Err(SetupError::BadArgument(format!(
                    "--{nume} nu e o optiune cunoscuta. Vezi --help"
                )));
            }
        }
        Ok(())
    }

    pub fn get(&self, nume: &str) -> Option<&str> {
        self.perechi
            .iter()
            .find(|(k, _)| k == nume)
            .map(|(_, v)| v.as_str())
    }

    pub fn has(&self, nume: &str) -> bool {
        self.flaguri.iter().any(|f| f == nume)
    }

    pub fn get_or(&self, nume: &str, implicit: &str) -> String {
        self.get(nume).unwrap_or(implicit).to_string()
    }

    pub fn parse_or<T: core::str::FromStr>(
        &self,
        nume: &str,
        implicit: T,
    ) -> Result<T, SetupError> {
        match self.get(nume) {
            Some(v) => v
                .parse()
                .map_err(|_| SetupError::BadArgument(format!("--{nume} {v}"))),
            None => Ok(implicit),
        }
    }

    /// Lista de porturi din `--exit-ports 80,443`.
    pub fn ports(&self, nume: &str) -> Result<Vec<u16>, SetupError> {
        match self.get(nume) {
            None => Ok(Vec::new()),
            Some(v) => v
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.trim()
                        .parse()
                        .map_err(|_| SetupError::BadArgument(format!("--{nume} {v}")))
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Result<Args, SetupError> {
        Args::parse(v.iter().map(|s| s.to_string()))
    }

    #[test]
    fn argumente_simple() {
        let a = args(&["--listen", "0.0.0.0:9001", "--log", "info"]).unwrap();
        assert_eq!(a.get("listen"), Some("0.0.0.0:9001"));
        assert_eq!(a.get("log"), Some("info"));
        assert_eq!(a.get("lipsa"), None);
        assert_eq!(a.get_or("lipsa", "implicit"), "implicit");
    }

    #[test]
    fn flaguri_fara_valoare() {
        let a = args(&["--verbose", "--listen", "1.2.3.4:1"]).unwrap();
        assert!(a.has("verbose"));
        assert!(!a.has("listen"));
        assert_eq!(a.get("listen"), Some("1.2.3.4:1"));
    }

    #[test]
    fn forma_cu_egal() {
        // Forma standard GNU, si singura pe care o scrii natural intr-o lista
        // YAML de docker compose.
        let a = args(&["--listen=0.0.0.0:9001", "--dirauth=10.0.0.1:9030"]).unwrap();
        assert_eq!(a.get("listen"), Some("0.0.0.0:9001"));
        assert_eq!(a.get("dirauth"), Some("10.0.0.1:9030"));
        assert!(!a.has("listen"), "nu e flag, e pereche");
    }

    #[test]
    fn valoare_care_contine_egal() {
        // Doar primul `=` separa; restul face parte din valoare.
        let a = args(&["--filtru=a=b=c"]).unwrap();
        assert_eq!(a.get("filtru"), Some("a=b=c"));
    }

    #[test]
    fn cele_doua_forme_sunt_echivalente() {
        let a = args(&["--listen", "1.2.3.4:9001"]).unwrap();
        let b = args(&["--listen=1.2.3.4:9001"]).unwrap();
        assert_eq!(a.get("listen"), b.get("listen"));
    }

    #[test]
    fn optiunile_necunoscute_sunt_refuzate() {
        // Un binar care ignora tacit o optiune data de operator e mai periculos
        // decat unul care refuza sa porneasca.
        let a = args(&["--listen=1.2.3.4:1", "--aiurea=5"]).unwrap();
        assert!(a.verifica(&["listen", "aiurea"]).is_ok());
        let e = a.verifica(&["listen"]).unwrap_err();
        assert!(format!("{e}").contains("aiurea"), "{e}");

        // Si flagurile.
        let b = args(&["--verbose"]).unwrap();
        assert!(b.verifica(&["verbose"]).is_ok());
        assert!(b.verifica(&["altceva"]).is_err());
    }

    #[test]
    fn argumente_invalide() {
        assert!(args(&["fara-prefix"]).is_err());
        assert!(args(&["--"]).is_err());
        assert!(args(&["--=valoare"]).is_err());
    }

    #[test]
    fn parsare_de_numere() {
        let a = args(&["--port", "9001", "--rau", "abc"]).unwrap();
        assert_eq!(a.parse_or::<u16>("port", 0).unwrap(), 9001);
        assert_eq!(a.parse_or::<u16>("lipsa", 42).unwrap(), 42);
        assert!(a.parse_or::<u16>("rau", 0).is_err());
    }

    #[test]
    fn liste_de_porturi() {
        let a = args(&["--exit-ports", "80,443, 8080"]).unwrap();
        assert_eq!(a.ports("exit-ports").unwrap(), vec![80, 443, 8080]);
        assert!(a.ports("lipsa").unwrap().is_empty());

        let b = args(&["--exit-ports", "80,abc"]).unwrap();
        assert!(b.ports("exit-ports").is_err());
    }

    #[test]
    fn nivelurile_sensibile_sunt_marcate() {
        assert!(Level::Debug.is_sensitive());
        assert!(Level::Trace.is_sensitive());
        assert!(!Level::Info.is_sensitive());
        assert!(!Level::Warn.is_sensitive());
        assert!(!Level::Error.is_sensitive());
    }

    #[test]
    fn nivelul_e_plafonat_de_build() {
        // In build de test, `debug_assertions` e activ, deci DEBUG trece.
        // In release, `max_level()` e INFO si plafonarea il reduce.
        let cerut = Level::Trace;
        let efectiv = clamp_level(cerut);
        assert!(efectiv <= max_level());
        if !cfg!(debug_assertions) {
            assert_eq!(efectiv, Level::Info, "release nu are voie sa logheze TRACE");
        }
    }

    #[test]
    fn parsarea_nivelului() {
        assert_eq!(Level::parse("INFO"), Some(Level::Info));
        assert_eq!(Level::parse("debug"), Some(Level::Debug));
        assert_eq!(Level::parse("aiurea"), None);
    }

    #[test]
    fn samanta_se_creeaza_si_se_reciteste() {
        let dir = std::env::temp_dir().join(format!("pqo-test-{}", std::process::id()));
        let p = dir.join("seed");
        let _ = fs::remove_file(&p);

        let a = load_or_create_seed(&p).unwrap();
        let b = load_or_create_seed(&p).unwrap();
        assert_eq!(a, b, "a doua pornire trebuie sa refoloseasca samanta");
        assert_ne!(a, [0u8; 32]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn permisiunile_prea_largi_sunt_respinse() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pqo-perm-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("seed");
        fs::write(&p, [0u8; 32]).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(
            matches!(
                load_or_create_seed(&p),
                Err(SetupError::InsecurePermissions(_))
            ),
            "o cheie privata lizibila de altii trebuie refuzata"
        );

        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_or_create_seed(&p).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn samanta_noua_are_permisiuni_stranse() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pqo-new-{}", std::process::id()));
        let p = dir.join("seed");
        let _ = fs::remove_dir_all(&dir);

        load_or_create_seed(&p).unwrap();
        let m = fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(m & 0o777, 0o600, "cheia trebuie creata direct cu 0600");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fisier_de_chei_de_lungime_gresita() {
        let dir = std::env::temp_dir().join(format!("pqo-len-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("seed");
        fs::write(&p, [0u8; 16]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            load_or_create_seed(&p),
            Err(SetupError::BadKeyFile(_))
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn guardurile_se_salveaza_si_se_reincarca() {
        let dir = std::env::temp_dir().join(format!("pqo-guards-{}", std::process::id()));
        let p = dir.join("guards");
        let _ = fs::remove_dir_all(&dir);

        // Prima pornire: fisier lipsa, nu e eroare.
        assert!(load_guards(&p).unwrap().is_empty());

        let g = vec![[1u8; 32], [0xABu8; 32]];
        save_guards(&p, &g).unwrap();
        assert_eq!(load_guards(&p).unwrap(), g);

        // Fisier stricat.
        fs::write(&p, "nu e hex\n").unwrap();
        assert!(load_guards(&p).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
