//! Handshake-ul de extindere de circuit `pq-ntor-v1`.
//!
//! Este un 1W-AKE (one-way authenticated key exchange) in traditia ntor
//! (Goldberg–Stebila–Ustaoglu): clientul autentifica releul, releul **nu**
//! autentifica clientul. Asta e intentionat — anonimitatea clientului e scopul.
//!
//! # Structura
//!
//! ntor clasic combina doua rezultate Diffie–Hellman:
//!   - `X25519(X, y)` — efemer × efemer, da forward secrecy
//!   - `X25519(X, b)` — efemer × static, autentifica releul
//!
//! `pq-ntor-v1` pastreaza ambele si adauga un al treilea secret, dintr-un KEM
//! generic. Cele doua variante din documentul de arhitectura difera prin *cine*
//! detine cheia de incapsulare:
//!
//! | Varianta | KEM efemer | KEM static | Confidentialitate | Autentificare |
//! |---|---|---|---|---|
//! | [`Variant::Transitional`] | client → releu | — | post-cuantica | clasica |
//! | [`Variant::FullPq`] | client → releu | releu (`EK_R`) | post-cuantica | post-cuantica (implicita) |
//!
//! Varianta tranzitionala e implicita, cu rationamentul din propunerea 269 a
//! Tor: autentificarea trebuie sparta *live*, deci un adversar cuantic viitor nu
//! se poate da retroactiv drept releu intr-un circuit din trecut. HNDL(harvest now decrypt later) ameninta
//! doar confidentialitatea, iar secretul KEM o acopera.
//!
//! Varianta FullPq inchide si gaura de autentificare, prin incapsulare catre o
//! cheie KEM statica a releului. Forward secrecy se pastreaza: daca `DK_R` se
//! compromite ulterior, `ss_static` se scurge, dar `ss_eph` nu, iar combiner-ul
//! e un PRF.
/*
    NTOR
    1. Clientul initiaza circuitul. -> isi construieste mesajul CREATE2(chei efemere clasice X25519 + chei KEM efemere, din care trimite cheia publica(eph_k))
    Fullpq-> clientul va incapsula un secret folosind cheia KEM statica a releului(static_ct), acest pas va forta releul sa demonstreze pe viitor ca detine cheia privata postcuantica.
    Pachetul trimis contine -> X, eph_ek si optional static_ct

    2. Releul calculeaza si raspunde(server_respond) -> verifica prin ID daca ii e adresat.
    Genereaza propria cheie efemera X25519(Y)  -> executa doua calcule matematice X25519 temporale cu cheia temporara X a clientului. Unul cu secretul sau temporar si altul cu secretul sau permanent(isi dem identitatea fata de client).
    Foloseste cheia eph_ek primita pt a incapsula un secret post-cuantic, generand ciphertext-ul eph_ct.
    Deriveaza un tag de autentificare(hash criptografic) amestecand toate secretele si transcriptul conversatiei. Raspunde cu mesajul CREATED2: Y, eph_ct si tag-ul auth. 

    3. Clientul verifica si finalizeaza -> pt a preveni man-in-the-middle attack.
    Reface calculele matematice clasice folosind Y-ul primit si cheia statica publica a releului.
    Decapsuleaza eph_ct folosind cheia sa privata KEM efemera, recuperand secretul post-cuantic generat de releu la pasul anterior.
    Clientul reconstruieste materialul secret punand cap la cap rezultaltele urmatoarea structuri: DHee || DHes || SSeph || SSstatic.

    Clientul se va folosi de acest material si transcriptul public, calculeaza propriul sau tag de autentificare. Daca acesta se potriveste bit cu bit cu tag-ul auth primit(comparatie realizata in timp constat pt a preveni atacurile laterale), confirma ca releul e autentic si extrage KEY_SEED-ul final.

    Prin acesti 3 pasi se va pastra forward secrecy, chiar daca cheile pe termen lung ale releului sunt furate in viitor.
*/

use core::fmt;

use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::Zeroizing;

use crate::kdf::{self, KeySeed};
use crate::kem::{Kem, KemError, SharedSecret};

/// Lungimea unui identificator de releu (hash-ul cheii sale de identitate).
pub const ID_LEN: usize = 32;
/// Lungimea unei chei publice X25519.
pub const X25519_LEN: usize = 32;
/// Lungimea tag-ului de autentificare.
pub const AUTH_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// Confidentialitate PQ, autentificare clasica. Mai ieftina.
    Transitional,
    /// Confidentialitate si autentificare PQ, prin cheie KEM statica la releu.
    FullPq,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtorError {
    /// Mesaj prea scurt sau de lungime gresita.
    BadLength { expected: usize, got: usize },
    /// Tag-ul de autentificare nu se verifica. Releul e fals, mesajul a fost
    /// modificat, sau clientul are cheia statica gresita.
    AuthFailed,
    /// Clientul a trimis un `ID_R` sau `B` care nu apartine acestui releu.
    WrongRelay,
    /// Eroare din stratul de KEM.
    Kem(KemError),
    /// Varianta ceruta nu se potriveste cu configuratia releului.
    VariantMismatch,
}

impl From<KemError> for NtorError {
    fn from(e: KemError) -> Self {
        NtorError::Kem(e)
    }
}

impl fmt::Display for NtorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtorError::BadLength { expected, got } => {
                write!(f, "lungime invalida: asteptat {expected}, primit {got}")
            }
            NtorError::AuthFailed => f.write_str("autentificarea releului a esuat"),
            NtorError::WrongRelay => f.write_str("handshake adresat altui releu"),
            NtorError::Kem(e) => write!(f, "eroare KEM: {e}"),
            NtorError::VariantMismatch => f.write_str("varianta de handshake nepotrivita"),
        }
    }
}

impl std::error::Error for NtorError {}

// ---------------------------------------------------------------------------
// Starea releului
// ---------------------------------------------------------------------------

/// Cheile de lunga durata ale unui releu, partea folosita la handshake.
///
/// `id` e hash-ul cheii de identitate ML-DSA a releului (nu cheia insasi:
/// 1312 de octeti nu incap in transcript in mod util). Legarea dintre `id` si
/// cheia ML-DSA se verifica la validarea descriptorului, in `pqo-dirproto`.
pub struct RelayKeys<K: Kem> {
    pub id: [u8; ID_LEN],
    /// Cheia statica X25519, `(b, B)`.
    x25519_secret: XSecret,
    x25519_public: XPublic,
    /// Cheia KEM statica, doar pentru [`Variant::FullPq`]. Se roteste zilnic.
    static_kem: Option<(K::DecapKey, Vec<u8>)>,
}

impl<K: Kem> fmt::Debug for RelayKeys<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelayKeys({:02x}{:02x}.., secrete redactate)", self.id[0], self.id[1])
    }
}

impl<K: Kem> RelayKeys<K> {
    /// Genereaza chei noi pentru un releu.
    pub fn generate(id: [u8; ID_LEN], variant: Variant, rng: &mut impl CryptoRngCore) -> Self {
        let x25519_secret = XSecret::random_from_rng(&mut *rng);
        let x25519_public = XPublic::from(&x25519_secret);
        let static_kem = match variant {
            Variant::Transitional => None,
            Variant::FullPq => Some(K::keygen(rng)),
        };
        RelayKeys {
            id,
            x25519_secret,
            x25519_public,
            static_kem,
        }
    }

    /// Partea publica, cea care se publica in descriptorul releului.
    pub fn public(&self) -> RelayPublic {
        RelayPublic {
            id: self.id,
            x25519: *self.x25519_public.as_bytes(),
            static_kem_ek: self.static_kem.as_ref().map(|(_, ek)| ek.clone()),
        }
    }

    pub fn variant(&self) -> Variant {
        if self.static_kem.is_some() {
            Variant::FullPq
        } else {
            Variant::Transitional
        }
    }
}

/// Partea publica a cheilor unui releu, asa cum apare in consens/descriptor.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayPublic {
    pub id: [u8; ID_LEN],
    pub x25519: [u8; X25519_LEN],
    /// Prezenta ei semnaleaza suport pentru [`Variant::FullPq`].
    pub static_kem_ek: Option<Vec<u8>>,
}

impl fmt::Debug for RelayPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Fingerprint-ul e informatie care leaga circuite. Nu il logam intreg.
        write!(
            f,
            "RelayPublic({:02x}{:02x}.., pq={})",
            self.id[0],
            self.id[1],
            self.static_kem_ek.is_some()
        )
    }
}

// ---------------------------------------------------------------------------
// Partea de client
// ---------------------------------------------------------------------------

/// Starea pastrata de client intre trimiterea CREATE2 si primirea CREATED2.
///
/// Nu implementeaza `Clone`: refolosirea unei stari de handshake ar insemna
/// refolosire de nonce efemer, adica exact bug-ul care sparge ECDSA. Tipul
/// impiedica asta la compilare.
pub struct ClientState<K: Kem> {
    variant: Variant,
    relay: RelayPublic,
    /// `x` — efemer, dar tinut ca `StaticSecret` pentru ca il folosim de doua ori
    /// (`X25519(Y,x)` si `X25519(B,x)`). `EphemeralSecret` consuma `self`.
    x: XSecret,
    big_x: XPublic,
    /// Cheia de decapsulare efemera a clientului.
    eph_dk: K::DecapKey,
    eph_ek: Vec<u8>,
    /// Doar FullPq: ciphertext-ul catre cheia KEM statica a releului, si
    /// secretul rezultat, pastrat pana la verificare.
    static_ct: Option<Vec<u8>>,
    static_ss: Option<SharedSecret>,
}

impl<K: Kem> fmt::Debug for ClientState<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientState({:?}, secrete redactate)", self.variant)
    }
}

/// Rezultatul unui handshake reusit.
pub struct HandshakeResult {
    pub key_seed: KeySeed,
}

impl fmt::Debug for HandshakeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HandshakeResult(redacted)")
    }
}

/// Pasul 1: clientul construieste mesajul CREATE2 / EXTEND2.
pub fn client_init<K: Kem>(
    relay: &RelayPublic,
    variant: Variant,
    rng: &mut impl CryptoRngCore,
) -> Result<(ClientState<K>, Vec<u8>), NtorError> {
    if variant == Variant::FullPq && relay.static_kem_ek.is_none() {
        return Err(NtorError::VariantMismatch);
    }

    let x = XSecret::random_from_rng(&mut *rng);
    let big_x = XPublic::from(&x);
    let (eph_dk, eph_ek) = K::keygen(rng);

    let (static_ct, static_ss) = match variant {
        Variant::Transitional => (None, None),
        Variant::FullPq => {
            let ek = relay.static_kem_ek.as_ref().ok_or(NtorError::VariantMismatch)?;
            let (ct, ss) = K::encapsulate(ek, rng)?;
            (Some(ct), Some(ss))
        }
    };

    // Format pe fir: ID_R ‖ B ‖ X ‖ eph_ek [‖ static_ct]
    let mut msg = Vec::with_capacity(ID_LEN + 2 * X25519_LEN + K::EK_LEN + K::CT_LEN);
    msg.extend_from_slice(&relay.id);
    msg.extend_from_slice(&relay.x25519);
    msg.extend_from_slice(big_x.as_bytes());
    msg.extend_from_slice(&eph_ek);
    if let Some(ct) = &static_ct {
        msg.extend_from_slice(ct);
    }

    Ok((
        ClientState {
            variant,
            relay: relay.clone(),
            x,
            big_x,
            eph_dk,
            eph_ek,
            static_ct,
            static_ss,
        },
        msg,
    ))
}

// ---------------------------------------------------------------------------
// Partea de releu
// ---------------------------------------------------------------------------

/// Pasul 2: releul proceseaza CREATE2 si construieste CREATED2.
///
/// Intoarce `(mesaj de raspuns, rezultat de handshake)`. Releul poate incepe sa
/// foloseasca cheile imediat; clientul le foloseste doar dupa `client_finish`.
pub fn server_respond<K: Kem>(
    keys: &RelayKeys<K>,
    msg: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(Vec<u8>, HandshakeResult), NtorError> {
    let variant = keys.variant();
    let expected = ID_LEN
        + X25519_LEN
        + X25519_LEN
        + K::EK_LEN
        + if variant == Variant::FullPq {
            K::CT_LEN
        } else {
            0
        };
    if msg.len() != expected {
        return Err(NtorError::BadLength {
            expected,
            got: msg.len(),
        });
    }

    let (id_r, rest) = msg.split_at(ID_LEN);
    let (big_b, rest) = rest.split_at(X25519_LEN);
    let (big_x, rest) = rest.split_at(X25519_LEN);
    let (eph_ek, rest) = rest.split_at(K::EK_LEN);

    // Verificare in timp constant ca handshake-ul ne e adresat noua. Fara asta,
    // un atacator poate folosi releul ca oracol pentru chei ale altui releu.
    let id_ok = id_r.ct_eq(&keys.id);
    let b_ok = big_b.ct_eq(keys.x25519_public.as_bytes());
    if !bool::from(id_ok & b_ok) {
        return Err(NtorError::WrongRelay);
    }

    // Secretul din cheia KEM statica (doar FullPq).
    let static_ss = if variant == Variant::FullPq {
        let (dk, _) = keys.static_kem.as_ref().ok_or(NtorError::VariantMismatch)?;
        Some(K::decapsulate(dk, rest)?)
    } else {
        None
    };
    let static_ct: &[u8] = if variant == Variant::FullPq { rest } else { &[] };

    // Partea efemera.
    let big_x_arr: [u8; 32] = big_x.try_into().expect("lungime verificata mai sus");
    let client_x = XPublic::from(big_x_arr);

    let y = XSecret::random_from_rng(&mut *rng);
    let big_y = XPublic::from(&y);

    let dh_ee = y.diffie_hellman(&client_x);
    let dh_es = keys.x25519_secret.diffie_hellman(&client_x);
    if !dh_ee.was_contributory() || !dh_es.was_contributory() {
        // `X` este punct de ordin mic. Respinge.
        return Err(NtorError::Kem(KemError::InvalidKey));
    }

    let (eph_ct, eph_ss) = K::encapsulate(eph_ek, rng)?;

    let transcript = Transcript {
        id_r: &keys.id,
        big_b: keys.x25519_public.as_bytes(),
        big_x,
        big_y: big_y.as_bytes(),
        eph_ek,
        eph_ct: &eph_ct,
        static_ct,
    };

    let (key_seed, auth) = derive::<K>(
        &transcript,
        dh_ee.as_bytes(),
        dh_es.as_bytes(),
        &eph_ss,
        static_ss.as_ref(),
    );

    // Format pe fir: Y ‖ eph_ct ‖ auth
    let mut resp = Vec::with_capacity(X25519_LEN + K::CT_LEN + AUTH_LEN);
    resp.extend_from_slice(big_y.as_bytes());
    resp.extend_from_slice(&eph_ct);
    resp.extend_from_slice(&auth);

    Ok((resp, HandshakeResult { key_seed }))
}

// ---------------------------------------------------------------------------
// Finalizarea la client
// ---------------------------------------------------------------------------

/// Pasul 3: clientul verifica CREATED2 si deriva cheile.
///
/// Consuma starea: un handshake nu poate fi finalizat de doua ori.
pub fn client_finish<K: Kem>(
    state: ClientState<K>,
    msg: &[u8],
) -> Result<HandshakeResult, NtorError> {
    let expected = X25519_LEN + K::CT_LEN + AUTH_LEN;
    if msg.len() != expected {
        return Err(NtorError::BadLength {
            expected,
            got: msg.len(),
        });
    }

    let (big_y, rest) = msg.split_at(X25519_LEN);
    let (eph_ct, auth_recv) = rest.split_at(K::CT_LEN);

    let big_y_arr: [u8; 32] = big_y.try_into().expect("lungime verificata mai sus");
    let server_y = XPublic::from(big_y_arr);
    let server_b = XPublic::from(state.relay.x25519);

    let dh_ee = state.x.diffie_hellman(&server_y);
    let dh_es = state.x.diffie_hellman(&server_b);
    if !dh_ee.was_contributory() || !dh_es.was_contributory() {
        return Err(NtorError::Kem(KemError::InvalidKey));
    }

    let eph_ss = K::decapsulate(&state.eph_dk, eph_ct)?;

    let static_ct: &[u8] = state.static_ct.as_deref().unwrap_or(&[]);
    let transcript = Transcript {
        id_r: &state.relay.id,
        big_b: &state.relay.x25519,
        big_x: state.big_x.as_bytes(),
        big_y,
        eph_ek: &state.eph_ek,
        eph_ct,
        static_ct,
    };

    let (key_seed, auth_calc) = derive::<K>(
        &transcript,
        dh_ee.as_bytes(),
        dh_es.as_bytes(),
        &eph_ss,
        state.static_ss.as_ref(),
    );

    // Comparatie in timp constant. O comparatie naiva `==` scurge, prin timp,
    // cati octeti de prefix coincid — suficient pentru a forja tag-ul octet cu
    // octet in 32 × 256 incercari.
    if !bool::from(auth_calc.ct_eq(auth_recv)) {
        return Err(NtorError::AuthFailed);
    }

    let _ = state.variant; // pastrat pentru diagnostic; nu intra in derivare
    Ok(HandshakeResult { key_seed })
}

// ---------------------------------------------------------------------------
// Derivarea propriu-zisa
// ---------------------------------------------------------------------------

/// Toate campurile publice care intra in transcript. Ambele parti trebuie sa
/// construiasca *exact* aceeasi structura, altfel tag-ul nu se verifica.
struct Transcript<'a> {
    id_r: &'a [u8],
    big_b: &'a [u8],
    big_x: &'a [u8],
    big_y: &'a [u8],
    eph_ek: &'a [u8],
    eph_ct: &'a [u8],
    /// Gol pentru varianta tranzitionala.
    static_ct: &'a [u8],
}

/// Calculeaza `KEY_SEED` si tag-ul `auth`.
///
/// `secret_input` contine, in ordine:
///   `dh_ee ‖ dh_es ‖ ss_eph [‖ ss_static] ‖ NAME ‖ transcript ‖ PROTOID`
///
/// Fiecare component e prefixat cu lungimea lui (vezi [`crate::kdf`]), deci
/// codarea e injectiva chiar daca lungimile variaza intre scheme de KEM.
fn derive<K: Kem>(
    t: &Transcript<'_>,
    dh_ee: &[u8],
    dh_es: &[u8],
    eph_ss: &SharedSecret,
    static_ss: Option<&SharedSecret>,
) -> (KeySeed, [u8; AUTH_LEN]) {
    let empty: &[u8] = &[];
    let static_bytes = static_ss.map(|s| s.as_bytes()).unwrap_or(empty);

    let parts: [&[u8]; 11] = [
        dh_ee,
        dh_es,
        eph_ss.as_bytes(),
        static_bytes,
        K::NAME.as_bytes(),
        t.id_r,
        t.big_b,
        t.big_x,
        t.big_y,
        t.eph_ek,
        t.eph_ct,
    ];
    // `static_ct` e ultimul ca sa pastram indexarea stabila cand e gol.
    let mut all: Vec<&[u8]> = parts.to_vec();
    all.push(t.static_ct);
    all.push(kdf::PROTOID);

    let key_seed = Zeroizing::new(kdf::hash(kdf::label::KEY_SEED, &all));
    let verify = Zeroizing::new(kdf::hash(kdf::label::VERIFY, &all));

    // Tag-ul acopera `verify` plus transcriptul public, plus eticheta "Server".
    // Eticheta previne reflectarea: un mesaj de client nu poate trece drept
    // mesaj de server.
    let auth = kdf::hash(
        kdf::label::AUTH,
        &[
            verify.as_slice(),
            t.id_r,
            t.big_b,
            t.big_y,
            t.big_x,
            t.eph_ek,
            t.eph_ct,
            t.static_ct,
            K::NAME.as_bytes(),
            kdf::PROTOID,
            b"Server",
        ],
    );

    (KeySeed::new(*key_seed), auth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::{Hybrid, X25519Kem};
    use rand_core::OsRng;

    type TestKem = X25519Kem;
    type HybridKem = Hybrid<X25519Kem, X25519Kem>;

    fn setup<K: Kem>(variant: Variant) -> (RelayKeys<K>, RelayPublic) {
        let mut rng = OsRng;
        let keys = RelayKeys::<K>::generate([0x42; ID_LEN], variant, &mut rng);
        let public = keys.public();
        (keys, public)
    }

    fn handshake_complet<K: Kem>(variant: Variant) {
        let mut rng = OsRng;
        let (keys, public) = setup::<K>(variant);

        let (state, msg1) = client_init::<K>(&public, variant, &mut rng).expect("client_init");
        let (msg2, server_res) = server_respond::<K>(&keys, &msg1, &mut rng).expect("server");
        let client_res = client_finish::<K>(state, &msg2).expect("client_finish");

        assert_eq!(
            client_res.key_seed.as_bytes(),
            server_res.key_seed.as_bytes(),
            "cele doua parti trebuie sa derive acelasi KEY_SEED"
        );

        // Materialul de cheie expandat trebuie sa coincida pe toata lungimea
        // ceruta de CGO (2 seed + 4 chei + 2 chei de hash = ~288 octeti).
        assert_eq!(
            client_res.key_seed.expand_vec(288),
            server_res.key_seed.expand_vec(288)
        );
    }

    #[test]
    fn tranzitional_x25519() {
        handshake_complet::<TestKem>(Variant::Transitional);
    }

    #[test]
    fn fullpq_x25519() {
        handshake_complet::<TestKem>(Variant::FullPq);
    }

    #[test]
    fn tranzitional_hibrid() {
        handshake_complet::<HybridKem>(Variant::Transitional);
    }

    #[test]
    fn fullpq_hibrid() {
        handshake_complet::<HybridKem>(Variant::FullPq);
    }

    #[cfg(feature = "pq")]
    #[test]
    fn fullpq_mlkem_real() {
        use crate::kem::MlKem768;
        handshake_complet::<Hybrid<X25519Kem, MlKem768>>(Variant::FullPq);
    }

    #[test]
    fn dimensiunile_mesajelor_sunt_cele_documentate() {
        let mut rng = OsRng;
        let (keys, public) = setup::<TestKem>(Variant::Transitional);
        let (_s, msg1) = client_init::<TestKem>(&public, Variant::Transitional, &mut rng).unwrap();
        assert_eq!(msg1.len(), 32 + 32 + 32 + TestKem::EK_LEN);
        let (msg2, _) = server_respond::<TestKem>(&keys, &msg1, &mut rng).unwrap();
        assert_eq!(msg2.len(), 32 + TestKem::CT_LEN + 32);
    }

    #[test]
    fn tag_modificat_e_respins() {
        let mut rng = OsRng;
        let (keys, public) = setup::<TestKem>(Variant::Transitional);
        let (state, msg1) = client_init::<TestKem>(&public, Variant::Transitional, &mut rng).unwrap();
        let (mut msg2, _) = server_respond::<TestKem>(&keys, &msg1, &mut rng).unwrap();
        let n = msg2.len();
        msg2[n - 1] ^= 0x01;
        assert_eq!(
            client_finish::<TestKem>(state, &msg2).err(),
            Some(NtorError::AuthFailed)
        );
    }

    #[test]
    fn ciphertext_modificat_e_respins() {
        let mut rng = OsRng;
        let (keys, public) = setup::<TestKem>(Variant::Transitional);
        let (state, msg1) = client_init::<TestKem>(&public, Variant::Transitional, &mut rng).unwrap();
        let (mut msg2, _) = server_respond::<TestKem>(&keys, &msg1, &mut rng).unwrap();
        msg2[40] ^= 0x01; // in mijlocul lui eph_ct
        let r = client_finish::<TestKem>(state, &msg2);
        assert!(r.is_err(), "modificarea ciphertext-ului trebuie detectata");
    }

    #[test]
    fn y_modificat_e_respins() {
        let mut rng = OsRng;
        let (keys, public) = setup::<TestKem>(Variant::Transitional);
        let (state, msg1) = client_init::<TestKem>(&public, Variant::Transitional, &mut rng).unwrap();
        let (mut msg2, _) = server_respond::<TestKem>(&keys, &msg1, &mut rng).unwrap();
        msg2[0] ^= 0x01;
        assert!(client_finish::<TestKem>(state, &msg2).is_err());
    }

    #[test]
    fn releu_impostor_e_respins() {
        // Un atacator care nu detine `b` nu poate produce un `auth` valid,
        // chiar daca controleaza complet canalul.
        let mut rng = OsRng;
        let (_adevarat, public) = setup::<TestKem>(Variant::Transitional);
        let mut impostor = RelayKeys::<TestKem>::generate([0x42; ID_LEN], Variant::Transitional, &mut rng);
        // Impostorul pretinde acelasi ID, dar are alt `b`.
        impostor.id = public.id;

        let (_state, msg1) = client_init::<TestKem>(&public, Variant::Transitional, &mut rng).unwrap();
        // Impostorul nici macar nu poate procesa mesajul: `B` nu se potriveste.
        assert_eq!(
            server_respond::<TestKem>(&impostor, &msg1, &mut rng).err(),
            Some(NtorError::WrongRelay)
        );
    }

    #[test]
    fn handshake_adresat_altui_releu_e_respins() {
        let mut rng = OsRng;
        let (keys_a, _pub_a) = setup::<TestKem>(Variant::Transitional);
        let keys_b = RelayKeys::<TestKem>::generate([0x99; ID_LEN], Variant::Transitional, &mut rng);
        let pub_b = keys_b.public();

        let (_state, msg1) = client_init::<TestKem>(&pub_b, Variant::Transitional, &mut rng).unwrap();
        assert_eq!(
            server_respond::<TestKem>(&keys_a, &msg1, &mut rng).err(),
            Some(NtorError::WrongRelay)
        );
    }

    #[test]
    fn punct_de_ordin_mic_in_x_e_respins() {
        let mut rng = OsRng;
        let (keys, public) = setup::<TestKem>(Variant::Transitional);
        let (_state, msg1) = client_init::<TestKem>(&public, Variant::Transitional, &mut rng).unwrap();
        let mut rau = msg1.clone();
        // Suprascrie `X` cu punctul de ordin mic u = 0.
        for b in &mut rau[64..96] {
            *b = 0;
        }
        assert!(
            server_respond::<TestKem>(&keys, &rau, &mut rng).is_err(),
            "releul trebuie sa respinga puncte de ordin mic"
        );
    }

    #[test]
    fn lungimi_gresite_sunt_respinse_fara_panica() {
        let mut rng = OsRng;
        let (keys, public) = setup::<TestKem>(Variant::Transitional);
        // Orice prefix trunchiat trebuie sa dea eroare, niciodata panica.
        let (_s, msg1) = client_init::<TestKem>(&public, Variant::Transitional, &mut rng).unwrap();
        for n in 0..msg1.len() {
            let r = server_respond::<TestKem>(&keys, &msg1[..n], &mut rng);
            assert!(r.is_err(), "prefix de lungime {n} ar fi trebuit respins");
        }
    }

    #[test]
    fn variantele_produc_chei_diferite() {
        // Acelasi releu, aceeasi cheie statica, dar varianta diferita nu trebuie
        // sa produca acelasi material de cheie (separare prin `static_ct`).
        let mut rng = OsRng;
        let keys = RelayKeys::<TestKem>::generate([1; ID_LEN], Variant::FullPq, &mut rng);
        let public = keys.public();

        let (s1, m1) = client_init::<TestKem>(&public, Variant::FullPq, &mut rng).unwrap();
        let (r1, _) = server_respond::<TestKem>(&keys, &m1, &mut rng).unwrap();
        let k1 = client_finish::<TestKem>(s1, &r1).unwrap();

        let (s2, m2) = client_init::<TestKem>(&public, Variant::FullPq, &mut rng).unwrap();
        let (r2, _) = server_respond::<TestKem>(&keys, &m2, &mut rng).unwrap();
        let k2 = client_finish::<TestKem>(s2, &r2).unwrap();

        assert_ne!(
            k1.key_seed.as_bytes(),
            k2.key_seed.as_bytes(),
            "doua handshake-uri distincte nu pot da acelasi seed"
        );
    }

    #[test]
    fn cerere_fullpq_catre_releu_fara_cheie_kem_esueaza() {
        let mut rng = OsRng;
        let (_keys, public) = setup::<TestKem>(Variant::Transitional);
        assert_eq!(
            client_init::<TestKem>(&public, Variant::FullPq, &mut rng)
                .err()
                .map(|e| e == NtorError::VariantMismatch),
            Some(true)
        );
    }

    #[test]
    fn debug_nu_scurge_nimic() {
        let (_k, public) = setup::<TestKem>(Variant::Transitional);
        let s = format!("{:?}", public);
        assert!(s.starts_with("RelayPublic("));
        assert!(s.len() < 60, "fingerprint-ul complet nu trebuie logat");
    }
}
