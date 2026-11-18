//! Descriptorul unui serviciu ascuns.
//!
//! # Doua straturi
//!
//! **Exterior**, in clar pentru HSDir: indexul blindat, perioada, contorul de
//! revizie, cheia de semnare a perioadei, blobul criptat, si o semnatura cu
//! cheia perioadei peste tot ce e deasupra.
//!
//! **Interior**, criptat cu o cheie derivata din identificatorul adresei:
//! cheia de identitate master, certificatul care leaga cheia perioadei de
//! master, si lista punctelor de introducere.
//!
//! HSDir stocheaza si serveste stratul exterior. Nu poate citi interiorul, nu
//! poate afla adresa, si nu poate lega doua perioade ale aceluiasi serviciu.
//!
//! # Ce nu poate HSDir si de ce conteaza
//!
//! HSDir **nu poate verifica ca cine publica detine slotul**. Cu blinding
//! algebric ar putea: cheia blindata e derivabila din adresa, deci HSDir ar
//! verifica semnatura sub ea. Aici cheia perioadei vine chiar din descriptor,
//! deci oricine poate genera o pereche si publica sub ea.
//!
//! Consecinta e refuz de serviciu, **nu impersonare**. Un descriptor fals nu
//! trece la client: tag-ul de autentificare al stratului criptat e cheiat pe
//! `addr_id`, pe care atacatorul il stie doar daca stie adresa; iar chiar si
//! atunci, interiorul trebuie sa contina o cheie master al carei hash e chiar
//! adresa. Fara cheia privata master nu exista descriptor acceptabil.
//!
//! Limitam refuzul de serviciu prin trei mecanisme, in [`DescStore`]:
//!   - contor de revizie strict crescator
//!   - primul care publica intr-o perioada isi pastreaza cheia de perioada
//!   - descriptorul se publica pe mai multe replici, deci un atacator trebuie sa
//!     le castige pe toate
//!
//! De documentat in lucrare ca regresie constienta fata de Tor v3, cu masura ei.

use pqo_crypto::kdf;
use pqo_crypto::sig::Sig;
use pqo_dirproto::doc::{b64_decode, b64_encode, hex_decode, hex_encode, parse_lines, signed_prefix, Builder, Line};
use subtle::ConstantTimeEq;

use crate::addr::{AddrId, OnionAddress};
use crate::blind::{blinded_id, period_cert_body, BlindedId, MasterSeed, TimePeriod};
use crate::HsError;

/// Cati octeti are tag-ul de autentificare al stratului criptat.
pub const TAG_LEN: usize = 32;

/// Un punct de introducere, asa cum il vede clientul.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntroPoint {
    /// Fingerprint-ul releului care joaca rolul de punct de introducere.
    pub relay_id: [u8; 32],
    /// Cheia catre care clientul **cripteaza corpul INTRODUCE**.
    ///
    /// Impreuna cu [`Self::onion_kem`] formeaza o cheie de incapsulare hibrida.
    /// Protejeaza cookie-ul si adresa punctului de rendezvous de punctul de
    /// introducere, care doar retransmite.
    pub onion_x25519: [u8; 32],
    pub onion_kem: Option<Vec<u8>>,
    /// Cheia statica X25519 cu care serviciul **raspunde la handshake-ul de
    /// rendezvous**.
    ///
    /// E o cheie **diferita** de cea de mai sus, si separarea nu e cosmetica:
    /// una serveste la criptarea cererii de introducere, cealalta la stabilirea
    /// hop-ului virtual. Prima versiune le suprapunea, iar `server_respond`
    /// esua cu `WrongRelay` — eroarea aparea abia la rendezvous, la trei
    /// straturi de cauza. Tor le tine separat din acelasi motiv
    /// (`enc-key` vs `onion-key`).
    pub svc_x25519: [u8; 32],
    /// Cheia de autentificare a acestui punct de introducere.
    pub auth_key: Vec<u8>,
}

/// Continutul stratului criptat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerDescriptor {
    /// Cheia publica de identitate a serviciului. Hash-ul ei e adresa.
    pub master_key: Vec<u8>,
    /// Semnatura cu cheia master peste `period_cert_body(period_pk, period)`.
    pub period_cert: Vec<u8>,
    pub intro_points: Vec<IntroPoint>,
}

impl InnerDescriptor {
    /// Cate puncte de introducere acceptam. Peste asta, un descriptor umflat ar
    /// putea fi folosit ca amplificator.
    pub const MAX_INTRO_POINTS: usize = 20;

    fn encode(&self) -> String {
        let mut b = Builder::new();
        b.line("master-key", [b64_encode(&self.master_key).as_str()]);
        b.line("period-cert", [b64_encode(&self.period_cert).as_str()]);
        for ip in &self.intro_points {
            let kem = ip
                .onion_kem
                .as_ref()
                .map(|k| b64_encode(k))
                .unwrap_or_else(|| "-".to_string());
            b.line(
                "intro-point",
                [
                    hex_encode(&ip.relay_id).as_str(),
                    b64_encode(&ip.onion_x25519).as_str(),
                    kem.as_str(),
                    b64_encode(&ip.svc_x25519).as_str(),
                    b64_encode(&ip.auth_key).as_str(),
                ],
            );
        }
        b.finish()
    }

    fn parse(doc: &str) -> Result<Self, HsError> {
        let lines = parse_lines(doc).map_err(HsError::Doc)?;
        let get = |kw: &str| -> Result<&Line, HsError> {
            lines
                .iter()
                .find(|l| l.keyword == kw)
                .ok_or(HsError::Malformed)
        };
        for kw in ["master-key", "period-cert"] {
            if lines.iter().filter(|l| l.keyword == kw).count() != 1 {
                return Err(HsError::Malformed);
            }
        }
        let master_key = b64_decode(get("master-key")?.arg(0).map_err(HsError::Doc)?)
            .map_err(HsError::Doc)?;
        let period_cert = b64_decode(get("period-cert")?.arg(0).map_err(HsError::Doc)?)
            .map_err(HsError::Doc)?;

        let mut intro_points = Vec::new();
        for l in lines.iter().filter(|l| l.keyword == "intro-point") {
            if intro_points.len() >= Self::MAX_INTRO_POINTS {
                return Err(HsError::TooManyIntroPoints);
            }
            let relay_id: [u8; 32] = hex_decode(l.arg(0).map_err(HsError::Doc)?)
                .map_err(HsError::Doc)?
                .try_into()
                .map_err(|_| HsError::Malformed)?;
            let onion_x25519: [u8; 32] = b64_decode(l.arg(1).map_err(HsError::Doc)?)
                .map_err(HsError::Doc)?
                .try_into()
                .map_err(|_| HsError::Malformed)?;
            let kem_arg = l.arg(2).map_err(HsError::Doc)?;
            let onion_kem = if kem_arg == "-" {
                None
            } else {
                Some(b64_decode(kem_arg).map_err(HsError::Doc)?)
            };
            let svc_x25519: [u8; 32] = b64_decode(l.arg(3).map_err(HsError::Doc)?)
                .map_err(HsError::Doc)?
                .try_into()
                .map_err(|_| HsError::Malformed)?;
            let auth_key =
                b64_decode(l.arg(4).map_err(HsError::Doc)?).map_err(HsError::Doc)?;
            intro_points.push(IntroPoint {
                relay_id,
                onion_x25519,
                onion_kem,
                svc_x25519,
                auth_key,
            });
        }
        if intro_points.is_empty() {
            return Err(HsError::NoIntroPoints);
        }
        Ok(InnerDescriptor {
            master_key,
            period_cert,
            intro_points,
        })
    }
}

// ---------------------------------------------------------------------------
// Criptarea stratului interior
// ---------------------------------------------------------------------------

/// Deriva cheile de criptare si de autentificare ale stratului interior.
///
/// Ambele depind de contorul de revizie: o revizie noua produce chei noi, deci
/// un ciphertext vechi nu poate fi reluat sub un numar de revizie mai mare.
fn inner_keys(addr: &AddrId, blinded: &BlindedId, revision: u64) -> ([u8; 32], [u8; 32]) {
    let mut k = [0u8; 64];
    kdf::hash_xof(
        b"pqonion-hs-desc-key-v1",
        &[addr, blinded, &revision.to_le_bytes()],
        &mut k,
    );
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&k[..32]);
    mac.copy_from_slice(&k[32..]);
    (enc, mac)
}

/// Ce se publica intr-o perioada.
#[derive(Debug)]
pub struct Publicare<'a> {
    pub addr: &'a OnionAddress,
    pub period: TimePeriod,
    pub revision: u64,
    pub intro_points: Vec<IntroPoint>,
    pub autorizare: &'a Autorizare,
}

/// Cine poate deschide stratul interior al unui descriptor.
///
/// # De ce exista
///
/// Fara autorizare, oricine afla adresa `.onion` poate citi descriptorul si se
/// poate conecta. Pentru multe servicii asta e chiar ce se doreste. Pentru
/// altele — un panou de administrare, un serviciu intern — adresa ajunge sa fie
/// singurul secret, iar adresele se scurg: din jurnale, din istoricul unui
/// browser, dintr-un HSDir ostil care observa cererile.
///
/// # Cum functioneaza
///
/// Cheia stratului interior nu se mai deriva din adresa, ci se alege aleator.
/// Pentru fiecare client autorizat, ea se incapsuleaza catre cheia lui publica,
/// iar rezultatul apare ca o linie `auth-client` in descriptor.
///
/// Un client incearca fiecare linie cu cheia lui privata. Cele care nu-i
/// apartin produc o cheie gresita, iar tag-ul stratului interior nu verifica.
/// **Nicio linie nu spune cui apartine**, deci descriptorul nu dezvaluie cine
/// sunt clientii autorizati.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Autorizare {
    /// Oricine cunoaste adresa poate deschide descriptorul.
    Publica,
    /// Doar posesorii cheilor de decapsulare corespunzatoare.
    Clienti(Vec<Vec<u8>>),
}

impl Autorizare {
    /// Cati clienti autorizati acceptam.
    ///
    /// Peste asta, descriptorul devine un amplificator: HSDir-ul il stocheaza si
    /// il serveste oricui il cere.
    pub const MAX_CLIENTI: usize = 64;

    /// La cati multipli rotunjim numarul de linii `auth-client`.
    ///
    /// Fara umplutura, numarul de linii ar spune oricui citeste descriptorul
    /// cati clienti are serviciul — o informatie care nu are de ce sa fie
    /// publica si care se schimba vizibil cand cineva e adaugat sau scos.
    pub const GRUPARE: usize = 8;
}

/// Deriva masca cu care se ascunde cheia interioara pentru un client.
///
/// Legata de adresa, de indexul blindat si de revizie: aceeasi pereche de chei
/// da masti diferite in perioade diferite, deci liniile `auth-client` nu se pot
/// corela intre publicari.
fn masca_client(
    ss: &[u8],
    addr: &AddrId,
    blinded: &BlindedId,
    revision: u64,
) -> [u8; INNER_KEY_LEN] {
    let mut m = [0u8; INNER_KEY_LEN];
    kdf::hash_xof(
        b"pqonion-hs-client-auth-v1",
        &[ss, addr, blinded, &revision.to_le_bytes()],
        &mut m,
    );
    m
}

/// Lungimea cheii aleatoare a stratului interior.
const INNER_KEY_LEN: usize = 32;

/// Deriva cheile de criptare si de autentificare dintr-o cheie interioara data.
///
/// Varianta publica foloseste `inner_keys`, care porneste de la adresa. Cu
/// autorizare, punctul de plecare e o cheie aleatoare pe care doar clientii
/// autorizati o pot recupera.
fn inner_keys_din(k0: &[u8; INNER_KEY_LEN]) -> ([u8; 32], [u8; 32]) {
    let mut k = [0u8; 64];
    kdf::hash_xof(b"pqonion-hs-desc-key-client-v1", &[k0], &mut k);
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&k[..32]);
    mac.copy_from_slice(&k[32..]);
    (enc, mac)
}

/// Cripteaza si autentifica: `tag ‖ ciphertext`.
///
/// Constructie encrypt-then-MAC cu SHAKE256 pe post de cifru flux si de MAC
/// cheiat. Keccak nu e vulnerabil la extensie de lungime, deci un hash cheiat
/// prin prefixare e un MAC valid — dar codarea framata din [`kdf`] o face
/// oricum neambigua.
///
/// **De inlocuit intr-o versiune de productie** cu un AEAD standard
/// (ChaCha20-Poly1305 sau AES-256-GCM). Constructia de aici e corecta dar
/// nestandardizata, deci nu beneficiaza de analiza publica.
fn seal(addr: &AddrId, blinded: &BlindedId, revision: u64, plain: &[u8]) -> Vec<u8> {
    seal_cu(inner_keys(addr, blinded, revision), plain)
}

fn seal_cu((enc, mac): ([u8; 32], [u8; 32]), plain: &[u8]) -> Vec<u8> {
    let mut ct = vec![0u8; plain.len()];
    kdf::hash_xof(b"pqonion-hs-desc-stream-v1", &[&enc], &mut ct);
    for (c, p) in ct.iter_mut().zip(plain) {
        *c ^= p;
    }
    let tag = kdf::hash(b"pqonion-hs-desc-mac-v1", &[&mac, &ct]);
    let mut out = Vec::with_capacity(TAG_LEN + ct.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    out
}

fn open(
    addr: &AddrId,
    blinded: &BlindedId,
    revision: u64,
    blob: &[u8],
) -> Result<Vec<u8>, HsError> {
    open_cu(inner_keys(addr, blinded, revision), blob)
}

fn open_cu((enc, mac): ([u8; 32], [u8; 32]), blob: &[u8]) -> Result<Vec<u8>, HsError> {
    if blob.len() < TAG_LEN {
        return Err(HsError::Malformed);
    }
    let (tag_primit, ct) = blob.split_at(TAG_LEN);
    let tag = kdf::hash(b"pqonion-hs-desc-mac-v1", &[&mac, ct]);
    // Verificare inainte de decriptare, in timp constant.
    if !bool::from(tag.ct_eq(tag_primit)) {
        return Err(HsError::BadInnerTag);
    }
    let mut plain = vec![0u8; ct.len()];
    kdf::hash_xof(b"pqonion-hs-desc-stream-v1", &[&enc], &mut plain);
    for (p, c) in plain.iter_mut().zip(ct) {
        *p ^= c;
    }
    Ok(plain)
}

// ---------------------------------------------------------------------------
// Descriptorul complet
// ---------------------------------------------------------------------------

/// Stratul exterior, asa cum il vede si il stocheaza HSDir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub blinded_id: BlindedId,
    pub period: TimePeriod,
    pub revision: u64,
    /// Cheia publica de semnare a perioadei.
    pub period_key: Vec<u8>,
    /// Cheia interioara, incapsulata catre fiecare client autorizat.
    ///
    /// Gol inseamna descriptor public: cheia se deriva din adresa. Vezi
    /// [`Autorizare`].
    pub auth_clients: Vec<Vec<u8>>,
    /// `tag ‖ ciphertext` al stratului interior.
    pub encrypted: Vec<u8>,
}

impl Descriptor {
    /// Cat de mare poate fi un descriptor. Plafoneaza memoria pe care o poate
    /// consuma un HSDir de la un singur publicator.
    pub const MAX_LEN: usize = 64 * 1024;

    fn body(&self) -> String {
        let mut b = Builder::new();
        b.line("hs-descriptor", ["1"]);
        b.line("blinded-id", [hex_encode(&self.blinded_id).as_str()]);
        b.line("period", [self.period.0.to_string().as_str()]);
        b.line("revision", [self.revision.to_string().as_str()]);
        b.line("period-key", [b64_encode(&self.period_key).as_str()]);
        // Ordinea e cea din structura, iar structura e sortata la construire:
        // altfel doua serializari ale aceluiasi descriptor ar diferi.
        for c in &self.auth_clients {
            b.line("auth-client", [b64_encode(c).as_str()]);
        }
        b.line("encrypted", [b64_encode(&self.encrypted).as_str()]);
        b.finish()
    }

    /// Construieste si semneaza un descriptor complet.
    pub fn build<S: Sig>(
        seed: &MasterSeed,
        addr: &OnionAddress,
        period: TimePeriod,
        revision: u64,
        intro_points: Vec<IntroPoint>,
    ) -> Result<String, HsError> {
        // Cheile de client nu se folosesc in varianta publica; tipul e dat doar
        // ca sa satisfaca semnatura.
        struct FaraRng;
        impl rand_core::RngCore for FaraRng {
            fn next_u32(&mut self) -> u32 {
                unreachable!("varianta publica nu consuma aleator")
            }
            fn next_u64(&mut self) -> u64 {
                unreachable!("varianta publica nu consuma aleator")
            }
            fn fill_bytes(&mut self, _: &mut [u8]) {
                unreachable!("varianta publica nu consuma aleator")
            }
            fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
                unreachable!("varianta publica nu consuma aleator")
            }
        }
        impl rand_core::CryptoRng for FaraRng {}

        Self::build_cu::<S, pqo_crypto::kem::X25519Kem>(
            seed,
            Publicare {
                addr,
                period,
                revision,
                intro_points,
                autorizare: &Autorizare::Publica,
            },
            &mut FaraRng,
        )
    }

    /// Ca [`Self::build`], dar cu autorizare de client.
    ///
    /// `K` e mecanismul de incapsulare folosit pentru cheile clientilor. Cu
    /// [`Autorizare::Publica`] nu se foloseste deloc, dar tipul trebuie dat —
    /// pretul faptului ca aceeasi functie acopera ambele cazuri.
    pub fn build_cu<S: Sig, K: pqo_crypto::kem::Kem>(
        seed: &MasterSeed,
        publicare: Publicare<'_>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<String, HsError> {
        let Publicare {
            addr,
            period,
            revision,
            intro_points,
            autorizare,
        } = publicare;
        if intro_points.is_empty() {
            return Err(HsError::NoIntroPoints);
        }
        if intro_points.len() > InnerDescriptor::MAX_INTRO_POINTS {
            return Err(HsError::TooManyIntroPoints);
        }
        let (master_sk, master_pk) = seed.identity_key::<S>();
        let (period_sk, period_pk) = seed.period_key::<S>(period);

        let cert = S::sign(&master_sk, &period_cert_body(&period_pk, period));
        let inner = InnerDescriptor {
            master_key: master_pk,
            period_cert: cert,
            intro_points,
        };

        let bid = blinded_id(addr.id(), period);
        let plain = inner.encode();

        let (auth_clients, encrypted) = match autorizare {
            Autorizare::Publica => (
                Vec::new(),
                seal(addr.id(), &bid, revision, plain.as_bytes()),
            ),
            Autorizare::Clienti(chei) => {
                if chei.is_empty() {
                    return Err(HsError::NoAuthorizedClients);
                }
                if chei.len() > Autorizare::MAX_CLIENTI {
                    return Err(HsError::TooManyAuthorizedClients);
                }

                // Cheia interioara e aleatoare, nu derivata din adresa: doar asa
                // cunoasterea adresei devine insuficienta.
                let mut k0 = [0u8; INNER_KEY_LEN];
                rand_core::RngCore::fill_bytes(rng, &mut k0);

                let mut linii = Vec::with_capacity(chei.len());
                for ek in chei {
                    let (ct, ss) = K::encapsulate(ek, rng).map_err(|_| HsError::BadClientKey)?;
                    let masca = masca_client(ss.as_bytes(), addr.id(), &bid, revision);
                    let mut linie = ct;
                    linie.extend(k0.iter().zip(masca.iter()).map(|(a, b)| a ^ b));
                    linii.push(linie);
                }

                // Umplutura pana la un multiplu, cu linii nedistinse de cele
                // reale. Fara ea, numarul de intrari ar spune cati clienti are
                // serviciul si cand se schimba lista.
                let tinta = linii.len().div_ceil(Autorizare::GRUPARE) * Autorizare::GRUPARE;
                let lungime = linii[0].len();
                while linii.len() < tinta {
                    let mut fals = vec![0u8; lungime];
                    rand_core::RngCore::fill_bytes(rng, &mut fals);
                    linii.push(fals);
                }
                // Sortarea sterge ordinea in care au fost date cheile. Fiind
                // valori aleatoare, ordinea sortata nu spune nimic despre ele.
                linii.sort();

                (linii, seal_cu(inner_keys_din(&k0), plain.as_bytes()))
            }
        };

        let d = Descriptor {
            blinded_id: bid,
            period,
            revision,
            period_key: period_pk,
            auth_clients,
            encrypted,
        };

        let body = d.body();
        let sig = S::sign(&period_sk, body.as_bytes());
        let mut b = Builder::new();
        b.line("signature", [b64_encode(&sig).as_str()]);
        Ok(body + b.as_str())
    }

    /// Parseaza stratul exterior si verifica semnatura cu cheia perioadei.
    ///
    /// Asta e tot ce poate face un HSDir: verifica autoconsistenta. Nu poate
    /// stabili ca publicatorul e cel indreptatit.
    pub fn parse_and_verify<S: Sig>(doc: &str) -> Result<Self, HsError> {
        if doc.len() > Self::MAX_LEN {
            return Err(HsError::TooLarge);
        }
        let lines = parse_lines(doc).map_err(HsError::Doc)?;
        let get = |kw: &str| -> Result<&Line, HsError> {
            lines
                .iter()
                .find(|l| l.keyword == kw)
                .ok_or(HsError::Malformed)
        };
        for kw in [
            "hs-descriptor",
            "blinded-id",
            "period",
            "revision",
            "period-key",
            "encrypted",
            "signature",
        ] {
            if lines.iter().filter(|l| l.keyword == kw).count() != 1 {
                return Err(HsError::Malformed);
            }
        }
        if get("hs-descriptor")?.arg(0).map_err(HsError::Doc)? != "1" {
            return Err(HsError::BadDescVersion);
        }
        let period_key = b64_decode(get("period-key")?.arg(0).map_err(HsError::Doc)?)
            .map_err(HsError::Doc)?;
        if period_key.len() != S::PK_LEN {
            return Err(HsError::Malformed);
        }
        let d = Descriptor {
            blinded_id: hex_decode(get("blinded-id")?.arg(0).map_err(HsError::Doc)?)
                .map_err(HsError::Doc)?
                .try_into()
                .map_err(|_| HsError::Malformed)?,
            period: TimePeriod(get("period")?.parse_arg(0).map_err(HsError::Doc)?),
            revision: get("revision")?.parse_arg(0).map_err(HsError::Doc)?,
            period_key,
            auth_clients: lines
                .iter()
                .filter(|l| l.keyword == "auth-client")
                .map(|l| {
                    b64_decode(l.arg(0).map_err(HsError::Doc)?).map_err(HsError::Doc)
                })
                .collect::<Result<Vec<_>, _>>()?,
            encrypted: b64_decode(get("encrypted")?.arg(0).map_err(HsError::Doc)?)
                .map_err(HsError::Doc)?,
        };
        // Plafon pe numarul de linii: un descriptor cu mii de intrari ar face
        // clientul sa incerce decapsularea de mii de ori.
        if d.auth_clients.len() > Autorizare::MAX_CLIENTI + Autorizare::GRUPARE {
            return Err(HsError::TooLarge);
        }

        // Verificare pe prefixul recalculat, ca in `pqo-dirproto`: orice camp pe
        // care parserul l-ar interpreta altfel decat serializatorul duce la esec.
        let asteptat = d.body();
        if asteptat != signed_prefix(doc, &["signature"]) {
            return Err(HsError::NotCanonical);
        }
        let sig = b64_decode(get("signature")?.arg(0).map_err(HsError::Doc)?)
            .map_err(HsError::Doc)?;
        S::verify(&d.period_key, asteptat.as_bytes(), &sig)
            .map_err(|_| HsError::BadSignature)?;
        Ok(d)
    }

    /// Decripteaza si valideaza stratul interior. Doar clientul poate: are nevoie
    /// de identificatorul adresei.
    ///
    /// Lantul de verificari, in ordine:
    ///   1. indexul blindat corespunde adresei si perioadei
    ///   2. tag-ul stratului criptat verifica
    ///   3. hash-ul cheii master **este** adresa
    ///   4. certificatul de perioada e semnat de master si acopera chiar cheia
    ///      cu care e semnat stratul exterior
    ///
    /// Pasii 3 si 4 sunt cei care fac impersonarea imposibila. Fara ei,
    /// descriptorul ar fi doar autoconsistent, nu autentic.
    pub fn open_inner<S: Sig>(&self, addr: &OnionAddress) -> Result<InnerDescriptor, HsError> {
        // Un descriptor cu autorizare nu poate fi deschis fara cheie. Eroarea e
        // distincta, ca un client sa poata spune „am nevoie de o cheie" in loc
        // de „descriptorul e stricat".
        if !self.auth_clients.is_empty() {
            return Err(HsError::NotAuthorized);
        }
        // Inaintea decriptarii: un descriptor din alta perioada trebuie sa
        // raporteze cauza reala, nu „tag gresit".
        let asteptat = blinded_id(addr.id(), self.period);
        if !bool::from(asteptat.ct_eq(&self.blinded_id)) {
            return Err(HsError::WrongBlindedId);
        }
        let plain = open(addr.id(), &self.blinded_id, self.revision, &self.encrypted)?;
        self.deschide::<S>(addr, plain)
    }

    /// Deschide un descriptor care cere autorizare de client.
    ///
    /// Incearca fiecare linie `auth-client` cu cheia data. Cele care nu apartin
    /// clientului produc o cheie gresita si esueaza la verificarea tag-ului —
    /// nu exista nicio indicatie in descriptor despre care linie e a cui.
    ///
    /// Costul: o decapsulare per linie. De aceea numarul de linii e plafonat la
    /// parsare.
    pub fn open_inner_autorizat<S: Sig, K: pqo_crypto::kem::Kem>(
        &self,
        addr: &OnionAddress,
        dk: &K::DecapKey,
    ) -> Result<InnerDescriptor, HsError> {
        if self.auth_clients.is_empty() {
            // Descriptor public: cheia clientului nu e necesara. Nu e o eroare
            // sa o ai oricum.
            return self.open_inner::<S>(addr);
        }
        let asteptat = blinded_id(addr.id(), self.period);
        if !bool::from(asteptat.ct_eq(&self.blinded_id)) {
            return Err(HsError::WrongBlindedId);
        }

        for linie in &self.auth_clients {
            if linie.len() <= INNER_KEY_LEN {
                continue;
            }
            let (ct, mascat) = linie.split_at(linie.len() - INNER_KEY_LEN);
            let Ok(ss) = K::decapsulate(dk, ct) else {
                continue;
            };
            let masca = masca_client(ss.as_bytes(), addr.id(), &self.blinded_id, self.revision);
            let mut k0 = [0u8; INNER_KEY_LEN];
            for (k, (m, x)) in k0.iter_mut().zip(mascat.iter().zip(masca.iter())) {
                *k = m ^ x;
            }
            // Singurul test valid: tag-ul stratului interior. ML-KEM foloseste
            // respingere implicita — decapsularea „reuseste" si cu un ciphertext
            // strain, dar da alt secret.
            if let Ok(plain) = open_cu(inner_keys_din(&k0), &self.encrypted) {
                return self.deschide::<S>(addr, plain);
            }
        }
        Err(HsError::NotAuthorized)
    }

    /// Partea comuna: verificarile care nu depind de cum s-a obtinut cheia.
    fn deschide<S: Sig>(
        &self,
        addr: &OnionAddress,
        plain: Vec<u8>,
    ) -> Result<InnerDescriptor, HsError> {
        let asteptat = blinded_id(addr.id(), self.period);
        if !bool::from(asteptat.ct_eq(&self.blinded_id)) {
            return Err(HsError::WrongBlindedId);
        }
        let s = core::str::from_utf8(&plain).map_err(|_| HsError::Malformed)?;
        let inner = InnerDescriptor::parse(s)?;

        if !addr.matches::<S>(&inner.master_key) {
            return Err(HsError::AddressMismatch);
        }
        S::verify(
            &inner.master_key,
            &period_cert_body(&self.period_key, self.period),
            &inner.period_cert,
        )
        .map_err(|_| HsError::BadPeriodCert)?;
        Ok(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqo_crypto::sig::Ed25519;

    type S = Ed25519;

    fn intro(n: u8) -> IntroPoint {
        IntroPoint {
            relay_id: [n; 32],
            onion_x25519: [n.wrapping_add(1); 32],
            onion_kem: if n % 2 == 0 { Some(vec![n; 1184]) } else { None },
            svc_x25519: [n.wrapping_add(3); 32],
            auth_key: vec![n.wrapping_add(2); 32],
        }
    }

    fn serviciu() -> (MasterSeed, OnionAddress) {
        let seed = MasterSeed::new([0x11; 32]);
        let (_sk, pk) = seed.identity_key::<S>();
        (seed, OnionAddress::from_identity::<S>(&pk))
    }

    #[test]
    fn descriptor_roundtrip() {
        let (seed, addr) = serviciu();
        let p = TimePeriod(100);
        let ips = vec![intro(1), intro(2), intro(3)];
        let doc = Descriptor::build::<S>(&seed, &addr, p, 1, ips.clone()).unwrap();

        let d = Descriptor::parse_and_verify::<S>(&doc).unwrap();
        assert_eq!(d.period, p);
        assert_eq!(d.revision, 1);

        let inner = d.open_inner::<S>(&addr).unwrap();
        assert_eq!(inner.intro_points, ips);
    }

    #[test]
    fn hsdir_nu_poate_citi_interiorul() {
        // Simulam HSDir: are doar documentul, nu si adresa.
        let (seed, addr) = serviciu();
        let doc = Descriptor::build::<S>(&seed, &addr, TimePeriod(1), 1, vec![intro(1)]).unwrap();
        let d = Descriptor::parse_and_verify::<S>(&doc).unwrap();

        // Cu o adresa gresita, nici indexul nu se potriveste.
        let (seed2, addr2) = {
            let s = MasterSeed::new([0x22; 32]);
            let (_k, pk) = s.identity_key::<S>();
            (s, OnionAddress::from_identity::<S>(&pk))
        };
        let _ = seed2;
        assert_eq!(d.open_inner::<S>(&addr2), Err(HsError::WrongBlindedId));
    }

    #[test]
    fn doua_perioade_nu_sunt_legabile_fara_adresa() {
        let (seed, addr) = serviciu();
        let d1 = Descriptor::parse_and_verify::<S>(
            &Descriptor::build::<S>(&seed, &addr, TimePeriod(1), 1, vec![intro(1)]).unwrap(),
        )
        .unwrap();
        let d2 = Descriptor::parse_and_verify::<S>(
            &Descriptor::build::<S>(&seed, &addr, TimePeriod(2), 1, vec![intro(1)]).unwrap(),
        )
        .unwrap();

        assert_ne!(d1.blinded_id, d2.blinded_id, "indecsii trebuie sa difere");
        assert_ne!(d1.period_key, d2.period_key, "cheile trebuie sa difere");
        assert_ne!(d1.encrypted, d2.encrypted, "blobul trebuie sa difere");
    }

    #[test]
    fn descriptor_fals_nu_trece_la_client() {
        // Un atacator care stie adresa publica un descriptor propriu, cu cheile
        // lui. Trece verificarea HSDir, dar nu si la client.
        let (_seed, addr) = serviciu();
        let atacator = MasterSeed::new([0xFF; 32]);
        let p = TimePeriod(50);

        // Atacatorul foloseste indexul corect (stie adresa) dar cheile lui.
        let (a_sk, a_pk) = atacator.identity_key::<S>();
        let (p_sk, p_pk) = atacator.period_key::<S>(p);
        let inner = InnerDescriptor {
            master_key: a_pk,
            period_cert: S::sign(&a_sk, &period_cert_body(&p_pk, p)),
            intro_points: vec![intro(9)],
        };
        let bid = blinded_id(addr.id(), p);
        let d = Descriptor {
            blinded_id: bid,
            period: p,
            revision: 999,
            period_key: p_pk,
            auth_clients: Vec::new(),
            encrypted: seal(addr.id(), &bid, 999, inner.encode().as_bytes()),
        };
        let body = d.body();
        let sig = S::sign(&p_sk, body.as_bytes());
        let mut b = Builder::new();
        b.line("signature", [b64_encode(&sig).as_str()]);
        let doc = body + b.as_str();

        // HSDir il accepta: e autoconsistent. Asta e regresia fata de Tor v3.
        let parsat = Descriptor::parse_and_verify::<S>(&doc).unwrap();

        // Clientul il respinge: hash-ul cheii master nu e adresa.
        assert_eq!(
            parsat.open_inner::<S>(&addr),
            Err(HsError::AddressMismatch),
            "impersonarea trebuie sa esueze la client"
        );
    }

    #[test]
    fn certificat_de_perioada_gresit_e_respins() {
        // Cineva ia un descriptor valid si inlocuieste cheia perioadei cu a lui.
        let (seed, addr) = serviciu();
        let p = TimePeriod(3);
        let (master_sk, master_pk) = seed.identity_key::<S>();
        let strain = MasterSeed::new([0x77; 32]);
        let (strain_sk, strain_pk) = strain.period_key::<S>(p);

        // Certificatul acopera cheia legitima, dar semnam cu cea straina.
        let (_leg_sk, leg_pk) = seed.period_key::<S>(p);
        let inner = InnerDescriptor {
            master_key: master_pk,
            period_cert: S::sign(&master_sk, &period_cert_body(&leg_pk, p)),
            intro_points: vec![intro(1)],
        };
        let bid = blinded_id(addr.id(), p);
        let d = Descriptor {
            blinded_id: bid,
            period: p,
            revision: 1,
            period_key: strain_pk,
            auth_clients: Vec::new(),
            encrypted: seal(addr.id(), &bid, 1, inner.encode().as_bytes()),
        };
        let body = d.body();
        let sig = S::sign(&strain_sk, body.as_bytes());
        let mut b = Builder::new();
        b.line("signature", [b64_encode(&sig).as_str()]);
        let parsat = Descriptor::parse_and_verify::<S>(&(body + b.as_str())).unwrap();

        assert_eq!(
            parsat.open_inner::<S>(&addr),
            Err(HsError::BadPeriodCert),
            "certificatul trebuie sa acopere chiar cheia care semneaza"
        );
    }

    #[test]
    fn blob_modificat_e_respins() {
        let (seed, addr) = serviciu();
        let doc = Descriptor::build::<S>(&seed, &addr, TimePeriod(1), 1, vec![intro(1)]).unwrap();
        let mut d = Descriptor::parse_and_verify::<S>(&doc).unwrap();
        let n = d.encrypted.len();
        d.encrypted[n - 1] ^= 0x01;
        assert_eq!(d.open_inner::<S>(&addr), Err(HsError::BadInnerTag));
    }

    #[test]
    fn revizia_intra_in_cheia_de_criptare() {
        // Un blob de la revizia 1 nu se poate reutiliza la revizia 2.
        let (seed, addr) = serviciu();
        let p = TimePeriod(1);
        let d1 = Descriptor::parse_and_verify::<S>(
            &Descriptor::build::<S>(&seed, &addr, p, 1, vec![intro(1)]).unwrap(),
        )
        .unwrap();
        let mut d2 = Descriptor::parse_and_verify::<S>(
            &Descriptor::build::<S>(&seed, &addr, p, 2, vec![intro(1)]).unwrap(),
        )
        .unwrap();
        d2.encrypted = d1.encrypted.clone();
        assert_eq!(d2.open_inner::<S>(&addr), Err(HsError::BadInnerTag));
    }

    #[test]
    fn semnatura_exterioara_modificata_e_respinsa() {
        let (seed, addr) = serviciu();
        let doc = Descriptor::build::<S>(&seed, &addr, TimePeriod(1), 1, vec![intro(1)]).unwrap();
        let stricat = doc.replace("revision 1", "revision 2");
        assert_eq!(
            Descriptor::parse_and_verify::<S>(&stricat),
            Err(HsError::BadSignature)
        );
    }

    #[test]
    fn fara_puncte_de_introducere_e_eroare() {
        let (seed, addr) = serviciu();
        assert_eq!(
            Descriptor::build::<S>(&seed, &addr, TimePeriod(1), 1, vec![]),
            Err(HsError::NoIntroPoints)
        );
    }

    #[test]
    fn prea_multe_puncte_de_introducere() {
        let (seed, addr) = serviciu();
        let ips: Vec<_> = (0..=InnerDescriptor::MAX_INTRO_POINTS)
            .map(|i| intro(i as u8))
            .collect();
        assert_eq!(
            Descriptor::build::<S>(&seed, &addr, TimePeriod(1), 1, ips),
            Err(HsError::TooManyIntroPoints)
        );
    }

    #[test]
    fn niciun_prefix_nu_produce_panica() {
        let (seed, addr) = serviciu();
        let doc =
            Descriptor::build::<S>(&seed, &addr, TimePeriod(1), 1, vec![intro(1), intro(2)])
                .unwrap();
        for n in 0..=doc.len() {
            if !doc.is_char_boundary(n) {
                continue;
            }
            let _ = Descriptor::parse_and_verify::<S>(&doc[..n]);
        }
    }
}

#[cfg(test)]
mod teste_autorizare {
    use super::*;
    use pqo_crypto::kem::{Kem, X25519Kem};
    use pqo_crypto::sig::Ed25519;
    use rand_core::OsRng;

    type S = Ed25519;
    type K = X25519Kem;

    fn intro(n: u8) -> IntroPoint {
        IntroPoint {
            relay_id: [n; 32],
            onion_x25519: [n; 32],
            onion_kem: None,
            svc_x25519: [n.wrapping_add(1); 32],
            auth_key: vec![n; 32],
        }
    }

    /// Serviciu, adresa, si `n` perechi de chei de client.
    fn pregateste(n: usize) -> (MasterSeed, OnionAddress, Vec<(<K as Kem>::DecapKey, Vec<u8>)>) {
        let seed = MasterSeed::random(&mut OsRng);
        let (_, pk) = seed.identity_key::<S>();
        let addr = OnionAddress::from_identity::<S>(&pk);
        let chei = (0..n).map(|_| K::keygen(&mut OsRng)).collect();
        (seed, addr, chei)
    }

    fn construieste(
        seed: &MasterSeed,
        addr: &OnionAddress,
        aut: &Autorizare,
    ) -> Descriptor {
        let doc = Descriptor::build_cu::<S, K>(
            &seed,
            Publicare {
                addr: &addr,
                period: TimePeriod(100),
                revision: 1,
                intro_points: vec![intro(1)],
                autorizare: aut,
            },
            &mut OsRng,
        )
        .expect("descriptorul trebuie construit");
        Descriptor::parse_and_verify::<S>(&doc).expect("descriptorul trebuie sa se verifice")
    }

    #[test]
    fn un_client_autorizat_deschide_descriptorul() {
        let (seed, addr, chei) = pregateste(3);
        let ek: Vec<Vec<u8>> = chei.iter().map(|(_, e)| e.clone()).collect();
        let d = construieste(&seed, &addr, &Autorizare::Clienti(ek));

        for (dk, _) in &chei {
            let inner = d
                .open_inner_autorizat::<S, K>(&addr, dk)
                .expect("clientul autorizat trebuie sa poata deschide");
            assert_eq!(inner.intro_points.len(), 1);
        }
    }

    #[test]
    fn cunoasterea_adresei_nu_mai_e_suficienta() {
        // Proprietatea centrala. Fara autorizare, oricine afla adresa citeste
        // descriptorul; adresa devine singurul secret, iar adresele se scurg.
        let (seed, addr, chei) = pregateste(2);
        let ek: Vec<Vec<u8>> = chei.iter().map(|(_, e)| e.clone()).collect();
        let d = construieste(&seed, &addr, &Autorizare::Clienti(ek));

        let e = d.open_inner::<S>(&addr).unwrap_err();
        assert_eq!(
            e,
            HsError::NotAuthorized,
            "adresa singura nu are voie sa deschida un descriptor cu autorizare"
        );
    }

    #[test]
    fn un_client_neautorizat_este_respins() {
        let (seed, addr, chei) = pregateste(2);
        let ek: Vec<Vec<u8>> = chei.iter().map(|(_, e)| e.clone()).collect();
        let d = construieste(&seed, &addr, &Autorizare::Clienti(ek));

        let (strain, _) = K::keygen(&mut OsRng);
        assert_eq!(
            d.open_inner_autorizat::<S, K>(&addr, &strain).unwrap_err(),
            HsError::NotAuthorized
        );
    }

    #[test]
    fn scoaterea_unui_client_ii_taie_accesul() {
        let (seed, addr, chei) = pregateste(3);
        let ramasi: Vec<Vec<u8>> = chei[..2].iter().map(|(_, e)| e.clone()).collect();
        let d = construieste(&seed, &addr, &Autorizare::Clienti(ramasi));

        assert!(d.open_inner_autorizat::<S, K>(&addr, &chei[0].0).is_ok());
        assert_eq!(
            d.open_inner_autorizat::<S, K>(&addr, &chei[2].0)
                .unwrap_err(),
            HsError::NotAuthorized,
            "un client scos din lista nu mai are acces la publicarea urmatoare"
        );
    }

    #[test]
    fn numarul_de_linii_nu_dezvaluie_numarul_de_clienti() {
        // Fara umplutura, cine citeste descriptorul afla cati clienti are
        // serviciul si vede cand lista se schimba.
        let (seed, addr, chei) = pregateste(Autorizare::GRUPARE);
        for n in 1..=Autorizare::GRUPARE {
            let ek: Vec<Vec<u8>> = chei[..n].iter().map(|(_, e)| e.clone()).collect();
            let d = construieste(&seed, &addr, &Autorizare::Clienti(ek));
            assert_eq!(
                d.auth_clients.len(),
                Autorizare::GRUPARE,
                "cu {n} clienti ar trebui tot {} linii",
                Autorizare::GRUPARE
            );
        }
    }

    #[test]
    fn cheia_interioara_nu_se_deriva_din_adresa() {
        // Testul criptografic, distinct de cel de politica. Chiar daca cineva ar
        // ocoli verificarea din `open_inner`, stratul interior nu trebuie sa
        // cedeze la cheile derivate din adresa — altfel autorizarea ar fi doar
        // un flag, nu o protectie.
        let (seed, addr, chei) = pregateste(2);
        let ek: Vec<Vec<u8>> = chei.iter().map(|(_, e)| e.clone()).collect();
        let d = construieste(&seed, &addr, &Autorizare::Clienti(ek));

        // Exact ce ar incerca un atacator care cunoaste doar adresa.
        assert!(
            open(addr.id(), &d.blinded_id, d.revision, &d.encrypted).is_err(),
            "cheile derivate din adresa nu au voie sa deschida stratul interior"
        );
        let derivata = inner_keys(addr.id(), &d.blinded_id, d.revision).0;
        assert!(
            open_cu(inner_keys_din(&derivata), &d.encrypted).is_err(),
            "nici trecute prin derivarea de client"
        );
    }

    #[test]
    fn descriptorii_nu_se_pot_lega_dupa_continut() {
        // Doua publicari ale aceleiasi liste dau linii diferite, pentru ca
        // incapsularea foloseste aleator proaspat. Fara asta, un HSDir care
        // primeste descriptori in perioade diferite i-ar putea lega dupa
        // continutul liniilor de autorizare.
        let (seed, addr, chei) = pregateste(3);
        let ek: Vec<Vec<u8>> = chei.iter().map(|(_, e)| e.clone()).collect();
        let a = construieste(&seed, &addr, &Autorizare::Clienti(ek.clone()));
        let b = construieste(&seed, &addr, &Autorizare::Clienti(ek));
        assert_ne!(a.auth_clients, b.auth_clients);
        // Dar ambele raman deschizabile.
        assert!(a.open_inner_autorizat::<S, K>(&addr, &chei[0].0).is_ok());
        assert!(b.open_inner_autorizat::<S, K>(&addr, &chei[0].0).is_ok());
    }

    #[test]
    fn umplutura_nu_se_distinge_de_liniile_reale() {
        let (seed, addr, chei) = pregateste(3);
        let ek: Vec<Vec<u8>> = chei.iter().map(|(_, e)| e.clone()).collect();
        let d = construieste(&seed, &addr, &Autorizare::Clienti(ek));
        let lungimi: std::collections::HashSet<usize> =
            d.auth_clients.iter().map(|l| l.len()).collect();
        assert_eq!(
            lungimi.len(),
            1,
            "toate liniile trebuie sa aiba aceeasi lungime"
        );
    }

    #[test]
    fn cheia_de_client_functioneaza_si_pe_un_descriptor_public() {
        // Un client cu cheie nu trebuie sa esueze pe un serviciu care nu cere
        // autorizare.
        let (seed, addr, chei) = pregateste(1);
        let d = construieste(&seed, &addr, &Autorizare::Publica);
        assert!(d.auth_clients.is_empty());
        assert!(d.open_inner_autorizat::<S, K>(&addr, &chei[0].0).is_ok());
    }

    #[test]
    fn autorizare_fara_clienti_e_refuzata() {
        let (seed, addr, _) = pregateste(0);
        let e = Descriptor::build_cu::<S, K>(
            &seed,
            Publicare {
                addr: &addr,
                period: TimePeriod(1),
                revision: 1,
                intro_points: vec![intro(1)],
                autorizare: &Autorizare::Clienti(Vec::new()),
            },
            &mut OsRng,
            )
        .unwrap_err();
        assert_eq!(e, HsError::NoAuthorizedClients);
    }

    #[test]
    fn prea_multi_clienti_sunt_refuzati() {
        let (seed, addr, chei) = pregateste(1);
        let multi = vec![chei[0].1.clone(); Autorizare::MAX_CLIENTI + 1];
        let e = Descriptor::build_cu::<S, K>(
            &seed,
            Publicare {
                addr: &addr,
                period: TimePeriod(1),
                revision: 1,
                intro_points: vec![intro(1)],
                autorizare: &Autorizare::Clienti(multi),
            },
            &mut OsRng,
            )
        .unwrap_err();
        assert_eq!(e, HsError::TooManyAuthorizedClients);
    }

    #[test]
    fn descriptorul_ramane_canonic() {
        // Liniile `auth-client` fac parte din corpul semnat, deci parsarea si
        // serializarea trebuie sa dea acelasi text.
        let (seed, addr, chei) = pregateste(3);
        let ek: Vec<Vec<u8>> = chei.iter().map(|(_, e)| e.clone()).collect();
        let doc = Descriptor::build_cu::<S, K>(
            &seed,
            Publicare {
                addr: &addr,
                period: TimePeriod(7),
                revision: 2,
                intro_points: vec![intro(1), intro(2)],
                autorizare: &Autorizare::Clienti(ek),
            },
            &mut OsRng,
            )
        .unwrap();
        let d = Descriptor::parse_and_verify::<S>(&doc).expect("trebuie sa se verifice");
        assert_eq!(d.auth_clients.len(), Autorizare::GRUPARE);
    }

    #[test]
    fn o_linie_modificata_nu_trece_de_semnatura() {
        let (seed, addr, chei) = pregateste(2);
        let ek: Vec<Vec<u8>> = chei.iter().map(|(_, e)| e.clone()).collect();
        let doc = Descriptor::build_cu::<S, K>(
            &seed,
            Publicare {
                addr: &addr,
                period: TimePeriod(7),
                revision: 1,
                intro_points: vec![intro(1)],
                autorizare: &Autorizare::Clienti(ek),
            },
            &mut OsRng,
            )
        .unwrap();
        // Schimbam un caracter dintr-o linie `auth-client`.
        let i = doc.find("auth-client ").expect("linie prezenta") + 12;
        let mut stricat = doc.clone();
        let c = if stricat.as_bytes()[i] == b'A' { 'B' } else { 'A' };
        stricat.replace_range(i..i + 1, &c.to_string());
        assert!(
            Descriptor::parse_and_verify::<S>(&stricat).is_err(),
            "liniile de autorizare sunt acoperite de semnatura"
        );
    }
}
