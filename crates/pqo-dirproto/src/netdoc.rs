//! Documentele sistemului de director.
//!
//! Trei tipuri, in ordinea in care circula:
//!
//!   1. [`RelayDescriptor`] — un releu isi descrie cheile si adresa, semnat de el
//!   2. [`Vote`] — o autoritate spune ce relee vede si cu ce proprietati
//!   3. [`Consensus`] — fuziunea deterministica a voturilor, semnata de mai multe
//!      autoritati
//!
//! # Ce semneaza fiecare
//!
//! Semnatura acopera **prefixul** documentului, adica tot ce e inainte de prima
//! linie de semnatura. Asta permite mai multe semnaturi pe acelasi consens fara
//! ca ele sa se acopere reciproc.

use pqo_crypto::sig::Sig;

use crate::doc::{b64_decode, b64_encode, hex_decode, hex_encode, parse_lines, signed_prefix, Builder, Line};
use crate::DirError;

/// Fingerprint-ul unui nod: SHAKE256 al cheii sale publice de identitate.
pub type Fingerprint = [u8; 32];

/// Calculeaza fingerprint-ul unei chei publice.
pub fn fingerprint(pk: &[u8]) -> Fingerprint {
    pqo_crypto::kdf::hash(b"pqonion-fingerprint-v1", &[pk])
}

/// Flag-urile pe care le poate avea un releu in consens.
///
/// Ordinea din acest tablou e si ordinea canonica in care se scriu. Nu o
/// schimba fara sa schimbi versiunea documentului.
pub const ALL_FLAGS: [&str; 6] = ["Exit", "Fast", "Guard", "HSDir", "Stable", "Valid"];

/// Un set de flag-uri, reprezentat ca masca de biti peste [`ALL_FLAGS`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Flags(pub u16);

impl Flags {
    pub fn has(self, name: &str) -> bool {
        ALL_FLAGS
            .iter()
            .position(|f| *f == name)
            .is_some_and(|i| self.0 & (1 << i) != 0)
    }

    pub fn set(&mut self, name: &str) -> Result<(), DirError> {
        let i = ALL_FLAGS
            .iter()
            .position(|f| *f == name)
            .ok_or(DirError::UnknownFlag)?;
        self.0 |= 1 << i;
        Ok(())
    }

    /// Numele flag-urilor, in ordine canonica.
    pub fn names(self) -> Vec<&'static str> {
        ALL_FLAGS
            .iter()
            .enumerate()
            .filter(|(i, _)| self.0 & (1 << i) != 0)
            .map(|(_, n)| *n)
            .collect()
    }

    pub fn from_names<'a>(it: impl IntoIterator<Item = &'a str>) -> Result<Self, DirError> {
        let mut f = Flags::default();
        for n in it {
            f.set(n)?;
        }
        Ok(f)
    }
}

// ---------------------------------------------------------------------------
// Descriptorul de releu
// ---------------------------------------------------------------------------

/// Ce publica un releu despre sine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayDescriptor {
    /// Cheia publica de identitate (schema depinde de `S` la semnare).
    pub identity: Vec<u8>,
    /// Cheia statica X25519 pentru `pq-ntor`.
    pub onion_x25519: [u8; 32],
    /// Cheia KEM statica, prezenta doar daca releul suporta `Variant::FullPq`.
    pub onion_kem: Option<Vec<u8>>,
    pub address: String,
    pub or_port: u16,
    /// Banda auto-raportata. Vezi nota din `pqo-dirauth` despre de ce nu poti
    /// avea incredere in ea.
    pub bandwidth: u64,
    /// Porturile pe care releul accepta iesire. Gol inseamna ca nu e exit.
    ///
    /// Autoritatea nu poate atribui flag-ul `Exit` fara informatia asta, iar un
    /// client care alege un releu fara politica de iesire ca ultim hop ar
    /// construi un circuit inutilizabil.
    pub exit_ports: Vec<u16>,
    pub published: u64,
}

impl RelayDescriptor {
    pub fn fingerprint(&self) -> Fingerprint {
        fingerprint(&self.identity)
    }

    /// Serializeaza partea semnabila.
    fn body(&self) -> String {
        let mut b = Builder::new();
        b.line("relay-descriptor", ["1"]);
        b.line("identity", [b64_encode(&self.identity).as_str()]);
        b.line("onion-x25519", [b64_encode(&self.onion_x25519).as_str()]);
        if let Some(k) = &self.onion_kem {
            b.line("onion-kem", [b64_encode(k).as_str()]);
        }
        b.line(
            "address",
            [self.address.as_str(), self.or_port.to_string().as_str()],
        );
        b.line("bandwidth", [self.bandwidth.to_string().as_str()]);
        // Lista se scrie mereu, ca sa nu depinda forma canonica de continut.
        // `-` inseamna „niciun port", nu „linie lipsa".
        let porturi = if self.exit_ports.is_empty() {
            "-".to_string()
        } else {
            self.exit_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        b.line("exit-ports", [porturi.as_str()]);
        b.line("published", [self.published.to_string().as_str()]);
        b.finish()
    }

    /// Semneaza descriptorul cu cheia de identitate a releului.
    pub fn sign<S: Sig>(&self, sk: &S::SecretKey) -> String {
        let body = self.body();
        let sig = S::sign(sk, body.as_bytes());
        let mut b = Builder::new();
        b.line("signature", [b64_encode(&sig).as_str()]);
        body + b.as_str()
    }

    /// Parseaza si verifica un descriptor semnat.
    ///
    /// Verificarea foloseste cheia din chiar documentul parsat: descriptorul e
    /// autosemnat. Legarea de o identitate de incredere se face in alta parte,
    /// prin consens.
    pub fn parse_and_verify<S: Sig>(doc: &str) -> Result<Self, DirError> {
        let lines = parse_lines(doc)?;
        let get = |kw: &str| -> Result<&Line, DirError> {
            lines
                .iter()
                .find(|l| l.keyword == kw)
                .ok_or(DirError::Missing)
        };
        // Fiecare cuvant cheie apare cel mult o data: altfel un atacator ar
        // putea adauga o a doua linie pe care parserul o ignora dar semnatura
        // o acopera, sau invers.
        for kw in [
            "relay-descriptor",
            "identity",
            "onion-x25519",
            "onion-kem",
            "address",
            "bandwidth",
            "exit-ports",
            "published",
            "signature",
        ] {
            if lines.iter().filter(|l| l.keyword == kw).count() > 1 {
                return Err(DirError::Duplicate);
            }
        }
        if get("relay-descriptor")?.arg(0)? != "1" {
            return Err(DirError::BadVersion);
        }

        let identity = b64_decode(get("identity")?.arg(0)?)?;
        if identity.len() != S::PK_LEN {
            return Err(DirError::Malformed);
        }
        let x = b64_decode(get("onion-x25519")?.arg(0)?)?;
        let onion_x25519: [u8; 32] = x.try_into().map_err(|_| DirError::Malformed)?;
        let onion_kem = match lines.iter().find(|l| l.keyword == "onion-kem") {
            Some(l) => Some(b64_decode(l.arg(0)?)?),
            None => None,
        };
        let addr_line = get("address")?;
        let d = RelayDescriptor {
            identity,
            onion_x25519,
            onion_kem,
            address: addr_line.arg(0)?.to_string(),
            or_port: addr_line.parse_arg(1)?,
            bandwidth: get("bandwidth")?.parse_arg(0)?,
            exit_ports: {
                let v = get("exit-ports")?.arg(0)?;
                if v == "-" {
                    Vec::new()
                } else {
                    v.split(',')
                        .map(|p| p.parse().map_err(|_| DirError::Malformed))
                        .collect::<Result<Vec<u16>, _>>()?
                }
            },
            published: get("published")?.parse_arg(0)?,
        };

        // Verificarea semnaturii se face pe prefixul recalculat, nu pe textul
        // primit. Astfel, orice camp pe care parserul nu-l intelege sau il
        // normalizeaza altfel duce la esec, nu la acceptare tacita.
        let sig = b64_decode(get("signature")?.arg(0)?)?;
        let asteptat = d.body();
        if asteptat != signed_prefix(doc, &["signature"]) {
            return Err(DirError::NotCanonical);
        }
        S::verify(&d.identity, asteptat.as_bytes(), &sig).map_err(|_| DirError::BadSignature)?;
        Ok(d)
    }
}

// ---------------------------------------------------------------------------
// Statusul unui releu, asa cum apare intr-un vot sau consens
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStatus {
    pub fingerprint: Fingerprint,
    pub address: String,
    pub or_port: u16,
    pub bandwidth: u64,
    pub flags: Flags,
    /// Adevarat daca releul a publicat o cheie KEM statica.
    pub pq_full: bool,
}

impl RelayStatus {
    fn write(&self, b: &mut Builder) {
        let fp = hex_encode(&self.fingerprint);
        let port = self.or_port.to_string();
        let bw = self.bandwidth.to_string();
        let mut args: Vec<&str> = vec![
            fp.as_str(),
            self.address.as_str(),
            port.as_str(),
            bw.as_str(),
            if self.pq_full { "pq=full" } else { "pq=trans" },
        ];
        let names = self.flags.names();
        args.extend(names.iter().copied());
        b.line("r", args);
    }

    fn read(l: &Line) -> Result<Self, DirError> {
        let fp = hex_decode(l.arg(0)?)?;
        let pq = match l.arg(4)? {
            "pq=full" => true,
            "pq=trans" => false,
            _ => return Err(DirError::Malformed),
        };
        let flags = Flags::from_names(l.args.iter().skip(5).map(|s| s.as_str()))?;
        // Flag-urile trebuie sa fie in ordine canonica si fara repetari.
        let canonic: Vec<&str> = flags.names();
        let primite: Vec<&str> = l.args.iter().skip(5).map(|s| s.as_str()).collect();
        if canonic != primite {
            return Err(DirError::NotCanonical);
        }
        Ok(RelayStatus {
            fingerprint: fp.try_into().map_err(|_| DirError::Malformed)?,
            address: l.arg(1)?.to_string(),
            or_port: l.parse_arg(2)?,
            bandwidth: l.parse_arg(3)?,
            flags,
            pq_full: pq,
        })
    }
}

// ---------------------------------------------------------------------------
// Perioada de valabilitate
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    pub valid_after: u64,
    pub fresh_until: u64,
    pub valid_until: u64,
}

impl Validity {
    fn check(&self) -> Result<(), DirError> {
        if self.valid_after < self.fresh_until && self.fresh_until <= self.valid_until {
            Ok(())
        } else {
            Err(DirError::BadValidity)
        }
    }

    fn write(&self, b: &mut Builder) {
        b.line("valid-after", [self.valid_after.to_string().as_str()]);
        b.line("fresh-until", [self.fresh_until.to_string().as_str()]);
        b.line("valid-until", [self.valid_until.to_string().as_str()]);
    }
}

// ---------------------------------------------------------------------------
// Vot
// ---------------------------------------------------------------------------

/// Ce trimite o autoritate celorlalte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    /// Cheia publica de semnare a autoritatii.
    pub authority: Vec<u8>,
    pub validity: Validity,
    /// Parametri de retea, sortati dupa nume.
    pub params: Vec<(String, i64)>,
    /// Statusuri, sortate dupa fingerprint.
    pub relays: Vec<RelayStatus>,
}

impl Vote {
    pub fn authority_fp(&self) -> Fingerprint {
        fingerprint(&self.authority)
    }

    /// Aduce documentul in forma canonica: sortari si eliminarea duplicatelor.
    pub fn canonicalize(&mut self) {
        self.params.sort_by(|a, b| a.0.cmp(&b.0));
        self.params.dedup_by(|a, b| a.0 == b.0);
        self.relays.sort_by_key(|r| r.fingerprint);
        self.relays.dedup_by_key(|r| r.fingerprint);
    }

    fn body(&self) -> String {
        let mut b = Builder::new();
        b.line("vote", ["1"]);
        b.line("authority", [b64_encode(&self.authority).as_str()]);
        self.validity.write(&mut b);
        for (k, v) in &self.params {
            b.line("param", [format!("{k}={v}").as_str()]);
        }
        for r in &self.relays {
            r.write(&mut b);
        }
        b.finish()
    }

    pub fn sign<S: Sig>(&self, sk: &S::SecretKey) -> String {
        let body = self.body();
        let sig = S::sign(sk, body.as_bytes());
        let mut b = Builder::new();
        b.line("signature", [b64_encode(&sig).as_str()]);
        body + b.as_str()
    }

    pub fn parse_and_verify<S: Sig>(doc: &str) -> Result<Self, DirError> {
        let lines = parse_lines(doc)?;
        let get = |kw: &str| -> Result<&Line, DirError> {
            lines
                .iter()
                .find(|l| l.keyword == kw)
                .ok_or(DirError::Missing)
        };
        if get("vote")?.arg(0)? != "1" {
            return Err(DirError::BadVersion);
        }
        let authority = b64_decode(get("authority")?.arg(0)?)?;
        if authority.len() != S::PK_LEN {
            return Err(DirError::Malformed);
        }
        let validity = Validity {
            valid_after: get("valid-after")?.parse_arg(0)?,
            fresh_until: get("fresh-until")?.parse_arg(0)?,
            valid_until: get("valid-until")?.parse_arg(0)?,
        };
        validity.check()?;

        let mut params = Vec::new();
        for l in lines.iter().filter(|l| l.keyword == "param") {
            let s = l.arg(0)?;
            let (k, v) = s.split_once('=').ok_or(DirError::Malformed)?;
            if k.is_empty() {
                return Err(DirError::Malformed);
            }
            params.push((k.to_string(), v.parse().map_err(|_| DirError::Malformed)?));
        }
        let relays: Result<Vec<_>, _> = lines
            .iter()
            .filter(|l| l.keyword == "r")
            .map(RelayStatus::read)
            .collect();

        let v = Vote {
            authority,
            validity,
            params,
            relays: relays?,
        };

        let sig = b64_decode(get("signature")?.arg(0)?)?;
        let asteptat = v.body();
        if asteptat != signed_prefix(doc, &["signature"]) {
            return Err(DirError::NotCanonical);
        }
        S::verify(&v.authority, asteptat.as_bytes(), &sig).map_err(|_| DirError::BadSignature)?;
        Ok(v)
    }
}

// ---------------------------------------------------------------------------
// Consens
// ---------------------------------------------------------------------------

/// Rezultatul fuziunii voturilor. Semnat de mai multe autoritati.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consensus {
    pub validity: Validity,
    pub params: Vec<(String, i64)>,
    pub relays: Vec<RelayStatus>,
    /// `(fingerprint autoritate, semnatura)`, sortate dupa fingerprint.
    pub signatures: Vec<(Fingerprint, Vec<u8>)>,
}

impl Consensus {
    /// Partea semnata: tot pana la prima `authority-signature`.
    pub fn body(&self) -> String {
        let mut b = Builder::new();
        b.line("consensus", ["1"]);
        self.validity.write(&mut b);
        for (k, v) in &self.params {
            b.line("param", [format!("{k}={v}").as_str()]);
        }
        for r in &self.relays {
            r.write(&mut b);
        }
        b.finish()
    }

    /// Adauga semnatura unei autoritati.
    pub fn add_signature<S: Sig>(&mut self, authority_pk: &[u8], sk: &S::SecretKey) {
        let sig = S::sign(sk, self.body().as_bytes());
        self.signatures.push((fingerprint(authority_pk), sig));
        self.signatures.sort_by_key(|(fp, _)| *fp);
        self.signatures.dedup_by_key(|(fp, _)| *fp);
    }

    pub fn encode(&self) -> String {
        let mut b = Builder::new();
        for (fp, sig) in &self.signatures {
            b.line(
                "authority-signature",
                [hex_encode(fp).as_str(), b64_encode(sig).as_str()],
            );
        }
        self.body() + b.as_str()
    }

    /// Parseaza un consens si verifica pragul de semnaturi.
    ///
    /// `authorities` e lista cheilor publice ale autoritatilor pe care clientul
    /// le are cablate in binar. Consensul e acceptat daca **mai mult de
    /// jumatate** dintre ele au semnat valid. Semnaturile de la chei
    /// necunoscute se ignora, nu invalideaza documentul.
    pub fn parse_and_verify<S: Sig>(doc: &str, authorities: &[Vec<u8>]) -> Result<Self, DirError> {
        if authorities.is_empty() {
            return Err(DirError::NoAuthorities);
        }
        let lines = parse_lines(doc)?;
        let get = |kw: &str| -> Result<&Line, DirError> {
            lines
                .iter()
                .find(|l| l.keyword == kw)
                .ok_or(DirError::Missing)
        };
        if get("consensus")?.arg(0)? != "1" {
            return Err(DirError::BadVersion);
        }
        let validity = Validity {
            valid_after: get("valid-after")?.parse_arg(0)?,
            fresh_until: get("fresh-until")?.parse_arg(0)?,
            valid_until: get("valid-until")?.parse_arg(0)?,
        };
        validity.check()?;

        let mut params = Vec::new();
        for l in lines.iter().filter(|l| l.keyword == "param") {
            let (k, v) = l.arg(0)?.split_once('=').ok_or(DirError::Malformed)?;
            params.push((k.to_string(), v.parse().map_err(|_| DirError::Malformed)?));
        }
        let relays: Result<Vec<_>, _> = lines
            .iter()
            .filter(|l| l.keyword == "r")
            .map(RelayStatus::read)
            .collect();

        let mut signatures = Vec::new();
        for l in lines.iter().filter(|l| l.keyword == "authority-signature") {
            let fp: Fingerprint = hex_decode(l.arg(0)?)?
                .try_into()
                .map_err(|_| DirError::Malformed)?;
            signatures.push((fp, b64_decode(l.arg(1)?)?));
        }

        let c = Consensus {
            validity,
            params,
            relays: relays?,
            signatures,
        };

        let body = c.body();
        if body != signed_prefix(doc, &["authority-signature"]) {
            return Err(DirError::NotCanonical);
        }

        let mut valide = 0usize;
        for pk in authorities {
            let fp = fingerprint(pk);
            if let Some((_, sig)) = c.signatures.iter().find(|(f, _)| *f == fp) {
                if S::verify(pk, body.as_bytes(), sig).is_ok() {
                    valide += 1;
                }
            }
        }
        if valide * 2 <= authorities.len() {
            return Err(DirError::NotEnoughSignatures {
                got: valide,
                need: authorities.len() / 2 + 1,
            });
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqo_crypto::sig::Ed25519;
    use rand_core::OsRng;

    type S = Ed25519;

    fn descriptor(seed: u8, pk: Vec<u8>) -> RelayDescriptor {
        RelayDescriptor {
            identity: pk,
            onion_x25519: [seed; 32],
            onion_kem: if seed % 2 == 0 {
                Some(vec![seed; 1184])
            } else {
                None
            },
            address: format!("10.0.0.{seed}"),
            or_port: 9001,
            bandwidth: 1000 * seed as u64,
            exit_ports: if seed % 2 == 0 { vec![80, 443] } else { Vec::new() },
            published: 1_700_000_000,
        }
    }

    #[test]
    fn descriptor_roundtrip() {
        let mut rng = OsRng;
        let (sk, pk) = S::keygen(&mut rng);
        let d = descriptor(2, pk);
        let doc = d.sign::<S>(&sk);
        assert_eq!(RelayDescriptor::parse_and_verify::<S>(&doc).unwrap(), d);
    }

    #[test]
    fn descriptor_modificat_e_respins() {
        let mut rng = OsRng;
        let (sk, pk) = S::keygen(&mut rng);
        let doc = descriptor(3, pk).sign::<S>(&sk);
        let stricat = doc.replace("bandwidth 3000", "bandwidth 9999999");
        assert_ne!(doc, stricat);
        assert_eq!(
            RelayDescriptor::parse_and_verify::<S>(&stricat),
            Err(DirError::BadSignature)
        );
    }

    #[test]
    fn descriptor_cu_linii_duplicate_e_respins() {
        let mut rng = OsRng;
        let (sk, pk) = S::keygen(&mut rng);
        let doc = descriptor(1, pk).sign::<S>(&sk);
        let stricat = doc.replace("bandwidth 1000\n", "bandwidth 1000\nbandwidth 5\n");
        assert_eq!(
            RelayDescriptor::parse_and_verify::<S>(&stricat),
            Err(DirError::Duplicate)
        );
    }

    fn vot(auth: Vec<u8>, n: usize) -> Vote {
        let mut v = Vote {
            authority: auth,
            validity: Validity {
                valid_after: 1000,
                fresh_until: 4600,
                valid_until: 11800,
            },
            params: vec![("circwindow".into(), 1000), ("bwweightscale".into(), 10000)],
            relays: (0..n)
                .map(|i| RelayStatus {
                    fingerprint: [i as u8; 32],
                    address: format!("10.0.0.{i}"),
                    or_port: 9001,
                    bandwidth: 100 * (i as u64 + 1),
                    flags: Flags::from_names(["Fast", "Valid"]).unwrap(),
                    pq_full: i % 2 == 0,
                })
                .collect(),
        };
        v.canonicalize();
        v
    }

    #[test]
    fn vot_roundtrip() {
        let mut rng = OsRng;
        let (sk, pk) = S::keygen(&mut rng);
        let v = vot(pk, 5);
        let doc = v.sign::<S>(&sk);
        assert_eq!(Vote::parse_and_verify::<S>(&doc).unwrap(), v);
    }

    #[test]
    fn flagurile_trebuie_sa_fie_in_ordine_canonica() {
        let mut rng = OsRng;
        let (sk, pk) = S::keygen(&mut rng);
        let doc = vot(pk, 2).sign::<S>(&sk);
        // "Fast Valid" -> "Valid Fast": aceeasi informatie, alta forma.
        let stricat = doc.replace("Fast Valid", "Valid Fast");
        assert_eq!(
            Vote::parse_and_verify::<S>(&stricat),
            Err(DirError::NotCanonical)
        );
    }

    #[test]
    fn valabilitate_inconsistenta_e_respinsa() {
        let mut rng = OsRng;
        let (sk, pk) = S::keygen(&mut rng);
        let mut v = vot(pk, 1);
        v.validity.fresh_until = 500; // inainte de valid_after
        let doc = v.sign::<S>(&sk);
        assert_eq!(
            Vote::parse_and_verify::<S>(&doc),
            Err(DirError::BadValidity)
        );
    }

    fn consens(n_relee: usize) -> Consensus {
        Consensus {
            validity: Validity {
                valid_after: 1000,
                fresh_until: 4600,
                valid_until: 11800,
            },
            params: vec![("circwindow".into(), 1000)],
            relays: (0..n_relee)
                .map(|i| RelayStatus {
                    fingerprint: [i as u8; 32],
                    address: format!("10.0.0.{i}"),
                    or_port: 9001,
                    bandwidth: 500,
                    flags: Flags::from_names(["Guard", "Valid"]).unwrap(),
                    pq_full: true,
                })
                .collect(),
            signatures: Vec::new(),
        }
    }

    #[test]
    fn consens_cu_prag_indeplinit() {
        let mut rng = OsRng;
        let chei: Vec<_> = (0..5).map(|_| S::keygen(&mut rng)).collect();
        let publice: Vec<Vec<u8>> = chei.iter().map(|(_, p)| p.clone()).collect();

        let mut c = consens(3);
        for (sk, pk) in chei.iter().take(3) {
            c.add_signature::<S>(pk, sk);
        }
        let doc = c.encode();
        let parsat = Consensus::parse_and_verify::<S>(&doc, &publice).unwrap();
        assert_eq!(parsat.relays.len(), 3);
        assert_eq!(parsat.signatures.len(), 3);
    }

    #[test]
    fn consens_sub_prag_e_respins() {
        let mut rng = OsRng;
        let chei: Vec<_> = (0..5).map(|_| S::keygen(&mut rng)).collect();
        let publice: Vec<Vec<u8>> = chei.iter().map(|(_, p)| p.clone()).collect();

        let mut c = consens(2);
        for (sk, pk) in chei.iter().take(2) {
            c.add_signature::<S>(pk, sk);
        }
        assert_eq!(
            Consensus::parse_and_verify::<S>(&c.encode(), &publice),
            Err(DirError::NotEnoughSignatures { got: 2, need: 3 })
        );
    }

    #[test]
    fn semnaturile_de_la_chei_necunoscute_nu_conteaza() {
        let mut rng = OsRng;
        let chei: Vec<_> = (0..3).map(|_| S::keygen(&mut rng)).collect();
        let publice: Vec<Vec<u8>> = chei.iter().map(|(_, p)| p.clone()).collect();
        let (sk_strain, pk_strain) = S::keygen(&mut rng);

        let mut c = consens(1);
        c.add_signature::<S>(&chei[0].1, &chei[0].0);
        c.add_signature::<S>(&pk_strain, &sk_strain);
        // 1 semnatura cunoscuta din 3 autoritati: sub prag, chiar daca sunt 2 in document.
        assert!(matches!(
            Consensus::parse_and_verify::<S>(&c.encode(), &publice),
            Err(DirError::NotEnoughSignatures { got: 1, .. })
        ));
    }

    #[test]
    fn corpul_modificat_invalideaza_toate_semnaturile() {
        let mut rng = OsRng;
        let chei: Vec<_> = (0..3).map(|_| S::keygen(&mut rng)).collect();
        let publice: Vec<Vec<u8>> = chei.iter().map(|(_, p)| p.clone()).collect();

        let mut c = consens(2);
        for (sk, pk) in &chei {
            c.add_signature::<S>(pk, sk);
        }
        let stricat = c.encode().replace("10.0.0.0", "10.0.0.9");
        assert!(matches!(
            Consensus::parse_and_verify::<S>(&stricat, &publice),
            Err(DirError::NotEnoughSignatures { got: 0, .. })
        ));
    }

    #[test]
    fn niciun_prefix_nu_produce_panica() {
        let mut rng = OsRng;
        let (sk, pk) = S::keygen(&mut rng);
        let publice = vec![pk.clone()];
        let docs = [
            descriptor(1, pk.clone()).sign::<S>(&sk),
            vot(pk.clone(), 3).sign::<S>(&sk),
            {
                let mut c = consens(2);
                c.add_signature::<S>(&pk, &sk);
                c.encode()
            },
        ];
        for d in &docs {
            for n in 0..=d.len() {
                let s = &d[..n];
                if !s.is_char_boundary(n) {
                    continue;
                }
                let _ = RelayDescriptor::parse_and_verify::<S>(s);
                let _ = Vote::parse_and_verify::<S>(s);
                let _ = Consensus::parse_and_verify::<S>(s, &publice);
            }
        }
    }
}
