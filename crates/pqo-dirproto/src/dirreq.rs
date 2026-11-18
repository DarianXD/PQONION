//! Cereri de director, servite printr-un circuit.
//!
//! # De ce prin circuit si nu direct
//!
//! Un client are nevoie de descriptorii releelor pe care le-a ales. Daca i-ar
//! cere direct unei autoritati, aceasta ar afla exact ce relee il intereseaza —
//! adica primul si al treilea hop al circuitului pe care urmeaza sa il
//! construiasca. Ar fi suficient ca o autoritate sa fie curioasa ca sa
//! dezanonimizeze clientii.
//!
//! De aceea cererile merg printr-un circuit deja construit, catre releul de la
//! capat. Releul vede ce se cere, dar nu si cine cere.
//!
//! # Format binar, nu text
//!
//! Spre deosebire de documentele propriu-zise, care sunt text canonic ca sa poata
//! fi semnate identic de mai multe autoritati, cererile sunt binare cu campuri
//! fixe. Nu se semneaza niciodata, deci canonicitatea nu conteaza; in schimb
//! conteaza sa nu existe ambiguitate de parsare intr-un mesaj care vine de la un
//! peer neautentificat.

use crate::netdoc::Fingerprint;
use crate::DirError;

/// Cea mai mare cerere de citire. Astea sunt minuscule; orice peste atat e o
/// incercare de a face releul sa aloce memorie degeaba.
pub const MAX_REQUEST_LEN: usize = 64;

/// Cel mai mare document acceptat la publicare.
///
/// Un descriptor de releu cu chei ML-DSA ajunge la cativa kiloocteti; unul de
/// serviciu ascuns cu 20 de puncte de introducere, la zeci. 128 KB lasa marja si
/// plafoneaza cat poate incarca un peer neautentificat.
pub const MAX_UPLOAD_LEN: usize = 128 * 1024;

/// Cel mai mare raspuns acceptat.
///
/// Un consens cu cateva mii de relee si semnaturi ML-DSA ajunge la sute de
/// kiloocteti; 4 MB lasa marja fara sa permita epuizarea memoriei clientului.
pub const MAX_RESPONSE_LEN: usize = 4 * 1024 * 1024;

const KIND_CONSENSUS: u8 = 1;
const KIND_DESCRIPTOR: u8 = 2;
const KIND_PUBLISH: u8 = 3;
const KIND_HS_UPLOAD: u8 = 4;
const KIND_HS_FETCH: u8 = 5;

/// Ce cere clientul.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirRequest {
    /// Consensul curent.
    Consensus,
    /// Descriptorul unui releu anume.
    Descriptor(Fingerprint),
    /// Un releu isi publica descriptorul.
    ///
    /// Nu e autentificat separat: descriptorul e autosemnat, iar destinatarul il
    /// verifica inainte sa il accepte. Cine trimite nu conteaza.
    Publish(Vec<u8>),
    /// Un serviciu ascuns isi incarca descriptorul la un HSDir.
    HsUpload(Vec<u8>),
    /// Un client cere descriptorul unui serviciu ascuns, dupa index blindat.
    HsFetch([u8; 32]),
}

impl DirRequest {
    /// Serializeaza cu prefix de lungime, pentru transport pe stream.
    ///
    /// Cererile de publicare pot depasi cu mult o celula: un descriptor de
    /// serviciu ascuns are cateva kiloocteti. Fara prefix, destinatarul ar
    /// interpreta fiecare bucata ca pe o cerere completa — ceea ce se manifesta
    /// exact ca „HSDir-ul refuza descriptorul", cu cauza la trei straturi
    /// distanta.
    pub fn encode_framed(&self) -> Vec<u8> {
        let corp = self.encode();
        let mut v = Vec::with_capacity(4 + corp.len());
        v.extend_from_slice(&(corp.len() as u32).to_be_bytes());
        v.extend_from_slice(&corp);
        v
    }

    /// Cati octeti anunta prefixul, daca prefixul e complet.
    pub fn framed_len(buf: &[u8]) -> Option<Result<usize, DirError>> {
        if buf.len() < 4 {
            return None;
        }
        let n = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if n > MAX_UPLOAD_LEN {
            return Some(Err(DirError::Malformed));
        }
        Some(Ok(4 + n))
    }

    /// Parseaza o cerere cu prefix de lungime.
    pub fn parse_framed(buf: &[u8]) -> Result<Self, DirError> {
        let total = match Self::framed_len(buf) {
            Some(Ok(n)) => n,
            Some(Err(e)) => return Err(e),
            None => return Err(DirError::Malformed),
        };
        if buf.len() != total {
            return Err(DirError::Malformed);
        }
        Self::parse(&buf[4..])
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            DirRequest::Consensus => vec![KIND_CONSENSUS],
            DirRequest::Descriptor(fp) => {
                let mut v = Vec::with_capacity(33);
                v.push(KIND_DESCRIPTOR);
                v.extend_from_slice(fp);
                v
            }
            DirRequest::Publish(doc) => {
                let mut v = Vec::with_capacity(1 + doc.len());
                v.push(KIND_PUBLISH);
                v.extend_from_slice(doc);
                v
            }
            DirRequest::HsUpload(doc) => {
                let mut v = Vec::with_capacity(1 + doc.len());
                v.push(KIND_HS_UPLOAD);
                v.extend_from_slice(doc);
                v
            }
            DirRequest::HsFetch(id) => {
                let mut v = Vec::with_capacity(33);
                v.push(KIND_HS_FETCH);
                v.extend_from_slice(id);
                v
            }
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self, DirError> {
        match buf.first() {
            Some(&KIND_CONSENSUS) if buf.len() == 1 => Ok(DirRequest::Consensus),
            Some(&KIND_DESCRIPTOR) if buf.len() == 33 => {
                let fp: Fingerprint = buf[1..].try_into().map_err(|_| DirError::Malformed)?;
                Ok(DirRequest::Descriptor(fp))
            }
            Some(&KIND_HS_FETCH) if buf.len() == 33 => {
                let id: [u8; 32] = buf[1..].try_into().map_err(|_| DirError::Malformed)?;
                Ok(DirRequest::HsFetch(id))
            }
            // Cererile care poarta documente pot fi mari, deci au propriul plafon.
            Some(&KIND_PUBLISH) if buf.len() > 1 && buf.len() <= MAX_UPLOAD_LEN => {
                Ok(DirRequest::Publish(buf[1..].to_vec()))
            }
            Some(&KIND_HS_UPLOAD) if buf.len() > 1 && buf.len() <= MAX_UPLOAD_LEN => {
                Ok(DirRequest::HsUpload(buf[1..].to_vec()))
            }
            _ => Err(DirError::Malformed),
        }
    }
}

/// Rezultatul unei cereri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DirStatus {
    Ok = 0,
    /// Documentul nu exista la acest releu.
    NotFound = 1,
    /// Cererea nu s-a putut interpreta.
    BadRequest = 2,
    /// Documentul a fost respins la validare.
    Rejected = 3,
}

impl DirStatus {
    fn from_u8(v: u8) -> Result<Self, DirError> {
        match v {
            0 => Ok(DirStatus::Ok),
            1 => Ok(DirStatus::NotFound),
            2 => Ok(DirStatus::BadRequest),
            3 => Ok(DirStatus::Rejected),
            _ => Err(DirError::Malformed),
        }
    }
}

/// Raspunsul releului.
///
/// Format: `status u8 | len u32 BE | corp`
///
/// Lungimea e explicita pentru ca raspunsul soseste pe un stream, deci in mai
/// multe celule. Fara ea, clientul nu ar sti cand documentul s-a terminat si ar
/// trebui sa astepte inchiderea stream-ului — ceea ce l-ar face vulnerabil la un
/// releu care tine conexiunea deschisa la nesfarsit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirResponse {
    pub status: DirStatus,
    pub body: Vec<u8>,
}

impl DirResponse {
    pub fn ok(body: Vec<u8>) -> Self {
        DirResponse {
            status: DirStatus::Ok,
            body,
        }
    }

    pub fn error(status: DirStatus) -> Self {
        DirResponse {
            status,
            body: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(5 + self.body.len());
        v.push(self.status as u8);
        v.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        v.extend_from_slice(&self.body);
        v
    }

    /// Cati octeti anunta antetul, daca antetul e complet.
    ///
    /// Clientul foloseste asta ca sa stie cat mai are de asteptat.
    pub fn expected_len(buf: &[u8]) -> Option<Result<usize, DirError>> {
        if buf.len() < 5 {
            return None;
        }
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if len > MAX_RESPONSE_LEN {
            return Some(Err(DirError::Malformed));
        }
        Some(Ok(5 + len))
    }

    pub fn parse(buf: &[u8]) -> Result<Self, DirError> {
        let total = match Self::expected_len(buf) {
            Some(Ok(n)) => n,
            Some(Err(e)) => return Err(e),
            None => return Err(DirError::Malformed),
        };
        if buf.len() != total {
            return Err(DirError::Malformed);
        }
        Ok(DirResponse {
            status: DirStatus::from_u8(buf[0])?,
            body: buf[5..].to_vec(),
        })
    }
}

/// Ce documente poate servi un releu.
///
/// Un releu obisnuit tine consensul curent, primit de la autoritati, si
/// descriptorii pe care i-a colectat. Nu produce nimic; doar redistribuie
/// documente deja semnate, iar clientul le verifica singur.
#[derive(Debug, Default)]
pub struct DirStore {
    consensus: Option<String>,
    descriptors: Vec<(Fingerprint, String)>,
}

/// Cate descriptoare accepta un releu. Plafoneaza memoria pe care o poate
/// consuma un peer care publica la nesfarsit.
pub const MAX_DESCRIPTORS: usize = 4096;

impl DirStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_consensus(&mut self, doc: String) {
        self.consensus = Some(doc);
    }

    pub fn add_descriptor(&mut self, fp: Fingerprint, doc: String) {
        self.descriptors.retain(|(f, _)| *f != fp);
        self.descriptors.push((fp, doc));
    }

    pub fn len(&self) -> usize {
        self.descriptors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.descriptors.is_empty() && self.consensus.is_none()
    }

    /// Accepta un descriptor publicat de un releu.
    ///
    /// `S` e schema cu care sunt semnati descriptorii. Validarea se face **aici**,
    /// nu la apelant: un descriptor care nu isi verifica propria semnatura nu
    /// intra in magazin, oricine l-ar fi trimis.
    pub fn accept_descriptor<S: pqo_crypto::sig::Sig>(
        &mut self,
        doc: &[u8],
    ) -> Result<Fingerprint, DirError> {
        if self.descriptors.len() >= MAX_DESCRIPTORS {
            return Err(DirError::Malformed);
        }
        let text = core::str::from_utf8(doc).map_err(|_| DirError::Malformed)?;
        let d = crate::netdoc::RelayDescriptor::parse_and_verify::<S>(text)?;
        let fp = d.fingerprint();
        self.add_descriptor(fp, text.to_string());
        Ok(fp)
    }

    /// Toate descriptoarele stocate, pentru ca o autoritate sa poata vota.
    pub fn all_descriptors(&self) -> impl Iterator<Item = (&Fingerprint, &str)> {
        self.descriptors.iter().map(|(f, d)| (f, d.as_str()))
    }

    /// Serveste o cerere de citire.
    ///
    /// Publicarile nu trec pe aici: modifica starea, deci au nevoie de acces
    /// mutabil si de validare. Vezi [`Self::accept_descriptor`].
    pub fn serve(&self, req: &DirRequest) -> DirResponse {
        match req {
            DirRequest::Consensus => match &self.consensus {
                Some(c) => DirResponse::ok(c.as_bytes().to_vec()),
                None => DirResponse::error(DirStatus::NotFound),
            },
            DirRequest::Descriptor(fp) => match self.descriptors.iter().find(|(f, _)| f == fp) {
                Some((_, d)) => DirResponse::ok(d.as_bytes().to_vec()),
                None => DirResponse::error(DirStatus::NotFound),
            },
            // Cererile care modifica starea nu se pot servi dintr-o referinta
            // partajata; apelantul trebuie sa le trateze separat.
            DirRequest::Publish(_) | DirRequest::HsUpload(_) | DirRequest::HsFetch(_) => {
                DirResponse::error(DirStatus::BadRequest)
            }
        }
    }
}

/// Stocare de descriptori de servicii ascunse.
///
/// Definita ca trait, nu ca tip concret, ca sa nu introducem o dependenta de la
/// `pqo-dirproto` catre `pqo-hs`. Stratul de retea primeste o implementare si nu
/// stie ce e inauntru.
///
/// Implementarea reala e `pqo_hs::hsdir::DescStore`, care aplica regulile de
/// acceptare: contor de revizie strict crescator si primul publicator pastreaza
/// slotul pe perioada.
pub trait HsDirStore: Send + Sync {
    /// Accepta un descriptor incarcat de un serviciu.
    fn upload(&self, doc: &[u8]) -> Result<(), HsUploadError>;

    /// Serveste un descriptor dupa indexul blindat.
    fn fetch(&self, blinded_id: &[u8; 32]) -> Option<Vec<u8>>;
}

/// De ce a fost respins un descriptor de serviciu ascuns.
///
/// Motivele sunt distincte pentru ca inseamna lucruri diferite pentru cine
/// publica: un document invalid e un bug la serviciu, un slot ocupat inseamna
/// ca altcineva a ajuns primul in aceasta perioada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsUploadError {
    /// Documentul nu se parseaza sau semnatura nu verifica.
    Invalid,
    /// Slotul e ocupat de alta cheie de perioada, sau revizia nu creste.
    Occupied,
    /// Stocarea e plina.
    Full,
}

impl core::fmt::Display for HsUploadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HsUploadError::Invalid => f.write_str("descriptor invalid"),
            HsUploadError::Occupied => f.write_str("slot ocupat in aceasta perioada"),
            HsUploadError::Full => f.write_str("stocare plina"),
        }
    }
}

impl std::error::Error for HsUploadError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cerere_roundtrip() {
        for r in [
            DirRequest::Consensus,
            DirRequest::Descriptor([7u8; 32]),
            DirRequest::HsFetch([9u8; 32]),
            DirRequest::Publish(b"relay-descriptor 1\n".to_vec()),
            DirRequest::HsUpload(vec![0xABu8; 5000]),
        ] {
            assert_eq!(DirRequest::parse(&r.encode()).unwrap(), r);
        }
    }

    #[test]
    fn incadrarea_cu_lungime_functioneaza() {
        for r in [
            DirRequest::Consensus,
            DirRequest::HsUpload(vec![0xABu8; 7000]),
        ] {
            let e = r.encode_framed();
            assert_eq!(DirRequest::parse_framed(&e).unwrap(), r);
            // Prefixe incomplete: nu stim inca lungimea.
            for n in 0..4 {
                assert!(DirRequest::framed_len(&e[..n]).is_none());
            }
            assert_eq!(DirRequest::framed_len(&e).unwrap().unwrap(), e.len());
        }
        // Lungime absurda: respinsa inainte de alocare.
        let rau = vec![0xFF, 0xFF, 0xFF, 0xFF, 1];
        assert!(DirRequest::framed_len(&rau).unwrap().is_err());
    }

    #[test]
    fn publicarea_are_propriul_plafon() {
        // Cererile de citire sunt minuscule, cele de publicare pot fi mari.
        let mare = DirRequest::Publish(vec![0u8; MAX_UPLOAD_LEN - 1]);
        assert!(DirRequest::parse(&mare.encode()).is_ok());
        let prea_mare = DirRequest::Publish(vec![0u8; MAX_UPLOAD_LEN]);
        assert!(DirRequest::parse(&prea_mare.encode()).is_err());
    }

    #[test]
    fn cereri_malformate_sunt_respinse() {
        for rau in [
            vec![],
            vec![KIND_CONSENSUS, 0],
            vec![KIND_DESCRIPTOR],
            vec![KIND_DESCRIPTOR; 32],
            vec![9u8],
            vec![0u8; MAX_REQUEST_LEN + 1],
        ] {
            assert!(DirRequest::parse(&rau).is_err(), "acceptat: {rau:?}");
        }
    }

    #[test]
    fn raspuns_roundtrip() {
        let r = DirResponse::ok(b"consensus 1\n".to_vec());
        assert_eq!(DirResponse::parse(&r.encode()).unwrap(), r);
        let e = DirResponse::error(DirStatus::NotFound);
        assert_eq!(DirResponse::parse(&e.encode()).unwrap(), e);
    }

    #[test]
    fn lungimea_asteptata_se_citeste_din_antet() {
        let r = DirResponse::ok(vec![0u8; 1000]);
        let e = r.encode();
        // Antet incomplet: inca nu stim.
        for n in 0..5 {
            assert!(DirResponse::expected_len(&e[..n]).is_none());
        }
        assert_eq!(DirResponse::expected_len(&e).unwrap().unwrap(), 1005);
    }

    #[test]
    fn raspuns_absurd_de_mare_e_respins() {
        // Un releu ostil anunta 4 GB. Clientul trebuie sa refuze inainte de a
        // aloca ceva.
        let mut e = vec![0u8, 0xFF, 0xFF, 0xFF, 0xFF];
        e.extend_from_slice(b"x");
        assert!(DirResponse::expected_len(&e).unwrap().is_err());
        assert!(DirResponse::parse(&e).is_err());
    }

    #[test]
    fn octeti_in_plus_sunt_respinsi() {
        let mut e = DirResponse::ok(b"abc".to_vec()).encode();
        e.push(0);
        assert!(DirResponse::parse(&e).is_err());
    }

    #[test]
    fn descriptorul_nevalid_nu_intra_in_magazin() {
        use pqo_crypto::sig::{Ed25519, Sig};
        use rand_core::OsRng;

        let mut rng = OsRng;
        let (sk, pk) = Ed25519::keygen(&mut rng);
        let d = crate::netdoc::RelayDescriptor {
            identity: pk,
            onion_x25519: [1u8; 32],
            onion_kem: None,
            address: "10.0.0.1".into(),
            or_port: 9001,
            bandwidth: 1000,
            exit_ports: Vec::new(),
            published: 1_700_000_000,
        };
        let doc = d.sign::<Ed25519>(&sk);

        let mut s = DirStore::new();
        let fp = s.accept_descriptor::<Ed25519>(doc.as_bytes()).unwrap();
        assert_eq!(fp, d.fingerprint());
        assert_eq!(s.len(), 1);

        // Modificat: semnatura nu mai verifica, deci nu intra.
        let stricat = doc.replace("bandwidth 1000", "bandwidth 9999");
        assert!(s.accept_descriptor::<Ed25519>(stricat.as_bytes()).is_err());
        assert_eq!(s.len(), 1, "magazinul nu are voie sa creasca la esec");

        // Gunoi complet.
        assert!(s.accept_descriptor::<Ed25519>(b"nu e document").is_err());
    }

    #[test]
    fn cererile_care_modifica_starea_nu_se_servesc_din_referinta() {
        let s = DirStore::new();
        for r in [
            DirRequest::Publish(vec![1]),
            DirRequest::HsUpload(vec![1]),
            DirRequest::HsFetch([0u8; 32]),
        ] {
            assert_eq!(s.serve(&r).status, DirStatus::BadRequest);
        }
    }

    #[test]
    fn niciun_prefix_nu_produce_panica() {
        let cazuri = [
            DirRequest::Descriptor([1u8; 32]).encode(),
            DirResponse::ok(vec![1u8; 500]).encode(),
        ];
        for c in &cazuri {
            for n in 0..=c.len() {
                let _ = DirRequest::parse(&c[..n]);
                let _ = DirResponse::parse(&c[..n]);
                let _ = DirResponse::expected_len(&c[..n]);
            }
        }
    }

    #[test]
    fn magazinul_serveste_si_raporteaza_lipsa() {
        let mut s = DirStore::new();
        assert!(s.is_empty());
        assert_eq!(s.serve(&DirRequest::Consensus).status, DirStatus::NotFound);

        s.set_consensus("consensus 1\n".into());
        s.add_descriptor([3u8; 32], "relay-descriptor 1\n".into());

        assert_eq!(
            s.serve(&DirRequest::Consensus).body,
            b"consensus 1\n".to_vec()
        );
        assert_eq!(
            s.serve(&DirRequest::Descriptor([3u8; 32])).body,
            b"relay-descriptor 1\n".to_vec()
        );
        assert_eq!(
            s.serve(&DirRequest::Descriptor([9u8; 32])).status,
            DirStatus::NotFound
        );
    }

    #[test]
    fn descriptorul_se_inlocuieste_nu_se_dubleaza() {
        let mut s = DirStore::new();
        s.add_descriptor([1u8; 32], "vechi".into());
        s.add_descriptor([1u8; 32], "nou".into());
        assert_eq!(s.len(), 1);
        assert_eq!(s.serve(&DirRequest::Descriptor([1u8; 32])).body, b"nou");
    }
}
