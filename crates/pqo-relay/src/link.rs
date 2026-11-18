//! Handshake-ul de nivel legatura, ca masina de stari pura.
//!
//! # De ce fara I/O
//!
//! Nicio functie din acest modul nu citeste si nu scrie nimic. Primesti o celula,
//! primesti inapoi celulele de trimis. Trei motive:
//!
//! 1. **Testabilitate.** Pot verifica exhaustiv fiecare ordine gresita de mesaje,
//!    fiecare mesaj lipsa, fiecare repetare — fara socket-uri, fara timeout-uri,
//!    fara teste care pica aleator.
//! 2. **Fara async in calea critica.** Verificarea semnaturilor si a
//!    transcriptului nu are nevoie de `.await`, deci nu poate avea curse.
//! 3. **Portabilitate.** Coaja de I/O poate fi tokio, async-std, sau fire
//!    blocante. Protocolul nu se schimba.
//!
//! # Fluxul
//!
//! ```text
//!   I -> R   VERSIONS
//!   R -> I   VERSIONS, CERTS(id_R), AUTH_CHALLENGE(nonce)
//!   I -> R   [CERTS(id_I), AUTHENTICATE(sig_I)],  NETINFO
//!   R -> I   AUTHENTICATE(sig_R), NETINFO
//! ```
//!
//! Partile in paranteze apar doar la autentificare reciproca (releu catre releu).
//! Un client care se conecteaza la guard-ul lui ramane anonim: releul se
//! autentifica, clientul nu.
//!
//! # Legarea de canal
//!
//! Semnatura acopera `channel_binding`, care in productie e exportul TLS
//! (RFC 8446 §7.5) al conexiunii curente. Fara el, un atacator ar putea prelua un
//! handshake valid observat pe alta conexiune — atac de tip unknown key share.
//! Coaja de I/O il furnizeaza; protocolul nu stie de unde vine.

use pqo_crypto::kdf;
use pqo_crypto::sig::Sig;
use pqo_wire::{Cell, ChanCmd, CircId};
use rand_core::CryptoRngCore;

use crate::RelayError;

/// Versiunea de protocol pe care o vorbim.
pub const PROTO_VERSION: u16 = 1;
/// Lungimea provocarii de autentificare.
pub const CHALLENGE_LEN: usize = 32;
/// Cate versiuni acceptam intr-o celula VERSIONS. Peste asta, e umplutura.
pub const MAX_VERSIONS: usize = 64;

/// Cine a initiat conexiunea.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    fn label(self) -> &'static [u8] {
        match self {
            Role::Initiator => b"Initiator",
            Role::Responder => b"Responder",
        }
    }
}

/// Cine trebuie sa se autentifice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Doar cel care raspunde. Folosit de clienti: raman anonimi.
    ResponderOnly,
    /// Amandoi. Folosit intre relee.
    Mutual,
    /// Doar la cel care asculta: accepta si peer-i care se autentifica, si peer-i
    /// care raman anonimi.
    ///
    /// Exista pentru ca un releu care asculta nu stie dinainte cine se conecteaza.
    /// Un client trebuie sa ramana anonim; un alt releu trebuie sa se
    /// autentifice. Modul se decide dupa ce face peer-ul, nu inainte.
    ///
    /// Nu il folosi la initiator: acolo stii intotdeauna ce esti.
    Optional,
}

/// Etapele prin care trece un handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Nu s-a trimis nimic inca.
    Start,
    /// S-a trimis VERSIONS, se asteapta raspuns.
    SentVersions,
    /// S-au primit VERSIONS, se asteapta CERTS.
    GotVersions,
    /// S-au primit certificatele, se asteapta provocarea.
    GotCerts,
    /// S-a primit provocarea, se asteapta autentificarea.
    GotChallenge,
    /// S-a primit autentificarea, se asteapta NETINFO.
    GotAuth,
    /// Canal deschis, se pot trimite celule de circuit.
    Open,
    /// Handshake esuat. Starea e terminala.
    Failed,
}

/// Transcriptul: hash-ul rulant peste toate mesajele, in ordinea de pe fir.
///
/// Ambele parti vad aceeasi secventa, deci ajung la aceeasi valoare. Semnatura
/// acopera transcriptul, deci orice modificare, reordonare sau injectare de
/// mesaj invalideaza handshake-ul.
struct Transcript {
    acc: [u8; 32],
    n: u64,
}

impl Transcript {
    fn new() -> Self {
        Transcript {
            acc: [0u8; 32],
            n: 0,
        }
    }

    /// Absoarbe un mesaj. Contorul intra in hash ca sa nu se poata reordona.
    fn absorb(&mut self, kind: u8, body: &[u8]) {
        self.acc = kdf::hash(
            b"pqonion-link-transcript-v1",
            &[&self.acc, &self.n.to_le_bytes(), &[kind], body],
        );
        self.n += 1;
    }

    fn bind(&self, role: Role, channel_binding: &[u8]) -> [u8; 32] {
        kdf::hash(
            b"pqonion-link-auth-v1",
            &[role.label(), channel_binding, &self.acc],
        )
    }
}

/// Starea unui handshake de legatura.
pub struct LinkHandshake<S: Sig> {
    role: Role,
    mode: AuthMode,
    stage: Stage,
    transcript: Transcript,
    channel_binding: Vec<u8>,
    /// Cheia noastra de identitate.
    ///
    /// In `Arc` pentru ca un releu are un singur set de chei si zeci de canale
    /// simultane. Alternativa ar fi fost sa cloneze cheia privata per canal,
    /// ceea ce inmulteste copiile de material secret in memorie fara motiv.
    id_sk: std::sync::Arc<S::SecretKey>,
    id_pk: Vec<u8>,
    /// Cheia partenerului, aflata din CERTS.
    peer_pk: Option<Vec<u8>>,
    /// Provocarea, la cel care raspunde.
    challenge: Option<[u8; CHALLENGE_LEN]>,
    /// Adevarat daca am trimis deja propria autentificare.
    sent_auth: bool,
    /// La modul [`AuthMode::Optional`]: adevarat daca peer-ul s-a autentificat.
    peer_authenticated: bool,
    /// Adevarat dupa ce initiatorul a trimis NETINFO.
    sent_netinfo: bool,
}

impl<S: Sig> core::fmt::Debug for LinkHandshake<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LinkHandshake({:?}, {:?})", self.role, self.stage)
    }
}

fn encode_versions() -> Vec<u8> {
    PROTO_VERSION.to_be_bytes().to_vec()
}

fn parse_versions(body: &[u8]) -> Result<(), RelayError> {
    if body.is_empty() || body.len() % 2 != 0 || body.len() / 2 > MAX_VERSIONS {
        return Err(RelayError::BadLinkMessage);
    }
    let ok = body
        .chunks_exact(2)
        .any(|c| u16::from_be_bytes([c[0], c[1]]) == PROTO_VERSION);
    if ok {
        Ok(())
    } else {
        Err(RelayError::NoCommonVersion)
    }
}

impl<S: Sig> LinkHandshake<S> {
    pub fn new(
        role: Role,
        mode: AuthMode,
        id_sk: S::SecretKey,
        id_pk: Vec<u8>,
        channel_binding: Vec<u8>,
    ) -> Self {
        Self::new_shared(
            role,
            mode,
            std::sync::Arc::new(id_sk),
            id_pk,
            channel_binding,
        )
    }

    /// Ca [`Self::new`], dar cu cheia partajata intre mai multe canale.
    pub fn new_shared(
        role: Role,
        mode: AuthMode,
        id_sk: std::sync::Arc<S::SecretKey>,
        id_pk: Vec<u8>,
        channel_binding: Vec<u8>,
    ) -> Self {
        LinkHandshake {
            role,
            mode,
            stage: Stage::Start,
            transcript: Transcript::new(),
            channel_binding,
            id_sk,
            id_pk,
            peer_pk: None,
            challenge: None,
            sent_auth: false,
            peer_authenticated: false,
            sent_netinfo: false,
        }
    }

    /// Adevarat daca initiatorul trebuie sa trimita acum NETINFO.
    ///
    /// Coaja de I/O apeleaza asta dupa fiecare celula procesata; protocolul
    /// decide momentul, nu bucla de retea.
    pub fn needs_netinfo(&self) -> bool {
        self.role == Role::Initiator && self.stage == Stage::GotChallenge && !self.sent_netinfo
    }

    /// Adevarat daca peer-ul si-a dovedit identitatea.
    ///
    /// La [`AuthMode::Optional`] asta e singurul mod de a sti daca ai de-a face
    /// cu un releu sau cu un client anonim. Nu confunda „nu s-a autentificat"
    /// cu „e client": un releu care esueaza la autentificare ajunge in
    /// [`Stage::Failed`], nu aici.
    pub fn peer_authenticated(&self) -> bool {
        self.peer_authenticated
    }

    pub fn stage(&self) -> Stage {
        self.stage
    }

    pub fn is_open(&self) -> bool {
        self.stage == Stage::Open
    }

    /// Cheia publica a partenerului, disponibila dupa CERTS.
    pub fn peer_identity(&self) -> Option<&[u8]> {
        self.peer_pk.as_deref()
    }

    /// Primul mesaj, trimis doar de initiator.
    pub fn start(&mut self) -> Result<Vec<Cell>, RelayError> {
        if self.role != Role::Initiator || self.stage != Stage::Start {
            return Err(RelayError::BadLinkState);
        }
        let body = encode_versions();
        self.transcript.absorb(ChanCmd::Versions as u8, &body);
        self.stage = Stage::SentVersions;
        Ok(vec![var(ChanCmd::Versions, body)?])
    }

    /// Consuma o celula si intoarce ce trebuie trimis inapoi.
    ///
    /// Orice eroare face starea terminala: un handshake esuat nu se reia, se
    /// inchide canalul. Astfel un atacator nu poate incerca variante la nesfarsit
    /// pe aceeasi conexiune.
    pub fn handle(
        &mut self,
        cell: &Cell,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<Cell>, RelayError> {
        if self.stage == Stage::Failed {
            return Err(RelayError::BadLinkState);
        }
        if !cell.circ().is_none() {
            self.stage = Stage::Failed;
            return Err(RelayError::BadLinkMessage);
        }
        let r = self.handle_inner(cell, rng);
        if r.is_err() {
            self.stage = Stage::Failed;
        }
        r
    }

    fn handle_inner(
        &mut self,
        cell: &Cell,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<Cell>, RelayError> {
        let body = cell.payload();
        match (self.role, self.stage, cell.cmd()) {
            // --- Cel care raspunde primeste VERSIONS si trimite tot al doilea zbor ---
            (Role::Responder, Stage::Start, ChanCmd::Versions) => {
                parse_versions(body)?;
                self.transcript.absorb(ChanCmd::Versions as u8, body);

                let mut out = Vec::with_capacity(3);
                let v = encode_versions();
                self.transcript.absorb(ChanCmd::Versions as u8, &v);
                out.push(var(ChanCmd::Versions, v)?);

                let certs = self.id_pk.clone();
                self.transcript.absorb(ChanCmd::Certs as u8, &certs);
                out.push(var(ChanCmd::Certs, certs)?);

                let mut ch = [0u8; CHALLENGE_LEN];
                rng.fill_bytes(&mut ch);
                self.transcript.absorb(ChanCmd::AuthChallenge as u8, &ch);
                self.challenge = Some(ch);
                out.push(var(ChanCmd::AuthChallenge, ch.to_vec())?);

                self.stage = Stage::GotVersions;
                Ok(out)
            }

            // --- Initiatorul primeste VERSIONS ---
            (Role::Initiator, Stage::SentVersions, ChanCmd::Versions) => {
                parse_versions(body)?;
                self.transcript.absorb(ChanCmd::Versions as u8, body);
                self.stage = Stage::GotVersions;
                Ok(Vec::new())
            }

            // --- Initiatorul primeste CERTS ---
            (Role::Initiator, Stage::GotVersions, ChanCmd::Certs) => {
                if body.len() != S::PK_LEN {
                    return Err(RelayError::BadLinkMessage);
                }
                self.transcript.absorb(ChanCmd::Certs as u8, body);
                self.peer_pk = Some(body.to_vec());
                self.stage = Stage::GotCerts;
                Ok(Vec::new())
            }

            // --- Initiatorul primeste provocarea si trimite zborul trei ---
            (Role::Initiator, Stage::GotCerts, ChanCmd::AuthChallenge) => {
                if body.len() != CHALLENGE_LEN {
                    return Err(RelayError::BadLinkMessage);
                }
                self.transcript.absorb(ChanCmd::AuthChallenge as u8, body);

                let mut out = Vec::new();
                if self.mode == AuthMode::Mutual {
                    let certs = self.id_pk.clone();
                    self.transcript.absorb(ChanCmd::Certs as u8, &certs);
                    out.push(var(ChanCmd::Certs, certs)?);

                    let sig = S::sign(
                        &self.id_sk,
                        &self.transcript.bind(Role::Initiator, &self.channel_binding),
                    );
                    self.transcript.absorb(ChanCmd::Authenticate as u8, &sig);
                    out.push(var(ChanCmd::Authenticate, sig)?);
                    self.sent_auth = true;
                }
                self.stage = Stage::GotChallenge;
                Ok(out)
            }

            // --- Cel care raspunde primeste certificatele initiatorului ---
            (Role::Responder, Stage::GotVersions, ChanCmd::Certs) => {
                if self.mode == AuthMode::ResponderOnly || body.len() != S::PK_LEN {
                    return Err(RelayError::BadLinkMessage);
                }
                self.transcript.absorb(ChanCmd::Certs as u8, body);
                self.peer_pk = Some(body.to_vec());
                self.stage = Stage::GotCerts;
                Ok(Vec::new())
            }

            // --- Cel care raspunde verifica autentificarea initiatorului ---
            (Role::Responder, Stage::GotCerts, ChanCmd::Authenticate) => {
                let pk = self.peer_pk.clone().ok_or(RelayError::BadLinkState)?;
                let asteptat = self.transcript.bind(Role::Initiator, &self.channel_binding);
                S::verify(&pk, &asteptat, body).map_err(|_| RelayError::BadLinkAuth)?;
                self.transcript.absorb(ChanCmd::Authenticate as u8, body);
                self.peer_authenticated = true;
                self.stage = Stage::GotChallenge;
                Ok(Vec::new())
            }

            // --- NETINFO de la initiator: raspunsul e zborul patru ---
            (Role::Responder, Stage::GotVersions | Stage::GotChallenge, ChanCmd::Netinfo) => {
                // La `Mutual` autentificarea e obligatorie, deci NETINFO nu are
                // voie sa vina inainte de ea. La `Optional` si `ResponderOnly`
                // lipsa autentificarii inseamna peer anonim, ceea ce e permis.
                if self.mode == AuthMode::Mutual && self.stage != Stage::GotChallenge {
                    return Err(RelayError::BadLinkState);
                }
                self.transcript.absorb(ChanCmd::Netinfo as u8, body);

                let sig = S::sign(
                    &self.id_sk,
                    &self.transcript.bind(Role::Responder, &self.channel_binding),
                );
                self.transcript.absorb(ChanCmd::Authenticate as u8, &sig);
                self.sent_auth = true;

                // NETINFO e celula FIXA: payload-ul se completeaza cu zerouri
                // pana la 509 octeti. Absorbim ce ajunge efectiv pe fir, nu
                // corpul logic — altfel cele doua parti calculeaza transcripte
                // diferite si semnatura nu se verifica.
                let ni_cell = Cell::fixed(CircId::NONE, ChanCmd::Netinfo, &netinfo_body())?;
                self.transcript
                    .absorb(ChanCmd::Netinfo as u8, ni_cell.payload());
                self.stage = Stage::Open;
                Ok(vec![var(ChanCmd::Authenticate, sig)?, ni_cell])
            }

            // --- Initiatorul verifica autentificarea celui care raspunde ---
            (Role::Initiator, Stage::GotChallenge, ChanCmd::Authenticate) => {
                let pk = self.peer_pk.clone().ok_or(RelayError::BadLinkState)?;
                let asteptat = self.transcript.bind(Role::Responder, &self.channel_binding);
                S::verify(&pk, &asteptat, body).map_err(|_| RelayError::BadLinkAuth)?;
                self.transcript.absorb(ChanCmd::Authenticate as u8, body);
                self.stage = Stage::GotAuth;
                Ok(Vec::new())
            }

            (Role::Initiator, Stage::GotAuth, ChanCmd::Netinfo) => {
                self.transcript.absorb(ChanCmd::Netinfo as u8, body);
                self.stage = Stage::Open;
                Ok(Vec::new())
            }

            // Orice altceva e o secventa gresita.
            _ => Err(RelayError::BadLinkState),
        }
    }

    /// Ce trimite initiatorul dupa ce a primit provocarea: NETINFO care declanseaza
    /// zborul patru.
    pub fn send_netinfo(&mut self) -> Result<Vec<Cell>, RelayError> {
        if self.role != Role::Initiator || self.stage != Stage::GotChallenge {
            return Err(RelayError::BadLinkState);
        }
        // Vezi nota de la raspunzator: absorbim payload-ul umplut, nu corpul gol.
        self.sent_netinfo = true;
        let ni_cell = Cell::fixed(CircId::NONE, ChanCmd::Netinfo, &netinfo_body())?;
        self.transcript
            .absorb(ChanCmd::Netinfo as u8, ni_cell.payload());
        Ok(vec![ni_cell])
    }
}

/// Corpul unei celule NETINFO.
///
/// Gol in aceasta versiune. Tor pune aici ora si adresele observate; le vom
/// adauga cand releul va avea nevoie sa isi descopere adresa publica.
fn netinfo_body() -> Vec<u8> {
    Vec::new()
}

fn var(cmd: ChanCmd, body: Vec<u8>) -> Result<Cell, RelayError> {
    Cell::var(CircId::NONE, cmd, body).map_err(RelayError::Wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqo_crypto::sig::Ed25519;
    use rand_core::OsRng;

    type S = Ed25519;

    struct Pereche {
        i: LinkHandshake<S>,
        r: LinkHandshake<S>,
    }

    fn pereche(mode: AuthMode, binding_i: &[u8], binding_r: &[u8]) -> Pereche {
        let mut rng = OsRng;
        let (isk, ipk) = S::keygen(&mut rng);
        let (rsk, rpk) = S::keygen(&mut rng);
        Pereche {
            i: LinkHandshake::new(Role::Initiator, mode, isk, ipk, binding_i.to_vec()),
            r: LinkHandshake::new(Role::Responder, mode, rsk, rpk, binding_r.to_vec()),
        }
    }

    /// Ruleaza handshake-ul pana la capat, trecand celulele prin serializare.
    fn ruleaza(p: &mut Pereche) -> Result<(), RelayError> {
        let mut rng = OsRng;
        let mut catre_r = p.i.start()?;
        let mut catre_i;

        loop {
            catre_i = Vec::new();
            for c in &catre_r {
                catre_i.extend(pe_fir(&mut p.r, c, &mut rng)?);
            }
            // Initiatorul trimite NETINFO dupa ce a procesat provocarea.
            if p.i.stage() == Stage::GotChallenge && catre_i.is_empty() {
                catre_r = p.i.send_netinfo()?;
                continue;
            }
            if catre_i.is_empty() {
                break;
            }
            catre_r = Vec::new();
            for c in &catre_i {
                catre_r.extend(pe_fir(&mut p.i, c, &mut rng)?);
            }
            if p.i.stage() == Stage::GotChallenge {
                catre_r.extend(p.i.send_netinfo()?);
            }
            if catre_r.is_empty() {
                break;
            }
        }
        Ok(())
    }

    /// Trece celula prin codare si decodare, ca sa prindem si erorile de format.
    fn pe_fir(
        h: &mut LinkHandshake<S>,
        c: &Cell,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<Cell>, RelayError> {
        let mut buf = Vec::new();
        c.encode(&mut buf);
        let (dec, n) = Cell::decode(&buf).unwrap().unwrap();
        assert_eq!(n, buf.len());
        h.handle(&dec, rng)
    }

    #[test]
    fn handshake_reciproc_reuseste() {
        let mut p = pereche(AuthMode::Mutual, b"canal", b"canal");
        ruleaza(&mut p).unwrap();
        assert!(p.i.is_open(), "initiatorul: {:?}", p.i.stage());
        assert!(p.r.is_open(), "cel care raspunde: {:?}", p.r.stage());
        assert!(p.i.peer_identity().is_some());
        assert!(p.r.peer_identity().is_some());
    }

    /// Ruleaza un handshake in care initiatorul si raspunzatorul au moduri
    /// diferite, cum se intampla in realitate.
    fn pereche_mixta(mod_i: AuthMode, mod_r: AuthMode) -> Pereche {
        let mut rng = OsRng;
        let (isk, ipk) = S::keygen(&mut rng);
        let (rsk, rpk) = S::keygen(&mut rng);
        Pereche {
            i: LinkHandshake::new(Role::Initiator, mod_i, isk, ipk, b"c".to_vec()),
            r: LinkHandshake::new(Role::Responder, mod_r, rsk, rpk, b"c".to_vec()),
        }
    }

    #[test]
    fn optional_accepta_un_releu_care_se_autentifica() {
        let mut p = pereche_mixta(AuthMode::Mutual, AuthMode::Optional);
        ruleaza(&mut p).unwrap();
        assert!(p.i.is_open() && p.r.is_open());
        assert!(
            p.r.peer_authenticated(),
            "un releu care se autentifica trebuie recunoscut ca atare"
        );
        assert!(p.r.peer_identity().is_some());
    }

    #[test]
    fn optional_accepta_un_client_anonim() {
        let mut p = pereche_mixta(AuthMode::ResponderOnly, AuthMode::Optional);
        ruleaza(&mut p).unwrap();
        assert!(p.i.is_open() && p.r.is_open());
        assert!(
            !p.r.peer_authenticated(),
            "clientul trebuie sa ramana anonim"
        );
        assert!(p.r.peer_identity().is_none());
    }

    #[test]
    fn mutual_refuza_un_peer_anonim() {
        // Un releu care cere autentificare stricta nu accepta un client anonim.
        let mut p = pereche_mixta(AuthMode::ResponderOnly, AuthMode::Mutual);
        assert!(ruleaza(&mut p).is_err());
    }

    #[test]
    fn handshake_doar_cu_raspunzator_reuseste() {
        // Cazul clientului: ramane anonim, releul se autentifica.
        let mut p = pereche(AuthMode::ResponderOnly, b"canal", b"canal");
        ruleaza(&mut p).unwrap();
        assert!(p.i.is_open());
        assert!(p.r.is_open());
        assert!(
            p.r.peer_identity().is_none(),
            "releul nu trebuie sa afle identitatea clientului"
        );
        assert!(p.i.peer_identity().is_some());
    }

    #[test]
    fn legare_de_canal_diferita_esueaza() {
        // Exact atacul pe care il opreste legarea: handshake valid, dar mutat pe
        // alta conexiune TLS.
        let mut p = pereche(AuthMode::Mutual, b"canal-A", b"canal-B");
        let r = ruleaza(&mut p);
        assert!(r.is_err(), "legarea de canal trebuie verificata");
    }

    #[test]
    fn ordine_gresita_e_respinsa() {
        let mut rng = OsRng;
        let mut p = pereche(AuthMode::Mutual, b"c", b"c");
        // Cel care raspunde primeste CERTS inainte de VERSIONS.
        let certs = Cell::var(CircId::NONE, ChanCmd::Certs, vec![0u8; 32]).unwrap();
        assert_eq!(
            p.r.handle(&certs, &mut rng),
            Err(RelayError::BadLinkState)
        );
        assert_eq!(p.r.stage(), Stage::Failed);
    }

    #[test]
    fn starea_esuata_e_terminala() {
        let mut rng = OsRng;
        let mut p = pereche(AuthMode::Mutual, b"c", b"c");
        let rau = Cell::var(CircId::NONE, ChanCmd::Certs, vec![0u8; 32]).unwrap();
        assert!(p.r.handle(&rau, &mut rng).is_err());
        // Chiar si mesajul corect e refuzat dupa esec.
        let v = Cell::var(CircId::NONE, ChanCmd::Versions, vec![0, 1]).unwrap();
        assert!(
            p.r.handle(&v, &mut rng).is_err(),
            "un handshake esuat nu se reia"
        );
    }

    #[test]
    fn celula_pe_circuit_nenul_e_respinsa() {
        let mut rng = OsRng;
        let mut p = pereche(AuthMode::Mutual, b"c", b"c");
        let c = Cell::var(CircId(5), ChanCmd::Versions, vec![0, 1]).unwrap();
        assert_eq!(p.r.handle(&c, &mut rng), Err(RelayError::BadLinkMessage));
    }

    #[test]
    fn fara_versiune_comuna_esueaza() {
        let mut rng = OsRng;
        let mut p = pereche(AuthMode::Mutual, b"c", b"c");
        let c = Cell::var(CircId::NONE, ChanCmd::Versions, vec![0xFF, 0xFF]).unwrap();
        assert_eq!(p.r.handle(&c, &mut rng), Err(RelayError::NoCommonVersion));
    }

    #[test]
    fn versiuni_malformate_sunt_respinse() {
        let mut rng = OsRng;
        for body in [vec![], vec![1u8], vec![0u8; 2 * MAX_VERSIONS + 2]] {
            let mut p = pereche(AuthMode::Mutual, b"c", b"c");
            let c = Cell::var(CircId::NONE, ChanCmd::Versions, body).unwrap();
            assert!(p.r.handle(&c, &mut rng).is_err());
        }
    }

    #[test]
    fn semnatura_falsa_e_respinsa() {
        // Un atacator inlocuieste AUTHENTICATE-ul raspunzatorului cu al lui.
        let mut rng = OsRng;
        let mut p = pereche(AuthMode::ResponderOnly, b"c", b"c");
        let mut catre_r = p.i.start().unwrap();
        let mut catre_i = Vec::new();
        for c in &catre_r {
            catre_i.extend(p.r.handle(c, &mut rng).unwrap());
        }
        catre_r = Vec::new();
        for c in &catre_i {
            catre_r.extend(p.i.handle(c, &mut rng).unwrap());
        }
        catre_r.extend(p.i.send_netinfo().unwrap());

        let mut raspuns = Vec::new();
        for c in &catre_r {
            raspuns.extend(p.r.handle(c, &mut rng).unwrap());
        }
        // Stricam semnatura din primul mesaj al zborului patru.
        let mut sig = raspuns[0].payload().to_vec();
        sig[0] ^= 0x01;
        let fals = Cell::var(CircId::NONE, ChanCmd::Authenticate, sig).unwrap();
        assert_eq!(p.i.handle(&fals, &mut rng), Err(RelayError::BadLinkAuth));
    }

    #[test]
    fn netinfo_absoarbe_payloadul_umplut() {
        // Regresia care a spart prima versiune: NETINFO e celula fixa, deci
        // payload-ul are 509 octeti, nu zero. Daca o parte absoarbe corpul logic
        // si cealalta payload-ul de pe fir, transcriptele diverg.
        let mut p = pereche(AuthMode::ResponderOnly, b"c", b"c");
        let mut rng = OsRng;
        let catre_r = p.i.start().unwrap();
        let mut catre_i = Vec::new();
        for c in &catre_r {
            catre_i.extend(p.r.handle(c, &mut rng).unwrap());
        }
        for c in &catre_i {
            p.i.handle(c, &mut rng).unwrap();
        }
        let ni = p.i.send_netinfo().unwrap();
        assert_eq!(
            ni[0].payload().len(),
            pqo_wire::CELL_PAYLOAD_LEN,
            "NETINFO are payload de dimensiune fixa"
        );
    }

    #[test]
    fn transcriptul_prinde_reordonarea() {
        let mut a = Transcript::new();
        let mut b = Transcript::new();
        a.absorb(1, b"x");
        a.absorb(2, b"y");
        b.absorb(2, b"y");
        b.absorb(1, b"x");
        assert_ne!(
            a.bind(Role::Initiator, b"c"),
            b.bind(Role::Initiator, b"c"),
            "ordinea mesajelor trebuie sa conteze"
        );
    }

    #[test]
    fn transcriptul_separa_rolurile() {
        let t = Transcript::new();
        assert_ne!(
            t.bind(Role::Initiator, b"c"),
            t.bind(Role::Responder, b"c"),
            "un mesaj de initiator nu poate trece drept mesaj de raspunzator"
        );
    }

    #[test]
    fn needs_netinfo_e_corect() {
        let mut rng = OsRng;
        let mut p = pereche(AuthMode::ResponderOnly, b"c", b"c");
        assert!(!p.i.needs_netinfo(), "nu inainte de provocare");
        let catre_r = p.i.start().unwrap();
        let mut catre_i = Vec::new();
        for c in &catre_r {
            catre_i.extend(p.r.handle(c, &mut rng).unwrap());
        }
        for c in &catre_i {
            p.i.handle(c, &mut rng).unwrap();
        }
        assert!(p.i.needs_netinfo(), "dupa provocare, da");
        p.i.send_netinfo().unwrap();
        assert!(!p.i.needs_netinfo(), "o singura data");
    }

    #[test]
    fn initiatorul_nu_poate_porni_de_doua_ori() {
        let mut p = pereche(AuthMode::Mutual, b"c", b"c");
        p.i.start().unwrap();
        assert_eq!(p.i.start(), Err(RelayError::BadLinkState));
    }

    #[test]
    fn raspunzatorul_nu_porneste() {
        let mut p = pereche(AuthMode::Mutual, b"c", b"c");
        assert_eq!(p.r.start(), Err(RelayError::BadLinkState));
    }
}
