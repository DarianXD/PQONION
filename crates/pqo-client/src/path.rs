//! Selectia caii dintr-un consens.
//!
//! # De ce nu alegem pur aleator
//!
//! Ponderarea dupa banda e necesara ca reteaua sa functioneze: daca toti clientii
//! ar alege uniform, releele mici s-ar sufoca iar cele mari ar sta degeaba. Dar
//! ponderarea singura nu ajunge — un adversar care ruleaza cateva relee rapide ar
//! aparea prea des in cai. De aceea exista constrangerile din [`Constraints`].
//!
//! # Guard-uri persistente
//!
//! Primul hop se alege **o singura data** si se refoloseste luni de zile.
//! Contraintuitiv, dar e cea mai importanta aparare a clientului.
//!
//! Daca ai alege un prim hop nou la fiecare circuit, probabilitatea sa nimeresti
//! macar o data unul ostil creste catre 1 pe masura ce construiesti circuite. Un
//! adversar care detine o fractiune mica din retea te prinde, mai devreme sau mai
//! tarziu, garantat.
//!
//! Cu un guard fix, ori ai nimerit de la inceput unul ostil — si atunci ai pierdut
//! imediat — ori esti in siguranta cat timp il pastrezi. Riscul se muta din
//! „sigur, la un moment dat" in „improbabil, dar tot sau nimic". Al doilea e mult
//! mai bun.
//!
//! # Ce lipseste
//!
//! Consensul nu contine cheile de handshake ale releelor, doar identitatile lor.
//! Cheile stau in descriptori, pe care un client real ii descarca prin circuit de
//! la o autoritate. Pana implementam asta, [`DescriptorCache`] se populeaza din
//! afara. Vezi nota de la sfarsitul modulului.

use std::collections::HashMap;

use pqo_crypto::RelayPublic;
use pqo_dirproto::netdoc::{Consensus, Fingerprint, RelayStatus};
use rand_core::RngCore;

use crate::ClientError;

/// Cate guard-uri isi tine un client.
///
/// Tor foloseste unul singur, cu un al doilea de rezerva. Trei e un compromis
/// intre disponibilitate (daca unul cade, ai unde merge) si expunere (fiecare
/// guard in plus e o sansa in plus sa fi nimerit unul ostil).
pub const N_GUARDS: usize = 3;

/// Constrangerile pe care trebuie sa le respecte o cale.
#[derive(Debug, Clone, Copy)]
pub struct Constraints {
    /// Doua relee din aceeasi subretea /16 nu pot aparea pe aceeasi cale.
    ///
    /// Sunt probabil ale aceluiasi operator sau in acelasi sistem autonom, deci
    /// cine vede unul poate vedea si pe celalalt. Fara regula asta, un operator
    /// cu doua masini in acelasi rack poate ocupa doua pozitii din trei.
    pub distinct_subnet16: bool,
    /// Lungimea caii.
    pub hops: usize,
}

impl Default for Constraints {
    fn default() -> Self {
        Constraints {
            distinct_subnet16: true,
            hops: 3,
        }
    }
}

/// Cheile de handshake ale releelor, indexate dupa fingerprint.
///
/// Intr-un client complet, se populeaza descarcand descriptori prin circuit.
#[derive(Debug, Default)]
pub struct DescriptorCache {
    keys: HashMap<Fingerprint, RelayPublic>,
}

impl DescriptorCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, fp: Fingerprint, public: RelayPublic) {
        self.keys.insert(fp, public);
    }

    pub fn get(&self, fp: &Fingerprint) -> Option<&RelayPublic> {
        self.keys.get(fp)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Un hop ales, cu tot ce trebuie ca sa fie contactat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    pub fingerprint: Fingerprint,
    pub address: String,
    pub or_port: u16,
    pub bandwidth: u64,
    pub pq_full: bool,
}

impl From<&RelayStatus> for Hop {
    fn from(r: &RelayStatus) -> Self {
        Hop {
            fingerprint: r.fingerprint,
            address: r.address.clone(),
            or_port: r.or_port,
            bandwidth: r.bandwidth,
            pq_full: r.pq_full,
        }
    }
}

/// Alege cai dintr-un consens.
#[derive(Debug)]
pub struct PathSelector {
    consensus: Consensus,
    guards: Vec<Fingerprint>,
    constraints: Constraints,
}

/// Primii doi octeti ai unei adrese IPv4, sau `None` daca nu e IPv4.
fn subnet16(addr: &str) -> Option<[u8; 2]> {
    let ip: std::net::Ipv4Addr = addr.parse().ok()?;
    let o = ip.octets();
    Some([o[0], o[1]])
}

/// Alege un element ponderat dupa banda.
///
/// Un releu cu banda zero nu se alege niciodata: ori e nou si nemasurat, ori e
/// mort. In ambele cazuri nu are ce cauta intr-un circuit.
fn weighted_pick<'a>(
    candidati: &[&'a RelayStatus],
    rng: &mut impl RngCore,
) -> Option<&'a RelayStatus> {
    let total: u128 = candidati.iter().map(|r| r.bandwidth as u128).sum();
    if total == 0 {
        return None;
    }
    // Reducere modulo pe un domeniu de 128 de biti: deviatia fata de uniform e
    // sub 2^-64, complet neglijabila aici.
    let mut tinta = (rng.next_u64() as u128) << 64 | rng.next_u64() as u128;
    tinta %= total;

    let mut acc: u128 = 0;
    for r in candidati {
        acc += r.bandwidth as u128;
        if acc > tinta {
            return Some(r);
        }
    }
    candidati.last().copied()
}

impl PathSelector {
    pub fn new(consensus: Consensus) -> Self {
        PathSelector {
            consensus,
            guards: Vec::new(),
            constraints: Constraints::default(),
        }
    }

    pub fn with_constraints(mut self, c: Constraints) -> Self {
        self.constraints = c;
        self
    }

    /// Guard-urile alese. Un client le salveaza pe disc si le reincarca.
    pub fn guards(&self) -> &[Fingerprint] {
        &self.guards
    }

    /// Reincarca guard-uri salvate anterior.
    ///
    /// Se pastreaza doar cele care mai sunt in consens si mai au flag-ul Guard.
    pub fn restore_guards(&mut self, saved: &[Fingerprint]) {
        self.guards = saved
            .iter()
            .filter(|fp| {
                self.consensus
                    .relays
                    .iter()
                    .any(|r| r.fingerprint == **fp && r.flags.has("Guard"))
            })
            .copied()
            .collect();
    }

    /// Completeaza setul de guard-uri pana la [`N_GUARDS`].
    ///
    /// Nu inlocuieste guard-urile existente: asta e tot rostul lor.
    pub fn ensure_guards(&mut self, rng: &mut impl RngCore) -> Result<(), ClientError> {
        while self.guards.len() < N_GUARDS {
            let candidati: Vec<&RelayStatus> = self
                .consensus
                .relays
                .iter()
                .filter(|r| {
                    r.flags.has("Guard")
                        && r.flags.has("Valid")
                        && !self.guards.contains(&r.fingerprint)
                })
                .collect();
            let Some(ales) = weighted_pick(&candidati, rng) else {
                break;
            };
            self.guards.push(ales.fingerprint);
        }
        if self.guards.is_empty() {
            return Err(ClientError::NoGuards);
        }
        Ok(())
    }

    fn status(&self, fp: &Fingerprint) -> Option<&RelayStatus> {
        self.consensus.relays.iter().find(|r| r.fingerprint == *fp)
    }

    /// Adevarat daca `r` poate fi adaugat la calea deja aleasa.
    fn compatibil(&self, cale: &[&RelayStatus], r: &RelayStatus) -> bool {
        if cale.iter().any(|x| x.fingerprint == r.fingerprint) {
            return false;
        }
        if self.constraints.distinct_subnet16 {
            if let Some(s) = subnet16(&r.address) {
                if cale
                    .iter()
                    .filter_map(|x| subnet16(&x.address))
                    .any(|t| t == s)
                {
                    return false;
                }
            }
        }
        true
    }

    /// Construieste o cale catre `port`.
    ///
    /// # Ordinea de alegere conteaza
    ///
    /// Se alege intai **exit-ul**, apoi guard-ul, apoi hop-urile din mijloc.
    /// Ordinea nu e arbitrara: exit-ul e pozitia cea mai constransa, pentru ca
    /// putine relee au flag-ul Exit. Daca l-am alege ultimul, un hop din mijloc
    /// ar putea ocupa exact releul care era singurul exit compatibil, si calea ar
    /// deveni imposibila desi exista una valida.
    ///
    /// Regula generala: alegi intai pozitia cu cei mai putini candidati. Mijlocul
    /// accepta aproape orice releu, deci se alege ultimul.
    pub fn build_path(
        &mut self,
        port: u16,
        rng: &mut impl RngCore,
    ) -> Result<Vec<Hop>, ClientError> {
        let _ = port;
        let n = self.constraints.hops;
        if n < 2 {
            return Err(ClientError::BadPathLength);
        }
        self.ensure_guards(rng)?;

        // 1. Exit-ul, cea mai constransa pozitie.
        let candidati: Vec<&RelayStatus> = self
            .consensus
            .relays
            .iter()
            .filter(|r| r.flags.has("Exit") && r.flags.has("Valid"))
            .collect();
        let exit = weighted_pick(&candidati, rng).ok_or(ClientError::NoExit)?;

        // 2. Guard-ul, dintre cele deja fixate, compatibil cu exit-ul.
        let g: Vec<&RelayStatus> = self
            .guards
            .iter()
            .filter_map(|f| self.status(f))
            .filter(|r| self.compatibil(&[exit], r))
            .collect();
        let guard = weighted_pick(&g, rng).ok_or(ClientError::NoGuards)?;

        // 3. Mijlocul, pozitia cea mai putin constransa.
        let mut cale: Vec<&RelayStatus> = vec![guard];
        for _ in 1..n - 1 {
            let mut deja = cale.clone();
            deja.push(exit);
            let candidati: Vec<&RelayStatus> = self
                .consensus
                .relays
                .iter()
                .filter(|r| r.flags.has("Valid") && self.compatibil(&deja, r))
                .collect();
            let ales = weighted_pick(&candidati, rng).ok_or(ClientError::NoPath)?;
            cale.push(ales);
        }
        cale.push(exit);

        Ok(cale.into_iter().map(Hop::from).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqo_dirproto::netdoc::{Flags, Validity};
    use rand_core::OsRng;

    fn releu(id: u8, bw: u64, flags: &[&str], subnet: u8) -> RelayStatus {
        RelayStatus {
            fingerprint: [id; 32],
            address: format!("10.{subnet}.0.{id}"),
            or_port: 9001,
            bandwidth: bw,
            flags: Flags::from_names(flags.iter().copied()).unwrap(),
            pq_full: true,
        }
    }

    fn consens(relee: Vec<RelayStatus>) -> Consensus {
        Consensus {
            validity: Validity {
                valid_after: 1000,
                fresh_until: 4600,
                valid_until: 11800,
            },
            params: vec![],
            relays: relee,
            signatures: vec![],
        }
    }

    /// O retea de test suficient de diversa ca sa existe cai valide.
    fn retea() -> Consensus {
        let mut r = Vec::new();
        for i in 1..=9u8 {
            let flags: &[&str] = match i % 3 {
                0 => &["Guard", "Fast", "Valid"],
                1 => &["Exit", "Fast", "Valid"],
                _ => &["Fast", "Valid"],
            };
            r.push(releu(i, 1000 * i as u64, flags, i));
        }
        consens(r)
    }

    #[test]
    fn calea_are_lungimea_ceruta() {
        let mut p = PathSelector::new(retea());
        let c = p.build_path(80, &mut OsRng).unwrap();
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn hopurile_sunt_distincte() {
        let mut p = PathSelector::new(retea());
        for _ in 0..200 {
            let c = p.build_path(80, &mut OsRng).unwrap();
            let mut fps: Vec<_> = c.iter().map(|h| h.fingerprint).collect();
            fps.sort();
            fps.dedup();
            assert_eq!(fps.len(), 3, "acelasi releu de doua ori pe cale");
        }
    }

    #[test]
    fn subretelele_sunt_distincte() {
        // Doua relee in acelasi /16 sunt probabil ale aceluiasi operator.
        let mut r = Vec::new();
        // Toate guard-urile si toate exit-urile in acelasi /16: nu exista cale.
        for i in 1..=3u8 {
            r.push(releu(i, 1000, &["Guard", "Valid"], 5));
        }
        for i in 4..=6u8 {
            r.push(releu(i, 1000, &["Exit", "Valid"], 5));
        }
        let mut p = PathSelector::new(consens(r));
        assert!(
            p.build_path(80, &mut OsRng).is_err(),
            "nu trebuie sa existe cale cand toate releele sunt in acelasi /16"
        );
    }

    #[test]
    fn subretelele_distincte_permit_cale() {
        let mut r = Vec::new();
        for i in 1..=3u8 {
            r.push(releu(i, 1000, &["Guard", "Valid"], i));
        }
        for i in 4..=6u8 {
            r.push(releu(i, 1000, &["Exit", "Valid"], i));
        }
        for i in 7..=9u8 {
            r.push(releu(i, 1000, &["Valid"], i));
        }
        let mut p = PathSelector::new(consens(r));
        let c = p.build_path(80, &mut OsRng).unwrap();
        let mut sub: Vec<_> = c.iter().filter_map(|h| subnet16(&h.address)).collect();
        sub.sort();
        sub.dedup();
        assert_eq!(sub.len(), 3);
    }

    #[test]
    fn ultimul_hop_e_exit() {
        let mut p = PathSelector::new(retea());
        let cons = retea();
        for _ in 0..50 {
            let c = p.build_path(443, &mut OsRng).unwrap();
            let ultimul = cons
                .relays
                .iter()
                .find(|r| r.fingerprint == c[2].fingerprint)
                .unwrap();
            assert!(ultimul.flags.has("Exit"), "ultimul hop trebuie sa fie exit");
        }
    }

    #[test]
    fn primul_hop_e_intotdeauna_un_guard_fixat() {
        // Proprietatea centrala: setul de prim hop nu se largeste in timp.
        let mut p = PathSelector::new(retea());
        p.ensure_guards(&mut OsRng).unwrap();
        let fixate: Vec<_> = p.guards().to_vec();
        assert!(!fixate.is_empty());

        for _ in 0..300 {
            let c = p.build_path(80, &mut OsRng).unwrap();
            assert!(
                fixate.contains(&c[0].fingerprint),
                "primul hop a iesit din setul de guard-uri"
            );
        }
        assert_eq!(p.guards(), &fixate[..], "setul nu are voie sa se schimbe");
    }

    #[test]
    fn guardurile_se_reincarca_si_se_filtreaza() {
        let mut p = PathSelector::new(retea());
        p.ensure_guards(&mut OsRng).unwrap();
        let salvate = p.guards().to_vec();

        // Client nou, acelasi consens: guard-urile se pastreaza.
        let mut q = PathSelector::new(retea());
        q.restore_guards(&salvate);
        assert_eq!(q.guards(), &salvate[..]);

        // Un guard care a disparut din consens se elimina.
        let mut fals = salvate.clone();
        fals.push([250u8; 32]);
        let mut r = PathSelector::new(retea());
        r.restore_guards(&fals);
        assert_eq!(
            r.guards().len(),
            salvate.len(),
            "un guard care nu mai e in consens nu se pastreaza"
        );
    }

    #[test]
    fn banda_zero_nu_se_alege_niciodata() {
        let mut r = vec![
            releu(1, 0, &["Guard", "Valid"], 1),
            releu(2, 1000, &["Guard", "Valid"], 2),
            releu(3, 1000, &["Valid"], 3),
            releu(4, 1000, &["Exit", "Valid"], 4),
        ];
        r.push(releu(5, 0, &["Exit", "Valid"], 5));
        let mut p = PathSelector::new(consens(r));
        for _ in 0..200 {
            let c = p.build_path(80, &mut OsRng).unwrap();
            for h in &c {
                assert_ne!(h.bandwidth, 0, "un releu cu banda zero a fost ales");
            }
        }
    }

    #[test]
    fn ponderarea_favorizeaza_banda_mare() {
        // Doua guard-uri, unul de zece ori mai rapid. Trebuie sa apara clar mai des.
        let r = vec![
            releu(1, 100, &["Guard", "Valid"], 1),
            releu(2, 1000, &["Guard", "Valid"], 2),
            releu(3, 1000, &["Valid"], 3),
            releu(4, 1000, &["Exit", "Valid"], 4),
        ];
        let mut p = PathSelector::new(consens(r));
        // Fortam un singur guard ca sa masuram alegerea, nu setul.
        p.guards = vec![[1u8; 32], [2u8; 32]];

        let mut rapid = 0;
        for _ in 0..2000 {
            let c = p.build_path(80, &mut OsRng).unwrap();
            if c[0].fingerprint == [2u8; 32] {
                rapid += 1;
            }
        }
        // Asteptat ~1818 din 2000. Marja larga ca sa nu fie test capricios.
        assert!(
            (1500..1990).contains(&rapid),
            "ponderarea pare gresita: {rapid} din 2000"
        );
    }

    #[test]
    fn fara_exit_nu_exista_cale() {
        let r = vec![
            releu(1, 1000, &["Guard", "Valid"], 1),
            releu(2, 1000, &["Valid"], 2),
        ];
        let mut p = PathSelector::new(consens(r));
        assert_eq!(p.build_path(80, &mut OsRng), Err(ClientError::NoExit));
    }

    #[test]
    fn mijlocul_nu_fura_singurul_exit() {
        // Regresia care a scos la iveala ordinea de alegere: cu un singur exit
        // utilizabil, un hop din mijloc ales inainte il putea ocupa, iar calea
        // devenea imposibila desi exista una valida.
        let r = vec![
            releu(1, 1000, &["Guard", "Valid"], 1),
            releu(2, 1000, &["Valid"], 2),
            releu(3, 1000, &["Exit", "Valid"], 3),
        ];
        let mut p = PathSelector::new(consens(r));
        for _ in 0..200 {
            let c = p
                .build_path(80, &mut OsRng)
                .expect("exista o cale valida, trebuie gasita de fiecare data");
            assert_eq!(c[2].fingerprint, [3u8; 32]);
            assert_eq!(c[1].fingerprint, [2u8; 32]);
        }
    }

    #[test]
    fn fara_guard_nu_exista_cale() {
        let r = vec![releu(1, 1000, &["Exit", "Valid"], 1)];
        let mut p = PathSelector::new(consens(r));
        assert_eq!(p.build_path(80, &mut OsRng), Err(ClientError::NoGuards));
    }

    #[test]
    fn consens_gol_nu_produce_panica() {
        let mut p = PathSelector::new(consens(vec![]));
        assert!(p.build_path(80, &mut OsRng).is_err());
        assert!(p.ensure_guards(&mut OsRng).is_err());
    }

    #[test]
    fn cai_de_doua_hopuri() {
        let mut p = PathSelector::new(retea()).with_constraints(Constraints {
            distinct_subnet16: true,
            hops: 2,
        });
        let c = p.build_path(80, &mut OsRng).unwrap();
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn lungime_invalida_e_respinsa() {
        let mut p = PathSelector::new(retea()).with_constraints(Constraints {
            distinct_subnet16: false,
            hops: 1,
        });
        assert_eq!(p.build_path(80, &mut OsRng), Err(ClientError::BadPathLength));
    }
}
