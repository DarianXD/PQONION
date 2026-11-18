//! Planificarea publicarii unui serviciu ascuns.
//!
//! Modulul nu face I/O: calculeaza **ce** trebuie publicat si **unde**, iar
//! stratul de retea executa. Din acelasi motiv ca peste tot: pot testa logica de
//! selectie a HSDir-urilor si de rotatie a perioadelor fara socket-uri.

use pqo_crypto::sig::Sig;

use crate::addr::OnionAddress;
use crate::blind::{blinded_id, MasterSeed, TimePeriod};
use crate::desc::{Descriptor, IntroPoint};
use crate::hsdir::{responsible_nodes, SharedRandom};
use crate::HsError;

/// Cheile persistente ale unui serviciu.
///
/// Tot ce trebuie salvat pe disc e samanta. Adresa si toate cheile se rederiva
/// din ea, deci un serviciu care reporneste isi pastreaza adresa.
#[derive(Debug)]
pub struct ServiceKeys {
    seed: MasterSeed,
    address: OnionAddress,
}

impl ServiceKeys {
    /// Construieste din samanta salvata.
    pub fn from_seed<S: Sig>(bytes: [u8; 32]) -> Self {
        let seed = MasterSeed::new(bytes);
        let (_sk, pk) = seed.identity_key::<S>();
        let address = OnionAddress::from_identity::<S>(&pk);
        ServiceKeys { seed, address }
    }

    pub fn address(&self) -> &OnionAddress {
        &self.address
    }

    pub fn seed(&self) -> &MasterSeed {
        &self.seed
    }
}

/// Un descriptor de publicat si nodurile care trebuie sa il primeasca.
#[derive(Debug, Clone)]
pub struct PublishTarget {
    pub period: TimePeriod,
    pub blinded_id: [u8; 32],
    /// Documentul serializat.
    pub document: String,
    /// Fingerprint-urile HSDir-urilor responsabile.
    pub nodes: Vec<[u8; 32]>,
}

/// Ce trebuie publicat acum.
#[derive(Debug, Clone)]
pub struct PublishPlan {
    pub targets: Vec<PublishTarget>,
}

impl PublishPlan {
    /// Calculeaza ce trebuie publicat la momentul `now`.
    ///
    /// Se publica pentru **doua** perioade simultan, cea curenta si urmatoarea.
    /// Ceasurile clientilor si ale releelor nu sunt sincronizate perfect; un
    /// client al carui ceas o ia inainte ar cauta descriptorul perioadei
    /// urmatoare inainte ca serviciul sa il fi publicat. Suprapunerea elimina
    /// fereastra de indisponibilitate.
    pub fn build<S: Sig>(
        keys: &ServiceKeys,
        now: u64,
        revision: u64,
        intro_points: &[IntroPoint],
        hsdirs: &[[u8; 32]],
        srv: &SharedRandom,
    ) -> Result<Self, HsError> {
        let curenta = TimePeriod::at(now);
        let mut targets = Vec::new();

        for p in curenta.published() {
            let doc = Descriptor::build::<S>(
                keys.seed(),
                keys.address(),
                p,
                revision,
                intro_points.to_vec(),
            )?;
            let bid = blinded_id(keys.address().id(), p);
            targets.push(PublishTarget {
                period: p,
                blinded_id: bid,
                document: doc,
                nodes: responsible_nodes(hsdirs, &bid, p, srv),
            });
        }
        Ok(PublishPlan { targets })
    }

    /// Cate incarcari presupune planul.
    pub fn upload_count(&self) -> usize {
        self.targets.iter().map(|t| t.nodes.len()).sum()
    }
}

/// Unde trebuie sa caute un client descriptorul unei adrese.
///
/// Se incearca ambele perioade: daca ceasul clientului e putin inaintea celui al
/// serviciului, descriptorul perioadei curente poate sa nu existe inca.
pub fn fetch_targets(
    addr: &OnionAddress,
    now: u64,
    hsdirs: &[[u8; 32]],
    srv: &SharedRandom,
) -> Vec<([u8; 32], Vec<[u8; 32]>)> {
    TimePeriod::at(now)
        .published()
        .iter()
        .map(|p| {
            let bid = blinded_id(addr.id(), *p);
            (bid, responsible_nodes(hsdirs, &bid, *p, srv))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqo_crypto::sig::Ed25519;

    type S = Ed25519;

    fn intro(n: u8) -> IntroPoint {
        IntroPoint {
            relay_id: [n; 32],
            onion_x25519: [n; 32],
            onion_kem: None,
            svc_x25519: [0u8; 32],
            auth_key: vec![n; 32],
        }
    }

    fn hsdirs(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| {
                let mut fp = [0u8; 32];
                fp[..8].copy_from_slice(&(i as u64).to_le_bytes());
                fp
            })
            .collect()
    }

    #[test]
    fn adresa_supravietuieste_repornirii() {
        let a = ServiceKeys::from_seed::<S>([7u8; 32]);
        let b = ServiceKeys::from_seed::<S>([7u8; 32]);
        assert_eq!(a.address(), b.address());
        assert_eq!(a.address().to_string().len(), 62);
    }

    #[test]
    fn planul_acopera_doua_perioade() {
        let k = ServiceKeys::from_seed::<S>([1u8; 32]);
        let p = PublishPlan::build::<S>(
            &k,
            1_700_000_000,
            1,
            &[intro(1), intro(2)],
            &hsdirs(40),
            &[5u8; 32],
        )
        .unwrap();
        assert_eq!(p.targets.len(), 2, "curenta plus urmatoarea");
        assert_ne!(
            p.targets[0].blinded_id, p.targets[1].blinded_id,
            "indecsii perioadelor nu au voie sa coincida"
        );
        assert!(p.upload_count() >= 6, "cel putin doua replici pe perioada");
    }

    #[test]
    fn clientul_cauta_unde_a_publicat_serviciul() {
        // Proprietatea centrala: fara sa comunice, cele doua parti ajung la
        // aceleasi noduri.
        let k = ServiceKeys::from_seed::<S>([2u8; 32]);
        let noduri = hsdirs(40);
        let srv = [9u8; 32];
        let acum = 1_700_000_000;

        let plan =
            PublishPlan::build::<S>(&k, acum, 1, &[intro(1)], &noduri, &srv).unwrap();
        let cautari = fetch_targets(k.address(), acum, &noduri, &srv);

        assert_eq!(cautari.len(), plan.targets.len());
        for (t, (bid, n)) in plan.targets.iter().zip(cautari.iter()) {
            assert_eq!(&t.blinded_id, bid, "index blindat diferit");
            assert_eq!(&t.nodes, n, "noduri diferite");
        }
    }

    #[test]
    fn descriptorii_publicati_sunt_valizi() {
        let k = ServiceKeys::from_seed::<S>([3u8; 32]);
        let p =
            PublishPlan::build::<S>(&k, 1_700_000_000, 5, &[intro(1)], &hsdirs(20), &[1u8; 32])
                .unwrap();
        for t in &p.targets {
            let d = Descriptor::parse_and_verify::<S>(&t.document).expect("descriptor valid");
            assert_eq!(d.revision, 5);
            assert_eq!(d.blinded_id, t.blinded_id);
            // Doar cine stie adresa poate deschide stratul interior.
            let inner = d.open_inner::<S>(k.address()).expect("strat interior");
            assert_eq!(inner.intro_points.len(), 1);
        }
    }

    #[test]
    fn fara_puncte_de_introducere_planul_esueaza() {
        let k = ServiceKeys::from_seed::<S>([4u8; 32]);
        assert!(
            PublishPlan::build::<S>(&k, 1, 1, &[], &hsdirs(10), &[0u8; 32]).is_err(),
            "un serviciu fara puncte de introducere nu are ce publica"
        );
    }

    #[test]
    fn planul_se_muta_odata_cu_perioada() {
        let k = ServiceKeys::from_seed::<S>([5u8; 32]);
        let n = hsdirs(40);
        let srv = [1u8; 32];
        let a = PublishPlan::build::<S>(&k, 0, 1, &[intro(1)], &n, &srv).unwrap();
        let b = PublishPlan::build::<S>(
            &k,
            crate::blind::PERIOD_LENGTH * 5,
            1,
            &[intro(1)],
            &n,
            &srv,
        )
        .unwrap();
        assert_ne!(a.targets[0].blinded_id, b.targets[0].blinded_id);
        assert_ne!(a.targets[0].nodes, b.targets[0].nodes);
    }
}

#[cfg(test)]
mod dimensiuni {
    use super::*;
    use pqo_crypto::sig::Ed25519;

    #[test]
    fn descriptorul_depaseste_o_celula() {
        // Cifra care dicteaza cum trebuie transportate cererile de director.
        let k = ServiceKeys::from_seed::<Ed25519>([1u8; 32]);
        let ip = crate::desc::IntroPoint {
            relay_id: [1; 32],
            onion_x25519: [1; 32],
            onion_kem: None,
            svc_x25519: [0u8; 32],
            auth_key: vec![1; 32],
        };
        let p = PublishPlan::build::<Ed25519>(
            &k,
            1_700_000_000,
            1,
            &[ip],
            &[[0u8; 32]],
            &[0u8; 32],
        )
        .unwrap();
        let n = p.targets[0].document.len();
        assert!(
            n > 487,
            "descriptorul are {n} octeti; daca ar incapea intr-o celula, \
             fragmentarea cererilor de director n-ar mai fi necesara"
        );
    }
}
