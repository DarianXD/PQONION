//! Inelul de dispersie al HSDir si stocarea descriptorilor.
//!
//! # Cum se aleg nodurile responsabile
//!
//! Fiecare nod cu flag-ul `HSDir` primeste o pozitie pe un inel de 256 de biti,
//! recalculata la fiecare perioada. Descriptorul primeste si el o pozitie, pe
//! acelasi inel. Nodurile responsabile sunt primele `k` de dupa pozitia
//! descriptorului, in sens crescator, cu revenire la inceput.
//!
//! Pozitia unui nod depinde de o valoare aleatoare partajata (`srv`), calculata
//! colectiv de autoritati. Fara ea, un atacator ar putea genera chei pana isi
//! plaseaza noduri exact langa un serviciu tinta si i-ar controla descriptorul.
//!
//! **Simplificare, de documentat:** folosim ca `srv` hash-ul consensului
//! anterior. E predictibil cu o perioada inainte si manipulabil de o autoritate
//! ostila. Tor foloseste un protocol de commit-and-reveal intre autoritati.

use pqo_crypto::kdf;
use subtle::ConstantTimeEq;

use crate::blind::{BlindedId, TimePeriod};
use crate::desc::Descriptor;
use crate::HsError;

/// Cate replici ale descriptorului se publica.
pub const N_REPLICAS: u8 = 2;
/// Cate noduri stocheaza fiecare replica.
pub const N_STORE: usize = 3;

/// Valoarea aleatoare partajata pentru o perioada.
pub type SharedRandom = [u8; 32];

/// Pozitia pe inel a unei replici de descriptor.
pub fn hs_index(blinded: &BlindedId, replica: u8, period: TimePeriod) -> [u8; 32] {
    kdf::hash(
        b"pqonion-hs-store-idx-v1",
        &[blinded, &[replica], &period.0.to_le_bytes()],
    )
}

/// Pozitia pe inel a unui nod HSDir.
pub fn hsdir_index(node_fp: &[u8; 32], srv: &SharedRandom, period: TimePeriod) -> [u8; 32] {
    kdf::hash(
        b"pqonion-hs-node-idx-v1",
        &[node_fp, srv, &period.0.to_le_bytes()],
    )
}

/// Alege nodurile responsabile pentru un descriptor.
///
/// `nodes` sunt fingerprint-urile tuturor releelor cu flag-ul `HSDir` din
/// consens. Rezultatul e determinist: clientul si serviciul ajung la aceeasi
/// lista fara sa comunice.
pub fn responsible_nodes(
    nodes: &[[u8; 32]],
    blinded: &BlindedId,
    period: TimePeriod,
    srv: &SharedRandom,
) -> Vec<[u8; 32]> {
    if nodes.is_empty() {
        return Vec::new();
    }
    let mut inel: Vec<([u8; 32], [u8; 32])> = nodes
        .iter()
        .map(|fp| (hsdir_index(fp, srv, period), *fp))
        .collect();
    inel.sort_unstable();
    inel.dedup_by_key(|(_, fp)| *fp);

    let mut out: Vec<[u8; 32]> = Vec::new();
    for replica in 0..N_REPLICAS {
        let idx = hs_index(blinded, replica, period);
        let start = inel.partition_point(|(pos, _)| *pos < idx);
        for j in 0..N_STORE.min(inel.len()) {
            let fp = inel[(start + j) % inel.len()].1;
            if !out.contains(&fp) {
                out.push(fp);
            }
        }
    }
    out
}

/// Stocarea de descriptori a unui nod HSDir.
///
/// Regulile de acceptare sunt singura aparare impotriva suprascrierii, de vreme
/// ce nodul nu poate verifica cine detine slotul:
///   - un descriptor nou pentru un slot ocupat trebuie semnat cu **aceeasi**
///     cheie de perioada ca cel existent
///   - contorul de revizie trebuie sa fie strict mai mare
///
/// Efectul: cine publica primul intr-o perioada pastreaza slotul pana la
/// sfarsitul ei. Un atacator trebuie sa castige cursa, si sa o castige pe toate
/// cele `N_REPLICAS * N_STORE` noduri ca sa faca serviciul inaccesibil.
#[derive(Debug, Default)]
pub struct DescStore {
    intrari: Vec<(BlindedId, StoredDesc)>,
}

#[derive(Debug, Clone)]
struct StoredDesc {
    period: TimePeriod,
    revision: u64,
    period_key: Vec<u8>,
    doc: String,
}

impl DescStore {
    /// Cate descriptoare distincte tine un nod. Plafoneaza memoria.
    pub const MAX_ENTRIES: usize = 4096;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.intrari.len()
    }

    pub fn is_empty(&self) -> bool {
        self.intrari.is_empty()
    }

    /// Incearca sa stocheze un descriptor. `doc` trebuie deja verificat cu
    /// `Descriptor::parse_and_verify`.
    pub fn store(&mut self, d: &Descriptor, doc: &str) -> Result<(), HsError> {
        match self.intrari.iter_mut().find(|(b, _)| *b == d.blinded_id) {
            Some((_, existent)) => {
                if existent.period != d.period {
                    // Perioada noua: slotul se elibereaza si se poate rescrie.
                    *existent = StoredDesc {
                        period: d.period,
                        revision: d.revision,
                        period_key: d.period_key.clone(),
                        doc: doc.to_string(),
                    };
                    return Ok(());
                }
                if !bool::from(existent.period_key.ct_eq(&d.period_key)) {
                    return Err(HsError::SlotOccupied);
                }
                if d.revision <= existent.revision {
                    return Err(HsError::StaleRevision {
                        got: d.revision,
                        have: existent.revision,
                    });
                }
                existent.revision = d.revision;
                existent.doc = doc.to_string();
                Ok(())
            }
            None => {
                if self.intrari.len() >= Self::MAX_ENTRIES {
                    return Err(HsError::StoreFull);
                }
                self.intrari.push((
                    d.blinded_id,
                    StoredDesc {
                        period: d.period,
                        revision: d.revision,
                        period_key: d.period_key.clone(),
                        doc: doc.to_string(),
                    },
                ));
                Ok(())
            }
        }
    }

    /// Serveste un descriptor. Singurul lucru pe care un client il cere unui HSDir.
    pub fn fetch(&self, blinded: &BlindedId) -> Option<&str> {
        self.intrari
            .iter()
            .find(|(b, _)| b == blinded)
            .map(|(_, s)| s.doc.as_str())
    }

    /// Sterge intrarile din perioade expirate.
    pub fn expire(&mut self, before: TimePeriod) {
        self.intrari.retain(|(_, s)| s.period >= before);
    }
}

/// [`DescStore`] impachetat pentru folosire din mai multe task-uri.
///
/// Un HSDir primeste incarcari si cereri concurent. `Mutex` e suficient: fiecare
/// operatie e scurta si nu face I/O, spre deosebire de starea de circuit care
/// trebuie sa ramana intr-un singur task.
#[derive(Debug)]
pub struct SharedDescStore {
    inner: std::sync::Mutex<DescStore>,
}

impl SharedDescStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|s| s.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SharedDescStore {
    fn default() -> Self {
        SharedDescStore {
            inner: std::sync::Mutex::new(DescStore::new()),
        }
    }
}

impl pqo_dirproto::dirreq::HsDirStore for SharedDescStore {
    fn upload(&self, doc: &[u8]) -> Result<(), pqo_dirproto::dirreq::HsUploadError> {
        use pqo_dirproto::dirreq::HsUploadError as E;
        let text = core::str::from_utf8(doc).map_err(|_| E::Invalid)?;
        // Verificarea semnaturii se face aici, nu la apelant: un descriptor care
        // nu isi verifica propriul strat exterior nu intra in stocare.
        let d = crate::desc::Descriptor::parse_and_verify::<pqo_crypto::sig::Ed25519>(text)
            .map_err(|_| E::Invalid)?;
        let mut s = self.inner.lock().map_err(|_| E::Full)?;
        s.store(&d, text).map_err(|e| match e {
            HsError::StoreFull => E::Full,
            _ => E::Occupied,
        })
    }

    fn fetch(&self, blinded_id: &[u8; 32]) -> Option<Vec<u8>> {
        let s = self.inner.lock().ok()?;
        s.fetch(blinded_id).map(|d| d.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::OnionAddress;
    use crate::blind::{blinded_id, MasterSeed};
    use crate::desc::IntroPoint;
    use pqo_crypto::sig::Ed25519;

    type S = Ed25519;

    fn noduri(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| {
                let mut fp = [0u8; 32];
                fp[..8].copy_from_slice(&(i as u64).to_le_bytes());
                fp
            })
            .collect()
    }

    fn serviciu(seed: u8) -> (MasterSeed, OnionAddress) {
        let s = MasterSeed::new([seed; 32]);
        let (_k, pk) = s.identity_key::<S>();
        let a = OnionAddress::from_identity::<S>(&pk);
        (s, a)
    }

    fn intro(n: u8) -> IntroPoint {
        IntroPoint {
            relay_id: [n; 32],
            onion_x25519: [n; 32],
            onion_kem: None,
            svc_x25519: [0u8; 32],
            auth_key: vec![n; 32],
        }
    }

    #[test]
    fn alegerea_nodurilor_e_determinista() {
        let n = noduri(30);
        let b = [5u8; 32];
        let srv = [1u8; 32];
        let p = TimePeriod(10);
        assert_eq!(
            responsible_nodes(&n, &b, p, &srv),
            responsible_nodes(&n, &b, p, &srv),
            "clientul si serviciul trebuie sa ajunga la aceeasi lista"
        );
    }

    #[test]
    fn ordinea_nodurilor_de_intrare_nu_conteaza() {
        let mut n = noduri(30);
        let b = [5u8; 32];
        let srv = [1u8; 32];
        let p = TimePeriod(10);
        let referinta = responsible_nodes(&n, &b, p, &srv);
        n.reverse();
        assert_eq!(responsible_nodes(&n, &b, p, &srv), referinta);
        n.swap(0, 15);
        assert_eq!(responsible_nodes(&n, &b, p, &srv), referinta);
    }

    #[test]
    fn se_aleg_cel_mult_sase_noduri() {
        let n = noduri(50);
        let r = responsible_nodes(&n, &[7u8; 32], TimePeriod(1), &[2u8; 32]);
        assert!(r.len() <= (N_REPLICAS as usize) * N_STORE);
        assert!(r.len() >= N_STORE, "cel putin o replica completa");
        // Fara duplicate.
        let mut sortate = r.clone();
        sortate.sort();
        sortate.dedup();
        assert_eq!(sortate.len(), r.len());
    }

    #[test]
    fn nodurile_se_schimba_intre_perioade() {
        let n = noduri(60);
        let b = [9u8; 32];
        let srv = [3u8; 32];
        let a = responsible_nodes(&n, &b, TimePeriod(1), &srv);
        let c = responsible_nodes(&n, &b, TimePeriod(2), &srv);
        assert_ne!(a, c, "rotatia trebuie sa mute descriptorul");
    }

    #[test]
    fn retea_mica_nu_produce_panica() {
        for k in 0..4usize {
            let n = noduri(k);
            let r = responsible_nodes(&n, &[1u8; 32], TimePeriod(1), &[1u8; 32]);
            assert!(r.len() <= k);
        }
    }

    #[test]
    fn stocare_si_regasire() {
        let (seed, addr) = serviciu(1);
        let p = TimePeriod(4);
        let doc = crate::desc::Descriptor::build::<S>(&seed, &addr, p, 1, vec![intro(1)]).unwrap();
        let d = crate::desc::Descriptor::parse_and_verify::<S>(&doc).unwrap();

        let mut st = DescStore::new();
        st.store(&d, &doc).unwrap();
        let bid = blinded_id(addr.id(), p);
        assert_eq!(st.fetch(&bid), Some(doc.as_str()));
        assert_eq!(st.fetch(&[0u8; 32]), None);
    }

    #[test]
    fn revizia_trebuie_sa_creasca() {
        let (seed, addr) = serviciu(2);
        let p = TimePeriod(4);
        let mut st = DescStore::new();

        let d2 = crate::desc::Descriptor::build::<S>(&seed, &addr, p, 2, vec![intro(1)]).unwrap();
        let p2 = crate::desc::Descriptor::parse_and_verify::<S>(&d2).unwrap();
        st.store(&p2, &d2).unwrap();

        // Revizie mai mica: refuzata.
        let d1 = crate::desc::Descriptor::build::<S>(&seed, &addr, p, 1, vec![intro(1)]).unwrap();
        let p1 = crate::desc::Descriptor::parse_and_verify::<S>(&d1).unwrap();
        assert_eq!(
            st.store(&p1, &d1),
            Err(HsError::StaleRevision { got: 1, have: 2 })
        );

        // Egala: la fel.
        assert!(st.store(&p2, &d2).is_err());

        // Mai mare: acceptata.
        let d3 = crate::desc::Descriptor::build::<S>(&seed, &addr, p, 3, vec![intro(2)]).unwrap();
        let p3 = crate::desc::Descriptor::parse_and_verify::<S>(&d3).unwrap();
        st.store(&p3, &d3).unwrap();
        assert_eq!(st.fetch(&p3.blinded_id), Some(d3.as_str()));
    }

    #[test]
    fn primul_publicator_pastreaza_slotul() {
        // Doi publicatori care pretind acelasi index blindat, cu chei diferite.
        // Al doilea e refuzat, oricat de mare i-ar fi revizia.
        let (seed, addr) = serviciu(3);
        let p = TimePeriod(4);
        let mut st = DescStore::new();

        let doc = crate::desc::Descriptor::build::<S>(&seed, &addr, p, 1, vec![intro(1)]).unwrap();
        let d = crate::desc::Descriptor::parse_and_verify::<S>(&doc).unwrap();
        st.store(&d, &doc).unwrap();

        let atac = MasterSeed::new([0xEE; 32]);
        let (a_sk, a_pk) = atac.period_key::<S>(p);
        let mut fals = d.clone();
        fals.revision = u64::MAX;
        fals.period_key = a_pk;
        let _ = a_sk;
        assert_eq!(st.store(&fals, "fals"), Err(HsError::SlotOccupied));
        assert_eq!(st.fetch(&d.blinded_id), Some(doc.as_str()));
    }

    #[test]
    fn perioada_noua_elibereaza_slotul() {
        let (seed, addr) = serviciu(4);
        let mut st = DescStore::new();
        let d1 = crate::desc::Descriptor::build::<S>(&seed, &addr, TimePeriod(1), 5, vec![intro(1)])
            .unwrap();
        let p1 = crate::desc::Descriptor::parse_and_verify::<S>(&d1).unwrap();
        st.store(&p1, &d1).unwrap();

        // Acelasi index blindat nu poate aparea in doua perioade, dar simulam.
        let mut p2 = p1.clone();
        p2.period = TimePeriod(2);
        p2.revision = 1;
        p2.period_key = seed.period_key::<S>(TimePeriod(2)).1;
        st.store(&p2, "nou").unwrap();
        assert_eq!(st.fetch(&p1.blinded_id), Some("nou"));
    }

    #[test]
    fn expirarea_curata_perioadele_vechi() {
        let (seed, addr) = serviciu(5);
        let mut st = DescStore::new();
        for p in 1..=3u64 {
            let doc =
                crate::desc::Descriptor::build::<S>(&seed, &addr, TimePeriod(p), 1, vec![intro(1)])
                    .unwrap();
            let d = crate::desc::Descriptor::parse_and_verify::<S>(&doc).unwrap();
            st.store(&d, &doc).unwrap();
        }
        assert_eq!(st.len(), 3);
        st.expire(TimePeriod(3));
        assert_eq!(st.len(), 1);
    }
}
