//! Perioade de timp si blinding derivat prin hash.
//!
//! # Ce inlocuim
//!
//! Tor v3 deriva o cheie blindata per perioada prin operatie de grup:
//! `A' = h·A`, unde `h = H(A ‖ perioada)`. HSDir verifica semnatura sub `A'`
//! fara sa afle `A`, iar `A'` se schimba la fiecare perioada, deci HSDir nu poate
//! lega perioadele intre ele.
//!
//! **ML-DSA nu are aceasta structura.** Nu exista o operatie care sa transforme
//! o cheie publica intr-o alta cheie publica valida, in mod previzibil si
//! inversabil pe partea privata. Nu e o scapare de implementare, e o limitare
//! reala a schemelor bazate pe latice, si e o problema deschisa de cercetare.
//!
//! # Ce punem in loc
//!
//! Doua mecanisme separate care impreuna acopera doua din cele trei proprietati:
//!
//! 1. **Indexul blindat** se deriva prin hash din identificatorul adresei si
//!    numarul perioadei: `blinded_id = SHAKE256(addr_id ‖ perioada)`. Clientul il
//!    poate calcula (are `addr_id` din adresa), HSDir nu il poate inversa. Deci
//!    unlinkability se pastreaza, si e post-cuantica.
//!
//! 2. **Cheia de semnare per perioada** se deriva determinist din samanta master:
//!    `seed_t = SHAKE256(master_seed ‖ perioada)`. Serviciul o poate rederiva
//!    dupa o repornire; nimeni altcineva nu o poate calcula.
//!
//! Proprietatea a treia — HSDir sa poata verifica cine detine slotul — se pierde.
//! Vezi [`crate::desc`] pentru cum limitam consecinta.

use pqo_crypto::kdf::{self, ShakeRng};
use pqo_crypto::sig::Sig;

use crate::addr::AddrId;

/// Lungimea unei perioade, in secunde. O zi.
///
/// Compromisul: perioade scurte inseamna unlinkability mai buna, dar mai multa
/// republicare si ferestre mai stramte de sincronizare a ceasurilor. Tor
/// foloseste tot 24 de ore.
pub const PERIOD_LENGTH: u64 = 86_400;

/// Identificatorul sub care se stocheaza un descriptor la HSDir.
pub type BlindedId = [u8; 32];

/// O perioada de timp, numarata de la epoca Unix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimePeriod(pub u64);

impl TimePeriod {
    /// Perioada in care cade un moment dat.
    pub fn at(unix_time: u64) -> Self {
        TimePeriod(unix_time / PERIOD_LENGTH)
    }

    pub fn next(self) -> Self {
        TimePeriod(self.0 + 1)
    }

    pub fn prev(self) -> Self {
        TimePeriod(self.0.saturating_sub(1))
    }

    pub fn start(self) -> u64 {
        self.0 * PERIOD_LENGTH
    }

    /// Perioadele pentru care un serviciu tine descriptori publicati simultan.
    ///
    /// Doua, nu una: ceasurile clientilor si ale releelor nu sunt sincronizate
    /// perfect, iar un client al carui ceas o ia inainte ar cauta descriptorul
    /// perioadei urmatoare inainte ca serviciul sa il fi publicat. Suprapunerea
    /// elimina fereastra de indisponibilitate la trecerea dintre perioade.
    pub fn published(self) -> [TimePeriod; 2] {
        [self, self.next()]
    }
}

/// Indexul blindat sub care se publica descriptorul pentru o perioada.
///
/// Calculabil de oricine stie adresa. Neinversabil pentru HSDir, care vede doar
/// rezultatul. Doua perioade ale aceluiasi serviciu sunt nelegabile fara adresa.
pub fn blinded_id(addr: &AddrId, period: TimePeriod) -> BlindedId {
    kdf::hash(
        b"pqonion-hs-blind-v1",
        &[
            addr,
            &period.0.to_le_bytes(),
            &PERIOD_LENGTH.to_le_bytes(),
        ],
    )
}

/// Samanta master a unui serviciu ascuns.
///
/// Din ea se deriva atat cheia de identitate de lunga durata, cat si cheile de
/// semnare per perioada. E singurul lucru pe care serviciul trebuie sa il
/// pastreze pe disc.
#[derive(Clone)]
pub struct MasterSeed([u8; 32]);

impl core::fmt::Debug for MasterSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MasterSeed(redacted)")
    }
}

impl Drop for MasterSeed {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl MasterSeed {
    pub fn new(bytes: [u8; 32]) -> Self {
        MasterSeed(bytes)
    }

    pub fn random(rng: &mut impl rand_core::CryptoRngCore) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        MasterSeed(b)
    }

    /// Cheia de identitate de lunga durata. Din ea iese adresa `.onion`.
    pub fn identity_key<S: Sig>(&self) -> (S::SecretKey, Vec<u8>) {
        let mut rng = ShakeRng::new(b"pqonion-hs-identity-v1", &[&self.0]);
        S::keygen(&mut rng)
    }

    /// Cheia de semnare pentru o perioada.
    ///
    /// Determinista: acelasi serviciu, aceeasi perioada, aceeasi cheie, oricate
    /// reporniri ar fi intre. Fara asta, un serviciu care reporneste nu si-ar
    /// mai putea actualiza descriptorul deja publicat.
    pub fn period_key<S: Sig>(&self, period: TimePeriod) -> (S::SecretKey, Vec<u8>) {
        let mut rng = ShakeRng::new(
            b"pqonion-hs-period-key-v1",
            &[&self.0, &period.0.to_le_bytes()],
        );
        S::keygen(&mut rng)
    }
}

/// Corpul certificatului care leaga o cheie de perioada de identitatea master.
///
/// Traieste in stratul criptat al descriptorului: HSDir nu il vede, deci nu poate
/// lega perioadele. Clientul il verifica dupa ce decripteaza.
pub fn period_cert_body(period_pk: &[u8], period: TimePeriod) -> [u8; 32] {
    kdf::hash(
        b"pqonion-hs-period-cert-v1",
        &[period_pk, &period.0.to_le_bytes()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqo_crypto::sig::Ed25519;
    use rand_core::OsRng;

    type S = Ed25519;

    #[test]
    fn perioadele_se_calculeaza_corect() {
        assert_eq!(TimePeriod::at(0), TimePeriod(0));
        assert_eq!(TimePeriod::at(PERIOD_LENGTH - 1), TimePeriod(0));
        assert_eq!(TimePeriod::at(PERIOD_LENGTH), TimePeriod(1));
        assert_eq!(TimePeriod(5).start(), 5 * PERIOD_LENGTH);
        assert_eq!(TimePeriod(5).next(), TimePeriod(6));
        assert_eq!(TimePeriod(0).prev(), TimePeriod(0), "nu se scade sub zero");
    }

    #[test]
    fn se_publica_doua_perioade_deodata() {
        let p = TimePeriod(100);
        assert_eq!(p.published(), [TimePeriod(100), TimePeriod(101)]);
    }

    #[test]
    fn indexul_blindat_difera_de_la_perioada_la_perioada() {
        let addr = [7u8; 32];
        let a = blinded_id(&addr, TimePeriod(100));
        let b = blinded_id(&addr, TimePeriod(101));
        assert_ne!(a, b, "HSDir nu trebuie sa poata lega perioadele");
    }

    #[test]
    fn indexul_blindat_e_determinist() {
        let addr = [7u8; 32];
        assert_eq!(
            blinded_id(&addr, TimePeriod(100)),
            blinded_id(&addr, TimePeriod(100)),
            "clientul si serviciul trebuie sa ajunga la acelasi index"
        );
    }

    #[test]
    fn adrese_diferite_dau_indecsi_diferiti() {
        let a = blinded_id(&[1u8; 32], TimePeriod(5));
        let b = blinded_id(&[2u8; 32], TimePeriod(5));
        assert_ne!(a, b);
    }

    #[test]
    fn cheia_de_perioada_e_rederivabila() {
        let seed = MasterSeed::new([9u8; 32]);
        let (_sk1, pk1) = seed.period_key::<S>(TimePeriod(42));
        let (_sk2, pk2) = seed.period_key::<S>(TimePeriod(42));
        assert_eq!(pk1, pk2, "serviciul trebuie sa poata rederiva dupa repornire");
    }

    #[test]
    fn cheile_de_perioada_sunt_independente() {
        let seed = MasterSeed::new([9u8; 32]);
        let (_s1, p1) = seed.period_key::<S>(TimePeriod(42));
        let (_s2, p2) = seed.period_key::<S>(TimePeriod(43));
        assert_ne!(p1, p2);

        // Si fata de cheia de identitate.
        let (_si, pi) = seed.identity_key::<S>();
        assert_ne!(p1, pi, "separarea de domeniu trebuie sa functioneze");
    }

    #[test]
    fn seminte_diferite_dau_chei_diferite() {
        let a = MasterSeed::new([1u8; 32]);
        let b = MasterSeed::new([2u8; 32]);
        assert_ne!(
            a.period_key::<S>(TimePeriod(1)).1,
            b.period_key::<S>(TimePeriod(1)).1
        );
    }

    #[test]
    fn cheia_de_perioada_semneaza_si_verifica() {
        let seed = MasterSeed::new([3u8; 32]);
        let (sk, pk) = seed.period_key::<S>(TimePeriod(7));
        let msg = b"descriptor";
        let sig = S::sign(&sk, msg);
        assert!(S::verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn certificatul_de_perioada_leaga_perioada() {
        let a = period_cert_body(b"cheie", TimePeriod(1));
        let b = period_cert_body(b"cheie", TimePeriod(2));
        assert_ne!(a, b, "acelasi certificat nu are voie sa fie valid in doua perioade");
    }

    #[test]
    fn samanta_aleatoare_difera_de_fiecare_data() {
        let mut rng = OsRng;
        let a = MasterSeed::random(&mut rng);
        let b = MasterSeed::random(&mut rng);
        assert_ne!(a.identity_key::<S>().1, b.identity_key::<S>().1);
    }

    #[test]
    fn debug_nu_scurge_samanta() {
        let s = MasterSeed::new([0xAB; 32]);
        assert!(format!("{s:?}").contains("redacted"));
    }
}
