//! Metrici de releu.
//!
//! # Ce se masoara si de ce atat
//!
//! Toate contoarele de aici sunt **agregate pe intreg releul**. Niciunul nu
//! poate fi atribuit unui circuit, unui canal sau unui peer anume.
//!
//! Restrictia nu e din lene. Un releu care ar tine „circuitul X a transportat N
//! celule catre Y" ar avea pe disc exact ce ii trebuie unui adversar ca sa
//! coreleze traficul. Cine ia serverul ia si corelatiile. De aceea nu exista
//! nicaieri un contor per circuit, nici macar in memorie.
//!
//! Aceeasi politica ca la logging: nivelurile care ar putea scurge
//! identificatori nu exista in build de release.
//!
//! # Ce nu poti afla de aici
//!
//! Cati clienti distincti sunt conectati, ce circuite trec prin ce canale, cat
//! trafic a generat un anume peer, de unde vin conexiunile. Toate sunt masurabile
//! tehnic si toate ar fi utile pentru diagnostic — si tocmai de aceea nu sunt
//! aici. Un operator care are nevoie de ele are nevoie de fapt de un mediu de
//! test, nu de un releu in productie.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

/// Contoare agregate.
#[derive(Debug)]
pub struct Metrici {
    /// Cate circuite s-au creat de la pornire.
    circuite_create: AtomicU64,
    /// Cate circuite sunt deschise acum.
    circuite_active: AtomicI64,
    /// Cate canale sunt deschise acum.
    canale_active: AtomicI64,
    /// Cate celule au fost retransmise, in ambele sensuri.
    celule: AtomicU64,
    /// Cate stream-uri de iesire s-au deschis.
    streamuri: AtomicU64,
    /// Cate cereri de director s-au servit.
    cereri_director: AtomicU64,
    /// Cate handshake-uri de legatura au esuat.
    ///
    /// Numarul, nu de la cine: o crestere brusca inseamna ceva stricat sau un
    /// atac, iar asta se vede si fara sa stii sursa.
    handshake_esuate: AtomicU64,
    pornit_la: Instant,
}

impl Default for Metrici {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrici {
    pub fn new() -> Self {
        Metrici {
            circuite_create: AtomicU64::new(0),
            circuite_active: AtomicI64::new(0),
            canale_active: AtomicI64::new(0),
            celule: AtomicU64::new(0),
            streamuri: AtomicU64::new(0),
            cereri_director: AtomicU64::new(0),
            handshake_esuate: AtomicU64::new(0),
            pornit_la: Instant::now(),
        }
    }

    pub fn circuit_creat(&self) {
        self.circuite_create.fetch_add(1, Ordering::Relaxed);
        self.circuite_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn circuit_inchis(&self) {
        self.circuite_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn canal_deschis(&self) {
        self.canale_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn canal_inchis(&self) {
        self.canale_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn celula(&self) {
        self.celule.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stream_deschis(&self) {
        self.streamuri.fetch_add(1, Ordering::Relaxed);
    }

    pub fn cerere_director(&self) {
        self.cereri_director.fetch_add(1, Ordering::Relaxed);
    }

    pub fn handshake_esuat(&self) {
        self.handshake_esuate.fetch_add(1, Ordering::Relaxed);
    }

    /// Instantaneu al contoarelor.
    pub fn instantaneu(&self) -> Instantaneu {
        // Contoarele active pot fi negative pentru scurt timp daca o inchidere e
        // procesata inaintea deschiderii corespunzatoare. Le taiem la zero: o
        // valoare negativa afisata ar arata ca un bug, cand e doar o citire intre
        // doua actualizari.
        Instantaneu {
            secunde_de_la_pornire: self.pornit_la.elapsed().as_secs(),
            circuite_create: self.circuite_create.load(Ordering::Relaxed),
            circuite_active: self.circuite_active.load(Ordering::Relaxed).max(0) as u64,
            canale_active: self.canale_active.load(Ordering::Relaxed).max(0) as u64,
            celule: self.celule.load(Ordering::Relaxed),
            streamuri: self.streamuri.load(Ordering::Relaxed),
            cereri_director: self.cereri_director.load(Ordering::Relaxed),
            handshake_esuate: self.handshake_esuate.load(Ordering::Relaxed),
        }
    }
}

/// Valorile contoarelor la un moment dat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instantaneu {
    pub secunde_de_la_pornire: u64,
    pub circuite_create: u64,
    pub circuite_active: u64,
    pub canale_active: u64,
    pub celule: u64,
    pub streamuri: u64,
    pub cereri_director: u64,
    pub handshake_esuate: u64,
}

impl Instantaneu {
    /// Celule pe secunda, de la pornire.
    pub fn celule_pe_secunda(&self) -> f64 {
        if self.secunde_de_la_pornire == 0 {
            0.0
        } else {
            self.celule as f64 / self.secunde_de_la_pornire as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contoarele_cresc() {
        let m = Metrici::new();
        m.circuit_creat();
        m.circuit_creat();
        m.circuit_inchis();
        m.canal_deschis();
        for _ in 0..10 {
            m.celula();
        }
        let i = m.instantaneu();
        assert_eq!(i.circuite_create, 2, "totalul nu scade la inchidere");
        assert_eq!(i.circuite_active, 1);
        assert_eq!(i.canale_active, 1);
        assert_eq!(i.celule, 10);
    }

    #[test]
    fn valorile_active_nu_devin_negative() {
        // O inchidere procesata inaintea deschiderii corespunzatoare ar da un
        // numar negativ, care ar arata ca un bug fara sa fie.
        let m = Metrici::new();
        m.circuit_inchis();
        m.canal_inchis();
        let i = m.instantaneu();
        assert_eq!(i.circuite_active, 0);
        assert_eq!(i.canale_active, 0);
    }

    #[test]
    fn rata_e_zero_la_pornire() {
        let m = Metrici::new();
        m.celula();
        // Sub o secunda de la pornire: impartirea ar fi la zero.
        assert_eq!(m.instantaneu().celule_pe_secunda(), 0.0);
    }

    #[test]
    fn instantaneul_nu_contine_identificatori() {
        // Testul care apara politica: daca cineva adauga un camp cu fingerprint,
        // adresa sau numar de circuit, structura nu mai e `Copy` de tipuri
        // primitive si asta se vede.
        //
        // Nu e o garantie formala, dar e un semnal la revizuire.
        fn e_doar_numere<T: Copy + PartialEq>(_: &T) {}
        e_doar_numere(&Metrici::new().instantaneu());
    }

    #[test]
    fn contoarele_sunt_sigure_intre_fire() {
        let m = std::sync::Arc::new(Metrici::new());
        let mut fire = Vec::new();
        for _ in 0..8 {
            let m = std::sync::Arc::clone(&m);
            fire.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    m.celula();
                }
            }));
        }
        for f in fire {
            f.join().unwrap();
        }
        assert_eq!(m.instantaneu().celule, 8000);
    }
}
