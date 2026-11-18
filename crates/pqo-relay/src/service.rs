//! Punctele de introducere si de rendezvous, ca masini de stari.
//!
//! Un releu poate juca ambele roluri simultan, pe circuite diferite. Ce e comun:
//! ambele **imperecheaza doua circuite** care nu se cunosc intre ele.
//!
//! ```text
//!   punct de introducere        punct de rendezvous
//!   serviciu ──ESTABLISH_INTRO──> IP     client ──ESTABLISH_RENDEZVOUS──> RP
//!   client ──INTRODUCE1──> IP                    serviciu ──RENDEZVOUS1──> RP
//!   IP ──INTRODUCE2──> serviciu                  RP imperecheaza circuitele
//! ```
//!
//! # Ce afla releul
//!
//! Punctul de introducere vede cererile de introducere si stie ce cheie de
//! autentificare le primeste, dar **nu poate citi corpul**: e criptat pentru
//! serviciu. Punctul de rendezvous vede doua circuite si un cookie de 20 de
//! octeti care se potriveste; nu stie cine sunt partile si nu poate citi
//! traficul, pentru ca hop-ul virtual are propria criptare.
//!
//! # Transportul hop-ului virtual
//!
//! Dupa imperechere, celulele hop-ului virtual circula ca **mesaje DATA pe un
//! stream rezervat**, iar releul le copiaza dintr-un circuit in celalalt fara sa
//! le atinga.
//!
//! Costul e masurabil: o celula a hop-ului virtual are 509 octeti (16 tag CGO +
//! 493 corp), iar un mesaj relay incape in 487 de octeti per celula. Deci
//! **fiecare celula virtuala consuma doua celule relay**. Alternativa ar fi fost
//! sa facem `LEN_XR` parametric si sa scadem corpul virtual la 471 de octeti,
//! ca sa incapa exact intr-o celula — dar asta ar schimba toate constantele CGO
//! si vectorii de test. Am ales suprapunerea de 2x, cu cifra la vedere.

use pqo_wire::{RelayCmd, StreamId};
use subtle::ConstantTimeEq;

use crate::circuit::{ChannelId, Endpoint};
use crate::RelayError;

/// Stream-ul rezervat pe care circula celulele hop-ului virtual dupa imperechere.
///
/// Numarul e in afara intervalului pe care si-l aloca un client pentru
/// stream-uri obisnuite, ca sa nu existe coliziune.
pub const RENDEZVOUS_STREAM: StreamId = StreamId(0xFFFF);

/// Cate puncte de introducere poate gazdui un releu.
pub const MAX_INTROS: usize = 512;
/// Cate rendezvous-uri in asteptare accepta un releu.
pub const MAX_RENDEZVOUS: usize = 1024;
/// Lungimea unui cookie de rendezvous.
pub const COOKIE_LEN: usize = 20;

/// Ce trebuie trimis, si pe ce circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceAction {
    /// Trimite un mesaj relay pe circuitul dat.
    Send {
        target: Endpoint,
        cmd: RelayCmd,
        body: Vec<u8>,
    },
    /// Doua circuite au fost imperecheate.
    ///
    /// Coaja de I/O nu trebuie sa faca nimic; e util pentru metrici si teste.
    Joined { a: Endpoint, b: Endpoint },
}

struct IntroReg {
    /// Circuitul pe care serviciul asteapta cereri.
    circ: Endpoint,
    /// Identificatorul cheii de autentificare, derivat de serviciu.
    auth_key_id: [u8; 32],
}

struct RendWait {
    cookie: [u8; COOKIE_LEN],
    /// Circuitul clientului, care asteapta.
    circ: Endpoint,
}

struct Joined {
    a: Endpoint,
    b: Endpoint,
}

/// Rolurile de serviciu ale unui releu.
#[derive(Debug, Default)]
pub struct ServiceTable {
    intros: Vec<IntroReg>,
    waiting: Vec<RendWait>,
    joined: Vec<Joined>,
}

impl core::fmt::Debug for IntroReg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IntroReg")
    }
}
impl core::fmt::Debug for RendWait {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RendWait")
    }
}
impl core::fmt::Debug for Joined {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Joined")
    }
}

impl ServiceTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn intro_count(&self) -> usize {
        self.intros.len()
    }

    pub fn waiting_count(&self) -> usize {
        self.waiting.len()
    }

    pub fn joined_count(&self) -> usize {
        self.joined.len()
    }

    // -----------------------------------------------------------------------
    // Punct de introducere
    // -----------------------------------------------------------------------

    /// Un serviciu se anunta pe circuitul dat.
    ///
    /// Corpul e un [`pqo_hs`]-style ESTABLISH_INTRO; aici nu il parsam complet,
    /// doar extragem identificatorul cheii de autentificare. Verificarea
    /// semnaturii se face de catre apelant, care stie ce schema foloseste.
    pub fn on_establish_intro(
        &mut self,
        circ: Endpoint,
        auth_key_id: [u8; 32],
    ) -> Result<Vec<ServiceAction>, RelayError> {
        if self.intros.len() >= MAX_INTROS {
            return Err(RelayError::TooManyCircuits);
        }
        // Un circuit nu poate gazdui doua inregistrari, si o cheie deja
        // inregistrata nu se muta pe alt circuit: altfel cine ghiceste
        // identificatorul poate devia cererile catre el.
        if self.intros.iter().any(|i| {
            i.circ == circ || bool::from(i.auth_key_id.ct_eq(&auth_key_id))
        }) {
            return Err(RelayError::CircuitExists);
        }
        self.intros.push(IntroReg { circ, auth_key_id });
        Ok(vec![ServiceAction::Send {
            target: circ,
            cmd: RelayCmd::IntroEstablished,
            body: Vec::new(),
        }])
    }

    /// Un client trimite o cerere de introducere.
    ///
    /// Corpul se retransmite **neschimbat** ca INTRODUCE2. Releul nu il poate
    /// citi: e criptat catre cheia serviciului.
    pub fn on_introduce1(
        &mut self,
        from: Endpoint,
        auth_key_id: &[u8; 32],
        body: Vec<u8>,
    ) -> Result<Vec<ServiceAction>, RelayError> {
        let Some(reg) = self
            .intros
            .iter()
            .find(|i| bool::from(i.auth_key_id.ct_eq(auth_key_id)))
        else {
            // Nu spunem clientului mai mult decat „nu e aici": daca am distinge
            // intre „cheie necunoscuta" si alte erori, un atacator ar putea
            // enumera ce servicii sunt gazduite de acest releu.
            return Ok(vec![ServiceAction::Send {
                target: from,
                cmd: RelayCmd::IntroduceAck,
                body: vec![1],
            }]);
        };
        Ok(vec![
            ServiceAction::Send {
                target: reg.circ,
                cmd: RelayCmd::Introduce2,
                body,
            },
            ServiceAction::Send {
                target: from,
                cmd: RelayCmd::IntroduceAck,
                body: vec![0],
            },
        ])
    }

    // -----------------------------------------------------------------------
    // Punct de rendezvous
    // -----------------------------------------------------------------------

    /// Un client lasa un cookie si asteapta.
    pub fn on_establish_rendezvous(
        &mut self,
        circ: Endpoint,
        cookie: [u8; COOKIE_LEN],
    ) -> Result<Vec<ServiceAction>, RelayError> {
        if self.waiting.len() >= MAX_RENDEZVOUS {
            return Err(RelayError::TooManyCircuits);
        }
        // Un cookie deja folosit nu se suprascrie: altfel oricine il observa
        // poate deturna rendezvous-ul altcuiva.
        if self
            .waiting
            .iter()
            .any(|w| bool::from(w.cookie.ct_eq(&cookie)) || w.circ == circ)
        {
            return Err(RelayError::CircuitExists);
        }
        self.waiting.push(RendWait { cookie, circ });
        Ok(vec![ServiceAction::Send {
            target: circ,
            cmd: RelayCmd::RendezvousEstablished,
            body: Vec::new(),
        }])
    }

    /// Serviciul soseste cu partea lui de handshake si cookie-ul.
    ///
    /// La potrivire, circuitele se imperecheaza si partea de handshake ajunge la
    /// client ca RENDEZVOUS2, **fara cookie**: clientul il stie deja, iar
    /// retrimiterea lui nu ar face decat sa mai ofere o copie unui observator.
    pub fn on_rendezvous1(
        &mut self,
        from: Endpoint,
        cookie: &[u8; COOKIE_LEN],
        handshake: Vec<u8>,
    ) -> Result<Vec<ServiceAction>, RelayError> {
        let pos = self
            .waiting
            .iter()
            .position(|w| bool::from(w.cookie.ct_eq(cookie)))
            .ok_or(RelayError::UnknownCircuit)?;
        let w = self.waiting.remove(pos);

        self.joined.push(Joined {
            a: w.circ,
            b: from,
        });
        Ok(vec![
            ServiceAction::Send {
                target: w.circ,
                cmd: RelayCmd::Rendezvous2,
                body: handshake,
            },
            ServiceAction::Joined {
                a: w.circ,
                b: from,
            },
        ])
    }

    /// Celalalt capat al unui circuit imperecheat.
    pub fn peer(&self, circ: Endpoint) -> Option<Endpoint> {
        self.joined.iter().find_map(|j| {
            if j.a == circ {
                Some(j.b)
            } else if j.b == circ {
                Some(j.a)
            } else {
                None
            }
        })
    }

    /// Copiaza un mesaj de pe stream-ul de rendezvous pe circuitul pereche.
    ///
    /// Releul nu atinge continutul: e criptat de hop-ul virtual, la care nu are
    /// cheia.
    pub fn relay_rendezvous(&self, from: Endpoint, body: Vec<u8>) -> Vec<ServiceAction> {
        match self.peer(from) {
            Some(target) => vec![ServiceAction::Send {
                target,
                cmd: RelayCmd::Data,
                body,
            }],
            None => Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Curatare
    // -----------------------------------------------------------------------

    /// Un circuit s-a inchis. Intoarce circuitul pereche, daca era imperecheat,
    /// ca apelantul sa il poata inchide si pe el.
    pub fn on_circuit_closed(&mut self, circ: Endpoint) -> Option<Endpoint> {
        self.intros.retain(|i| i.circ != circ);
        self.waiting.retain(|w| w.circ != circ);

        let pos = self.joined.iter().position(|j| j.a == circ || j.b == circ)?;
        let j = self.joined.remove(pos);
        Some(if j.a == circ { j.b } else { j.a })
    }

    /// Un canal a cazut: toate circuitele de pe el dispar.
    pub fn on_channel_closed(&mut self, chan: ChannelId) -> Vec<Endpoint> {
        self.intros.retain(|i| i.circ.chan != chan);
        self.waiting.retain(|w| w.circ.chan != chan);

        let mut perechi = Vec::new();
        let mut i = 0;
        while i < self.joined.len() {
            let j = &self.joined[i];
            if j.a.chan == chan {
                perechi.push(j.b);
                self.joined.remove(i);
            } else if j.b.chan == chan {
                perechi.push(j.a);
                self.joined.remove(i);
            } else {
                i += 1;
            }
        }
        perechi
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqo_wire::CircId;

    fn ep(chan: u64, circ: u32) -> Endpoint {
        Endpoint {
            chan: ChannelId(chan),
            circ: CircId(circ),
        }
    }

    fn tinta(a: &ServiceAction) -> Option<Endpoint> {
        match a {
            ServiceAction::Send { target, .. } => Some(*target),
            _ => None,
        }
    }

    fn cmd(a: &ServiceAction) -> Option<RelayCmd> {
        match a {
            ServiceAction::Send { cmd, .. } => Some(*cmd),
            _ => None,
        }
    }

    #[test]
    fn introducere_completa() {
        let mut t = ServiceTable::new();
        let serviciu = ep(1, 10);
        let client = ep(2, 20);
        let akid = [7u8; 32];

        let a = t.on_establish_intro(serviciu, akid).unwrap();
        assert_eq!(cmd(&a[0]), Some(RelayCmd::IntroEstablished));
        assert_eq!(t.intro_count(), 1);

        let corp = vec![0xABu8; 500];
        let a = t.on_introduce1(client, &akid, corp.clone()).unwrap();
        // Corpul ajunge la serviciu, neschimbat.
        assert_eq!(tinta(&a[0]), Some(serviciu));
        assert_eq!(cmd(&a[0]), Some(RelayCmd::Introduce2));
        match &a[0] {
            ServiceAction::Send { body, .. } => assert_eq!(body, &corp),
            _ => panic!(),
        }
        // Clientul primeste confirmare.
        assert_eq!(tinta(&a[1]), Some(client));
        assert_eq!(cmd(&a[1]), Some(RelayCmd::IntroduceAck));
    }

    #[test]
    fn cheie_neinregistrata_da_ack_negativ() {
        // Nu distingem intre „cheie necunoscuta" si alte erori: altfel un
        // atacator ar putea enumera serviciile gazduite.
        let mut t = ServiceTable::new();
        let client = ep(2, 20);
        let a = t.on_introduce1(client, &[9u8; 32], vec![1]).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(tinta(&a[0]), Some(client));
        match &a[0] {
            ServiceAction::Send { body, .. } => assert_eq!(body, &vec![1]),
            _ => panic!(),
        }
    }

    #[test]
    fn cheia_nu_se_muta_pe_alt_circuit() {
        // Cine ghiceste identificatorul nu are voie sa devieze cererile.
        let mut t = ServiceTable::new();
        let akid = [1u8; 32];
        t.on_establish_intro(ep(1, 10), akid).unwrap();
        assert_eq!(
            t.on_establish_intro(ep(9, 90), akid),
            Err(RelayError::CircuitExists)
        );
        assert_eq!(t.intro_count(), 1);
    }

    #[test]
    fn un_circuit_gazduieste_o_singura_inregistrare() {
        let mut t = ServiceTable::new();
        t.on_establish_intro(ep(1, 10), [1u8; 32]).unwrap();
        assert_eq!(
            t.on_establish_intro(ep(1, 10), [2u8; 32]),
            Err(RelayError::CircuitExists)
        );
    }

    #[test]
    fn rendezvous_complet() {
        let mut t = ServiceTable::new();
        let client = ep(1, 10);
        let serviciu = ep(2, 20);
        let cookie = [3u8; COOKIE_LEN];

        let a = t.on_establish_rendezvous(client, cookie).unwrap();
        assert_eq!(cmd(&a[0]), Some(RelayCmd::RendezvousEstablished));
        assert_eq!(t.waiting_count(), 1);

        let hs = vec![0xCDu8; 1184];
        let a = t.on_rendezvous1(serviciu, &cookie, hs.clone()).unwrap();
        // Handshake-ul ajunge la client, fara cookie.
        assert_eq!(tinta(&a[0]), Some(client));
        assert_eq!(cmd(&a[0]), Some(RelayCmd::Rendezvous2));
        match &a[0] {
            ServiceAction::Send { body, .. } => assert_eq!(body, &hs),
            _ => panic!(),
        }
        assert_eq!(a[1], ServiceAction::Joined { a: client, b: serviciu });
        assert_eq!(t.waiting_count(), 0);
        assert_eq!(t.joined_count(), 1);
    }

    #[test]
    fn imperecherea_merge_in_ambele_sensuri() {
        let mut t = ServiceTable::new();
        let client = ep(1, 10);
        let serviciu = ep(2, 20);
        let cookie = [4u8; COOKIE_LEN];
        t.on_establish_rendezvous(client, cookie).unwrap();
        t.on_rendezvous1(serviciu, &cookie, vec![]).unwrap();

        assert_eq!(t.peer(client), Some(serviciu));
        assert_eq!(t.peer(serviciu), Some(client));
        assert_eq!(t.peer(ep(9, 99)), None);

        let corp = vec![1u8; 509];
        let a = t.relay_rendezvous(client, corp.clone());
        assert_eq!(tinta(&a[0]), Some(serviciu));
        match &a[0] {
            // Releul copiaza octetii fara sa ii atinga.
            ServiceAction::Send { body, .. } => assert_eq!(body, &corp),
            _ => panic!(),
        }
        let a = t.relay_rendezvous(serviciu, corp.clone());
        assert_eq!(tinta(&a[0]), Some(client));
    }

    #[test]
    fn cookie_gresit_nu_imperecheaza() {
        let mut t = ServiceTable::new();
        t.on_establish_rendezvous(ep(1, 10), [5u8; COOKIE_LEN])
            .unwrap();
        assert_eq!(
            t.on_rendezvous1(ep(2, 20), &[6u8; COOKIE_LEN], vec![]),
            Err(RelayError::UnknownCircuit)
        );
        assert_eq!(t.joined_count(), 0);
    }

    #[test]
    fn cookie_duplicat_nu_deturneaza() {
        let mut t = ServiceTable::new();
        let cookie = [7u8; COOKIE_LEN];
        t.on_establish_rendezvous(ep(1, 10), cookie).unwrap();
        assert_eq!(
            t.on_establish_rendezvous(ep(2, 20), cookie),
            Err(RelayError::CircuitExists)
        );
        // Primul ramane.
        let a = t.on_rendezvous1(ep(3, 30), &cookie, vec![]).unwrap();
        assert_eq!(tinta(&a[0]), Some(ep(1, 10)));
    }

    #[test]
    fn un_cookie_se_foloseste_o_singura_data() {
        let mut t = ServiceTable::new();
        let cookie = [8u8; COOKIE_LEN];
        t.on_establish_rendezvous(ep(1, 10), cookie).unwrap();
        t.on_rendezvous1(ep(2, 20), &cookie, vec![]).unwrap();
        assert_eq!(
            t.on_rendezvous1(ep(3, 30), &cookie, vec![]),
            Err(RelayError::UnknownCircuit)
        );
    }

    #[test]
    fn fara_imperechere_nu_se_copiaza_nimic() {
        let t = ServiceTable::new();
        assert!(t.relay_rendezvous(ep(1, 10), vec![1, 2, 3]).is_empty());
    }

    #[test]
    fn inchiderea_unui_circuit_da_perechea() {
        let mut t = ServiceTable::new();
        let client = ep(1, 10);
        let serviciu = ep(2, 20);
        let cookie = [9u8; COOKIE_LEN];
        t.on_establish_rendezvous(client, cookie).unwrap();
        t.on_rendezvous1(serviciu, &cookie, vec![]).unwrap();

        assert_eq!(t.on_circuit_closed(client), Some(serviciu));
        assert_eq!(t.joined_count(), 0);
        // A doua oara nu mai exista.
        assert_eq!(t.on_circuit_closed(client), None);
    }

    #[test]
    fn inchiderea_curata_si_inregistrarile() {
        let mut t = ServiceTable::new();
        t.on_establish_intro(ep(1, 10), [1u8; 32]).unwrap();
        t.on_establish_rendezvous(ep(1, 11), [2u8; COOKIE_LEN])
            .unwrap();
        assert_eq!(t.on_circuit_closed(ep(1, 10)), None);
        assert_eq!(t.intro_count(), 0);
        assert_eq!(t.on_circuit_closed(ep(1, 11)), None);
        assert_eq!(t.waiting_count(), 0);
    }

    #[test]
    fn caderea_unui_canal_curata_tot() {
        let mut t = ServiceTable::new();
        t.on_establish_intro(ep(1, 10), [1u8; 32]).unwrap();
        t.on_establish_rendezvous(ep(1, 11), [2u8; COOKIE_LEN])
            .unwrap();
        // Un rendezvous imperecheat pe doua canale diferite.
        t.on_establish_rendezvous(ep(1, 12), [3u8; COOKIE_LEN])
            .unwrap();
        t.on_rendezvous1(ep(2, 20), &[3u8; COOKIE_LEN], vec![])
            .unwrap();

        let perechi = t.on_channel_closed(ChannelId(1));
        assert_eq!(perechi, vec![ep(2, 20)], "perechea trebuie anuntata");
        assert_eq!(t.intro_count(), 0);
        assert_eq!(t.waiting_count(), 0);
        assert_eq!(t.joined_count(), 0);
    }

    #[test]
    fn plafoanele_sunt_aplicate() {
        let mut t = ServiceTable::new();
        for i in 0..MAX_INTROS {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64).to_le_bytes());
            t.on_establish_intro(ep(1, i as u32), k).unwrap();
        }
        assert_eq!(
            t.on_establish_intro(ep(9, 9), [0xFF; 32]),
            Err(RelayError::TooManyCircuits)
        );

        let mut r = ServiceTable::new();
        for i in 0..MAX_RENDEZVOUS {
            let mut c = [0u8; COOKIE_LEN];
            c[..8].copy_from_slice(&(i as u64).to_le_bytes());
            r.on_establish_rendezvous(ep(1, i as u32), c).unwrap();
        }
        assert_eq!(
            r.on_establish_rendezvous(ep(9, 9), [0xFF; COOKIE_LEN]),
            Err(RelayError::TooManyCircuits)
        );
    }
}
