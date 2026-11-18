//! Tabela de circuite si rutarea la un releu.
//!
//! # Modelul
//!
//! Un circuit, vazut de un releu din mijloc, e o **pereche** de capete:
//! `prev` catre client si `next` catre hop-ul urmator. Rolul releului e sa mute
//! celule intre ele, decriptand exact un strat in fiecare sens.
//!
//! ```text
//!   client ──(chan A, circ 5)──> [releu] ──(chan B, circ 9)──> hop urmator
//! ```
//!
//! Identificatorii de circuit sunt **locali fiecarui canal**. Acelasi circuit are
//! numere diferite pe cele doua legaturi, si asta e intentionat: un observator
//! care vede ambele legaturi nu poate corela dupa numar.
//!
//! # Fara I/O
//!
//! Fiecare metoda intoarce o lista de [`Action`]. Nu se deschide niciun socket,
//! nu se scrie nimic. Coaja de I/O executa actiunile si raporteaza inapoi
//! rezultatele. Consecinta practica: pot testa aici rutarea completa, inclusiv
//! cazurile de eroare, fara retea.

use pqo_crypto::cgo::{Outbound, RelayCircuit};
use pqo_crypto::kem::Kem;
use pqo_crypto::{server_respond, RelayKeys};
use pqo_wire::{
    Cell, ChanCmd, CircId, Create2, Created2, Extend2, Extended2, Reassembler, RelayCmd,
    RelayMessage, StreamId,
};
use rand_core::CryptoRngCore;

use crate::RelayError;

/// Identificator local de canal, atribuit de coaja de I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelId(pub u64);

/// Un capat de circuit: pe ce canal si cu ce numar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub chan: ChannelId,
    pub circ: CircId,
}

/// Cate celule RELAY_EARLY acceptam pe un circuit.
///
/// Fiecare EXTEND2 consuma una. Plafonul limiteaza lungimea unui circuit, ca
/// aparare impotriva unui client care ar construi circuite arbitrar de lungi ca
/// sa amplifice trafic sau sa creeze bucle.
pub const MAX_RELAY_EARLY: u8 = 8;

/// Cate circuite tine un releu simultan.
pub const MAX_CIRCUITS: usize = 8192;

/// Ce trebuie sa faca coaja de I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Trimite o celula pe un canal deja deschis.
    Send { chan: ChannelId, cell: Cell },
    /// Deschide un canal catre un releu si raporteaza inapoi cu `channel_ready`.
    ///
    /// `token` identifica extinderea in asteptare.
    Connect {
        relay_id: [u8; 32],
        address: String,
        port: u16,
        token: u64,
    },
    /// Circuitul a fost inchis; elibereaza resursele asociate.
    CircuitClosed { chan: ChannelId, circ: CircId },
    /// Un mesaj relay a ajuns la destinatie si trebuie tratat de stratul de sus
    /// (deschidere de stream, date, SENDME).
    Deliver {
        chan: ChannelId,
        circ: CircId,
        msg: RelayMessage,
    },
}

/// O extindere in asteptarea deschiderii unui canal.
struct PendingExtend {
    token: u64,
    /// Circuitul dinspre client care a cerut extinderea.
    prev: Endpoint,
    /// Payload-ul CREATE2 de trimis dupa ce canalul e gata.
    create2: Vec<u8>,
}

struct Circuit<K: Kem> {
    prev: Endpoint,
    next: Option<Endpoint>,
    cgo: RelayCircuit,
    reasm: Reassembler,
    relay_early: u8,
    /// Marcat cand asteptam CREATED2 de la hop-ul urmator.
    extending: bool,
    _kem: core::marker::PhantomData<K>,
}

/// Nucleul unui releu: cheile lui si circuitele pe care le deserveste.
pub struct RelayNode<K: Kem> {
    keys: RelayKeys<K>,
    circuits: Vec<Circuit<K>>,
    pending: Vec<PendingExtend>,
    next_token: u64,
    next_circ: u32,
}

impl<K: Kem> core::fmt::Debug for RelayNode<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "RelayNode({} circuite, {} extinderi in asteptare)",
            self.circuits.len(),
            self.pending.len()
        )
    }
}

impl<K: Kem> RelayNode<K> {
    pub fn new(keys: RelayKeys<K>) -> Self {
        RelayNode {
            keys,
            circuits: Vec::new(),
            pending: Vec::new(),
            next_token: 1,
            next_circ: 1,
        }
    }

    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    fn find(&mut self, chan: ChannelId, circ: CircId) -> Option<usize> {
        self.circuits.iter().position(|c| {
            (c.prev.chan == chan && c.prev.circ == circ)
                || c.next.is_some_and(|n| n.chan == chan && n.circ == circ)
        })
    }

    /// Aloca un numar de circuit pentru un canal pe care noi initiem.
    ///
    /// Bitul cel mai semnificativ marcheaza initiatorul, ca sa nu existe
    /// coliziuni intre cele doua capete ale aceluiasi canal.
    fn alloc_circ(&mut self) -> CircId {
        let id = CircId(0x8000_0000 | self.next_circ);
        self.next_circ = self.next_circ.wrapping_add(1).max(1);
        id
    }

    // -----------------------------------------------------------------------
    // Creare de circuit
    // -----------------------------------------------------------------------

    /// Un client sau un releu ne cere sa cream primul hop.
    pub fn on_create2(
        &mut self,
        chan: ChannelId,
        circ: CircId,
        payload: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<Action>, RelayError> {
        if circ.is_none() {
            return Err(RelayError::BadCircId);
        }
        if self.circuits.len() >= MAX_CIRCUITS {
            return Err(RelayError::TooManyCircuits);
        }
        // Un numar deja folosit pe acest canal nu se refoloseste: altfel un peer
        // ar putea suprascrie starea criptografica a unui circuit existent.
        if self.find(chan, circ).is_some() {
            return Err(RelayError::CircuitExists);
        }

        let create = Create2::parse(payload).map_err(RelayError::Wire)?;
        let (hs, res) =
            server_respond::<K>(&self.keys, &create.data, rng).map_err(RelayError::Ntor)?;

        self.circuits.push(Circuit {
            prev: Endpoint { chan, circ },
            next: None,
            cgo: RelayCircuit::new(&res.key_seed),
            reasm: Reassembler::new(),
            relay_early: 0,
            extending: false,
            _kem: core::marker::PhantomData,
        });

        let cell = Cell::var(circ, ChanCmd::Created2, Created2 { data: hs }.encode())
            .map_err(RelayError::Wire)?;
        Ok(vec![Action::Send { chan, cell }])
    }

    // -----------------------------------------------------------------------
    // Celule dinspre client
    // -----------------------------------------------------------------------

    /// O celula RELAY sau RELAY_EARLY a sosit dinspre client.
    pub fn on_relay_forward(
        &mut self,
        chan: ChannelId,
        circ: CircId,
        cell: &Cell,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<Action>, RelayError> {
        let early = cell.cmd() == ChanCmd::RelayEarly;
        let idx = self.find(chan, circ).ok_or(RelayError::UnknownCircuit)?;

        // Verificam ca vine chiar dinspre client, nu dinspre hop-ul urmator.
        if self.circuits[idx].prev.chan != chan || self.circuits[idx].prev.circ != circ {
            return Err(RelayError::WrongDirection);
        }
        if early {
            let c = &mut self.circuits[idx];
            c.relay_early += 1;
            if c.relay_early > MAX_RELAY_EARLY {
                return Ok(self.teardown(idx, "prea multe RELAY_EARLY"));
            }
        }

        let ad = cell.cmd() as u8;
        let payload: &[u8; pqo_crypto::cgo::MSG_LEN] = cell
            .payload()
            .try_into()
            .map_err(|_| RelayError::BadCellSize)?;

        match self.circuits[idx].cgo.process_outbound(ad, payload) {
            Outbound::Recognized(body) => {
                let msg = match self.circuits[idx].reasm.push(body.as_slice()) {
                    Ok(Some(m)) => m,
                    Ok(None) => return Ok(Vec::new()),
                    Err(e) => return Err(RelayError::Wire(e)),
                };
                self.handle_message(idx, msg, early, rng)
            }
            Outbound::Forward(next_cell) => {
                let Some(next) = self.circuits[idx].next else {
                    // Nimeni de partea cealalta: circuitul nu a fost extins.
                    return Ok(self.teardown(idx, "celula de retransmis fara hop urmator"));
                };
                // RELAY_EARLY se degradeaza la RELAY dupa primul hop, ca sa nu
                // poata fi folosit pentru a construi circuite nelimitate.
                let cmd = if early {
                    ChanCmd::RelayEarly
                } else {
                    ChanCmd::Relay
                };
                let out = Cell::fixed(next.circ, cmd, next_cell.as_slice())
                    .map_err(RelayError::Wire)?;
                Ok(vec![Action::Send {
                    chan: next.chan,
                    cell: out,
                }])
            }
        }
    }

    /// Un mesaj relay ne e adresat noua.
    fn handle_message(
        &mut self,
        idx: usize,
        msg: RelayMessage,
        early: bool,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<Action>, RelayError> {
        match msg.cmd {
            RelayCmd::Extend2 => {
                // Extinderea se cere doar prin RELAY_EARLY. Fara regula asta,
                // plafonul de lungime de circuit nu ar avea efect.
                if !early {
                    return Ok(self.teardown(idx, "EXTEND2 fara RELAY_EARLY"));
                }
                if self.circuits[idx].next.is_some() || self.circuits[idx].extending {
                    return Ok(self.teardown(idx, "circuit deja extins"));
                }
                let ext = Extend2::parse(&msg.body).map_err(RelayError::Wire)?;
                let relay_id = ext.relay_id().ok_or(RelayError::NoRelayId)?;
                let (address, port) = ext
                    .specs
                    .iter()
                    .find_map(|s| match s {
                        pqo_wire::LinkSpec::Ipv4 { addr, port } => Some((
                            format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]),
                            *port,
                        )),
                        _ => None,
                    })
                    .ok_or(RelayError::NoAddress)?;

                let create2 = Create2 {
                    htype: ext.htype,
                    data: ext.data,
                }
                .encode();

                let token = self.next_token;
                self.next_token += 1;
                self.circuits[idx].extending = true;
                self.pending.push(PendingExtend {
                    token,
                    prev: self.circuits[idx].prev,
                    create2,
                });

                Ok(vec![Action::Connect {
                    relay_id,
                    address,
                    port,
                    token,
                }])
            }
            _ => {
                let c = &self.circuits[idx];
                Ok(vec![Action::Deliver {
                    chan: c.prev.chan,
                    circ: c.prev.circ,
                    msg,
                }])
            }
        }
    }

    // -----------------------------------------------------------------------
    // Extindere: raspunsul cojii de I/O
    // -----------------------------------------------------------------------

    /// Coaja de I/O a deschis canalul cerut de o actiune [`Action::Connect`].
    pub fn on_channel_ready(
        &mut self,
        token: u64,
        chan: ChannelId,
    ) -> Result<Vec<Action>, RelayError> {
        let pos = self
            .pending
            .iter()
            .position(|p| p.token == token)
            .ok_or(RelayError::UnknownToken)?;
        let p = self.pending.remove(pos);

        let idx = self
            .find(p.prev.chan, p.prev.circ)
            .ok_or(RelayError::UnknownCircuit)?;
        let circ = self.alloc_circ();
        self.circuits[idx].next = Some(Endpoint { chan, circ });

        let cell = Cell::var(circ, ChanCmd::Create2, p.create2).map_err(RelayError::Wire)?;
        Ok(vec![Action::Send { chan, cell }])
    }

    /// Deschiderea canalului a esuat. Circuitul se inchide.
    pub fn on_channel_failed(&mut self, token: u64) -> Result<Vec<Action>, RelayError> {
        let pos = self
            .pending
            .iter()
            .position(|p| p.token == token)
            .ok_or(RelayError::UnknownToken)?;
        let p = self.pending.remove(pos);
        let idx = self
            .find(p.prev.chan, p.prev.circ)
            .ok_or(RelayError::UnknownCircuit)?;
        Ok(self.teardown(idx, "canalul catre hop-ul urmator nu s-a deschis"))
    }

    /// Hop-ul urmator a raspuns cu CREATED2; il impachetam in EXTENDED2.
    pub fn on_created2(
        &mut self,
        chan: ChannelId,
        circ: CircId,
        payload: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<Action>, RelayError> {
        let idx = self.find(chan, circ).ok_or(RelayError::UnknownCircuit)?;
        if !self.circuits[idx].extending {
            return Err(RelayError::UnexpectedCreated2);
        }
        // Trebuie sa vina chiar dinspre hop-ul urmator.
        if self.circuits[idx].next != Some(Endpoint { chan, circ }) {
            return Err(RelayError::WrongDirection);
        }
        self.circuits[idx].extending = false;

        let created = Created2::parse(payload).map_err(RelayError::Wire)?;
        let msg = RelayMessage::new(
            RelayCmd::Extended2,
            StreamId::CONTROL,
            Extended2 {
                data: created.data,
            }
            .encode(),
        )
        .map_err(RelayError::Wire)?;

        self.send_back(idx, &msg, rng)
    }

    // -----------------------------------------------------------------------
    // Celule dinspre hop-ul urmator
    // -----------------------------------------------------------------------

    /// O celula RELAY a sosit dinspre hop-ul urmator; o mai invelim cu un strat.
    pub fn on_relay_backward(
        &mut self,
        chan: ChannelId,
        circ: CircId,
        cell: &Cell,
    ) -> Result<Vec<Action>, RelayError> {
        let idx = self.find(chan, circ).ok_or(RelayError::UnknownCircuit)?;
        if self.circuits[idx].next != Some(Endpoint { chan, circ }) {
            return Err(RelayError::WrongDirection);
        }
        let payload: &[u8; pqo_crypto::cgo::MSG_LEN] = cell
            .payload()
            .try_into()
            .map_err(|_| RelayError::BadCellSize)?;

        let out = self.circuits[idx]
            .cgo
            .relay_inbound(ChanCmd::Relay as u8, payload);
        let prev = self.circuits[idx].prev;
        let c = Cell::fixed(prev.circ, ChanCmd::Relay, out.as_slice()).map_err(RelayError::Wire)?;
        Ok(vec![Action::Send {
            chan: prev.chan,
            cell: c,
        }])
    }

    /// Originam un mesaj catre client (EXTENDED2, SENDME, date de la exit).
    fn send_back(
        &mut self,
        idx: usize,
        msg: &RelayMessage,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<Action>, RelayError> {
        let prev = self.circuits[idx].prev;
        let mut out = Vec::new();
        for corp in msg.fragment(rng) {
            let cell = self.circuits[idx]
                .cgo
                .originate_inbound(ChanCmd::Relay as u8, &corp);
            out.push(Action::Send {
                chan: prev.chan,
                cell: Cell::fixed(prev.circ, ChanCmd::Relay, cell.as_slice())
                    .map_err(RelayError::Wire)?,
            });
        }
        Ok(out)
    }

    /// Trimite un mesaj catre client pe un circuit existent.
    pub fn deliver_to_client(
        &mut self,
        chan: ChannelId,
        circ: CircId,
        msg: &RelayMessage,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<Action>, RelayError> {
        let idx = self.find(chan, circ).ok_or(RelayError::UnknownCircuit)?;
        self.send_back(idx, msg, rng)
    }

    // -----------------------------------------------------------------------
    // Inchidere
    // -----------------------------------------------------------------------

    /// Un DESTROY a sosit. Se propaga in celalalt sens si se elibereaza starea.
    pub fn on_destroy(&mut self, chan: ChannelId, circ: CircId) -> Vec<Action> {
        match self.find(chan, circ) {
            Some(idx) => self.teardown(idx, "DESTROY"),
            // Un DESTROY pentru un circuit necunoscut se ignora tacit: e cazul
            // normal cand ambele capete inchid simultan.
            None => Vec::new(),
        }
    }

    /// Inchide un circuit si anunta ambele capete.
    fn teardown(&mut self, idx: usize, _motiv: &str) -> Vec<Action> {
        let c = self.circuits.remove(idx);
        self.pending
            .retain(|p| p.prev.chan != c.prev.chan || p.prev.circ != c.prev.circ);

        let mut out = Vec::new();
        if let Ok(cell) = Cell::fixed(c.prev.circ, ChanCmd::Destroy, &[]) {
            out.push(Action::Send {
                chan: c.prev.chan,
                cell,
            });
        }
        if let Some(n) = c.next {
            if let Ok(cell) = Cell::fixed(n.circ, ChanCmd::Destroy, &[]) {
                out.push(Action::Send {
                    chan: n.chan,
                    cell,
                });
            }
        }
        out.push(Action::CircuitClosed {
            chan: c.prev.chan,
            circ: c.prev.circ,
        });
        out
    }

    /// Un canal a cazut. Toate circuitele care il foloseau se inchid.
    pub fn on_channel_closed(&mut self, chan: ChannelId) -> Vec<Action> {
        let mut out = Vec::new();
        while let Some(idx) = self
            .circuits
            .iter()
            .position(|c| c.prev.chan == chan || c.next.is_some_and(|n| n.chan == chan))
        {
            out.extend(self.teardown(idx, "canal inchis"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqo_crypto::cgo::ClientCircuit;
    use pqo_crypto::kem::{Hybrid, X25519Kem};
    use pqo_crypto::{client_finish, client_init, ntor, Variant};
    use pqo_wire::{HandshakeType, LinkSpec};
    use rand_core::OsRng;

    type K = Hybrid<X25519Kem, X25519Kem>;

    const CH_CLIENT: ChannelId = ChannelId(1);
    const CH_NEXT: ChannelId = ChannelId(2);
    const CIRC: CircId = CircId(0x8000_0005);

    fn releu(id: u8) -> RelayNode<K> {
        RelayNode::new(RelayKeys::<K>::generate(
            [id; ntor::ID_LEN],
            Variant::Transitional,
            &mut OsRng,
        ))
    }

    fn cheile(id: u8) -> RelayKeys<K> {
        RelayKeys::<K>::generate([id; ntor::ID_LEN], Variant::Transitional, &mut OsRng)
    }

    /// Construieste primul hop si intoarce starea criptografica a clientului.
    fn creeaza(node: &mut RelayNode<K>, keys_pub: &pqo_crypto::RelayPublic) -> ClientCircuit {
        let mut rng = OsRng;
        let (state, hs) = client_init::<K>(keys_pub, Variant::Transitional, &mut rng).unwrap();
        let payload = Create2 {
            htype: HandshakeType::PqNtorTransitional,
            data: hs,
        }
        .encode();

        let act = node.on_create2(CH_CLIENT, CIRC, &payload, &mut rng).unwrap();
        let Action::Send { cell, .. } = &act[0] else {
            panic!("asteptam Send")
        };
        let created = Created2::parse(cell.payload()).unwrap();
        let res = client_finish::<K>(state, &created.data).unwrap();

        let mut cc = ClientCircuit::new();
        cc.add_hop(&res.key_seed);
        cc
    }

    /// Impacheteaza un mesaj relay in celule criptate pentru hop-ul `d`.
    fn celule_client(cc: &mut ClientCircuit, d: usize, msg: &RelayMessage, early: bool) -> Vec<Cell> {
        let cmd = if early {
            ChanCmd::RelayEarly
        } else {
            ChanCmd::Relay
        };
        msg.fragment(&mut OsRng)
            .into_iter()
            .map(|corp| {
                let c = cc.encrypt_outbound(d, cmd as u8, &corp).unwrap();
                Cell::fixed(CIRC, cmd, c.as_slice()).unwrap()
            })
            .collect()
    }

    fn extend2(tinta: &pqo_crypto::RelayPublic, hs: Vec<u8>) -> RelayMessage {
        RelayMessage::new(
            RelayCmd::Extend2,
            StreamId::CONTROL,
            Extend2 {
                specs: vec![
                    LinkSpec::Ipv4 {
                        addr: [10, 0, 0, 2],
                        port: 9001,
                    },
                    LinkSpec::RelayId(tinta.id),
                ],
                htype: HandshakeType::PqNtorTransitional,
                data: hs,
            }
            .encode(),
        )
        .unwrap()
    }

    #[test]
    fn creare_de_circuit() {
        let keys = cheile(1);
        let public = keys.public();
        let mut n = RelayNode::new(keys);
        let _cc = creeaza(&mut n, &public);
        assert_eq!(n.circuit_count(), 1);
    }

    #[test]
    fn acelasi_numar_de_circuit_nu_se_refoloseste() {
        let keys = cheile(1);
        let public = keys.public();
        let mut n = RelayNode::new(keys);
        let _cc = creeaza(&mut n, &public);

        let (_s, hs) = client_init::<K>(&public, Variant::Transitional, &mut OsRng).unwrap();
        let payload = Create2 {
            htype: HandshakeType::PqNtorTransitional,
            data: hs,
        }
        .encode();
        assert_eq!(
            n.on_create2(CH_CLIENT, CIRC, &payload, &mut OsRng),
            Err(RelayError::CircuitExists)
        );
    }

    #[test]
    fn circuitul_zero_e_respins() {
        let keys = cheile(1);
        let mut n = RelayNode::new(keys);
        assert_eq!(
            n.on_create2(CH_CLIENT, CircId::NONE, &[], &mut OsRng),
            Err(RelayError::BadCircId)
        );
    }

    #[test]
    fn extinderea_cere_deschiderea_unui_canal() {
        let keys = cheile(1);
        let public = keys.public();
        let mut n = RelayNode::new(keys);
        let mut cc = creeaza(&mut n, &public);

        let tinta = cheile(2);
        let (_st, hs) =
            client_init::<K>(&tinta.public(), Variant::Transitional, &mut OsRng).unwrap();
        let msg = extend2(&tinta.public(), hs);

        let mut actiuni = Vec::new();
        for cell in celule_client(&mut cc, 1, &msg, true) {
            actiuni.extend(
                n.on_relay_forward(CH_CLIENT, CIRC, &cell, &mut OsRng)
                    .unwrap(),
            );
        }
        assert_eq!(actiuni.len(), 1);
        match &actiuni[0] {
            Action::Connect {
                relay_id,
                address,
                port,
                ..
            } => {
                assert_eq!(*relay_id, tinta.public().id);
                assert_eq!(address, "10.0.0.2");
                assert_eq!(*port, 9001);
            }
            a => panic!("asteptam Connect, am primit {a:?}"),
        }
    }

    #[test]
    fn extindere_completa_cu_doua_hopuri() {
        let mut rng = OsRng;
        let keys1 = cheile(1);
        let public1 = keys1.public();
        let mut n1 = RelayNode::new(keys1);
        let mut cc = creeaza(&mut n1, &public1);

        // Hop-ul 2, ca releu separat.
        let keys2 = cheile(2);
        let public2 = keys2.public();
        let mut n2 = RelayNode::new(keys2);

        let (state2, hs) = client_init::<K>(&public2, Variant::Transitional, &mut rng).unwrap();
        let msg = extend2(&public2, hs);

        // Clientul cere extinderea.
        let mut act = Vec::new();
        for cell in celule_client(&mut cc, 1, &msg, true) {
            act.extend(n1.on_relay_forward(CH_CLIENT, CIRC, &cell, &mut rng).unwrap());
        }
        let Action::Connect { token, .. } = act[0] else {
            panic!("asteptam Connect")
        };

        // Coaja de I/O deschide canalul.
        let act = n1.on_channel_ready(token, CH_NEXT).unwrap();
        let Action::Send { chan, cell } = &act[0] else {
            panic!("asteptam Send")
        };
        assert_eq!(*chan, CH_NEXT);
        assert_eq!(cell.cmd(), ChanCmd::Create2);
        let circ_next = cell.circ();

        // Hop-ul 2 raspunde.
        let act = n2
            .on_create2(ChannelId(9), circ_next, cell.payload(), &mut rng)
            .unwrap();
        let Action::Send { cell: created, .. } = &act[0] else {
            panic!("asteptam Send")
        };

        // Hop-ul 1 impacheteaza in EXTENDED2 si trimite inapoi clientului.
        let act = n1
            .on_created2(CH_NEXT, circ_next, created.payload(), &mut rng)
            .unwrap();
        assert!(!act.is_empty());

        // Clientul reasambleaza si finalizeaza handshake-ul cu hop-ul 2.
        let mut reasm = Reassembler::new();
        let mut extended = None;
        for a in &act {
            let Action::Send { cell, .. } = a else {
                panic!("asteptam Send")
            };
            let p: &[u8; pqo_crypto::cgo::MSG_LEN] = cell.payload().try_into().unwrap();
            let (hop, corp) = cc.decrypt_inbound(ChanCmd::Relay as u8, p).unwrap();
            assert_eq!(hop, 1);
            if let Some(m) = reasm.push(corp.as_slice()).unwrap() {
                extended = Some(m);
            }
        }
        let m = extended.expect("EXTENDED2 nu s-a completat");
        assert_eq!(m.cmd, RelayCmd::Extended2);
        let e = Extended2::parse(&m.body).unwrap();
        let res = client_finish::<K>(state2, &e.data).unwrap();
        cc.add_hop(&res.key_seed);
        assert_eq!(cc.len(), 2, "circuitul are acum doua hopuri");
    }

    #[test]
    fn celula_pentru_hopul_doi_se_retransmite() {
        let mut rng = OsRng;
        let keys1 = cheile(1);
        let public1 = keys1.public();
        let mut n1 = RelayNode::new(keys1);
        let mut cc = creeaza(&mut n1, &public1);

        // Simulam ca extinderea s-a facut: setam manual `next`.
        let keys2 = cheile(2);
        let public2 = keys2.public();
        let (state2, hs) = client_init::<K>(&public2, Variant::Transitional, &mut rng).unwrap();
        let msg = extend2(&public2, hs);
        let mut act = Vec::new();
        for cell in celule_client(&mut cc, 1, &msg, true) {
            act.extend(n1.on_relay_forward(CH_CLIENT, CIRC, &cell, &mut rng).unwrap());
        }
        let Action::Connect { token, .. } = act[0] else {
            panic!()
        };
        let act = n1.on_channel_ready(token, CH_NEXT).unwrap();
        let Action::Send { cell, .. } = &act[0] else {
            panic!()
        };
        let circ_next = cell.circ();
        let mut n2 = RelayNode::new(keys2);
        let a2 = n2
            .on_create2(ChannelId(9), circ_next, cell.payload(), &mut rng)
            .unwrap();
        let Action::Send { cell: created, .. } = &a2[0] else {
            panic!()
        };
        let act = n1
            .on_created2(CH_NEXT, circ_next, created.payload(), &mut rng)
            .unwrap();
        let mut reasm = Reassembler::new();
        let mut extended = None;
        for a in &act {
            let Action::Send { cell, .. } = a else { panic!() };
            let p: &[u8; pqo_crypto::cgo::MSG_LEN] = cell.payload().try_into().unwrap();
            let (_h, corp) = cc.decrypt_inbound(ChanCmd::Relay as u8, p).unwrap();
            if let Some(m) = reasm.push(corp.as_slice()).unwrap() {
                extended = Some(m);
            }
        }
        let e = Extended2::parse(&extended.unwrap().body).unwrap();
        cc.add_hop(&client_finish::<K>(state2, &e.data).unwrap().key_seed);

        // Acum trimitem date catre hop-ul 2. Hop-ul 1 trebuie sa le retransmita.
        let date = RelayMessage::new(RelayCmd::Data, StreamId(1), vec![7u8; 200]).unwrap();
        let mut fwd = Vec::new();
        for cell in celule_client(&mut cc, 2, &date, false) {
            fwd.extend(n1.on_relay_forward(CH_CLIENT, CIRC, &cell, &mut rng).unwrap());
        }
        assert_eq!(fwd.len(), 1);
        match &fwd[0] {
            Action::Send { chan, cell } => {
                assert_eq!(*chan, CH_NEXT);
                assert_eq!(cell.circ(), circ_next);
                assert_eq!(cell.cmd(), ChanCmd::Relay);
            }
            a => panic!("asteptam retransmisie, am primit {a:?}"),
        }
    }

    #[test]
    fn extend2_fara_relay_early_inchide_circuitul() {
        let mut rng = OsRng;
        let keys = cheile(1);
        let public = keys.public();
        let mut n = RelayNode::new(keys);
        let mut cc = creeaza(&mut n, &public);

        let tinta = cheile(2);
        let (_s, hs) = client_init::<K>(&tinta.public(), Variant::Transitional, &mut rng).unwrap();
        let msg = extend2(&tinta.public(), hs);

        let mut act = Vec::new();
        for cell in celule_client(&mut cc, 1, &msg, false) {
            act.extend(n.on_relay_forward(CH_CLIENT, CIRC, &cell, &mut rng).unwrap());
        }
        assert!(
            act.iter().any(|a| matches!(a, Action::CircuitClosed { .. })),
            "EXTEND2 fara RELAY_EARLY trebuie sa inchida circuitul"
        );
        assert_eq!(n.circuit_count(), 0);
    }

    #[test]
    fn prea_multe_relay_early_inchid_circuitul() {
        let mut rng = OsRng;
        let keys = cheile(1);
        let public = keys.public();
        let mut n = RelayNode::new(keys);
        let mut cc = creeaza(&mut n, &public);

        let drop_msg = RelayMessage::new(RelayCmd::Drop, StreamId::CONTROL, vec![]).unwrap();
        let mut inchis = false;
        for _ in 0..(MAX_RELAY_EARLY as usize + 2) {
            for cell in celule_client(&mut cc, 1, &drop_msg, true) {
                if let Ok(act) = n.on_relay_forward(CH_CLIENT, CIRC, &cell, &mut rng) {
                    if act.iter().any(|a| matches!(a, Action::CircuitClosed { .. })) {
                        inchis = true;
                    }
                }
            }
            if inchis {
                break;
            }
        }
        assert!(inchis, "plafonul de RELAY_EARLY trebuie aplicat");
    }

    #[test]
    fn circuit_necunoscut_e_respins() {
        let mut n = releu(1);
        let cell = Cell::fixed(CircId(99), ChanCmd::Relay, &[0u8; 509]).unwrap();
        assert_eq!(
            n.on_relay_forward(CH_CLIENT, CircId(99), &cell, &mut OsRng),
            Err(RelayError::UnknownCircuit)
        );
    }

    #[test]
    fn created2_neasteptat_e_respins() {
        let keys = cheile(1);
        let public = keys.public();
        let mut n = RelayNode::new(keys);
        let _cc = creeaza(&mut n, &public);
        assert_eq!(
            n.on_created2(CH_CLIENT, CIRC, &[0, 0], &mut OsRng),
            Err(RelayError::UnexpectedCreated2)
        );
    }

    #[test]
    fn token_necunoscut_e_respins() {
        let mut n = releu(1);
        assert_eq!(
            n.on_channel_ready(999, CH_NEXT),
            Err(RelayError::UnknownToken)
        );
        assert_eq!(n.on_channel_failed(999), Err(RelayError::UnknownToken));
    }

    #[test]
    fn destroy_inchide_ambele_capete() {
        let keys = cheile(1);
        let public = keys.public();
        let mut n = RelayNode::new(keys);
        let _cc = creeaza(&mut n, &public);
        let act = n.on_destroy(CH_CLIENT, CIRC);
        assert!(act
            .iter()
            .any(|a| matches!(a, Action::CircuitClosed { .. })));
        assert_eq!(n.circuit_count(), 0);
        // Al doilea DESTROY se ignora tacit.
        assert!(n.on_destroy(CH_CLIENT, CIRC).is_empty());
    }

    #[test]
    fn caderea_unui_canal_inchide_circuitele() {
        let keys = cheile(1);
        let public = keys.public();
        let mut n = RelayNode::new(keys);
        for i in 0..5u32 {
            let (state, hs) =
                client_init::<K>(&public, Variant::Transitional, &mut OsRng).unwrap();
            let p = Create2 {
                htype: HandshakeType::PqNtorTransitional,
                data: hs,
            }
            .encode();
            let act = n
                .on_create2(CH_CLIENT, CircId(0x8000_0100 + i), &p, &mut OsRng)
                .unwrap();
            let Action::Send { cell, .. } = &act[0] else {
                panic!()
            };
            let _ = client_finish::<K>(state, &Created2::parse(cell.payload()).unwrap().data);
        }
        assert_eq!(n.circuit_count(), 5);
        let act = n.on_channel_closed(CH_CLIENT);
        assert_eq!(
            act.iter()
                .filter(|a| matches!(a, Action::CircuitClosed { .. }))
                .count(),
            5
        );
        assert_eq!(n.circuit_count(), 0);
    }

    #[test]
    fn celula_de_dimensiune_gresita_e_respinsa() {
        let keys = cheile(1);
        let public = keys.public();
        let mut n = RelayNode::new(keys);
        let _cc = creeaza(&mut n, &public);
        let cell = Cell::var(CIRC, ChanCmd::Certs, vec![0u8; 10]).unwrap();
        assert_eq!(
            n.on_relay_forward(CH_CLIENT, CIRC, &cell, &mut OsRng),
            Err(RelayError::BadCellSize)
        );
    }
}
