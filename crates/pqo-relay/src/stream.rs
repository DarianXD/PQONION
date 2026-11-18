//! Stream-urile la releul de iesire.
//!
//! Un circuit multiplexeaza mai multe stream-uri. Fiecare corespunde unei
//! conexiuni TCP pe care exit-ul o deschide catre destinatie.
//!
//! # Tot fara I/O
//!
//! Modulul nu deschide nicio conexiune. Cand un client cere BEGIN, produce
//! [`crate::circuit::Action::StreamConnect`] si asteapta ca stratul de retea sa
//! raporteze rezultatul prin [`StreamTable::on_connected`] sau
//! [`StreamTable::on_connect_failed`].
//!
//! Motivul e acelasi ca peste tot: pot testa aici politica de iesire, controlul
//! de flux si toate cazurile de eroare fara sa deschid un socket.
//!
//! # Politica de iesire
//!
//! Implicit **nu se permite nimic**. Un releu devine exit doar daca cineva
//! configureaza explicit ce are voie sa iasa. Alegerea inversa — permis implicit
//! — ar transforma orice releu pornit din greseala intr-un proxy deschis, cu
//! consecinte legale pentru operator.

use pqo_wire::stream::{Begin, EndReason, FlowWindow};
use pqo_wire::StreamId;

use crate::RelayError;

/// Cate stream-uri poate avea un circuit deschise simultan.
pub const MAX_STREAMS_PER_CIRCUIT: usize = 64;

/// Ce are voie sa iasa printr-un releu.
#[derive(Debug, Clone, Default)]
pub struct ExitPolicy {
    /// Porturi permise. Gol inseamna ca releul nu e exit.
    allowed_ports: Vec<u16>,
    /// Daca e adevarat, se accepta si conexiuni catre adrese private.
    ///
    /// Implicit fals: altfel un client ar putea folosi releul ca sa scaneze
    /// reteaua interna a operatorului, sau sa ajunga la servicii de
    /// administrare care asculta pe localhost.
    allow_private: bool,
}

impl ExitPolicy {
    /// Politica implicita: nu se iese nicaieri.
    pub fn reject_all() -> Self {
        Self::default()
    }

    /// Permite o lista de porturi.
    pub fn allow_ports(ports: &[u16]) -> Self {
        ExitPolicy {
            allowed_ports: ports.to_vec(),
            allow_private: false,
        }
    }

    /// Permite si adrese private. **Doar pentru testnet.**
    pub fn allow_private_for_testing(mut self) -> Self {
        self.allow_private = true;
        self
    }

    pub fn is_exit(&self) -> bool {
        !self.allowed_ports.is_empty()
    }

    /// Adevarat daca politica permite adrese private.
    ///
    /// Stratul de retea are nevoie de asta ca sa verifice adresele **dupa**
    /// rezolvare, nu doar literalele din cerere.
    pub fn allows_private(&self) -> bool {
        self.allow_private
    }

    /// Verifica o cerere de iesire.
    pub fn check(&self, b: &Begin) -> Result<(), EndReason> {
        if !self.allowed_ports.contains(&b.port) {
            return Err(EndReason::ExitPolicy);
        }
        if !self.allow_private && is_private(&b.address) {
            return Err(EndReason::ExitPolicy);
        }
        Ok(())
    }
}

/// Adrese pe care un exit nu are voie sa le atinga implicit.
///
/// Verificarea e pe text, deci acopera doar literalele din cerere. Un nume de
/// domeniu care rezolva la o adresa privata trece de aici — de aceea stratul de
/// retea reverifica **dupa rezolvare**, prin [`is_private_addr`]. Fara al doilea
/// pas, oricine poate inregistra un domeniu care indica spre `127.0.0.1` si
/// poate ajunge la serviciile locale ale operatorului.
fn is_private(addr: &str) -> bool {
    if addr.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
        return ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified();
    }
    if let Ok(ip) = addr.parse::<std::net::Ipv6Addr>() {
        return ip.is_loopback() || ip.is_unspecified();
    }
    false
}

/// Adevarat daca adresa rezolvata e privata.
///
/// Al doilea pas al verificarii, aplicat pe rezultatul rezolvarii de nume.
pub fn is_private_addr(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => {
            v.is_loopback() || v.is_private() || v.is_link_local() || v.is_unspecified()
        }
        std::net::IpAddr::V6(v) => {
            v.is_loopback()
                || v.is_unspecified()
                // Adrese unice locale (fc00::/7) si link-local (fe80::/10).
                || (v.segments()[0] & 0xfe00) == 0xfc00
                || (v.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// In ce etapa e un stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// S-a cerut conexiunea, se asteapta rezultatul.
    Connecting,
    /// Conexiunea e deschisa, datele pot curge.
    Open,
    /// Stream de director: releul raspunde din propriile documente, fara sa
    /// deschida nimic in exterior.
    ///
    /// De aceea nu trece prin politica de iesire: nu iese nicaieri. Orice releu
    /// poate servi director, inclusiv unul care nu e exit.
    Directory,
}

/// Cate bucati de date pot astepta pe un stream cand fereastra e inchisa.
///
/// Peste asta, clientul nu consuma si nu confirma. Inchidem stream-ul in loc sa
/// crestem memoria: un client care cere date si nu le citeste e fie stricat, fie
/// ostil.
pub const MAX_PENDING_CHUNKS: usize = 256;

struct Stream {
    id: StreamId,
    state: StreamState,
    /// Fereastra pentru ce trimitem noi catre client.
    send: FlowWindow,
    /// Fereastra pentru ce primim de la client.
    recv: FlowWindow,
    /// Date citite de la destinatie care asteapta sa se deschida fereastra.
    ///
    /// Fara coada asta, datele s-ar pierde tacut cand fereastra e inchisa —
    /// exact bugul pe care l-a prins testul de transfer mare.
    pending: std::collections::VecDeque<Vec<u8>>,
}

/// Ce trebuie sa faca stratul de retea pentru stream-uri.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamAction {
    /// Deschide o conexiune TCP catre destinatie.
    Connect {
        stream: StreamId,
        address: String,
        port: u16,
    },
    /// Scrie date pe conexiunea deschisa.
    Write { stream: StreamId, data: Vec<u8> },
    /// Inchide conexiunea.
    Close { stream: StreamId },
    /// Serveste o cerere de director din documentele proprii.
    DirRequest { stream: StreamId, request: Vec<u8> },
    /// Trimite un mesaj inapoi clientului.
    ToClient {
        stream: StreamId,
        cmd: pqo_wire::RelayCmd,
        body: Vec<u8>,
    },
}

/// Stream-urile unui circuit, la releul de iesire.
#[derive(Debug)]
pub struct StreamTable {
    policy: ExitPolicy,
    streams: Vec<Stream>,
    /// Fereastra de circuit pentru ce trimitem catre client.
    circ_send: FlowWindow,
    /// Fereastra de circuit pentru ce primim de la client.
    circ_recv: FlowWindow,
}

impl core::fmt::Debug for Stream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Stream({}, {:?})", self.id.0, self.state)
    }
}

impl StreamTable {
    pub fn new(policy: ExitPolicy) -> Self {
        StreamTable {
            policy,
            streams: Vec::new(),
            circ_send: FlowWindow::circuit(),
            circ_recv: FlowWindow::circuit(),
        }
    }

    pub fn len(&self) -> usize {
        self.streams.len()
    }

    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    fn find(&mut self, id: StreamId) -> Option<usize> {
        self.streams.iter().position(|s| s.id == id)
    }

    /// Clientul cere deschiderea unui stream catre serviciul de director.
    ///
    /// Nu se verifica politica de iesire: nu se deschide nicio conexiune in
    /// exterior. Un releu care nu e exit poate servi director.
    pub fn on_begin_dir(&mut self, id: StreamId) -> Result<Vec<StreamAction>, RelayError> {
        if id.is_control() {
            return Err(RelayError::Wire(pqo_wire::WireError::StreamMismatch));
        }
        if self.find(id).is_some() || self.streams.len() >= MAX_STREAMS_PER_CIRCUIT {
            return Ok(vec![end(id, EndReason::Misc)]);
        }
        self.streams.push(Stream {
            id,
            state: StreamState::Directory,
            send: FlowWindow::stream(),
            recv: FlowWindow::stream(),
            pending: std::collections::VecDeque::new(),
        });
        Ok(vec![StreamAction::ToClient {
            stream: id,
            cmd: pqo_wire::RelayCmd::Connected,
            body: pqo_wire::stream::Connected {
                addr: [0, 0, 0, 0],
                ttl: 0,
            }
            .encode(),
        }])
    }

    /// Clientul cere deschiderea unui stream.
    pub fn on_begin(&mut self, id: StreamId, body: &[u8]) -> Result<Vec<StreamAction>, RelayError> {
        if id.is_control() {
            return Err(RelayError::Wire(pqo_wire::WireError::StreamMismatch));
        }
        if self.find(id).is_some() {
            return Ok(vec![end(id, EndReason::Misc)]);
        }
        if self.streams.len() >= MAX_STREAMS_PER_CIRCUIT {
            return Ok(vec![end(id, EndReason::Misc)]);
        }

        let b = match Begin::parse(body) {
            Ok(b) => b,
            Err(_) => return Ok(vec![end(id, EndReason::Misc)]),
        };
        if let Err(motiv) = self.policy.check(&b) {
            return Ok(vec![end(id, motiv)]);
        }

        self.streams.push(Stream {
            id,
            state: StreamState::Connecting,
            send: FlowWindow::stream(),
            recv: FlowWindow::stream(),
            pending: std::collections::VecDeque::new(),
        });
        Ok(vec![StreamAction::Connect {
            stream: id,
            address: b.address,
            port: b.port,
        }])
    }

    /// Stratul de retea a deschis conexiunea.
    pub fn on_connected(&mut self, id: StreamId, addr: [u8; 4]) -> Vec<StreamAction> {
        let Some(i) = self.find(id) else {
            return Vec::new();
        };
        self.streams[i].state = StreamState::Open;
        vec![StreamAction::ToClient {
            stream: id,
            cmd: pqo_wire::RelayCmd::Connected,
            body: pqo_wire::stream::Connected { addr, ttl: 60 }.encode(),
        }]
    }

    /// Conexiunea nu s-a putut deschide.
    pub fn on_connect_failed(&mut self, id: StreamId, reason: EndReason) -> Vec<StreamAction> {
        if let Some(i) = self.find(id) {
            self.streams.remove(i);
        }
        vec![end(id, reason)]
    }

    /// Date de la client catre destinatie.
    pub fn on_data(&mut self, id: StreamId, data: &[u8]) -> Result<Vec<StreamAction>, RelayError> {
        let Some(i) = self.find(id) else {
            // Date pentru un stream inexistent: raspundem cu END, nu ignoram, ca
            // sa nu ramana clientul blocat asteptand.
            return Ok(vec![end(id, EndReason::Misc)]);
        };
        let director = self.streams[i].state == StreamState::Directory;
        if !director && self.streams[i].state != StreamState::Open {
            return Ok(vec![end(id, EndReason::Misc)]);
        }

        let mut out = Vec::new();
        // Controlul de flux se aplica pe ambele niveluri. Un client care
        // depaseste fereastra incalca protocolul; inchidem circuitul.
        if self.circ_recv.on_recv() {
            out.push(sendme(StreamId::CONTROL));
        }
        if self.streams[i].recv.on_recv() {
            out.push(sendme(id));
        }
        if director {
            // Cererea se serveste local; nu iese nimic in retea.
            out.push(StreamAction::DirRequest {
                stream: id,
                request: data.to_vec(),
            });
        } else {
            out.push(StreamAction::Write {
                stream: id,
                data: data.to_vec(),
            });
        }
        Ok(out)
    }

    /// Date de la destinatie catre client.
    ///
    /// Datele intra intr-o coada si se trimit atat cat permit ferestrele. Restul
    /// asteapta un SENDME. Nimic nu se pierde: coada e plafonata, iar depasirea
    /// inchide stream-ul in loc sa arunce octeti in tacere.
    pub fn data_to_client(&mut self, id: StreamId, data: Vec<u8>) -> Vec<StreamAction> {
        let Some(i) = self.find(id) else {
            return Vec::new();
        };
        if self.streams[i].pending.len() >= MAX_PENDING_CHUNKS {
            self.streams.remove(i);
            return vec![
                end(id, EndReason::Misc),
                StreamAction::Close { stream: id },
            ];
        }
        self.streams[i].pending.push_back(data);
        self.drain(id)
    }

    /// Trimite cat permit ferestrele din ce asteapta pe un stream.
    fn drain(&mut self, id: StreamId) -> Vec<StreamAction> {
        let Some(i) = self.find(id) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        while self.circ_send.can_send() && self.streams[i].send.can_send() {
            let Some(body) = self.streams[i].pending.pop_front() else {
                break;
            };
            // Ambele ferestre au fost verificate mai sus.
            let _ = self.circ_send.on_send();
            let _ = self.streams[i].send.on_send();
            out.push(StreamAction::ToClient {
                stream: id,
                cmd: pqo_wire::RelayCmd::Data,
                body,
            });
        }
        out
    }

    /// Un SENDME de la client. Poate debloca date care asteptau.
    pub fn on_sendme(&mut self, id: StreamId) -> Result<Vec<StreamAction>, RelayError> {
        if id.is_control() {
            self.circ_send.on_sendme().map_err(RelayError::Wire)?;
            // Un SENDME de circuit poate debloca oricare stream.
            let ids: Vec<StreamId> = self.streams.iter().map(|s| s.id).collect();
            let mut out = Vec::new();
            for s in ids {
                out.extend(self.drain(s));
            }
            Ok(out)
        } else {
            let i = self.find(id).ok_or(RelayError::UnknownStream)?;
            self.streams[i].send.on_sendme().map_err(RelayError::Wire)?;
            Ok(self.drain(id))
        }
    }

    /// Clientul inchide un stream.
    pub fn on_end(&mut self, id: StreamId) -> Vec<StreamAction> {
        match self.find(id) {
            Some(i) => {
                self.streams.remove(i);
                vec![StreamAction::Close { stream: id }]
            }
            None => Vec::new(),
        }
    }

    /// Destinatia a inchis conexiunea.
    pub fn on_remote_closed(&mut self, id: StreamId, reason: EndReason) -> Vec<StreamAction> {
        match self.find(id) {
            Some(i) => {
                self.streams.remove(i);
                vec![end(id, reason)]
            }
            None => Vec::new(),
        }
    }

    /// Circuitul se inchide: toate stream-urile cad.
    pub fn close_all(&mut self) -> Vec<StreamAction> {
        self.streams
            .drain(..)
            .map(|s| StreamAction::Close { stream: s.id })
            .collect()
    }
}

fn end(stream: StreamId, reason: EndReason) -> StreamAction {
    StreamAction::ToClient {
        stream,
        cmd: pqo_wire::RelayCmd::End,
        body: pqo_wire::stream::End { reason }.encode(),
    }
}

fn sendme(stream: StreamId) -> StreamAction {
    StreamAction::ToClient {
        stream,
        cmd: pqo_wire::RelayCmd::Sendme,
        body: pqo_wire::stream::Sendme::V1.encode(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqo_wire::stream::{Begin, STREAM_WINDOW_START};

    fn begin(addr: &str, port: u16) -> Vec<u8> {
        Begin {
            address: addr.into(),
            port,
        }
        .encode()
        .unwrap()
    }

    fn masa() -> StreamTable {
        StreamTable::new(ExitPolicy::allow_ports(&[80, 443]))
    }

    fn motiv(a: &StreamAction) -> Option<EndReason> {
        match a {
            StreamAction::ToClient { cmd, body, .. } if *cmd == pqo_wire::RelayCmd::End => {
                pqo_wire::stream::End::parse(body).ok().map(|e| e.reason)
            }
            _ => None,
        }
    }

    #[test]
    fn politica_implicita_refuza_tot() {
        let mut t = StreamTable::new(ExitPolicy::reject_all());
        assert!(!ExitPolicy::reject_all().is_exit());
        let a = t.on_begin(StreamId(1), &begin("example.com", 80)).unwrap();
        assert_eq!(motiv(&a[0]), Some(EndReason::ExitPolicy));
    }

    #[test]
    fn portul_nepermis_e_refuzat() {
        let mut t = masa();
        let a = t.on_begin(StreamId(1), &begin("example.com", 22)).unwrap();
        assert_eq!(motiv(&a[0]), Some(EndReason::ExitPolicy));
    }

    #[test]
    fn adresele_private_sunt_refuzate() {
        // Fara asta, un client ar putea scana reteaua interna a operatorului sau
        // ajunge la servicii de administrare care asculta pe localhost.
        let mut t = masa();
        for a in [
            "127.0.0.1",
            "localhost",
            "LOCALHOST",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "::1",
        ] {
            let r = t.on_begin(StreamId(1), &begin(a, 80)).unwrap();
            assert_eq!(motiv(&r[0]), Some(EndReason::ExitPolicy), "acceptat: {a}");
        }
    }

    #[test]
    fn adresele_publice_trec() {
        let mut t = masa();
        let a = t.on_begin(StreamId(1), &begin("example.com", 443)).unwrap();
        assert!(matches!(a[0], StreamAction::Connect { .. }));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn ciclu_complet_de_stream() {
        let mut t = masa();
        let id = StreamId(7);
        t.on_begin(id, &begin("example.com", 80)).unwrap();

        let a = t.on_connected(id, [93, 184, 216, 34]);
        assert!(matches!(
            a[0],
            StreamAction::ToClient {
                cmd: pqo_wire::RelayCmd::Connected,
                ..
            }
        ));

        let a = t.on_data(id, b"GET / HTTP/1.0\r\n\r\n").unwrap();
        assert!(a.iter().any(|x| matches!(x, StreamAction::Write { .. })));

        let a = t.on_end(id);
        assert_eq!(a, vec![StreamAction::Close { stream: id }]);
        assert!(t.is_empty());
    }

    #[test]
    fn datele_inainte_de_conectare_sunt_refuzate() {
        let mut t = masa();
        let id = StreamId(1);
        t.on_begin(id, &begin("example.com", 80)).unwrap();
        // Inca `Connecting`.
        let a = t.on_data(id, b"x").unwrap();
        assert_eq!(motiv(&a[0]), Some(EndReason::Misc));
    }

    #[test]
    fn stream_inexistent_primeste_end() {
        let mut t = masa();
        let a = t.on_data(StreamId(99), b"x").unwrap();
        assert_eq!(motiv(&a[0]), Some(EndReason::Misc));
    }

    #[test]
    fn stream_duplicat_e_refuzat() {
        let mut t = masa();
        t.on_begin(StreamId(1), &begin("a.com", 80)).unwrap();
        let a = t.on_begin(StreamId(1), &begin("b.com", 80)).unwrap();
        assert_eq!(motiv(&a[0]), Some(EndReason::Misc));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn begin_pe_stream_de_control_e_respins() {
        let mut t = masa();
        assert!(t.on_begin(StreamId::CONTROL, &begin("a.com", 80)).is_err());
    }

    #[test]
    fn plafonul_de_streamuri_e_aplicat() {
        let mut t = masa();
        for i in 1..=MAX_STREAMS_PER_CIRCUIT {
            t.on_begin(StreamId(i as u16), &begin("a.com", 80)).unwrap();
        }
        let a = t
            .on_begin(StreamId(9999), &begin("a.com", 80))
            .unwrap();
        assert_eq!(motiv(&a[0]), Some(EndReason::Misc));
    }

    #[test]
    fn fereastra_opreste_trimiterea_catre_client() {
        let mut t = masa();
        let id = StreamId(1);
        t.on_begin(id, &begin("a.com", 80)).unwrap();
        t.on_connected(id, [1, 2, 3, 4]);

        for i in 0..STREAM_WINDOW_START {
            assert_eq!(
                t.data_to_client(id, vec![0u8; 10]).len(),
                1,
                "celula {i} ar fi trebuit sa treaca imediat"
            );
        }
        // Fereastra e epuizata: datele se pun la coada, nu se pierd.
        assert!(
            t.data_to_client(id, vec![0u8; 10]).is_empty(),
            "fereastra epuizata trebuie sa retina, nu sa trimita"
        );

        // Dupa SENDME se elibereaza ce astepta.
        let dupa = t.on_sendme(id).unwrap();
        assert_eq!(dupa.len(), 1, "SENDME trebuie sa deblocheze datele retinute");
    }

    #[test]
    fn datele_nu_se_pierd_cand_fereastra_e_inchisa() {
        // Bugul pe care l-a prins testul de transfer mare: prima versiune
        // arunca datele in tacere cand fereastra era inchisa.
        let mut t = masa();
        let id = StreamId(1);
        t.on_begin(id, &begin("a.com", 80)).unwrap();
        t.on_connected(id, [1, 2, 3, 4]);

        let mut trimise = 0;
        for i in 0..(STREAM_WINDOW_START + 100) {
            trimise += t.data_to_client(id, vec![i as u8; 4]).len();
        }
        assert_eq!(trimise, STREAM_WINDOW_START as usize);

        // Toate cele 100 retinute ies dupa SENDME-uri.
        let mut eliberate = 0;
        for _ in 0..2 {
            eliberate += t.on_sendme(id).unwrap().len();
        }
        assert_eq!(eliberate, 100, "restul trebuie sa iasa, nu sa se piarda");
    }

    #[test]
    fn coada_plina_inchide_streamul() {
        let mut t = masa();
        let id = StreamId(1);
        t.on_begin(id, &begin("a.com", 80)).unwrap();
        t.on_connected(id, [1, 2, 3, 4]);

        let mut inchis = false;
        for _ in 0..(STREAM_WINDOW_START as usize + MAX_PENDING_CHUNKS + 10) {
            for a in t.data_to_client(id, vec![0u8; 4]) {
                if matches!(a, StreamAction::Close { .. }) {
                    inchis = true;
                }
            }
            if inchis {
                break;
            }
        }
        assert!(inchis, "un client care nu consuma trebuie deconectat");
    }

    #[test]
    fn sendme_in_exces_e_respins() {
        let mut t = masa();
        let id = StreamId(1);
        t.on_begin(id, &begin("a.com", 80)).unwrap();
        assert!(t.on_sendme(id).is_err(), "fereastra e deja plina");
        assert!(t.on_sendme(StreamId::CONTROL).is_err());
        let _ = &t;
    }

    #[test]
    fn receptia_emite_sendme_uri() {
        let mut t = masa();
        let id = StreamId(1);
        t.on_begin(id, &begin("a.com", 80)).unwrap();
        t.on_connected(id, [1, 2, 3, 4]);

        let mut sendme_stream = 0;
        let mut sendme_circ = 0;
        for _ in 0..(pqo_wire::CIRC_WINDOW_INC * 2) {
            for a in t.on_data(id, b"x").unwrap() {
                if let StreamAction::ToClient { stream, cmd, .. } = a {
                    if cmd == pqo_wire::RelayCmd::Sendme {
                        if stream.is_control() {
                            sendme_circ += 1;
                        } else {
                            sendme_stream += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(sendme_circ, 2, "SENDME de circuit la fiecare 100 de celule");
        assert!(sendme_stream > 0, "si SENDME de stream");
    }

    #[test]
    fn inchiderea_circuitului_curata_tot() {
        let mut t = masa();
        for i in 1..=5u16 {
            t.on_begin(StreamId(i), &begin("a.com", 80)).unwrap();
        }
        assert_eq!(t.close_all().len(), 5);
        assert!(t.is_empty());
    }

    #[test]
    fn directorul_se_serveste_si_fara_politica_de_exit() {
        // Un releu care nu e exit poate totusi servi director: nu deschide
        // nimic in exterior.
        let mut t = StreamTable::new(ExitPolicy::reject_all());
        let id = StreamId(1);
        let a = t.on_begin_dir(id).unwrap();
        assert!(matches!(
            a[0],
            StreamAction::ToClient {
                cmd: pqo_wire::RelayCmd::Connected,
                ..
            }
        ));

        let a = t.on_data(id, &[1u8]).unwrap();
        assert!(
            a.iter()
                .any(|x| matches!(x, StreamAction::DirRequest { .. })),
            "datele pe un stream de director devin cerere, nu scriere in retea"
        );
        assert!(
            !a.iter().any(|x| matches!(x, StreamAction::Write { .. })),
            "nu are voie sa iasa nimic in retea"
        );
    }

    #[test]
    fn begin_dir_pe_stream_de_control_e_respins() {
        let mut t = StreamTable::new(ExitPolicy::reject_all());
        assert!(t.on_begin_dir(StreamId::CONTROL).is_err());
    }

    #[test]
    fn adresele_rezolvate_sunt_verificate_si_ele() {
        // Al doilea pas: un nume care rezolva la o adresa privata trebuie prins.
        use std::net::IpAddr;
        for a in [
            "127.0.0.1", "10.1.2.3", "192.168.0.1", "172.20.0.1", "169.254.1.1",
            "0.0.0.0", "::1", "fc00::1", "fe80::1",
        ] {
            let ip: IpAddr = a.parse().unwrap();
            assert!(is_private_addr(&ip), "nedetectat ca privata: {a}");
        }
        for a in ["93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"] {
            let ip: IpAddr = a.parse().unwrap();
            assert!(!is_private_addr(&ip), "gresit marcata ca privata: {a}");
        }
    }

    #[test]
    fn politica_expune_daca_permite_privat() {
        assert!(!ExitPolicy::allow_ports(&[80]).allows_private());
        assert!(ExitPolicy::allow_ports(&[80])
            .allow_private_for_testing()
            .allows_private());
    }

    #[test]
    fn testnetul_poate_permite_adrese_private() {
        let mut t = StreamTable::new(
            ExitPolicy::allow_ports(&[8080]).allow_private_for_testing(),
        );
        let a = t.on_begin(StreamId(1), &begin("127.0.0.1", 8080)).unwrap();
        assert!(matches!(a[0], StreamAction::Connect { .. }));
    }
}
