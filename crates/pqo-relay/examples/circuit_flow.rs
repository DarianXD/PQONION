//! Arata fluxul de actiuni pe care il produce un releu, fara nicio linie de I/O.
//!
//!     cargo run -p pqo-relay --example circuit_flow

use pqo_crypto::cgo::ClientCircuit;
use pqo_crypto::kem::{Hybrid, X25519Kem};
use pqo_crypto::{client_finish, client_init, ntor, RelayKeys, Variant};
use pqo_relay::circuit::{Action, ChannelId, RelayNode};
use pqo_wire::{
    Cell, ChanCmd, CircId, Create2, Created2, Extend2, HandshakeType, LinkSpec, RelayCmd,
    RelayMessage, StreamId,
};
use rand_core::OsRng;

type K = Hybrid<X25519Kem, X25519Kem>;

fn nume(a: &Action) -> String {
    match a {
        Action::Send { chan, cell } => {
            format!("Send   -> canal {} | {:?} | circ {:#x}", chan.0, cell.cmd(), cell.circ().0)
        }
        Action::Connect { address, port, .. } => format!("Connect-> {address}:{port}"),
        Action::CircuitClosed { circ, .. } => format!("Closed   circ {:#x}", circ.0),
        Action::Deliver { msg, .. } => format!("Deliver  {:?} ({} octeti)", msg.cmd, msg.body.len()),
    }
}

fn main() {
    let mut rng = OsRng;
    let keys1 = RelayKeys::<K>::generate([1; ntor::ID_LEN], Variant::Transitional, &mut rng);
    let public1 = keys1.public();
    let mut n1 = RelayNode::new(keys1);

    let keys2 = RelayKeys::<K>::generate([2; ntor::ID_LEN], Variant::Transitional, &mut rng);
    let public2 = keys2.public();

    const CH_CLI: ChannelId = ChannelId(1);
    const CIRC: CircId = CircId(0x8000_0005);

    println!("Fluxul de actiuni al unui releu (sans-io)\n");

    // --- CREATE2 ---
    let (state, hs) = client_init::<K>(&public1, Variant::Transitional, &mut rng).unwrap();
    let payload = Create2 { htype: HandshakeType::PqNtorTransitional, data: hs }.encode();
    println!("eveniment: CREATE2 de la client ({} octeti)", payload.len());
    let act = n1.on_create2(CH_CLI, CIRC, &payload, &mut rng).unwrap();
    for a in &act { println!("  {}", nume(a)); }

    let Action::Send { cell, .. } = &act[0] else { unreachable!() };
    let res = client_finish::<K>(state, &Created2::parse(cell.payload()).unwrap().data).unwrap();
    let mut cc = ClientCircuit::new();
    cc.add_hop(&res.key_seed);

    // --- EXTEND2 ---
    let (_st2, hs2) = client_init::<K>(&public2, Variant::Transitional, &mut rng).unwrap();
    let msg = RelayMessage::new(
        RelayCmd::Extend2,
        StreamId::CONTROL,
        Extend2 {
            specs: vec![
                LinkSpec::Ipv4 { addr: [10, 0, 0, 2], port: 9001 },
                LinkSpec::RelayId(public2.id),
            ],
            htype: HandshakeType::PqNtorTransitional,
            data: hs2,
        }
        .encode(),
    )
    .unwrap();

    println!("\neveniment: EXTEND2 de la client ({} celule RELAY_EARLY)", msg.cell_count());
    let mut token = 0;
    for corp in msg.fragment(&mut rng) {
        let c = cc.encrypt_outbound(1, ChanCmd::RelayEarly as u8, &corp).unwrap();
        let cell = Cell::fixed(CIRC, ChanCmd::RelayEarly, c.as_slice()).unwrap();
        for a in n1.on_relay_forward(CH_CLI, CIRC, &cell, &mut rng).unwrap() {
            println!("  {}", nume(&a));
            if let Action::Connect { token: t, .. } = a { token = t; }
        }
    }

    println!("\neveniment: coaja de I/O a deschis canalul (token {token})");
    for a in &n1.on_channel_ready(token, ChannelId(2)).unwrap() {
        println!("  {}", nume(a));
    }

    // --- DESTROY ---
    println!("\neveniment: DESTROY de la client");
    for a in &n1.on_destroy(CH_CLI, CIRC) {
        println!("  {}", nume(a));
    }

    println!("\nCircuite ramase: {}", n1.circuit_count());
    println!("\nNiciun socket deschis, niciun .await. Coaja de I/O executa actiunile.");
}
