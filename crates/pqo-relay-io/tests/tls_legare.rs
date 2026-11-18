//! Legarea de canal: ce anume impiedica.
//!
//! Handshake-ul de legatura demonstreaza posesia cheii de identitate. Fara o
//! legatura cu conexiunea pe care circula, un atacator care observa un handshake
//! valid l-ar putea reda pe o conexiune pe care o controleaza el — atac de tip
//! unknown key share.
//!
//! Testele de aici rulează handshake-ul peste TLS real si verifica exact asta.

#![cfg(feature = "tls")]

use std::sync::Arc;

use pqo_crypto::sig::{Ed25519, Sig};
use pqo_relay::link::{AuthMode, Role};
use pqo_relay_io::codec::CellStream;
use pqo_relay_io::node::link_handshake_cu_legare;
use pqo_relay_io::tls::{acceptor, connect, connector, TlsKeys};
use pqo_relay_io::ChannelBinding;
use rand_core::OsRng;
use tokio::net::{TcpListener, TcpStream};

type S = Ed25519;

#[tokio::test]
async fn handshake_peste_tls_reuseste() {
    let keys = TlsKeys::generate().unwrap();
    let acc = acceptor(&keys).unwrap();
    let con = connector();

    let (rsk, rpk) = S::keygen(&mut OsRng);
    let (isk, ipk) = S::keygen(&mut OsRng);

    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (sock, _) = l.accept().await.unwrap();
        let c = pqo_relay_io::tls::accept(&acc, sock).await.unwrap();
        let mut stream = CellStream::new(c.stream);
        link_handshake_cu_legare::<S, _>(
            &mut stream,
            Role::Responder,
            AuthMode::Optional,
            Arc::new(rsk),
            &rpk,
            c.binding,
        )
        .await
    });

    let sock = TcpStream::connect(addr).await.unwrap();
    let c = connect(&con, sock).await.unwrap();
    let mut stream = CellStream::new(c.stream);
    link_handshake_cu_legare::<S, _>(
        &mut stream,
        Role::Initiator,
        AuthMode::ResponderOnly,
        Arc::new(isk),
        &ipk,
        c.binding,
    )
    .await
    .expect("handshake-ul peste TLS trebuie sa reuseasca");

    server.await.unwrap().expect("si la celalalt capat");
}

#[tokio::test]
async fn legari_diferite_rup_handshake_ul() {
    // Simuleaza exact atacul: cele doua capete cred ca sunt pe conexiuni
    // diferite. Semnatura acopera legarea, deci nu se verifica.
    //
    // In realitate asta se intampla cand un atacator retransmite un handshake
    // observat pe alta conexiune TLS.
    let (rsk, rpk) = S::keygen(&mut OsRng);
    let (isk, ipk) = S::keygen(&mut OsRng);

    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (sock, _) = l.accept().await.unwrap();
        let mut stream = CellStream::new(sock);
        link_handshake_cu_legare::<S, _>(
            &mut stream,
            Role::Responder,
            AuthMode::Optional,
            Arc::new(rsk),
            &rpk,
            ChannelBinding::from_tls_exporter(vec![0xAA; 32]),
        )
        .await
    });

    let sock = TcpStream::connect(addr).await.unwrap();
    let mut stream = CellStream::new(sock);
    let r = link_handshake_cu_legare::<S, _>(
        &mut stream,
        Role::Initiator,
        AuthMode::ResponderOnly,
        Arc::new(isk),
        &ipk,
        // Alta legare: alta conexiune.
        ChannelBinding::from_tls_exporter(vec![0xBB; 32]),
    )
    .await;

    assert!(
        r.is_err(),
        "un handshake cu legare diferita nu are voie sa treaca"
    );
    let _ = server.await;
}

#[tokio::test]
async fn legarea_din_tls_nu_e_cea_nesigura() {
    // Marcajul exista tocmai ca sa se vada in cod daca cineva ruleaza fara TLS.
    let keys = TlsKeys::generate().unwrap();
    let acc = acceptor(&keys).unwrap();
    let con = connector();

    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (sock, _) = l.accept().await.unwrap();
        pqo_relay_io::tls::accept(&acc, sock).await.unwrap().binding
    });

    let sock = TcpStream::connect(addr).await.unwrap();
    let b = connect(&con, sock).await.unwrap().binding;
    assert!(!b.is_insecure());
    assert!(!server.await.unwrap().is_insecure());
    assert!(ChannelBinding::insecure_plaintext_tcp().is_insecure());
}
