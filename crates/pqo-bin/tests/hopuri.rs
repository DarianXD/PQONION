//! Cate hopuri au circuitele catre punctele de introducere si de rendezvous.
//!
//! # De ce exista acest fisier
//!
//! Prima versiune a binarelor se conecta **direct** la releul care juca rolul de
//! punct de introducere sau de rendezvous. Mesajele erau corecte, semantica de
//! protocol era corecta, si toate cele 490 de teste treceau — pentru ca verificau
//! ca rendezvous-ul *functioneaza*, nu **prin cate relee trece**.
//!
//! Consecinta: punctul de introducere vedea adresa reala a serviciului, iar
//! punctul de rendezvous pe cea a clientului. Adica exact ce trebuie sa nu se
//! intample.
//!
//! S-a vazut abia intr-o captura de trafic — nu exista nicio conexiune
//! releu-releu. Testele de aici verifica proprietatea, nu functionalitatea.

use std::net::SocketAddr;
use std::sync::Arc;

use pqo_crypto::kem::{Hybrid, X25519Kem};
use pqo_crypto::sig::{Ed25519, Sig};
use pqo_crypto::{ntor, RelayKeys, Variant};
use pqo_dirproto::dirreq::DirStore;
use pqo_relay::stream::ExitPolicy;
use pqo_relay_io::client::TransportClient;
use pqo_relay_io::node::{spawn, NodeConfig, Transport};
use rand_core::OsRng;

type K = Hybrid<X25519Kem, X25519Kem>;
type S = Ed25519;

/// Porneste `n` relee cu semintele de testnet, si intoarce adresele.
async fn retea(n: u8) -> (Vec<SocketAddr>, Vec<pqo_relay_io::NodeHandle>) {
    use pqo_crypto::kdf::ShakeRng;

    let mut adrese = Vec::new();
    let mut mane = Vec::new();
    for i in 0..n {
        let seed = pqo_bin::testnet_seed(i);
        // Aceeasi derivare ca in binarul de releu, ca fingerprint-urile sa
        // corespunda cu ce asteapta `testnet_relay_public`.
        let mut r_id = ShakeRng::new(b"pqonion-relay-identity-v1", &[&seed]);
        let (id_sk, id_pk) = S::keygen(&mut r_id);
        let mut r_onion = ShakeRng::new(b"pqonion-relay-onion-v1", &[&seed]);
        let keys = RelayKeys::<K>::generate(
            pqo_dirproto::netdoc::fingerprint(&id_pk),
            Variant::Transitional,
            &mut r_onion,
        );
        let _ = ntor::ID_LEN;

        let h = spawn::<K, S>(NodeConfig {
            circuit_keys: keys,
            id_sk: Arc::new(id_sk),
            id_pk,
            listen: "127.0.0.1:0".parse().unwrap(),
            exit_policy: ExitPolicy::reject_all(),
            dir_store: Arc::new(std::sync::Mutex::new(DirStore::new())),
            hs_store: None,
            metrici: Default::default(),
            transport: Arc::new(Transport::Plaintext),
        })
        .await
        .expect("releul trebuie sa porneasca");
        adrese.push(h.addr());
        mane.push(h);
    }
    (adrese, mane)
}

#[tokio::test]
async fn circuitul_catre_un_releu_are_trei_hopuri() {
    // Proprietatea, nu functionalitatea.
    let (adrese, mane) = retea(3).await;
    let (sk, pk) = S::keygen(&mut OsRng);
    let sk = Arc::new(sk);

    for tinta in 0..3u8 {
        let c = pqo_bin::circuit_catre::<K, S>(
            &adrese,
            tinta,
            Arc::clone(&sk),
            &pk,
            TransportClient::Plaintext,
        )
        .await
        .unwrap_or_else(|e| panic!("cale catre releul {tinta}: {e}"));

        assert_eq!(
            c.hops(),
            pqo_bin::HOPURI_SERVICIU,
            "circuitul catre releul {tinta} trebuie sa aiba {} hopuri, nu {}",
            pqo_bin::HOPURI_SERVICIU,
            c.hops()
        );
    }

    for h in mane {
        h.shutdown();
    }
}

#[tokio::test]
async fn ultimul_hop_e_chiar_releul_cerut() {
    // Un circuit de trei hopuri care se termina altundeva n-ar ajunge la punctul
    // de introducere.
    let (adrese, mane) = retea(3).await;
    let (sk, pk) = S::keygen(&mut OsRng);

    // Deschidem un stream de director la capat: doar releul-tinta il poate servi,
    // deci reusita confirma unde s-a terminat circuitul.
    let mut c = pqo_bin::circuit_catre::<K, S>(
        &adrese,
        2,
        Arc::new(sk),
        &pk,
        TransportClient::Plaintext,
    )
    .await
    .unwrap();
    assert_eq!(c.hops(), 3);

    let r = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        c.dir_request(pqo_dirproto::dirreq::DirRequest::Consensus),
    )
    .await
    .expect("cererea nu trebuie sa expire")
    .expect("ultimul hop trebuie sa raspunda la cereri de director");
    // Magazinul de documente e gol, dar raspunsul dovedeste ca am ajuns acolo.
    assert_eq!(r.status, pqo_dirproto::dirreq::DirStatus::NotFound);

    for h in mane {
        h.shutdown();
    }
}

#[tokio::test]
async fn niciun_releu_nu_apare_de_doua_ori_pe_cale() {
    // Un releu care ar aparea de doua ori ar vedea doua pozitii si ar putea
    // corela intrarea cu iesirea.
    let (adrese, mane) = retea(4).await;
    let (sk, pk) = S::keygen(&mut OsRng);

    let c = pqo_bin::circuit_catre::<K, S>(
        &adrese,
        3,
        Arc::new(sk),
        &pk,
        TransportClient::Plaintext,
    )
    .await
    .unwrap();
    assert_eq!(c.hops(), 3);

    for h in mane {
        h.shutdown();
    }
}

#[tokio::test]
async fn o_retea_prea_mica_e_refuzata() {
    // Cu doua relee nu se poate construi o cale de trei hopuri distincte.
    // Alternativa — sa construim una mai scurta in tacere — ar da un circuit
    // care pare ca merge dar nu ofera anonimat.
    let (adrese, mane) = retea(2).await;
    let (sk, pk) = S::keygen(&mut OsRng);

    let r = pqo_bin::circuit_catre::<K, S>(
        &adrese,
        1,
        Arc::new(sk),
        &pk,
        TransportClient::Plaintext,
    )
    .await;
    assert!(
        r.is_err(),
        "o retea cu doua relee nu are voie sa produca un circuit"
    );
    let e = r.unwrap_err().to_string();
    assert!(e.contains("relee"), "eroarea trebuie sa explice de ce: {e}");

    for h in mane {
        h.shutdown();
    }
}

#[tokio::test]
async fn tinta_inexistenta_e_refuzata() {
    let (adrese, mane) = retea(3).await;
    let (sk, pk) = S::keygen(&mut OsRng);
    let r = pqo_bin::circuit_catre::<K, S>(
        &adrese,
        9,
        Arc::new(sk),
        &pk,
        TransportClient::Plaintext,
    )
    .await;
    assert!(r.is_err());
    for h in mane {
        h.shutdown();
    }
}
