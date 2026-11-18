//! Serverul magazinului.
//!
//! ```text
//! pqonion-shop --listen 127.0.0.1:8080
//! ```
//!
//! Coaja de retea peste [`pqo_shop::api`]. Nu contine nicio regula de afacere si
//! niciun cod de stare: tot ce conteaza se decide in stratul de dedesubt, care se
//! testeaza fara socket-uri.
//!
//! # De expus prin serviciu ascuns
//!
//! ```text
//! pqonion-shop --listen 127.0.0.1:8080 &
//! pqonion-hs --target 127.0.0.1:8080 --hsdir ...
//! ```
//!
//! Magazinul nu stie ca e accesat prin `.onion` si nici nu trebuie: nu vede
//! adrese de client, deci nu are ce sa scurga.

use std::sync::Arc;

use pqo_shop::http::{self, EroareHttp, Metoda, Raspuns};
use pqo_shop::{trateaza, Magazin};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Cat asteptam o cerere completa inainte sa inchidem.
///
/// Fara el, o conexiune care trimite jumatate de antet si tace ar ocupa un task
/// la nesfarsit — atacul cunoscut ca Slowloris.
const TIMEOUT_CERERE: u64 = 30;

#[tokio::main]
async fn main() {
    let mut listen = "127.0.0.1:8080".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        // Acceptam si `--listen VAL` si `--listen=VAL`. A doua forma e cea pe
        // care o scrii natural intr-o lista YAML de docker compose.
        let (nume, valoare) = match a.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (a.clone(), None),
        };
        match nume.as_str() {
            "--listen" => {
                listen = match valoare {
                    Some(v) => v,
                    None => match args.next() {
                        Some(v) => v,
                        None => {
                            eprintln!("[EROARE] --listen cere o adresa");
                            std::process::exit(1);
                        }
                    },
                }
            }
            "--help" => {
                println!("pqonion-shop --listen ADRESA:PORT   (implicit 127.0.0.1:8080)");
                return;
            }
            alt => {
                eprintln!("[EROARE] argument necunoscut: {alt}");
                std::process::exit(1);
            }
        }
    }

    let addr: std::net::SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("[EROARE] adresa invalida: {listen}");
            std::process::exit(1);
        }
    };

    let l = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[EROARE] nu pot asculta pe {addr}: {e}");
            std::process::exit(1);
        }
    };
    // Adresa **efectiva**, nu cea ceruta: cu `--listen 127.0.0.1:0` sistemul
    // alege portul, iar cine porneste procesul il afla de aici.
    //
    // Asta elimina o cursa la care testele sunt expuse altfel: daca cel care
    // porneste procesul ar cauta el un port liber, l-ar elibera inainte ca noi
    // sa il legam, si intre timp altcineva l-ar putea lua.
    eprintln!("[INFO] magazin pe {}", l.local_addr().unwrap_or(addr));

    let acum = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let magazin = Arc::new(Mutex::new(Magazin::demonstrativ().cu_ceas(acum)));

    loop {
        tokio::select! {
            r = l.accept() => match r {
                Ok((sock, _)) => {
                    let m = Arc::clone(&magazin);
                    tokio::spawn(async move { deserveste(sock, m).await });
                }
                Err(_) => break,
            },
            _ = tokio::signal::ctrl_c() => {
                eprintln!("[INFO] oprire");
                return;
            }
        }
    }
}

async fn deserveste(mut sock: TcpStream, magazin: Arc<Mutex<Magazin>>) {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 4096];

    loop {
        // Parsam ce avem; daca nu e destul, mai citim.
        let (cerere, consumat) = match http::parseaza(&buf) {
            Ok(v) => v,
            Err(EroareHttp::Incomplet) => {
                let n = match tokio::time::timeout(
                    std::time::Duration::from_secs(TIMEOUT_CERERE),
                    sock.read(&mut chunk),
                )
                .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
                    Ok(Ok(n)) => n,
                };
                buf.extend_from_slice(&chunk[..n]);
                continue;
            }
            Err(e) => {
                let r = match e {
                    EroareHttp::PreaMare => Raspuns::nou(413).text("cerere prea mare"),
                    EroareHttp::MetodaNecunoscuta => Raspuns::nou(501).text("metoda nesuportata"),
                    _ => Raspuns::nou(400).text("cerere malformata"),
                };
                let _ = sock.write_all(&r.encode(false)).await;
                return;
            }
        };

        let doar_antete = cerere.metoda == Metoda::Head;
        let raspuns = {
            let mut m = magazin.lock().await;
            trateaza(&mut m, &cerere)
        };
        if sock.write_all(&raspuns.encode(doar_antete)).await.is_err() {
            return;
        }
        buf.drain(..consumat);
    }
}
