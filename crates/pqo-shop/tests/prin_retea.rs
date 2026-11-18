//! Magazinul, prin socket-uri reale.
//!
//! Verifica exact ce se va vedea la sustinere: un client HTTP obisnuit face
//! cereri REST, iar raspunsurile respecta contractul — coduri de stare, `ETag`,
//! `Location`, legaturi.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Proces(Child);

impl Drop for Proces {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn binar(nume: &str) -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("calea testului");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(nume)
}

fn asteapta(addr: SocketAddr) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Un raspuns HTTP citit de pe fir.
struct Raspuns {
    stare: u16,
    antete: Vec<(String, String)>,
    corp: String,
}

impl Raspuns {
    fn antet(&self, nume: &str) -> Option<&str> {
        self.antete
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(nume))
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.corp).expect("corp JSON")
    }
}

/// Trimite o cerere pe o conexiune noua si citeste raspunsul complet.
fn cere(addr: SocketAddr, brut: &str) -> Raspuns {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(brut.as_bytes()).unwrap();
    // Un raspuns la `HEAD` anunta lungimea corpului, dar nu il trimite. Un
    // client care ar astepta octetii aia ar atarna la nesfarsit — de aceea
    // metoda cererii determina cum se citeste raspunsul.
    citeste_cu(&mut s, !brut.starts_with("HEAD "))
}

/// Citeste un raspuns complet: antet, apoi exact cat spune `Content-Length`.
fn citeste(s: &mut TcpStream) -> Raspuns {
    citeste_cu(s, true)
}

fn citeste_cu(s: &mut TcpStream, cu_corp: bool) -> Raspuns {
    let mut date = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if let Some(i) = date.windows(4).position(|w| w == b"\r\n\r\n") {
            let cap = String::from_utf8_lossy(&date[..i]).to_string();
            let declarata: usize = cap
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    if k.eq_ignore_ascii_case("content-length") {
                        v.trim().parse().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let len = if cu_corp { declarata } else { 0 };
            if date.len() >= i + 4 + len {
                let mut linii = cap.lines();
                let prima = linii.next().unwrap_or("");
                let stare = prima
                    .split(' ')
                    .nth(1)
                    .and_then(|c| c.parse().ok())
                    .unwrap_or(0);
                let antete = linii
                    .filter_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        Some((k.trim().to_string(), v.trim().to_string()))
                    })
                    .collect();
                return Raspuns {
                    stare,
                    antete,
                    corp: String::from_utf8_lossy(&date[i + 4..i + 4 + len]).to_string(),
                };
            }
        }
        match s.read(&mut buf) {
            Ok(0) | Err(_) => panic!("raspuns incomplet"),
            Ok(n) => date.extend_from_slice(&buf[..n]),
        }
    }
}

fn get(addr: SocketAddr, cale: &str) -> Raspuns {
    cere(addr, &format!("GET {cale} HTTP/1.1\r\nHost: x\r\n\r\n"))
}

fn cu_corp(addr: SocketAddr, metoda: &str, cale: &str, antete: &str, corp: &str) -> Raspuns {
    cere(
        addr,
        &format!(
            "{metoda} {cale} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n{antete}Content-Length: {}\r\n\r\n{corp}",
            corp.len()
        ),
    )
}

/// Porneste un magazin pe un port ales de sistem si afla care e.
///
/// Nu cautam noi un port liber: intre momentul in care l-am gasi si cel in care
/// procesul l-ar lega, alt test rulat in paralel l-ar putea ocupa. Cele doua
/// teste ar ajunge sa vorbeasca cu **acelasi** magazin si si-ar strica reciproc
/// stocul si identificatorii de cos — exact tiparul unui esec care apare la alt
/// test la fiecare rulare.
fn porneste() -> (Proces, SocketAddr) {
    let mut copil = Command::new(binar("pqonion-shop"))
        .args(["--listen", "127.0.0.1:0"])
        .stderr(Stdio::piped())
        .spawn()
        .expect("magazinul trebuie sa porneasca");

    let mut err = copil.stderr.take().expect("stderr captat");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut buf = String::new();
        let mut chunk = [0u8; 512];
        loop {
            match err.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    if buf.contains('\n') && tx.send(buf.clone()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let text = rx
        .recv_timeout(Duration::from_secs(15))
        .expect("magazinul trebuie sa isi anunte adresa");
    let addr: SocketAddr = text
        .lines()
        .find_map(|l| l.rsplit_once("magazin pe ")?.1.trim().parse().ok())
        .unwrap_or_else(|| panic!("nu gasesc adresa in: {text}"));

    assert!(asteapta(addr), "magazinul nu asculta pe {addr}");
    (Proces(copil), addr)
}

#[test]
fn ciclu_complet_de_cumparare_prin_http() {
    let (_p, addr) = porneste();

    // Pornim de la radacina si urmam legaturile, ca un client REST adevarat.
    let r = get(addr, "/");
    assert_eq!(r.stare, 200);
    let cale_produse = r.json()["legaturi"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x[0] == "produse")
        .expect("radacina trebuie sa dea calea catre produse")[1]["href"]
        .as_str()
        .unwrap()
        .to_string();

    let r = get(addr, &cale_produse);
    assert_eq!(r.stare, 200);
    assert!(r.json()["total"].as_u64().unwrap() > 0);

    // Cos nou.
    let r = cere(addr, "POST /cosuri HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(r.stare, 201);
    let cos = r.antet("Location").unwrap().to_string();
    let et = r.antet("ETag").unwrap().to_string();

    // Doua blastere.
    let r = cu_corp(
        addr,
        "PUT",
        &format!("{cos}/articole/p-001"),
        &format!("If-Match: {et}\r\n"),
        r#"{"cantitate":2}"#,
    );
    assert_eq!(r.stare, 200);
    let et2 = r.antet("ETag").unwrap().to_string();
    assert_eq!(r.json()["total_bani"], 25_800);

    // Plus un set de munitie.
    let r = cu_corp(
        addr,
        "PUT",
        &format!("{cos}/articole/p-006"),
        &format!("If-Match: {et2}\r\n"),
        r#"{"cantitate":1}"#,
    );
    assert_eq!(r.stare, 200);
    assert_eq!(r.json()["total_bani"], 29_000);

    // Comanda.
    let id = cos.trim_start_matches("/cosuri/");
    let r = cu_corp(addr, "POST", "/comenzi", "", &format!(r#"{{"cos":"{id}"}}"#));
    assert_eq!(r.stare, 201);
    let comanda = r.antet("Location").unwrap().to_string();
    assert_eq!(r.json()["total_bani"], 29_000);

    // Se citeste de la adresa data in Location.
    let r = get(addr, &comanda);
    assert_eq!(r.stare, 200);
    assert_eq!(r.json()["stare"], "plasata");

    // Stocul a scazut cu exact cat s-a comandat.
    let r = get(addr, "/produse/p-001");
    assert_eq!(r.json()["stoc"], 38);
}

#[test]
fn conditiile_functioneaza_pe_fir() {
    let (_p, addr) = porneste();
    let r = cere(addr, "POST /cosuri HTTP/1.1\r\nHost: x\r\n\r\n");
    let cos = r.antet("Location").unwrap().to_string();
    let et = r.antet("ETag").unwrap().to_string();

    // Fara `If-Match`: refuzat, cu explicatia.
    let r = cu_corp(
        addr,
        "PUT",
        &format!("{cos}/articole/p-001"),
        "",
        r#"{"cantitate":1}"#,
    );
    assert_eq!(r.stare, 428);

    let r = cu_corp(
        addr,
        "PUT",
        &format!("{cos}/articole/p-001"),
        &format!("If-Match: {et}\r\n"),
        r#"{"cantitate":1}"#,
    );
    assert_eq!(r.stare, 200);

    // Cu ETag-ul vechi: al doilea client afla ca resursa s-a schimbat.
    let r = cu_corp(
        addr,
        "PUT",
        &format!("{cos}/articole/p-002"),
        &format!("If-Match: {et}\r\n"),
        r#"{"cantitate":1}"#,
    );
    assert_eq!(r.stare, 412);

    // `If-None-Match` cu versiunea curenta: nu retrimitem corpul.
    let r = get(addr, &cos);
    let curent = r.antet("ETag").unwrap().to_string();
    let r = cere(
        addr,
        &format!("GET {cos} HTTP/1.1\r\nHost: x\r\nIf-None-Match: {curent}\r\n\r\n"),
    );
    assert_eq!(r.stare, 304);
    assert!(r.corp.is_empty());
}

#[test]
fn head_da_aceleasi_antete_fara_corp() {
    let (_p, addr) = porneste();
    let g = get(addr, "/produse");
    let h = cere(addr, "HEAD /produse HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(g.stare, h.stare);
    assert_eq!(
        g.antet("Content-Length"),
        h.antet("Content-Length"),
        "HEAD trebuie sa anunte aceeasi dimensiune ca GET"
    );
    assert!(h.corp.is_empty());
    assert!(!g.corp.is_empty());
}

#[test]
fn erorile_respecta_contractul() {
    let (_p, addr) = porneste();

    assert_eq!(get(addr, "/produse/inexistent").stare, 404);
    assert_eq!(get(addr, "/aiurea").stare, 404);
    assert_eq!(get(addr, "/produse?categorie=bazooka").stare, 422);

    let r = cere(addr, "DELETE /produse HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(r.stare, 405);
    assert!(
        r.antet("Allow").is_some(),
        "un 405 trebuie sa spuna ce metode sunt permise"
    );

    // Cerere malformata: raspuns de eroare, nu conexiune inchisa brusc.
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"CEVA ORICE\r\n\r\n").unwrap();
    // Citim complet, nu o singura bucata: un `read` intoarce doar ce a ajuns
    // pana atunci, iar un test care presupune altceva trece sau pica dupa noroc.
    let r = citeste(&mut s);
    assert!((400..500).contains(&r.stare), "asteptam o eroare de client");
}

#[test]
fn conexiunea_se_refoloseste() {
    // keep-alive: mai multe cereri pe aceeasi conexiune, ca sa nu platim un
    // handshake de circuit pentru fiecare cerere.
    let (_p, addr) = porneste();
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    for i in 0..3 {
        s.write_all(b"GET /produse?limita=1 HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let r = citeste(&mut s);
        assert_eq!(r.stare, 200, "cererea {i} pe aceeasi conexiune");
    }
}

#[test]
fn stocul_nu_se_vinde_de_doua_ori() {
    // Doua cosuri cer tot stocul aceluiasi produs. Doar unul poate reusi.
    let (_p, addr) = porneste();

    let mut cosuri = Vec::new();
    for _ in 0..2 {
        let r = cere(addr, "POST /cosuri HTTP/1.1\r\nHost: x\r\n\r\n");
        let cos = r.antet("Location").unwrap().to_string();
        let et = r.antet("ETag").unwrap().to_string();
        // p-005 are stoc 18.
        let r = cu_corp(
            addr,
            "PUT",
            &format!("{cos}/articole/p-005"),
            &format!("If-Match: {et}\r\n"),
            r#"{"cantitate":18}"#,
        );
        assert_eq!(r.stare, 200);
        cosuri.push(cos.trim_start_matches("/cosuri/").to_string());
    }

    let r1 = cu_corp(
        addr,
        "POST",
        "/comenzi",
        "",
        &format!(r#"{{"cos":"{}"}}"#, cosuri[0]),
    );
    assert_eq!(r1.stare, 201);

    let r2 = cu_corp(
        addr,
        "POST",
        "/comenzi",
        "",
        &format!(r#"{{"cos":"{}"}}"#, cosuri[1]),
    );
    assert_eq!(r2.stare, 409, "al doilea nu mai are ce cumpara");
    assert_eq!(r2.json()["tip"], "stoc-insuficient");
}

#[test]
fn ambele_forme_de_argument_functioneaza() {
    // `docker compose` scrie natural `--listen=ADRESA`. Parserul trebuie sa o
    // accepte la fel ca `--listen ADRESA`, altfel procesul refuza sa porneasca
    // in container fara niciun motiv vizibil din configuratie.
    //
    // Testul traieste aici, nu in `pqo-bin`: binarul apartine acestui crate,
    // deci doar aici e garantat construit. Pus in alta parte, ar trece doar cand
    // ramane din alt build — ceea ce s-a si intamplat prima data.
    for arg in [
        vec!["--listen", "127.0.0.1:0"],
        vec!["--listen=127.0.0.1:0"],
    ] {
        let mut copil = Command::new(binar("pqonion-shop"))
            .args(&arg)
            .stderr(Stdio::piped())
            .spawn()
            .expect("magazinul trebuie sa porneasca");

        let mut err = copil.stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut buf = String::new();
            let mut chunk = [0u8; 256];
            while let Ok(n) = err.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                if tx.send(buf.clone()).is_err() {
                    break;
                }
            }
        });
        let text = rx
            .recv_timeout(Duration::from_secs(10))
            .unwrap_or_default();
        let _ = copil.kill();
        let _ = copil.wait();

        assert!(
            text.contains("magazin pe"),
            "forma {arg:?} nu a pornit: {text}"
        );
    }
}
