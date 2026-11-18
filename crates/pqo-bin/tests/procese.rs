//! Testeaza binarele ca **procese**, nu ca functii.
//!
//! Diferenta conteaza: pana acum toate testele apelau cod direct. Aici pornim
//! executabilele, le dam argumente, si verificam ca fac ce trebuie prin socket-uri
//! reale. E singurul mod de a prinde erori de ambalaj — argumente parsate gresit,
//! chei care nu se salveaza, procese care mor la pornire.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Un proces pornit, care se opreste cand iese din scop.
struct Proces(Child);

impl Drop for Proces {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn binar(nume: &str) -> std::path::PathBuf {
    // Binarele stau langa executabilul de test, in `target/debug`.
    let mut p = std::env::current_exe().expect("calea testului");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(nume)
}

/// Citeste un raspuns HTTP complet de pe un socket.
///
/// Un singur `read` intoarce ce a ajuns pana atunci, nu tot raspunsul. O pagina
/// de cativa kiloocteti vine aproape sigur in mai multe segmente TCP, deci un
/// test care citeste o data si presupune ca are tot trece sau pica dupa noroc.
///
/// `cu_corp` e fals pentru `HEAD`, care anunta o lungime dar nu trimite corpul.
fn citeste_http(s: &mut TcpStream, cu_corp: bool) -> String {
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
                return String::from_utf8_lossy(&date[..i + 4 + len]).to_string();
            }
        }
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return String::from_utf8_lossy(&date).to_string(),
            Ok(n) => date.extend_from_slice(&buf[..n]),
        }
    }
}

/// Citeste stderr-ul unui proces pana apare un marcaj, sau pana expira.
///
/// Necesar pentru ca portul se leaga inainte ca procesul sa isi scrie log-urile
/// de pornire: cine asteapta doar sa se poata conecta si apoi omoara procesul
/// poate citi ieșirea la jumatate.
fn stderr_pana(p: &mut Child, marcaj: &str, cat: Duration) -> String {
    use std::sync::mpsc;

    let mut err = p.stderr.take().expect("stderr trebuie sa fie captat");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut buf = String::new();
        let mut chunk = [0u8; 1024];
        loop {
            match err.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    if tx.send(buf.clone()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let start = Instant::now();
    let mut ultim = String::new();
    while start.elapsed() < cat {
        if let Ok(t) = rx.recv_timeout(Duration::from_millis(200)) {
            ultim = t;
            if ultim.contains(marcaj) {
                break;
            }
        }
    }
    let _ = p.kill();
    ultim
}

fn dir_temp(eticheta: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "pqo-bin-{}-{}-{}",
        eticheta,
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Un port liber, eliberat imediat.
///
/// Are o cursa inerenta — altcineva poate ocupa portul intre eliberare si
/// folosire — dar e singura optiune cand procesul copil isi alege singur portul.
/// Un port liber, garantat distinct de celelalte cerute in acest proces.
///
/// Varianta naiva — leaga portul 0, il afla, il elibereaza — are o cursa: intre
/// eliberare si momentul in care procesul copil il leaga, alt test rulat in
/// paralel poate primi acelasi port. Cele doua teste ajung sa vorbeasca cu
/// acelasi proces si isi strica reciproc starea, iar esecul apare la alt test la
/// fiecare rulare.
///
/// `cargo test` ruleaza binarele de test secvential, dar testele dintr-un binar
/// in paralel, pe fire. Deci un contor atomic per proces e suficient ca sa
/// elimine coliziunile dintre teste; verificarea de legare ramane pentru cazul
/// in care portul e ocupat de altcineva din afara.
fn port_liber() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};

    // Baza se deriva din identificatorul procesului, ca doua rulari simultane
    // sa nu se calce.
    static URMATOR: AtomicU16 = AtomicU16::new(0);
    let baza = 20_000u16.wrapping_add((std::process::id() % 30_000) as u16);

    for _ in 0..2000 {
        let n = URMATOR.fetch_add(1, Ordering::Relaxed);
        let port = baza.wrapping_add(n) | 0x4000;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("nu am gasit niciun port liber");
}

/// Asteapta ca cineva sa asculte pe adresa data.
fn asteapta_port(addr: SocketAddr, cat: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < cat {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Un server care intoarce ce primeste, intr-un fir separat.
fn server_ecou() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

#[test]
fn ajutorul_se_afiseaza_pentru_toate_binarele() {
    for b in ["pqonion-relay", "pqonion-dirauth", "pqonion-client"] {
        let out = Command::new(binar(b))
            .arg("--help")
            .output()
            .unwrap_or_else(|e| panic!("{b} nu a pornit: {e}"));
        assert!(out.status.success(), "{b} --help a esuat");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("--log"), "{b} nu documenteaza --log");
        assert!(text.contains("--help"), "{b} nu documenteaza --help");
    }
}

#[test]
fn argumentele_invalide_dau_eroare_nu_panica() {
    for b in ["pqonion-relay", "pqonion-dirauth", "pqonion-client"] {
        let out = Command::new(binar(b))
            .args(["--log", "aiurea"])
            .output()
            .unwrap();
        assert!(!out.status.success(), "{b} a acceptat un nivel invalid");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("EROARE"), "{b} nu a raportat clar eroarea");
        assert!(
            !err.contains("panicked"),
            "{b} a produs panica in loc de eroare"
        );
    }
}

#[test]
fn clientul_cere_cel_putin_doua_hopuri() {
    let out = Command::new(binar("pqonion-client"))
        .args(["--guard", "127.0.0.1:1"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "o cale de un hop nu are sens");
}

#[test]
fn releul_isi_pastreaza_identitatea_intre_porniri() {
    // Un releu care isi schimba cheia la fiecare repornire ar aparea ca nod nou
    // si nu ar acumula niciodata reputatie in consens.
    let dir = dir_temp("identitate");
    let port = port_liber();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let mut fingerprints = Vec::new();
    for _ in 0..2 {
        let p = Proces(
            Command::new(binar("pqonion-relay"))
                .args([
                    "--listen",
                    &addr.to_string(),
                    "--data-dir",
                    dir.to_str().unwrap(),
                ])
                .stderr(Stdio::piped())
                .spawn()
                .expect("releul trebuie sa porneasca"),
        );
        assert!(
            asteapta_port(addr, Duration::from_secs(10)),
            "releul nu a inceput sa asculte"
        );

        // Citim fingerprint-ul din log, dupa ce pornirea s-a incheiat.
        let mut p = p;
        let text = stderr_pana(&mut p.0, "gata", Duration::from_secs(10));
        let fp = text
            .lines()
            .find(|l| l.contains("fingerprint"))
            .map(|l| l.to_string())
            .expect("releul trebuie sa isi anunte fingerprint-ul");
        fingerprints.push(fp);
        std::thread::sleep(Duration::from_millis(200));
    }

    assert_eq!(
        fingerprints[0], fingerprints[1],
        "identitatea trebuie sa supravietuiasca repornirii"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn releul_refuza_chei_cu_permisiuni_largi() {
    // Pe o masina partajata, o cheie privata lizibila de altii inseamna ca
    // oricine poate impersona releul.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = dir_temp("permisiuni");
        std::fs::create_dir_all(&dir).unwrap();
        let k = dir.join("identitate.key");
        std::fs::write(&k, [0u8; 32]).unwrap();
        std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o644)).unwrap();

        let out = Command::new(binar("pqonion-relay"))
            .args([
                "--listen",
                &format!("127.0.0.1:{}", port_liber()),
                "--data-dir",
                dir.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!out.status.success(), "cheia nesigura trebuia refuzata");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("0600"), "eroarea nu explica ce e gresit: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn autoritatea_scrie_un_consens_verificabil() {
    let dir = dir_temp("autoritate");
    let out = Command::new(binar("pqonion-dirauth"))
        .args([
            "--data-dir",
            dir.to_str().unwrap(),
            "--interval",
            "3600",
            "--cicluri",
            "1",
        ])
        .output()
        .expect("autoritatea trebuie sa porneasca");
    assert!(out.status.success(), "autoritatea a esuat");

    let doc = std::fs::read_to_string(dir.join("consens.txt")).expect("consensul trebuie scris");
    assert!(doc.starts_with("consensus 1\n"));
    assert!(
        doc.contains("authority-signature"),
        "consensul trebuie semnat"
    );

    // Rularea a doua trebuie sa foloseasca aceeasi cheie.
    let out2 = Command::new(binar("pqonion-dirauth"))
        .args([
            "--data-dir",
            dir.to_str().unwrap(),
            "--cicluri",
            "1",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out2.stderr);
    let fp1 = String::from_utf8_lossy(&out.stderr)
        .lines()
        .find(|l| l.contains("fingerprint"))
        .map(|s| s.to_string())
        .unwrap();
    assert!(
        err.contains(fp1.trim()),
        "autoritatea si-a schimbat cheia intre porniri"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Testul care conteaza: trei procese, un proxy, o conexiune reala.
#[test]
fn proxy_complet_prin_procese() {
    let tinta = server_ecou();
    let dir = dir_temp("proxy");

    // Doua relee, cu seminte pe care le stie si clientul (vezi nota din client.rs).
    let mut relee = Vec::new();
    let mut adrese = Vec::new();
    for i in 0..2u8 {
        let d = dir.join(format!("releu{i}"));
        std::fs::create_dir_all(&d).unwrap();
        // Samanta cunoscuta, ca in `chei_din_samanta`.
        let mut s = [0u8; 32];
        s[0] = i + 1;
        let k = d.join("identitate.key");
        std::fs::write(&k, s).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let port = port_liber();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut cmd = Command::new(binar("pqonion-relay"));
        cmd.args([
            "--listen",
            &addr.to_string(),
            "--data-dir",
            d.to_str().unwrap(),
        ]);
        // Ultimul releu e exit, catre portul serverului de test.
        if i == 1 {
            // Serverul de test asculta pe localhost, deci exit-ul are nevoie de
            // permisiunea explicita pentru adrese private. Fara flag, politica
            // refuza pe buna dreptate: altfel orice client ar putea scana
            // reteaua interna a operatorului.
            cmd.args([
                "--exit-ports",
                &tinta.port().to_string(),
                "--permite-adrese-private",
            ]);
        }
        relee.push(Proces(cmd.spawn().expect("releul trebuie sa porneasca")));
        assert!(
            asteapta_port(addr, Duration::from_secs(10)),
            "releul {i} nu a pornit"
        );
        adrese.push(addr);
    }

    // Clientul.
    let socks_port = port_liber();
    let socks: SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let _client = Proces(
        Command::new(binar("pqonion-client"))
            .args([
                "--socks",
                &socks.to_string(),
                "--guard",
                &adrese[0].to_string(),
                "--exit",
                &adrese[1].to_string(),
                "--data-dir",
                dir.join("client").to_str().unwrap(),
            ])
            .spawn()
            .expect("clientul trebuie sa porneasca"),
    );
    assert!(
        asteapta_port(socks, Duration::from_secs(10)),
        "clientul nu asculta pe SOCKS5"
    );

    // O aplicatie care vorbeste SOCKS5.
    let mut app = TcpStream::connect(socks).unwrap();
    app.set_read_timeout(Some(Duration::from_secs(20))).unwrap();

    // Nume de domeniu, nu IP: asa nu scurgem DNS.
    let nume = "localhost";
    let mut cerere = vec![5u8, 1, 0, 5, 1, 0, 3, nume.len() as u8];
    cerere.extend_from_slice(nume.as_bytes());
    cerere.extend_from_slice(&tinta.port().to_be_bytes());
    app.write_all(&cerere).unwrap();

    let mut metoda = [0u8; 2];
    app.read_exact(&mut metoda).unwrap();
    assert_eq!(metoda, [5, 0], "negocierea SOCKS5 a esuat");

    let mut rasp = [0u8; 10];
    app.read_exact(&mut rasp).unwrap();
    assert_eq!(rasp[1], 0, "SOCKS5 a refuzat conexiunea (cod {})", rasp[1]);

    let mesaj = b"salut prin doua procese de releu";
    app.write_all(mesaj).unwrap();
    let mut primit = vec![0u8; mesaj.len()];
    app.read_exact(&mut primit)
        .expect("raspunsul trebuie sa ajunga inapoi");
    assert_eq!(&primit[..], mesaj, "datele s-au corupt pe drum");

    drop(relee);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn exitul_refuza_localhost_fara_flag_explicit() {
    // Regresia care a scos la iveala nevoia flag-ului: un exit obisnuit nu are
    // voie sa atinga localhost, chiar daca portul e permis.
    let tinta = server_ecou();
    let dir = dir_temp("fara-privat");

    let mut adrese = Vec::new();
    let mut relee = Vec::new();
    for i in 0..2u8 {
        let d = dir.join(format!("releu{i}"));
        std::fs::create_dir_all(&d).unwrap();
        let mut s = [0u8; 32];
        s[0] = i + 1;
        let k = d.join("identitate.key");
        std::fs::write(&k, s).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let addr: SocketAddr = format!("127.0.0.1:{}", port_liber()).parse().unwrap();
        let mut cmd = Command::new(binar("pqonion-relay"));
        cmd.args([
            "--listen",
            &addr.to_string(),
            "--data-dir",
            d.to_str().unwrap(),
        ]);
        // Portul e permis, dar FARA --permite-adrese-private.
        if i == 1 {
            cmd.args(["--exit-ports", &tinta.port().to_string()]);
        }
        relee.push(Proces(cmd.spawn().unwrap()));
        assert!(asteapta_port(addr, Duration::from_secs(10)));
        adrese.push(addr);
    }

    let socks: SocketAddr = format!("127.0.0.1:{}", port_liber()).parse().unwrap();
    let _client = Proces(
        Command::new(binar("pqonion-client"))
            .args([
                "--socks",
                &socks.to_string(),
                "--guard",
                &adrese[0].to_string(),
                "--exit",
                &adrese[1].to_string(),
                "--data-dir",
                dir.join("client").to_str().unwrap(),
            ])
            .spawn()
            .unwrap(),
    );
    assert!(asteapta_port(socks, Duration::from_secs(10)));

    let mut app = TcpStream::connect(socks).unwrap();
    app.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let nume = "localhost";
    let mut cerere = vec![5u8, 1, 0, 5, 1, 0, 3, nume.len() as u8];
    cerere.extend_from_slice(nume.as_bytes());
    cerere.extend_from_slice(&tinta.port().to_be_bytes());
    app.write_all(&cerere).unwrap();

    let mut metoda = [0u8; 2];
    app.read_exact(&mut metoda).unwrap();
    let mut rasp = [0u8; 10];
    app.read_exact(&mut rasp).unwrap();
    assert_ne!(
        rasp[1], 0,
        "exit-ul nu are voie sa atinga localhost fara flag explicit"
    );

    drop(relee);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn releul_avertizeaza_cand_nu_e_post_cuantic() {
    // Un operator trebuie sa vada clar daca ruleaza un build fara `pq`.
    let dir = dir_temp("avertisment");
    let port = port_liber();
    let mut p = Proces(
        Command::new(binar("pqonion-relay"))
            .args([
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--data-dir",
                dir.to_str().unwrap(),
            ])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    assert!(asteapta_port(
        format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(10)
    ));
    let text = stderr_pana(&mut p.0, "gata", Duration::from_secs(10));

    if cfg!(feature = "pq") {
        assert!(
            !text.contains("NU e post-cuantica"),
            "build cu 'pq' nu trebuie sa avertizeze"
        );
    } else {
        assert!(
            text.contains("NU e post-cuantica"),
            "build fara 'pq' trebuie sa avertizeze clar operatorul"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn serviciul_ascuns_isi_pastreaza_adresa() {
    // Un serviciu care si-ar schimba adresa la fiecare pornire ar fi
    // inutilizabil: nimeni nu l-ar putea gasi de doua ori.
    let dir = dir_temp("hs-adresa");

    let mut adrese = Vec::new();
    for _ in 0..2 {
        let out = Command::new(binar("pqonion-hs"))
            .args(["--data-dir", dir.to_str().unwrap(), "--adresa-doar"])
            .output()
            .expect("serviciul trebuie sa porneasca");
        assert!(out.status.success());
        let a = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(a.ends_with(".onion"), "iesirea nu e o adresa: {a}");
        assert_eq!(a.len(), 62, "adresa trebuie sa aiba 62 de caractere");
        adrese.push(a);
    }
    assert_eq!(
        adrese[0], adrese[1],
        "adresa trebuie sa supravietuiasca repornirii"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn serviciul_ascuns_publica_la_hsdir() {
    // Lantul complet prin procese: releu pornit ca HSDir, serviciu care publica.
    let dir = dir_temp("hs-publicare");

    // Releul, cu samanta de testnet cunoscuta de serviciu.
    let d = dir.join("releu0");
    std::fs::create_dir_all(&d).unwrap();
    let mut s = [0u8; 32];
    s[0] = 1;
    let k = d.join("identitate.key");
    std::fs::write(&k, s).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let addr: SocketAddr = format!("127.0.0.1:{}", port_liber()).parse().unwrap();
    let _releu = Proces(
        Command::new(binar("pqonion-relay"))
            .args([
                "--listen",
                &addr.to_string(),
                "--data-dir",
                d.to_str().unwrap(),
                "--hsdir",
            ])
            .spawn()
            .expect("releul trebuie sa porneasca"),
    );
    assert!(
        asteapta_port(addr, Duration::from_secs(10)),
        "releul nu a pornit"
    );

    let out = Command::new(binar("pqonion-hs"))
        .args([
            "--data-dir",
            dir.join("hs").to_str().unwrap(),
            "--hsdir",
            &addr.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("serviciul trebuie sa porneasca");

    // Ii dam timp sa publice, apoi il oprim si citim ce a raportat.
    let mut p = Proces(out);
    std::thread::sleep(Duration::from_secs(3));
    let mut stderr = p.0.stderr.take().unwrap();
    let _ = p.0.kill();
    let mut err = String::new();
    let _ = stderr.read_to_string(&mut err);

    assert!(
        err.contains("incarcari reusite"),
        "serviciul nu a raportat publicarea: {err}"
    );
    assert!(
        !err.contains("0 incarcari reusite"),
        "nicio publicare nu a reusit: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn conexiune_la_serviciu_ascuns_prin_socks5() {
    // Demonstratia completa: o aplicatie cere o adresa .onion prin SOCKS5 si
    // primeste octetii serviciului. Intre timp trec doua circuite, un HSDir, un
    // punct de introducere, un rendezvous si un tunel criptat.
    let tinta = server_ecou();
    let dir = dir_temp("onion");

    // Trei relee, toate HSDir si puncte de introducere.
    let mut relee = Vec::new();
    let mut adrese = Vec::new();
    for i in 0..3u8 {
        let d = dir.join(format!("releu{i}"));
        std::fs::create_dir_all(&d).unwrap();
        let mut s = [0u8; 32];
        s[0] = i + 1;
        let k = d.join("identitate.key");
        std::fs::write(&k, s).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let addr: SocketAddr = format!("127.0.0.1:{}", port_liber()).parse().unwrap();
        relee.push(Proces(
            Command::new(binar("pqonion-relay"))
                .args([
                    "--listen",
                    &addr.to_string(),
                    "--data-dir",
                    d.to_str().unwrap(),
                    "--hsdir",
                ])
                .spawn()
                .expect("releul trebuie sa porneasca"),
        ));
        assert!(asteapta_port(addr, Duration::from_secs(10)));
        adrese.push(addr);
    }
    let lista: String = adrese
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(",");

    // Serviciul ascuns, care expune serverul de ecou.
    let adresa_onion = String::from_utf8_lossy(
        &Command::new(binar("pqonion-hs"))
            .args([
                "--data-dir",
                dir.join("hs").to_str().unwrap(),
                "--adresa-doar",
            ])
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    assert!(adresa_onion.ends_with(".onion"));

    let _hs = Proces(
        Command::new(binar("pqonion-hs"))
            .args([
                "--data-dir",
                dir.join("hs").to_str().unwrap(),
                "--hsdir",
                &lista,
                "--target",
                &tinta.to_string(),
            ])
            .spawn()
            .expect("serviciul trebuie sa porneasca"),
    );
    // Ii dam timp sa publice si sa deschida punctele de introducere.
    std::thread::sleep(Duration::from_secs(4));

    // Clientul.
    let socks: SocketAddr = format!("127.0.0.1:{}", port_liber()).parse().unwrap();
    let _client = Proces(
        Command::new(binar("pqonion-client"))
            .args([
                "--socks",
                &socks.to_string(),
                "--guard",
                &adrese[0].to_string(),
                "--exit",
                &adrese[1].to_string(),
                "--hsdir",
                &lista,
                "--data-dir",
                dir.join("client").to_str().unwrap(),
            ])
            .spawn()
            .expect("clientul trebuie sa porneasca"),
    );
    assert!(asteapta_port(socks, Duration::from_secs(10)));

    // O aplicatie cere adresa .onion prin SOCKS5.
    let mut app = TcpStream::connect(socks).unwrap();
    app.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut cerere = vec![5u8, 1, 0, 5, 1, 0, 3, adresa_onion.len() as u8];
    cerere.extend_from_slice(adresa_onion.as_bytes());
    cerere.extend_from_slice(&80u16.to_be_bytes());
    app.write_all(&cerere).unwrap();

    let mut metoda = [0u8; 2];
    app.read_exact(&mut metoda).unwrap();
    assert_eq!(metoda, [5, 0]);
    let mut rasp = [0u8; 10];
    app.read_exact(&mut rasp).unwrap();
    assert_eq!(
        rasp[1], 0,
        "SOCKS5 a refuzat conexiunea .onion (cod {})",
        rasp[1]
    );

    let mesaj = b"salut printr-un serviciu ascuns, prin procese reale";
    app.write_all(mesaj).unwrap();
    let mut primit = vec![0u8; mesaj.len()];
    app.read_exact(&mut primit)
        .expect("raspunsul serviciului trebuie sa ajunga inapoi");
    assert_eq!(&primit[..], mesaj, "octetii s-au corupt pe drum");

    drop(relee);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn releul_ajunge_in_consensul_autoritatii() {
    // Testul care lipsea. Doua erori au trecut de suita si au fost prinse abia
    // manual, in testnet:
    //
    //   1. autoritatea si releul foloseau scheme de semnatura diferite la
    //      legatura -> "mesaj de legatura malformat"
    //   2. autoritatea verifica descriptorii cu schema consensului, nu cu cea a
    //      releelor -> "0 relee din 3 descriptori", fara nicio eroare
    //
    // A doua e cea periculoasa: un descriptor care nu se verifica e sarit tacit,
    // deci o nepotrivire de scheme arata identic cu "nu a publicat nimeni".
    let dir = dir_temp("consens");

    // Autoritatea, cu samanta fixa ca releele sa ii poata deriva cheile.
    std::fs::create_dir_all(dir.join("aut")).unwrap();
    let mut s = [0u8; 32];
    s[0] = 0xA0;
    let k = dir.join("aut/autoritate.key");
    std::fs::write(&k, s).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let paut: SocketAddr = format!("127.0.0.1:{}", port_liber()).parse().unwrap();
    let log_aut = dir.join("aut.log");
    let _aut = Proces(
        Command::new(binar("pqonion-dirauth"))
            .args([
                "--data-dir",
                dir.join("aut").to_str().unwrap(),
                "--listen",
                &paut.to_string(),
                // Ciclu scurt, ca testul sa nu astepte o ora.
                "--interval",
                "3",
            ])
            .stderr(Stdio::from(std::fs::File::create(&log_aut).unwrap()))
            .spawn()
            .expect("autoritatea trebuie sa porneasca"),
    );
    assert!(
        asteapta_port(paut, Duration::from_secs(10)),
        "autoritatea nu asculta"
    );

    // Doua relee care se inregistreaza.
    let mut relee = Vec::new();
    for i in 0..2u8 {
        let d = dir.join(format!("releu{i}"));
        std::fs::create_dir_all(&d).unwrap();
        let mut s = [0u8; 32];
        s[0] = i + 1;
        let k = d.join("identitate.key");
        std::fs::write(&k, s).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let addr: SocketAddr = format!("127.0.0.1:{}", port_liber()).parse().unwrap();
        let mut cmd = Command::new(binar("pqonion-relay"));
        cmd.args([
            "--listen",
            &addr.to_string(),
            "--data-dir",
            d.to_str().unwrap(),
            "--dirauth",
            &paut.to_string(),
        ]);
        // Unul dintre ele e releu de iesire, ca sa verificam si flag-ul Exit.
        if i == 1 {
            cmd.args(["--exit-ports", "80,443"]);
        }
        relee.push(Proces(cmd.spawn().expect("releul trebuie sa porneasca")));
        assert!(asteapta_port(addr, Duration::from_secs(10)));
    }

    // Asteptam un ciclu de vot care sa contina ambele relee.
    let mut gasit = 0usize;
    for _ in 0..80 {
        if let Ok(t) = std::fs::read_to_string(&log_aut) {
            for l in t.lines() {
                if let Some(rest) = l.split("consens: ").nth(1) {
                    if let Some(n) = rest.split(' ').next().and_then(|x| x.parse::<usize>().ok()) {
                        gasit = gasit.max(n);
                    }
                }
            }
        }
        if gasit >= 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let log = std::fs::read_to_string(&log_aut).unwrap_or_default();
    assert!(
        gasit >= 2,
        "releele nu au ajuns in consens (max {gasit}). Log:\n{log}"
    );

    // Consensul scris trebuie sa fie coerent: doua relee, unul cu flag Exit.
    let doc = std::fs::read_to_string(dir.join("aut/consens.txt")).expect("consens scris");
    let r: Vec<&str> = doc.lines().filter(|l| l.starts_with("r ")).collect();
    assert_eq!(r.len(), 2, "consensul trebuie sa contina ambele relee");
    assert_eq!(
        r.iter().filter(|l| l.contains(" Exit")).count(),
        1,
        "exact un releu are politica de iesire"
    );
    assert!(
        doc.contains("authority-signature"),
        "consensul trebuie semnat"
    );

    drop(relee);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn consola_web_raspunde() {
    let dir = dir_temp("consola");
    let port = port_liber();
    let pc = port_liber();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let caddr: SocketAddr = format!("127.0.0.1:{pc}").parse().unwrap();

    let _p = Proces(
        Command::new(binar("pqonion-relay"))
            .args([
                "--listen",
                &addr.to_string(),
                "--data-dir",
                dir.to_str().unwrap(),
                "--consola",
                &caddr.to_string(),
            ])
            .spawn()
            .expect("releul trebuie sa porneasca"),
    );
    assert!(asteapta_port(addr, Duration::from_secs(10)));
    assert!(
        asteapta_port(caddr, Duration::from_secs(10)),
        "consola nu asculta"
    );

    let cere = |brut: &str| {
        let mut s = TcpStream::connect(caddr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(brut.as_bytes()).unwrap();
        citeste_http(&mut s, true)
    };

    // Pagina.
    let t = cere("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(
        t.starts_with("HTTP/1.1 200"),
        "pagina: {}",
        &t[..40.min(t.len())]
    );
    assert!(t.contains("releu pqonion"), "pagina incompleta sau alta");

    // Starea, ca JSON.
    let t = cere("GET /stare HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(t.starts_with("HTTP/1.1 200"));
    assert!(t.contains("\"circuite_active\""));
    assert!(
        !t.contains("peer") && !t.contains("circ_id"),
        "consola nu are voie sa expuna identificatori"
    );

    // Doar de citit.
    let t = cere("POST /stare HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
    assert!(t.starts_with("HTTP/1.1 405"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn releul_publica_adresa_data_nu_pe_cea_pe_care_asculta() {
    // In container, releul asculta pe 0.0.0.0 dar trebuie sa anunte adresa pe
    // care il vad ceilalti. Fara `--adresa-publica` ar publica 0.0.0.0 si nimeni
    // nu l-ar putea contacta — o greseala care pe localhost nu se vede, pentru
    // ca acolo toti sunt pe aceeasi masina.
    let dir = dir_temp("adresa-publica");
    let port = port_liber();

    let mut p = Proces(
        Command::new(binar("pqonion-relay"))
            .args([
                "--listen",
                &format!("0.0.0.0:{port}"),
                "--data-dir",
                dir.to_str().unwrap(),
                "--dirauth",
                // Autoritate inexistenta: ne intereseaza doar avertismentul.
                "127.0.0.1:1",
            ])
            .stderr(Stdio::piped())
            .spawn()
            .expect("releul trebuie sa porneasca"),
    );
    assert!(asteapta_port(
        format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(10)
    ));
    let text = stderr_pana(&mut p.0, "gata", Duration::from_secs(10));
    assert!(
        text.contains("publici adresa 0.0.0.0"),
        "releul trebuie sa avertizeze ca adresa publicata e inutilizabila:\n{text}"
    );

    // Cu `--adresa-publica`, fara avertisment.
    let port2 = port_liber();
    let mut p2 = Proces(
        Command::new(binar("pqonion-relay"))
            .args([
                "--listen",
                &format!("0.0.0.0:{port2}"),
                "--adresa-publica",
                "10.42.0.11",
                "--data-dir",
                dir.to_str().unwrap(),
                "--dirauth",
                "127.0.0.1:1",
            ])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    assert!(asteapta_port(
        format!("127.0.0.1:{port2}").parse().unwrap(),
        Duration::from_secs(10)
    ));
    let text = stderr_pana(&mut p2.0, "gata", Duration::from_secs(10));
    assert!(!text.contains("publici adresa 0.0.0.0"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forma_cu_egal_chiar_ia_efect() {
    // Testul trebuie sa verifice **efectul** optiunii, nu doar ca procesul
    // raspunde la ea. Prima versiune compara doar codurile de iesire pentru un
    // argument invalid — si trecea si cu parserul stricat, pentru ca ambele
    // forme esuau, doar din motive diferite.
    //
    // Aici pornim un releu cu `--listen=ADRESA` si verificam ca asculta chiar
    // acolo. Cu parserul vechi, `--listen=X` devenea un flag numit `listen=X`,
    // deci releul ar fi pornit pe portul implicit sau ar fi refuzat sa porneasca.
    let dir = dir_temp("forma-egal");
    let port = port_liber();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let _p = Proces(
        Command::new(binar("pqonion-relay"))
            .args([
                &format!("--listen={addr}"),
                &format!("--data-dir={}", dir.to_str().unwrap()),
            ])
            .spawn()
            .expect("releul trebuie sa porneasca"),
    );
    assert!(
        asteapta_port(addr, Duration::from_secs(10)),
        "releul nu asculta pe adresa data cu --listen=ADRESA"
    );

    let _ = std::fs::remove_dir_all(&dir);
}


#[test]
fn optiunile_necunoscute_opresc_pornirea() {
    for binar_nume in ["pqonion-relay", "pqonion-dirauth", "pqonion-client", "pqonion-hs"] {
        let out = Command::new(binar(binar_nume))
            .args(["--optiune-inexistenta=5"])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "{binar_nume}: o optiune necunoscuta nu are voie sa fie ignorata"
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("optiune-inexistenta"),
            "{binar_nume}: eroarea trebuie sa spuna care optiune: {err}"
        );
    }
}

