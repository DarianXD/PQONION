//! Consola web a releului.
//!
//! O pagina si un punct JSON, servite pe un port **local**. Utile ca sa vezi
//! dintr-o privire ca releul functioneaza.
//!
//! # Ce arata si de ce atat
//!
//! Doar agregate: circuite active, celule pe secunda, canale, cereri de
//! director. Niciun identificator de circuit, nicio adresa de peer, niciun
//! fingerprint de client.
//!
//! Regula e aceeasi ca la logging si la metrici: orice afiseaza consola e
//! informatie pe care ar avea-o si cineva care iti ia serverul. O consola care ar
//! lista circuitele active cu peer-ii lor ar fi, in fapt, un jurnal de corelatie
//! cu interfata grafica.
//!
//! # De ce implicit pe localhost
//!
//! Consola nu are autentificare. Legata pe o adresa publica, ar spune oricui cat
//! trafic duce releul si cate circuite are — informatie utila pentru cineva care
//! incearca sa aleaga ce releu sa atace sau sa observe. Cine vrea sa o expuna
//! trebuie sa o faca explicit, si sa puna ceva in fata.

use std::sync::Arc;

use pqo_relay_io::Metrici;
use pqo_shop::http::{self, EroareHttp, Metoda, Raspuns};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Ce stie consola despre releul pe care il descrie.
#[derive(Debug, Clone)]
pub struct Identitate {
    pub fingerprint: String,
    pub adresa: String,
    pub e_exit: bool,
    pub e_hsdir: bool,
    pub post_cuantic: bool,
    pub schema_kem: &'static str,
    pub schema_sig: &'static str,
}

/// Porneste consola. Intoarce adresa pe care asculta.
pub async fn porneste(
    listen: std::net::SocketAddr,
    id: Identitate,
    metrici: Arc<Metrici>,
) -> std::io::Result<std::net::SocketAddr> {
    let l = TcpListener::bind(listen).await?;
    let addr = l.local_addr()?;
    tokio::spawn(async move {
        while let Ok((sock, _)) = l.accept().await {
            let id = id.clone();
            let m = Arc::clone(&metrici);
            tokio::spawn(async move { deserveste(sock, id, m).await });
        }
    });
    Ok(addr)
}

async fn deserveste(mut sock: TcpStream, id: Identitate, metrici: Arc<Metrici>) {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 4096];

    loop {
        let (cerere, consumat) = match http::parseaza(&buf) {
            Ok(v) => v,
            Err(EroareHttp::Incomplet) => {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    sock.read(&mut chunk),
                )
                .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
                    Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                }
                continue;
            }
            Err(_) => {
                let _ = sock
                    .write_all(&Raspuns::nou(400).text("cerere malformata").encode(false))
                    .await;
                return;
            }
        };

        let doar_antete = cerere.metoda == Metoda::Head;
        let r = raspunde(&cerere, &id, &metrici);
        if sock.write_all(&r.encode(doar_antete)).await.is_err() {
            return;
        }
        buf.drain(..consumat);
    }
}

/// Produce raspunsul pentru o cerere.
///
/// Functie pura, ca sa poata fi testata fara socket-uri — acelasi tipar ca in
/// restul proiectului.
pub fn raspunde(c: &http::Cerere, id: &Identitate, metrici: &Metrici) -> Raspuns {
    if !matches!(c.metoda, Metoda::Get | Metoda::Head) {
        return Raspuns::nou(405)
            .cu_antet("Allow", "GET, HEAD")
            .text("consola e doar de citit");
    }
    match c.cale.as_str() {
        "/" => Raspuns::nou(200)
            .cu_antet("Content-Type", "text/html; charset=utf-8")
            .cu_antet("Cache-Control", "no-store")
            .corp_brut(pagina(id).into_bytes()),
        "/stare" => {
            let i = metrici.instantaneu();
            Raspuns::nou(200)
                .cu_antet("Cache-Control", "no-store")
                .json(serde_json::json!({
                    "fingerprint": id.fingerprint,
                    "adresa": id.adresa,
                    "exit": id.e_exit,
                    "hsdir": id.e_hsdir,
                    "post_cuantic": id.post_cuantic,
                    "kem": id.schema_kem,
                    "semnatura": id.schema_sig,
                    "secunde_de_la_pornire": i.secunde_de_la_pornire,
                    "circuite_create": i.circuite_create,
                    "circuite_active": i.circuite_active,
                    "canale_active": i.canale_active,
                    "celule": i.celule,
                    "celule_pe_secunda": (i.celule_pe_secunda() * 100.0).round() / 100.0,
                    "streamuri": i.streamuri,
                    "cereri_director": i.cereri_director,
                    "handshake_esuate": i.handshake_esuate,
                }))
        }
        _ => Raspuns::nou(404).text("nu exista"),
    }
}

/// Pagina, cu tot ce trebuie inclus.
///
/// Fara fisiere separate si fara resurse externe: un releu care ar descarca CSS
/// de pe internet ar spune fiecarui vizitator al consolei cine gazduieste
/// serverul respectiv.
fn pagina(id: &Identitate) -> String {
    let avertisment = if id.post_cuantic {
        ""
    } else {
        "<p class=\"rau\">Compilat FARA feature-ul 'pq': criptografia NU e post-cuantica.</p>"
    };
    // Construite inainte, nu in argumentele lui `format!`: un `format!` imbricat
    // aloca de doua ori si e mai greu de citit.
    let mut roluri = String::new();
    if id.e_exit {
        roluri.push_str("<span class=\"eticheta-rol\">exit</span>");
    }
    if id.e_hsdir {
        roluri.push_str("<span class=\"eticheta-rol\">hsdir</span>");
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>releu pqonion</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font: 15px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
         background: #14161a; color: #d8dee9; margin: 0; padding: 2rem; }}
  h1 {{ font-size: 1.1rem; letter-spacing: .04em; color: #88c0d0; margin: 0 0 .3rem; }}
  .fp {{ font-size: .75rem; color: #6b7280; word-break: break-all; margin-bottom: 1.6rem; }}
  .grid {{ display: grid; gap: .8rem;
          grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); max-width: 900px; }}
  .card {{ background: #1c1f26; border: 1px solid #2b303b; border-radius: 6px; padding: .9rem 1rem; }}
  .eticheta {{ font-size: .7rem; text-transform: uppercase; letter-spacing: .08em; color: #6b7280; }}
  .val {{ font-size: 1.6rem; color: #a3be8c; margin-top: .2rem; }}
  .roluri {{ margin: 1.6rem 0 0; max-width: 900px; }}
  .eticheta-rol {{ display: inline-block; padding: .15rem .5rem; margin-right: .4rem;
                  border-radius: 3px; font-size: .72rem; background: #2b303b; color: #88c0d0; }}
  .rau {{ color: #bf616a; margin-top: 1.2rem; }}
  .nota {{ color: #6b7280; font-size: .75rem; margin-top: 2rem; max-width: 640px; }}
</style>
</head>
<body>
<h1>releu pqonion</h1>
<div class="fp">{fp}<br>{adresa}</div>

<div class="grid">
  <div class="card"><div class="eticheta">circuite active</div><div class="val" id="circuite_active">-</div></div>
  <div class="card"><div class="eticheta">canale active</div><div class="val" id="canale_active">-</div></div>
  <div class="card"><div class="eticheta">celule / s</div><div class="val" id="celule_pe_secunda">-</div></div>
  <div class="card"><div class="eticheta">celule total</div><div class="val" id="celule">-</div></div>
  <div class="card"><div class="eticheta">circuite create</div><div class="val" id="circuite_create">-</div></div>
  <div class="card"><div class="eticheta">cereri director</div><div class="val" id="cereri_director">-</div></div>
  <div class="card"><div class="eticheta">handshake esuate</div><div class="val" id="handshake_esuate">-</div></div>
  <div class="card"><div class="eticheta">de la pornire</div><div class="val" id="uptime">-</div></div>
</div>

<div class="roluri">
  <span class="eticheta-rol">{kem}</span>
  <span class="eticheta-rol">{sig}</span>
  {roluri}
</div>
{avertisment}

<p class="nota">
Consola arata doar valori agregate pe intreg releul. Nu exista nicaieri
un contor per circuit sau per peer: ce nu se masoara nu se poate scurge.
</p>

<script>
function durata(s) {{
  const z = n => String(n).padStart(2, '0');
  return Math.floor(s / 3600) + ':' + z(Math.floor(s / 60) % 60) + ':' + z(s % 60);
}}
async function reimprospateaza() {{
  try {{
    const r = await fetch('/stare', {{ cache: 'no-store' }});
    const d = await r.json();
    for (const k of ['circuite_active','canale_active','celule','celule_pe_secunda',
                     'circuite_create','cereri_director','handshake_esuate']) {{
      document.getElementById(k).textContent = d[k];
    }}
    document.getElementById('uptime').textContent = durata(d.secunde_de_la_pornire);
  }} catch (e) {{ /* releul s-a oprit; incercam din nou */ }}
}}
reimprospateaza();
setInterval(reimprospateaza, 1000);
</script>
</body>
</html>
"#,
        fp = id.fingerprint,
        adresa = id.adresa,
        kem = id.schema_kem,
        sig = id.schema_sig,
        roluri = roluri,
        avertisment = avertisment,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqo_shop::http::parseaza;

    fn id() -> Identitate {
        Identitate {
            fingerprint: "AABB".into(),
            adresa: "127.0.0.1:9001".into(),
            e_exit: true,
            e_hsdir: false,
            post_cuantic: true,
            schema_kem: "Hybrid",
            schema_sig: "hybrid",
        }
    }

    fn cere(text: &str) -> http::Cerere {
        parseaza(text.as_bytes()).unwrap().0
    }

    #[test]
    fn pagina_se_serveste() {
        let r = raspunde(&cere("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), &id(), &Metrici::new());
        assert_eq!(r.stare, 200);
        let corp = String::from_utf8(r.corp).unwrap();
        assert!(corp.starts_with("<!DOCTYPE html>"));
        assert!(corp.contains("AABB"));
        assert!(corp.contains("exit"));
    }

    #[test]
    fn starea_e_json_cu_agregate() {
        let m = Metrici::new();
        m.circuit_creat();
        m.circuit_creat();
        m.canal_deschis();
        for _ in 0..5 {
            m.celula();
        }
        let r = raspunde(&cere("GET /stare HTTP/1.1\r\nHost: x\r\n\r\n"), &id(), &m);
        assert_eq!(r.stare, 200);
        let v: serde_json::Value = serde_json::from_slice(&r.corp).unwrap();
        assert_eq!(v["circuite_create"], 2);
        assert_eq!(v["circuite_active"], 2);
        assert_eq!(v["canale_active"], 1);
        assert_eq!(v["celule"], 5);
        assert_eq!(v["exit"], true);
    }

    #[test]
    fn starea_nu_contine_identificatori_de_circuit() {
        // Testul care apara politica. Daca cineva adauga un camp cu adrese de
        // peer sau numere de circuit, aici se vede.
        let r = raspunde(&cere("GET /stare HTTP/1.1\r\nHost: x\r\n\r\n"), &id(), &Metrici::new());
        let v: serde_json::Value = serde_json::from_slice(&r.corp).unwrap();
        let chei: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        let permise = [
            "fingerprint", "adresa", "exit", "hsdir", "post_cuantic", "kem", "semnatura",
            "secunde_de_la_pornire", "circuite_create", "circuite_active", "canale_active",
            "celule", "celule_pe_secunda", "streamuri", "cereri_director", "handshake_esuate",
        ];
        for k in &chei {
            assert!(
                permise.contains(k),
                "camp nou in consola: {k}. Daca poarta informatie despre un \
                 circuit sau un peer anume, nu are ce cauta aici."
            );
        }
    }

    #[test]
    fn consola_e_doar_de_citit() {
        for m in ["POST", "PUT", "DELETE"] {
            let r = raspunde(
                &cere(&format!("{m} /stare HTTP/1.1\r\nHost: x\r\n\r\n")),
                &id(),
                &Metrici::new(),
            );
            assert_eq!(r.stare, 405, "{m} ar trebui refuzat");
        }
    }

    #[test]
    fn calea_necunoscuta_da_404() {
        let r = raspunde(
            &cere("GET /altceva HTTP/1.1\r\nHost: x\r\n\r\n"),
            &id(),
            &Metrici::new(),
        );
        assert_eq!(r.stare, 404);
    }

    #[test]
    fn avertismentul_apare_doar_fara_pq() {
        let mut i = id();
        i.post_cuantic = false;
        let r = raspunde(&cere("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), &i, &Metrici::new());
        assert!(String::from_utf8(r.corp).unwrap().contains("NU e post-cuantica"));

        let r = raspunde(&cere("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), &id(), &Metrici::new());
        assert!(!String::from_utf8(r.corp).unwrap().contains("NU e post-cuantica"));
    }

    #[test]
    fn pagina_nu_incarca_resurse_externe() {
        // Un releu care ar descarca CSS de pe internet ar spune fiecarui
        // vizitator al consolei cine gazduieste serverul.
        let corp = pagina(&id());
        for rea in ["http://", "https://", "//cdn", "<link"] {
            assert!(!corp.contains(rea), "resursa externa: {rea}");
        }
    }
}
