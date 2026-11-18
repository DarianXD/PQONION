//! Stratul REST.
//!
//! O functie pura: `(&mut Magazin, &Cerere) -> Raspuns`. Nu deschide socket-uri,
//! deci toata semantica — coduri de stare, conditii, legaturi — se testeaza fara
//! retea. Aceeasi arhitectura ca in restul proiectului.
//!
//! # Ce face acest API sa fie REST si nu doar JSON peste HTTP
//!
//! **Resurse, nu actiuni.** Nu exista `/adaugaInCos`. Exista un cos, iar
//! articolele lui sunt resurse pe care le pui si le stergi. Verbul e in metoda
//! HTTP, nu in cale.
//!
//! **Metodele isi respecta contractul.** `GET` nu schimba nimic. `PUT` e
//! idempotent: aceeasi cerere de doua ori are acelasi efect ca o data — de aceea
//! fixeaza cantitatea, nu o incrementeaza. `DELETE` pe ceva inexistent nu e
//! eroare. Doar `POST` creeaza resurse noi cu identificator ales de server.
//!
//! **Codurile de stare poarta informatie.** 201 cu `Location` cand se creeaza
//! ceva, 204 cand nu e nimic de intors, 409 cand cererea e valida dar starea nu
//! permite, 412 cand conditia clientului nu mai e adevarata.
//!
//! **Reprezentarile poarta legaturi.** Un client care primeste un cos afla din
//! el unde poate plasa comanda, fara sa aiba caile compilate in cod. Asta e
//! partea din REST pe care majoritatea API-urilor o omit.
//!
//! **Concurenta e explicita.** `ETag` pe cos, `If-Match` obligatoriu la
//! modificare. Doi clienti nu se pot suprascrie tacit.

use serde::Serialize;

use crate::http::{Cerere, Metoda, Raspuns};
use crate::model::{Categorie, Comanda, Cos, EroareDomeniu, Magazin, Produs};

/// Cate produse intorc implicit pe pagina.
pub const PER_PAGINA_IMPLICIT: usize = 20;
/// Cate produse cel mult pe pagina.
pub const PER_PAGINA_MAXIM: usize = 100;

/// O legatura catre alta resursa.
#[derive(Debug, Serialize)]
pub struct Legatura {
    pub href: String,
    /// Metodele permise pe ea.
    pub metode: Vec<&'static str>,
}

fn leg(href: impl Into<String>, metode: &[&'static str]) -> Legatura {
    Legatura {
        href: href.into(),
        metode: metode.to_vec(),
    }
}

/// Corpul unei erori.
///
/// Format inspirat din RFC 9457 (`application/problem+json`): un tip, un titlu
/// citibil, si detalii. Un client poate ramifica pe `tip` fara sa parseze text.
#[derive(Debug, Serialize)]
struct Problema {
    tip: &'static str,
    titlu: &'static str,
    detaliu: String,
}

fn problema(stare: u16, tip: &'static str, titlu: &'static str, detaliu: String) -> Raspuns {
    Raspuns::nou(stare)
        .json(Problema {
            tip,
            titlu,
            detaliu,
        })
        .cu_antet("Content-Type", "application/problem+json; charset=utf-8")
}

/// Traduce o eroare de domeniu intr-un raspuns HTTP.
///
/// Aici, si nicaieri altundeva: modelul nu stie ce e un cod de stare.
fn din_domeniu(e: EroareDomeniu) -> Raspuns {
    use EroareDomeniu::*;
    let detaliu = e.to_string();
    match e {
        ProdusNecunoscut(_) | CosNecunoscut(_) | ComandaNecunoscuta(_) => {
            problema(404, "resursa-inexistenta", "Resursa nu exista", detaliu)
        }
        // 409, nu 400: cererea e valida, dar starea serverului nu o permite acum.
        // Un client poate reincerca mai tarziu si poate reusi.
        StocInsuficient { .. } => problema(409, "stoc-insuficient", "Stoc insuficient", detaliu),
        CosPlin => problema(409, "cos-plin", "Cosul e plin", detaliu),
        CosGol => problema(409, "cos-gol", "Cosul e gol", detaliu),
        // 422, nu 400: sintaxa e corecta, continutul nu.
        CantitateInvalida(_) => problema(422, "cantitate-invalida", "Cantitate invalida", detaliu),
        ConflictDeRevizie { .. } => problema(
            412,
            "revizie-depasita",
            "Resursa a fost modificata intre timp",
            detaliu,
        ),
    }
}

// ---------------------------------------------------------------------------
// Reprezentari
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ProdusRepr<'a> {
    #[serde(flatten)]
    produs: &'a Produs,
    legaturi: Vec<(&'static str, Legatura)>,
}

#[derive(Debug, Serialize)]
struct Colectie<T> {
    elemente: Vec<T>,
    total: usize,
    offset: usize,
    limita: usize,
    legaturi: Vec<(&'static str, Legatura)>,
}

#[derive(Debug, Serialize)]
struct CosRepr<'a> {
    #[serde(flatten)]
    cos: &'a Cos,
    legaturi: Vec<(&'static str, Legatura)>,
}

#[derive(Debug, Serialize)]
struct ComandaRepr<'a> {
    #[serde(flatten)]
    comanda: &'a Comanda,
    legaturi: Vec<(&'static str, Legatura)>,
}

#[derive(Debug, Serialize)]
struct Radacina {
    serviciu: &'static str,
    versiune: &'static str,
    legaturi: Vec<(&'static str, Legatura)>,
}

fn etag(revizie: u64) -> String {
    format!("\"{revizie}\"")
}

/// Extrage revizia dintr-un `If-Match`.
///
/// Acceptam doar forma exacta: `*` nu e suportat, pentru ca ar insemna „orice
/// revizie", adica exact protectia pe care o cerem.
fn revizie_din_if_match(v: &str) -> Option<u64> {
    v.trim().trim_matches('"').parse().ok()
}

// ---------------------------------------------------------------------------
// Rutare
// ---------------------------------------------------------------------------

/// Trateaza o cerere.
pub fn trateaza(m: &mut Magazin, c: &Cerere) -> Raspuns {
    let seg = c.segmente();
    let r = match seg.as_slice() {
        [] => radacina(c),
        ["produse"] => lista_produse(m, c),
        ["produse", id] => un_produs(m, c, id),
        ["cosuri"] => cosuri(m, c),
        ["cosuri", id] => un_cos(m, c, id),
        ["cosuri", id, "articole", produs] => articol(m, c, id, produs),
        ["comenzi"] => comenzi(m, c),
        ["comenzi", id] => o_comanda(m, c, id),
        _ => problema(
            404,
            "resursa-inexistenta",
            "Resursa nu exista",
            format!("nu exista {}", c.cale),
        ),
    };
    // `HEAD` produce acelasi raspuns ca `GET`, iar corpul se taie la serializare.
    // Asa antetele raman identice, ceea ce e chiar rostul lui `HEAD`.
    r
}

fn metoda_nepermisa(permise: &[&str]) -> Raspuns {
    problema(
        405,
        "metoda-nepermisa",
        "Metoda nu e permisa pe aceasta resursa",
        format!("permise: {}", permise.join(", ")),
    )
    .cu_antet("Allow", permise.join(", "))
}

fn radacina(c: &Cerere) -> Raspuns {
    match c.metoda {
        Metoda::Get | Metoda::Head => Raspuns::nou(200).json(Radacina {
            serviciu: "magazin de jucarii",
            versiune: "1",
            legaturi: vec![
                ("produse", leg("/produse", &["GET"])),
                ("cosuri", leg("/cosuri", &["POST"])),
                ("comenzi", leg("/comenzi", &["POST"])),
            ],
        }),
        Metoda::Options => Raspuns::nou(204).cu_antet("Allow", "GET, HEAD, OPTIONS"),
        _ => metoda_nepermisa(&["GET", "HEAD", "OPTIONS"]),
    }
}

fn lista_produse(m: &Magazin, c: &Cerere) -> Raspuns {
    if !matches!(c.metoda, Metoda::Get | Metoda::Head | Metoda::Options) {
        return metoda_nepermisa(&["GET", "HEAD", "OPTIONS"]);
    }
    if c.metoda == Metoda::Options {
        return Raspuns::nou(204).cu_antet("Allow", "GET, HEAD, OPTIONS");
    }

    let categorie = match c.parametru("categorie") {
        Some(t) => match Categorie::din_text(t) {
            Some(cat) => Some(cat),
            None => {
                return problema(
                    422,
                    "categorie-necunoscuta",
                    "Categorie necunoscuta",
                    format!("categoria {t} nu exista"),
                )
            }
        },
        None => None,
    };
    let doar_in_stoc = c.parametru("in_stoc").map(|v| v == "1" || v == "true") == Some(true);

    let offset: usize = c.parametru("offset").and_then(|v| v.parse().ok()).unwrap_or(0);
    let limita: usize = c
        .parametru("limita")
        .and_then(|v| v.parse().ok())
        .unwrap_or(PER_PAGINA_IMPLICIT)
        .clamp(1, PER_PAGINA_MAXIM);

    let (pagina, total) = m.produse(categorie, doar_in_stoc, offset, limita);
    let elemente: Vec<ProdusRepr> = pagina
        .into_iter()
        .map(|p| ProdusRepr {
            produs: p,
            legaturi: vec![("sine", leg(format!("/produse/{}", p.id), &["GET"]))],
        })
        .collect();

    // Legaturi de paginare, ca sa nu trebuiasca clientul sa construiasca URL-uri.
    let mut legaturi = vec![("sine", leg(cale_paginata(c, offset, limita), &["GET"]))];
    if offset + limita < total {
        legaturi.push((
            "urmatoarea",
            leg(cale_paginata(c, offset + limita, limita), &["GET"]),
        ));
    }
    if offset > 0 {
        legaturi.push((
            "precedenta",
            leg(
                cale_paginata(c, offset.saturating_sub(limita), limita),
                &["GET"],
            ),
        ));
    }

    Raspuns::nou(200).json(Colectie {
        elemente,
        total,
        offset,
        limita,
        legaturi,
    })
}

fn cale_paginata(c: &Cerere, offset: usize, limita: usize) -> String {
    let mut q: Vec<String> = c
        .interogare
        .iter()
        .filter(|(k, _)| k.as_str() != "offset" && k.as_str() != "limita")
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    q.push(format!("offset={offset}"));
    q.push(format!("limita={limita}"));
    format!("/produse?{}", q.join("&"))
}

fn un_produs(m: &Magazin, c: &Cerere, id: &str) -> Raspuns {
    if !matches!(c.metoda, Metoda::Get | Metoda::Head | Metoda::Options) {
        return metoda_nepermisa(&["GET", "HEAD", "OPTIONS"]);
    }
    if c.metoda == Metoda::Options {
        return Raspuns::nou(204).cu_antet("Allow", "GET, HEAD, OPTIONS");
    }
    match m.produs(id) {
        Some(p) => Raspuns::nou(200).json(ProdusRepr {
            produs: p,
            legaturi: vec![("colectie", leg("/produse", &["GET"]))],
        }),
        None => din_domeniu(EroareDomeniu::ProdusNecunoscut(id.to_string())),
    }
}

fn cosuri(m: &mut Magazin, c: &Cerere) -> Raspuns {
    match c.metoda {
        // `POST` pentru ca serverul alege identificatorul. Daca l-ar alege
        // clientul, ar fi `PUT` pe o cale cunoscuta.
        Metoda::Post => {
            let id = m.cos_nou();
            let cos = m.cos(&id).expect("tocmai creat");
            Raspuns::nou(201)
                .cu_antet("Location", format!("/cosuri/{id}"))
                .cu_antet("ETag", etag(cos.revizie))
                .json(CosRepr {
                    cos,
                    legaturi: legaturi_cos(&id),
                })
        }
        Metoda::Options => Raspuns::nou(204).cu_antet("Allow", "POST, OPTIONS"),
        _ => metoda_nepermisa(&["POST", "OPTIONS"]),
    }
}

fn legaturi_cos(id: &str) -> Vec<(&'static str, Legatura)> {
    vec![
        ("sine", leg(format!("/cosuri/{id}"), &["GET"])),
        (
            "articole",
            leg(format!("/cosuri/{id}/articole/{{produs}}"), &["PUT", "DELETE"]),
        ),
        ("plaseaza-comanda", leg("/comenzi", &["POST"])),
    ]
}

fn un_cos(m: &Magazin, c: &Cerere, id: &str) -> Raspuns {
    if !matches!(c.metoda, Metoda::Get | Metoda::Head | Metoda::Options) {
        return metoda_nepermisa(&["GET", "HEAD", "OPTIONS"]);
    }
    if c.metoda == Metoda::Options {
        return Raspuns::nou(204).cu_antet("Allow", "GET, HEAD, OPTIONS");
    }
    let Some(cos) = m.cos(id) else {
        return din_domeniu(EroareDomeniu::CosNecunoscut(id.to_string()));
    };
    let et = etag(cos.revizie);

    // Cache conditionat: daca clientul are deja versiunea, nu retrimitem corpul.
    if let Some(inm) = c.antet("if-none-match") {
        if inm.trim() == et {
            return Raspuns::nou(304).cu_antet("ETag", et);
        }
    }
    Raspuns::nou(200).cu_antet("ETag", et).json(CosRepr {
        cos,
        legaturi: legaturi_cos(id),
    })
}

fn articol(m: &mut Magazin, c: &Cerere, cos_id: &str, produs_id: &str) -> Raspuns {
    match c.metoda {
        Metoda::Options => {
            return Raspuns::nou(204).cu_antet("Allow", "PUT, DELETE, OPTIONS")
        }
        Metoda::Put | Metoda::Delete => {}
        _ => return metoda_nepermisa(&["PUT", "DELETE", "OPTIONS"]),
    }

    // `If-Match` obligatoriu la modificare. 428 e codul potrivit: cererea ar
    // putea reusi, dar clientul trebuie sa spuna pe ce versiune se bazeaza.
    // Fara el, doi clienti s-ar suprascrie tacit.
    let Some(im) = c.antet("if-match") else {
        return problema(
            428,
            "conditie-necesara",
            "Antetul If-Match e obligatoriu",
            "obtine ETag-ul cu GET pe cos si trimite-l ca If-Match".into(),
        );
    };
    let Some(revizie) = revizie_din_if_match(im) else {
        return problema(
            400,
            "if-match-invalid",
            "If-Match nu e o revizie valida",
            format!("nu inteleg {im}"),
        );
    };

    if c.metoda == Metoda::Delete {
        return match m.scoate_articol(cos_id, produs_id, Some(revizie)) {
            Ok(()) => {
                let r = m.cos(cos_id).map_or(revizie, |c| c.revizie);
                Raspuns::nou(204).cu_antet("ETag", etag(r))
            }
            Err(e) => din_domeniu(e),
        };
    }

    // PUT: corpul spune ce cantitate vrem.
    if let Some(ct) = c.antet("content-type") {
        if !ct.starts_with("application/json") {
            return problema(
                415,
                "tip-nesuportat",
                "Tip de continut nesuportat",
                "trimite application/json".into(),
            );
        }
    }
    #[derive(serde::Deserialize)]
    struct Corp {
        cantitate: u32,
    }
    let corp: Corp = match serde_json::from_slice(&c.corp) {
        Ok(v) => v,
        Err(e) => {
            return problema(
                400,
                "corp-invalid",
                "Corpul nu e JSON valid",
                e.to_string(),
            )
        }
    };

    match m.seteaza_cantitate(cos_id, produs_id, corp.cantitate, Some(revizie)) {
        Ok(cos) => {
            let et = etag(cos.revizie);
            Raspuns::nou(200).cu_antet("ETag", et).json(CosRepr {
                cos,
                legaturi: legaturi_cos(cos_id),
            })
        }
        Err(e) => din_domeniu(e),
    }
}

fn comenzi(m: &mut Magazin, c: &Cerere) -> Raspuns {
    match c.metoda {
        Metoda::Options => return Raspuns::nou(204).cu_antet("Allow", "POST, OPTIONS"),
        Metoda::Post => {}
        _ => return metoda_nepermisa(&["POST", "OPTIONS"]),
    }

    #[derive(serde::Deserialize)]
    struct Corp {
        cos: String,
    }
    let corp: Corp = match serde_json::from_slice(&c.corp) {
        Ok(v) => v,
        Err(e) => {
            return problema(
                400,
                "corp-invalid",
                "Corpul nu e JSON valid",
                e.to_string(),
            )
        }
    };

    match m.plaseaza_comanda(&corp.cos) {
        Ok(cmd) => {
            let id = cmd.id.clone();
            Raspuns::nou(201)
                .cu_antet("Location", format!("/comenzi/{id}"))
                .json(ComandaRepr {
                    comanda: cmd,
                    legaturi: vec![("sine", leg(format!("/comenzi/{id}"), &["GET"]))],
                })
        }
        Err(e) => din_domeniu(e),
    }
}

fn o_comanda(m: &Magazin, c: &Cerere, id: &str) -> Raspuns {
    if !matches!(c.metoda, Metoda::Get | Metoda::Head | Metoda::Options) {
        return metoda_nepermisa(&["GET", "HEAD", "OPTIONS"]);
    }
    if c.metoda == Metoda::Options {
        return Raspuns::nou(204).cu_antet("Allow", "GET, HEAD, OPTIONS");
    }
    match m.comanda(id) {
        Some(cmd) => Raspuns::nou(200).json(ComandaRepr {
            comanda: cmd,
            legaturi: vec![("produse", leg("/produse", &["GET"]))],
        }),
        None => din_domeniu(EroareDomeniu::ComandaNecunoscuta(id.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::parseaza;

    fn cer(text: &str) -> Cerere {
        parseaza(text.as_bytes()).expect("cerere valida").0
    }

    fn get(cale: &str) -> Cerere {
        cer(&format!("GET {cale} HTTP/1.1\r\nHost: x\r\n\r\n"))
    }

    fn cu_corp(metoda: &str, cale: &str, antete: &str, corp: &str) -> Cerere {
        cer(&format!(
            "{metoda} {cale} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n{antete}Content-Length: {}\r\n\r\n{corp}",
            corp.len()
        ))
    }

    fn json(r: &Raspuns) -> serde_json::Value {
        serde_json::from_slice(&r.corp).expect("corp JSON")
    }

    fn antet<'a>(r: &'a Raspuns, nume: &str) -> Option<&'a str> {
        r.antete
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(nume))
            .map(|(_, v)| v.as_str())
    }

    /// Creeaza un cos si intoarce (id, etag).
    fn cos_nou(m: &mut Magazin) -> (String, String) {
        let r = trateaza(m, &cer("POST /cosuri HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert_eq!(r.stare, 201);
        let loc = antet(&r, "Location").unwrap().to_string();
        let et = antet(&r, "ETag").unwrap().to_string();
        (loc.trim_start_matches("/cosuri/").to_string(), et)
    }

    #[test]
    fn radacina_ofera_punctele_de_intrare() {
        // Un client trebuie sa poata porni de la `/` fara cai compilate in cod.
        let mut m = Magazin::demonstrativ();
        let r = trateaza(&mut m, &get("/"));
        assert_eq!(r.stare, 200);
        let v = json(&r);
        let l = v["legaturi"].as_array().unwrap();
        assert!(l.iter().any(|x| x[0] == "produse"));
        assert!(l.iter().any(|x| x[0] == "cosuri"));
    }

    #[test]
    fn lista_de_produse_are_total_si_paginare() {
        let mut m = Magazin::demonstrativ();
        let r = trateaza(&mut m, &get("/produse?limita=3"));
        assert_eq!(r.stare, 200);
        let v = json(&r);
        assert_eq!(v["total"], 8);
        assert_eq!(v["elemente"].as_array().unwrap().len(), 3);

        // Legatura catre pagina urmatoare exista, cea precedenta nu.
        let l = v["legaturi"].as_array().unwrap();
        assert!(l.iter().any(|x| x[0] == "urmatoarea"));
        assert!(!l.iter().any(|x| x[0] == "precedenta"));
    }

    #[test]
    fn paginarea_pastreaza_filtrele_in_legaturi() {
        let mut m = Magazin::demonstrativ();
        let r = trateaza(&mut m, &get("/produse?categorie=accesorii&limita=1"));
        let v = json(&r);
        let urm = v["legaturi"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x[0] == "urmatoarea")
            .unwrap()[1]["href"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            urm.contains("categorie=accesorii"),
            "filtrul trebuie sa ramana: {urm}"
        );
    }

    #[test]
    fn limita_e_plafonata() {
        let mut m = Magazin::demonstrativ();
        let r = trateaza(&mut m, &get("/produse?limita=99999"));
        assert_eq!(json(&r)["limita"], PER_PAGINA_MAXIM);
        // Zero nu are sens: se ridica la 1.
        let r = trateaza(&mut m, &get("/produse?limita=0"));
        assert_eq!(json(&r)["limita"], 1);
    }

    #[test]
    fn categoria_necunoscuta_da_422() {
        let mut m = Magazin::demonstrativ();
        let r = trateaza(&mut m, &get("/produse?categorie=bazooka"));
        assert_eq!(r.stare, 422);
        assert_eq!(json(&r)["tip"], "categorie-necunoscuta");
    }

    #[test]
    fn produsul_inexistent_da_404() {
        let mut m = Magazin::demonstrativ();
        let r = trateaza(&mut m, &get("/produse/p-999"));
        assert_eq!(r.stare, 404);
        assert_eq!(json(&r)["tip"], "resursa-inexistenta");
        assert_eq!(
            antet(&r, "Content-Type"),
            Some("application/problem+json; charset=utf-8")
        );
    }

    #[test]
    fn crearea_cosului_da_201_cu_location() {
        let mut m = Magazin::demonstrativ();
        let r = trateaza(&mut m, &cer("POST /cosuri HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert_eq!(r.stare, 201);
        assert!(antet(&r, "Location").unwrap().starts_with("/cosuri/"));
        assert!(antet(&r, "ETag").is_some());
    }

    #[test]
    fn modificarea_fara_if_match_da_428() {
        // Fara conditie, doi clienti s-ar suprascrie tacit.
        let mut m = Magazin::demonstrativ();
        let (cos, _) = cos_nou(&mut m);
        let r = trateaza(
            &mut m,
            &cu_corp(
                "PUT",
                &format!("/cosuri/{cos}/articole/p-001"),
                "",
                r#"{"cantitate":1}"#,
            ),
        );
        assert_eq!(r.stare, 428);
        assert_eq!(json(&r)["tip"], "conditie-necesara");
    }

    #[test]
    fn ciclu_complet_de_cumparare() {
        let mut m = Magazin::demonstrativ().cu_ceas(1_700_000_000);
        let (cos, et) = cos_nou(&mut m);

        // Adaugam doua bucati.
        let r = trateaza(
            &mut m,
            &cu_corp(
                "PUT",
                &format!("/cosuri/{cos}/articole/p-001"),
                &format!("If-Match: {et}\r\n"),
                r#"{"cantitate":2}"#,
            ),
        );
        assert_eq!(r.stare, 200);
        let et2 = antet(&r, "ETag").unwrap().to_string();
        assert_ne!(et, et2, "ETag-ul se schimba dupa modificare");
        assert_eq!(json(&r)["total_bani"], 2 * 12_900);

        // Plasam comanda.
        let r = trateaza(
            &mut m,
            &cu_corp("POST", "/comenzi", "", &format!(r#"{{"cos":"{cos}"}}"#)),
        );
        assert_eq!(r.stare, 201);
        let loc = antet(&r, "Location").unwrap().to_string();
        assert_eq!(json(&r)["total_bani"], 2 * 12_900);
        assert_eq!(json(&r)["stare"], "plasata");

        // Comanda se poate citi de la adresa din Location.
        let r = trateaza(&mut m, &get(&loc));
        assert_eq!(r.stare, 200);
        assert_eq!(json(&r)["stare"], "plasata");
    }

    #[test]
    fn put_ul_e_idempotent() {
        let mut m = Magazin::demonstrativ();
        let (cos, et) = cos_nou(&mut m);
        let cale = format!("/cosuri/{cos}/articole/p-003");

        let r1 = trateaza(
            &mut m,
            &cu_corp("PUT", &cale, &format!("If-Match: {et}\r\n"), r#"{"cantitate":5}"#),
        );
        let et2 = antet(&r1, "ETag").unwrap().to_string();
        let total1 = json(&r1)["total_bani"].clone();

        let r2 = trateaza(
            &mut m,
            &cu_corp("PUT", &cale, &format!("If-Match: {et2}\r\n"), r#"{"cantitate":5}"#),
        );
        assert_eq!(json(&r2)["total_bani"], total1, "acelasi efect");
        assert_eq!(
            json(&r2)["articole"].as_array().unwrap().len(),
            1,
            "nu se dubleaza"
        );
    }

    #[test]
    fn if_match_depasit_da_412() {
        let mut m = Magazin::demonstrativ();
        let (cos, et) = cos_nou(&mut m);
        let cale = format!("/cosuri/{cos}/articole/p-001");

        trateaza(
            &mut m,
            &cu_corp("PUT", &cale, &format!("If-Match: {et}\r\n"), r#"{"cantitate":1}"#),
        );
        // Al doilea client are inca ETag-ul vechi.
        let r = trateaza(
            &mut m,
            &cu_corp("PUT", &cale, &format!("If-Match: {et}\r\n"), r#"{"cantitate":9}"#),
        );
        assert_eq!(r.stare, 412);
        assert_eq!(json(&r)["tip"], "revizie-depasita");
    }

    #[test]
    fn if_none_match_da_304() {
        let mut m = Magazin::demonstrativ();
        let (cos, et) = cos_nou(&mut m);
        let r = trateaza(
            &mut m,
            &cer(&format!(
                "GET /cosuri/{cos} HTTP/1.1\r\nHost: x\r\nIf-None-Match: {et}\r\n\r\n"
            )),
        );
        assert_eq!(r.stare, 304);
        assert!(r.corp.is_empty(), "304 nu are corp");
    }

    #[test]
    fn stergerea_da_204_si_e_idempotenta() {
        let mut m = Magazin::demonstrativ();
        let (cos, et) = cos_nou(&mut m);
        let cale = format!("/cosuri/{cos}/articole/p-001");

        let r = trateaza(
            &mut m,
            &cu_corp("PUT", &cale, &format!("If-Match: {et}\r\n"), r#"{"cantitate":1}"#),
        );
        let et2 = antet(&r, "ETag").unwrap().to_string();

        let r = trateaza(
            &mut m,
            &cer(&format!(
                "DELETE {cale} HTTP/1.1\r\nHost: x\r\nIf-Match: {et2}\r\n\r\n"
            )),
        );
        assert_eq!(r.stare, 204);
        assert!(r.corp.is_empty());
        let et3 = antet(&r, "ETag").unwrap().to_string();

        // A doua stergere: tot succes, resursa lipseste deja.
        let r = trateaza(
            &mut m,
            &cer(&format!(
                "DELETE {cale} HTTP/1.1\r\nHost: x\r\nIf-Match: {et3}\r\n\r\n"
            )),
        );
        assert_eq!(r.stare, 204);
    }

    #[test]
    fn stocul_insuficient_da_409_nu_400() {
        // Cererea e valida; starea serverului nu o permite acum. Clientul poate
        // reincerca mai tarziu si poate reusi.
        let mut m = Magazin::demonstrativ();
        let (cos, et) = cos_nou(&mut m);
        let r = trateaza(
            &mut m,
            &cu_corp(
                "PUT",
                &format!("/cosuri/{cos}/articole/p-008"),
                &format!("If-Match: {et}\r\n"),
                r#"{"cantitate":1}"#,
            ),
        );
        assert_eq!(r.stare, 409);
        assert_eq!(json(&r)["tip"], "stoc-insuficient");
    }

    #[test]
    fn cantitatea_invalida_da_422_nu_400() {
        // Sintaxa e corecta, continutul nu.
        let mut m = Magazin::demonstrativ();
        let (cos, et) = cos_nou(&mut m);
        let r = trateaza(
            &mut m,
            &cu_corp(
                "PUT",
                &format!("/cosuri/{cos}/articole/p-001"),
                &format!("If-Match: {et}\r\n"),
                r#"{"cantitate":0}"#,
            ),
        );
        assert_eq!(r.stare, 422);
    }

    #[test]
    fn corpul_invalid_da_400() {
        let mut m = Magazin::demonstrativ();
        let (cos, et) = cos_nou(&mut m);
        let r = trateaza(
            &mut m,
            &cu_corp(
                "PUT",
                &format!("/cosuri/{cos}/articole/p-001"),
                &format!("If-Match: {et}\r\n"),
                "nu e json",
            ),
        );
        assert_eq!(r.stare, 400);
    }

    #[test]
    fn tipul_gresit_de_continut_da_415() {
        let mut m = Magazin::demonstrativ();
        let (cos, et) = cos_nou(&mut m);
        let r = trateaza(
            &mut m,
            &cer(&format!(
                "PUT /cosuri/{cos}/articole/p-001 HTTP/1.1\r\nHost: x\r\nIf-Match: {et}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi"
            )),
        );
        assert_eq!(r.stare, 415);
    }

    #[test]
    fn metoda_nepermisa_da_405_cu_allow() {
        let mut m = Magazin::demonstrativ();
        let r = trateaza(&mut m, &cer("DELETE /produse HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert_eq!(r.stare, 405);
        assert_eq!(antet(&r, "Allow"), Some("GET, HEAD, OPTIONS"));
    }

    #[test]
    fn options_raporteaza_metodele() {
        let mut m = Magazin::demonstrativ();
        for (cale, asteptat) in [
            ("/produse", "GET, HEAD, OPTIONS"),
            ("/cosuri", "POST, OPTIONS"),
            ("/comenzi", "POST, OPTIONS"),
        ] {
            let r = trateaza(
                &mut m,
                &cer(&format!("OPTIONS {cale} HTTP/1.1\r\nHost: x\r\n\r\n")),
            );
            assert_eq!(r.stare, 204);
            assert_eq!(antet(&r, "Allow"), Some(asteptat), "la {cale}");
        }
    }

    #[test]
    fn get_ul_nu_schimba_nimic() {
        // Proprietatea de siguranta a metodei.
        let mut m = Magazin::demonstrativ();
        let stoc = m.produs("p-001").unwrap().stoc;
        for cale in ["/", "/produse", "/produse/p-001", "/produse?limita=2"] {
            trateaza(&mut m, &get(cale));
        }
        assert_eq!(m.produs("p-001").unwrap().stoc, stoc);
        assert_eq!(m.numar_comenzi(), 0);
    }

    #[test]
    fn cosul_dispare_dupa_comanda_si_da_404() {
        let mut m = Magazin::demonstrativ();
        let (cos, et) = cos_nou(&mut m);
        trateaza(
            &mut m,
            &cu_corp(
                "PUT",
                &format!("/cosuri/{cos}/articole/p-003"),
                &format!("If-Match: {et}\r\n"),
                r#"{"cantitate":1}"#,
            ),
        );
        trateaza(
            &mut m,
            &cu_corp("POST", "/comenzi", "", &format!(r#"{{"cos":"{cos}"}}"#)),
        );
        let r = trateaza(&mut m, &get(&format!("/cosuri/{cos}")));
        assert_eq!(r.stare, 404);
    }

    #[test]
    fn calea_necunoscuta_da_404() {
        let mut m = Magazin::demonstrativ();
        for cale in ["/aiurea", "/produse/p-001/altceva", "/cosuri/a/b/c/d"] {
            assert_eq!(trateaza(&mut m, &get(cale)).stare, 404, "la {cale}");
        }
    }
}
