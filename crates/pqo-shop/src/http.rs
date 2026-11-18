//! HTTP/1.1 minimal, fara I/O.
//!
//! Suficient cat sa serveasca un API REST: metode, cale, sir de interogare,
//! antete, corp cu lungime declarata. Nu implementeaza `Transfer-Encoding:
//! chunked`, `Expect: 100-continue`, sau conexiuni pipelined.
//!
//! # De ce scris de mana
//!
//! Un cadru HTTP complet ar aduce zeci de dependente tranzitive intr-un proiect
//! al carui subiect e criptografia. Fiecare dependenta e cod pe care nu l-am
//! citit si care ruleaza in acelasi proces cu cheile serviciului ascuns.
//!
//! Compromisul e explicit: e mai putin cod strain, dar si mai putine
//! functionalitati. Pentru un serviciu demonstrativ e alegerea potrivita;
//! pentru un magazin real, nu.

use std::collections::BTreeMap;

/// Cat de mare poate fi antetul unei cereri.
pub const MAX_ANTET: usize = 8 * 1024;
/// Cat de mare poate fi corpul.
pub const MAX_CORP: usize = 64 * 1024;

/// Metoda HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metoda {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
}

impl Metoda {
    pub fn din_text(s: &str) -> Option<Self> {
        match s {
            "GET" => Some(Metoda::Get),
            "HEAD" => Some(Metoda::Head),
            "POST" => Some(Metoda::Post),
            "PUT" => Some(Metoda::Put),
            "DELETE" => Some(Metoda::Delete),
            "OPTIONS" => Some(Metoda::Options),
            _ => None,
        }
    }

    /// Adevarat daca metoda nu are voie sa schimbe starea serverului.
    pub fn e_sigura(self) -> bool {
        matches!(self, Metoda::Get | Metoda::Head | Metoda::Options)
    }
}

/// O cerere HTTP parsata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cerere {
    pub metoda: Metoda,
    /// Calea, decodata din procente.
    pub cale: String,
    /// Parametrii din sirul de interogare, decodati.
    pub interogare: BTreeMap<String, String>,
    /// Antetele, cu numele in litere mici.
    pub antete: BTreeMap<String, String>,
    pub corp: Vec<u8>,
}

impl Cerere {
    pub fn antet(&self, nume: &str) -> Option<&str> {
        self.antete.get(&nume.to_ascii_lowercase()).map(|s| s.as_str())
    }

    /// Segmentele nevide ale caii.
    pub fn segmente(&self) -> Vec<&str> {
        self.cale.split('/').filter(|s| !s.is_empty()).collect()
    }

    pub fn parametru(&self, nume: &str) -> Option<&str> {
        self.interogare.get(nume).map(|s| s.as_str())
    }
}

/// De ce nu s-a putut parsa o cerere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EroareHttp {
    /// Antetul nu e complet inca; mai citeste.
    Incomplet,
    /// Prima linie sau un antet nu respecta formatul.
    Malformat,
    /// Metoda nu e recunoscuta.
    MetodaNecunoscuta,
    /// Antetul sau corpul depaseste plafonul.
    PreaMare,
}

/// Incearca sa parseze o cerere din octetii primiti.
///
/// Intoarce cererea si cati octeti a consumat, sau [`EroareHttp::Incomplet`]
/// daca mai trebuie citit.
pub fn parseaza(buf: &[u8]) -> Result<(Cerere, usize), EroareHttp> {
    let capat = gaseste_capat_antet(buf).ok_or({
        if buf.len() > MAX_ANTET {
            EroareHttp::PreaMare
        } else {
            EroareHttp::Incomplet
        }
    })?;
    if capat > MAX_ANTET {
        return Err(EroareHttp::PreaMare);
    }

    let text = core::str::from_utf8(&buf[..capat]).map_err(|_| EroareHttp::Malformat)?;
    let mut linii = text.split("\r\n");

    // Prima linie: METODA CALE VERSIUNE
    let prima = linii.next().ok_or(EroareHttp::Malformat)?;
    let mut p = prima.split(' ');
    let metoda_txt = p.next().ok_or(EroareHttp::Malformat)?;
    let tinta = p.next().ok_or(EroareHttp::Malformat)?;
    let versiune = p.next().ok_or(EroareHttp::Malformat)?;
    if p.next().is_some() || !versiune.starts_with("HTTP/1.") {
        return Err(EroareHttp::Malformat);
    }
    let metoda = Metoda::din_text(metoda_txt).ok_or(EroareHttp::MetodaNecunoscuta)?;

    let (cale_bruta, interogare_bruta) = match tinta.split_once('?') {
        Some((c, q)) => (c, Some(q)),
        None => (tinta, None),
    };
    if !cale_bruta.starts_with('/') {
        return Err(EroareHttp::Malformat);
    }
    let cale = decodeaza_procente(cale_bruta)?;
    // O cale care contine `..` dupa decodare ar putea scapa din spatiul de nume
    // al resurselor. Aici nu servim fisiere, dar regula e mai ieftina decat
    // rationamentul despre ce s-ar putea intampla daca vom servi candva.
    if cale.split('/').any(|s| s == "..") {
        return Err(EroareHttp::Malformat);
    }

    let mut interogare = BTreeMap::new();
    if let Some(q) = interogare_bruta {
        for pereche in q.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = pereche.split_once('=').unwrap_or((pereche, ""));
            interogare.insert(decodeaza_procente(k)?, decodeaza_procente(v)?);
        }
    }

    let mut antete = BTreeMap::new();
    for l in linii {
        if l.is_empty() {
            continue;
        }
        let (k, v) = l.split_once(':').ok_or(EroareHttp::Malformat)?;
        if k.is_empty() || k.contains(' ') {
            return Err(EroareHttp::Malformat);
        }
        antete.insert(k.to_ascii_lowercase(), v.trim().to_string());
    }

    let lungime: usize = match antete.get("content-length") {
        Some(v) => v.parse().map_err(|_| EroareHttp::Malformat)?,
        None => 0,
    };
    if lungime > MAX_CORP {
        return Err(EroareHttp::PreaMare);
    }
    if buf.len() < capat + lungime {
        return Err(EroareHttp::Incomplet);
    }

    Ok((
        Cerere {
            metoda,
            cale,
            interogare,
            antete,
            corp: buf[capat..capat + lungime].to_vec(),
        },
        capat + lungime,
    ))
}

fn gaseste_capat_antet(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn decodeaza_procente(s: &str) -> Result<String, EroareHttp> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                if i + 2 >= b.len() {
                    return Err(EroareHttp::Malformat);
                }
                let h = core::str::from_utf8(&b[i + 1..i + 3]).map_err(|_| EroareHttp::Malformat)?;
                out.push(u8::from_str_radix(h, 16).map_err(|_| EroareHttp::Malformat)?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| EroareHttp::Malformat)
}

/// Un raspuns HTTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raspuns {
    pub stare: u16,
    pub antete: Vec<(String, String)>,
    pub corp: Vec<u8>,
}

impl Raspuns {
    pub fn nou(stare: u16) -> Self {
        Raspuns {
            stare,
            antete: Vec::new(),
            corp: Vec::new(),
        }
    }

    /// Pune un antet, inlocuindu-l daca exista deja.
    ///
    /// Inlocuirea nu e o comoditate: doua antete `Content-Type` intr-un raspuns
    /// sunt malformate, iar un client care le vede pe amandoua poate alege
    /// oricare. Prima versiune adauga mereu, si un raspuns de eroare ajungea sa
    /// declare si `application/json` si `application/problem+json`.
    pub fn cu_antet(mut self, nume: &str, valoare: impl Into<String>) -> Self {
        let v = valoare.into();
        match self
            .antete
            .iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case(nume))
        {
            Some(slot) => slot.1 = v,
            None => self.antete.push((nume.to_string(), v)),
        }
        self
    }

    /// Corp JSON, cu tipul de continut potrivit.
    pub fn json(mut self, corp: impl serde::Serialize) -> Self {
        match serde_json::to_vec_pretty(&corp) {
            Ok(v) => {
                self.corp = v;
                self.cu_antet("Content-Type", "application/json; charset=utf-8")
            }
            // Serializarea nu poate esua pentru tipurile noastre, dar daca ar
            // esua e o eroare de server, nu una de client.
            Err(_) => Raspuns::nou(500),
        }
    }

    /// Corp brut, cu tipul de continut pus separat.
    pub fn corp_brut(mut self, corp: Vec<u8>) -> Self {
        self.corp = corp;
        self
    }

    pub fn text(mut self, corp: &str) -> Self {
        self.corp = corp.as_bytes().to_vec();
        self.cu_antet("Content-Type", "text/plain; charset=utf-8")
    }

    /// Serializeaza raspunsul.
    ///
    /// `doar_antete` pentru `HEAD`: acelasi raspuns, fara corp, dar cu
    /// `Content-Length` care descrie ce **ar fi fost** trimis. Un client trebuie
    /// sa poata afla dimensiunea fara sa descarce.
    pub fn encode(&self, doar_antete: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.corp.len());
        out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", self.stare, motiv(self.stare)).as_bytes());
        for (k, v) in &self.antete {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n", self.corp.len()).as_bytes());
        out.extend_from_slice(b"Connection: keep-alive\r\n\r\n");
        if !doar_antete {
            out.extend_from_slice(&self.corp);
        }
        out
    }
}

/// Fraza de motiv pentru un cod de stare.
pub fn motiv(cod: u16) -> &'static str {
    match cod {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        304 => "Not Modified",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        428 => "Precondition Required",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cerere(text: &str) -> Result<Cerere, EroareHttp> {
        parseaza(text.as_bytes()).map(|(c, _)| c)
    }

    #[test]
    fn cerere_simpla() {
        let c = cerere("GET /produse HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(c.metoda, Metoda::Get);
        assert_eq!(c.cale, "/produse");
        assert_eq!(c.antet("host"), Some("x"));
        assert_eq!(c.segmente(), vec!["produse"]);
    }

    #[test]
    fn antetele_sunt_insensibile_la_capitalizare() {
        let c = cerere("GET / HTTP/1.1\r\nIf-Match: \"5\"\r\n\r\n").unwrap();
        assert_eq!(c.antet("if-match"), Some("\"5\""));
        assert_eq!(c.antet("IF-MATCH"), Some("\"5\""));
    }

    #[test]
    fn sirul_de_interogare_se_decodeaza() {
        let c = cerere("GET /produse?categorie=spuma&q=pistol+mic&x=%C4%83 HTTP/1.1\r\n\r\n")
            .unwrap();
        assert_eq!(c.parametru("categorie"), Some("spuma"));
        assert_eq!(c.parametru("q"), Some("pistol mic"));
        assert_eq!(c.parametru("x"), Some("ă"));
        assert_eq!(c.parametru("lipsa"), None);
    }

    #[test]
    fn corpul_se_citeste_dupa_lungime() {
        let brut = b"POST /cosuri HTTP/1.1\r\nContent-Length: 5\r\n\r\nabcde";
        let (c, n) = parseaza(brut).unwrap();
        assert_eq!(c.corp, b"abcde");
        assert_eq!(n, brut.len(), "consumam exact cererea, nici mai mult");
    }

    #[test]
    fn cerere_incompleta_cere_mai_multi_octeti() {
        assert_eq!(cerere("GET / HTTP/1.1\r\nHost:"), Err(EroareHttp::Incomplet));
        assert_eq!(
            parseaza(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc"),
            Err(EroareHttp::Incomplet)
        );
    }

    #[test]
    fn cereri_malformate_sunt_respinse() {
        for rea in [
            "GET\r\n\r\n",
            "GET / HTTP/2.0\r\n\r\n",
            "GET produse HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nfara-doua-puncte\r\n\r\n",
            "GET / HTTP/1.1\r\n: gol\r\n\r\n",
            "GET / / HTTP/1.1\r\n\r\n",
        ] {
            assert!(cerere(rea).is_err(), "acceptat: {rea:?}");
        }
        assert_eq!(
            cerere("BREW / HTTP/1.1\r\n\r\n"),
            Err(EroareHttp::MetodaNecunoscuta)
        );
    }

    #[test]
    fn caile_cu_puncte_duble_sunt_respinse() {
        // Chiar daca nu servim fisiere: regula e mai ieftina decat rationamentul.
        for rea in [
            "GET /../secret HTTP/1.1\r\n\r\n",
            "GET /a/%2e%2e/b HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(cerere(rea), Err(EroareHttp::Malformat), "acceptat: {rea:?}");
        }
    }

    #[test]
    fn plafoanele_sunt_aplicate() {
        let mare = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_ANTET));
        assert_eq!(cerere(&mare), Err(EroareHttp::PreaMare));

        let corp_mare = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_CORP + 1
        );
        assert_eq!(cerere(&corp_mare), Err(EroareHttp::PreaMare));
    }

    #[test]
    fn niciun_prefix_nu_produce_panica() {
        let plina = b"POST /cosuri/c-1/articole/p-2?x=1 HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc";
        for n in 0..=plina.len() {
            let _ = parseaza(&plina[..n]);
        }
    }

    #[test]
    fn metodele_sigure_sunt_marcate() {
        assert!(Metoda::Get.e_sigura());
        assert!(Metoda::Head.e_sigura());
        assert!(Metoda::Options.e_sigura());
        assert!(!Metoda::Post.e_sigura());
        assert!(!Metoda::Put.e_sigura());
        assert!(!Metoda::Delete.e_sigura());
    }

    #[test]
    fn antetul_se_inlocuieste_nu_se_dubleaza() {
        // Doua `Content-Type` intr-un raspuns sunt malformate.
        let r = Raspuns::nou(200)
            .text("x")
            .cu_antet("Content-Type", "application/problem+json");
        assert_eq!(
            r.antete
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .count(),
            1
        );
        assert_eq!(r.antete[0].1, "application/problem+json");
    }

    #[test]
    fn raspunsul_are_lungime_si_stare() {
        let r = Raspuns::nou(201)
            .cu_antet("Location", "/comenzi/cmd-1")
            .text("gata");
        let b = String::from_utf8(r.encode(false)).unwrap();
        assert!(b.starts_with("HTTP/1.1 201 Created\r\n"));
        assert!(b.contains("Location: /comenzi/cmd-1\r\n"));
        assert!(b.contains("Content-Length: 4\r\n"));
        assert!(b.ends_with("\r\n\r\ngata"));
    }

    #[test]
    fn head_pastreaza_lungimea_dar_nu_corpul() {
        // Un client trebuie sa poata afla dimensiunea fara sa descarce.
        let r = Raspuns::nou(200).text("douasprezece");
        let b = String::from_utf8(r.encode(true)).unwrap();
        assert!(b.contains("Content-Length: 12\r\n"));
        assert!(b.ends_with("\r\n\r\n"), "HEAD nu are corp");
    }
}
