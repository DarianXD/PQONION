//! Codare base64 (RFC 4648) si formatul canonic de document.
//!
//! # De ce format text si nu binar
//!
//! Documentele de director trebuie sa fie **canonice**: aceeasi informatie
//! trebuie sa produca exact aceiasi octeti la toate autoritatile, altfel
//! semnaturile nu se potrivesc. Un format text linie-orientat face canonicitatea
//! usor de verificat cu ochiul si usor de depanat cand doua autoritati diverg.
//! E si alegerea Tor, din aceleasi motive.
//!
//! Costul e dimensiunea: base64 umfla cu 33%. Pentru o semnatura ML-DSA-65 de
//! 3309 octeti asta inseamna 4412 caractere. Acceptabil pentru un consens pe ora.

use crate::DirError;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Codeaza in base64 cu umplutura, conform RFC 4648.
pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn b64_val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a') as u32 + 26),
        b'0'..=b'9' => Some((c - b'0') as u32 + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodeaza base64 strict: lungime multiplu de 4, umplutura doar la final,
/// bitii de umplutura obligatoriu zero.
///
/// Strictetea conteaza: o decodare permisiva ar face ca doua siruri diferite sa
/// produca aceiasi octeti, iar un document semnat ar avea mai multe forme
/// valide. Asta rupe canonicitatea si deschide un canal ascuns.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, DirError> {
    let b = s.as_bytes();
    if b.is_empty() {
        return Ok(Vec::new());
    }
    if b.len() % 4 != 0 {
        return Err(DirError::BadBase64);
    }
    let pad = b.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 || b[..b.len() - pad].contains(&b'=') {
        return Err(DirError::BadBase64);
    }

    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for chunk in b.chunks(4) {
        let mut n = 0u32;
        let mut valid = 4;
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                valid = i;
                break;
            }
            n |= b64_val(c).ok_or(DirError::BadBase64)? << (18 - 6 * i);
        }
        match valid {
            4 => out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]),
            3 => {
                if n & 0xFF != 0 {
                    return Err(DirError::BadBase64); // biti de umplutura nenuli
                }
                out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8]);
            }
            2 => {
                if n & 0xFFFF != 0 {
                    return Err(DirError::BadBase64);
                }
                out.push((n >> 16) as u8);
            }
            _ => return Err(DirError::BadBase64),
        }
    }
    Ok(out)
}

/// Codare hexazecimala cu litere mari, pentru fingerprint-uri.
pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, DirError> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err(DirError::BadHex);
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks(2) {
        let hi = (pair[0] as char).to_digit(16).ok_or(DirError::BadHex)?;
        let lo = (pair[1] as char).to_digit(16).ok_or(DirError::BadHex)?;
        // Doar litere mari, ca sa fie canonic.
        if pair[0].is_ascii_lowercase() || pair[1].is_ascii_lowercase() {
            return Err(DirError::BadHex);
        }
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Documentul linie-orientat
// ---------------------------------------------------------------------------

/// O linie dintr-un document: un cuvant cheie si argumentele lui.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub keyword: String,
    pub args: Vec<String>,
}

impl Line {
    pub fn arg(&self, i: usize) -> Result<&str, DirError> {
        self.args.get(i).map(|s| s.as_str()).ok_or(DirError::Missing)
    }

    pub fn parse_arg<T: core::str::FromStr>(&self, i: usize) -> Result<T, DirError> {
        self.arg(i)?.parse().map_err(|_| DirError::Malformed)
    }
}

/// Construieste un document canonic.
#[derive(Debug, Default)]
pub struct Builder {
    out: String,
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adauga o linie. Argumentele nu au voie sa contina spatii sau linii noi —
    /// altfel ar putea injecta linii false intr-un document semnat.
    pub fn line<'a>(&mut self, keyword: &str, args: impl IntoIterator<Item = &'a str>) {
        debug_assert!(!keyword.contains([' ', '\n']));
        self.out.push_str(keyword);
        for a in args {
            debug_assert!(
                !a.contains([' ', '\n', '\r']),
                "argument cu spatiu: injectie de linie"
            );
            self.out.push(' ');
            self.out.push_str(a);
        }
        self.out.push('\n');
    }

    pub fn finish(self) -> String {
        self.out
    }

    pub fn as_str(&self) -> &str {
        &self.out
    }
}

/// Descompune un document in linii.
///
/// Reguli stricte, pentru canonicitate:
///   - separator de linie exact `\n`, niciodata `\r\n`
///   - un singur spatiu intre argumente
///   - fara linii goale, fara spatii la inceput sau sfarsit
///   - documentul se termina cu `\n`
pub fn parse_lines(doc: &str) -> Result<Vec<Line>, DirError> {
    if doc.contains('\r') {
        return Err(DirError::Malformed);
    }
    if !doc.is_empty() && !doc.ends_with('\n') {
        return Err(DirError::Malformed);
    }
    let mut out = Vec::new();
    for raw in doc.lines() {
        if raw.is_empty() {
            return Err(DirError::Malformed);
        }
        if raw.starts_with(' ') || raw.ends_with(' ') || raw.contains("  ") {
            return Err(DirError::Malformed);
        }
        let mut it = raw.split(' ');
        let keyword = it.next().ok_or(DirError::Malformed)?.to_string();
        if keyword.is_empty() {
            return Err(DirError::Malformed);
        }
        out.push(Line {
            keyword,
            args: it.map(|s| s.to_string()).collect(),
        });
    }
    Ok(out)
}

/// Partea semnabila a unui document: tot ce e inainte de prima linie cu unul
/// dintre cuvintele cheie date.
///
/// Semnaturile acopera prefixul, nu tot documentul — altfel n-ar putea exista
/// mai multe semnaturi pe acelasi consens.
pub fn signed_prefix<'a>(doc: &'a str, stop_keywords: &[&str]) -> &'a str {
    let mut off = 0usize;
    for raw in doc.split_inclusive('\n') {
        let kw = raw.trim_end_matches('\n').split(' ').next().unwrap_or("");
        if stop_keywords.contains(&kw) {
            return &doc[..off];
        }
        off += raw.len();
    }
    doc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectorii din RFC 4648, sectiunea 10.
    #[test]
    fn rfc4648_vectori() {
        let cazuri = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in cazuri {
            assert_eq!(b64_encode(plain.as_bytes()), encoded, "codare {plain:?}");
            assert_eq!(
                b64_decode(encoded).unwrap(),
                plain.as_bytes(),
                "decodare {encoded:?}"
            );
        }
    }

    #[test]
    fn b64_roundtrip_toate_lungimile() {
        for n in 0..200usize {
            let v: Vec<u8> = (0..n).map(|i| (i * 37 % 256) as u8).collect();
            assert_eq!(b64_decode(&b64_encode(&v)).unwrap(), v, "lungime {n}");
        }
    }

    #[test]
    fn b64_respinge_input_necanonic() {
        // Lungime gresita.
        assert!(b64_decode("Zm9").is_err());
        // Caracter invalid.
        assert!(b64_decode("Zm9*").is_err());
        // Umplutura la mijloc.
        assert!(b64_decode("Zg==Zg==").is_err());
        // Biti de umplutura nenuli: "Zh==" ar decoda tot 'f' ca si "Zg==".
        assert!(
            b64_decode("Zh==").is_err(),
            "doua siruri diferite nu au voie sa dea aceiasi octeti"
        );
    }

    #[test]
    fn hex_e_canonic() {
        assert_eq!(hex_encode(&[0xAB, 0x0F]), "AB0F");
        assert_eq!(hex_decode("AB0F").unwrap(), vec![0xAB, 0x0F]);
        // Litere mici respinse, ca sa existe o singura forma valida.
        assert!(hex_decode("ab0f").is_err());
        assert!(hex_decode("AB0").is_err());
        assert!(hex_decode("ZZ").is_err());
    }

    #[test]
    fn document_roundtrip() {
        let mut b = Builder::new();
        b.line("consensus", ["1"]);
        b.line("valid-after", ["1700000000"]);
        b.line("r", ["AABB", "10.0.0.1", "9001", "1000"]);
        let doc = b.finish();
        assert_eq!(doc, "consensus 1\nvalid-after 1700000000\nr AABB 10.0.0.1 9001 1000\n");

        let lines = parse_lines(&doc).unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[2].keyword, "r");
        assert_eq!(lines[2].arg(1).unwrap(), "10.0.0.1");
        assert_eq!(lines[2].parse_arg::<u32>(2).unwrap(), 9001);
        assert!(lines[2].arg(9).is_err());
    }

    #[test]
    fn parserul_respinge_forme_necanonice() {
        for rau in [
            "a b\r\n",       // CRLF
            "a b",           // fara \n final
            "a  b\n",        // spatiu dublu
            " a b\n",        // spatiu la inceput
            "a b \n",        // spatiu la final
            "a b\n\nc d\n",  // linie goala
        ] {
            assert!(parse_lines(rau).is_err(), "ar fi trebuit respins: {rau:?}");
        }
    }

    #[test]
    fn prefixul_semnabil_se_opreste_corect() {
        let doc = "consensus 1\nvalid-after 5\nauthority-signature AA xx\nauthority-signature BB yy\n";
        assert_eq!(
            signed_prefix(doc, &["authority-signature"]),
            "consensus 1\nvalid-after 5\n"
        );
        // Fara linia de oprire, prefixul e tot documentul.
        let doc2 = "consensus 1\n";
        assert_eq!(signed_prefix(doc2, &["authority-signature"]), doc2);
    }
}
