//! POLYVAL, hash-ul universal din RFC 8452, folosit de CGO ca `UH`.
//!
//! # Reprezentare
//!
//! Un element de camp e un bloc de 16 octeti. Bitul `i` (numarand de la bitul
//! cel mai putin semnificativ al octetului 0) e coeficientul lui `x^i`. Asta
//! corespunde exact lui `u128::from_le_bytes`, ceea ce face conversia gratuita.
//!
//! Reducerea se face modulo `P(x) = x^128 + x^127 + x^126 + x^121 + 1`.
//!
//! # Capcana: POLYVAL nu foloseste inmultire obisnuita
//!
//! RFC 8452 defineste `dot(a, b) = a · b · x^-128`, nu `a · b`. E o inmultire de
//! tip Montgomery. Daca implementezi inmultirea directa in corp, toate testele
//! de consistenta interna trec (comutativitate, distributivitate, element
//! neutru) si totusi rezultatul e gresit — vezi ce iese pe vectorul din RFC.
//!
//! Implementam `dot` direct: parcurgem bitii lui `b` de sus in jos si impartim
//! `a` la `x` la fiecare pas, obtinand `a · x^(i-128)` exact cand avem nevoie
//! de el. Impartirea la `x` foloseste
//! `x^-1 = x^127 + x^126 + x^125 + x^120`, care se verifica inmultind cu `x`
//! si reducand modulo `P`.
//!
//! # Performanta
//!
//! Inmultirea e bit cu bit, O(128) pasi. E lenta si intentionat asa: e usor de
//! citit si de auditat.POLYVAL se apeleaza de doua ori per celula per hop.
//!
//! Implementarea e in timp constant fata de *date*: bucla ruleaza mereu 128 de
//! pasi si selectia se face prin masca aritmetica, nu prin ramificare.

/// `x^-1 = x^127 + x^126 + x^125 + x^120`.
///
/// Verificare: `x · (x^127+x^126+x^125+x^120) = x^128+x^127+x^126+x^121`, iar
/// din `P` avem `x^128 = x^127+x^126+x^121+1`, deci suma se reduce la `1`.
const INV_X: u128 = (1u128 << 127) | (1u128 << 126) | (1u128 << 125) | (1u128 << 120);

/// `dot(a, b) = a · b · x^-128` in GF(2^128) modulo `P`.
///
/// Nu e inmultirea obisnuita. Vezi nota de modul.
fn dot(a: u128, b: u128) -> u128 {
    let mut z: u128 = 0;
    let mut v = a;
    // La iteratia pentru bitul `i`, dupa impartire avem `v = a · x^(i-128)`.
    for i in (0..128).rev() {
        // v <- v / x
        let lsb = v & 1;
        let dmask = 0u128.wrapping_sub(lsb);
        v = (v >> 1) ^ (INV_X & dmask);

        // Acumulare fara ramificare pe date.
        let bit = (b >> i) & 1;
        z ^= v & 0u128.wrapping_sub(bit);
    }
    z
}

/// Starea unui calcul POLYVAL.
pub struct Polyval {
    h: u128,
    s: u128,
}

impl core::fmt::Debug for Polyval {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Polyval(redacted)")
    }
}

impl Polyval {
    pub fn new(key: &[u8; 16]) -> Self {
        Polyval {
            h: u128::from_le_bytes(*key),
            s: 0,
        }
    }

    /// Absoarbe un bloc complet de 16 octeti.
    pub fn update_block(&mut self, block: &[u8; 16]) {
        self.s = dot(self.s ^ u128::from_le_bytes(*block), self.h);
    }

    /// Absoarbe date de lungime arbitrara, completand ultimul bloc cu zerouri.
    ///
    /// ATENTIE: completarea cu zerouri e sigura doar daca fiecare cheie se
    /// foloseste cu mesaje de o *singura* lungime. RFC 8452 avertizeaza explicit,
    /// iar propunerea 359 se bazeaza pe asta: `MLEN_UH(KU) = 510` si
    /// `MLEN_UH(B) = 16`, fixe. Nu refolosi o cheie cu doua lungimi diferite.
    pub fn update(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(16);
        for c in &mut chunks {
            let mut b = [0u8; 16];
            b.copy_from_slice(c);
            self.update_block(&b);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut b = [0u8; 16];
            b[..rem.len()].copy_from_slice(rem);
            self.update_block(&b);
        }
    }

    pub fn finish(self) -> [u8; 16] {
        self.s.to_le_bytes()
    }
}

/// `UH(K, M)` — POLYVAL cu cheia `K` peste mesajul `M`.
pub fn uh(key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    let mut p = Polyval::new(key);
    p.update(msg);
    p.finish()
}

/// `UH` peste doua bucati concatenate, fara sa le copiem intr-un buffer nou.
///
/// CGO calculeaza mereu `UH(KU, H | X_R)` unde `H` are 17 octeti si `X_R` are
/// 493. Concatenarea ar insemna o alocare de 510 octeti per celula per hop.
pub fn uh2(key: &[u8; 16], a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut p = Polyval::new(key);
    // Aliniem manual la granita de bloc peste jonctiune.
    let total = a.len() + b.len();
    let mut buf = [0u8; 16];
    let mut fill = 0usize;
    let feed = |p: &mut Polyval, src: &[u8], buf: &mut [u8; 16], fill: &mut usize| {
        let mut off = 0;
        while off < src.len() {
            let take = (16 - *fill).min(src.len() - off);
            buf[*fill..*fill + take].copy_from_slice(&src[off..off + take]);
            *fill += take;
            off += take;
            if *fill == 16 {
                p.update_block(buf);
                *fill = 0;
            }
        }
    };
    feed(&mut p, a, &mut buf, &mut fill);
    feed(&mut p, b, &mut buf, &mut fill);
    if fill > 0 {
        for x in buf.iter_mut().skip(fill) {
            *x = 0;
        }
        p.update_block(&buf);
    }
    debug_assert!(total > 0);
    p.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn h16(s: &str) -> [u8; 16] {
        hex(s).try_into().unwrap()
    }

    /// Vectorul de test din RFC 8452, sectiunea 3.
    ///
    /// Daca acesta pica, POLYVAL e gresit si tot CGO e gresit. E singurul test
    /// din acest modul care valideaza fata de o sursa externa; restul verifica
    /// doar consistenta.
    #[test]
    fn rfc8452_vector_doua_blocuri() {
        let h = h16("25629347589242761d31f826ba4b757b");
        let x1 = h16("4f4f95668c83dfb6401762bb2d01a262");
        let x2 = h16("d1a24ddd2721d006bbe45f20d3c9f362");
        let asteptat = h16("f7a3b47b846119fae5b7866cf5e5b77e");

        let mut p = Polyval::new(&h);
        p.update_block(&x1);
        p.update_block(&x2);
        assert_eq!(p.finish(), asteptat);
    }

    /// Cazul degenerat: fara blocuri, rezultatul e zero.
    #[test]
    fn fara_blocuri_da_zero() {
        let h = h16("25629347589242761d31f826ba4b757b");
        assert_eq!(Polyval::new(&h).finish(), [0u8; 16]);
    }

    #[test]
    fn dot_e_comutativ_si_distributiv() {
        // Proprietati necesare, dar NU suficiente: o inmultire obisnuita le
        // satisface si ea, si totusi e gresita. De aceea vectorul din RFC e
        // singurul test care conteaza cu adevarat aici.
        let a = 0xdead_beef_cafe_babe_0123_4567_89ab_cdefu128;
        let b = 0x1111_2222_3333_4444_5555_6666_7777_8888u128;
        let c = 0x9999_aaaa_bbbb_cccc_dddd_eeee_ffff_0000u128;
        assert_eq!(dot(a, b), dot(b, a));
        assert_eq!(dot(a, b ^ c), dot(a, b) ^ dot(a, c));
        assert_eq!(dot(a, 0), 0);
    }

    #[test]
    fn elementul_neutru_pentru_dot_e_x_128() {
        // Pentru `dot`, neutrul nu e 1, ci x^128 (adica `x^127+x^126+x^121+1`
        // dupa reducere). Inca o dovada ca nu e inmultire obisnuita.
        let neutru = (1u128 << 127) | (1u128 << 126) | (1u128 << 121) | 1;
        let a = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128;
        assert_eq!(dot(a, neutru), a);
    }

    #[test]
    fn uh2_e_egal_cu_concatenarea() {
        let k = h16("25629347589242761d31f826ba4b757b");
        for (la, lb) in [(17usize, 493usize), (0, 16), (16, 0), (1, 1), (15, 1), (17, 15)] {
            let a: Vec<u8> = (0..la).map(|i| (i * 7) as u8).collect();
            let b: Vec<u8> = (0..lb).map(|i| (i * 13 + 1) as u8).collect();
            let mut cat = a.clone();
            cat.extend_from_slice(&b);
            assert_eq!(
                uh2(&k, &a, &b),
                uh(&k, &cat),
                "uh2 difera de concatenare pentru ({la}, {lb})"
            );
        }
    }

    #[test]
    fn completarea_cu_zerouri_e_ca_in_rfc() {
        let k = h16("25629347589242761d31f826ba4b757b");
        // Un mesaj de 20 de octeti se completeaza la 32.
        let m: Vec<u8> = (0..20).map(|i| i as u8).collect();
        let mut padded = m.clone();
        padded.resize(32, 0);
        assert_eq!(uh(&k, &m), uh(&k, &padded));
    }
}
