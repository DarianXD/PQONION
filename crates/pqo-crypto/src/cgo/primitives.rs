//! Primitivele CGO, nivelurile 1–3 din propunerea 359.
//!
//! Ierarhia, de jos in sus:
//!   1. `AES-128` + `POLYVAL` (vezi [`super::polyval`])
//!   2. `ENC_ET`/`DEC_ET` — cifru bloc tweakabil, constructia LRW2
//!      `PRF` — functie pseudoaleatoare, AES-CTR indexat de POLYVAL
//!   3. `UIV+` — permutare pseudoaleatoare "rugged" pe domeniu impartit
//!
//! Proprietatea centrala a lui UIV+, de retinut: **`ENC_UIV` e nemaleabil,
//! `DEC_UIV` nu e.** De aceea clientul foloseste mereu `DEC_UIV` si releele
//! mereu `ENC_UIV`. Daca inversezi directiile, pierzi exact rezistenta la
//! tagging pentru care exista toata constructia.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use zeroize::Zeroize;

use super::polyval::{uh, uh2};

/// Lungimea partii criptate a unei celule relay.
pub const MSG_LEN: usize = 509;
/// Lungimea unui bloc.
pub const BLK_LEN: usize = 16;
/// Lungimea partii drepte `X_R`.
pub const LEN_XR: usize = MSG_LEN - BLK_LEN; // 493
/// Lungimea tweak-ului UIV: `T'` (16) + `AD` (1).
pub const HLEN_UIV: usize = BLK_LEN + 1; // 17
/// Lungimea cheii UIV+: `J` (32) + `S` (32).
pub const KLEN_UIV: usize = 64;
/// Iesirea PRF pentru `t = 0`.
pub const N0: usize = LEN_XR; // 493
/// Iesirea PRF pentru `t = 1`: cheie UIV noua + nonce nou.
pub const N1: usize = KLEN_UIV + BLK_LEN; // 80
/// Decalajul in blocuri dintre iesirile `t=0` si `t=1`.
pub const C_OFFSET: u128 = 31;

/// Cheia UIV+, 64 de octeti.
///
/// Aranjament: `J = (KB, KU)` in octetii 0..32, `S = (K, B)` in 32..64.
/// `KB` si `K` sunt chei AES, `KU` si `B` sunt chei POLYVAL.
#[derive(Clone, Zeroize, zeroize::ZeroizeOnDrop)]
pub struct UivKey(pub(crate) [u8; KLEN_UIV]);

impl core::fmt::Debug for UivKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("UivKey(redacted)")
    }
}

impl UivKey {
    pub fn from_bytes(b: [u8; KLEN_UIV]) -> Self {
        UivKey(b)
    }
    #[inline]
    fn kb(&self) -> &[u8; 16] {
        self.0[0..16].try_into().expect("aranjament fix")
    }
    #[inline]
    fn ku(&self) -> &[u8; 16] {
        self.0[16..32].try_into().expect("aranjament fix")
    }
    #[inline]
    fn k(&self) -> &[u8; 16] {
        self.0[32..48].try_into().expect("aranjament fix")
    }
    #[inline]
    fn b(&self) -> &[u8; 16] {
        self.0[48..64].try_into().expect("aranjament fix")
    }
}

// ---------------------------------------------------------------------------
// Nivelul 1: AES si CTR
// ---------------------------------------------------------------------------

fn aes_enc(key: &[u8; 16], block: &mut [u8; 16]) {
    let c = Aes128::new(key.into());
    c.encrypt_block(block.into());
}

fn aes_dec(key: &[u8; 16], block: &mut [u8; 16]) {
    let c = Aes128::new(key.into());
    c.decrypt_block(block.into());
}

/// `CTR_n(K, X)` — n octeti de flux AES in mod contor, pornind de la blocul `X`.
///
/// Contorul e blocul de 128 de biti interpretat big-endian, ca in NIST SP 800-38A.
fn ctr(key: &[u8; 16], start: u128, out: &mut [u8]) {
    let c = Aes128::new(key.into());
    let mut counter = start;
    for chunk in out.chunks_mut(BLK_LEN) {
        let mut blk = counter.to_be_bytes();
        c.encrypt_block((&mut blk).into());
        let n = chunk.len();
        chunk.copy_from_slice(&blk[..n]);
        counter = counter.wrapping_add(1);
    }
}

// ---------------------------------------------------------------------------
// Nivelul 2: ENC_ET / DEC_ET (LRW2) si PRF
// ---------------------------------------------------------------------------

/// `ENC_ET((KB,KU), T, M) = UH(KU,T) ^ ENC_BC(KB, M ^ UH(KU,T))`
///
/// Tweak-ul `T` e mereu `H | X_R`, deci il primim ca doua bucati ca sa evitam o
/// alocare de 510 octeti per celula per hop.
fn enc_et(key: &UivKey, tweak_a: &[u8], tweak_b: &[u8], m: &[u8; 16]) -> [u8; 16] {
    let mask = uh2(key.ku(), tweak_a, tweak_b);
    let mut blk = [0u8; 16];
    for i in 0..16 {
        blk[i] = m[i] ^ mask[i];
    }
    aes_enc(key.kb(), &mut blk);
    for i in 0..16 {
        blk[i] ^= mask[i];
    }
    blk
}

/// `DEC_ET((KB,KU), T, M) = UH(KU,T) ^ DEC_BC(KB, M ^ UH(KU,T))`
fn dec_et(key: &UivKey, tweak_a: &[u8], tweak_b: &[u8], m: &[u8; 16]) -> [u8; 16] {
    let mask = uh2(key.ku(), tweak_a, tweak_b);
    let mut blk = [0u8; 16];
    for i in 0..16 {
        blk[i] = m[i] ^ mask[i];
    }
    aes_dec(key.kb(), &mut blk);
    for i in 0..16 {
        blk[i] ^= mask[i];
    }
    blk
}

/// `MASK(x)` — sterge cei 6 biti de jos ai ultimului octet.
///
/// Contorul big-endian are astfel 64 de valori libere. `t=0` foloseste 31 de
/// blocuri (493 octeti), `t=1` incepe la decalajul 31 si foloseste 5 blocuri
/// (80 octeti). 36 < 64, deci cele doua fluxuri nu se suprapun niciodata.
fn mask_counter(x: [u8; 16]) -> u128 {
    let mut x = x;
    x[15] &= !0x3F;
    u128::from_be_bytes(x)
}

/// `PRF((K,B), T, t) = CTR_{nt}(K, MASK(UH(B,T)) + t*C)`
fn prf(key: &UivKey, input: &[u8; 16], t: bool, out: &mut [u8]) {
    let idx = mask_counter(uh(key.b(), input));
    let start = if t { idx.wrapping_add(C_OFFSET) } else { idx };
    ctr(key.k(), start, out);
}

// ---------------------------------------------------------------------------
// Nivelul 3: UIV+
// ---------------------------------------------------------------------------

/// `ENC_UIV((J,S), H, (X_L, X_R))`. Lucreaza pe loc peste o celula de 509 octeti,
/// unde primii 16 sunt `X_L` si restul `X_R`.
///
/// **Nemaleabil.** Folosit de relee.
pub fn enc_uiv(key: &UivKey, h: &[u8; HLEN_UIV], cell: &mut [u8; MSG_LEN]) {
    let mut x_l = [0u8; BLK_LEN];
    x_l.copy_from_slice(&cell[..BLK_LEN]);

    // Y_L <- ENC_ET(J, H | X_R, X_L)
    let y_l = enc_et(key, h, &cell[BLK_LEN..], &x_l);

    // Y_R <- X_R ^ PRF(S, Y_L, 0)
    let mut stream = [0u8; N0];
    prf(key, &y_l, false, &mut stream);
    for i in 0..LEN_XR {
        cell[BLK_LEN + i] ^= stream[i];
    }
    stream.zeroize();
    cell[..BLK_LEN].copy_from_slice(&y_l);
    x_l.zeroize();
}

/// `DEC_UIV((J,S), H, (Y_L, Y_R))`.
///
/// **Maleabil.** Folosit de clienti. Nu inversa directiile.
pub fn dec_uiv(key: &UivKey, h: &[u8; HLEN_UIV], cell: &mut [u8; MSG_LEN]) {
    let mut y_l = [0u8; BLK_LEN];
    y_l.copy_from_slice(&cell[..BLK_LEN]);

    // X_R <- Y_R ^ PRF(S, Y_L, 0)
    let mut stream = [0u8; N0];
    prf(key, &y_l, false, &mut stream);
    for i in 0..LEN_XR {
        cell[BLK_LEN + i] ^= stream[i];
    }
    stream.zeroize();

    // X_L <- DEC_ET(J, H | X_R, Y_L)
    let x_l = dec_et(key, h, &cell[BLK_LEN..], &y_l);
    cell[..BLK_LEN].copy_from_slice(&x_l);
    y_l.zeroize();
}

/// `UPDATE_UIV((J,S), N) -> ((J',S'), N')`
///
/// Ratchet-ul care da forward secrecy imediata: dupa actualizare, cheia veche nu
/// mai exista, deci celulele deja procesate nu mai pot fi decriptate nici de
/// posesorul starii curente.
pub fn update_uiv(key: &mut UivKey, n: &[u8; BLK_LEN]) -> [u8; BLK_LEN] {
    let mut out = [0u8; N1];
    prf(key, n, true, &mut out);

    let mut new_key = [0u8; KLEN_UIV];
    new_key.copy_from_slice(&out[..KLEN_UIV]);
    let mut new_n = [0u8; BLK_LEN];
    new_n.copy_from_slice(&out[KLEN_UIV..]);

    key.0.zeroize();
    key.0 = new_key;
    out.zeroize();
    new_n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheie(seed: u8) -> UivKey {
        let mut k = [0u8; KLEN_UIV];
        for (i, b) in k.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8).wrapping_mul(37);
        }
        UivKey::from_bytes(k)
    }

    fn celula(seed: u8) -> [u8; MSG_LEN] {
        let mut c = [0u8; MSG_LEN];
        for (i, b) in c.iter_mut().enumerate() {
            *b = seed.wrapping_add((i % 251) as u8);
        }
        c
    }

    #[test]
    fn constantele_sunt_cele_din_propunerea_359() {
        assert_eq!(MSG_LEN, 509);
        assert_eq!(BLK_LEN, 16);
        assert_eq!(LEN_XR, 493);
        assert_eq!(HLEN_UIV, 17);
        assert_eq!(KLEN_UIV, 64);
        assert_eq!(N0, 493);
        assert_eq!(N1, 80);
        assert_eq!(C_OFFSET, 31);
        // Cele doua fluxuri PRF nu se suprapun: 31 blocuri + 5 blocuri < 64.
        let blocuri_t0 = N0.div_ceil(BLK_LEN);
        let blocuri_t1 = N1.div_ceil(BLK_LEN);
        assert!(C_OFFSET as usize >= blocuri_t0);
        assert!(C_OFFSET as usize + blocuri_t1 <= 64);
    }

    #[test]
    fn et_e_inversabil() {
        let k = cheie(1);
        let ta = [7u8; HLEN_UIV];
        let tb = [9u8; LEN_XR];
        let m = [0x42u8; 16];
        let c = enc_et(&k, &ta, &tb, &m);
        assert_ne!(c, m);
        assert_eq!(dec_et(&k, &ta, &tb, &c), m);
    }

    #[test]
    fn et_depinde_de_tweak() {
        let k = cheie(2);
        let m = [0x11u8; 16];
        let tb = [0u8; LEN_XR];
        let a = enc_et(&k, &[1u8; HLEN_UIV], &tb, &m);
        let b = enc_et(&k, &[2u8; HLEN_UIV], &tb, &m);
        assert_ne!(a, b, "tweak diferit trebuie sa dea rezultat diferit");
    }

    #[test]
    fn prf_separa_cele_doua_iesiri() {
        let k = cheie(3);
        let inp = [5u8; 16];
        let mut a = [0u8; N0];
        let mut b = [0u8; N1];
        prf(&k, &inp, false, &mut a);
        prf(&k, &inp, true, &mut b);
        // Fluxul t=1 nu trebuie sa apara nicaieri in fluxul t=0.
        assert!(
            !a.windows(N1).any(|w| w == b),
            "fluxurile PRF se suprapun"
        );
    }

    #[test]
    fn uiv_e_inversabil() {
        let k = cheie(4);
        let h = [3u8; HLEN_UIV];
        let orig = celula(7);
        let mut c = orig;
        enc_uiv(&k, &h, &mut c);
        assert_ne!(c, orig);
        dec_uiv(&k, &h, &mut c);
        assert_eq!(c, orig);
    }

    #[test]
    fn uiv_difuzeaza_complet() {
        // O modificare de un bit in intrare trebuie sa schimbe tot tag-ul.
        // Asta e proprietatea de wide-block care da rezistenta la tagging.
        let k = cheie(5);
        let h = [0u8; HLEN_UIV];
        let mut a = celula(1);
        let mut b = celula(1);
        b[MSG_LEN - 1] ^= 0x01; // ultimul octet din X_R
        enc_uiv(&k, &h, &mut a);
        enc_uiv(&k, &h, &mut b);
        assert_ne!(&a[..BLK_LEN], &b[..BLK_LEN], "tag-ul nu s-a schimbat");
        let diferite = a.iter().zip(b.iter()).filter(|(x, y)| x != y).count();
        assert!(
            diferite > MSG_LEN / 2,
            "difuzie insuficienta: doar {diferite} octeti difera"
        );
    }

    #[test]
    fn update_schimba_cheia_si_nonce_ul() {
        let mut k = cheie(6);
        let vechi = k.0;
        let n = [1u8; BLK_LEN];
        let n_nou = update_uiv(&mut k, &n);
        assert_ne!(k.0, vechi, "cheia trebuie sa se schimbe");
        assert_ne!(n_nou, n, "nonce-ul trebuie sa se schimbe");
    }

    #[test]
    fn update_e_determinist() {
        let mut a = cheie(7);
        let mut b = cheie(7);
        let n = [2u8; BLK_LEN];
        assert_eq!(update_uiv(&mut a, &n), update_uiv(&mut b, &n));
        assert_eq!(a.0, b.0);
    }
}
