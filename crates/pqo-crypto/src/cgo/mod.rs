//! Counter Galois Onion — criptarea celulelor relay, conform propunerii 359 a
//! Tor si lucrarii Degabriele–Melloni–Münch–Stam (eprint 2025/583).
//!
//! Inlocuieste `tor1` (AES-128-CTR + digest SHA-1 pe 4 octeti). Ce castigam:
//!
//! | Proprietate | tor1 | CGO |
//! |---|---|---|
//! | Autentificare | 4 octeti | 16 octeti |
//! | Rezistenta la tagging | nu | da (wide-block, nemaleabil) |
//! | Forward secrecy | nu (aceeasi cheie pe tot circuitul) | imediata (ratchet per celula) |
//! | SHA-1 | da | nu |
//!
//! Structura modulului urmeaza nivelurile din propunere:
//!   - [`polyval`]    — nivelul 1, hash-ul universal (RFC 8452)
//!   - [`primitives`] — nivelurile 2 si 3: LRW2, PRF, UIV+
//!   - [`onion`]      — nivelul 4: algoritmii de client si de releu
//!
//! # Limitari fata de propunerea 359
//!
//! 1. `ENC_BC` e AES-128, ca in lucrare. Propunerea noteaza intentia de a trece
//!    la AES-192/256. Pentru rezistenta la Grover, AES-128 da ~64 de biti
//!    efectivi, ceea ce e sub prag. **De schimbat inainte de versiunea finala**;
//!    e o modificare de cateva linii in `primitives.rs`, dar schimba `KLEN_BC`
//!    si deci si `KLEN_UIV`.
//! 2. Nu am implementat SENDME-urile autentificate (sectiunea corespunzatoare
//!    din propunere cere tag-ul `T` al celei de-a 100-a celule).
//! 3. Nu am verificat fata de vectorii de test oficiali

pub mod onion;
pub mod polyval;
pub mod primitives;

pub use onion::{CgoError, ClientCircuit, Outbound, RelayCircuit, KEY_MATERIAL_LEN};
pub use primitives::{BLK_LEN, LEN_XR, MSG_LEN};
