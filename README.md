# pqonion

Platformă distribuită pentru comunicații anonime cu criptografie post-cuantică.
Proiect de diplomă. Pașii 1 și 2 din MVP-ul de semestrul II.

```bash
rm Cargo.lock          # e pinuit pentru un toolchain vechi, vezi la final
cargo test
cargo run -p pqo-wire --example cost_circuit
cargo run -p pqo-crypto --example handshake --features pq
```

Rust >= 1.81 pentru feature-ul `pq`. Fără el crate-urile compilează pe 1.75, dar
`pqo-crypto` folosește X25519 în loc de ML-KEM.

## Stare

| Crate | Conținut | Teste |
|---|---|---|
| `pqo-crypto` | KDF, trait `Kem`, trait `Sig`, `pq-ntor-v1`, criptare CGO | 56 |
| `pqo-wire` | Celule link-layer, mesaje relay, fragmentare, mesaje de protocol | 34 |
| `pqo-dirproto` | Formate canonice: descriptor, vot, consens; base64, hex | 18 |
| `pqo-dirauth` | Algoritmul determinist de fuziune a voturilor | 14 |
| `pqo-hs` | Adrese `.onion` post-cuantice, descriptori, HSDir, rendezvous | 56 |
| `pqo-relay` | Legătură, rutare de circuite, stream-uri de exit, **sans-io** | 49 |
| `pqo-relay-io` | Încadrare de celule, noduri pe tokio, client cu stream-uri | 23 |
| `pqo-client` | Selecție de cale din consens, guard-uri persistente, SOCKS5 | 26 |
| `pqo-bin` | Config, chei persistente, logging; **patru executabile** | 13 |
| integrare | Circuit; proxy; bootstrap; procese; **servicii ascunse în rețea** | 59 |

371 de teste, toate trec.

```bash
./testnet.sh                # porturi fixe 9001-9003, SOCKS 9050
./testnet.sh --auto-port    # dacă ai deja ceva pornit pe ele
```

Scriptul **verifică fiecare pas** și se oprește la prima problemă: porturi
ocupate, proces care moare la pornire, publicare eșuată, sau cerere HTTP care nu
trece prin circuit. Ultimul pas pornește un server local și face o cerere reală
prin proxy — dacă scriptul spune `TESTNET FUNCTIONAL`, chiar funcționează.

**Proxy funcțional.** Un client deschide un stream printr-un circuit de 3 hopuri,
releul de ieșire conectează TCP la destinație, și datele curg în ambele sensuri
cu control de flux pe două niveluri. Testul `proxy_cap_coada_prin_trei_hopuri`. Zero warning-uri. `#![forbid(unsafe_code)]` pe ambele crate-uri.

**Un circuit funcționează cap-coadă.** `tests/integrare_circuit.rs` construiește
un circuit de 3 hop-uri prin CREATE2 și două EXTEND2 fragmentate și criptate,
apoi trimite trafic bidirecțional 20 de runde și verifică că nu divergă.

## Rezultatul central

```
schema                 varianta          EXT2   EXTD2  cel. E/R    total  octeti fir
X25519+ML-KEM-768      Transitional      1359    1186       3/3       12        8684
X25519+ML-KEM-768      FullPq            2479    1186       6/3       18       12888
ntor clasic (Tor)      —                  131      66       1/1        4        3084
```

Construirea unui circuit de 3 hop-uri costă **2.8x** (Transitional) sau **4.2x**
(FullPq) mai mulți octeți pe fir decât în Tor. Numărul de celule crește de la 4
la 12 sau 18. Ăsta e rezultatul empiric central al lucrării — regenerează tabelul
cu `cargo run -p pqo-wire --example cost_circuit`, se calculează din formatele
reale de mesaj, nu e scris de mână.

Cifrele s-au schimbat când am adăugat CGO: tag-ul de autentificare consumă 16
octeți din payload, deci datele utile per celulă au scăzut de la 503 la 487, iar
EXTEND2 în varianta FullPq a trecut de la 5 celule la 6. Merită menționat în
lucrare ca exemplu de cuplaj între straturi.

## Criptarea celulelor: CGO

Implementat conform propunerii 359 a Tor și lucrării Degabriele–Melloni–Münch–Stam
(eprint 2025/583). Înlocuiește `tor1` (AES-128-CTR + digest SHA-1 pe 4 octeți).

| Proprietate | tor1 | CGO |
|---|---|---|
| Autentificare | 4 octeți | 16 octeți |
| Rezistență la tagging | nu | da (wide-block, nemaleabil) |
| Forward secrecy | nu (aceeași cheie pe tot circuitul) | imediată (ratchet per celulă) |
| SHA-1 | da | nu |

Structura urmează nivelurile din propunere: POLYVAL (RFC 8452) → LRW2 + PRF →
UIV+ → algoritmii onion.

