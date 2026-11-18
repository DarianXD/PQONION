# Ghid de parcurgere a codului

Documentul descrie, pentru fiecare crate, **ce am urmărit**, **ce am decis** și
**de ce**. Deciziile de aici sunt cele scrise în documentația de modul din cod —

---

## Principiul care organizează totul

Crate-urile sunt ordonate după dependențe, iar dependențele merg **într-o singură
direcție**. `pqo-crypto` nu depinde de nimic din proiect; `pqo-bin` depinde de
toți. Poți citi de sus în jos fără să dai vreodată peste un tip pe care nu l-ai
văzut definit.

Există o singură linie care contează cu adevărat, între `pqo-relay` și
`pqo-relay-io`: **deasupra ei nu există `async` deloc**. Motivul e explicat la
`pqo-relay`.

---

## 1. `pqo-crypto` — 2.103 linii, 916 de test

### Ce am urmărit

Ca primitivele să fie **interschimbabile**, astfel încât să pot compara scheme
fără să rescriu protocolul. Fiecare tabel de măsurători din lucrare există pentru
că același cod rulează cu X25519, cu ML-KEM-768 și cu hibridul lor, doar
schimbând un parametru de tip.

### Decizia de fond: acest crate nu implementează primitive

Le **compune**. Toate primitivele vin din biblioteci verificate: `sha3` și
`x25519-dalek` din RustCrypto/dalek, `ml-kem` pentru partea post-cuantică.

Motivul e simplu: o implementare proprie de curbă eliptică într-o lucrare de
licență ar fi fost o sursă de erori pe care nimeni nu le-ar fi găsit. Ce
implementez sunt *construcțiile* — handshake-ul, derivarea de chei, criptarea de
celule — pentru că alea sunt subiectul.

### Cele patru invariante

Scrise în `lib.rs` și verificate:

1. **Zero `unsafe`.** Verificat de compilator prin `#![forbid(unsafe_code)]`.
2. **Niciun tip cu material de cheie nu implementează `Clone`**, și `Debug` nu
   afișează conținut real. Vezi testul `debug_nu_scurge_chei`.
3. **Toate comparațiile de valori secrete sunt în timp constant**, prin `subtle`.
4. **Niciun parser nu poate produce panică** pe input arbitrar. Vezi
   `lungimi_gresite_sunt_respinse_fara_panica`.

Al doilea invariant e cel mai ușor de încălcat accidental: un `#[derive(Debug)]`
pus din reflex ar fi scurs chei în log-uri.

### Fișiere, în ordinea de citire

| Fișier | Linii | Ce conține |
|---|---|---|
| `kem.rs` | 371 | trait-ul `Kem`, X25519-ca-KEM, ML-KEM-768, combinerul `Hybrid<A,B>` |
| `sig.rs` | 262 | trait-ul `Sig`, Ed25519, ML-DSA, `HybridSig<A,B>` |
| `kdf.rs` | 171 | SHAKE256 cu separare de domeniu, `ShakeRng` |
| `ntor.rs` | 501 | handshake-ul `pq-ntor-v1` |
| `cgo/polyval.rs` | 152 | înmulțirea în GF(2¹²⁸) |
| `cgo/primitives.rs` | 220 | LRW2, PRF |
| `cgo/onion.rs` | 327 | UIV+, criptarea per hop, ratchet |

**Începe cu `kem.rs`.** Trait-ul se citește în zece minute și explică de ce restul
arată așa. `Hybrid<A,B>` e cheia: implementează `Kem` compunând alte două, deci
`Hybrid<X25519Kem, MlKem768>` e el însuși un `Kem` pe care protocolul îl folosește
fără să știe ce e înăuntru.

### `kdf.rs` — de ce separare de domeniu

Fiecare derivare are o etichetă distinctă. Fără ea, aceeași intrare folosită în
două scopuri ar produce aceeași cheie, iar un adversar ar putea muta o valoare
dintr-un context în altul.

`ShakeRng` e un generator determinist dintr-o sămânță. Există pentru ca releele
de testnet să aibă chei reproductibile — clientul le poate deriva fără să descarce
descriptori. **Nu se folosește nicăieri pentru chei reale.**

### `ntor.rs` — punctul central

Handshake-ul are două variante:

- **`Transitional`** — X25519 efemer + KEM efemer. Confidențialitate
  post-cuantică, autentificare clasică.
- **`FullPq`** — adaugă un KEM static la releu, deci autentificare post-cuantică.
  Costă +1088 octeți per salt.

Distincția vine din asimetria descrisă în lucrare: autentificarea se verifică în
momentul folosirii, deci compromiterea ei viitoare nu afectează circuitele
trecute. Confidențialitatea, în schimb, e retroactivă.

**Ce merită urmărit în cod:** derivarea include *întregul transcript* —
identificatorul releului, cheile publice, textul cifrat. Fără asta, două execuții
diferite ar putea produce aceeași intrare pentru KDF.

### `cgo/polyval.rs` — locul unde era cel mai instructiv bug

Funcția `dot(a, b) = a · b · x⁻¹²⁸`. **Nu** e înmulțire simplă în GF(2¹²⁸).

Implementarea inițială o făcea ca înmulțire obișnuită. Toate testele scrise de
mine treceau — comutativitate, asociativitate, distributivitate, element neutru —
pentru că ambele operații sunt înmulțiri într-un corp finit și satisfac aceleași
proprietăți.

A fost prinsă exclusiv de vectorul de test din RFC 8452.

**Lecția, și motivul pentru care merită citit acest fișier primul dintre cele din
`cgo/`:** proprietățile algebrice nu identifică operația.

### `cgo/onion.rs` — asimetria

Clientul aplică **întotdeauna** `DEC_UIV`, releul **întotdeauna** `ENC_UIV`,
indiferent de sensul în care circulă datele.

Motivul: doar `ENC_UIV` e nemaleabilă, iar partea nemaleabilă trebuie să fie la
releu. Altfel un adversar ar putea modifica o celulă în tranzit astfel încât
modificarea să se propage previzibil, marcând circuitul pentru recunoaștere
ulterioară — atacul de tip *tagging*.

Ratchet-ul per celulă: cheile se actualizează după fiecare celulă. Consecința pe
care trebuie s-o ții minte când citești `pqo-relay-io`: **o celulă pierdută nu e
degradare, e corupere.** De aceea nicio coadă internă nu are voie să arunce
celule.

---

## 2. `pqo-wire` — 1.274 linii, 1.012 de test

### Ce am urmărit

Formatul de fir separat complet de orice logică. Acest crate **nu conține
criptografie**. Conține parsere.

### Invariantul central

**Niciun parser nu poate produce panică pentru niciun input.** Totul intră prin
`Result`, toate accesele în buffer sunt verificate, fiecare parser are o țintă de
fuzzing.

Motivul e că aceste parsere procesează octeți veniți de la un adversar. O panică
înseamnă oprirea releului, deci refuz de serviciu gratuit.

### Straturile

| Fișier | Linii | Nivel |
|---|---|---|
| `cell.rs` | 256 | celule de canal: fixe (514B) și variabile |
| `relay.rs` | 388 | mesaje relay în interiorul celulelor, cu fragmentare |
| `msg.rs` | 244 | mesaje tipizate: CREATE2, EXTEND2, ... |
| `stream.rs` | 285 | BEGIN/DATA/END, ferestre de control de flux |

`StreamKind::Either` se află în `relay.rs`, nu în `stream.rs` — SENDME e legitim
pe ambele niveluri, deci nu poate fi clasificat static.

### Cifrele care contează

```
514 pe fir → 509 payload → 493 corp după tag CGO → 487 utili
```

Ține minte 487. Din el decurge fragmentarea, și tot din el decurge faptul că un
mesaj de tunel (509 octeți) ocupă **două** celule.

### `stream.rs` — controlul de flux pe două niveluri

Ferestre separate pentru circuit (1000 de celule, SENDME la 100) și pentru flux
(500, SENDME la 50). Un `SENDME` primit poate aparține oricăruia, de unde
`StreamKind::Either` — definit în `relay.rs:190`, cu explicația la linia 156.

Motivul celor două niveluri: fără fereastra de circuit, un singur flux lent ar
putea umple memoria releului; fără cea de flux, un flux rapid ar înfometa restul
fluxurilor din același circuit.

---

## 3. `pqo-dirproto` — 1.241 linii, 519 de test

### Ce am urmărit

**Canonicitatea.** Aceeași informație trebuie să producă exact aceiași octeți, la
fiecare autoritate, de fiecare dată. Fără asta semnăturile nu se potrivesc și
consensul nu se formează.

### Cele trei locuri unde se impune, toate necesare

1. **La serializare** — sortări fixe, ordine fixă a câmpurilor.
2. **La parsare** — orice formă necanonică e **respinsă**, nu normalizată.
3. **La verificare** — semnătura se verifică pe prefixul **recalculat** din
   structura parsată, nu pe textul primit.

Punctul 3 e cel mai important și cel mai ușor de omis. El închide clasa de
atacuri *parser differential*: două implementări care citesc același document
diferit nu pot ajunge amândouă să creadă că semnătura e validă.

Merită să te uiți la `parse_and_verify` din `netdoc.rs` ca să vezi cum e făcut.

### Fișiere

`netdoc.rs` (538) — descriptori de releu, voturi, consens. `doc.rs` (240) —
`Builder` și parserul de linii. `dirreq.rs` (379) — cereri de director prin
circuit, cu încadrare cu prefix de lungime.

---

## 4. `pqo-dirauth` — 259 linii, 337 de test

### De ce începi cu acesta

**259 de linii, complet autonom, reguli deterministe.** Îl poți reproduce din
descriere într-o zi. Nu ca să înveți sistemul, ci ca să afli dacă metoda ta de
lucru funcționează.

### Invariantul

Toate autoritățile trebuie să producă **exact aceiași octeți**. Nu „același
conținut" — aceiași octeți.

De aici decurge o regulă care ți se va părea excesivă până înțelegi de ce:
**iterarea peste un `HashMap` e interzisă în acest modul.** Ordinea ei depinde de
o sămânță aleatoare per proces, deci două autorități ar produce documente
diferite.

### Regulile de fuziune

| Ce | Regulă |
|---|---|
| Includerea unui releu | apare în cel puțin `n/2 + 1` voturi |
| Banda | mediana valorilor, plafonată |
| Adresa și portul | perechea majoritară; la egalitate, cea mai mică lexicografic |
| Fiecare flag | setat de cel puțin `m/2 + 1` din voturile care listează releul |
| Ordine | relee după fingerprint, parametri după nume |

Observă „cea mai mică lexicografic": fiecare loc unde ar putea apărea egalitate
are o regulă de departajare. Nu pentru că e elegant, ci pentru că altfel
consensul nu se formează.

### Ce nu face, declarat explicit

Nu măsoară banda. Folosește valoarea auto-raportată, plafonată. Într-un
deployment real e exploatabil: un releu își declară o bandă uriașă și vede mai
multe circuite.

---

## 5. `pqo-hs` — 1.941 linii, 2.154 de test

**Subiectul lucrării.** Raportul teste/cod e 1,1 — cel mai mare din proiect.

### Ce am urmărit

O identitate de serviciu ascuns care rezistă unui adversar cuantic, fără să
crească lungimea adresei.

### Decizia centrală, și ce pierde

Tor v3 obține trei proprietăți simultan din blinding-ul algebric Ed25519. ML-DSA
nu are operația de grup care face asta posibilă.

Schema de aici păstrează două și o pierde pe a treia:

| Proprietate | Tor v3 | aici |
|---|---|---|
| Lungimea adresei | 56 caractere | 56 caractere |
| Clientul calculează indexul din adresă | da | da |
| HSDir nu poate lega perioadele | da | da, și post-cuantic |
| **HSDir verifică proprietatea slotului** | da | **nu** |
| Impersonare sub calculator cuantic | posibilă | **imposibilă** |

Pierderea e limitată la refuz de serviciu, și e atenuată prin contor de revizie,
regula primului publicator și replicare. Vezi `hsdir::DescStore`.

### Ordinea de citire, scrisă în `lib.rs`

1. **`addr.rs`** (189) — de unde vine adresa. `from_identity` e trei linii și e
   contribuția centrală a lucrării.
2. **`blind.rs`** (156) — cum se derivă indexul și cheile per perioadă.
3. **`desc.rs`** (695) — cele două straturi ale descriptorului, plus autorizarea
   clientului.
4. **`hsdir.rs`** (236) — inelul, replicarea, unde se stochează.
5. **`rend.rs`** (416) — cum se ajunge la o conexiune.

### `desc.rs` — ce merită urmărit

Cele două straturi: exteriorul e vizibil directorului, interiorul nu. Cheia
interiorului se derivă din adresă — **sau**, cu autorizare, e aleatoare și
încapsulată către fiecare client.

Cele trei proprietăți de confidențialitate ale autorizării:

- intrările nu conțin identificatori — nu se știe **cine** sunt clienții
- se completează până la un multiplu de 8 — nu se știe **câți** sunt
- masca include indexul și revizia — nu se pot lega două publicări

Ultimele două par cosmetice. Nu sunt: fără ele, lista de acces ar fi vizibilă în
evoluția ei.

---

## 6. `pqo-relay` — 1.884 linii, 1.307 de test

### Decizia care organizează tot proiectul

Nimic din acest crate nu deschide socket-uri, nu folosește `async`, nu depinde de
un runtime. Fiecare metodă are forma:

```
(stare, eveniment) → Vec<Action>
```

Coaja de I/O se ocupă doar să pompeze octeți și să execute acțiunile.

### Motivele, în ordinea importanței

**1. Calea critică nu are async.** Verificarea semnăturilor, decizia de rutare și
actualizarea stării CGO se întâmplă în cod sincron. Nu pot exista curse pe starea
criptografică, pentru că **nu există `.await` între citirea și scrierea ei**.

Dacă două fire ar ajunge simultan la actualizarea cheilor CGO, ar deriva același
flux de chei pentru celule diferite. E o eroare care compromite confidențialitatea
și care se manifestă rar, sub sarcină. Aici devine imposibilă prin construcție, nu
improbabilă.

**2. Testele sunt deterministe.** Fiecare scenariu de eroare — ordine greșită,
circuit necunoscut, canal căzut la mijlocul unei extinderi — se verifică fără
rețea și fără timeout-uri.

**3. Runtime-ul e înlocuibil.**

**Costul**, declarat: coaja de I/O trebuie să țină evidența canalelor și să
traducă între identificatorii ei și `ChannelId`. E cod plictisitor, dar e cod
plictisitor *izolat*.

### Fișiere

| Fișier | Linii | Ce conține |
|---|---|---|
| `link.rs` | 469 | handshake-ul de legătură, ca mașină de stări |
| `circuit.rs` | 518 | tabela de circuite, rutarea celulelor |
| `stream.rs` | 450 | tabela de fluxuri, politica de ieșire |
| `service.rs` | 328 | puncte de introducere și rendezvous |

### `link.rs` — `AuthMode::Optional`

Releul care ascultă **nu știe dinainte** dacă cel care se conectează e un client
(anonim) sau un releu (autentificare reciprocă). De aceea modul e `Optional`:
acceptă ambele.

E o subtilitate ușor de ratat, și e motivul pentru care mașina de stări are mai
multe ramuri decât te-ai aștepta.

### `stream.rs` — politica de ieșire

Verifică doar **literalele** din cerere. Un nume de domeniu care rezolvă la o
adresă privată trece de aici — de aceea stratul de rețea reverifică **după
rezolvare**. Vezi `is_private_addr`.

Aceasta a fost o gaură reală, documentată în cod dar nereparată câteva versiuni.

---

## 7. `pqo-relay-io` — 2.692 linii, 1.899 de test

### Ce face

`pqo-relay` decide *ce* trebuie făcut; acest crate se ocupă *să se întâmple*. Tot
codul cu `async` trăiește aici.

### Transportul

Generic peste `AsyncRead + AsyncWrite`, deci același cod servește TCP simplu și
TLS. Alegerea se face la rulare, prin `node::Transport`.

Peste TCP simplu, `ChannelBinding::insecure_plaintext_tcp` marchează faptul că nu
există nimic de legat — **numele tipului o spune raspicat**, ceea ce a fost
intenționat: era un marcaj care trebuia să deranjeze până se implementa TLS.

Cu TLS, legarea vine din exportul de material de cheie (RFC 8446 §7.5) și
împiedică mutarea unui handshake valid pe altă conexiune.

### Fișiere

| Fișier | Linii | Ce conține |
|---|---|---|
| `node.rs` | 1.296 | bucla de evenimente, accept, dial, pump |
| `client.rs` | 667 | `Circuit`, extindere, tunel, cereri de director |
| `tls.rs` | 192 | certificate efemere, legarea de canal |
| `codec.rs` | 178 | citire de celule, **cancel-safe** |
| `metrici.rs` | 145 | contoare agregate |
| `tunnel.rs` | 143 | hopul virtual |

### `node.rs` — cel mai greu fișier din proiect

1.296 de linii, și aici erau bug-urile pe care le-am reparat ultimele. **Lasă-l la
sfârșit.**

Ce merită urmărit: bucla `core_loop` primește evenimente, le dă lui `pqo-relay`, și
execută acțiunile rezultate. Toată complexitatea e în traducerea dintre
identificatorii de canal ai celor două straturi.

### `codec.rs` — cancel-safety

`read_cell` nu are voie să modifice starea înainte de un `.await`. Prima versiune
făcea `buf.resize()` înainte, iar anularea într-un `tokio::select!` lăsa 8 KB de
zerouri, interpretate ca celule PADDING.

E singura clasă de eroare pe care Rust nu o previne și care nu are echivalent în
programarea sincronă. Merită citit fișierul întreg — are 178 de linii.

### `metrici.rs` — ce nu se măsoară

Toate contoarele sunt **agregate pe întreg releul**. Niciunul nu poate fi atribuit
unui circuit sau unui peer.

Nu e lene. Un releu care ar ține „circuitul X a transportat N celule către Y" ar
avea pe disc exact ce îi trebuie unui adversar. Cine ia serverul ia și corelațiile.

---

## 8. `pqo-client` — 553 linii, 934 de test

Două module cu roluri clar separate.

**`path.rs`** (308) — alege pe unde merge circuitul. Aici trăiesc deciziile de
securitate.

Ordinea alegerii: **exit primul**, apoi guard, apoi hopurile din mijloc. Vezi
comentariul de la `path.rs:251`. Exit-ul e poziția cea mai constrânsă — trebuie
să permită portul cerut — deci se alege primul. Ordinea inversă producea `NoExit`
când guard-ul ales era singurul exit posibil.

Guard-urile sunt persistente. Riscul se mută din „sigur, la un moment dat" în
„improbabil, dar tot sau nimic".

**`socks.rs`** (196) — traduce cererile aplicațiilor. Aici trăiește singura
problemă de anonimitate pe care clientul **nu o poate rezolva singur**: dacă
aplicația rezolvă numele local, DNS-ul a plecat deja în clar. De aceea clientul
numără cererile cu IP literal și avertizează.

---

## 9. `pqo-bin` — 2.621 linii, 1.605 de test

Infrastructura comună a celor cinci executabile.

### Politica de logging — decizia care merită citită

Într-un sistem de anonimitate, logging-ul e o **vulnerabilitate**, nu o
comoditate.

Nivelurile care ar putea scurge identificatori **nu există în build de release**:
sunt compilate afară prin `cfg(debug_assertions)`. Nu sunt „oprite implicit" — nu
se pot activa deloc.

| Nivel | Ce se scrie | În release |
|---|---|---|
| ERROR | erori de protocol, fără identificatori | da |
| WARN | handshake-uri eșuate, agregat | da |
| INFO | statistici agregate | da |
| DEBUG | ID-uri de circuit, fingerprint-uri | **nu** |
| TRACE | conținut de celule, material de cheie | **nu** |

### Fișiere

`lib.rs` (596) — argumente, chei, logging, `circuit_catre`. `consola.rs` (242) —
consola web, doar agregate. Cele patru binare: `relay.rs` (442), `hs.rs` (548),
`client.rs` (542), `dirauth.rs` (251).

### `circuit_catre` — funcția care a lipsit

Construiește un circuit de trei salturi care se **termină** la releul dat. Prima
versiune a binarelor se conecta direct, iar punctul de introducere vedea adresa
reală a serviciului.

`tests/hopuri.rs` (205) verifică proprietatea, nu funcționalitatea.

---

## 10. `pqo-shop` — 1.440 linii, 1.206 de test

Există ca să arate că platforma transportă trafic real, nu octeți de test.

Aceeași structură ca restul proiectului:

- **`model.rs`** (458) — regulile de afacere, fără HTTP
- **`http.rs`** (315) — parsare și serializare, fără I/O
- **`api.rs`** (488) — semantica REST, ca funcție pură `(stare, cerere) → răspuns`

Serverul e o coajă de 158 de linii peste tokio. 51 din cele 57 de teste rulează
fără socket-uri.

---

## Cum aș citi, dacă aș fi în locul tău

| Zile | Ce | De ce |
|---|---|---|
| 1 | `pqo-dirauth` | 259 linii, autonom. Test dacă metoda funcționează. |
| 2–5 | `pqo-crypto` | Miezul. `kem.rs` → `ntor.rs` → `cgo/` |
| 6–7 | `pqo-hs` | Subiectul lucrării |
| 8 | `pqo-wire` | Formatul de fir |
| 9–10 | `pqo-relay` | Logica, fără I/O |
| 11–13 | restul | La nivel de arhitectură |
| 14–15 | rezervă | Va merge ceva prost |

**Testele sunt cea mai bună documentație.** Fiecare are un comentariu care spune
*de ce* există, nu doar ce verifică. Citește-le înaintea codului pe care îl
testează — vei ști ce cauți.

**Testul care contează** nu e „am citit tot". E: acoperi ecranul, deschizi un
fișier gol, scrii modulul din specificație. Dacă îl reproduci, îl stăpânești.
