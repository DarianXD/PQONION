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

## Rezultatul central de până acum

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

**Capcana pe care am nimerit-o și merită pusă în lucrare:** POLYVAL nu e
înmulțire obișnuită în GF(2^128). RFC 8452 definește `dot(a,b) = a·b·x⁻¹²⁸`, o
înmulțire de tip Montgomery. Prima implementare folosea înmulțirea directă și
trecea *toate* testele de consistență internă — comutativitate, distributivitate,
element neutru — dar pica vectorul oficial din RFC. E cel mai bun argument
practic pentru care testele de proprietate nu înlocuiesc vectorii externi.

**Asimetria client/releu.** În `tor1` ambele părți făceau același lucru. În CGO
clientul folosește **întotdeauna** `DEC_UIV` și releul **întotdeauna** `ENC_UIV`,
în ambele direcții, pentru că `ENC_UIV` e nemaleabil iar `DEC_UIV` nu e. Dacă
inversezi direcțiile compilează, testele de roundtrip trec, și pierzi exact
rezistența la tagging pentru care există toată construcția. Consecință pentru
serviciile ascunse: pe hop-ul virtual, **serviciul joacă rolul de releu**.

**Limitări față de propunerea 359, de documentat:**
1. `ENC_BC` e AES-128, ca în lucrare. Pentru marja Grover ar trebui AES-256
   (AES-128 dă ~64 biți efectivi). E o schimbare de câteva linii, dar modifică
   `KLEN_BC` și deci `KLEN_UIV`. **De făcut înainte de versiunea finală.**
2. SENDME-urile autentificate nu sunt implementate.
3. Nu am verificat față de vectorii de test oficiali CGO (sunt la
   `gitlab.torproject.org/nickm/cgo-drafts`). POLYVAL și AES sunt verificate
   față de RFC 8452 și NIST; compunerea nu. **Ăsta e primul lucru de făcut.**

## Sistemul de director

`pqo-dirproto` definește formatele, `pqo-dirauth` calculează consensul.

**Invariantul central e canonicitatea.** Toate autoritățile trebuie să producă
exact aceiași octeți din aceleași voturi — nu „același conținut", aceiași octeți.
Dacă două autorități diferă cu un caracter, semnăturile lor se aplică pe
documente diferite și niciun client nu atinge pragul. De aici decurg toate
regulile: mediana în loc de medie, departajare lexicografică la egalitate,
sortări explicite, și interdicția de a itera peste un `HashMap` în `pqo-dirauth`
(ordinea lui depinde de o sămânță aleatoare per proces).

**Verificarea se face pe prefixul recalculat, nu pe textul primit.** După
parsare, documentul se re-serializează din structură și se compară cu ce a venit.
Orice câmp pe care parserul l-ar interpreta altfel decât serializatorul duce la
`NotCanonical`, nu la acceptare tăcută. Asta închide clasa de atacuri *parser
differential*: două implementări care citesc același document diferit nu pot
ajunge amândouă să creadă că semnătura e validă.

**Reguli de fuziune:**

| Ce | Regulă |
|---|---|
| Includerea unui releu | apare în cel puțin `n/2 + 1` voturi |
| Bandă | mediana valorilor votate, plafonată |
| Adresă și port | perechea majoritară, aleasă *împreună* |
| Flag-uri | fiecare, de la majoritatea voturilor care listează releul |
| Parametri | mediana, dacă majoritatea autorităților l-au votat |

Adresa și portul se aleg ca pereche, nu separat — altfel ai putea produce o
combinație pe care n-a votat-o nimeni: adresa de la o autoritate, portul de la
alta. Testul `adresa_si_portul_raman_impreuna`.

**Semnături: `HybridSig<A, B>` cere *ambele* componente valide.** Atenție la
dualitatea cu `Hybrid<A, B>` de la KEM, care e sigur dacă *măcar una* dintre
scheme e sigură. Sunt proprietăți duale și e ușor să le confunzi. Pentru
autorități: Ed25519 + ML-DSA-65. Pentru descriptori de releu: Ed25519 + ML-DSA-44.

**Limitare cunoscută, de documentat:** banda e auto-raportată de releu, doar
plafonată. Un releu care își declară o bandă uriașă primește trafic
disproporționat și vede mai multe circuite. Tor rezolvă prin măsurare distribuită
(`sbws`); noi nu.

Rulează `cargo run -p pqo-dirauth --example consens` pentru un ciclu complet cu
5 autorități.

## Servicii ascunse

Adresa `.onion` are 62 de caractere, ca în Tor v3, dar conține **hash-ul** cheii
de identitate, nu cheia. Cu ML-DSA-44 cheia are 1312 octeți; pusă în adresă ar da
~2100 de caractere.

**Problema pe care o rezolvă asta.** Tor v3 obține trei proprietăți simultan din
blinding-ul algebric Ed25519: HSDir verifică cine deține slotul, HSDir nu poate
lega perioadele, clientul calculează indexul doar din adresă. ML-DSA nu are
operația de grup `A' = h·A`. Nu e o scăpare de implementare — e o problemă
deschisă de cercetare pentru scheme bazate pe latice.

Schema implementată păstrează a doua și a treia proprietate și o pierde pe prima:

| | Tor v3 | aici |
|---|---|---|
| Lungime adresă | 62 caractere | 62 caractere |
| Client calculează indexul din adresă | da | da |
| HSDir nu poate lega perioadele | da | da, și post-cuantic |
| HSDir verifică proprietatea slotului | da | **nu** |
| Impersonare sub calculator cuantic | posibilă | imposibilă |

**Varianta respinsă, care merită un paragraf în lucrare:** hibridul naiv, unde
adresa e cheia Ed25519 ca în Tor v3 și identitatea ML-DSA stă în interiorul
descriptorului. E insuficient — un atacator cuantic recuperează cheia privată
direct din adresă și publică descriptori care trec verificarea HSDir. Nu e
degradare parțială, e preluare completă a serviciului.

**Ce costă pierderea proprietății a treia.** Oricine știe adresa poate publica un
descriptor la indexul corect. Consecința e refuz de serviciu, nu impersonare:
descriptorul fals nu trece la client, pentru că hash-ul cheii master din interior
trebuie să fie chiar adresa. Limitat prin trei mecanisme în `DescStore`: contor
de revizie strict crescător, regula primului publicator pe perioadă, și
replicare pe 2×3 noduri pe care atacatorul trebuie să le câștige pe toate.
Testele `un_hsdir_ostil_nu_poate_suprascrie` și `descriptor_fals_nu_trece_la_client`.

**Cheile per perioadă se derivă determinist** din sămânța master prin `ShakeRng`,
un XOF-RNG peste SHAKE256. Fără asta, un serviciu care repornește nu și-ar mai
putea actualiza descriptorul deja publicat. Testul
`serviciul_isi_rederiva_cheile_dupa_repornire`.

**Pe hop-ul virtual, serviciul joacă rolul de releu.** Consecință directă a
asimetriei CGO — partea nemaleabilă (`ENC_UIV`) trebuie să fie la capătul care
răspunde. Serviciul folosește `RelayCircuit`, clientul `ClientCircuit`.

Rulează `cargo run -p pqo-hs --example serviciu`.

## Releul: arhitectură sans-io

`pqo-relay` nu deschide niciun socket, nu folosește `async`, și nu depinde de un
runtime. Fiecare metodă are forma `(stare, eveniment) → Vec<Action>`. Coaja de
I/O — tokio plus rustls — doar pompează octeți și execută acțiunile.

**De ce, în ordinea importanței:**

1. **Calea critică nu are async.** Verificarea semnăturilor, decizia de rutare și
   actualizarea stării CGO se întâmplă în cod sincron. Nu pot exista curse pe
   starea criptografică, pentru că nu există `.await` între citirea și scrierea
   ei. Reamintire: două fire care ajung simultan la `update_uiv` pot deriva
   **același keystream**.
2. **Testele sunt deterministe.** Cele 28 de teste acoperă ordine greșită de
   mesaje, circuit necunoscut, canal căzut la mijlocul unei extinderi, plafon de
   `RELAY_EARLY` — fără rețea și fără timeout-uri. Niciun test nu pică aleator.
3. **Runtime-ul e înlocuibil.** Dacă tokio devine o problemă, se schimbă coaja
   fără să se atingă protocolul.

Costul: coaja trebuie să țină evidența canalelor și să traducă între
identificatorii ei și `ChannelId`. E cod plictisitor, dar izolat.

**Bugul pe care l-a prins arhitectura asta imediat.** Prima versiune a
handshake-ului de legătură pica la verificarea semnăturii. Cauza: NETINFO e
celulă *fixă*, deci payload-ul se completează cu zerouri până la 509 octeți. Cel
care trimitea absorbea în transcript corpul logic (vector gol), cel care primea
absorbea cei 509 octeți de pe fir. Transcriptele divergeau.

Într-o implementare cu I/O real asta s-ar fi manifestat ca „handshake-ul eșuează
uneori" și ar fi costat ore de tcpdump. Aici a fost un test care pică determinist,
cu regresia blocată de `netinfo_absoarbe_payloadul_umplut`.

**Apărări implementate în rutare:**

- `RELAY_EARLY` plafonat la 8 celule per circuit, și EXTEND2 acceptat *doar* prin
  RELAY_EARLY — altfel plafonul de lungime de circuit n-ar avea efect
- numerele de circuit sunt locale fiecărui canal, deci un observator care vede
  ambele legături nu poate corela după număr
- un număr de circuit deja folosit nu se refolosește: altfel un peer ar putea
  suprascrie starea criptografică a unui circuit existent
- celulele din sensul greșit al circuitului sunt respinse
- un handshake de legătură eșuat e stare terminală, nu se reia pe aceeași
  conexiune

Rulează `cargo run -p pqo-relay --example circuit_flow`.

## Stratul de rețea

`pqo-relay-io` e coaja: tot codul cu `async` trăiește aici, protocolul rămâne
sincron în `pqo-relay`. Un task nucleu deține `RelayNode` și registrul de canale;
câte un task per canal mută octeți. Nucleul e **singurul** care atinge starea
criptografică, dintr-un singur task — deci nu există `Mutex` pe starea de
circuit și nici posibilitatea ca două fire să ajungă simultan la `update_uiv`.

Transportul e generic peste `AsyncRead + AsyncWrite`. Azi e `TcpStream`; când se
adaugă `rustls`, devine `TlsStream<TcpStream>` fără modificări în crate.

### Bugul care merită un paragraf în lucrare

Circuitele de un hop mergeau. Extinderea eșua cu `UnexpectedEof` — canalul se
închidea singur, aparent fără motiv.

Cauza era la trei straturi distanță. `read_cell` făcea `buf.resize()` **înainte**
de `await` și `buf.truncate()` după. `pump` rulează `read_cell` într-un
`tokio::select!`, deci viitorul e anulat de fiecare dată când cealaltă ramură
câștigă. Anularea între resize și truncate lăsa în buffer 8 KB de zerouri pe care
nu-i scrisese nimeni. `Cell::decode` îi citea ca pe o celulă PADDING perfect
validă de 514 octeți, înghițea date reale, fluxul se desincroniza, canalul cădea.

Simptomul: „extinderea de circuit eșuează uneori". Cauza: o funcție care nu era
cancel-safe. Nici borrow checker-ul, nici testele sincrone nu prind asta —
**e o clasă de bug care apare doar când adaugi async**, și e argumentul cel mai
concret pentru care restul stivei e sans-io.

Reparația: citim într-o zonă separată și mutăm în buffer abia după ce `await` a
întors. Regresia e blocată de `citirea_e_sigura_la_anulare`, care anulează
citirea de sute de ori la mijloc și verifică că nu se pierde nicio celulă.

### Ce lipsește înainte de orice deployment

- **TLS.** Vezi `ChannelBinding::insecure_plaintext_tcp` — numele e lung și urât
  intenționat. Fără TLS nu există nimic de care să legăm handshake-ul, deci
  atacul de tip unknown key share e deschis.
- Timeout-uri pe handshake, limite de rată, tratarea mesajelor livrate la exit.

## Stream-uri și control de flux

Un circuit multiplexează mai multe stream-uri. BEGIN cere exit-ului o conexiune,
DATA transportă octeți, END închide. Adresa se trimite ca **text** și se rezolvă
la exit — dacă am rezolva-o la client, cererea DNS ar pleca prin rețeaua locală
și ar dezvălui ce site vizităm.

**Politica de ieșire refuză implicit tot.** Un releu devine exit doar dacă
operatorul cere explicit. Alegerea inversă ar transforma orice releu pornit din
greșeală într-un proxy deschis, cu consecințe legale pentru operator. Adresele
private sunt refuzate separat, altfel un client ar putea scana rețeaua internă a
operatorului sau ajunge la servicii de administrare pe localhost.

**Ferestre pe două niveluri** — circuit (1000 celule, SENDME la 100) și stream
(500, SENDME la 50). Fără ele, un exit care descarcă rapid ar umple cozile
releelor intermediare cu trafic care nu e al lor: atac de epuizare a memoriei
deghizat în trafic normal.

### Trei bug-uri din aceeași familie

Toate trei au apărut la primul transfer de 400 KB și toate erau variații pe
„aruncăm date când coada e plină".

**1. Celule aruncate la scriere.** Bucla principală făcea `try_send` pe coada
canalului și ignora eșecul, cu justificarea că e backpressure. E fals: CGO
actualizează cheile după **fiecare** celulă procesată. Dacă releul a procesat
celula N și aceasta nu ajunge la client, stările diverg și tot ce urmează devine
gunoi. O celulă pierdută nu e degradare, e corupere silențioasă.

**2. Date de stream aruncate.** Aceeași greșeală pe coada către destinație:
o bucată pierdută taie o secțiune din mijlocul fluxului TCP, iar destinația
primește date corupte fără ca cineva să observe.

**3. Date de exit aruncate când fereastra era închisă.** `data_to_client`
întorcea `None` și apelantul arunca datele. Acum intră într-o coadă mărginită;
dacă se umple, clientul nu consumă și stream-ul se închide explicit.

Reparația comună: cozile trebuie să fie **mai mari decât fereastra de flux**
(care garantează câte celule pot fi în zbor), iar dacă totuși se umplu, se
închide circuitul în loc să se piardă octeți.

### Al patrulea, care era de fapt arhitectural

Reparațiile de mai sus au lăsat o cursă de sincronizare. Simptomul era ciudat:
`transfer_mare_cu_control_de_flux` pica **fără** feature-ul `pq` și trecea **cu**
el. Același cod, aceleași date — ML-KEM doar încetinește execuția. Un test care
depinde de viteza mașinii e un test care ascunde o cursă.

Cauza: exit-ul citea din socket **cât de repede putea**, indiferent dacă
fereastra de flux permitea trimiterea mai departe. Datele se adunau într-o coadă
de 256 de bucăți; când se umplea (~124 KB, aproape exact offset-ul unde apărea
corupția), stream-ul se închidea. Se întâmpla numai când clientul era mai lent
decât destinația.

Coada era o cârpeală. Reparația corectă e **backpressure real**: task-ul de
citire cere un permis înainte de fiecare `read()`, iar permisele vin doar din
SENDME-urile clientului. Dacă clientul încetinește, încetinește și citirea din
socket, fereastra TCP se închide, și presiunea ajunge la serverul de origine —
singurul loc unde chiar are efect.

Regresia e blocată de `client_lent_nu_pierde_date`, care pune un server ce
inundă și un client care citește cu pauze. `verifica.sh` rulează testele de
rețea de cinci ori tocmai pentru că un test de concurență care trece o dată nu
demonstrează nimic.

### Un bug de protocol găsit pe drum

SENDME e legitim pe **ambele** niveluri: pe stream-ul de control confirmă
fereastra circuitului, pe un stream de date confirmă fereastra acelui stream.
Verificarea mea rigidă control-sau-date îl respingea într-unul din cazuri, ceea ce
făcea transferurile mari imposibile. De aici a apărut `StreamKind::Either`.

## Clientul: de la consens la conexiune

`pqo-client` închide bucla. Până acum clientul primea structuri `RelayPublic`
direct în teste; acum pornește de la un consens semnat, verifică semnăturile,
alege guard-uri, construiește o cale și proxiază prin SOCKS5.

### Guard-uri persistente

Primul hop se alege **o singură dată** și se refolosește luni de zile.
Contraintuitiv, dar e cea mai importantă apărare a clientului.

Dacă ai alege un prim hop nou la fiecare circuit, probabilitatea să nimerești
măcar o dată unul ostil crește către 1 pe măsură ce construiești circuite. Un
adversar cu o fracțiune mică din rețea te prinde garantat, mai devreme sau mai
târziu. Cu un guard fix, ori ai nimerit de la început unul ostil — și atunci ai
pierdut imediat — ori ești în siguranță cât timp îl păstrezi. Riscul se mută din
„sigur, la un moment dat" în „improbabil, dar tot sau nimic".

Testul `primul_hop_e_intotdeauna_un_guard_fixat` verifică asta peste 300 de
circuite.

### Ordinea de alegere a hopurilor

Se alege **întâi exit-ul**, apoi guard-ul, apoi mijlocul. Nu e arbitrar: exit-ul
e poziția cu cei mai puțini candidați. Prima versiune alegea mijlocul înainte, iar
un hop din mijloc putea ocupa exact releul care era singurul exit compatibil —
calea devenea imposibilă deși exista una validă. Regula generală: alegi întâi
poziția cea mai constrânsă. Testul `mijlocul_nu_fura_singurul_exit`.

### Diversitate de subrețea

Două relee din același /16 nu pot apărea pe aceeași cale: sunt probabil ale
aceluiași operator sau în același sistem autonom, deci cine vede unul poate vedea
și pe celălalt. Fără regula asta, un operator cu două mașini în același rack poate
ocupa două poziții din trei.

### Scurgerea de DNS

SOCKS5 permite atât nume de domeniu (`ATYP=3`) cât și IP (`ATYP=1`). Dacă
aplicația trimite un IP, înseamnă că a rezolvat deja numele — iar cererea DNS a
plecat prin rețeaua locală, în clar, către rezolverul furnizorului. Tot circuitul
devine inutil.

Nu putem împiedica asta din server, cererea a plecat deja. Dar o **numărăm** și o
raportăm prin `SocksStats::ip_literals`, ca să fie vizibilă. În Firefox se
rezolvă cu `network.proxy.socks_remote_dns = true`; în `curl` cu
`--socks5-hostname`, nu `--socks5`.

## Protocolul de director

`BEGIN_DIR` deschide un stream către serviciul de director al releului însuși.
Spre deosebire de `BEGIN`, nu se deschide nicio conexiune în exterior — releul
răspunde din propriile documente. De aceea funcționează și pe relee care nu sunt
exit, iar politica de ieșire nu se aplică.

**De ce prin circuit și nu direct.** Clientul are nevoie de descriptorii releelor
pe care le-a ales. Dacă i-ar cere direct unei autorități, aceasta ar afla exact ce
relee îl interesează — adică primul și ultimul hop al circuitului pe care urmează
să-l construiască. Ar fi suficient ca o autoritate să fie curioasă ca să
dezanonimizeze clienții. Prin circuit, releul vede ce se cere, dar nu cine cere.

**Lungimea vine din antetul răspunsului, nu din închiderea stream-ului.** Altfel
un releu ostil ar putea ține conexiunea deschisă la nesfârșit, iar clientul ar
aștepta degeaba. Plafonul de 4 MB oprește un releu care anunță un document absurd
de mare înainte ca clientul să aloce ceva.

**Releul nu semnează nimic.** Redistribuie documente deja semnate de autorități,
iar clientul le verifică singur. Un releu ostil poate refuza să servească sau
poate servi un document vechi, dar nu poate fabrica unul.

## Executabile

Trei binare: `pqonion-relay`, `pqonion-dirauth`, `pqonion-client`. Până acum
totul rula doar din teste; acum sunt procese pe care le pornești din linia de
comandă.

**Identitatea supraviețuiește repornirii.** Cheile se derivă determinist dintr-o
sămânță salvată pe disc, prin `ShakeRng`. Un releu care își schimbă cheia la
fiecare repornire ar apărea ca nod nou și n-ar acumula niciodată reputație în
consens. Testul `releul_isi_pastreaza_identitatea_intre_porniri` pornește procesul
de două ori și compară fingerprint-ul din log.

**Cheile private se creează direct cu `0600` și se verifică la fiecare citire.**
Ordinea contează: dacă am crea fișierul și abia apoi i-am schimba permisiunile, ar
exista o fereastră în care e lizibil de oricine. Pe o mașină partajată, o cheie
lizibilă de alți utilizatori înseamnă că oricine poate impersona releul.

**Nivelurile de logging care ar putea scurge identificatori nu există în build de
release** — sunt compilate afară prin `cfg(debug_assertions)`. Nu sunt „oprite
implicit", nu se pot activa deloc. Un releu care scrie „circuit 0x1234 de la
192.0.2.5 către exit 198.51.100.7" a distrus anonimitatea pentru oricine îi ia
discul.

**Fără `clap`.** Un parser de argumente scris de mână, 60 de linii, pentru șase
opțiuni. Fiecare dependență în plus e cod pe care nu l-am citit și care rulează cu
privilegiile releului.

### Testele rulează procesele, nu funcțiile

`crates/pqo-bin/tests/procese.rs` pornește executabilele cu `Command`, le dă
argumente reale și verifică prin socket-uri. E singurul mod de a prinde erori de
ambalaj: argumente parsate greșit, chei care nu se salvează, procese care mor la
pornire. `proxy_complet_prin_procese` pornește trei procese separate și trece o
conexiune prin ele.

### Un flag pe care testele l-au cerut

Prima versiune a testului de proxy pica: exit-ul refuza `localhost`, pe bună
dreptate — altfel orice client ar putea scana rețeaua internă a operatorului. De
aici a apărut `--permite-adrese-private`, cu nume lung intenționat, plus testul
`exitul_refuza_localhost_fara_flag_explicit` care verifică refuzul implicit.

## Publicarea prin rețea

Ultimele două bucle sunt închise: releele își publică descriptorii, iar
serviciile ascunse își încarcă descriptorii la HSDir — ambele **prin circuit**.

`pqo-hs` avea 62 de teste dar rula doar în proces: descriptorii treceau din mână
în mână între structuri. Acum trec prin socket-uri, circuite și celule criptate.
Testul `serviciul_publica_si_clientul_gaseste` pornește șase HSDir-uri, publică pe
cele responsabile, apoi caută pornind **doar de la șirul adresei**.

**Validarea se face la destinatar, nu la expeditor.** `accept_descriptor` și
`SharedDescStore::upload` verifică semnătura înainte de stocare. Nimeni nu se
autentifică — documentele sunt autosemnate, deci nu contează cine le trimite.
Testele `hsdirul_refuza_un_descriptor_stricat` și
`un_atacator_nu_poate_suprascrie_slotul`.

### Bugul care a apărut imediat

Publicarea eșua cu `Rejected`. Cauza: un descriptor de serviciu ascuns are câțiva
kiloocteți, deci depășește cei 487 de octeți utili ai unei celule. Cererea se
fragmenta, iar releul trata **fiecare bucată ca pe o cerere completă** — prima
bucată nu se parsa, deci răspundea cu eroare.

Răspunsurile aveau deja prefix de lungime; cererile nu, pentru că până acum toate
erau minuscule. Am adăugat `encode_framed`/`parse_framed` și acumulare la releu
până când cererea e întreagă. E același tipar ca la fragmentarea celulelor: orice
mesaj care poate depăși o unitate de transport are nevoie de un cadru explicit.

### Al patrulea executabil

`pqonion-hs` afișează adresa `.onion` la pornire și publică descriptorul.
Adresa se derivă din sămânța de pe disc, deci supraviețuiește repornirii — un
serviciu care și-ar schimba adresa ar fi inutilizabil, nimeni nu l-ar găsi de
două ori. Verificat prin `serviciul_ascuns_isi_pastreaza_adresa`, care pornește
procesul de două ori.

## Rendezvous prin rețea

Ultima bucată de protocol e conectată. Un client și un serviciu ascuns comunică
fără să-și cunoască adresele, prin două relee care nu știu cine sunt părțile.

`pqo-relay/src/service.rs` implementează ambele roluri ca mașini de stări
sans-io: punctul de introducere ține evidența cheilor anunțate și retransmite
cererile; punctul de rendezvous ține cookie-urile și împerechează circuitele.
Un releu poate juca ambele roluri simultan, pe circuite diferite — verificat de
`punctul_de_rendezvous_poate_fi_acelasi_cu_cel_de_introducere`.

**Ce află fiecare releu.** Punctul de introducere vede o cerere pe care nu o
poate citi: corpul e criptat către cheia serviciului, iar releul primește doar
identificatorul cheii de autentificare, ca să știe unde să retransmită. Punctul
de rendezvous vede două circuite și un cookie de 20 de octeți care se potrivește;
traficul de după împerechere e criptat de hopul virtual, la care nu are cheia.

Când o cheie de autentificare nu e înregistrată, punctul de introducere răspunde
cu același `INTRODUCE_ACK` negativ ca la orice altă eroare. Dacă ar distinge
cazurile, ar putea fi folosit ca să enumeri serviciile pe care le găzduiește.

### Tunelul: mesaje relay peste hopul virtual

`pqo-relay-io/src/tunnel.rs` transportă **mesaje relay obișnuite** — BEGIN, DATA,
END — peste cheia partajată de rendezvous. Serviciul poate deci refolosi
`StreamTable`, iar clientul același cod de stream ca pe un circuit normal.

Dimensiunile se potrivesc exact: `RelayMessage::fragment` produce corpuri de 493
de octeți, cât are `LEN_XR` la CGO. Un fragment intră direct într-o celulă
virtuală, fără umplutură. Testul `fragmentul_intra_exact_intr_o_celula_virtuala`
blochează această coincidență, ca să nu se rupă la o schimbare de constante.

`conexiune_completa_la_serviciu_ascuns` face traseul pe care îl vede un
utilizator: BEGIN prin tunel, serviciul deschide o conexiune locală, date
dus-întors, octeții ajung intacți.

**INTRODUCE1 poartă acum și adresa punctului de rendezvous.** Fără ea serviciul
ar ști *pe cine* să contacteze, dar nu și *unde* — ar trebui să caute în consens,
deci să aibă mereu unul proaspăt. Clientul a ales deja releul, deci știe adresa.
Tor face la fel, prin link specifiers.

### Costul transportului: 2 celule per celulă virtuală

Celula hopului virtual are 509 octeți (16 tag CGO + 493 corp), iar corpul util al
unui mesaj relay e 487. Deci **fiecare celulă virtuală consumă două celule
relay** pe fiecare dintre cele două circuite.

Alternativa ar fi fost să facem `LEN_XR` parametric și să coborâm corpul virtual
la 471 de octeți, ca să încapă exact într-o celulă. Asta ar fi schimbat toate
constantele CGO — `N0`, `C_OFFSET`, decalajele de flux PRF — și ar fi invalidat
verificările față de propunerea 359. Am ales suprapunerea de 2×, cu cifra la
vedere. E un compromis de documentat în capitolul de evaluare, nu o scăpare.

### Refactorizare cerută de clippy

`core_loop` ajunsese la 8 parametri, `exec_stream` la 10. Soluția n-a fost
`#[allow]`, ci gruparea în două structuri care clarifică ce e ce:

- `NodeCtx` — configurația fixă a releului: chei de identitate, politică de
  ieșire, magazinele de documente. Nu se schimbă după pornire.
- `ExitState` — starea care se modifică: tabele de stream, cozi de scriere,
  permise de citire, cereri de director parțiale.

Separarea nu e cosmetică. Înainte, cinci parametri independenți circulau prin
fiecare funcție și nimic nu spunea care e configurație și care e stare mutabilă.
Acum `ExitState::drop_stream` curăță toate cele trei hărți dintr-o singură
chemare — înainte erau trei ștergeri manuale în cinci locuri diferite, și una
lipsea.

### `scan-lint.py`

Mediul în care a fost scris codul nu are clippy instalat, deci obiecțiile apăreau
una câte una, la fiecare rulare pe mașina ta. Scriptul caută static tiparele
frecvente: funcții cu prea multe argumente, `Result<(), ()>`, `&Vec<T>` ca
parametru, și bucle care indexează în loc să itereze.

**Calibrarea a fost partea grea.** Prima versiune raporta 13 bucle; clippy
semnalase una singură. Diferența e că `needless_range_loop` se declanșează doar
când bucla indexează *o singură* colecție, *direct*, cu forma `x[i]`. Nu se
declanșează pentru:

- indexare a mai multor colecții — `blk[i] = m[i] ^ mask[i]`
- indexare cu decalaj — `cell[BLK_LEN + i]`
- felii — `buf[..n]`
- indici calculați — `inel[(start + j) % n]`
- intervale inversate — `for i in (0..n).rev()`
- colecții construite chiar în corpul buclei

Scriptul aplică acum toate șase regulile și raportează zero pe codul curent,
dar prinde tiparul real într-un test de control. Un scanner care raportează tot
e la fel de inutil ca unul care nu raportează nimic — semnalul se pierde în
zgomot și înveți să-l ignori.

Detectorul de `format!` imbricat potrivește parantezele efectiv, nu doar caută
două `format!` apropiate: varianta naivă raporta patru apeluri vecine, pe care
clippy nu le semnalează. Un scanner care raportează zgomot e la fel de inutil ca
unul care tace.

Scannerul ignoră acum literalele brute (`r#"..."#`): fără asta, JavaScript-ul
din pagina consolei era analizat ca și cum ar fi Rust, iar un `return` din el
apărea ca `needless_return`. Regexul de detecție a avut nevoie și de o limită de
cuvânt — fără ea, `"hsdir": ...` arăta ca începutul unui literal brut, pentru că
se termină în `r` urmat de ghilimele.

`verifica.sh` raportează acum **toate** obiecțiile clippy, cu lista lint-urilor
distincte, și nu mai numără linia `could not compile` ca obiecție separată.
Versiunea anterioară afișa doar prima (`grep -m5`), ceea ce transforma reparatul
într-un șir de runde.

Extragerea numelor de lint avea și ea un bug: clippy scrie același lint în două
forme, `clippy::needless-return` și `clippy::needless_return`. Clasa de caractere
`[a-z_]` se oprea la cratimă, deci `clippy::needless` apărea ca al treilea lint
inexistent. Acum se normalizează cratimele.

**`needless_return` are o limitare cunoscută în scanner.** Cazul semnalat de
clippy era un `return` ca ultimă instrucțiune a unui bloc `#[cfg(unix)]` — ceea
ce ar cere să știm ce blocuri se compilează, adică exact ce face compilatorul.
Scannerul prinde doar cazul simplu (`return` urmat de acolada funcției), iar
limitarea e scrisă în cod. Reparația a fost oricum mai curată: două funcții
separate pe `cfg`, în loc de una cu două blocuri.

### Exemplele nu mai intră în panică

Pasul 7 rula `cargo run ... | head -14`. După N linii, `head` închide capătul
țevii, programul primește SIGPIPE și intră în panică la scriere. Odată ce am
oprit înghițirea stderr-ului, panicile au devenit vizibile și arătau exact ca un
bug de cod — deși erau un artefact al scriptului. Acum rezultatul se scrie într-un
fișier și abia apoi se taie.

### O cursă în alocarea de porturi

Testele de rețea picau intermitent — **alt test la fiecare rulare**, semnătura
tipică a unei curse, nu a unui bug determinist.

Cauza: `port_liber()` lega portul 0, îl afla, apoi îl **elibera** înainte ca
procesul copil să-l lege. `cargo test` rulează testele dintr-un binar în paralel,
pe fire, deci două teste puteau primi același port. Ambele porneau un proces;
unul eșua la legare, iar celălalt test se conecta la procesul greșit. De aici
stocuri consumate de altcineva și identificatori de coș care nu mai existau.

Două reparații, după ce se putea:

- `pqonion-shop` acceptă `--listen 127.0.0.1:0` și **raportează adresa efectivă**.
  Testul o citește din stderr, deci nu mai există interval între aflarea portului
  și legarea lui. E soluția corectă, când procesul o permite.
- Pentru celelalte binare, unde portul trebuie știut dinainte (clientul primește
  `--guard` și `--exit`), `port_liber()` folosește un contor atomic per proces.
  Testele dintr-un binar nu mai pot primi același port; verificarea de legare
  rămâne doar pentru procese din afară.

Verificat: 25 de rulări consecutive ale testelor de magazin și 6 ale celor de
proces, toate curate. `verifica.sh` include acum și magazinul în pasul de
stabilitate.

### Diagnostice care nu inventează cauze

`verifica.sh` a raportat odată „ML-KEM nu merge, probabil API-ul crate-ului s-a
schimbat" și „5 din 5 rulări au picat: cursă de sincronizare". Ambele erau
invenții. Cauza reală era în chiar textul erorii: `linking with cc failed` —
adică disc plin sau memorie insuficientă, nu cod greșit. Dovada că era mediul, nu
codul: pasul 3 compilase și rulase **același cod** cu succes.

Un mesaj de eroare care ghicește cauza te trimite să cauți într-un fișier care nu
are nimic. Scriptul acum:

- verifică spațiul liber înainte de orice compilare (build-ul fără `pq` ocupă
  ~1.5 GB, cel cu `pq` construiește separat)
- separă **build-ul** de **rulare** la pasul 4, ca să distingă „codul e greșit"
  de „mediul n-a putut produce binarele"
- citește cauza reală din log: disc plin, proces omorât de OOM, eșec de linking,
  sau eroare de compilare — fiecare cu comanda de verificat
- sare peste pasul de stabilitate dacă build-ul a eșuat, în loc să raporteze o
  cursă inexistentă
- nu mai înghite stderr-ul exemplelor cu `2>/dev/null`, care ascunsese complet un
  eșec de build

### O lecție despre scripturi de demonstrație

Prima versiune a lui `testnet.sh` pornea procesele în fundal și raporta `OK`
imediat, fără să verifice nimic. Într-o rulare reală, toate cele trei relee și
clientul au murit cu `Address already in use` — rămăseseră procese dintr-o rulare
anterioară — iar scriptul a scris vesel „trei relee pe porturile 9001 9002 9003".

Mai rău: releele vechi *ascultau*, deci serviciul ascuns s-a conectat la ele și a
primit `BadRequest` la fiecare încărcare, pentru că versiunea veche nu cunoștea
încadrarea cu prefix de lungime. Simptomul arăta ca un bug de protocol; cauza era
un script care mințea.

Un script de demonstrație care raportează succes când nimic nu merge e mai
periculos decât lipsa lui — la susținere ți-ar da încredere falsă exact în
momentul cu cea mai mică marjă de manevră. Acum fiecare pas e verificat: porturi
libere, proces care chiar ascultă, publicare confirmată, cerere HTTP care chiar
trece prin circuit.

## Decizii de design de apărat la susținere

**CREATE2 / CREATED2 sunt celule variabile, EXTEND2 / EXTENDED2 nu.**
Prima pereche circulă hop-by-hop, în interiorul TLS, iar primul releu știe oricum
că se creează un circuit — lungimea nu-i spune nimic nou. A doua pereche trece
prin releele din mijloc, unde lungimea variabilă ar dezvălui imediat că circuitul
se extinde, câte hop-uri mai sunt și ce variantă de handshake se folosește. Exact
informația pe care onion routing trebuie să o ascundă. De aceea fragmentarea nu e
opțională.

**Fragmentele non-finale trebuie să fie pline.** Un fragment cu `MORE` setat și
`FragLen < 503` e respins. Altfel tiparul de lungimi devine canal ascuns între
două relee coluzive. Verificat de `fragment_non_final_scurt_e_respins`.

**Biții rezervați din flags trebuie să fie zero.** Aceeași logică: orice bit
liber pe care nu-l verifici e un canal ascuns. `biti_rezervati_sunt_respinsi`.

**Octeții în plus după câmpul de lungime declarat sunt respinși.** Parserele cer
potrivire exactă, nu prefix valid. `octeti_in_plus_sunt_respinsi`.

**Comenzile necunoscute sunt respinse, nu ignorate.** Tor le aruncă tăcut pentru
compatibilitate înainte; într-o rețea închisă de cercetare, respingerea e mai
curată și elimină un canal.

**Comenzile de control nu pot apărea pe stream-uri de date și invers.** Închide o
clasă de confuzii între planul de control și cel de date, de exemplu un EXTEND2
injectat pe un stream de date. `confuzie_control_date_e_respinsa`.

**Fără câmp `Digest` în antetul relay.** În tor1, cei 4 octeți de SHA-1 trunchiat
făceau și integritate end-to-end și recunoașterea hop-ului. CGO oferă un
autentificator de 16 octeți la nivelul stratului de criptare, deci câmpul e
redundant. Câștigăm 6 octeți utili per celulă și scăpăm de SHA-1. Costul:
pierdem semantica "leaky pipe". Nu o folosim în MVP.

**Umplutura e aleatoare, nu zerouri.** Umplutura deterministă e text clar
cunoscut. Costul unei surse de aleator e neglijabil aici.

**Codare injectivă în KDF.** ntor clasic concatenează câmpuri de lungime fixă.
Cu ML-KEM lungimile variază între scheme și invariantul cade — două tuple diferite
pot produce același `KEY_SEED`. Fiecare component se prefixează cu lungimea. E o
clasă de atac pe care migrarea la PQ o *introduce*.

**Tipurile împiedică refolosirea de material efemer.** `ClientState` nu e `Clone`,
iar `client_finish` îl consumă. Refolosirea unui nonce efemer e bug-ul care sparge
ECDSA — aici e imposibilă la compilare.

## Ce trebuie verificat înainte să te bazezi pe cod

- **`MlKem768` nu a fost compilat** în mediul unde a fost scris (toolchain blocat
  la 1.75). Rulează `cargo test --features pq` primul lucru. Dacă pică, e problemă
  de API în `kem.rs`, nu de logică de protocol — aia e testată cu X25519 și hibrid.
- **`ml-kem` din RustCrypto nu e auditat.** Pentru versiunea finală evaluează
  `libcrux-ml-kem` (verificat formal cu hax/F*). Trait-ul `Kem` face schimbarea
  ~30 de linii.
- **Combinerul hibrid nu e X-Wing exact** — nu include `pkX`. Nu ești
  interoperabil cu implementări terțe. Dacă vrei asta, folosește crate-ul `x-wing`.

## Fuzzing

```bash
cargo install cargo-fuzz
cargo fuzz run cell_decode  -- -max_total_time=28800
cargo fuzz run reassembler  -- -max_total_time=28800
cargo fuzz run msg_parse    -- -max_total_time=28800
cargo fuzz run ntor_server  -- -max_total_time=28800
cargo fuzz run cgo_client   -- -max_total_time=28800
cargo fuzz run cgo_relay    -- -max_total_time=28800
```

Șase ținte. Rulează-le înainte de susținere și raportează numărul de execuții —
e un rezultat concret pentru capitolul de testare.

## Următorii pași

1. **Vectorii de test CGO oficiali** de la `gitlab.torproject.org/nickm/cgo-drafts`.
   Acum am doar POLYVAL și AES verificate extern; compunerea ET/PRF/UIV nu e.
   Fără asta nu poți afirma în lucrare că ai implementat CGO corect.
2. **AES-256 în loc de AES-128** în `primitives.rs`, pentru marja Grover.
3. **TLS în `pqo-relay-io`** — `rustls` cu grup X25519MLKEM768. Transportul e
   deja generic, deci e o substituție de tip plus derivarea legării de canal din
   exportul TLS (RFC 8446 §7.5). **`rustls` cere Rust ≥ 1.85.**
4. **Rendezvous prin rețea.** Ultima bucată de protocol neconectată. Releul
   trebuie să expună circuite pentru punctele de introducere și rendezvous;
   `pqo_hs::rend` are deja mesajele și logica.
5. **Autoritățile să colecteze descriptorii publicați** și să-i pună în vot, ca
   `dirauth` să producă un consens cu relee reale.
6. **Testnet Docker** — 3 autorități, 6 relee, 1 client, 1 serviciu ascuns.
   Activitatea 7 din raport (testare blackbox).
6. **Valoarea aleatoare partajată** — acum folosim hash-ul consensului anterior,
   care e predictibil cu o perioadă înainte. Tor folosește commit-and-reveal
   între autorități. De documentat sau de implementat.

## Notă despre `Cargo.lock`

E pinuit la `zeroize 1.8.1` / `zeroize_derive 1.4.2` ca să compileze pe Rust 1.75,
singurul toolchain disponibil în mediul unde a fost scris codul. Pe mașina ta,
cu stable curent, șterge-l.
