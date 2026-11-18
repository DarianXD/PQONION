#!/usr/bin/env bash
# Verificare completa a proiectului. Ruleaza din radacina workspace-ului.
#   ./verifica.sh
set -u

VERDE=$'\033[32m'; ROSU=$'\033[31m'; GALBEN=$'\033[33m'; RESET=$'\033[0m'
ESECURI=0

pas() { printf "\n${GALBEN}==> %s${RESET}\n" "$1"; }
ok()  { printf "${VERDE}  OK${RESET}  %s\n" "$1"; }
nok() { printf "${ROSU}  ESEC${RESET}  %s\n" "$1"; ESECURI=$((ESECURI+1)); }

# Citeste cauza reala a unui esec de build, in loc sa o presupunem.
#
# Un `linking with cc failed` inseamna aproape intotdeauna disc plin sau memorie
# insuficienta, nu o problema de cod. Confuzia costa timp: mesajul „API-ul s-a
# schimbat" te trimite sa cauti intr-un fisier care nu are nimic.
diagnostic_build() {
  local log=$1
  if grep -q "No space left on device" "$log" 2>/dev/null; then
    echo "     CAUZA: nu mai ai spatiu pe disc."
    echo "     Elibereaza cu: cargo clean"
    df -h . 2>/dev/null | tail -1 | sed 's/^/     /'
    return
  fi
  if grep -qE "signal: 9|Killed|Cannot allocate memory|out of memory" "$log" 2>/dev/null; then
    echo "     CAUZA: procesul a fost omorat, cel mai probabil de lipsa de memorie."
    echo "     Incearca: cargo test --features pq -j 1"
    echo "     Verifica: dmesg | tail -20"
    return
  fi
  if grep -q "linking with .* failed" "$log" 2>/dev/null; then
    echo "     CAUZA: editarea de legaturi a esuat."
    echo "     Nu e o problema de cod: pasul 3 a compilat si a rulat acelasi cod."
    echo "     Cel mai des inseamna disc plin sau memorie insuficienta."
    echo "     Verifica:  df -h .   |   du -sh target   |   dmesg | tail -20"
    echo "     Apoi:      cargo clean && ./verifica.sh"
    df -h . 2>/dev/null | tail -1 | sed 's/^/     spatiu: /'
    return
  fi
  if grep -qE "^error\\[E[0-9]+\\]" "$log" 2>/dev/null; then
    echo "     CAUZA: eroare de compilare. Primele mesaje:"
    grep -m6 -E "^error" "$log" | sed 's/^/     /'
    return
  fi
  echo "     Primele mesaje din log:"
  grep -m6 -E "^error|^warning" "$log" | sed 's/^/     /'
}

pas "0. Toolchain"
if ! command -v cargo >/dev/null; then
  nok "cargo lipseste. Instaleaza de la https://rustup.rs"
  exit 1
fi
RV=$(rustc --version | awk '{print $2}')
echo "  rustc $RV"
MAJOR=$(echo "$RV" | cut -d. -f1); MINOR=$(echo "$RV" | cut -d. -f2)
PQ_OK=0
if [ "$MAJOR" -gt 1 ] || { [ "$MAJOR" -eq 1 ] && [ "$MINOR" -ge 81 ]; }; then
  PQ_OK=1; ok "suficient de nou pentru feature-ul 'pq' (ML-KEM real)"
else
  nok "prea vechi pentru 'pq'; ai nevoie de >= 1.81. Ruleaza: rustup update stable"
fi

# Ruleaza un exemplu si arata primele $4 linii.
#
# Scrie intai intr-un fisier, apoi taie. Daca am pune `head` direct pe teava,
# ar inchide stdout-ul dupa N linii, programul ar primi SIGPIPE si ar intra in
# panica — un artefact al scriptului care arata exact ca un bug de cod.
exemplu() {
  local pachet=$1 nume=$2 optiuni=$3 linii=$4
  local out=/tmp/ex_$nume.out
  # shellcheck disable=SC2086
  if cargo run -q -p "$pachet" --example "$nume" $optiuni >"$out" 2>>/tmp/ex_run.log; then
    head -"$linii" "$out"
  else
    printf "${ROSU}  exemplul %s a esuat${RESET}\n" "$nume"
    tail -5 "$out" 2>/dev/null | sed 's/^/     /'
    ESECURI=$((ESECURI+1))
  fi
}

pas "0b. Spatiu pe disc"
LIBER_KB=$(df -Pk . 2>/dev/null | tail -1 | awk '{print $4}')
if [ -n "${LIBER_KB:-}" ]; then
  LIBER_MB=$((LIBER_KB / 1024))
  # Build-ul fara `pq` ocupa ~1.5 GB; cel cu `pq` construieste separat.
  # Sub 3 GB liberi, editarea de legaturi poate cadea la mijloc.
  if [ "$LIBER_MB" -lt 3072 ]; then
    nok "doar ${LIBER_MB} MB liberi; ai nevoie de ~3 GB pentru ambele build-uri"
    echo "     Elibereaza cu: cargo clean"
    [ -d target ] && echo "     target/ ocupa acum: $(du -sh target 2>/dev/null | cut -f1)"
  else
    ok "${LIBER_MB} MB liberi"
  fi
fi

pas "1. Lockfile"
if [ -f Cargo.lock ] && [ "$PQ_OK" = "1" ]; then
  echo "  Cargo.lock e pinuit pentru Rust 1.75. Il sterg."
  rm -f Cargo.lock
fi
ok "gata"

pas "2. Compilare, toate tintele"
if cargo build --all-targets 2>&1 | tee /tmp/build.log | grep -q "^error"; then
  nok "compilarea a esuat"; grep -m5 -A4 "^error" /tmp/build.log
else
  W=$(grep -c "^warning" /tmp/build.log || true)
  [ "$W" -eq 0 ] && ok "compileaza, zero warning-uri" || nok "$W warning-uri (ar trebui 0)"
fi

pas "3. Teste, fara ML-KEM (logica de protocol)"
if cargo test 2>&1 | tee /tmp/test1.log | grep -qE "^test result: FAILED"; then
  nok "teste picate"; grep -E "^test .* FAILED" /tmp/test1.log
else
  N=$(grep -oE "[0-9]+ passed" /tmp/test1.log | awk '{s+=$1} END{print s}')
  [ "${N:-0}" -ge 397 ] && ok "$N teste trec (asteptat: 397)" || nok "doar $N teste; asteptat 397"
fi

pas "4. Teste, CU ML-KEM real  <-- verificarea critica"
PQ_BUILD_OK=0
if [ "$PQ_OK" = "1" ]; then
  # Intai construim, apoi rulam. Altfel nu putem distinge „codul e gresit" de
  # „mediul nu a putut produce binarele".
  if ! cargo build --features pq --all-targets >/tmp/pq_build.log 2>&1; then
    nok "build-ul cu 'pq' a esuat (NU inseamna ca ML-KEM e gresit)"
    diagnostic_build /tmp/pq_build.log
  else
    PQ_BUILD_OK=1
    cargo test --features pq >/tmp/test2.log 2>&1
    if grep -q "test result: FAILED" /tmp/test2.log; then
      nok "teste picate cu ML-KEM real"
      echo "     Daca picurile sunt in pqo-crypto, uita-te in kem.rs / sig.rs."
      grep -E "^test .*FAILED|^test result: FAILED" /tmp/test2.log \
        | sed 's/^/     /' | head -20
    elif grep -qE "^error" /tmp/test2.log; then
      nok "rularea testelor a esuat"
      diagnostic_build /tmp/test2.log
    else
      N=$(grep -oE "[0-9]+ passed" /tmp/test2.log | awk '{s+=$1} END{print s}')
      ok "$N teste trec cu ML-KEM-768 real (asteptat: 403)"
    fi
  fi
else
  nok "sarit: toolchain prea vechi"
fi

pas "4b. Stabilitate: testele de retea, de 5 ori"
if [ "$PQ_BUILD_OK" != "1" ]; then
  echo "  SARIT  build-ul de la pasul 4 a esuat; nu are rost sa masuram stabilitatea"
else
  ESEC_RETEA=0
  for i in 1 2 3 4 5; do
    cargo test -q -p pqo-relay-io -p pqo-client -p pqo-shop >/tmp/retea_$i.log 2>&1 \
      || ESEC_RETEA=$((ESEC_RETEA+1))
  done
  if [ "$ESEC_RETEA" -eq 0 ]; then
    ok "5/5 rulari curate (fara curse de sincronizare)"
  elif grep -qE "^error" /tmp/retea_1.log 2>/dev/null; then
    # Un esec de build nu e o cursa. Distinctia conteaza: una se repara in cod,
    # cealalta in mediu.
    nok "$ESEC_RETEA din 5 rulari nu au putut fi construite sau rulate"
    diagnostic_build /tmp/retea_1.log
  else
    nok "$ESEC_RETEA din 5 rulari au picat: cursa de sincronizare"
    grep -E "^test .*FAILED" /tmp/retea_1.log | sed 's/^/     /' | head -10
  fi
fi

pas "4c. TLS"
if cargo build -p pqo-relay-io --features tls >/tmp/tls_build.log 2>&1; then
  cargo test -p pqo-relay-io --features tls >/tmp/tls_test.log 2>&1
  if grep -q "test result: FAILED" /tmp/tls_test.log; then
    nok "testele TLS pica"
    grep -E "^test .*FAILED" /tmp/tls_test.log | sed 's/^/     /' | head -10
  else
    N=$(grep -oE "[0-9]+ passed" /tmp/tls_test.log | awk '{s+=$1} END{print s}')
    ok "$N teste trec cu TLS (legare de canal din exportul TLS)"
  fi
else
  nok "build-ul cu feature-ul 'tls' a esuat"
  diagnostic_build /tmp/tls_build.log
fi

pas "4d. Latenta"
# Exemplul e singurul care exercita calea completa de rendezvous si masoara
# timpul. O intarziere de tip Nagle nu se vede in teste — vezi nota din
# tests/rendezvous.rs.
if cargo run --release -q -p pqo-bin --example latenta >/tmp/lat.log 2>&1; then
  TUNEL=$(grep "cerere ulterioara" /tmp/lat.log | awk '{print $6}')
  CIRC=$(grep "construire" /tmp/lat.log | awk '{print $6}')
  # Praguri largi: ne intereseaza ordinul de marime, nu cifra exacta.
  if [ -n "$TUNEL" ] && [ "$(echo "$TUNEL < 20" | bc -l 2>/dev/null || echo 1)" = "1" ]; then
    ok "dus-intors prin tunel: $TUNEL ms; circuit de 3 hopuri: $CIRC ms"
  else
    nok "dus-intors prin tunel: $TUNEL ms. Peste ~40 ms inseamna TCP_NODELAY lipsa"
    grep -E "^(1|2|3|4)\." /tmp/lat.log | sed 's/^/     /'
  fi
else
  nok "exemplul de latenta nu a rulat"
  tail -5 /tmp/lat.log | sed 's/^/     /'
fi

pas "5. Clippy"
if command -v cargo-clippy >/dev/null || cargo clippy --version >/dev/null 2>&1; then
  cargo clippy --all-targets -- -D warnings >/tmp/clippy.log 2>&1
  if grep -q "^error" /tmp/clippy.log; then
    # Raportam TOATE obiectiile, nu doar prima. Altfel fiecare rulare arata o
    # singura problema si reparatul devine un sir de dus-intorsuri.
    # `could not compile` e consecinta, nu o obiectie in sine.
    N=$(grep "^error" /tmp/clippy.log | grep -vc "could not compile")
    nok "clippy are $N obiectii"
    echo "     --- lint-uri distincte ---"
    grep -oE 'clippy::[a-z_-]+' /tmp/clippy.log \
      | tr '-' '_' | sort -u | sed 's/^/     /'
    echo "     --- locuri ---"
    grep -E "^error|^\s+--> " /tmp/clippy.log \
      | grep -v "could not compile" | sed 's/^/     /' | head -60
    echo "     (log complet: /tmp/clippy.log)"
  else
    ok "clippy curat"
  fi
else
  echo "  clippy lipseste: rustup component add clippy"
fi

pas "6. Formatare"
if ! cargo fmt --version >/dev/null 2>&1; then
  echo "  rustfmt lipseste: rustup component add rustfmt"
elif cargo fmt --check >/tmp/fmt.log 2>&1; then
  ok "formatat"
else
  # Cate fisiere ar fi schimbate, ca sa se vada daca e o problema mica sau mare.
  N=$(grep -c '^Diff in ' /tmp/fmt.log 2>/dev/null || echo 0)
  nok "$N fisiere neformatate. Repara cu: cargo fmt"
  grep '^Diff in ' /tmp/fmt.log 2>/dev/null | sed 's/^Diff in /     /' \
    | sed 's/ at line.*//' | sort -u | head -12
fi

pas "7. Exemple"
: > /tmp/ex_run.log
if [ "$PQ_BUILD_OK" != "1" ] && ! cargo build --examples >/tmp/ex_build.log 2>&1; then
  nok "exemplele nu se construiesc"
  diagnostic_build /tmp/ex_build.log
  ESECURI=$((ESECURI))
fi
exemplu pqo-wire cost_circuit '' 14
echo
exemplu pqo-dirauth consens '' 8
echo
exemplu pqo-hs serviciu '' 12
echo
exemplu pqo-relay-io testnet '' 18
echo
if [ "$PQ_OK" = "1" ]; then
  exemplu pqo-crypto handshake '--features pq' 12
fi

# Daca vreun exemplu a scris pe stderr, il aratam: tacerea totala la pasul 7
# a ascuns odata un esec de build complet.
if [ -s /tmp/ex_run.log ]; then
  printf "\n${ROSU}  Exemplele au raportat erori:${RESET}\n"
  head -12 /tmp/ex_run.log | sed 's/^/     /'
  ESECURI=$((ESECURI+1))
fi

pas "REZULTAT"
if [ "$ESECURI" -eq 0 ]; then
  printf "${VERDE}Totul e in regula.${RESET}\n"
else
  printf "${ROSU}%d verificari au esuat.${RESET}\n" "$ESECURI"
fi
exit "$ESECURI"
