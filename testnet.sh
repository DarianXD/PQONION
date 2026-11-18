#!/usr/bin/env bash
# Porneste un testnet local si VERIFICA fiecare pas.
#   ./testnet.sh              porturi fixe 9001-9003, SOCKS pe 9050
#   ./testnet.sh --auto-port  alege porturi libere
#
# Pentru sustinere: ruleaza asta, apoi din alt terminal
#   curl --socks5-hostname 127.0.0.1:9050 http://example.com/
set -u

VERDE=$'\033[32m'; GALBEN=$'\033[33m'; ROSU=$'\033[31m'; RESET=$'\033[0m'
DIR=$(mktemp -d /tmp/pqonion-testnet.XXXXXX)
PIDS=()

curata() {
  printf "\n${GALBEN}Opresc testnet-ul...${RESET}\n"
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  rm -rf "$DIR"
}
trap curata EXIT INT TERM

pas() { printf "\n${GALBEN}==> %s${RESET}\n" "$1"; }
ok()  { printf "${VERDE}  OK${RESET}  %s\n" "$1"; }
mor() { printf "${ROSU}  ESEC${RESET}  %s\n" "$1"; exit 1; }

# Adevarat daca cineva asculta deja pe port.
port_ocupat() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | grep -qE "[:.]$1[[:space:]]"
  else
    python3 -c "
import socket,sys
s=socket.socket()
try:
    s.bind(('127.0.0.1',$1)); sys.exit(1)
except OSError:
    sys.exit(0)
finally:
    s.close()
"
  fi
}

# Asteapta ca un proces sa inceapa sa asculte. Renunta daca a murit.
asteapta_port() {
  local port=$1 nume=$2 pid=$3 i
  for i in $(seq 1 100); do
    if ! kill -0 "$pid" 2>/dev/null; then
      mor "$nume a murit la pornire (vezi mesajele de mai sus)"
    fi
    if port_ocupat "$port"; then return 0; fi
    sleep 0.1
  done
  mor "$nume nu asculta pe portul $port dupa 10 secunde"
}

port_liber() {
  python3 -c "
import socket
s=socket.socket(); s.bind(('127.0.0.1',0))
print(s.getsockname()[1]); s.close()
"
}

AUTO_PORT=0
[ "${1:-}" = "--auto-port" ] && AUTO_PORT=1

pas "0. Verific porturile"
if [ "$AUTO_PORT" = "1" ]; then
  P1=$(port_liber); P2=$(port_liber); P3=$(port_liber); PSOCKS=$(port_liber)
  ok "porturi alese automat: $P1 $P2 $P3, SOCKS $PSOCKS"
else
  P1=9001; P2=9002; P3=9003; PSOCKS=9050
  OCUPATE=()
  for p in $P1 $P2 $P3 $PSOCKS; do
    if port_ocupat "$p"; then OCUPATE+=("$p"); fi
  done
  if [ ${#OCUPATE[@]} -gt 0 ]; then
    printf "${ROSU}  ESEC${RESET}  porturi deja ocupate: %s\n" "${OCUPATE[*]}"
    cat <<'MSG'

     Cel mai probabil au ramas procese dintr-o rulare anterioara.
     Vezi cine le tine:
         ss -ltnp | grep -E ':900[123]|:9050'
     Opreste-le:
         pkill -f pqonion-
     Sau foloseste porturi libere:
         ./testnet.sh --auto-port

     ATENTIE: relee dintr-o versiune mai veche par sa functioneze, dar
     raspund cu BadRequest la cereri de director, pentru ca nu cunosc
     incadrarea cu prefix de lungime.
MSG
    exit 1
  fi
  ok "porturile $P1 $P2 $P3 si $PSOCKS sunt libere"
fi

PWEB=$(port_liber)
PAUT=$(port_liber)
PCON=$(port_liber)

pas "1. Compilez"
if cargo build --features pq --bins >/dev/null 2>&1; then
  ok "compilat cu ML-KEM si ML-DSA reale"
else
  cargo build --bins >/dev/null 2>&1 || mor "compilarea a esuat"
  printf "${ROSU}  ATENTIE${RESET}  compilat fara 'pq': criptografia NU e post-cuantica\n"
fi
BIN=target/debug
for b in pqonion-relay pqonion-dirauth pqonion-client pqonion-hs pqonion-shop; do
  [ -x "$BIN/$b" ] || mor "lipseste $BIN/$b"
done

pas "2. Autoritatea de director"
mkdir -p "$DIR/aut"
# Samanta fixa, ca releele sa ii poata deriva cheile. DOAR pentru testnet:
# intr-un deployment real cheile autoritatilor sunt cablate in binarul clientului.
python3 -c "
b = bytearray(32); b[0] = 0xA0
open('$DIR/aut/autoritate.key','wb').write(bytes(b))
" || mor "nu am putut scrie samanta autoritatii"
chmod 600 "$DIR/aut/autoritate.key"

LOG_AUT="$DIR/aut.log"
"$BIN/pqonion-dirauth" --data-dir "$DIR/aut" --listen "127.0.0.1:$PAUT" \
    --interval 20 >"$LOG_AUT" 2>&1 &
PIDS+=($!)
asteapta_port "$PAUT" "autoritatea" "${PIDS[${#PIDS[@]}-1]}"
sed 's/^/     /' "$LOG_AUT"
ok "autoritatea asculta pe 127.0.0.1:$PAUT"

pas "3. Trei relee"
PORTURI=("$P1" "$P2" "$P3")
for i in 0 1 2; do
  D="$DIR/releu$i"
  mkdir -p "$D"
  # Seminte fixe, ca sa le cunoasca si clientul si serviciul ascuns.
  # DOAR pentru testnet: in realitate fiecare releu isi genereaza samanta.
  python3 -c "
b = bytearray(32); b[0] = $((i+1))
open('$D/identitate.key','wb').write(bytes(b))
" || mor "nu am putut scrie samanta releului $i"
  chmod 600 "$D/identitate.key"

  EXTRA=(--hsdir --dirauth "127.0.0.1:$PAUT")
  # Doar primul releu are consola, ca sa nu ocupam trei porturi degeaba.
  [ "$i" = "0" ] && EXTRA+=(--consola "127.0.0.1:$PCON")
  # Exit-ul permite si portul serverului de test, ca sa putem verifica
  # automat ca proxy-ul chiar transporta trafic.
  [ "$i" = "2" ] && EXTRA+=(--exit-ports "80,443,8080,$PWEB" --permite-adrese-private)

  "$BIN/pqonion-relay" --listen "127.0.0.1:${PORTURI[$i]}" \
      --data-dir "$D" "${EXTRA[@]}" 2>&1 | sed "s/^/     releu$((i+1)): /" &
  PIDS+=($!)
  asteapta_port "${PORTURI[$i]}" "releul $((i+1))" "${PIDS[${#PIDS[@]}-1]}"
done
ok "trei relee asculta pe ${PORTURI[*]}"

pas "3a. Inregistrarea releelor in consens"
# Autoritatea voteaza la fiecare 20 de secunde; asteptam un ciclu complet.
GASIT=0
for i in $(seq 1 60); do
  N=$(grep -oE 'consens: [0-9]+ relee' "$LOG_AUT" 2>/dev/null | tail -1 | grep -oE '[0-9]+')
  if [ -n "${N:-}" ] && [ "$N" -ge 3 ]; then GASIT=1; break; fi
  sleep 1
done
grep -E 'consens:' "$LOG_AUT" 2>/dev/null | tail -2 | sed 's/^/     /'
[ "$GASIT" = "1" ] || mor "releele nu au ajuns in consens (vezi $LOG_AUT)"
ok "$N relee in consens, din descriptori publicati pe retea"

pas "3b. Magazinul REST"
"$BIN/pqonion-shop" --listen "127.0.0.1:$PWEB" 2>&1 | sed 's/^/     magazin: /' &
PIDS+=($!)
asteapta_port "$PWEB" "magazinul" "${PIDS[${#PIDS[@]}-1]}"
ok "magazin REST pe 127.0.0.1:$PWEB"

pas "4. Clientul cu SOCKS5"
"$BIN/pqonion-client" --socks "127.0.0.1:$PSOCKS" \
    --guard "127.0.0.1:$P1" --middle "127.0.0.1:$P2" --exit "127.0.0.1:$P3" \
    --hsdir "127.0.0.1:$P1,127.0.0.1:$P2,127.0.0.1:$P3" \
    --data-dir "$DIR/client" 2>&1 | sed 's/^/     client: /' &
PIDS+=($!)
asteapta_port "$PSOCKS" "clientul" "${PIDS[${#PIDS[@]}-1]}"
ok "SOCKS5 pe 127.0.0.1:$PSOCKS"

pas "5. Serviciu ascuns"
ADRESA=$("$BIN/pqonion-hs" --data-dir "$DIR/hs" --adresa-doar) \
  || mor "nu am putut deriva adresa .onion"
LOG_HS="$DIR/hs.log"
# Serviciul ascuns expune serverul de test.
"$BIN/pqonion-hs" --data-dir "$DIR/hs" \
    --hsdir "127.0.0.1:$P1,127.0.0.1:$P2,127.0.0.1:$P3" \
    --target "127.0.0.1:$PWEB" >"$LOG_HS" 2>&1 &
PIDS+=($!)

for i in $(seq 1 150); do
  grep -q "puncte de introducere deschise" "$LOG_HS" 2>/dev/null && break
  sleep 0.1
done
sed 's/^/     hs: /' "$LOG_HS"
REUSITE=$(grep -oE '[0-9]+ incarcari reusite' "$LOG_HS" 2>/dev/null | grep -oE '^[0-9]+' | head -1)
[ -n "${REUSITE:-}" ] || mor "serviciul ascuns nu a raportat rezultatul publicarii"
[ "$REUSITE" -gt 0 ] || mor "nicio publicare nu a reusit"
grep -q "puncte de introducere deschise" "$LOG_HS" \
  || mor "serviciul nu a deschis puncte de introducere"
ok "$REUSITE incarcari reusite; puncte de introducere active"

pas "6. Verificare cap-coada prin proxy"
if command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  if curl -s --max-time 20 --socks5-hostname "127.0.0.1:$PSOCKS" \
       "http://localhost:$PWEB/" >/dev/null 2>&1; then
    ok "o cerere HTTP a trecut prin circuitul de 3 hop-uri"
  else
    mor "cererea prin proxy a esuat: circuitul nu transporta trafic"
  fi

  pas "7. Magazinul prin serviciul ascuns"
  RASPUNS=$(curl -s --max-time 30 --socks5-hostname "127.0.0.1:$PSOCKS" \
       "http://$ADRESA/produse?limita=2" 2>/dev/null)
  if echo "$RASPUNS" | grep -q '"total"'; then
    N=$(echo "$RASPUNS" | grep -oE '"total": [0-9]+' | grep -oE '[0-9]+')
    ok "catalogul cu $N produse, citit prin rendezvous"
  else
    mor "cererea catre .onion a esuat"
  fi

  pas "8. O comanda completa prin .onion"
  BAZA="--max-time 30 --socks5-hostname 127.0.0.1:$PSOCKS"
  # shellcheck disable=SC2086
  ANTETE=$(curl -s -D - -o /dev/null -X POST $BAZA "http://$ADRESA/cosuri")
  COS=$(echo "$ANTETE" | grep -i '^location:' | tr -d '\r' | awk '{print $2}')
  ETAG=$(echo "$ANTETE" | grep -i '^etag:' | tr -d '\r' | awk '{print $2}')
  if [ -z "$COS" ]; then mor "nu am putut crea un cos"; fi
  # shellcheck disable=SC2086
  curl -s -X PUT $BAZA -H "If-Match: $ETAG" -H "Content-Type: application/json" \
    -d '{"cantitate":2}' "http://$ADRESA$COS/articole/p-001" >/dev/null
  ID=${COS#/cosuri/}
  # shellcheck disable=SC2086
  CMD=$(curl -s -X POST $BAZA -H "Content-Type: application/json" \
    -d "{\"cos\":\"$ID\"}" "http://$ADRESA/comenzi")
  if echo "$CMD" | grep -q '"stare": "plasata"'; then
    TOTAL=$(echo "$CMD" | grep -oE '"total_bani": [0-9]+' | grep -oE '[0-9]+')
    ok "comanda plasata prin .onion, total $((TOTAL / 100)) lei"
  else
    mor "comanda prin .onion a esuat"
  fi
else
  printf "${GALBEN}  SARIT${RESET}  curl sau python3 lipseste; nu pot verifica proxy-ul\n"
fi

pas "TESTNET FUNCTIONAL"
cat <<MSG
     Circuitul: client -> $P1 -> $P2 -> $P3 -> internet

     Incearca din alt terminal:
       curl --socks5-hostname 127.0.0.1:$PSOCKS http://example.com/

     Foloseste --socks5-hostname, NU --socks5.
     Al doilea rezolva numele local si trimite cererea DNS in clar.

     Magazin ca serviciu ascuns: $ADRESA

       curl --socks5-hostname 127.0.0.1:$PSOCKS http://$ADRESA/
       curl --socks5-hostname 127.0.0.1:$PSOCKS http://$ADRESA/produse
       curl --socks5-hostname 127.0.0.1:$PSOCKS -X POST http://$ADRESA/cosuri

     Fiecare cerere trece prin HSDir, punct de introducere si rendezvous.

     Consola releului 1:  http://127.0.0.1:$PCON/
     Arata doar agregate: circuite active, celule/s, canale.

     Ctrl-C ca sa opresti.
MSG

wait
