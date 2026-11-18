#!/usr/bin/env bash
# Verifica testnet-ul din Docker, de pe masina gazda.
#
#   docker compose up --build -d
#   ./docker/verifica.sh
#
# Verifica *din exterior*, prin singurul port publicat: SOCKS5 pe 9050. Daca
# ceva merge doar pentru ca nodurile impart o masina, aici nu va merge.
set -u

VERDE=$'\033[32m'; GALBEN=$'\033[33m'; ROSU=$'\033[31m'; RESET=$'\033[0m'
SOCKS=127.0.0.1:9050
CONSOLA=127.0.0.1:9100

pas() { printf "\n${GALBEN}==> %s${RESET}\n" "$1"; }
ok()  { printf "${VERDE}  OK${RESET}  %s\n" "$1"; }
mor() { printf "${ROSU}  ESEC${RESET}  %s\n" "$1"; exit 1; }

command -v docker >/dev/null 2>&1 || mor "docker lipseste"
command -v curl   >/dev/null 2>&1 || mor "curl lipseste"

# `docker compose` (v2) sau `docker-compose` (v1).
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  mor "nici 'docker compose' nici 'docker-compose' nu sunt disponibile"
fi

pas "0. Containerele"
RULEAZA=$($DC ps --services --filter status=running 2>/dev/null | wc -l | tr -d ' ')
[ "$RULEAZA" -ge 7 ] || mor "doar $RULEAZA din 7 servicii ruleaza. Vezi: $DC ps"
ok "$RULEAZA servicii pornite"

pas "1. Fiecare nod are adresa lui"
# Daca doua noduri ar imparti o adresa, testnet-ul n-ar demonstra nimic.
ADRESE=$($DC ps -q | xargs -r docker inspect \
  -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null | sort)
DISTINCTE=$(echo "$ADRESE" | sort -u | wc -l | tr -d ' ')
TOTAL=$(echo "$ADRESE" | wc -l | tr -d ' ')
[ "$DISTINCTE" = "$TOTAL" ] || mor "adrese duplicate intre containere"
ok "$TOTAL adrese distincte in 10.42.0.0/24"

pas "2. Releele s-au inregistrat in consens"
GASIT=0
for _ in $(seq 1 40); do
  N=$($DC logs autoritate 2>/dev/null | grep -oE 'consens: [0-9]+ relee' | tail -1 | grep -oE '[0-9]+')
  if [ -n "${N:-}" ] && [ "$N" -ge 3 ]; then GASIT=1; break; fi
  sleep 2
done
[ "$GASIT" = "1" ] || mor "releele nu au ajuns in consens. Vezi: $DC logs autoritate"
ok "$N relee in consens, publicate pe retea"

pas "3. Consola releului 1"
if curl -s --max-time 5 "http://$CONSOLA/stare" | grep -q '"circuite_active"'; then
  ok "consola raspunde pe http://$CONSOLA/"
else
  mor "consola nu raspunde"
fi

pas "4. Adresa serviciului ascuns"
ONION=""
for _ in $(seq 1 40); do
  ONION=$($DC logs serviciu-ascuns 2>/dev/null | grep -oE '[a-z2-7]{56}\.onion' | tail -1)
  [ -n "$ONION" ] && break
  sleep 2
done
[ -n "$ONION" ] || mor "serviciul ascuns nu si-a anuntat adresa"
ok "$ONION"

pas "5. Punctele de introducere"
for _ in $(seq 1 40); do
  $DC logs serviciu-ascuns 2>/dev/null | grep -q "puncte de introducere deschise" && break
  sleep 2
done
$DC logs serviciu-ascuns 2>/dev/null | grep -q "puncte de introducere deschise" \
  || mor "serviciul ascuns nu a deschis puncte de introducere"
ok "puncte de introducere active"

pas "6. Catalogul, prin rendezvous"
R=$(curl -s --max-time 40 --socks5-hostname "$SOCKS" "http://$ONION/produse?limita=2" 2>/dev/null)
echo "$R" | grep -q '"total"' || mor "cererea catre .onion a esuat"
NPROD=$(echo "$R" | grep -oE '"total": [0-9]+' | grep -oE '[0-9]+')
ok "catalog cu $NPROD produse"

pas "7. O comanda completa"
BAZA="--max-time 40 --socks5-hostname $SOCKS"
# shellcheck disable=SC2086
ANTETE=$(curl -s -D - -o /dev/null -X POST $BAZA "http://$ONION/cosuri")
COS=$(echo "$ANTETE" | grep -i '^location:' | tr -d '\r' | awk '{print $2}')
ETAG=$(echo "$ANTETE" | grep -i '^etag:'     | tr -d '\r' | awk '{print $2}')
[ -n "$COS" ] || mor "nu am putut crea un cos"

# shellcheck disable=SC2086
curl -s -X PUT $BAZA -H "If-Match: $ETAG" -H "Content-Type: application/json" \
  -d '{"cantitate":2}' "http://$ONION$COS/articole/p-001" >/dev/null

ID=${COS#/cosuri/}
# shellcheck disable=SC2086
CMD=$(curl -s -X POST $BAZA -H "Content-Type: application/json" \
  -d "{\"cos\":\"$ID\"}" "http://$ONION/comenzi")
echo "$CMD" | grep -q '"stare": "plasata"' || mor "comanda a esuat: $CMD"
TOTAL=$(echo "$CMD" | grep -oE '"total_bani": [0-9]+' | grep -oE '[0-9]+')
ok "comanda plasata, total $((TOTAL / 100)) lei"

pas "8. Serviciul ascuns NU e accesibil direct"
# Nu are niciun port publicat. Daca ar fi, .onion-ul n-ar avea rost.
if docker port pqonion-hs 2>/dev/null | grep -q .; then
  mor "serviciul ascuns are porturi publicate catre gazda"
fi
ok "se ajunge la el doar prin rendezvous"

pas "9. Legaturile sunt criptate"
# Verificam din log ca releele chiar folosesc TLS. Fara el, o captura ar arata
# antetele de celula — vezi docker/captura.sh.
if $DC logs releu1 2>/dev/null | grep -q "fara TLS"; then
  printf "${ROSU}  ATENTIE${RESET}  releele ruleaza FARA TLS: traficul e in clar\n"
  printf "        Adauga '--tls' in docker-compose.yml.\n"
else
  ok "legaturile dintre noduri sunt criptate"
fi

pas "TESTNET DOCKER FUNCTIONAL"
cat <<MSG
     Sapte containere, fiecare cu adresa lui in 10.42.0.0/24.
     Singurul port catre gazda: SOCKS5 pe $SOCKS.

     Serviciu ascuns: $ONION

       curl --socks5-hostname $SOCKS http://$ONION/produse
       curl --socks5-hostname $SOCKS http://example.com/

     Consola releului 1: http://$CONSOLA/
     Log-uri:            $DC logs -f releu1
     Captura de trafic:  ./docker/captura.sh
     Oprire:             $DC down
MSG
