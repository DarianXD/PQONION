#!/usr/bin/env bash
# Captureaza traficul dintre nodurile testnet-ului si produce un fisier .pcap.
#
#   ./docker/captura.sh              captureaza tot traficul de pe punte
#   ./docker/captura.sh 10.42.0.12   doar traficul unui nod anume
#
# Rezultatul se deschide cu Wireshark. Vezi `docker/analiza.py` pentru un rezumat
# in terminal, fara interfata grafica.
#
# # Ce se vede si ce nu
#
# Depinde de cum a fost pornit testnet-ul:
#
#   fara `--tls`  antetele de celula sunt vizibile: comanda, identificatorul de
#                 circuit, si dimensiunea fixa de 514 octeti. Payload-ul ramane
#                 criptat cu CGO, dar metadatele nu.
#
#   cu `--tls`    doar inregistrari TLS Application Data. Nici macar nu se poate
#                 spune cate celule sunt intr-un pachet.
#
# Rulate amandoua, capturile arata exact ce adauga TLS — si de ce nu e optional.
set -u

VERDE=$'\033[32m'; GALBEN=$'\033[33m'; ROSU=$'\033[31m'; RESET=$'\033[0m'
DURATA="${DURATA:-25}"
IESIRE="${IESIRE:-captura.pcap}"
FILTRU_NOD="${1:-}"

pas() { printf "\n${GALBEN}==> %s${RESET}\n" "$1"; }
ok()  { printf "${VERDE}  OK${RESET}  %s\n" "$1"; }
mor() { printf "${ROSU}  ESEC${RESET}  %s\n" "$1"; exit 1; }

command -v docker >/dev/null 2>&1 || mor "docker lipseste"
if docker compose version >/dev/null 2>&1; then DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"
else mor "docker compose lipseste"; fi

pas "0. Gasesc puntea retelei"
# Docker numeste interfata `br-<primele 12 caractere din id-ul retelei>`.
NET_ID=$(docker network inspect -f '{{.Id}}' pqonion_pqonion 2>/dev/null)
[ -n "$NET_ID" ] || mor "reteaua pqonion_pqonion nu exista. Porneste: $DC up -d"
PUNTE="br-${NET_ID:0:12}"
ip link show "$PUNTE" >/dev/null 2>&1 || mor "interfata $PUNTE nu exista"
ok "$PUNTE"

pas "1. Verific ca testnet-ul ruleaza"
N=$($DC ps --services --filter status=running 2>/dev/null | wc -l | tr -d ' ')
[ "$N" -ge 7 ] || mor "doar $N din 7 servicii ruleaza"
ONION=$($DC logs serviciu-ascuns 2>/dev/null | grep -oE '[a-z2-7]{56}\.onion' | tail -1)
[ -n "$ONION" ] || mor "serviciul ascuns nu si-a anuntat adresa"
ok "7 servicii, serviciu ascuns la ${ONION:0:16}..."

pas "2. Pornesc captura"
FILTRU="tcp"
[ -n "$FILTRU_NOD" ] && FILTRU="tcp and host $FILTRU_NOD"

# `tcpdump` are nevoie de privilegii pe interfata. Il rulam intr-un container cu
# reteaua gazdei, ca sa nu cerem `sudo` pe masina.
docker run --rm -d --name pqonion-captura \
  --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$(pwd):/iesire" \
  nicolaka/netshoot \
  tcpdump -i "$PUNTE" -s 0 -w "/iesire/$IESIRE" "$FILTRU" >/dev/null 2>&1 \
  || mor "nu am putut porni tcpdump. Ai imaginea nicolaka/netshoot?"
sleep 2
ok "tcpdump ruleaza pe $PUNTE, filtru: $FILTRU"

pas "3. Generez trafic ($DURATA secunde)"
BAZA="--max-time 20 --socks5-hostname 127.0.0.1:9050"
INCEPUT=$(date +%s)
CERERI=0
while [ $(( $(date +%s) - INCEPUT )) -lt "$DURATA" ]; do
  # shellcheck disable=SC2086
  curl -s $BAZA "http://$ONION/produse?limita=3" >/dev/null 2>&1 && CERERI=$((CERERI+1))
  printf "     %d cereri prin rendezvous\r" "$CERERI"
  sleep 1
done
printf "\n"
ok "$CERERI cereri"

pas "4. Opresc captura"
docker stop pqonion-captura >/dev/null 2>&1
sleep 1
[ -f "$IESIRE" ] || mor "fisierul $IESIRE nu s-a creat"
MARIME=$(du -h "$IESIRE" | cut -f1)
ok "$IESIRE ($MARIME)"

pas "GATA"
cat <<MSG
     Deschide cu:
       wireshark $IESIRE

     Sau un rezumat in terminal:
       python3 docker/analiza.py $IESIRE

     Ce merita urmarit in Wireshark:

       ip.addr == 10.42.0.11 && ip.addr == 10.42.0.12
         traficul dintre releul 1 si releul 2

       tcp.len == 514
         celule intregi. Fara TLS sunt majoritatea; cu TLS, niciuna —
         pentru ca inregistrarile TLS au alta dimensiune.

     Compara doua capturi, una cu si una fara --tls in docker-compose.yml.
     Diferenta e exact ce adauga transportul.
MSG
