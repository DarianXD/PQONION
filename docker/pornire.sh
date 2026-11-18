#!/bin/sh
# Scrie samanta de testnet, apoi porneste rolul cerut.
#
# DOAR PENTRU TESTNET. Intr-un deployment real fiecare nod isi genereaza samanta
# la prima pornire si nimeni altcineva nu o cunoaste. Aici o derivam din index,
# ca sa poata clientii si serviciile ascunse sa afle cheile fara un sistem de
# director complet.
set -e

if [ -n "$INDEX_SAMANTA" ]; then
  DIR="${DATA_DIR:-/var/lib/pqonion/date}"
  FISIER="${NUME_CHEIE:-identitate.key}"
  mkdir -p "$DIR"

  if [ ! -f "$DIR/$FISIER" ]; then
    # Primul octet e indexul; restul zerouri. Aceeasi derivare ca in
    # `pqo_bin::testnet_seed` si `testnet_authority_seed`.
    printf "$(printf '\\%03o' "$INDEX_SAMANTA")" > "$DIR/$FISIER"
    dd if=/dev/zero bs=1 count=31 >> "$DIR/$FISIER" 2>/dev/null
    chmod 600 "$DIR/$FISIER"
  fi
fi

exec "$@"
