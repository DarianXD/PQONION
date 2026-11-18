# Imagine pentru testnet-ul din Docker.
#
# Un singur binar-set pentru toate rolurile: releu, autoritate, client, serviciu
# ascuns, magazin. Rolul se alege prin comanda din docker-compose, nu prin imagini
# separate — altfel ar trebui reconstruite cinci imagini la fiecare schimbare.

# ---------------------------------------------------------------------------
FROM rust:1-slim-bookworm AS constructor

WORKDIR /src

# Intai doar manifestele, ca stratul cu dependente sa se refoloseasca intre
# reconstructii cand se schimba doar codul.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

# `pq` e obligatoriu: un testnet fara ML-KEM ar demonstra arhitectura, dar nu si
# subiectul lucrarii. `tls` la fel — fara el, traficul dintre relee circula in
# clar si o captura ar arata exact opusul a ce sustine lucrarea.
RUN cargo build --release --features pq,tls --bins

# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

# `curl` pentru verificarile din testnet; `ca-certificates` pentru cazul in care
# exit-ul chiar iese in internet.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=constructor \
     /src/target/release/pqonion-relay \
     /src/target/release/pqonion-dirauth \
     /src/target/release/pqonion-client \
     /src/target/release/pqonion-hs \
     /src/target/release/pqonion-shop \
     /usr/local/bin/

COPY docker/pornire.sh /usr/local/bin/pornire.sh
RUN chmod +x /usr/local/bin/pornire.sh

# Nu rulam ca root. Un releu compromis nu are de ce sa poata scrie in imagine.
RUN useradd --system --create-home --home-dir /var/lib/pqonion pqonion
USER pqonion
WORKDIR /var/lib/pqonion

ENTRYPOINT ["/usr/local/bin/pornire.sh"]
