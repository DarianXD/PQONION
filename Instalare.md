# Instalare și rulare — pqonion

## 1. Instalează Rust

**Linux / macOS:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

**Windows:** instalează [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (workload „Desktop development with C++"), apoi [rustup-init.exe](https://rustup.rs).

Verificare:
```bash
rustc --version && cargo --version
```

## 2. Componente Rust suplimentare

```bash
rustup component add clippy rustfmt
```

## 3. Python 3

```bash
python3 --version
```
Dacă lipsește: `sudo apt install python3` (Linux) / `brew install python3` (macOS) / [python.org](https://python.org) (Windows, bifează „Add to PATH").

## 4. Docker (opțional, doar pt. testnet în containere)

[Docker Desktop](https://www.docker.com/products/docker-desktop/) sau [Docker Engine](https://docs.docker.com/engine/install/).

## 5. Compilare

```bash
cd pqonion
cargo build --all-targets
```

## 6. Verificare completă

```bash
./verifica.sh
```

## 7. Rulare

**Local:**
```bash
./testnet.sh
```

**Docker:**
```bash
docker compose up --build -d
./docker/verifica.sh
```

Test manual:
```bash
curl --socks5-hostname 127.0.0.1:9050 http://example.com/
curl --socks5-hostname 127.0.0.1:9050 http://<adresa>.onion/
```

Oprire: `docker compose down`

## Probleme frecvente

| Problemă | Soluție |
|---|---|
| `command not found: cargo` | `source "$HOME/.cargo/env"` sau redeschide terminalul |
| `no default toolchain set` | `rustup default stable` |
| porturi ocupate | `pkill -f pqonion-` |
| fișiere neformatate | `cargo fmt` |