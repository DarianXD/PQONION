#!/usr/bin/env python3
"""Rezumatul unei capturi de trafic pqonion.

    python3 docker/analiza.py captura.pcap

Fara dependente: parseaza direct formatul pcap clasic, care are un antet de 24
de octeti si cate 16 per pachet. Wireshark ramane util pentru inspectie
detaliata; asta e pentru cifrele care intra in lucrare.

# Ce raspunde

- Cat trafic circula intre fiecare pereche de noduri.
- Ce dimensiuni au segmentele TCP, si daca predomina cele de dimensiunea unei
  celule (514 octeti).
- Daca traficul e criptat cu TLS sau nu, dupa antetul inregistrarilor.
"""

import collections
import struct
import sys

# Dimensiunea unei celule pe fir, din `pqo_wire`.
CELULA = 514

# Numele nodurilor din testnet, ca rezumatul sa fie citibil.
NODURI = {
    "10.42.0.10": "autoritate",
    "10.42.0.11": "releu1",
    "10.42.0.12": "releu2",
    "10.42.0.13": "releu3",
    "10.42.0.20": "magazin",
    "10.42.0.21": "serviciu-ascuns",
    "10.42.0.30": "client",
}


def nume(ip):
    return NODURI.get(ip, ip)


def citeste_pcap(cale):
    """Produce (sursa, destinatie, port_sursa, port_dest, payload_tcp)."""
    with open(cale, "rb") as f:
        antet = f.read(24)
        if len(antet) < 24:
            raise SystemExit(f"{cale}: prea scurt ca sa fie un pcap")

        magic = antet[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            end, nano = "<", False
        elif magic == b"\xa1\xb2\xc3\xd4":
            end, nano = ">", False
        elif magic == b"\x4d\x3c\xb2\xa1":
            end, nano = "<", True
        elif magic == b"\xa1\xb2\x3c\x4d":
            end, nano = ">", True
        elif magic[:4] == b"\x0a\x0d\x0d\x0a":
            raise SystemExit(
                f"{cale} e in format pcapng, nu pcap.\n"
                "Converteste cu:  tshark -r fisier.pcapng -w fisier.pcap -F pcap"
            )
        else:
            raise SystemExit(f"{cale}: nu recunosc formatul")
        _ = nano

        linktype = struct.unpack(end + "I", antet[20:24])[0]
        # 1 = Ethernet, 113 = Linux cooked. Puntea Docker e Ethernet.
        offset_l3 = 14 if linktype == 1 else 16

        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            _, _, caplen, _ = struct.unpack(end + "IIII", ph)
            date = f.read(caplen)
            if len(date) < caplen:
                return

            if len(date) < offset_l3 + 20:
                continue
            ip = date[offset_l3:]
            if (ip[0] >> 4) != 4:
                continue
            ihl = (ip[0] & 0x0F) * 4
            if ip[9] != 6:  # doar TCP
                continue
            total = struct.unpack(">H", ip[2:4])[0]
            src = ".".join(str(b) for b in ip[12:16])
            dst = ".".join(str(b) for b in ip[16:20])

            tcp = ip[ihl:]
            if len(tcp) < 20:
                continue
            sport, dport = struct.unpack(">HH", tcp[:4])
            doff = (tcp[12] >> 4) * 4
            payload = tcp[doff : total - ihl]
            yield src, dst, sport, dport, payload


def main():
    if len(sys.argv) != 2:
        raise SystemExit("folosire: python3 docker/analiza.py FISIER.pcap")

    perechi = collections.Counter()
    octeti = collections.Counter()
    dimensiuni = collections.Counter()
    tls_inregistrari = 0
    cu_payload = 0

    for src, dst, _sp, _dp, payload in citeste_pcap(sys.argv[1]):
        cheie = tuple(sorted([nume(src), nume(dst)]))
        perechi[cheie] += 1
        octeti[cheie] += len(payload)
        if payload:
            cu_payload += 1
            dimensiuni[len(payload)] += 1
            # Antet de inregistrare TLS: tip 0x14-0x17, versiune 0x03 0x0X.
            if len(payload) >= 5 and 0x14 <= payload[0] <= 0x17 and payload[1] == 0x03:
                tls_inregistrari += 1

    if not perechi:
        raise SystemExit("captura nu contine trafic TCP")

    print("\n=== Trafic intre noduri ===\n")
    print(f"  {'pereche':34s} {'pachete':>8s} {'octeti':>10s}")
    print("  " + "-" * 54)
    for (a, b), n in perechi.most_common():
        print(f"  {a + ' <-> ' + b:34s} {n:8d} {octeti[(a, b)]:10d}")

    print("\n=== Dimensiuni de segment TCP ===\n")
    print(f"  {'octeti':>8s} {'pachete':>8s}")
    print("  " + "-" * 18)
    for d, n in dimensiuni.most_common(10):
        marca = "  <- celula intreaga" if d == CELULA else ""
        print(f"  {d:8d} {n:8d}{marca}")

    celule = dimensiuni.get(CELULA, 0)
    print("\n=== Interpretare ===\n")
    if tls_inregistrari > cu_payload * 0.5:
        print(f"  Traficul pare CRIPTAT cu TLS.")
        print(f"  {tls_inregistrari} din {cu_payload} segmente au antet de inregistrare TLS.")
        print()
        print("  Un observator vede doar 'Application Data'. Nu poate spune cate")
        print("  celule sunt intr-un segment, nici pe ce circuit merg.")
    else:
        print(f"  Traficul pare IN CLAR.")
        print(f"  {celule} segmente de exact {CELULA} octeti — celule intregi.")
        print()
        print("  Un observator vede antetele de celula: comanda si identificatorul")
        print("  de circuit. Payload-ul ramane criptat cu CGO, dar metadatele nu.")
        print("  Porneste testnet-ul cu --tls si compara.")

    print()
    print("  Ce NU se poate deduce din nicio varianta: ce circuit din")
    print("  releu1<->releu2 corespunde carui circuit din releu2<->releu3.")
    print("  Fiecare hop are propriul strat CGO, deci aceiasi octeti utili")
    print("  arata complet diferit pe cele doua legaturi.")
    print()


if __name__ == "__main__":
    main()
