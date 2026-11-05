#!/usr/bin/env python3
"""Generate the PCAPs used by the lab. No external host is contacted.

The packets live on RFC 1918 addresses (10.10.0.0/24) and are only ever written
to a file. Every flow is a complete TCP handshake or a complete DNS exchange so
that Suricata and Zeek can reassemble and parse it.
"""

from __future__ import annotations

from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

CLIENT = "10.10.0.20"
SERVER = "10.10.0.1"
OUT = Path(__file__).resolve().parent / "pcaps"


def finalize(packets):
    """Build each packet once so Scapy computes the IP/TCP/UDP checksums."""
    return [Ether(bytes(packet)) for packet in packets]


def tcp_exchange(src, dst, sport, dport, request: bytes, response: bytes):
    seq, sseq = 1000, 5000
    packets = [
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq),
        Ether()
        / IP(src=dst, dst=src)
        / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=seq + 1),
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags="A", seq=seq + 1, ack=sseq + 1),
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags="PA", seq=seq + 1, ack=sseq + 1)
        / Raw(request),
        Ether()
        / IP(src=dst, dst=src)
        / TCP(sport=dport, dport=sport, flags="PA", seq=sseq + 1, ack=seq + 1 + len(request))
        / Raw(response),
        Ether()
        / IP(src=src, dst=dst)
        / TCP(
            sport=sport,
            dport=dport,
            flags="A",
            seq=seq + 1 + len(request),
            ack=sseq + 1 + len(response),
        ),
    ]
    return finalize(packets)


def http_request(path: str, user_agent: str = "lab-client/1.0") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: 10.10.0.1\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode()


def http_response(body: str = "ok") -> bytes:
    return (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
        f"{body}"
    ).encode()


def dns_exchange(src, qname: str, sport: int):
    query = Ether() / IP(src=src, dst=SERVER) / UDP(sport=sport, dport=53) / DNS(
        rd=1, qd=DNSQR(qname=qname)
    )
    answer = Ether() / IP(src=SERVER, dst=src) / UDP(sport=53, dport=sport) / DNS(
        qr=1,
        aa=1,
        rd=1,
        qd=DNSQR(qname=qname),
        an=DNSRR(rrname=qname, type="A", rdata="10.10.0.99", ttl=60),
    )
    return finalize([query, answer])


def syn_packets(src, dports, sport_base=40000):
    packets = [
        Ether()
        / IP(src=src, dst=SERVER)
        / TCP(sport=sport_base + index, dport=dport, flags="S", seq=1000 + index)
        for index, dport in enumerate(dports)
    ]
    return finalize(packets)


def main() -> None:
    OUT.mkdir(exist_ok=True)

    wrpcap(str(OUT / "S01_tcp_syn_scan.pcap"), syn_packets("10.10.0.11", range(1000, 1030)))

    traversal = tcp_exchange(
        "10.10.0.12",
        SERVER,
        41000,
        80,
        http_request("/download?file=../../../../etc/passwd"),
        http_response("root:x:0:0:root:/root:/bin/bash\n"),
    )
    wrpcap(str(OUT / "S02_http_path_traversal.pcap"), traversal)

    sqli = tcp_exchange(
        "10.10.0.13",
        SERVER,
        41001,
        80,
        http_request("/item?id=1'OR'1'='1"),
        http_response("error"),
    )
    wrpcap(str(OUT / "S03_http_sqli.pcap"), sqli)

    scan_ua = tcp_exchange(
        "10.10.0.14",
        SERVER,
        41002,
        80,
        http_request("/login", user_agent="sqlmap/1.7.2#stable (https://sqlmap.org)"),
        http_response("login"),
    )
    wrpcap(str(OUT / "S04_sqlmap_user_agent.pcap"), scan_ua)

    qname = "dGhpcy1pcy1hLWxhYi1leGZpbHRyYXRpb24tY2FuYXJ5.exfil.lab"
    wrpcap(str(OUT / "S05_dns_exfil_query.pcap"), dns_exchange("10.10.0.15", qname, 53001))

    wrpcap(str(OUT / "S06_ssh_bruteforce.pcap"), syn_packets("10.10.0.16", [22] * 10, 42000))

    benign = []
    for index in range(3):
        benign += tcp_exchange(
            CLIENT,
            SERVER,
            44000 + index,
            80,
            http_request("/index.html"),
            http_response("welcome"),
        )
    benign += dns_exchange(CLIENT, "www.example.lab", 53010)
    benign += dns_exchange(CLIENT, "mail.example.lab", 53011)
    benign += syn_packets(CLIENT, [22], 45000)
    wrpcap(str(OUT / "S99_benign.pcap"), benign)

    for path in sorted(OUT.glob("*.pcap")):
        print(f"{path.name}: {path.stat().st_size} bytes")


if __name__ == "__main__":
    main()

