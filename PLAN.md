# PLAN — network-detection-lab

## Goal

Measure a small, hand-written Suricata ruleset against six network attack scenarios and one
benign capture, and show what Zeek's protocol logs add. Every capture is generated locally; no
external host is contacted and no third-party PCAP is redistributed.

## Why generated PCAPs

Malware-traffic PCAPs have restrictive licences and often contain real victim data. Generating
the traffic keeps the licence clean (MIT), makes the ground truth exact, and lets anyone rerun
the lab offline. The cost is realism: these are protocol-correct but synthetic flows, not a
sample of production traffic. That limitation is stated in the README.

## Scenarios and rules

| Scenario | Suricata rule | Logic |
|---|---|---|
| S01 TCP SYN scan | `LAB TCP SYN scan` (sid 1000101) | 20 SYN packets from one source in 5 s |
| S02 HTTP path traversal | `LAB HTTP path traversal` (1000102) | `../` in `http.uri` |
| S03 HTTP SQL injection | `LAB HTTP SQL injection` (1000103) | `OR'1'='1` in `http.uri` |
| S04 sqlmap user agent | `LAB sqlmap user agent` (1000104) | `sqlmap` in `http.user_agent` |
| S05 DNS exfiltration | `LAB DNS exfiltration query` (1000105) | `.exfil.lab` in `dns.query` |
| S06 SSH brute force | `LAB SSH brute force` (1000106) | 8 SYNs to port 22 from one source in 10 s |
| S99 benign | none | normal HTTP, DNS and one SSH connection |

## Ground truth

`expected.yaml` was committed before the first Suricata run. It names, for each scenario, the
signature that counts as a detection, and declares zero expected alerts on the benign capture.

## Metrics

- Scenario recall (alerts whose signature is the expected one).
- Alerts on the benign capture (false positives).
- Zeek `conn.log` / `http.log` / `dns.log` row counts per capture, proving the traffic parsed.
- The CI gate requires 6/6 detection and 0 benign alerts.

## Tools

Suricata and Zeek from Ubuntu 24.04 packages (versions recorded in `results/`), Scapy 2.6.1 to
write the PCAPs. The rules are the only rule file loaded (`suricata -S rules/lab.rules`), so a
detection is attributable to this repo.

## Time box

2-3 hours. Suricata and Zeek are Linux-only here, so the evaluation runs in GitHub Actions.
