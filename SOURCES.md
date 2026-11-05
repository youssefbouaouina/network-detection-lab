# Sources and licences

| Component | Version | Licence | Use |
|---|---|---|---|
| Suricata | Ubuntu 24.04 package (7.x), version recorded in `results/suricata_version.txt` | GPL-2.0 | IDS/IPS engine and rules |
| Zeek | `security:zeek` Ubuntu 24.04 package, version recorded in `results/zeek_version.txt` | BSD-3-Clause | Protocol logs |
| Scapy | 2.6.1 | GPL-2.0 | PCAP generation |
| PyYAML / pytest / ruff | 6.0.2 / 8.3.4 / 0.8.4 | MIT | Evaluation and CI |
| RFC 1918 addresses | n/a | n/a | 10.10.0.0/24 lab subnet |

No third-party PCAP, malware sample or rule set is redistributed. The six Suricata rules and all
captures are original to this repository. The captures are generated into `pcaps/` and contain
no real traffic.

Code and rules: MIT.
