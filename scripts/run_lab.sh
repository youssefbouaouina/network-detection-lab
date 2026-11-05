#!/usr/bin/env bash
# Run Suricata and Zeek over every generated PCAP and keep their raw output.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
rm -rf results
mkdir -p results/suricata results/zeek

suricata --build-info > results/suricata_version.txt 2>&1 || true
zeek --version > results/zeek_version.txt 2>&1 || true
scapy_version=$(python -c 'import scapy; print(scapy.__version__)')
echo "scapy $scapy_version" >> results/suricata_version.txt

for pcap in pcaps/*.pcap; do
  name=$(basename "$pcap" .pcap)
  mkdir -p "results/suricata/$name" "results/zeek/$name"
  echo "== $name =="
  suricata -r "$pcap" -l "results/suricata/$name" -S rules/lab.rules -k none \
    --set default-log-dir="$ROOT/results/suricata/$name" \
    > "results/suricata/$name/stdout.txt" 2> "results/suricata/$name/stderr.txt" || true
  (
    cd "results/zeek/$name"
    zeek -C -r "$ROOT/$pcap" > zeek.stdout 2>&1 || true
  )
done

python evaluate.py
