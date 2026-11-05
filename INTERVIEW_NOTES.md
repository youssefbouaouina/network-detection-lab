# Interview notes - network-detection-lab

## The 60-second version

I wrote six Suricata rules and seven PCAPs, then measured the rules against those captures with
Suricata 7.0.3 and Zeek 9.0.1: 6/6 scenarios detected, 0 alerts on the benign capture. The
value is not the six rules; it is that the ground truth was frozen before the first run, the
evaluation reads the real `eve.json` and Zeek logs, and the gate fails if either number moves.

## Why generated PCAPs instead of a public malware capture set

Public malware PCAPs usually come with redistribution restrictions and can contain real victim
data. Generating RFC 1918 traffic with Scapy keeps the repository licence-clean (MIT) and makes
the ground truth exact: I know which packet was supposed to trigger which rule. The cost is
realism, and I state it in the README rather than pretending these are production captures.
If I had a licensed capture set, the same `evaluate.py` would work; only `expected.yaml` and the
generator would change.

## Why not ET Open

The brief for this project suggested ET Open as v1 and custom rules as v2. I did not do that
because measuring ET Open on tiny synthetic flows would understate it and produce a number that
means nothing. Instead the experiment measures the six rules in this repository. The trade-off
is documented in `DECISIONS.md` and in the README limitations. A next step would be to rerun the
same harness on a licensed capture set and add ET Open as a second scanner.

## Ground truth design

`expected.yaml` gives each scenario exactly one expected signature, and the benign capture zero.
Per-scenario PCAPs mean one alert cannot satisfy two scenarios. Detection is strict: the
signature name must match, not just any alert. That avoids the "something fired, call it a
detection" failure mode.

## Rule choices worth defending

- **SYN scan:** `threshold: type both, track by_src, count 20, seconds 5`. `type both` alerts on
  the first packet after the threshold and then once per interval, instead of once per packet.
- **SSH brute force:** counts SYN packets to port 22, not completed logins, because the capture
  has no credentials. It measures connection attempts, which is what the scenario generates.
- **HTTP rules:** inspect `http.uri` and `http.user_agent`, so Suricata's HTTP parser does the
  work and the rule does not hand-roll a byte match across TCP segments.
- **DNS exfiltration:** a content match on `.exfil.lab` in `dns.query`; a production rule would
  add label length/entropy because an attacker controls the domain.

## False positives

Zero on one benign capture is a weak claim, and I say so. The benign capture has six connections,
three HTTP requests and two DNS transactions; it is a smoke test, not a traffic sample. The
dashboard-worthy metric would be alerts per hour over days of real traffic, which this lab
cannot produce without a licensed dataset.

## Zeek's role

Suricata answers "did a rule fire". Zeek answers "did the traffic parse": `conn.log` shows 30
SYNs for the scan and 10 connections for SSH, `http.log` shows the request URI, `dns.log` shows
the queried name. If a rule stops firing because the protocol parser changed, the Zeek counts
tell me whether the capture or the rule is at fault.

## What I would do next

1. Replace the synthetic set with a licensed capture corpus and keep the same harness.
2. Add ET Open plus the custom rules, and report alerts per hour on a long benign capture.
3. Add JA3/JA4 and beacon-periodicity detections, which need flow state the current rules do not use.
4. Run Suricata in IPS mode against a local container to test drop rules, not just alerts.

## Questions to expect

**"Isn't 6/6 overfitting?"** The rules were written for the scenarios, which is what detection
engineering is. The evaluation is not fitted because the ground truth was committed first and
the gate is independent of the rules. The honest limitation is that both the traffic and the
rules are mine.

**"Why is a benign alert count of 0 not impressive?"** Because the benign capture is small. I
report the Zeek parse counts next to it so the reader can judge how much traffic it represents.

**"How would this scale?"** Suricata and Zeek are the same tools used in production; the harness
would need a capture source (SPAN, AF_PACKET), rule management (suricata-update), and a much
larger benign baseline. The evaluation code would not change.
