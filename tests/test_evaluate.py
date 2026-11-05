import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import evaluate  # noqa: E402


def write_eve(path: Path, signatures):
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for signature in signatures:
        lines.append(
            json.dumps(
                {
                    "event_type": "alert",
                    "src_ip": "10.10.0.11",
                    "dest_ip": "10.10.0.1",
                    "proto": "TCP",
                    "alert": {"signature": signature, "signature_id": 1000101, "severity": 2},
                }
            )
        )
    lines.append(json.dumps({"event_type": "flow", "src_ip": "10.10.0.11"}))
    path.write_text("\n".join(lines), encoding="utf-8")


def test_read_alerts_ignores_non_alerts_and_bad_json(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text(
        "\n".join(
            [
                '{"event_type":"flow"}',
                "not json",
                '{"event_type":"alert","alert":{"signature":"X","signature_id":1}}',
            ]
        ),
        encoding="utf-8",
    )
    alerts = evaluate.read_alerts(eve)
    assert len(alerts) == 1
    assert alerts[0]["signature"] == "X"


def test_read_alerts_missing_file(tmp_path):
    assert evaluate.read_alerts(tmp_path / "nope.json") == []


def test_zeek_counts_skips_comments(tmp_path):
    (tmp_path / "conn.log").write_text(
        "#separator \\t\n#fields\tts\tuid\n1.0\tC1\n2.0\tC2\n", encoding="utf-8"
    )
    (tmp_path / "http.log").write_text("#fields\n", encoding="utf-8")
    counts = evaluate.zeek_counts(tmp_path)
    assert counts["conn.log"] == 2
    assert counts["http.log"] == 0
    assert counts["dns.log"] == 0


def test_evaluate_matches_expected_rules(monkeypatch, tmp_path):
    monkeypatch.setattr(evaluate, "RESULTS", tmp_path)
    expected = {
        "scenarios": [
            {"id": "S1", "title": "one", "expected_alerts": ["Rule A"]},
            {"id": "S2", "title": "two", "expected_alerts": ["Rule B"]},
        ],
        "benign": {"pcap": "x", "title": "benign", "expected_alerts": []},
    }
    write_eve(tmp_path / "suricata" / "S1" / "eve.json", ["Rule A"])
    write_eve(tmp_path / "suricata" / "S2" / "eve.json", ["Other"])
    write_eve(tmp_path / "suricata" / "S99_benign" / "eve.json", [])
    metrics = evaluate.evaluate(expected)
    assert metrics["detected"] == 1
    assert metrics["scenarios_total"] == 2
    assert metrics["recall"] == 0.5
    assert metrics["benign_alerts"] == 0
    assert metrics["per_scenario"][0]["matched"] == ["Rule A"]


def test_false_positive_is_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(evaluate, "RESULTS", tmp_path)
    expected = {
        "scenarios": [{"id": "S1", "title": "one", "expected_alerts": ["Rule A"]}],
        "benign": {"pcap": "x", "title": "benign", "expected_alerts": []},
    }
    write_eve(tmp_path / "suricata" / "S1" / "eve.json", ["Rule A"])
    write_eve(tmp_path / "suricata" / "S99_benign" / "eve.json", ["Noise"])
    metrics = evaluate.evaluate(expected)
    assert metrics["benign_alerts"] == 1
    assert metrics["benign_signatures"] == ["Noise"]


def test_expected_yaml_has_six_scenarios_and_benign():
    expected = evaluate.load_yaml(ROOT / "expected.yaml")
    assert len(expected["scenarios"]) == 6
    assert expected["benign"]["expected_alerts"] == []
    assert all(scenario["expected_alerts"] for scenario in expected["scenarios"])


def test_generation_is_deterministic_packet_count(tmp_path, monkeypatch):
    scapy = pytest.importorskip("scapy.all")
    import generate_pcaps

    monkeypatch.setattr(generate_pcaps, "OUT", tmp_path)
    generate_pcaps.main()
    names = {path.name for path in tmp_path.glob("*.pcap")}
    assert names == {
        "S01_tcp_syn_scan.pcap",
        "S02_http_path_traversal.pcap",
        "S03_http_sqli.pcap",
        "S04_sqlmap_user_agent.pcap",
        "S05_dns_exfil_query.pcap",
        "S06_ssh_bruteforce.pcap",
        "S99_benign.pcap",
    }
    packets = scapy.rdpcap(str(tmp_path / "S01_tcp_syn_scan.pcap"))
    assert len(packets) == 30
    assert all(packet["TCP"].flags == "S" for packet in packets)

    benign = scapy.rdpcap(str(tmp_path / "S99_benign.pcap"))
    assert len(benign) > 3 * 6

