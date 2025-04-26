import json
import re
import pyshark
from datetime import datetime, timezone

REPORT_PATH = "../input/report.txt"
PCAP_PATH = "../input/capture@eth1.pcap"
OUTPUT_PATH = "../output/filtered_packets.json"

def parse_report(path):
    with open(path, "r") as f:
        raw_report = f.read()
    
    try:
        report = json.loads(raw_report)
    except json.JSONDecodeError:
        match = re.search(r"{.*}", raw_report, re.DOTALL)
        report = json.loads(match.group(0)) if match else {}

    warnings = report.get("report", {}).get("warnings", [])
    vulnerabilities = report.get("report", {}).get("vulnerabilities", [])
    exploits = [e for e in (warnings + vulnerabilities) if e.get("id", "").startswith("CVE")]

    for e in exploits:
        for key in ["start_timestamp", "end_timestamp"]:
            if key in e:
                e[key] = datetime.fromisoformat(e[key].replace("Z", "+00:00"))
    return exploits

def filter_packets(pcap_path, time_windows):
    cap = pyshark.FileCapture(pcap_path, keep_packets=False)
    filtered = []

    for pkt in cap:
        try:
            pkt_time = datetime.fromtimestamp(float(pkt.sniff_timestamp), tz=timezone.utc)
            for start, end in time_windows:
                if start <= pkt_time <= end:
                    filtered.append({
                        "time": pkt.sniff_time.isoformat(),
                        "src": pkt.ip.src if hasattr(pkt, 'ip') else None,
                        "dst": pkt.ip.dst if hasattr(pkt, 'ip') else None,
                        "proto": pkt.transport_layer if hasattr(pkt, 'transport_layer') else None,
                        "sport": pkt[pkt.transport_layer].srcport if hasattr(pkt, 'transport_layer') else None,
                        "dport": pkt[pkt.transport_layer].dstport if hasattr(pkt, 'transport_layer') else None,
                        "payload": str(pkt.layers[-1])[:200]
                    })
                    break
        except Exception:
            continue
    cap.close()
    return filtered

def process_data():
    exploits = parse_report(REPORT_PATH)
    time_windows = [(e["start_timestamp"], e["end_timestamp"]) for e in exploits if "start_timestamp" in e and "end_timestamp" in e]
    filtered_packets = filter_packets(PCAP_PATH, time_windows)

    with open(OUTPUT_PATH, "w") as f:
        json.dump(filtered_packets, f, indent=2)

    print(f"\n🔎 Preprocesamiento completado. Paquetes filtrados guardados en {OUTPUT_PATH}")
