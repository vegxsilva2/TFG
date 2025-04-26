import json
import re
import pyshark
from datetime import datetime, timezone

REPORT_PATH = "../input/report.txt"
PCAP_PATH = "../input/capture@eth1.pcap"
OUTPUT_PATH = "../output/filtered_packets.json"

def parse_report(path):
    
    with open(REPORT_PATH, "r") as f:
        raw_report = f.read()
    
    try:
        report = json.loads(raw_report)
    except json.JSONDecodeError:
        match = re.search(r"{.*}", raw_report, re.DOTALL)
        report = json.loads(match.group(0)) if match else {}

    exploits = []

    reports_list = report.get("reports", [])


    for r in reports_list:
        report_content = r.get("report", {})

        #Procesar vulnerabilities
        vulnerabilities = report_content.get("vulnerabilities", {})
        for vuln_id, entries in vulnerabilities.items():
            for entry in entries:
                exploit_info = {
                    "id": vuln_id,
                    "exploit": entry.get("exploit"),
                    "payload": entry.get("payload"),
                    "references": entry.get("references"),
                    "shell_type": entry.get("shell_type"),
                    "source": "vulnerability"
                }
                timestamps = entry.get("timestamp", [])
                if len(timestamps) == 2:
                    exploit_info["start_timestamp"] = datetime.fromisoformat(timestamps[0])
                    exploit_info["end_timestamp"] = datetime.fromisoformat(timestamps[1])
                exploits.append(exploit_info)

        #Procesar warnigns
        warnings = report_content.get("warnings", {})
        for cve_id, entries in warnings.items():
            for entry in entries:
                exploit_info = {
                    "cve": cve_id,
                    "exploit": entry.get("exploit"),
                    "payload": entry.get("payload"),
                    "references": entry.get("references"),
                    "shell_type": entry.get("shell_type"),
                    "source": "warning"
                }
                timestamps = entry.get("timestamp", [])
                if len(timestamps) == 2:
                    exploit_info["start_timestamp"] = datetime.fromisoformat(timestamps[0])
                    exploit_info["end_timestamp"] = datetime.fromisoformat(timestamps[1])
                exploits.append(exploit_info)        

    with open(OUTPUT_PATH, "w") as f:
        json.dump(exploits, f, indent=2, default=str)

    return exploits


def filter_exploits_by_source(exploits, allowed_sources=["vulnerability"]):
    """
    Filtra los exploits por su fuente (source).
    
    :param exploits: Lista de exploits procesados.
    :param allowed_sources: Lista de tipos de source permitidos ("vulnerability", "warning").
    :return: Lista de exploits filtrados.
    """
    return [e for e in exploits if e.get("source") in allowed_sources]


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
