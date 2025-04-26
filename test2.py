import json
import re
from datetime import datetime, timezone

REPORT_PATH = "../input/report.txt"
OUTPUT_PATH = "../output/exploits_output.json"

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

print(f"\n✅ Exploits guardados en {OUTPUT_PATH}")

