# Script para analizar informe de pentesting y captura de red, extraer IoCs y asociarlos con trazas

import json
import os
import re
import pyshark
from openai import OpenAI

client = OpenAI(api_key=OPENAI_API_KEY)
from datetime import datetime, timezone


# Configuración inicial
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")  # O puedes asignarla directamente aquí
REPORT_PATH = "report.txt"
PCAP_PATH = "capture@eth1.pcap"

# Cargar y parsear el informe
with open(REPORT_PATH, "r") as f:
    raw_report = f.read()

# Convertir texto plano a JSON si es posible (lo asumimos para este caso)
try:
    report = json.loads(raw_report)
except json.JSONDecodeError:
    match = re.search(r"{.*}", raw_report, re.DOTALL)
    report = json.loads(match.group(0)) if match else {}

warnings = report.get("report", {}).get("warnings", [])
vulnerabilities = report.get("report", {}).get("vulnerabilities", [])

# Filtrar entradas válidas con CVE
exploits = [e for e in (warnings + vulnerabilities) if e.get("id", "").startswith("CVE")]

# Convertir timestamps a objetos datetime
for e in exploits:
    for key in ["start_timestamp", "end_timestamp"]:
        if key in e:
            e[key] = datetime.fromisoformat(e[key].replace("Z", "+00:00"))

# Extraer ventanas de tiempo
time_windows = [(e["start_timestamp"], e["end_timestamp"]) for e in exploits if "start_timestamp" in e and "end_timestamp" in e]

# Filtrar tráfico del pcap por esas ventanas
cap = pyshark.FileCapture(PCAP_PATH, keep_packets=False)
filtered_packets = []

for pkt in cap:
    try:
        pkt_time = datetime.fromtimestamp(float(pkt.sniff_timestamp), tz=timezone.utc)
        for start, end in time_windows:
            if start <= pkt_time <= end:
                filtered_packets.append({
                    "time": pkt.sniff_time.isoformat(),
                    "src": pkt.ip.src if hasattr(pkt, 'ip') else None,
                    "dst": pkt.ip.dst if hasattr(pkt, 'ip') else None,
                    "proto": pkt.transport_layer if hasattr(pkt, 'transport_layer') else None,
                    "sport": pkt[pkt.transport_layer].srcport if hasattr(pkt, 'transport_layer') else None,
                    "dport": pkt[pkt.transport_layer].dstport if hasattr(pkt, 'transport_layer') else None,
                    "payload": str(pkt.layers[-1])[:200]  # Limitar longitud del payload
                })
                break
    except Exception:
        continue

cap.close()

# Llamada al LLM para extraer IoCs del tráfico filtrado

prompt = f"""
Estas son trazas de red obtenidas durante ataques de pentesting. Extrae indicadores de compromiso (IoCs), como:
- direcciones IP maliciosas
- dominios
- comandos de shell
- rutas sospechosas
- payloads relevantes

Trazas:
{json.dumps(filtered_packets[:30], indent=2)}

Responde en formato JSON con claves como "ips", "dominios", "comandos", "urls", "payloads".
"""

response = client.chat.completions.create(model="gpt-4",
messages=[
    {"role": "system", "content": "Eres un analista de seguridad experto en tráfico de red."},
    {"role": "user", "content": prompt}
],
temperature=0.2,
max_tokens=1000)

# Mostrar resultados
ioc_results = response.choices[0].message.content
print("\nIoCs extraídos por el LLM:\n", ioc_results)

# Puedes guardar los resultados a disco
with open("iocs_extraidos.json", "w") as f:
    f.write(ioc_results)

print("\nAnálisis completado y resultados guardados en iocs_extraidos.json")