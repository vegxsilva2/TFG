import json
from pathlib import Path

# Carga del JSON generado por el LLM
BASE_DIR = Path(__file__).resolve().parent
INPUT_PATH = BASE_DIR / "../output/iocs_por_exploit3.json"
OUTPUT_PATH = BASE_DIR / "../output/informe_iocs.html"

def read_json():
    with open(INPUT_PATH, "r") as f:
        return json.load(f)

def create_html(exploits_data):
    html = """
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Informe de IoCs por Exploit</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f7f7f7; }
            h1 { color: #333; }
            h2 { background: #003366; color: white; padding: 10px; }
            h3 { color: #003366; }
            .exploit-block { background: white; padding: 20px; margin-bottom: 30px; border-radius: 8px; box-shadow: 0 0 5px #ccc; }
            .packet { margin-bottom: 15px; padding: 10px; border-left: 3px solid #003366; background: #f0f0f0; border-radius: 4px; }
            .field-label { font-weight: bold; color: #333; }
            ul { padding-left: 20px; }
        </style>
    </head>
    <body>
    <h1>Informe de Indicadores de Compromiso (IoCs)</h1>
    """

    for exploit in exploits_data:
        meta = exploit["exploit_metadata"]
        resumen = exploit["resumen_exploit"].get("resumen", "")
        html += f"""
        <div class="exploit-block">
            <h2>Exploit: {meta.get("id", "Sin ID")} - {meta.get("cve", "")}</h2>
            <p><span class="field-label">Resumen:</span> {resumen}</p>
            <p><span class="field-label">Exploit:</span> {meta.get("exploit", "")}</p>
            <p><span class="field-label">Payload:</span> {meta.get("payload", "")}</p>
            <p><span class="field-label">Shell Type:</span> {", ".join(meta.get("shell_type", []))}</p>
            <p><span class="field-label">Fuente:</span> {meta.get("source", "")}</p>
            <p><span class="field-label">Ventana temporal:</span> {meta.get("start_timestamp")} → {meta.get("end_timestamp")}</p>
            <h3>Paquetes asociados:</h3>
        """

        for pkt in exploit["iocs"]:
            pkt_win = pkt.get("packet_window", {})
            iocs = pkt.get("iocs", {})
            payload_text = pkt.get("payload_text", "")
            html += f"""
            <div class="packet">
                <p><span class="field-label">Ventana:</span> {pkt_win.get("start")} → {pkt_win.get("end")}</p>
                <p><span class="field-label">Protocolo:</span> {pkt.get("protocol", "UNKNOWN")}</p>
                <p><span class="field-label">Payload interpretado:</span> {payload_text or '<em>No disponible</em>'}</p>
                <p><span class="field-label">IPs:</span> {", ".join(iocs.get("ips", []))}</p>
                <p><span class="field-label">Puertos:</span> {", ".join(iocs.get("puertos", []))}</p>
                <p><span class="field-label">Comandos:</span> {", ".join(iocs.get("comandos", [])) or '—'}</p>
                <p><span class="field-label">URLs:</span> {", ".join(iocs.get("urls", [])) or '—'}</p>
                <p><span class="field-label">Observaciones:</span> {iocs.get("observaciones", "")}</p>
            </div>
            """

        html += "</div>"

    html += "</body></html>"

    # Guardar el HTML en disco
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(html)
    

def generate_report():
    json_file = read_json()
    create_html(json_file)
    print(f"✅ Informe HTML generado en: {OUTPUT_PATH.resolve()}")
