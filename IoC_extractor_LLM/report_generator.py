import json
from pathlib import Path
import html

# Rutas
BASE_DIR = Path(__file__).resolve().parent
INPUT_PATH = BASE_DIR / "../output/iocs_por_exploit.json"
OUTPUT_PATH = BASE_DIR / "../output/iocs_report.html"

# Lectura del JSON
def read_json(iocs_input_path):
    with open(iocs_input_path, "r", encoding="utf-8") as f:
        return json.load(f)

# Creación del HTML
def create_html(exploits_data, output_path):
    html_content = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Informe de IoCs por Exploit</title>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Montserrat', sans-serif; margin: 0; background: #f4f7fa; color: #222; }
        header { background: #003366; color: white; padding: 32px 0; text-align: center; }
        header h1 { margin: 0; font-size: 2.5em; }
        .container { max-width: 1100px; margin: auto; padding: 32px 16px; }

        .exploit-block {
            background: #fff; border-radius: 16px; box-shadow: 0 2px 16px rgba(0,52,102,0.07);
            margin-bottom: 40px; padding: 32px; border-left: 8px solid #00b4d8;
        }
        .exploit-header { display: flex; align-items: center; gap: 18px; margin-bottom: 18px; }
        .exploit-icon { font-size: 2em; color: #00b4d8; }
        .exploit-title { font-size: 1.35em; font-weight: 600; color: #003366; }
        .badge { background: #e3f7fc; color: #00b4d8; padding: 4px 12px; border-radius: 12px; font-weight: 600; }

        .summary {
            background: #f7fafc; border-left: 4px solid #00b4d8;
            padding: 16px 18px; margin: 18px 0; border-radius: 8px;
        }

        .exploit-details {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px 32px; margin-bottom: 18px;
        }
        .exploit-details p { margin: 0; }
        .field-label { font-weight: 600; color: #003366; }

        h3 { color: #00b4d8; margin-top: 28px; }

        .packet-list { list-style: none; padding: 0; }
        .packet {
            background: #f4f7fa; border-radius: 10px;
            padding: 18px 20px; margin-bottom: 18px;
            border-left: 4px solid #00b4d8;
        }
        .packet:hover { border-left-color: #003366; }

        .protocolo-badge {
            display: inline-block; background: #00b4d8; color: white;
            border-radius: 8px; padding: 2px 10px; font-size: 0.95em;
            font-weight: 600;
        }
        em { color: #888; }

        @media (max-width: 900px) {
            .container { padding: 18px 8px; }
            .exploit-block { padding: 20px; }
            .exploit-details { grid-template-columns: 1fr; gap: 8px; }
        }
        .payload-container {
            margin-top: 8px;
        }

        .payload-container summary {
            cursor: pointer;
            color: #007bff;
            font-weight: 600;
            margin-bottom: 6px;
        }

        .payload {
            display: block;              /* importante para que se apliquen los límites */
            white-space: pre-wrap;       /* conserva saltos de línea */
            word-break: break-all;       /* rompe incluso cadenas largas */
            overflow-wrap: break-word;   /* compatibilidad extra */
            background: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 10px;
            font-family: monospace;
            font-size: 0.9em;
            max-height: 300px;
            overflow-y: auto;            /* scroll vertical si es necesario */
            overflow-x: hidden;          /* evitar scroll horizontal */
        }
    </style>
</head>
<body>
<header>
    <h1>Informe de Indicadores de Compromiso (IoCs)</h1>
</header>
<div class="container">
"""

    for exploit in exploits_data:
        meta = exploit["exploit_metadata"]
        resumen_html = exploit.get("resumen_exploit", {})
        # Obtener las tres primeras referencias (CVE, OSVDB, BID o URL)
        refs_html = ""
        if "references" in meta and isinstance(meta["references"], str):
            try:
                refs = eval(meta["references"])
                if isinstance(refs, list):
                    refs_html = ", ".join(f"{r[0]}-{r[1]}" if r[0] != "URL" else f"<a href='{r[1]}' target='_blank'>{r[1]}</a>"
                                          for r in refs[:3])
            except Exception:
                refs_html = "<em>Referencias no disponibles</em>"

        html_content += f"""
    <div class="exploit-block">
        <div class="exploit-header">
            <div class="exploit-icon">🛡️</div>
            <div class="exploit-title">
                {meta.get("id", "Sin ID")}
                <span class="badge">{refs_html or "Sin referencias"}</span>
            </div>
        </div>
        <div class="summary">{resumen_html}</div>
        <div class="exploit-details">
            <p><span class="field-label">Exploit:</span> {meta.get("exploit", "")}</p>
            <p><span class="field-label">Payload:</span> {meta.get("payload", "")}</p>
            <p><span class="field-label">Shell Type:</span> {", ".join(str(st) for st in meta.get("shell_type", []))}</p>
            <p><span class="field-label">Fuente:</span> {meta.get("source", "")}</p>
            <p><span class="field-label">Ventana temporal:</span> {meta.get("start_timestamp")} → {meta.get("end_timestamp")}</p>
            <p><span class="field-label">Fuente:</span> {meta.get("source", "")}</p>
        </div>
        <h3>Paquetes asociados</h3>
        <ul class="packet-list">"""

        for pkt in exploit["iocs"]:
            pkt_win = pkt.get("packet_timestamp", {})
            iocs = pkt.get("iocs", {})
            payload_text = pkt.get("payload_text", "")
            protocolo = pkt.get("protocol", "UNKNOWN")

            html_content += f"""
            <li class="packet">
                <div>
                    <p><span class="field-label">Timestamp:</span> {pkt_win}</p>
                    <p><span class="field-label">Protocolo:</span> <span class="protocolo-badge">{protocolo}</span></p>
                    <p><span class="field-label">Payload interpretado:</span></p>
                    <div class="payload">{payload_text}</div>
                    <p><span class="field-label">IPs:</span> {", ".join(str(ip) for ip in iocs.get("ips", []))}</p>
                    <p><span class="field-label">Puertos:</span> {" → ".join(str(p) for p in iocs.get("puertos", []))}</p>
                    <p><span class="field-label">Comandos:</span> {", ".join(str(cmd) for cmd in iocs.get("comandos", [])) or '—'}</p>
                    <p><span class="field-label">URLs:</span> {", ".join(str(url) for url in iocs.get("urls", [])) or '—'}</p>
                    <p><span class="field-label">Observaciones:</span> {iocs.get("observaciones", "")}</p>
                </div>
            </li>"""

        html_content += """
        </ul>
    </div>"""

    html_content += """
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

# Generador
def generate_report(iocs_input_path=INPUT_PATH, output_path=OUTPUT_PATH):
    exploits_data = read_json(iocs_input_path)
    if exploits_data:
        create_html(exploits_data, output_path)
        print(f"Informe HTML generado en: {output_path.resolve()}")
    else:
        print("El archivo JSON está vacío o no se pudo cargar.")
