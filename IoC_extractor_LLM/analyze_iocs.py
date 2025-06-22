from pathlib import Path
from openai import OpenAI
import json
import os
from datetime import datetime, timezone

#Refinado el promt para obtener el output deseado -> DONE
#Decidir si es necesario enviar todos los paquetes por exploit al LLM (aporta esto información extra?) -> TBD
#Obtener el resultado para un exploit basándome en el número de paquetes decidido en la task anterior -> TBD
#Obtener el resultado para todos los exploits -> TBD

# Paths
BASE_DIR = Path(__file__).resolve().parent
EXPLOITS_INPUT_PATH = BASE_DIR / "../output/exploits_output.json"
PACKETS_INPUT_PATH = BASE_DIR / "../output/refined_packets.json"
IOCS_OUTPUT_PATH = BASE_DIR / "../output/iocs_por_exploit.json"

# API Key. Algun dia lo pondré por variable de entorno pero hoy no va a ser
OPENAI_API_KEY = "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"
client = OpenAI(api_key=OPENAI_API_KEY)

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)

def match_packets_to_exploit(exploit, packets):
    """
    Devuelve los paquetes cuya ventana de tiempo coincide exactamente con la del exploit.
    Se asegura que ambas fechas estén normalizadas como datetime con UTC.
    """
    try:
        start = datetime.fromisoformat(exploit["start_timestamp"]).replace(tzinfo=timezone.utc)
        end = datetime.fromisoformat(exploit["end_timestamp"]).replace(tzinfo=timezone.utc)
    except Exception:
        return []

    matched = []
    for pkt in packets:
        try:
            pkt_start = datetime.fromisoformat(pkt["window"]["start"]).replace(tzinfo=timezone.utc)
            pkt_end = datetime.fromisoformat(pkt["window"]["end"]).replace(tzinfo=timezone.utc)
        except Exception:
            continue

        if pkt_start == start and pkt_end == end:
            matched.append(pkt)

    print("=====================================")
    print("Para el exploit: " + exploit.get("id", "N/A") + " con CVE: " + exploit.get("cve","") + " y timestamp " + exploit.get("start_timestamp","") + " - " + exploit.get("end_timestamp","") + " se encontraron los paquetes:")
    print("=====================================")
    print(matched)

    return matched

def build_prompt(exploit, packet):
    """
    Construye un prompt detallado para el LLM siguiendo estructura basada en plantilla.
    """
    prompt_template = f"""
ROLE: Cybersecurity analyst.
TASK: Extract Indicators of Compromise (IoC) from the provided JSON packet traces.
NOTES: 
 - The network packets are anonymized and come from a pentesting session.
 - Return only a valid JSON object. Do NOT include any explanation or wrap the result in code blocks (e.g. ```json).
 - Your output must only include IoCs and a concise technical summary of what happened, without disclaimers or generic recommendations.
 - Do not explain reliability or false positives.
 - Include any IPs, ports, payloads, commands, or URLs you find relevant.
 - Return only a JSON output following the exact format.

EXPLOIT DETAILS:
- ID: {exploit.get("id", "N/A")}
- CVE: {exploit.get("cve", "")}
- Exploit: {exploit.get("exploit", "")}
- Payload: {exploit.get("payload", "")}
- References: {exploit.get("references","")}
- Shell Type: {exploit.get("shell_type", "")}
- Source: {exploit.get("source", "")}
- Time Window: {exploit.get("start_timestamp")} to {exploit.get("end_timestamp")}

TRACES:
{json.dumps(packet, indent=2)}

OUTPUT FORMAT (in JSON):
{{
  "ips": [],
  "puertos": [],
  "payloads": [],
  "comandos": [],
  "urls": [],
  "observaciones": "Breve descripción técnica, sin recomendaciones."
}}
"""
    return prompt_template

def analyze_exploits_with_llm(exploits, packets):
    """
    Ejecuta el análisis de IoCs para cada exploit y sus paquetes relacionados.
    """
    results = []

    for exploit in exploits:
        matched_packets = match_packets_to_exploit(exploit, packets)
        if not matched_packets:
            continue
        
        exploit_results = []
        for packet in matched_packets:
            
            prompt = build_prompt(exploit, packet)

            response = client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "Eres un experto analista de ciberseguridad."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=400
            )

            try:
                parsed = json.loads(response.choices[0].message.content)
            except json.JSONDecodeError:
                parsed = {"raw": response.choices[0].message.content}

            exploit_results.append({
                "packet_window": packet.get("window"),
                "iocs": parsed
            })

            print("################")
            print("Para el paquete")
            print(packet)
            #Solo primera iteración para debugear
            break

        results.append({
            "exploit_id": exploit.get("id") or exploit.get("cve"),
            "exploit_metadata": exploit,
            "iocs": exploit_results
        })

        print("RESULTADOS DEL TODOPODEROSO")
        print("############################")
        print(results)
        #Solo primera iteración para debugear
        break
    return results

def save_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def process_ioc_analysis():
    print("\n🔄 Cargando exploits y paquetes refinados...")
    exploits = load_json(EXPLOITS_INPUT_PATH)
    packets = load_json(PACKETS_INPUT_PATH)

    print("🧠 Ejecutando análisis de IoCs por exploit...")
    results = analyze_exploits_with_llm(exploits, packets)

    print(f"💾 Guardando resultados en {IOCS_OUTPUT_PATH}...")
    save_json(results, IOCS_OUTPUT_PATH)

    print("\n✅ Análisis completado exitosamente.")

if __name__ == "__main__":
    process_ioc_analysis()
