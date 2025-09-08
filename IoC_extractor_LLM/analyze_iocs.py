from pathlib import Path
from openai import OpenAI
import json
import os
from datetime import datetime, timezone
import requests
import re


#Refinado el promt para obtener el output deseado -> DONE
#Decidir si es necesario enviar todos los paquetes por exploit al LLM (aporta esto información extra?) -> DONE
#   Solucion -> Coger 5 (o los que queramos) paquetes por exploit que sean lo más significativos y menos redundantes posible
#Obtener el resultado para un exploit basándome en el número de paquetes decidido en la task anterior -> DONE
#Obtener el resultado para todos los exploits -> TBD

# Paths
BASE_DIR = Path(__file__).resolve().parent
EXPLOITS_INPUT_PATH = BASE_DIR / "../output/exploits_output.json"
PACKETS_INPUT_PATH = BASE_DIR / "../output/refined_packets.json"
IOCS_OUTPUT_PATH = BASE_DIR / "../output/iocs_por_exploit2.json"


# API Key. Algun dia lo pondré por variable de entorno pero hoy no va a ser
OPENAI_API_KEY = "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"
client = OpenAI(api_key=OPENAI_API_KEY)

def load_json(path):
    """
    Carga un archivo JSON desde una ruta especificada y devuelve su contenido.

    La función abre el archivo en modo lectura, lo interpreta como JSON y 
    devuelve el objeto Python correspondiente (lista o diccionario). 

    :param path: Ruta del archivo JSON a cargar.
    :return: Objeto Python resultante del parseo del JSON.
    """
    with open(path, "r") as f:
        return json.load(f)

def match_packets_to_exploit(exploit, packets):
    """
    Asocia paquetes de red con un exploit en función de sus ventanas temporales.

    La función compara las marcas de tiempo de inicio y fin de un exploit 
    con las ventanas de los paquetes. Devuelve únicamente aquellos paquetes 
    cuya ventana coincide exactamente con la del exploit. 

    :param exploit: Diccionario con metadatos del exploit (incluyendo timestamps).
    :param packets: Lista de diccionarios con información de paquetes refinados.
    :return: Lista de paquetes coincidentes con el exploit.
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
    #print(matched)

    return matched

def build_analysis_prompt(exploit, packet):
    """
    Construye el prompt para el LLM con la información de un exploit y un paquete.

    El prompt incluye detalles técnicos del exploit, el contenido del paquete
    (protocolo, payload, capas) y una plantilla JSON para la extracción de IoCs. 
    Está diseñado para guiar al modelo en la identificación de indicadores de 
    compromiso a nivel de red.

    :param exploit: Diccionario con los detalles de un exploit específico.
    :param packet: Diccionario con los datos de un paquete asociado.
    :return: Cadena de texto con el prompt completo para el LLM.
    """
    protocol = packet.get("protocol", "UNKNOWN")
    payload_text = packet.get("payload_text", "").strip()
    prompt_template = f"""
ROLE: Cybersecurity analyst.
TASK: Extract Indicators of Compromise (IoC) from the provided JSON packet traces.
NOTES: 
 - The network packets are anonymized and come from a pentesting session.
 - The most relevant protocol involved is: {protocol}
 - If the payload contains hexadecimal data, analyze and interpret it according to the expected behavior of the {protocol} protocol. 
 - Look for embedded commands, identifiers, file names, credentials, or any meaningful information inside the decoded payload.
 - Return only a valid JSON object. Do NOT include any explanation or wrap the result in code blocks (e.g. ```json).
 - Your output must only include IoCs and a concise technical summary of what happened, without disclaimers or generic recommendations.
 - Do not explain reliability or false positives.
 - Include any IPs, ports, payloads, commands, or URLs you find relevant.
 - Return only a JSON output following the exact format.
 - Do not include your internal reasoning or thought process.

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

def build_summary_prompt(exploit, iocs_por_paquete):
    """
    Construye el prompt para el LLM encargado de generar un resumen global del exploit.

    Toma como entrada los IoCs extraídos previamente de los paquetes asociados 
    a un exploit y genera un contexto que permita al modelo redactar una síntesis 
    técnica sobre el patrón de ataque.

    :param exploit: Diccionario con metadatos del exploit.
    :param iocs_por_paquete: Lista de IoCs (uno por paquete) en formato JSON.
    :return: Cadena de texto con el prompt de resumen para el LLM.
    """
    prompt_template = f"""
ROLE: Cybersecurity analyst.
TASK: Based on the Indicators of Compromise (IoCs) extracted from the network packets of this exploit,
write a technical narrative summary of the exploit's activity in Spanish.

NOTES:
- Output MUST be a plaintext
- Write a continuous paragraph, detailed, please DO NOT write more than 100 words.
- Include IPs, ports, payloads, commands, tools, attack sequence, suspicious activity.
- Do NOT add recommendations, disclaimers, or any other JSON fields.
- Do not include your internal reasoning or thought process.

EXPLOIT:
- ID: {exploit.get("id", "N/A")}
- CVE: {exploit.get("cve", "")}
- Payload: {exploit.get("payload", "")}
- Shell Type: {exploit.get("shell_type", "")}
- Time Window: {exploit.get("start_timestamp")} → {exploit.get("end_timestamp")}

IoCs extraídos por paquete:
{json.dumps(iocs_por_paquete, indent=2)}

OUTPUT FORMAT:
{
    "Un párrafo de texto técnico en español que describa completamente la actividad del exploit."
}
"""
    return prompt_template

def extract_content(choice, model_type=None):
    """
    Extrae el texto de una respuesta del modelo, compatible con GPT-4, GPT-5 y Ollama.
    """
    if hasattr(choice, "message") and hasattr(choice.message, "content"):
        content = choice.message.content
        # GPT-4
        if isinstance(content, str):
            return content
        # GPT-5: lista de bloques
        elif isinstance(content, list):
            texts = [block.get("text", "") for block in content if block.get("type") == "text"]
            return "\n".join(texts)
    elif hasattr(choice, "output") and isinstance(choice.output, list):
        # GPT-5 responses.create
        texts = []
        for item in choice.output:
            if hasattr(item, "content"):
                for c in item.content:
                    if getattr(c, "type", "") == "output_text":
                        texts.append(getattr(c, "text", ""))
        return "\n".join(texts)
    elif isinstance(choice, dict) and "response" in choice:
        # Ollama JSON response
        raw_text = choice["response"].strip()
        # Extraer bloque JSON encerrado entre ```json ... ```
        match = re.search(r"```json\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                # Si no se puede parsear, devolver el texto crudo
                return match.group(1)
        else:
            # Si no hay bloque JSON, devolver el texto crudo
            return raw_text
    return ""


def query_ollama(model: str, prompt: str) -> dict:
    """
    Realiza una llamada a Ollama REST API.
    Devuelve el JSON completo de la respuesta.
    """
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }
    response = requests.post(url, json=payload)
    response.raise_for_status()
    return response.json()


def analyze_exploits_with_llm(exploits, packets, model):
    """
    Ejecuta el análisis de IoCs y resumen técnico de los exploits usando el LLM.
    Compatible con GPT-4, GPT-5 y Ollama.
    """
    results = []
    max_exploit = 5
    num_exploit = 0

    for exploit in exploits:
        matched_packets = match_packets_to_exploit(exploit, packets)
        if not matched_packets:
            continue

        exploit_results = []
        solo_iocs = []

        for packet in matched_packets:
            prompt = build_analysis_prompt(exploit, packet)

            if model.startswith("gpt-4"):
                response = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": "Eres un experto analista de ciberseguridad."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2,
                    max_tokens=600
                )
            elif model.startswith("gpt-5"):
                response = client.responses.create(
                    model=model,
                    input=f"Eres un experto analista de ciberseguridad.\n\n{prompt}",
                    reasoning={"effort": "low"},
                    text={"verbosity": "low"},
                    max_output_tokens=600
                )
            else:  # Ollama
                response = query_ollama(
                    model=model,
                    prompt=f"Eres un experto analista de ciberseguridad.\n\n{prompt}"
                )

            try:
                content = extract_content(response, model_type=model)
                if isinstance(content, dict):
                    parsed = content
                else:
                    parsed = json.loads(content)
                print("==== PARSED MODEL OUTPUT ====")
                print(parsed)
                print("==========================")
            except json.JSONDecodeError:
                raw = extract_content(response, model_type=model)
                print("==== RAW MODEL OUTPUT ====")
                print(raw)
                print("==========================")
                parsed = {"raw": raw}

            exploit_results.append({
                "packet_timestamp": packet.get("timestamp"),
                "protocol": packet.get("protocol", "UNKNOWN"),
                "payload_text": packet.get("payload_text", ""),
                "iocs": parsed
            })

            solo_iocs.append(parsed)

        # Generar resumen del exploit
        summary_prompt = build_summary_prompt(exploit, solo_iocs)

        if model.startswith("gpt-4"):
            summary_response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "Eres un experto analista de ciberseguridad."},
                    {"role": "user", "content": summary_prompt}
                ],
                temperature=0.2,
                max_tokens=500
            )
        elif model.startswith("gpt-5"):
            summary_response = client.responses.create(
                model=model,
                input=f"Eres un experto analista de ciberseguridad.\n\n{summary_prompt}",
                reasoning={"effort": "low"},
                text={"verbosity": "low"},
                max_output_tokens=500
            )
        else:  # Ollama
            summary_response = query_ollama(
                model=model,
                prompt=f"Eres un experto analista de ciberseguridad.\n\n{summary_prompt}"
            )

        try:
            content = extract_content(summary_response, model_type=model)
            if isinstance(content, dict):
                parsed = content
            else:
                parsed = json.loads(content)
            resumen_exploit = parsed.get("resumen", "").strip()
        except json.JSONDecodeError:
            resumen_exploit = extract_content(summary_response, model_type=model).strip()

        results.append({
            "exploit_id": exploit.get("id") or exploit.get("cve"),
            "exploit_metadata": exploit,
            "iocs": exploit_results,
            "resumen_exploit": resumen_exploit
        })

        num_exploit += 1
        if num_exploit == max_exploit:
            break

    return results

def save_json(data, path):
    """
    Guarda un objeto Python en un archivo JSON en la ruta especificada.

    La función convierte el objeto a formato JSON con indentación para mayor 
    legibilidad y lo escribe en disco.

    :param data: Objeto Python a guardar (lista o diccionario).
    :param path: Ruta de salida para el archivo JSON.
    """
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def process_ioc_analysis(exploits_input_path=EXPLOITS_INPUT_PATH,
                         packets_input_path=PACKETS_INPUT_PATH,
                         iocs_output_path=IOCS_OUTPUT_PATH,
                         model="gpt-4"):
    """
    Orquesta el flujo completo de análisis de IoCs para los exploits.

    Pasos principales:
      1. Cargar exploits y paquetes refinados desde archivos JSON.
      2. Ejecutar el análisis de IoCs con el LLM.
      3. Guardar los resultados (IoCs y resúmenes por exploit) en disco.
    
    :return: None
    """
    
    print("\nCargando exploits y paquetes refinados...")
    exploits = load_json(exploits_input_path)
    packets = load_json(packets_input_path)

    print("Ejecutando análisis de IoCs por exploit...")
    results = analyze_exploits_with_llm(exploits, packets, model=model)

    print(f"Guardando resultados en {iocs_output_path}...")
    save_json(results, iocs_output_path)

    print("Ejecutando análisis opensource")

    #Opensource
    #results = analyze_exploits_with_hf_api(exploits,packets)
    #save_json(results,BASE_DIR / "../output/opensource.json")

    print("\nAnálisis completado exitosamente.")

if __name__ == "__main__":
    process_ioc_analysis()
