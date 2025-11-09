from pathlib import Path
from openai import OpenAI
import json
import os
from datetime import datetime, timezone
import requests
import re
import subprocess


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

api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)


#Model Validation

def check_ollama_model_installed(model_name="deepseek-r1"):
    """
    Comprueba si el modelo local está instalado en Ollama.
    """
    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True, check=True)
        return model_name in result.stdout
    except FileNotFoundError:
        print("[ERROR] Ollama no está instalado o no se encuentra en el PATH del sistema.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] No se pudo ejecutar 'ollama list': {e}")
        return False


def verify_openai_key(model_name):
    """
    Verifica que el modelo de OpenAI es soportado y que la API Key de OpenAI esté configurada correctamente.
    """
    if model_name.lower() not in ["gpt-4", "gpt-5", "gpt-5-mini"]:
        print("[!] Modelo de OpenAI no soportado: " + model_name)    
        return False
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("[ERROR] No se encontró la variable de entorno OPENAI_API_KEY.")
        print("        Establécela antes de continuar: export OPENAI_API_KEY='tu_api_key'")
        return False
    return True

def validate_model(model_name):
    """
    Determina si el modelo solicitado está disponible y listo para usarse.
    """
    # Modelos locales
    if model_name.lower() in ["deepseek-r1", "ollama", "local"]:
        print(f"[INFO] Se ha seleccionado el modelo local '{model_name}'. Verificando instalación...")
        if check_ollama_model_installed("deepseek-r1"):
            print("[OK] Modelo local 'deepseek-r1' disponible.")
            return True
        else:
            print("[ERROR] El modelo local 'deepseek-r1' no está instalado en Ollama.")
            print("        Instálalo con: ollama pull deepseek-r1")
            return False

    # Modelos OpenAI
    elif model_name.lower().startswith("gpt"):
        print(f"[INFO] Se ha seleccionado un modelo OpenAI: {model_name}")
        return verify_openai_key(model_name)

    # Cualquier otro modelo desconocido
    else:
        print(f"[ERROR] Modelo '{model_name}' no reconocido.")
        print("        Usa 'gpt-4', 'gpt-5', 'gpt-5-mini' o 'deepseek-r1'.")
        return False

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
- Payload: {payload_text}
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
- Protocol: {exploit.get("protocol","")}
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

def extract_content(response, model_type=None):
    """
    Extrae el texto de una respuesta del modelo, compatible con GPT-4, GPT-5 y Ollama.
    """
    # -------------------
    # Soporte GPT-4 (Chat Completions clásicos)
    # -------------------
    if hasattr(response, "choices"):
        first_choice = response.choices[0]
        if hasattr(first_choice, "message") and hasattr(first_choice.message, "content"):
            content = first_choice.message.content
            if isinstance(content, str):
                return content  # texto plano
            elif isinstance(content, list):
                # En GPT-5 o variantes, puede venir como lista de bloques
                texts = [block.get("text", "") for block in content if block.get("type") == "text"]
                return "\n".join(texts)

    # -------------------
    # Soporte GPT-5 (responses.create)
    # -------------------
    if hasattr(response, "output") and isinstance(response.output, list):
        texts = []
        for item in response.output:
            if hasattr(item, "content"):
                for c in item.content:
                    if getattr(c, "type", "") == "output_text":
                        texts.append(getattr(c, "text", ""))
        return "\n".join(texts)

    # -------------------
    # Soporte Ollama (respuesta en dict con campo "response")
    # -------------------
    if isinstance(response, dict) and "response" in response:
        raw_text = response["response"].strip()
        # Intentar extraer bloque JSON entre ```json ... ```
        match = re.search(r"```json\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                return match.group(1)
        else:
            return raw_text

    # Fallback
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


def analyze_exploits_with_llm(exploits, packets, model, max_exploit=None):
    """
    Ejecuta el análisis de IoCs y resumen técnico de los exploits usando el LLM.
    Compatible con GPT-4, GPT-5 y Ollama.
    """
    results = []
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
                    max_output_tokens=800
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
        if max_exploit is not None and num_exploit>=max_exploit:
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
                         model="gpt-5-mini",
                         max_exploit=None):
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
    results = analyze_exploits_with_llm(exploits, packets, model=model, max_exploit=max_exploit)

    print(f"Guardando resultados en {iocs_output_path}...")
    save_json(results, iocs_output_path)

    print("Ejecutando análisis opensource")

    print("\nAnálisis completado exitosamente.")

if __name__ == "__main__":
    process_ioc_analysis()
