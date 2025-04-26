
from openai import OpenAI
import json

# Llamada al LLM para extraer IoCs del tráfico filtrado
OPENAI_API_KEY = "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"
INPUT_PATH = "../output/filtered_packets.json"
OUTPUT_PATH = "../output/iocs_extraidos.json"

def call_openai_api(filtered_packets):


    client = OpenAI(api_key=OPENAI_API_KEY)

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

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "Eres un analista de seguridad experto en tráfico de red."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2,
        max_tokens=1000
    )

    return response.choices[0].message.content


def analyze_iocs():
    with open(INPUT_PATH, "r") as f:
        filtered_packets = json.load(f)

    ioc_results = call_openai_api(filtered_packets)

    with open(OUTPUT_PATH, "w") as f:
        f.write(ioc_results)

    print("\n🤖 IoCs extraídos y guardados en", OUTPUT_PATH)
