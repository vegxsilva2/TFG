import requests

def query_ollama(model: str, prompt: str) -> str:
    """
    Envía un prompt a un modelo de Ollama y devuelve la respuesta completa (sin streaming).

    :param model: Nombre del modelo cargado en Ollama (ej: "deepseek-r1:7b")
    :param prompt: Texto del prompt
    :return: Respuesta generada por el modelo
    """
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }

    response = requests.post(url, json=payload)
    response.raise_for_status()  # Lanza excepción si hay error HTTP
    data = response.json()

    return data.get("response", "").strip()


# Ejemplo de uso
if __name__ == "__main__":
    result = query_ollama("deepseek-r1:7b", "Cuánto es 2+2, no quiro que me expliques tu razonamiento, solo dame la respuesta")
    print("Respuesta del modelo:", result)