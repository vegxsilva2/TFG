from openai import OpenAI

client = OpenAI(api_key="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")


def generar_texto(prompt):
    try:
        # Llamada a la API de OpenAI utilizando ChatCompletion
        respuesta = client.chat.completions.create(
        model="gpt-3.5-turbo",      # Modelo a utilizar
        messages=[
            {"role": "system", "content": "Eres un asistente útil."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=100,            # Número máximo de tokens en la respuesta
        temperature=0.7)           # Controla la creatividad de la respuesta
        # Devuelve el texto generado
        return respuesta.choices[0].message.content.strip()
    except Exception as e:
        # Manejo de excepciones
        return f"Error al generar texto: {e}"

# Ejemplo de uso
if __name__ == "__main__":
    prompt = "Escribe un poema sobre la inteligencia artificial"
    resultado = generar_texto(prompt)
    print("Texto generado:")
    print(resultado)