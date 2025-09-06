from huggingface_hub import InferenceClient

# Inicializa el cliente con tu HF_TOKEN (que debes haber generado en https://huggingface.co/settings/tokens)
hf_token = "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"
client = InferenceClient(token=hf_token)

# Modelo ligero y abierto que soporta text-generation vía API
model_name = "deepseek-ai/DeepSeek-V3.1-Base"  # se ejecuta en la nube, no en tu máquina

# Prompt sencillo de prueba
prompt = "Escribe un resumen técnico sobre un exploit de tipo SQL Injection."

# Llamada a la API
response = client.text_generation(
    model=model_name,
    prompt=prompt,
    max_new_tokens=200,
    do_sample=False
)

# El resultado viene como lista de dicts con 'generated_text'
print("Respuesta del modelo:")
print(response[0]['generated_text'])