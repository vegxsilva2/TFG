from transformers import AutoModelForCausalLM, AutoTokenizer

model_name = "fdtn-ai/Foundation-Sec-8B"

# Tokenizer
tokenizer = AutoTokenizer.from_pretrained(model_name)

# Modelo (usa device_map="auto" para GPU si tienes)
model = AutoModelForCausalLM.from_pretrained(
    model_name,
    device_map="auto",
    torch_dtype="auto",
    trust_remote_code=True
)

# Prueba de generación
prompt = "Traduce al inglés: Hola Mundo"
inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

outputs = model.generate(**inputs, max_new_tokens=100)
print(tokenizer.decode(outputs[0], skip_special_tokens=True))
