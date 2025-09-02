from preprocessing import preprocess_data
from analyze_iocs import process_ioc_analysis
from report_generator import generate_report
from huggingface_hub import InferenceClient


def test_hf_api():
    # Crea cliente con tu token
    client = InferenceClient(
        model="google/gemma-3-270m",
        token="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"
        )

    # Modelo abierto sencillo (puedes cambiarlo por otro)
    #model_name = "tiiuae/falcon-7b-instruct"

    # Prompt de prueba
    prompt = "¿Cuál es la capital de Francia?"

    # Llamada a la API de Hugging Face
    response = client.text_generation(
        #model=model_name,
        prompt=prompt,
        max_new_tokens=50,
        do_sample=False
    )

    print("Respuesta del modelo:")
    print(response)

def main():
    #print("\n🔎 Iniciando preprocesamiento de datos...")
    #process_data()
        
    #print("\nLlamando al modelo LLM para análisis de IoCs...")
    #process_ioc_analysis()

    #print("\n Generando el reporte...")
    #generate_report()

    test_hf_api()

    print("\nProceso completado exitosamente.")



if __name__ == "__main__":
    main()
