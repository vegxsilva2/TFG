from preprocessing import process_data
from analyze_iocs import analyze_iocs

def main():
    print("🔎 Iniciando preprocesamiento de datos...")
    process_data()

    print("\n🤖 Llamando al modelo LLM para análisis de IoCs...")
    analyze_iocs()
    
    print("\n✅ Proceso completado exitosamente.")

if __name__ == "__main__":
    main()