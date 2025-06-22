from preprocessing import process_data
from analyze_iocs import process_ioc_analysis

def main():
    #print("🔎 Iniciando preprocesamiento de datos...")
    #process_data()
        
    print("\n🤖 Llamando al modelo LLM para análisis de IoCs...")
    process_ioc_analysis()
    
    print("\n✅ Proceso completado exitosamente.")

if __name__ == "__main__":
    main()
