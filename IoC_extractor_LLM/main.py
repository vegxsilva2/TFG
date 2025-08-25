from preprocessing import preprocess_data
from analyze_iocs import process_ioc_analysis
from report_generator import generate_report

def main():
    #print("\n🔎 Iniciando preprocesamiento de datos...")
    #process_data()
        
    #print("\n🤖 Llamando al modelo LLM para análisis de IoCs...")
    #process_ioc_analysis()

    print("\n Generando el reporte...")
    generate_report()

    print("\n✅ Proceso completado exitosamente.")

if __name__ == "__main__":
    main()
