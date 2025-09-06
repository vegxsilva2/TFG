import argparse
from pathlib import Path
from preprocessing import preprocess_data
from analyze_iocs import process_ioc_analysis
from report_generator import generate_report

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_REPORT_PATH = (BASE_DIR / "../input/report.txt").resolve()
DEFAULT_PCAP_PATH = (BASE_DIR / "../input/capture@eth1.pcap").resolve()

def main():
    parser = argparse.ArgumentParser(
        description="Pipeline de análisis IoC mediante LLMs"
    )

    # Entradas
    parser.add_argument("--report-path", required=False, help="Ruta al informe de exploits (JSON)")
    parser.add_argument("--pcap-path", required=False, help="Ruta al archivo .pcap")

    # Salida base
    parser.add_argument("--output-dir", required=True, help="Directorio donde guardar los resultados")

    # Modelo a usar
    parser.add_argument(
        "--model",
        required=False,
        default="gpt-4",
        help="Modelo LLM a usar (ej: gpt-4, gpt-5, gpt-5-mini)"
    )

    args = parser.parse_args()

    # Validar report-path
    if args.report_path:
        report_path = Path(args.report_path)
        if not report_path.exists():
            print(f"[!] Archivo report no encontrado, usando por defecto: {DEFAULT_REPORT_PATH}")
            report_path = DEFAULT_REPORT_PATH
    else:
        report_path = DEFAULT_REPORT_PATH

    if not report_path.exists():
        raise FileNotFoundError(f"Archivo de report por defecto no encontrado: {report_path}")

    # Validar pcap-path
    if args.pcap_path:
        pcap_path = Path(args.pcap_path)
        if not pcap_path.exists():
            print(f"[!] Archivo pcap no encontrado, usando por defecto: {DEFAULT_PCAP_PATH}")
            pcap_path = DEFAULT_PCAP_PATH
    else:
        pcap_path = DEFAULT_PCAP_PATH

    if not pcap_path.exists():
        raise FileNotFoundError(f"Archivo pcap por defecto no encontrado: {pcap_path}")

    # Crear directorio de salida si no existe
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Definir rutas de salida automáticamente
    exploits_output = output_dir / "exploits.json"
    packets_output = output_dir / "refined_packets.json"
    iocs_output = output_dir / "iocs.json"
    report_output = output_dir / "report.html"

    print("Iniciando preprocesamiento de datos...")
    preprocess_data(
        report_path=report_path,
        pcap_path=pcap_path,
        exploits_output_path=exploits_output,
        packets_output_path=packets_output
    )

    print("\nLlamando al modelo LLM para análisis de IoCs...")
    process_ioc_analysis(
        exploits_input_path=exploits_output,
        packets_input_path=packets_output,
        iocs_output_path=iocs_output,
        model=args.model 
    )

    print("\nGenerando el reporte...")
    generate_report(
        iocs_input_path=iocs_output,
        output_path=report_output
    )

    print(f"\nProceso completado exitosamente. Resultados guardados en: {output_dir}")

if __name__ == "__main__":
    main()
