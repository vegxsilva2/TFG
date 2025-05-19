import json
import re
import pyshark
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REPORT_PATH = BASE_DIR / "../input/report.txt"
PCAP_PATH = BASE_DIR / "../input/capture@eth1.pcap"
EXPLOITS_OUTPUT_PATH = BASE_DIR / "../output/exploits_output.json"
PACKETS_OUTPUT_PATH = BASE_DIR / "../output/filtered_packets.json"

def parse_report(path):
    
    with open(REPORT_PATH, "r") as f:
        raw_report = f.read()
    
    try:
        report = json.loads(raw_report)
    except json.JSONDecodeError:
        match = re.search(r"{.*}", raw_report, re.DOTALL)
        report = json.loads(match.group(0)) if match else {}

    exploits = []

    reports_list = report.get("reports", [])


    for r in reports_list:
        report_content = r.get("report", {})

        #Procesar vulnerabilities
        vulnerabilities = report_content.get("vulnerabilities", {})
        for vuln_id, entries in vulnerabilities.items():
            for entry in entries:
                exploit_info = {
                    "id": vuln_id,
                    "exploit": entry.get("exploit"),
                    "payload": entry.get("payload"),
                    "references": entry.get("references"),
                    "shell_type": entry.get("shell_type"),
                    "source": "vulnerability"
                }
                timestamps = entry.get("timestamp", [])
                if len(timestamps) == 2:
                    exploit_info["start_timestamp"] = datetime.fromisoformat(timestamps[0]).replace(tzinfo=timezone.utc)
                    exploit_info["end_timestamp"] = datetime.fromisoformat(timestamps[1]).replace(tzinfo=timezone.utc)
                exploits.append(exploit_info)

        #Procesar warnigns
        warnings = report_content.get("warnings", {})
        for cve_id, entries in warnings.items():
            for entry in entries:
                exploit_info = {
                    "cve": cve_id,
                    "exploit": entry.get("exploit"),
                    "payload": entry.get("payload"),
                    "references": entry.get("references"),
                    "shell_type": entry.get("shell_type"),
                    "source": "warning"
                }
                timestamps = entry.get("timestamp", [])
                if len(timestamps) == 2:
                    exploit_info["start_timestamp"] = datetime.fromisoformat(timestamps[0]).replace(tzinfo=timezone.utc)
                    exploit_info["end_timestamp"] = datetime.fromisoformat(timestamps[1]).replace(tzinfo=timezone.utc)

                exploits.append(exploit_info)        

    with open(EXPLOITS_OUTPUT_PATH, "w") as f:
        json.dump(exploits, f, indent=2, default=str)

    return exploits


def filter_exploits_by_source(exploits, allowed_sources=["vulnerability"]):
    """
    Filtra los exploits por su fuente (source).
    
    :param exploits: Lista de exploits procesados.
    :param allowed_sources: Lista de tipos de source permitidos ("vulnerability", "warning").
    :return: Lista de exploits filtrados.
    """
    return [e for e in exploits if e.get("source") in allowed_sources]

def report_timestamps(exploits):
    timestamps = [(e["start_timestamp"], e["end_timestamp"]) for e in exploits if "start_timestamp" in e and "end_timestamp" in e]
    print(timestamps)
    return timestamps

def normalize_time_windows(time_windows):
    """
    Convierte todas las tuplas de tiempo (start, end) en objetos datetime con zona horaria UTC.

    Parámetros:
        time_windows (list): Lista de tuplas (start, end), en formato str o datetime.

    Devuelve:
        list: Lista de tuplas normalizadas (datetime UTC, datetime UTC).
    """
    parsed_windows = []
    for start, end in time_windows:
        if isinstance(start, str):
            start = datetime.fromisoformat(start).replace(tzinfo=timezone.utc)
        else:
            start = start.replace(tzinfo=timezone.utc)

        if isinstance(end, str):
            end = datetime.fromisoformat(end).replace(tzinfo=timezone.utc)
        else:
            end = end.replace(tzinfo=timezone.utc)

        parsed_windows.append((start, end))
    return parsed_windows

def find_matching_window(pkt_time, time_windows):
    """
    Determina a qué ventana temporal pertenece un paquete.

    Parámetros:
        pkt_time (datetime): Timestamp del paquete (UTC).
        time_windows (list): Lista de tuplas (start, end) con timestamps UTC.

    Devuelve:
        dict | None: Diccionario con los timestamps 'start' y 'end' en formato ISO si hay coincidencia,
                     o None si no cae dentro de ninguna ventana.
    """
    for start, end in time_windows:
        if start <= pkt_time <= end:
            return {"start": start.isoformat(), "end": end.isoformat()}
    return None

def extract_packet_dict(pkt, pkt_time, matched_window):
    """
    Extrae toda la información relevante de un paquete, incluyendo timestamp y capas.

    Parámetros:
        pkt (pyshark.packet.packet.Packet): Paquete capturado por PyShark.
        pkt_time (datetime): Timestamp UTC del paquete.
        matched_window (dict): Ventana temporal a la que pertenece el paquete.

    Devuelve:
        dict: Representación serializable del paquete con 'timestamp', 'window' y 'layers'.
    """
    pkt_dict = {
        "timestamp": pkt_time.isoformat(),
        "window": matched_window,
        "layers": {}
    }

    for layer in pkt.layers:
        layer_name = layer.layer_name
        pkt_dict["layers"][layer_name] = {}

        for field_name in layer.field_names:
            try:
                value = getattr(layer, field_name)
                pkt_dict["layers"][layer_name][field_name] = value
            except AttributeError:
                continue

    return pkt_dict

def group_packets_by_windows(pcap_path, time_windows=None):
    """
    Filtra un archivo .pcap por ventanas temporales y extrae paquetes enriquecidos con metadatos.

    Parámetros:
        pcap_path (str | Path): Ruta al archivo .pcap.
        time_windows (list): Lista de tuplas (start, end) con timestamps UTC o str.

    Devuelve:
        list: Lista de diccionarios, cada uno representando un paquete con capas + metadata.
    """
    cap = pyshark.FileCapture(pcap_path, keep_packets=False)
    packets = []

    if time_windows:
        time_windows = normalize_time_windows(time_windows)

    for pkt in cap:
        try:
            pkt_time = datetime.fromtimestamp(float(pkt.sniff_timestamp), tz=timezone.utc)
            matched_window = find_matching_window(pkt_time, time_windows)
            if not matched_window:
                continue

            pkt_dict = extract_packet_dict(pkt, pkt_time, matched_window)
            packets.append(pkt_dict)

        except Exception as e:
            print(f"Error processing packet: {e}")
            continue

    cap.close()

    with open(PACKETS_OUTPUT_PATH, "w") as f:
        json.dump(packets, f, indent=2, default=str)

    return packets

def validate_filtered_packets(packet_json_path, time_windows):
    with open(packet_json_path, "r") as f:
        packets = json.load(f)

    total = len(packets)
    passed = 0
    failed = 0

    for pkt in packets:
        pkt_time = datetime.fromisoformat(pkt["timestamp"])  # ISO 8601 con tzinfo

        if any(start <= pkt_time <= end for start, end in time_windows):
            passed += 1
        else:
            failed += 1
            print(f"❌ Paquete fuera de rango: {pkt_time.isoformat()}")

    print(f"\n✅ Paquetes en rango: {passed}")
    print(f"❌ Paquetes fuera de rango: {failed}")
    print(f"📦 Total en archivo: {total}")

    assert failed == 0, "Hay paquetes que no cumplen las ventanas de tiempo."

    return passed, failed

def count_all_packets_in_windows(pcap_path, time_windows):
    cap = pyshark.FileCapture(pcap_path, keep_packets=False)
    count = 0
    first_match_time = None
    last_match_time = None

    for pkt in cap:
        try:
            pkt_time = datetime.fromtimestamp(float(pkt.sniff_timestamp), tz=timezone.utc)

            if any(start <= pkt_time <= end for start, end in time_windows):
                count += 1
                if first_match_time is None:
                    first_match_time = pkt_time
                last_match_time = pkt_time

        except Exception:
            continue

    cap.close()

    print(f"\n🔍 Total paquetes en ventanas (raw .pcap): {count}")
    if first_match_time:
        print(f"⏱ Primer paquete en ventana: {first_match_time}")
        print(f"⏱ Último paquete en ventana: {last_match_time}")

    return count

def process_data():
    exploits = parse_report(REPORT_PATH)
    time_windows = report_timestamps(exploits)
    print(time_windows)
    grouped_packets = group_packets_by_windows(PCAP_PATH, time_windows)


    print(f"\n🔎 Preprocesamiento completado. Paquetes filtrados guardados en {EXPLOITS_OUTPUT_PATH} y en {PACKETS_OUTPUT_PATH}")

    """
    # Validación
    print("\n🧪 Validando paquetes filtrados...")
    validate_filtered_packets(PACKETS_OUTPUT_PATH, time_windows)
    
    print("\n📊 Comprobando si se han perdido paquetes en el filtrado...")
    total_in_pcap = count_all_packets_in_windows(PCAP_PATH, time_windows)

    if total_in_pcap != len(filtered_packets):
        print(f"⚠️ Atención: se esperaban {total_in_pcap} paquetes pero solo se guardaron {len(filtered_packets)}.")
    else:
        print("✅ Todos los paquetes de las ventanas han sido guardados.")
    """