import json
import re
import pyshark
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter, defaultdict 


BASE_DIR = Path(__file__).resolve().parent
REPORT_PATH = BASE_DIR / "../input/report.txt"
PCAP_PATH = BASE_DIR / "../input/capture@eth1.pcap"
EXPLOITS_OUTPUT_PATH = BASE_DIR / "../output/exploits_output.json"
PACKETS_OUTPUT_PATH = BASE_DIR / "../output/filtered_packets.json"
FILTERED_PACKETS_OUTPUT_PATH = BASE_DIR / "../output/refined_packets.json"
FILTERED_PACKETS2_OUTPUT_PATH = BASE_DIR / "../output/refined_packets2.json"

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
    Por si solo nos interesa ver las vulnerability y no los warnings
    
    :param exploits: Lista de exploits procesados.
    :param allowed_sources: Lista de tipos de source permitidos ("vulnerability", "warning").
    :return: Lista de exploits filtrados.
    """
    return [e for e in exploits if e.get("source") in allowed_sources]

def report_timestamps(exploits):
    """
    Extrae las ventanas temporales (start, end) de los exploits procesados.

    Parámetros:
        exploits (list): Lista de exploits con campos 'start_timestamp' y 'end_timestamp'.

    Devuelve:
        list: Lista de tuplas (start_timestamp, end_timestamp) presentes en los exploits.
    """
    timestamps = [
        (e["start_timestamp"], e["end_timestamp"])
        for e in exploits
        if "start_timestamp" in e and "end_timestamp" in e
    ]
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

def packets_extraction(pcap_path, time_windows=None):
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

def group_packets_by_window(packets):
    """
    Agrupa los paquetes por ventana temporal (start, end).

    Parámetros:
        packets (list): Lista de paquetes JSON.

    Devuelve:
        dict: Diccionario con clave (start, end) → lista de paquetes.
    """
    grouped = defaultdict(list)

    for pkt in packets:
        window = pkt.get("window")
        if window:
            start = window["start"]
            end = window["end"]
            grouped[(start, end)].append(pkt)

    return grouped

def extract_ip_frequencies(packets):
    """
    Extrae y cuenta las IPs src y dst de cada paquete.

    Parámetros:
        packets (list): Lista de paquetes en una ventana.

    Devuelve:
        Counter: Conteo total de IPs origen y destino.
    """
    ip_counter = Counter()

    for pkt in packets:
        layers = pkt.get("layers", {})
        ip_layer = layers.get("ip", {})
        src = ip_layer.get("src")
        dst = ip_layer.get("dst")

        if src:
            ip_counter[src] += 1
        if dst:
            ip_counter[dst] += 1

    return ip_counter

def select_main_ips(ip_counter, top_n=2):
    """
    Selecciona las IPs más frecuentes como candidatas principales del exploit.

    Parámetros:
        ip_counter (Counter): Conteo de IPs.
        top_n (int): Número de IPs a conservar.

    Devuelve:
        set: IPs más frecuentes (top N).
    """
    return set(ip for ip, _ in ip_counter.most_common(top_n))


def filter_packets_by_ip_and_protocol(packets, allowed_ips):
    """
    Elimina paquetes que no tengan IP o que no estén relacionados con las IPs relevantes.

    Parámetros:
        packets (list): Lista de paquetes.
        allowed_ips (set): IPs consideradas relacionadas con el exploit.

    Devuelve:
        list: Paquetes filtrados.
    """
    filtered = []

    for pkt in packets:
        layers = pkt.get("layers", {})

        if "ip" not in layers:
            continue  # sin IP, fuera

        ip_layer = layers["ip"]
        src = ip_layer.get("src")
        dst = ip_layer.get("dst")

        if src in allowed_ips or dst in allowed_ips:
            filtered.append(pkt)

    return filtered

def select_representative_packets(packets, max_packets):
    """
    Selecciona un subconjunto representativo de paquetes dentro de un grupo filtrado.
    
    Objetivo:
        Reducir el número total de paquetes a analizar sin perder diversidad informativa.
        Se priorizan paquetes que:
          - Usan protocolos distintos (ej. TCP, UDP, DNS, HTTP, SMB...)
          - Utilizan puertos no estándar (potencialmente sospechosos)
          - Son los primeros en aparecer (en caso de que falten paquetes para completar el máximo)

    Estrategia:
        1. Se seleccionan paquetes con combinaciones de protocolos únicas, para representar distintas capas vistas en la sesión.
        2. Se priorizan paquetes con destino a puertos no comunes (fuera de los típicos de servicios legítimos como HTTP, DNS, FTP...).
        3. Si aún no se alcanza el número deseado de paquetes, se completan con los primeros paquetes no seleccionados del grupo.

    Parámetros:
        packets (list): Lista de paquetes ya filtrados por ventana e IPs dominantes.
        max_packets (int): Número máximo de paquetes a conservar.

    Devuelve:
        list: Lista de paquetes seleccionados para análisis semántico.
    """
    COMMON_PORTS = {
        "20",  # FTP data
        "21",  # FTP control
        "22",  # SSH
        "23",  # Telnet
        "25",  # SMTP
        "53",  # DNS
        "80",  # HTTP
        "110", # POP3
        "143", # IMAP
        "443", # HTTPS
    }

    selected = []
    seen_combinations = set()

    # 1. Selección por combinación única de protocolos
    for pkt in packets:
        layers = tuple(pkt.get("layers", {}).keys())
        if layers not in seen_combinations:
            seen_combinations.add(layers)
            selected.append(pkt)
            if len(selected) >= max_packets:
                return selected

    # 2. Selección por puerto destino no común
    for pkt in packets:
        layers = pkt.get("layers", {})
        dst_port = layers.get("tcp", {}).get("dstport") or layers.get("udp", {}).get("dstport")

        if dst_port and dst_port not in COMMON_PORTS and pkt not in selected:
            selected.append(pkt)
            if len(selected) >= max_packets:
                return selected

    # 3. Completar con los primeros paquetes restantes
    for pkt in packets:
        if pkt not in selected:
            selected.append(pkt)
            if len(selected) >= max_packets:
                break

    return selected

def refine_packets(packets, top_n_ips=2,max_packets_per_window=5):
    """
    Refina la lista de paquetes para eliminar ruido no relacionado con los exploits.

    - Agrupa por ventana temporal
    - Detecta IPs dominantes por ventana
    - Filtra paquetes que no involucren esas IPs

    Parámetros:
        packets (list): Lista de paquetes enriquecidos con 'window'.
        top_n_ips (int): Número de IPs dominantes a conservar por ventana.

    Devuelve:
        list: Lista de paquetes refinados.
    """
    refined = []
    grouped = group_packets_by_window(packets)

    for (start, end), pkts in grouped.items():
        ip_counts = extract_ip_frequencies(pkts)
        dominant_ips = select_main_ips(ip_counts, top_n=top_n_ips)
        filtered = filter_packets_by_ip_and_protocol(pkts, dominant_ips)
        representative = select_representative_packets(filtered, max_packets=max_packets_per_window)
        refined.extend(representative)

    with open(FILTERED_PACKETS2_OUTPUT_PATH, "w") as f:
        json.dump(refined, f, indent=2, default=str)

    return refined

#---------------------------------------------------------------------------------------------------------------
#--Verification functions
 
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

#--------------------------------------------------------------------------------------------------------------
#--Main

def process_data():
    exploits = parse_report(REPORT_PATH)
    time_windows = report_timestamps(exploits)
    packets = packets_extraction(PCAP_PATH, time_windows)
    refined_packets = refine_packets(packets)


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