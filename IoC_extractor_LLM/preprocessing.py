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


def parse_report(report_path, output_path, allowed_sources=None):
    """
    Parsea el archivo de reporte y extrae información de exploits.

    Procesa únicamente las secciones incluidas en allowed_sources,
    que deben coincidir con las claves reales del JSON
    (por ejemplo: ["vulnerabilities"] o ["vulnerabilities", "warnings"]).
    """
    if allowed_sources is None:
        allowed_sources = ["vulnerabilities"]

    with open(report_path, "r", encoding="utf-8") as f:
        raw_report = f.read()

    try:
        report = json.loads(raw_report)
    except json.JSONDecodeError:
        match = re.search(r"{.*}", raw_report, re.DOTALL)
        report = json.loads(match.group(0)) if match else {}

    exploits, seen_keys = [], set()
    reports_list = report.get("reports", [])
    section_to_source = {
        "vulnerabilities": "vulnerability",
        "warnings": "warning"
    }

    for report_entry in reports_list:
        report_content = report_entry.get("report", {})

        for section_key in allowed_sources:
            section_entries = report_content.get(section_key, {})
            if not isinstance(section_entries, dict):
                continue

            source = section_to_source.get(section_key, section_key)

            for entry_id, entries in section_entries.items():
                for entry in entries:
                    exploit_info = {
                        "id": entry_id,
                        "exploit": entry.get("exploit"),
                        "payload": entry.get("payload"),
                        "references": entry.get("references"),
                        "shell_type": entry.get("shell_type"),
                        "source": source
                    }

                    # Procesar timestamps si existen
                    timestamps = entry.get("timestamp", [])
                    if len(timestamps) == 2:
                        exploit_info["start_timestamp"] = datetime.fromisoformat(timestamps[0]).replace(tzinfo=timezone.utc)
                        exploit_info["end_timestamp"] = datetime.fromisoformat(timestamps[1]).replace(tzinfo=timezone.utc)

                    key = (
                        str(exploit_info.get("id")),
                        str(exploit_info.get("exploit")),
                        str(exploit_info.get("payload")),
                        str(exploit_info.get("start_timestamp", "")),
                        str(exploit_info.get("end_timestamp", "")),
                        str(exploit_info.get("source"))
                    )

                    if key not in seen_keys:
                        seen_keys.add(key)
                        exploits.append(exploit_info)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(exploits, f, indent=2, default=str)

    return exploits



def extract_time_windows(exploits):
    """
    Extrae las ventanas temporales (start, end) de los exploits procesados.

    :param exploits: Lista de exploits con campos 'start_timestamp' y 'end_timestamp'.
    :return: Lista de tuplas (start_timestamp, end_timestamp) presentes en los exploits.
    """
    timestamps = [
        (e["start_timestamp"], e["end_timestamp"])
        for e in exploits
        if "start_timestamp" in e and "end_timestamp" in e
    ]
    return timestamps

def normalize_time_windows(time_windows):
    """
    Normaliza todas las tuplas de tiempo (start, end) en objetos datetime con zona horaria UTC.

    :param time_windows: Lista de tuplas (start, end), donde cada elemento puede ser 
                         un string en formato ISO o un objeto datetime.
    :return: Lista de tuplas normalizadas (datetime UTC, datetime UTC).
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

    :param pkt_time: Timestamp del paquete (datetime, UTC).
    :param time_windows: Lista de tuplas (start, end) con timestamps UTC.
    :return: Diccionario con los timestamps 'start' y 'end' en formato ISO si el paquete 
             cae dentro de alguna ventana; de lo contrario, None.
    """
    for start, end in time_windows:
        if start <= pkt_time <= end:
            return {"start": start.isoformat(), "end": end.isoformat()}
    return None

def detect_protocol(packet):
    """
    Detecta el protocolo más relevante presente en un paquete.

    La función prioriza los protocolos según una lista predefinida, 
    buscando primero las capas superiores (aplicación). 
    Si se encuentra un protocolo en el paquete, se devuelve en mayúsculas. 
    Si no se detecta ninguno relevante, devuelve "UNKNOWN".

    :param paquete: Diccionario que representa un paquete, con clave 'layers' conteniendo una lista de capas.
    :return: Nombre del protocolo detectado en mayúsculas, o "UNKNOWN" si no se encuentra ninguno relevante.
    """
    # Normaliza las capas a minúsculas
    layers = [layer.lower() for layer in packet.get("layers", [])]

    # Lista priorizada de protocolos relevantes (capas superiores primero)
    protocol_priority = [
        "smb", "smb2", "http", "https", "ftp", "ssh", "telnet", "smtp", "imap", "pop",
        "dns", "ntp", "snmp", "ldap", "dhcp", "rdp", "quic", "tls", "ssl",
        "mqtt", "coap", "rtsp", "sip", "tftp", "netbios", "mdns", "radius",
    ]

    for proto in protocol_priority:
        if proto in layers:
            return proto.upper()  # Uniformizamos a mayúsculas en el output

    return "UNKNOWN"  # Si no hay protocolo relevante

def hex_payload_to_text(hex_payload):
    """
    Convierte un payload en formato hexadecimal a texto legible.

    La función elimina separadores (":" y espacios), decodifica los bytes 
    a UTF-8 ignorando errores y filtra caracteres no imprimibles, reemplazándolos 
    por puntos.

    :param hex_payload: Cadena de texto que representa el payload en hexadecimal.
    :return: Cadena de texto legible, con caracteres no imprimibles reemplazados por '.'.
             Devuelve cadena vacía si ocurre algún error en la conversión.
    """
    # Quitar ':' y espacios
    clean_hex = hex_payload.replace(":", "").replace(" ", "").strip()
    try:
        # Convertir hex a bytes
        byte_data = bytes.fromhex(clean_hex)
        # Intentar decodificar a utf-8 ignorando errores
        text = byte_data.decode("utf-8", errors="ignore")
        # Filtrar caracteres no imprimibles
        printable_text = "".join(c if 32 <= ord(c) <= 126 else "." for c in text)
        return printable_text
    except Exception as e:
        return ""

def serialize_packet(pkt, pkt_time, matched_window):
    """
    Extrae toda la información relevante de un paquete capturado por PyShark.

    La función serializa el paquete en un diccionario, incluyendo timestamp,
    ventana temporal, capas y sus campos. Detecta el protocolo principal y
    decodifica el payload de la capa de aplicación o transporte si está disponible.

    :param pkt: Paquete capturado por PyShark (pyshark.packet.packet.Packet).
    :param pkt_time: Timestamp UTC del paquete (datetime).
    :param matched_window: Diccionario con la ventana temporal a la que pertenece el paquete.
    :return: Diccionario serializable con 'timestamp', 'window', 'layers', 'protocol' y
             opcionalmente 'payload_text' si se detecta información útil.
    """
    pkt_dict = {
        "timestamp": pkt_time.isoformat(),
        "window": matched_window,
        "layers": {},
        "src_port": None,   
        "dst_port": None
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

    # Extraer puertos TCP/UDP solo si existe capa de transporte
    if hasattr(pkt, "transport_layer") and pkt.transport_layer:
        transport_layer = pkt.transport_layer.lower()
        if transport_layer in ("tcp", "udp"):
            try:
                src = getattr(pkt[transport_layer], "srcport", None)
                dst = getattr(pkt[transport_layer], "dstport", None)
                pkt_dict["src_port"] = int(src) if src is not None else None
                pkt_dict["dst_port"] = int(dst) if dst is not None else None
            except Exception as e:
                print(f"No se ha podido extraer puertos: {e}")

        pkt_dict["protocol"] = detect_protocol(pkt_dict)

    # Extraer y decodificar el payload desde capa de aplicación o transporte
    payload_hex = None

    for candidate_layer in ["tcp", "udp", "data", "http", "smb", "ftp", "dns", "smtp"]:
        layer_data = pkt_dict["layers"].get(candidate_layer, {})
        payload_hex = layer_data.get("payload") or layer_data.get("data") or layer_data.get("data_data")
        if payload_hex:
            break  # usar el primer payload que encontremos

    if payload_hex:
        decoded = hex_payload_to_text(payload_hex)
        if decoded.strip():  # solo si contiene algo útil
            pkt_dict["payload_text"] = decoded

    return pkt_dict

def extract_packets(pcap_path, output_path, time_windows=None):
    """
    Filtra un archivo .pcap por ventanas temporales y extrae paquetes enriquecidos con metadatos.

    :param pcap_path: Ruta al archivo .pcap (str o Path).
    :param time_windows: Lista opcional de tuplas (start, end) con timestamps UTC o str. 
                         Si se proporciona, solo se extraen paquetes dentro de estas ventanas.
    :param output_path: Ruta del archivo JSON donde se guardarán los paquetes extraídos.
    :return: Lista de diccionarios, cada uno representando un paquete con capas y metadatos.
    """
    capture = pyshark.FileCapture(pcap_path, keep_packets=False)
    packets = []

    if time_windows:
        time_windows = normalize_time_windows(time_windows)

    for pkt in capture:
        try:
            pkt_time = datetime.fromtimestamp(float(pkt.sniff_timestamp), tz=timezone.utc)
            matched_window = find_matching_window(pkt_time, time_windows)

            if not matched_window:
                continue
            
            pkt_dict = serialize_packet(pkt, pkt_time, matched_window)
            packets.append(pkt_dict)

        except Exception as e:
            print(f"Error processing packet: {e}")
            continue

    capture.close()

    with open(output_path, "w") as f:
        json.dump(packets, f, indent=2, default=str)

    return packets

def group_packets_by_window(packets):
    """
    Agrupa los paquetes de red según la ventana temporal a la que pertenecen.

    Cada paquete incluye un campo 'window' con los límites de inicio y fin
    de la ventana en la que fue capturado. Esta función organiza dichos
    paquetes en un diccionario, donde cada clave es una tupla
    (start_timestamp, end_timestamp) y el valor asociado es la lista de
    paquetes que caen dentro de esa ventana.

    :param packets: Lista de paquetes representados como diccionarios,
                    cada uno con un campo 'window' que contiene los límites
                    de inicio y fin de la ventana.
    :return: Diccionario donde cada clave es una tupla (start, end) de
             timestamps ISO, y cada valor es la lista de paquetes que
             pertenecen a esa ventana.
    """
    grouped_packets = defaultdict(list)

    for pkt in packets:
        window = pkt.get("window")
        if window:
            start = window["start"]
            end = window["end"]
            grouped_packets[(start, end)].append(pkt)

    return grouped_packets

def extract_ip_frequencies(packets):
    """
    Calcula la frecuencia de direcciones IP origen y destino presentes en una lista de paquetes.

    :param packets: Lista de paquetes representados como diccionarios,
                    cada uno con una capa 'ip' que puede incluir los
                    campos 'src' y 'dst'.
    :return: Objeto Counter con las direcciones IP como claves y el número
             de apariciones totales (src + dst) como valor.
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

def select_top_ips(ip_counter, top_n=2):
    """
    Selecciona las direcciones IP más frecuentes a partir del conteo de paquetes.

    Esta función toma un contador de IPs y devuelve las N direcciones con mayor
    número de apariciones, considerando tanto origen como destino.

    :param ip_counter: Objeto Counter con las direcciones IP como claves y su
                       frecuencia de aparición como valores.
    :param top_n: Número de direcciones IP a conservar (por defecto 2).
    :return: Conjunto (set) con las IPs más frecuentes.
    """
    return set(ip for ip, _ in ip_counter.most_common(top_n))


def filter_packets_by_ip(packets, allowed_ips):
    """
    Filtra los paquetes de red en función de las direcciones IP relevantes.

    Esta función recorre todos los paquetes y elimina aquellos que no contienen
    capa IP o que no están asociados a ninguna de las direcciones IP consideradas
    relevantes para el análisis.

    :param packets: Lista de paquetes representados como diccionarios, cada uno
                    con sus capas y metadatos.
    :param allowed_ips: Conjunto de direcciones IP relevantes (set) que se
                        consideran parte del exploit.
    :return: Lista de paquetes que contienen capa IP y cuya dirección de origen
             o destino coincide con alguna de las direcciones relevantes.
    """
    filtered_packets = []

    for pkt in packets:
        layers = pkt.get("layers", {})

        if "ip" not in layers:
            continue  # sin IP, fuera

        ip_layer = layers["ip"]
        src = ip_layer.get("src")
        dst = ip_layer.get("dst")

        if src in allowed_ips or dst in allowed_ips:
            filtered_packets.append(pkt)

    return filtered_packets

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

    :param packets: Lista de paquetes representados como diccionarios,
                    ya filtrados por ventana temporal e IPs relevantes.
    :param max_packets: Número máximo de paquetes a conservar.
    :return: Lista de paquetes seleccionados como representativos para
             análisis posterior.
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

    selected_packets = []
    seen_combinations = set()

    # 1. Selección por combinación única de protocolos
    for pkt in packets:
        layers = tuple(pkt.get("layers", {}).keys())
        if layers not in seen_combinations:
            seen_combinations.add(layers)
            selected_packets.append(pkt)
            if len(selected_packets) >= max_packets:
                return selected_packets

    # 2. Selección por puerto destino no común
    for pkt in packets:
        layers = pkt.get("layers", {})
        dst_port = layers.get("tcp", {}).get("dstport") or layers.get("udp", {}).get("dstport")

        if dst_port and dst_port not in COMMON_PORTS and pkt not in selected_packets:
            selected_packets.append(pkt)
            if len(selected_packets) >= max_packets:
                return selected_packets

    # 3. Completar con los primeros paquetes restantes
    for pkt in packets:
        if pkt not in selected_packets:
            selected_packets.append(pkt)
            if len(selected_packets) >= max_packets:
                break

    return selected_packets

def refine_packets(packets, output_path, top_n_ips=2,max_packets_per_window=5):
    """
    Refina la lista de paquetes capturados eliminando tráfico irrelevante y seleccionando un subconjunto representativo por ventana temporal.

    El proceso incluye los siguientes pasos:
      1. Agrupar los paquetes por ventana temporal.
      2. Identificar las IPs dominantes en cada ventana.
      3. Filtrar los paquetes que no involucren dichas IPs.
      4. Seleccionar un subconjunto representativo de paquetes, limitado por un máximo por ventana.

    :param packets: Lista de paquetes enriquecidos con metadatos, cada uno con un
                    campo 'window' que indica la ventana temporal a la que pertenece.
    :param top_n_ips: Número de IPs dominantes a conservar por ventana (por defecto: 2).
    :param max_packets_per_window: Número máximo de paquetes representativos a
                                   seleccionar dentro de cada ventana (por defecto: 5).
    :return: Lista refinada de paquetes, representativos y relevantes para
             el análisis de posibles exploits.
    """
    refined_packets = []
    grouped_packets = group_packets_by_window(packets)

    for (start, end), pkts in grouped_packets.items():
        ip_counts = extract_ip_frequencies(pkts)
        dominant_ips = select_top_ips(ip_counts, top_n=top_n_ips)
        filtered = filter_packets_by_ip(pkts, dominant_ips)
        representative_packets = select_representative_packets(filtered, max_packets=max_packets_per_window)
        refined_packets.extend(representative_packets)

    with open(output_path, "w") as f:
        json.dump(refined_packets, f, indent=2, default=str)

    return refined_packets

#---------------------------------------------------------------------------------------------------------------
#--Verification functions
 
def validate_filtered_packets(packet_json_path, time_windows):
    """
    Valida que los paquetes previamente filtrados y guardados en un archivo JSON
    pertenezcan a las ventanas temporales especificadas.

    Se cuentan los paquetes dentro y fuera de rango, se muestran estadísticas en
    consola y se lanza una excepción si algún paquete está fuera de su ventana.

    :param packet_json_path: Ruta al archivo JSON con los paquetes filtrados.
    :param time_windows: Lista de tuplas (start, end) con límites de ventanas de
                         tiempo en formato datetime con tzinfo.
    :return: Tupla (passed, failed) con el número de paquetes que cumplen y no
             cumplen las ventanas de tiempo.
    """
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
            print(f"Paquete fuera de rango: {pkt_time.isoformat()}")

    print(f"\nPaquetes en rango: {passed}")
    print(f"Paquetes fuera de rango: {failed}")
    print(f"Total en archivo: {total}")

    assert failed == 0, "Hay paquetes que no cumplen las ventanas de tiempo."

    return passed, failed

def count_all_packets_in_windows(pcap_path, time_windows):
    """
    Cuenta los paquetes en un archivo .pcap que caen dentro de las ventanas
    temporales especificadas.

    Además de devolver el número total de coincidencias, imprime en consola
    el instante del primer y último paquete que cumplen el criterio.

    :param pcap_path: Ruta al archivo .pcap a analizar.
    :param time_windows: Lista de tuplas (start, end) con límites de ventanas de
                         tiempo en formato datetime con tzinfo.
    :return: Número total de paquetes dentro de las ventanas especificadas.
    """
    capture = pyshark.FileCapture(pcap_path, keep_packets=False)
    count = 0
    first_match_time = None
    last_match_time = None

    for pkt in capture:
        try:
            pkt_time = datetime.fromtimestamp(float(pkt.sniff_timestamp), tz=timezone.utc)

            if any(start <= pkt_time <= end for start, end in time_windows):
                count += 1
                if first_match_time is None:
                    first_match_time = pkt_time
                last_match_time = pkt_time

        except Exception:
            continue

    capture.close()

    print(f"\n🔍 Total paquetes en ventanas (raw .pcap): {count}")
    if first_match_time:
        print(f"Primer paquete en ventana: {first_match_time}")
        print(f"Último paquete en ventana: {last_match_time}")

    return count

#--------------------------------------------------------------------------------------------------------------
#--Main

def preprocess_data(report_path=REPORT_PATH,
                    pcap_path=PCAP_PATH,
                    exploits_output_path=EXPLOITS_OUTPUT_PATH,
                    packets_output_path=PACKETS_OUTPUT_PATH,
                    allowed_sources=None):
    """
    Punto de entrada principal para el procesamiento de datos de red.

    El flujo completo incluye:
      1. Parseo del informe de exploits para extraer las ventanas temporales.
      2. Extracción de paquetes del archivo .pcap que caen dentro de dichas ventanas.
      3. Refinamiento de los paquetes para eliminar ruido y seleccionar muestras representativas.
      4. Almacenamiento de los resultados intermedios en archivos JSON.

    :param report_path: Ruta al informe de exploits (JSON o similar).
    :param pcap_path: Ruta al archivo .pcap con la captura de tráfico.
    :param exploits_output_path: Ruta del archivo JSON donde se guardarán los exploits procesados.
    :param packets_output_path: Ruta del archivo JSON donde se guardarán los paquetes extraídos.
    :return: None. Los resultados se escriben en los archivos especificados.
    """
    exploits = parse_report(report_path,exploits_output_path, allowed_sources)
    time_windows = extract_time_windows(exploits)
    packets = extract_packets(pcap_path, packets_output_path, time_windows)
    refined_packets = refine_packets(packets,packets_output_path)

    print(f"\nPreprocesamiento completado.")
    print(f"Exploits guardados en: {exploits_output_path}")
    print(f"Paquetes filtrados guardados en: {packets_output_path}")
    

    """---Validación opcional---
    
    print("\nValidando paquetes filtrados...")
    validate_filtered_packets(packets_output_path, time_windows)
    
    print("\nComprobando si se han perdido paquetes en el filtrado...")
    total_in_pcap = count_all_packets_in_windows(pcap_path, time_windows)

    if total_in_pcap != len(refined_packets):
        print(f"Atención: se esperaban {total_in_pcap} paquetes pero solo se guardaron {len(filtered_packets)}.")
    else:
        print("Todos los paquetes de las ventanas han sido guardados.")
    """