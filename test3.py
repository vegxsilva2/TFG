import pyshark
import IoC_extractor_LLM.preprocessing as p
print(p)
import json
from datetime import datetime, timezone

REPORT_PATH = "../input/report.txt"
PCAP_PATH = "../input/capture@eth1.pcap"
OUTPUT_PATH = "../output/filtered_packets.json"

def filter_packets_full_json(pcap_path, time_windows=None):
    cap = pyshark.FileCapture(pcap_path, keep_packets=False)
    packets = []

    # Normalizamos las ventanas si se usan
    if time_windows:
        time_windows = [
            (start.replace(tzinfo=timezone.utc), end.replace(tzinfo=timezone.utc))
            for start, end in time_windows
        ]

    for pkt in cap:
        try:
            pkt_time = datetime.fromtimestamp(float(pkt.sniff_timestamp), tz=timezone.utc)

            if time_windows:
                if not any(start <= pkt_time <= end for start, end in time_windows):
                    continue

            pkt_dict = {
                "timestamp": pkt.sniff_time.isoformat(),
                "layers": {}
            }

            for layer in pkt.layers:
                layer_name = layer.layer_name
                pkt_dict["layers"][layer_name] = {}

                for field in layer._all_fields:
                    key = field.showname_key or field.name
                    value = field.show or field.raw_value or field.value
                    pkt_dict["layers"][layer_name][key] = value

            packets.append(pkt_dict)

        except Exception as e:
            continue

    cap.close()

    with open(OUTPUT_PATH, "w") as f:
        json.dump(packets, f, indent=2, default=str)
    return packets



exploits = p.parse_report(REPORT_PATH)
timestamps = p.pentesting_timestamps(exploits)
packets = filter_packets_full_json(PCAP_PATH, timestamps)
