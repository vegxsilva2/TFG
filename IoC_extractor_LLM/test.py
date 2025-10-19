import pyshark
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_PCAP_PATH = (BASE_DIR / "../input/capture@eth1.pcap").resolve()

capture = pyshark.FileCapture(DEFAULT_PCAP_PATH, keep_packets=False)

for packet in capture:
    protocol = packet.transport_layer
    packet_time = packet.sniff_time
    packet_timestamp = packet.sniff_timestamp

    if protocol is not None:
        source_port = packet[protocol].srcport
        destination_port = packet[protocol].dstport
        destination_address = packet.ip.dst
        print(f"Protocol: {protocol}, Src Port: {source_port}, Dst Port: {destination_port}")
    else:
        print(f"Paquete sin capa de transporte ({packet.highest_layer})")