from scapy.all import sniff, TCP, IP, Raw
from datetime import datetime
import csv

csv_file = "http_traffic_log.csv"

# Create CSV file with headers
with open(csv_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Timestamp", "Source IP", "Source Port", "Destination IP", "Destination Port", "HTTP Info"])

def process_packet(packet):

    if packet.haslayer(TCP) and packet.haslayer(Raw):

        tcp_layer = packet[TCP]
        ip_layer = packet[IP]

        payload = packet[Raw].load.decode(errors="ignore")

        http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]

        for method in http_methods:
            if payload.startswith(method):

                http_info = payload.split("\r\n")[0]

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                print(f"[{timestamp}] {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport} | {http_info}")

                with open(csv_file, "a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        timestamp,
                        ip_layer.src,
                        tcp_layer.sport,
                        ip_layer.dst,
                        tcp_layer.dport,
                        http_info
                    ])

print("Starting HTTP traffic sniffer...")

sniff(filter="tcp port 80", prn=process_packet, store=False)
