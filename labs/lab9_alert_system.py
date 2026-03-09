from scapy.all import sniff, IP
from datetime import datetime

print("Starting Security Alert System...")

packet_count = {}
THRESHOLD = 15

def process_packet(packet):

    if packet.haslayer(IP):

        src_ip = packet[IP].src

        if src_ip not in packet_count:
            packet_count[src_ip] = 0

        packet_count[src_ip] += 1

        print(f"Packet from: {src_ip} | Count: {packet_count[src_ip]}")

        if packet_count[src_ip] > THRESHOLD:

            alert_message = f"ALERT: Suspicious traffic from {src_ip}"

            print(f"⚠️ {alert_message}")

            with open("security_alerts.txt", "a") as log_file:

                log_file.write(
                    f"{datetime.now()} - {alert_message}\n"
                )

sniff(prn=process_packet, store=False)
