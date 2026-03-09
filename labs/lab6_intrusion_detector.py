from scapy.all import sniff, IP

print("Starting Mini Intrusion Detection System...")

# Dictionary to track IP packet counts
ip_count = {}

# Alert threshold
THRESHOLD = 10

def process_packet(packet):

    if packet.haslayer(IP):

        src_ip = packet[IP].src

        # Count packets from this IP
        if src_ip in ip_count:
            ip_count[src_ip] += 1
        else:
            ip_count[src_ip] = 1

        print(f"Packet from: {src_ip} | Count: {ip_count[src_ip]}")

        # Alert if threshold exceeded
        if ip_count[src_ip] > THRESHOLD:
            print(f"⚠️ ALERT: Possible suspicious activity from {src_ip}")

sniff(prn=process_packet, store=False)
