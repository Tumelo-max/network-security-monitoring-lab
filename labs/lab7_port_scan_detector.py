from scapy.all import sniff, TCP, IP

print("Starting Port Scan Detector...")

# Dictionary to track ports accessed by each IP
scan_tracker = {}

# Alert threshold
PORT_THRESHOLD = 10

def process_packet(packet):

    if packet.haslayer(TCP) and packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        print(f"Connection attempt from {src_ip} to port {dst_port}")

        if src_ip not in scan_tracker:
            scan_tracker[src_ip] = set()

        scan_tracker[src_ip].add(dst_port)

        if len(scan_tracker[src_ip]) > PORT_THRESHOLD:
            print(f"⚠️ ALERT: Possible port scan detected from {src_ip}")

sniff(filter="tcp", prn=process_packet, store=False)

