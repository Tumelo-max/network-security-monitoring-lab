from scapy.all import *

def process_packet(packet):

    # Detect ICMP (ping)
    if packet.haslayer(ICMP):
        print("[ICMP] Packet:", packet.summary())

    # Detect DNS queries
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode()
        print("[DNS] Query for:", query)

    # Detect HTTP traffic
    if packet.haslayer(TCP):
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if b"HTTP" in payload or b"GET" in payload:
                print("[HTTP] Possible HTTP traffic detected")
                print(payload[:100])

print("Starting traffic sniffer...")

sniff(prn=process_packet, store=0)
