from scapy.all import sniff, DNSQR

print("Starting DNS sniffer...")

def process_packet(packet):

    if packet.haslayer(DNSQR):

        query = packet[DNSQR].qname.decode()

        print(f"[DNS] Query: {query}")

sniff(filter="udp port 53", prn=process_packet, store=False)
