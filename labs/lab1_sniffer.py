# Lab 1 - Basic ICMP Sniffer
# Observations: ____________________________

from scapy.all import sniff, ICMP

def process_packet(packet):
    if ICMP in packet:
        print(f"ICMP Packet: {packet.summary()}")

print("Starting Lab 1 ICMP packet capture...")
sniff(filter="icmp", prn=process_packet, count=5)
print("Lab 1 capture finished.")
