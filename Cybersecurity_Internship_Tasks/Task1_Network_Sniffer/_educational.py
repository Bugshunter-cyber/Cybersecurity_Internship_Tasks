from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

packet_count = 0

def process_packet(packet):
    global packet_count

    if packet.haslayer(IP):
        packet_count += 1
        ip_layer = packet[IP]

        print(f"\n===== Packet #{packet_count} =====")
        print(f"Source: {ip_layer.src}")
        print(f"Destination: {ip_layer.dst}")

        if packet.haslayer(TCP):
            print("Protocol: TCP")
            print(f"Ports: {packet[TCP].sport} → {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print("Protocol: UDP")

        else:
            print("Protocol: Other")

        with open("logs.txt", "a") as f:
            f.write(f"{ip_layer.src} -> {ip_layer.dst}\n")

sniff(prn=process_packet, store=False)