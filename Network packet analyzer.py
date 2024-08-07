from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:  # TCP
            proto_name = "TCP"
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            else:
                src_port = dst_port = None
        elif protocol == 17:  # UDP
            proto_name = "UDP"
            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                src_port = dst_port = None
        else:
            proto_name = "Other"
            src_port = dst_port = None

        print(f"IP Source: {ip_src}")
        print(f"IP Destination: {ip_dst}")
        print(f"Protocol: {proto_name}")
        if src_port and dst_port:
            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")
        print(f"Payload: {bytes(packet[IP].payload)}")
        print("="*50)

# Sniffing packets
print("Starting packet sniffer...")
sniff(prn=packet_callback, store=0)
