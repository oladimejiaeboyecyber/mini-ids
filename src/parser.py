from evaluate import evaluate
from visualize import visualize
from signatures import detect_portscan, detect_suspicious_ports, detect_packet_flood
from anomaly import detect_anomalies
from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd


def parse_pcap(file_path):
    print(f"Reading packets from: {file_path}")

    #Read the pcap file
    packets = rdpcap(file_path)

    # Store exatracted data
    packet_data = []

    for packet in packets:
        # Only process packets that have an IP layer 
        if IP in packet:
            data = {
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'size': len(packet),
                'timestamp': pd.to_datetime(float(packet.time), unit='s').strftime('%Y-%m-%d %H:%M:%S')
            }
            #IF it has a TCP layer , grap the ports
            if TCP in packet:
                data['src_port'] = packet[TCP].sport
                data['dst_port'] = packet[TCP].dport

            #IF it has a UDP layer , grap the ports
            elif UDP in packet:
                data['src_port'] = packet[UDP].sport
                data['dst_port'] = packet[UDP].dport

            packet_data.append(data)
    df = pd.DataFrame(packet_data)
    print(df)
    return df

df = parse_pcap('data/snort.log.1425572414')
open("outputs/alerts.txt", "w").close()
detect_portscan(df)
detect_suspicious_ports(df)
detect_packet_flood(df)
detect_anomalies(df)
evaluate(df)
visualize(df)
