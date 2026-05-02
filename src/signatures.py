from itertools import count

from alerts import save_alert, get_severity_scan, get_severity_flood
def detect_portscan(df, threshold = 5):
    print("\n----Checking for port scans ---")
    # Group packets by source IP
    # For each source IP, count the number of unique destination ports
    scan_summary = df.groupby('src_ip')['dst_port'].nunique()


    # Find Ips that contacted more ports than our threshold
    scanners = scan_summary[scan_summary > threshold]

    if len(scanners) == 0:
        print("No port scans detected.")
    else:
        for ip, port_count in scanners.items():
            severity = get_severity_scan(port_count)
            print(f"[ALERT] Port scan detected!")
            print(f"Source IP: {ip}")
            print(f"Unique ports contacted: {port_count}")
            print(f"Severity: {severity}")
            print("---")
            save_alert("Port Scan Detected", {
                "Source IP": ip,
                "Unique Ports": port_count,
                "Severity": severity
            })


def detect_suspicious_ports(df):
    print("\n---- Checking for suspicious ports ---")


    #list of known dangerous ports
    suspicious_ports = [23, 21, 3389, 445, 8080, 1433, 3306, 4444, 6667,]

    #Find packets going into any of these ports
    hits = df[df['dst_port'].isin(suspicious_ports)]

    if len(hits) == 0:
        print("No suspicious ports detected.")

    else:
        for _, row in hits.iterrows():
            print(f"[ALERT] Traffic to suspicious port!")
            print(f"Source IP: {row['src_ip']}")
            print(f"Destination IP: {row['dst_ip']}")
            print(f"Suspicious port: {row['dst_port']}")
            print("---")
def detect_packet_flood(df, threshold=100):
    print("\n--- Checking for packet floods ---")
    
    # Count total packets per source IP
    packet_counts = df.groupby('src_ip')['dst_port'].count()
    
    # Find IPs sending more packets than threshold
    floaters = packet_counts[packet_counts > threshold]
    
    if len(floaters) == 0:
        print("No packet floods detected")
    else:        
        for ip, count in floaters.items():
            severity = get_severity_flood(count)
            print(f"[ALERT] Packet flood detected!")
            print(f"Source IP: {ip}")
            print(f"Total packets sent: {count}")
            print(f"Severity: {severity}")
            print("---")
            save_alert("Packet Flood Detected", {
                "Source IP": ip,
                "Total Packets": count,
                "Severity": severity
    })