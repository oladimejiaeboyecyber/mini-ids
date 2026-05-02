import os
from datetime import datetime

def get_severity_scan(port_count):
    if port_count > 50:
        return "HIGH"
    elif port_count > 10:
        return "MEDIUM"
    else:
        return "LOW"




def get_severity_flood(packet_count):
    if packet_count > 1000:
        return "HIGH"
    elif packet_count > 500:
        return "MEDIUM"
    else:
        return "LOW"




def save_alert(alert_type, details):
    # Make sure outputs folder exists
    os.makedirs("outputs", exist_ok=True)
    
    # Open alerts file and append new alert
    with open("outputs/alerts.txt", "a") as f:
        f.write("=" * 40 + "\n")
        f.write(f"[ALERT] {alert_type}\n")
        f.write(f"Logged at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        for key, value in details.items():
            f.write(f"{key}: {value}\n")
        f.write("=" * 40 + "\n\n")