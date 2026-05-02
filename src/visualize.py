import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import re
import os

def visualize(df):
    print("\n--- Generating Visualizations ---")
    
    # Make sure outputs folder exists
    # os.makedirs is Regular Python
    os.makedirs("outputs", exist_ok=True)

    # ---- Chart 1 - Alert Severity Distribution ----
    # Read alerts.txt and count severities
    # Regular Python - reading a text file
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    if os.path.exists("outputs/alerts.txt"):
        with open("outputs/alerts.txt", "r") as f:
            content = f.read()
            # re is Regular Python - searches text for patterns
            severity_counts["HIGH"] = content.count("Severity: HIGH")
            severity_counts["MEDIUM"] = content.count("Severity: MEDIUM")
            severity_counts["LOW"] = content.count("Severity: LOW")

    # Create the chart
    plt.figure(figsize=(6, 4))
    # sns.barplot is Seaborn
    sns.barplot(
        x=list(severity_counts.keys()),
        y=list(severity_counts.values()),
        palette=["red", "orange", "green"]
    )
    plt.title("Alert Severity Distribution")
    plt.xlabel("Severity Level")
    plt.ylabel("Number of Alerts")
    plt.tight_layout()
    # plt.savefig is Matplotlib
    plt.savefig("outputs/chart_severity.png")
    plt.close()
    print("Saved: chart_severity.png")

    # ---- Chart 2 - Top 10 Attacking IPs ----
    # Pandas - count packets per source IP
    top_ips = df['src_ip'].value_counts().head(10)

    plt.figure(figsize=(8, 5))
    sns.barplot(
        x=top_ips.values,
        y=top_ips.index,
        palette="Reds_r"
    )
    plt.title("Top 10 Source IPs by Packet Count")
    plt.xlabel("Total Packets")
    plt.ylabel("Source IP")
    plt.tight_layout()
    plt.savefig("outputs/chart_top_ips.png")
    plt.close()
    print("Saved: chart_top_ips.png")

    # ---- Chart 3 - Protocol Distribution ----
    # Pandas - count packets per protocol
    protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    df['protocol_name'] = df['protocol'].map(protocol_map).fillna("Other")
    protocol_counts = df['protocol_name'].value_counts()

    plt.figure(figsize=(6, 6))
    plt.pie(
        protocol_counts.values,
        labels=protocol_counts.index,
        autopct='%1.1f%%',
        colors=["#4C72B0", "#DD8452", "#55A868"]
    )
    plt.title("Protocol Distribution")
    plt.tight_layout()
    plt.savefig("outputs/chart_protocols.png")
    plt.close()
    print("Saved: chart_protocols.png")

    print("\nAll charts saved to outputs/ folder!")