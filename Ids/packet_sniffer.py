from scapy.all import sniff, IP, TCP
from datetime import datetime

SUSPICIOUS_PORTS = [23, 2323, 445, 3389]

def analyze(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip = packet[IP]
        tcp = packet[TCP]

        if tcp.dport in SUSPICIOUS_PORTS:
            log = f"[IDS] {datetime.now()} | {ip.src} -> {ip.dst}:{tcp.dport}"
            print(log)
            with open("logs/events.log", "a") as f:
                f.write(log + "\n")

sniff(prn=analyze, store=0)
