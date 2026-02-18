from scapy.all import sniff, IP, TCP
from datetime import datetime
from core.logger import log_event

SUSPICIOUS_PORTS = [23, 2323, 445, 3389]

def analyze(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip = packet[IP]
        tcp = packet[TCP]

        if tcp.dport in SUSPICIOUS_PORTS:
            event = f"IDS ALERT | {ip.src} -> {ip.dst}:{tcp.dport}"
            print(event)
            log_event("port_scan", event)

def start_ids():
    print("[*] IDS iniciado...")
    sniff(prn=analyze, store=0)
