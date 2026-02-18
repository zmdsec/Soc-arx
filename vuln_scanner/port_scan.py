import socket
from core.logger import log_event
from core.risk_engine import calculate_risk

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

SENSITIVE_PORTS = [21, 23, 445, 3389]

def scan(target, ports):
    open_ports = []

    for port in ports:
        s = socket.socket()
        s.settimeout(1)
        if s.connect_ex((target, port)) == 0:
            service = COMMON_SERVICES.get(port, "Unknown")
            open_ports.append((port, service))

            print(f"[ABERTA] Porta {port} ({service})")

            if port in SENSITIVE_PORTS:
                risk = calculate_risk("port_scan")
                log_event("port_scan", f"{target}:{port} | Risco {risk}")

        s.close()

    return open_ports


if __name__ == "__main__":
    target = input("IP alvo: ")
    ports = [21,22,23,80,443,445,3389]
    result = scan(target, ports)

    if not result:
        print("Nenhuma porta aberta.")
