import socket
import json
from datetime import datetime

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore")
        s.close()
        return banner.strip()
    except:
        return "Banner não identificado"

def scan(ip):
    results = []
    print(f"\nEscaneando {ip}...\n")

    for port in COMMON_PORTS:
        s = socket.socket()
        s.settimeout(1)
        result = s.connect_ex((ip, port))

        if result == 0:
            print(f"[ABERTA] Porta {port}")
            banner = grab_banner(ip, port)
            results.append({
                "porta": port,
                "banner": banner
            })

        s.close()

    return results


if __name__ == "__main__":
    alvo = input("IP alvo: ")
    dados = scan(alvo)

    arquivo = f"relatorio_{alvo}.json"

    with open(arquivo, "w") as f:
        json.dump({
            "ip": alvo,
            "data": str(datetime.now()),
            "resultados": dados
        }, f, indent=4)

    print(f"\nRelatório salvo em {arquivo}")
