import socket
import json
from datetime import datetime

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]

PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-ALT"
}


def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))

        if port in [80, 8080, 443]:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")

        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()

        return banner if banner else "Banner não identificado"
    except:
        return "Banner não identificado"


def scan(ip):
    results = []
    print(f"\nEscaneando {ip}...\n")

    for port in COMMON_PORTS:
        s = socket.socket()
        s.settimeout(1)

        if s.connect_ex((ip, port)) == 0:
            service = PORT_SERVICES.get(port, "Desconhecido")
            banner = grab_banner(ip, port)

            print(f"[ABERTA] Porta {port} ({service})")

            results.append({
                "porta": port,
                "servico": service,
                "banner": banner
            })

        s.close()

    return results


def resumo_executivo(alvo, resultados):
    risco = "BAIXO"

    for r in resultados:
        if r["porta"] == 23:
            risco = "ALTO"
            break
        elif r["porta"] == 80:
            risco = "MÉDIO"

    print("\n====== RESUMO EXECUTIVO ======")
    print(f"IP analisado: {alvo}")
    print(f"Portas abertas: {len(resultados)}")
    print(f"Nível de risco: {risco}")

    if risco == "ALTO":
        print("Recomendação: Desativar Telnet imediatamente.")
    elif risco == "MÉDIO":
        print("Recomendação: Usar HTTPS e senha forte.")
    else:
        print("Recomendação: Nenhuma ação crítica necessária.")


if __name__ == "__main__":
    alvo = input("IP alvo: ")
    resultados = scan(alvo)

    if not resultados:
        print("\nNenhuma porta aberta encontrada.")
        exit()

    resumo_executivo(alvo, resultados)

    arquivo = f"relatorio_{alvo}.json"

    with open(arquivo, "w") as f:
        json.dump({
            "ip": alvo,
            "data": str(datetime.now()),
            "resultados": resultados
        }, f, indent=4)

    print(f"\nRelatório salvo em {arquivo}")
