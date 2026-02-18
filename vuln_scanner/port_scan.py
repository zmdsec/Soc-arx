import socket
import json
from datetime import datetime

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet


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

    return risco


def gerar_pdf(alvo, resultados, risco):
    arquivo_pdf = f"relatorio_{alvo}.pdf"
    doc = SimpleDocTemplate(arquivo_pdf, pagesize=A4)

    estilos = getSampleStyleSheet()
    elementos = []

    elementos.append(Paragraph("<b>RELATÓRIO DE AUDITORIA DE REDE</b>", estilos["Title"]))
    elementos.append(Spacer(1, 12))

    elementos.append(Paragraph(f"<b>IP analisado:</b> {alvo}", estilos["Normal"]))
    elementos.append(Paragraph(f"<b>Data:</b> {datetime.now()}", estilos["Normal"]))
    elementos.append(Paragraph(f"<b>Nível de risco:</b> {risco}", estilos["Normal"]))
    elementos.append(Spacer(1, 12))

    elementos.append(Paragraph("<b>Serviços Detectados</b>", estilos["Heading2"]))
    elementos.append(Spacer(1, 8))

    for r in resultados:
        elementos.append(
            Paragraph(
                f"Porta {r['porta']} – {r['servico']}",
                estilos["Normal"]
            )
        )

    elementos.append(Spacer(1, 12))
    elementos.append(Paragraph("<b>Recomendações</b>", estilos["Heading2"]))
    elementos.append(Spacer(1, 8))

    if risco == "ALTO":
        elementos.append(Paragraph("Desativar o serviço Telnet imediatamente.", estilos["Normal"]))
    elif risco == "MÉDIO":
        elementos.append(Paragraph("Utilizar HTTPS e senha forte no painel administrativo.", estilos["Normal"]))
    else:
        elementos.append(Paragraph("Nenhuma ação crítica necessária no momento.", estilos["Normal"]))

    doc.build(elementos)

    print(f"\nRelatório PDF gerado: {arquivo_pdf}")


if __name__ == "__main__":
    alvo = input("IP alvo: ")
    resultados = scan(alvo)

    if not resultados:
        print("\nNenhuma porta aberta encontrada.")
        exit()

    risco = resumo_executivo(alvo, resultados)

    # JSON
    arquivo_json = f"relatorio_{alvo}.json"
    with open(arquivo_json, "w") as f:
        json.dump({
            "ip": alvo,
            "data": str(datetime.now()),
            "risco": risco,
            "resultados": resultados
        }, f, indent=4)

    print(f"\nRelatório JSON salvo em {arquivo_json}")

    # PDF
    gerar_pdf(alvo, resultados, risco)
