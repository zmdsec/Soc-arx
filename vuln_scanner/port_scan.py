import socket
import json
import os
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

SENSITIVE_PATHS = [
    "/admin",
    "/login",
    "/wp-admin",
    "/phpmyadmin",
    "/dashboard",
    "/.env"
]

DOWNLOAD_DIR = "/storage/emulated/0/Download/Soc-Arx"


# ===================== RECON WEB =====================

def coletar_headers_http(ip, port):
    headers = {}
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))
        s.send(b"GET / HTTP/1.1\r\nHost: alvo\r\n\r\n")
        response = s.recv(4096).decode(errors="ignore")
        s.close()

        for linha in response.split("\r\n"):
            if ":" in linha:
                k, v = linha.split(":", 1)
                headers[k.strip()] = v.strip()
    except:
        pass

    return headers


def verificar_headers_seguranca(headers):
    essenciais = [
        "X-Frame-Options",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "Strict-Transport-Security"
    ]
    return [h for h in essenciais if h not in headers]


def enumerar_diretorios(ip, port):
    encontrados = []

    for path in SENSITIVE_PATHS:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((ip, port))
            req = f"GET {path} HTTP/1.1\r\nHost: alvo\r\n\r\n"
            s.send(req.encode())
            resp = s.recv(1024).decode(errors="ignore")
            s.close()

            if "200 OK" in resp or "302" in resp:
                encontrados.append(path)
        except:
            continue

    return encontrados


# ===================== SCANNER =====================

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
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

            registro = {
                "porta": port,
                "servico": service,
                "banner": banner
            }

            if port in [80, 8080, 443]:
                headers = coletar_headers_http(ip, port)
                registro["headers_http"] = headers
                registro["headers_seguranca_ausentes"] = verificar_headers_seguranca(headers)
                registro["diretorios_sensiveis"] = enumerar_diretorios(ip, port)

            results.append(registro)

        s.close()

    return results


# ===================== RISCO =====================

def calcular_score(resultados):
    score = 0
    for r in resultados:
        if r["porta"] == 23:
            score += 50
        elif r["porta"] == 80:
            score += 20
        else:
            score += 5
    return min(score, 100)


def resumo_executivo(alvo, resultados):
    risco = "BAIXO"

    for r in resultados:
        if r["porta"] == 23:
            risco = "ALTO"
            break
        elif r["porta"] == 80:
            risco = "MÉDIO"

    score = calcular_score(resultados)

    print("\n====== RESUMO EXECUTIVO ======")
    print(f"IP analisado: {alvo}")
    print(f"Portas abertas: {len(resultados)}")
    print(f"Nível de risco: {risco}")
    print(f"Score de risco: {score}/100")

    return risco, score


# ===================== PDF =====================

def gerar_pdf(alvo, resultados, risco, score):
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)

    data = datetime.now().strftime("%Y-%m-%d_%H-%M")
    arquivo_pdf = f"{DOWNLOAD_DIR}/relatorio_{alvo}_{data}.pdf"

    doc = SimpleDocTemplate(arquivo_pdf, pagesize=A4)
    estilos = getSampleStyleSheet()
    elementos = []

    elementos.append(Paragraph("<b>SOC-ARX – RELATÓRIO DE RECON WEB</b>", estilos["Title"]))
    elementos.append(Spacer(1, 12))

    elementos.append(Paragraph(f"IP analisado: {alvo}", estilos["Normal"]))
    elementos.append(Paragraph(f"Data: {datetime.now()}", estilos["Normal"]))
    elementos.append(Paragraph(f"Risco: {risco}", estilos["Normal"]))
    elementos.append(Paragraph(f"Score: {score}/100", estilos["Normal"]))
    elementos.append(Spacer(1, 12))

    for r in resultados:
        elementos.append(
            Paragraph(f"Porta {r['porta']} – {r['servico']}", estilos["Heading2"])
        )

        if "headers_seguranca_ausentes" in r and r["headers_seguranca_ausentes"]:
            elementos.append(
                Paragraph(
                    f"Headers de segurança ausentes: {', '.join(r['headers_seguranca_ausentes'])}",
                    estilos["Normal"]
                )
            )

        if "diretorios_sensiveis" in r and r["diretorios_sensiveis"]:
            elementos.append(
                Paragraph(
                    f"Diretórios sensíveis encontrados: {', '.join(r['diretorios_sensiveis'])}",
                    estilos["Normal"]
                )
            )

        elementos.append(Spacer(1, 8))

    doc.build(elementos)

    print(f"\n📄 PDF salvo em: {arquivo_pdf}")


# ===================== MAIN =====================

if __name__ == "__main__":
    alvo = input("IP alvo: ")
    resultados = scan(alvo)

    if not resultados:
        print("\nNenhuma porta aberta encontrada.")
        exit()

    risco, score = resumo_executivo(alvo, resultados)
    gerar_pdf(alvo, resultados, risco, score)

    with open(f"relatorio_{alvo}.json", "w") as f:
        json.dump({
            "ip": alvo,
            "data": str(datetime.now()),
            "risco": risco,
            "score": score,
            "resultados": resultados
        }, f, indent=4)

    print("\n✅ Relatórios gerados com sucesso.")
