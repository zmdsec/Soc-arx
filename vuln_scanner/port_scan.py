import socket
import json
import os
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet

# -------------------- CONFIG --------------------
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 8080: "HTTP-ALT"
}
SENSITIVE_PATHS = ["/admin","/login","/wp-admin","/phpmyadmin","/dashboard","/.env"]
DOWNLOAD_DIR = "/storage/emulated/0/Download/Soc-Arx"
DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "OPTIONS"]

# -------------------- UTIL --------------------
def escapar_pdf(texto):
    if not texto:
        return "Não identificado"
    return (
        texto.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
    )

def limpar_banner(raw, limite=120):
    raw = raw.decode("utf-8", errors="ignore")
    raw = "".join(c for c in raw if c.isprintable())
    raw = raw.replace("\r", " ").replace("\n", " ")
    raw = " ".join(raw.split())
    if len(raw) > limite:
        raw = raw[:limite] + "..."
    return raw if raw else "Não identificado"

def ping_host(ip):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, 80))
        s.close()
        return True
    except:
        return False

# -------------------- NETWORK --------------------
def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        if port in [80, 8080, 443]:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        raw = s.recv(1024)
        s.close()
        return limpar_banner(raw)
    except:
        return "Não identificado"

def coletar_headers_http(ip, port):
    headers = {}
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))
        s.send(b"GET / HTTP/1.1\r\nHost: alvo\r\n\r\n")
        resp = s.recv(4096).decode(errors="ignore")
        s.close()
        for linha in resp.split("\r\n"):
            if ":" in linha:
                k, v = linha.split(":", 1)
                headers[k.strip()] = v.strip()
    except:
        pass
    return headers

def verificar_headers_seguranca(headers):
    essenciais = ["X-Frame-Options","Content-Security-Policy","X-Content-Type-Options","Strict-Transport-Security"]
    return [h for h in essenciais if h not in headers]

def enumerar_diretorios(ip, port):
    encontrados = []
    for path in SENSITIVE_PATHS:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((ip, port))
            s.send(f"GET {path} HTTP/1.1\r\nHost: alvo\r\n\r\n".encode())
            resp = s.recv(1024).decode(errors="ignore")
            s.close()
            if "200 OK" in resp or "302" in resp:
                encontrados.append(path)
        except:
            continue
    return encontrados

def verificar_metodos_http(ip, port):
    ativos = []
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))
        s.send(b"OPTIONS / HTTP/1.1\r\nHost: alvo\r\n\r\n")
        resp = s.recv(2048).decode(errors="ignore")
        s.close()
        for m in DANGEROUS_METHODS:
            if m in resp:
                ativos.append(m)
    except:
        pass
    return ativos

# -------------------- SCAN --------------------
def scan_host(ip):
    resultados = []
    print(f"\nEscaneando {ip}...\n")
    for port in COMMON_PORTS:
        s = socket.socket()
        s.settimeout(1)
        if s.connect_ex((ip, port)) == 0:
            r = {
                "porta": port,
                "servico": PORT_SERVICES.get(port, "Desconhecido"),
                "banner": grab_banner(ip, port)
            }
            if port in [80, 8080, 443]:
                headers = coletar_headers_http(ip, port)
                r["headers_seguranca_ausentes"] = verificar_headers_seguranca(headers)
                r["diretorios_sensiveis"] = enumerar_diretorios(ip, port)
                r["metodos_http_perigosos"] = verificar_metodos_http(ip, port)
            resultados.append(r)
        s.close()
    return resultados

# -------------------- RISCO --------------------
def calcular_score(resultados):
    score = 0
    for r in resultados:
        if r["porta"] == 23: score += 50
        elif r["porta"] == 80: score += 20
        if r.get("metodos_http_perigosos"): score += 20
    return min(score, 100)

def resumo_executivo(ip, resultados):
    risco = "ALTO" if any(r["porta"] == 23 for r in resultados) else "MÉDIO"
    score = calcular_score(resultados)
    print("\n====== RESUMO EXECUTIVO ======")
    print(f"IP analisado: {ip}")
    print(f"Portas abertas: {len(resultados)}")
    print(f"Nível de risco: {risco}")
    print(f"Score de risco: {score}/100")
    return risco, score

# -------------------- PDF --------------------
def gerar_pdf(ip, resultados, risco, score):
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    nome = f"{DOWNLOAD_DIR}/SOC_ARX_{ip}_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.pdf"
    doc = SimpleDocTemplate(nome, pagesize=A4)
    estilos = getSampleStyleSheet()
    elementos = []

    elementos.append(Paragraph("<b>SOC-ARX – RELATÓRIO DE SEGURANÇA</b>", estilos["Title"]))
    elementos.append(Spacer(1, 12))
    elementos.append(Paragraph(f"IP analisado: {ip}", estilos["Normal"]))
    elementos.append(Paragraph(f"Risco: {risco}", estilos["Normal"]))
    elementos.append(Paragraph(f"Score: {score}/100", estilos["Normal"]))
    elementos.append(PageBreak())

    for r in resultados:
        elementos.append(Paragraph(
            f"<b>Porta {r['porta']} ({r['servico']})</b>",
            estilos["Heading2"]
        ))

        elementos.append(Paragraph(
            f"<b>Banner:</b> {escapar_pdf(r['banner'])}",
            estilos["Normal"]
        ))

        if r.get("diretorios_sensiveis"):
            elementos.append(Paragraph(
                f"<b>Diretórios:</b> {escapar_pdf(', '.join(r['diretorios_sensiveis']))}",
                estilos["Normal"]
            ))

        if r.get("headers_seguranca_ausentes"):
            elementos.append(Paragraph(
                f"<b>Headers ausentes:</b> {escapar_pdf(', '.join(r['headers_seguranca_ausentes']))}",
                estilos["Normal"]
            ))

        if r.get("metodos_http_perigosos"):
            elementos.append(Paragraph(
                f"<b>Métodos HTTP perigosos:</b> {escapar_pdf(', '.join(r['metodos_http_perigosos']))}",
                estilos["Normal"]
            ))

        elementos.append(Spacer(1, 12))

    doc.build(elementos)
    print(f"\n📄 PDF salvo em: {nome}")

# -------------------- MAIN --------------------
if __name__ == "__main__":
    alvo = input("IP alvo: ")
    if not ping_host(alvo):
        print("Host inacessível.")
        exit()

    resultados = scan_host(alvo)
    if not resultados:
        print("Nenhuma porta aberta.")
        exit()

    risco, score = resumo_executivo(alvo, resultados)
    gerar_pdf(alvo, resultados, risco, score)

    with open(f"{DOWNLOAD_DIR}/SOC_ARX_{alvo}.json", "w") as f:
        json.dump(resultados, f, indent=4)

    print("\n✅ Execução concluída com sucesso.")
