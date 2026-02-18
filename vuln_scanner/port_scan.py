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

# -------------------- UTILIDADES --------------------
def ping_host(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, 80))
        s.close()
        return True
    except:
        return False

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))

        if port in [80, 8080, 443]:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")

        banner = s.recv(1024)
        banner = banner.decode("utf-8", errors="ignore")
        banner = "".join(c for c in banner if c.isprintable())
        banner = banner.replace("\r", " ").replace("\n", " ")
        banner = " ".join(banner.split())
        if len(banner) > 120:
            banner = banner[:120] + "..."
        s.close()
        return banner if banner else "Não identificado"
    except:
        return "Não identificado"

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
    essenciais = ["X-Frame-Options","Content-Security-Policy","X-Content-Type-Options","Strict-Transport-Security"]
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

def verificar_metodos_http(ip, port):
    ativos = []
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))
        s.send(b"OPTIONS / HTTP/1.1\r\nHost: alvo\r\n\r\n")
        response = s.recv(2048).decode(errors="ignore")
        s.close()
        for m in DANGEROUS_METHODS:
            if m in response:
                ativos.append(m)
    except:
        pass
    return ativos

# -------------------- SCANNER --------------------
def scan_host(ip):
    resultados = []
    print(f"\nEscaneando {ip}...\n")
    for port in COMMON_PORTS:
        s = socket.socket()
        s.settimeout(1)
        if s.connect_ex((ip, port)) == 0:
            service = PORT_SERVICES.get(port, "Desconhecido")
            banner = grab_banner(ip, port)
            registro = {"porta": port, "servico": service, "banner": banner}

            if port in [80, 8080, 443]:
                headers = coletar_headers_http(ip, port)
                registro["headers_http"] = headers
                registro["headers_seguranca_ausentes"] = verificar_headers_seguranca(headers)
                registro["diretorios_sensiveis"] = enumerar_diretorios(ip, port)
                registro["metodos_http_perigosos"] = verificar_metodos_http(ip, port)

            resultados.append(registro)
        s.close()
    return resultados

# -------------------- RISCO --------------------
def calcular_score(resultados):
    score = 0
    for r in resultados:
        if r["porta"] == 23: score += 50
        elif r["porta"] == 80: score += 20
        if "metodos_http_perigosos" in r and r["metodos_http_perigosos"]:
            score += 20
    return min(score, 100)

def resumo_executivo(ip, resultados):
    risco = "BAIXO"
    for r in resultados:
        if r["porta"] == 23:
            risco = "ALTO"
            break
        elif r["porta"] == 80:
            risco = "MÉDIO"
    score = calcular_score(resultados)
    print("\n====== RESUMO EXECUTIVO ======")
    print(f"IP analisado: {ip}")
    print(f"Portas abertas: {len(resultados)}")
    print(f"Nível de risco: {risco}")
    print(f"Score de risco: {score}/100")
    return risco, score

# -------------------- PDF PROFISSIONAL --------------------
def gerar_pdf(ip, resultados, risco, score):
    from reportlab.platypus import PageBreak
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    data = datetime.now().strftime("%Y-%m-%d_%H-%M")
    arquivo_pdf = f"{DOWNLOAD_DIR}/relatorio_{ip}_{data}.pdf"
    doc = SimpleDocTemplate(arquivo_pdf, pagesize=A4)
    estilos = getSampleStyleSheet()
    elementos = []

    elementos.append(Paragraph("<b>SOC-ARX – RELATÓRIO DE RECON WEB & REDE</b>", estilos["Title"]))
    elementos.append(Spacer(1, 12))
    elementos.append(Paragraph(f"IP analisado: {ip}", estilos["Normal"]))
    elementos.append(Paragraph(f"Data: {datetime.now()}", estilos["Normal"]))
    elementos.append(Paragraph(f"Risco: {risco}", estilos["Normal"]))
    elementos.append(Paragraph(f"Score: {score}/100", estilos["Normal"]))
    elementos.append(Spacer(1, 12))
    elementos.append(PageBreak())  # Separa capa do conteúdo

    for r in resultados:
        elementos.append(Paragraph(f"<b>Porta {r['porta']} ({r['servico']})</b>", estilos["Heading2"]))
        elementos.append(Paragraph(f"Banner / Info: {r['banner']}", estilos["Normal"]))
        if r.get("diretorios_sensiveis"):
            elementos.append(Paragraph(f"Diretórios sensíveis: {', '.join(r['diretorios_sensiveis'])}", estilos["Normal"]))
        if r.get("headers_seguranca_ausentes"):
            elementos.append(Paragraph(f"Headers ausentes: {', '.join(r['headers_seguranca_ausentes'])}", estilos["Normal"]))
        if r.get("metodos_http_perigosos"):
            elementos.append(Paragraph(f"Métodos HTTP perigosos: {', '.join(r['metodos_http_perigosos'])}", estilos["Normal"]))
        elementos.append(Spacer(1, 12))

    doc.build(elementos)
    print(f"\n📄 PDF salvo em: {arquivo_pdf}")

# -------------------- MAIN --------------------
if __name__ == "__main__":
    alvo = input("IP alvo: ")
    if not ping_host(alvo):
        print("Host inativo ou inacessível. Verifique a rede.")
        exit()
    resultados = scan_host(alvo)
    if not resultados:
        print("\nNenhuma porta aberta encontrada.")
        exit()
    risco, score = resumo_executivo(alvo, resultados)
    gerar_pdf(alvo, resultados, risco, score)

    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    arquivo_json = f"{DOWNLOAD_DIR}/relatorio_{alvo}_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.json"
    with open(arquivo_json, "w") as f:
        json.dump({
            "ip": alvo,
            "data": str(datetime.now()),
            "risco": risco,
            "score": score,
            "resultados": resultados
        }, f, indent=4)

    print("\n✅ Relatórios gerados com sucesso no celular.")
