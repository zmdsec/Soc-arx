import socket
import json
import os
import requests
from datetime import datetime
from urllib.parse import urljoin, urlparse
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# -------------------- CONFIG --------------------
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 8080: "HTTP-ALT"
}
SENSITIVE_PATHS = ["/admin", "/login", "/wp-admin", "/phpmyadmin", "/dashboard", "/.env"]
DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "OPTIONS"]
DOWNLOAD_DIR = "/storage/emulated/0/Download/Soc-Arx"
SQLI_TESTS = ["'", '"', "' OR 1=1 -- ", '" OR "1"="1']

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
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner if banner else "Banner não identificado"
    except:
        return "Banner não identificado"

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
    metodos_ativos = []
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))
        s.send(b"OPTIONS / HTTP/1.1\r\nHost: alvo\r\n\r\n")
        response = s.recv(2048).decode(errors="ignore")
        s.close()
        for metodo in DANGEROUS_METHODS:
            if metodo in response:
                metodos_ativos.append(metodo)
    except:
        pass
    return metodos_ativos

def interpretar_banner(porta, banner):
    banner = banner.replace("<", "&lt;").replace(">", "&gt;")
    if porta == 23:
        return "Telnet ativo com prompt de autenticação (inseguro)"
    if porta in [80, 8080, 443]:
        info = []
        if "server:" in banner.lower():
            try:
                server = banner.lower().split("server:")[1].split()[0]
                info.append(f"Servidor web: {server}")
            except:
                pass
        if "set-cookie" in banner.lower():
            info.append("Cookie de sessão detectado")
        if not info:
            info.append("Serviço HTTP ativo")
        return " | ".join(info)
    return "Serviço ativo (banner genérico)"

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
                registro["metodos_http_perigosos"] = verificar_metodos_http(ip, port)
            resultados.append(registro)
        s.close()
    return resultados

# -------------------- SQL INJECTION BÁSICO --------------------
def scan_sqli(url):
    vulneraveis = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if not parsed.query:
        return vulneraveis
    params = parsed.query.split("&")
    for p in params:
        key = p.split("=")[0]
        for payload in SQLI_TESTS:
            test_url = f"{base}?{key}={payload}"
            try:
                r = requests.get(test_url, timeout=3)
                if "error" in r.text.lower() or "sql" in r.text.lower():
                    vulneraveis.append(f"Parâmetro '{key}' vulnerável a SQLi (payload: {payload})")
                    break
            except:
                continue
    return vulneraveis

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
    return risco, score

# -------------------- PDF SIMPLES --------------------
def gerar_pdf(ip, resultados, risco, score, sqli=[]):
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    data = datetime.now().strftime("%Y-%m-%d_%H-%M")
    arquivo_pdf = f"{DOWNLOAD_DIR}/relatorio_{ip}_{data}.pdf"
    doc = SimpleDocTemplate(arquivo_pdf, pagesize=A4)
    estilos = getSampleStyleSheet()
    elementos = []

    elementos.append(Paragraph("<b>SOC-ARX – RELATÓRIO DE RECON WEB & REDE</b>", estilos["Title"]))
    elementos.append(Spacer(1,12))
    elementos.append(Paragraph(f"IP analisado: {ip}", estilos["Normal"]))
    elementos.append(Paragraph(f"Data: {datetime.now()}", estilos["Normal"]))
    elementos.append(Paragraph(f"Nível de risco: {risco}", estilos["Normal"]))
    elementos.append(Paragraph(f"Score geral: {score}/100", estilos["Normal"]))
    elementos.append(Spacer(1,12))

    for r in resultados:
        elementos.append(Paragraph(f"Porta {r['porta']} ({r['servico']})", estilos["Heading2"]))
        elementos.append(Paragraph(f"Banner / Info: {interpretar_banner(r['porta'], r['banner'])}", estilos["Normal"]))
        if r.get("diretorios_sensiveis"):
            elementos.append(Paragraph(f"Diretórios sensíveis: {', '.join(r['diretorios_sensiveis'])}", estilos["Normal"]))
        if r.get("headers_seguranca_ausentes"):
            elementos.append(Paragraph(f"Headers ausentes: {', '.join(r['headers_seguranca_ausentes'])}", estilos["Normal"]))
        if r.get("metodos_http_perigosos"):
            elementos.append(Paragraph(f"Métodos HTTP perigosos: {', '.join(r['metodos_http_perigosos'])}", estilos["Normal"]))
        elementos.append(Spacer(1,8))

    if sqli:
        elementos.append(Spacer(1,12))
        elementos.append(Paragraph("<b>SQL Injection detectada:</b>", estilos["Heading2"]))
        for vuln in sqli:
            elementos.append(Paragraph(vuln, estilos["Normal"]))

    doc.build(elementos)
    print(f"\n📄 PDF salvo em: {arquivo_pdf}")

# -------------------- MAIN --------------------
if __name__ == "__main__":
    alvo = input("IP ou URL alvo: ").strip()
    if not ping_host(alvo.split('/')[0]):
        print("Host inativo ou inacessível. Verifique a rede.")
        exit()

    resultados = scan_host(alvo.split('/')[0])
    sqli_vulns = scan_sqli(alvo)
    if not resultados and not sqli_vulns:
        print("Nenhuma vulnerabilidade encontrada.")
        exit()

    risco, score = resumo_executivo(alvo.split('/')[0], resultados)
    gerar_pdf(alvo, resultados, risco, score, sqli_vulns)

    with open(f"{DOWNLOAD_DIR}/relatorio_{alvo}_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.json","w") as f:
        json.dump({
            "ip": alvo,
            "data": str(datetime.now()),
            "risco": risco,
            "score": score,
            "resultados": resultados,
            "sql_injection": sqli_vulns
        }, f, indent=4)

    print("\n✅ Relatórios gerados com sucesso no celular.")
