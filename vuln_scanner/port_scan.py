import socket
import json
import os
import requests
import ssl
import uuid
import threading
from datetime import datetime
from urllib.parse import urljoin, urlparse
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# -------------------- CONFIGURAÇÕES GLOBAIS --------------------
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-ALT", 8443: "HTTPS-ALT"
}
SENSITIVE_PATHS = [
    "/admin", "/login", "/wp-admin", "/phpmyadmin", "/dashboard", "/.env", 
    "/.git", "/config.php", "/backup", "/v1/api", "/robots.txt"
]
DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT"]
DOWNLOAD_DIR = "/storage/emulated/0/Download/Soc-Arx"
SQLI_TESTS = ["'", '"', "' OR 1=1 -- ", '" OR "1"="1', "admin' --", "') OR ('1'='1"]
SUBDOMAINS_LIST = ["www", "mail", "dev", "test", "api", "admin", "vpn", "ssh", "staging", "mysql", "support"]

RECOMENDACOES = {
    21: "FTP é inseguro. Use SFTP (Porta 22) para criptografia.",
    23: "CRÍTICO: Telnet expõe senhas em texto claro. Desative imediatamente e use SSH.",
    25: "SMTP exposto pode permitir Relay de SPAM. Verifique autenticação.",
    80: "HTTP detectado. Instale um certificado SSL e force o redirecionamento para HTTPS.",
    445: "SMB exposto é um vetor comum para Ransomware (WannaCry). Feche o acesso externo.",
    3306: "MySQL não deve ser acessível pela Internet. Use túneis SSH ou VPN.",
    3389: "RDP exposto é alvo constante de Brute Force. Use Gateway de Desktop Remoto.",
    "SQLi": "Vulnerabilidade Crítica! Use 'Prepared Statements' e sanitize todas as entradas de usuários.",
    "Headers": "Segurança de Navegador: Implemente HSTS, CSP e X-Frame-Options para evitar Clickjacking.",
    "Paths": "Diretório Sensível Exposto: Restrinja o acesso via .htaccess ou Firewall de Aplicação (WAF).",
    "SSL": "SSL Inválido: Isso destrói a confiança do cliente e o ranking no Google. Renove o certificado."
}

# -------------------- MÓDULOS DE RECONHECIMENTO --------------------

def verificar_ssl(dominio):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((dominio, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
                expira = cert.get('notAfter')
                sujeito = dict(x[0] for x in cert.get('subject'))
                emissor = dict(x[0] for x in cert.get('issuer'))
                return {
                    "status": "Válido",
                    "expira": expira,
                    "emissor": emissor.get('organizationName', 'Desconhecido')
                }
    except Exception as e:
        return {"status": "Inexistente/Inválido", "erro": str(e)}

def detectar_tecnologias(url):
    print(f"[*] Executando Fingerprinting em {url}...")
    techs = []
    try:
        r = requests.get(url, timeout=4, verify=False, allow_redirects=True)
        h = r.headers
        if 'Server' in h: techs.append(f"Servidor: {h['Server']}")
        if 'X-Powered-By' in h: techs.append(f"Linguagem: {h['X-Powered-By']}")
        if 'via' in h.lower(): techs.append(f"Proxy/WAF: {h['via']}")
        # Verificação de CMS por corpo de página
        corpo = r.text.lower()
        if "wp-content" in corpo: techs.append("CMS: WordPress")
        if "drupal" in corpo: techs.append("CMS: Drupal")
        if "joomla" in corpo: techs.append("CMS: Joomla")
    except: pass
    return techs

# -------------------- LÓGICA DE REDE E DNS --------------------

def ping_host(ip):
    try:
        socket.setdefaulttimeout(1.5)
        socket.gethostbyname(ip)
        return True
    except: return False

def scan_subdominios(dominio):
    print(f"[*] Iniciando Busca de Subdomínios (Anti-Pegadinha)...")
    encontrados = []
    
    # Detecção de Wildcard DNS (Falso Positivo)
    ip_falso = None
    try:
        ip_falso = socket.gethostbyname(f"arx-check-{uuid.uuid4().hex[:6]}.{dominio}")
        print(f"[!] Aviso: Rede com Wildcard detectada (Redirecionando para {ip_falso})")
    except: pass

    for sub in SUBDOMAINS_LIST:
        alvo_sub = f"{sub}.{dominio}"
        try:
            ip_real = socket.gethostbyname(alvo_sub)
            if ip_real != ip_falso:
                encontrados.append({"host": alvo_sub, "ip": ip_real})
                print(f"  [+] Achado: {alvo_sub}")
        except: continue
    return encontrados

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2.5)
        s.connect((ip, port))
        if port in [80, 8080, 443]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        banner = s.recv(2048).decode(errors="ignore").strip()
        s.close()
        return banner if banner else "Sem banner disponível"
    except: return "Conexão recusada/Timeout"

# -------------------- AUDITORIA WEB --------------------

def scan_host_completo(ip):
    print(f"[*] Escaneando portas e serviços em {ip}...")
    resultados = []
    for port in COMMON_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.6)
        if s.connect_ex((ip, port)) == 0:
            serv = PORT_SERVICES.get(port, "Desconhecido")
            banner = grab_banner(ip, port)
            registro = {"porta": port, "servico": serv, "banner": banner}
            
            if port in [80, 8080, 443]:
                # Cabeçalhos
                url = f"{'https' if port == 443 else 'http'}://{ip}:{port}"
                try:
                    r = requests.get(url, timeout=3, verify=False)
                    registro["headers_ausentes"] = verificar_headers_seguranca(r.headers)
                    registro["metodos_perigosos"] = verificar_metodos_http(url)
                    registro["diretorios"] = enumerar_diretorios(url)
                except: pass
            resultados.append(registro)
        s.close()
    return resultados

def verificar_headers_seguranca(h):
    f_h = h.keys()
    essenciais = ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options", "Strict-Transport-Security"]
    return [item for item in essenciais if item not in f_h]

def verificar_metodos_http(url):
    ativos = []
    for m in DANGEROUS_METHODS:
        try:
            r = requests.request(m, url, timeout=2, verify=False)
            if r.status_code != 405: ativos.append(m)
        except: pass
    return ativos

def enumerar_diretorios(url):
    achados = []
    for p in SENSITIVE_PATHS:
        try:
            r = requests.get(url + p, timeout=2, verify=False)
            if r.status_code in [200, 301, 302, 403]:
                achados.append(f"{p} ({r.status_code})")
        except: continue
    return achados

def scan_sqli(url_completa):
    if "http" not in url_completa: return []
    print(f"[*] Testando injeção SQL em {url_completa}...")
    vulneraveis = []
    parsed = urlparse(url_completa)
    if not parsed.query: return []
    
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = parsed.query.split("&")
    for p in params:
        key = p.split("=")[0]
        for payload in SQLI_TESTS:
            try:
                r = requests.get(f"{base}?{key}={payload}", timeout=4)
                if any(err in r.text.lower() for err in ["sql syntax", "mysql_fetch", "sqlite3", "psycopg2"]):
                    vulneraveis.append(f"Parâmetro '{key}' vulnerável com payload: {payload}")
                    break
            except: continue
    return vulneraveis

# -------------------- GERAÇÃO DE RELATÓRIO PDF --------------------

def gerar_pdf_pro(ip, resultados, sqli, subs, ssl_data, techs):
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    nome_arquivo = f"{DOWNLOAD_DIR}/SOC_ARX_AUDIT_{ip}_{datetime.now().strftime('%d%m%Y')}.pdf"
    doc = SimpleDocTemplate(nome_arquivo, pagesize=A4)
    estilos = getSampleStyleSheet()
    elementos = []

    # Título
    elementos.append(Paragraph("🛡️ SOC-ARX – RELATÓRIO DE INTELIGÊNCIA EM CIBERSEGURANÇA", estilos["Title"]))
    elementos.append(Spacer(1, 15))

    # Resumo Executivo
    score = 0
    for r in resultados: 
        if r['porta'] in [23, 445, 3389]: score += 30
        if r.get('diretorios'): score += 10
    if sqli: score += 50
    score = min(score, 100)
    risco = "CRÍTICO" if score > 70 else "MÉDIO" if score > 30 else "BAIXO"

    data_resumo = [
        ['Métrica', 'Estado'],
        ['Host Analisado', ip],
        ['Nível de Risco', risco],
        ['Score de Exposição', f"{score}/100"],
        ['SSL Status', ssl_data['status']]
    ]
    t = Table(data_resumo, colWidths=[150, 250])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.black),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('BACKGROUND', (1,2), (1,2), colors.red if risco == "CRÍTICO" else colors.green),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey)
    ]))
    elementos.append(t)
    elementos.append(Spacer(1, 20))

    # Tecnologias
    if techs:
        elementos.append(Paragraph("<b>📊 Fingerprinting de Infraestrutura:</b>", estilos["Heading2"]))
        for tc in techs: elementos.append(Paragraph(f"• {tc}", estilos["Normal"]))
        elementos.append(Spacer(1, 10))

    # Subdomínios
    if subs:
        elementos.append(Paragraph("<b>🌐 Mapeamento de Ativos (DNS):</b>", estilos["Heading2"]))
        for s in subs: elementos.append(Paragraph(f"• {s['host']} ({s['ip']})", estilos["Normal"]))
        elementos.append(Spacer(1, 10))

    # Vulnerabilidades Técnicas
    elementos.append(Paragraph("<b>🔍 Detalhes Técnicos e Portas:</b>", estilos["Heading2"]))
    for r in resultados:
        elementos.append(Paragraph(f"Porta {r['porta']} - {r['servico']}", estilos["Heading3"]))
        elementos.append(Paragraph(f"<i>Recomendação: {RECOMENDACOES.get(r['porta'], 'Manter monitoramento ativo.')}</i>", estilos["Normal"]))
        if r.get('diretorios'):
            elementos.append(Paragraph(f"<b>Caminhos Expostos:</b> {', '.join(r['diretorios'])}", estilos["Normal"]))
        elementos.append(Spacer(1, 5))

    if sqli:
        elementos.append(Paragraph("<b>⚠️ Vulnerabilidades de Aplicação (SQLi):</b>", estilos["Heading2"]))
        for v in sqli: elementos.append(Paragraph(f"• {v}", estilos["Normal"]))

    doc.build(elementos)
    print(f"\n[SUCCESS] Relatório Profissional: {nome_arquivo}")

# -------------------- EXECUÇÃO PRINCIPAL --------------------

if __name__ == "__main__":
    print("""
    #########################################
    #       SOC-ARX PROFESSIONAL V3.0       #
    #    Security Operations Command        #
    #########################################
    """)
    
    alvo_raw = input("Digite o Alvo (IP ou URL): ").strip()
    dominio = alvo_raw.replace("http://", "").replace("https://", "").split('/')[0]

    if not ping_host(dominio):
        print("[!] Host Offline. Abortando..."); exit()

    # Fluxo de Trabalho
    sub_encontrados = scan_subdominios(dominio) if "." in dominio else []
    ssl_info = verificar_ssl(dominio) if "." in dominio else {"status": "N/A"}
    tecnologias = detectar_tecnologias(f"http://{dominio}")
    resultados_portas = scan_host_completo(dominio)
    vulnerabilidades_sql = scan_sqli(alvo_raw)

    # Geração do PDF Final
    gerar_pdf_pro(dominio, resultados_portas, vulnerabilidades_sql, sub_encontrados, ssl_info, tecnologias)
