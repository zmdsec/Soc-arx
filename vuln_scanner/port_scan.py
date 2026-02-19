import socket
import os
import requests
import ssl
import uuid
import urllib3
import time
import sys
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import List, Dict

# --- SUPORTE A PDF NO TERMUX ---
try:
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    PDF_OK = True
except ImportError:
    PDF_OK = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CORES PARA O TERMINAL DO TERMUX ---
G = '\033[92m' # Verde (Sucesso)
Y = '\033[93m' # Amarelo (Aviso)
R = '\033[91m' # Vermelho (Perigo)
C = '\033[96m' # Ciano (Info)
E = '\033[0m'  # Reset

# --- CAMINHO DE DOWNLOAD NO ANDROID ---
# O comando 'termux-setup-storage' deve ter sido executado
DOWNLOAD_PATH = "/sdcard/Download/Soc-Arx"
if not os.path.exists(DOWNLOAD_PATH):
    os.makedirs(DOWNLOAD_PATH, exist_ok=True)

# --- BANCO DE CONHECIMENTO DE VULNERABILIDADES ---
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443, 9000]

DB_VULNS = {
    21: {"servico": "FTP", "risco": "ALTO", "obs": "Dados trafegam em texto claro. Risco de Sniffing."},
    23: {"servico": "Telnet", "risco": "CRÍTICO", "obs": "Protocolo obsoleto e inseguro. Use SSH."},
    80: {"servico": "HTTP", "risco": "MÉDIO", "obs": "Site sem criptografia SSL/TLS."},
    445: {"servico": "SMB", "risco": "CRÍTICO", "obs": "Vulnerável a EternalBlue/Ransomware se não patcheado."},
    1433: {"servico": "MSSQL", "risco": "ALTO", "obs": "Banco de dados exposto. Alvo de injeção direta."},
    3306: {"servico": "MySQL", "risco": "ALTO", "obs": "Exposição de DB. Risco de vazamento de dados."},
    3389: {"servico": "RDP", "risco": "CRÍTICO", "obs": "Acesso remoto exposto. Alvo de Brute Force/BlueKeep."},
}

# -------------------- MOTOR TÉCNICO --------------------

def get_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1.5)
        s.connect((ip, port))
        if port in [80, 8080, 443]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        banner = s.recv(1024).decode(errors='ignore').strip()
        return banner[:150] if banner else "Banner Oculto"
    except: return "N/A"

def analyze_headers(url):
    findings = []
    try:
        r = requests.get(url, timeout=5, verify=False)
        headers = r.headers
        security_headers = {
            "Strict-Transport-Security": "HSTS não implementado (Risco de Downgrade)",
            "Content-Security-Policy": "CSP ausente (Risco de XSS)",
            "X-Frame-Options": "Proteção Anti-Clickjacking ausente",
            "X-Content-Type-Options": "MIME Sniffing não bloqueado"
        }
        for h, msg in security_headers.items():
            if h not in headers:
                findings.append(f"MISSING: {h} -> {msg}")
        
        server = headers.get("Server", "Oculto")
        powered = headers.get("X-Powered-By", "Oculto")
        return findings, server, powered
    except: return [], "Erro", "Erro"

def check_ssl_expiry(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return "Protegido", cert.get('notAfter'), dict(x[0] for x in cert['issuer']).get('organizationName')
    except: return "Inseguro/Nenhum", "N/A", "N/A"

# -------------------- GERADOR DE PDF --------------------

def export_pdf(target, open_ports, web_vulns, ssl_info, server_info):
    if not PDF_OK:
        print(f"{R}[!] Reportlab não instalado. PDF não gerado.{E}")
        return
    
    filename = f"{DOWNLOAD_PATH}/SCAN_{target.replace('.', '_')}.pdf"
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    
    # Estilo customizado
    styles.add(ParagraphStyle(name='CenterTitle', alignment=TA_CENTER, fontSize=20, textColor=colors.darkblue, spaceAfter=20))
    
    elements = []
    elements.append(Paragraph("🛡️ SOC-ARX SECURITY SCANNER", styles['CenterTitle']))
    elements.append(Paragraph(f"<b>Alvo:</b> {target}", styles['Normal']))
    elements.append(Paragraph(f"<b>Data:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles['Normal']))
    elements.append(Spacer(1, 15))

    # Tabela de Portas
    elements.append(Paragraph("1. Análise de Portas e Serviços", styles['Heading2']))
    p_data = [["Porta", "Serviço", "Risco", "Observação"]]
    for p in open_ports:
        v_info = DB_VULNS.get(p['num'], {"servico": "Unk", "risco": "BAIXO", "obs": "Monitorar tráfego."})
        p_data.append([str(p['num']), v_info['servico'], v_info['risco'], v_info['obs']])
    
    pt = Table(p_data, colWidths=[50, 80, 70, 250])
    pt.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('FONTSIZE', (0,0), (-1,-1), 9)
    ]))
    elements.append(pt)
    elements.append(Spacer(1, 20))

    # Vulnerabilidades Web
    elements.append(Paragraph("2. Auditoria de Configuração Web", styles['Heading2']))
    elements.append(Paragraph(f"<b>Servidor Detectado:</b> {server_info}", styles['Normal']))
    elements.append(Paragraph(f"<b>Status SSL:</b> {ssl_info[0]} (Expira: {ssl_info[1]})", styles['Normal']))
    
    for v in web_vulns:
        elements.append(Paragraph(f"• {v}", styles['Normal']))

    doc.build(elements)
    print(f"\n{G}[✔] RELATÓRIO PDF GERADO EM: {filename}{E}")

# -------------------- EXECUÇÃO --------------------

def main():
    print(f"{C}{'='*50}\n   SOC-ARX V3.8 - SCANNER DE VULNERABILIDADES\n{'='*50}{E}")
    target = input(f"{Y}➤ Digite o IP ou Domínio: {E}").strip()
    if not target: return

    # Início do Scan
    print(f"\n{C}[*] Analisando Infraestrutura de {target}...{E}")
    
    # 1. SSL
    ssl_res = check_ssl_expiry(target)
    
    # 2. Portas e Banners
    open_ports = []
    for port in SCAN_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.6)
        if s.connect_ex((target, port)) == 0:
            print(f"  {G}[+] Porta {port} Aberta!{E}")
            open_ports.append({"num": port, "banner": get_banner(target, port)})
        s.close()
    
    # 3. Web Intelligence
    web_vulns, server_name, _ = analyze_headers(f"http://{target}")

    # 4. Geração do Relatório
    if open_ports or web_vulns:
        export_pdf(target, open_ports, web_vulns, ssl_res, server_name)
    else:
        print(f"{R}[!] Nenhuma vulnerabilidade exposta encontrada.{E}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nSaindo...")
