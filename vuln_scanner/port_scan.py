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

# --- CORES E ESTILO ---
G = '\033[92m' # Verde
Y = '\033[93m' # Amarelo
R = '\033[91m' # Vermelho
C = '\033[96m' # Ciano
B = '\033[1m'  # Negrito
E = '\033[0m'  # Reset

# --- CAMINHO DE DOWNLOAD ---
DOWNLOAD_PATH = "/sdcard/Download/Soc-Arx"
if not os.path.exists(DOWNLOAD_PATH):
    os.makedirs(DOWNLOAD_PATH, exist_ok=True)

# --- BANCO DE CONHECIMENTO ---
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443, 9000]

DB_VULNS = {
    21: {"servico": "FTP", "risco": "ALTO", "obs": "Dados em texto claro. Risco de Sniffing."},
    22: {"servico": "SSH", "risco": "BAIXO", "obs": "Serviço seguro. Verifique força bruta."},
    23: {"servico": "Telnet", "risco": "CRÍTICO", "obs": "Protocolo obsoleto. Use SSH."},
    80: {"servico": "HTTP", "risco": "MÉDIO", "obs": "Falta de criptografia SSL/TLS."},
    443: {"servico": "HTTPS", "risco": "BAIXO", "obs": "Web Segura."},
    445: {"servico": "SMB", "risco": "CRÍTICO", "obs": "Vulnerável a Ransomware (WannaCry)."},
    1433: {"servico": "MSSQL", "risco": "ALTO", "obs": "DB exposto diretamente."},
    3306: {"servico": "MySQL", "risco": "ALTO", "obs": "DB exposto. Risco de vazamento."},
    3389: {"servico": "RDP", "risco": "CRÍTICO", "obs": "Alvo de BlueKeep e Brute Force."},
}

# -------------------- MOTOR TÉCNICO --------------------

def logo():
    os.system('clear')
    print(f"""{C}
    ███████╗ ██████╗  ██████╗         █████╗ ██████╗ ██╗  ██╗
    ██╔════╝██╔═══██╗██╔════╝        ██╔══██╗██╔══██╗╚██╗██╔╝
    ███████╗██║   ██║██║     █████╗  ███████║██████╔╝ ╚███╔╝ 
    ╚════██║██║   ██║██║     ╚════╝  ██╔══██║██╔══██╗ ██╔██╗ 
    ███████║╚██████╔╝╚██████╗        ██║  ██║██║  ██║██╔╝ ██╗
    ╚══════╝ ╚═════╝  ╚═════╝        ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
             {R}V4.5 - CYBERSECURITY OPERATIONS CENTER{E}
    """)

def progress_bar(it, total, prefix='', length=30):
    percent = ("{0:.1f}").format(100 * (it / float(total)))
    filled = int(length * it // total)
    bar = '█' * filled + '-' * (length - filled)
    sys.stdout.write(f'\r{prefix} |{C}{bar}{E}| {percent}% ')
    sys.stdout.flush()

def get_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1.0)
        s.connect((ip, port))
        if port in [80, 8080, 443]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        banner = s.recv(1024).decode(errors='ignore').strip()
        return banner[:150] if banner else "Oculto"
    except: return "N/A"

def analyze_headers(url):
    findings = []
    try:
        r = requests.get(url, timeout=5, verify=False)
        headers = r.headers
        sec_h = {
            "Strict-Transport-Security": "HSTS ausente",
            "Content-Security-Policy": "CSP ausente",
            "X-Frame-Options": "Anti-Clickjacking ausente"
        }
        for h, msg in sec_h.items():
            if h not in headers: findings.append(f"{h}: {msg}")
        return findings, headers.get("Server", "Oculto")
    except: return [], "Erro"

def check_ssl(hostname):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return "Protegido", cert.get('notAfter')
    except: return "Inseguro", "N/A"

# -------------------- GERADOR DE PDF --------------------

def export_pdf(target, open_ports, web_vulns, ssl_info, server_info):
    if not PDF_OK: return
    filename = f"{DOWNLOAD_PATH}/SCAN_{target.replace('.', '_')}.pdf"
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='SOC_Title', alignment=TA_CENTER, fontSize=22, textColor=colors.darkblue, spaceAfter=20))
    
    elements = []
    elements.append(Paragraph("🛡️ SOC-ARX AUDIT REPORT", styles['SOC_Title']))
    elements.append(Paragraph(f"<b>Alvo:</b> {target} | <b>Data:</b> {datetime.now().strftime('%d/%m/%Y')}", styles['Normal']))
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("1. Portas Detectadas", styles['Heading2']))
    p_data = [["Porta", "Serviço", "Risco", "Observação"]]
    for p in open_ports:
        v = DB_VULNS.get(p['num'], {"servico": "Unk", "risco": "BAIXO", "obs": "Monitorar."})
        p_data.append([str(p['num']), v['servico'], v['risco'], v['obs']])
    
    pt = Table(p_data, colWidths=[50, 80, 70, 250])
    pt.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.darkblue),('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),('GRID',(0,0),(-1,-1),0.5,colors.grey)]))
    elements.append(pt)
    
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("2. Segurança Web", styles['Heading2']))
    elements.append(Paragraph(f"Servidor: {server_info} | SSL: {ssl_info[0]}", styles['Normal']))
    for v in web_vulns: elements.append(Paragraph(f"• {v}", styles['Normal']))

    doc.build(elements)
    return filename

# -------------------- EXECUÇÃO --------------------

def main():
    logo()
    target = input(f"{B}{Y}❯ TARGET_ID (IP/Dominio): {E}").strip()
    if not target: return

    print(f"\n{C}[*] INICIANDO PROTOCOLO EM: {target}{E}")
    
    ssl_res = check_ssl(target)
    open_ports = []
    
    total = len(SCAN_PORTS)
    for i, port in enumerate(SCAN_PORTS):
        progress_bar(i + 1, total, prefix='[AUDIT]')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if s.connect_ex((target, port)) == 0:
            open_ports.append({"num": port, "banner": get_banner(target, port)})
        s.close()

    web_vulns, server_name = analyze_headers(f"http://{target}")

    # Tabela Visual no Terminal
    print(f"\n\n{B}{'PORTA':<8} | {'SERVIÇO':<12} | {'ESTADO':<8} | {'RISCO':<10}{E}")
    print("-" * 50)
    for p in open_ports:
        v = DB_VULNS.get(p['num'], {"servico": "Unk", "risco": "BAIXO"})
        color = R if v['risco'] in ["CRÍTICO", "ALTO"] else Y
        print(f"{p['num']:<8} | {v['servico']:<12} | {G}{'OPEN':<8}{E} | {color}{v['risco']:<10}{E}")

    if open_ports or web_vulns:
        path = export_pdf(target, open_ports, web_vulns, ssl_res, server_name)
        print(f"\n{G}[✔] RELATÓRIO PDF GERADO: {path}{E}\n")
    else:
        print(f"\n{R}[!] Alvo aparentemente seguro.{E}")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nProtocolo interrompido.")
