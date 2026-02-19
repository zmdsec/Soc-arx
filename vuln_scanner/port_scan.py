import socket
import os
import requests
import ssl
import subprocess
import urllib3
import time
import sys
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import List, Dict

# --- SUPORTE A PDF ---
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
G, Y, R, C, B, E = '\033[92m', '\033[93m', '\033[91m', '\033[96m', '\033[1m', '\033[0m'

DOWNLOAD_PATH = "/sdcard/Download/Soc-Arx"
if not os.path.exists(DOWNLOAD_PATH): os.makedirs(DOWNLOAD_PATH, exist_ok=True)

# --- CONFIGURAÇÕES DE SCAN ---
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 8080, 9000]
SENSITIVE_FILES = ["/robots.txt", "/.env", "/package.json", "/ftp/", "/admin/", "/.git/config"]

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
             {R}V6.0 - FULL ORCHESTRATOR & STUDY MODE{E}
    """)

def progress_bar(it, total, prefix='', length=30):
    percent = ("{0:.1f}").format(100 * (it / float(total)))
    filled = int(length * it // total)
    bar = '█' * filled + '-' * (length - filled)
    sys.stdout.write(f'\r{prefix} |{C}{bar}{E}| {percent}% ')
    sys.stdout.flush()

def run_nmap_scan(target):
    print(f"\n{B}{Y}[NMAP] Executando diagnóstico de serviços...{E}")
    try:
        cmd = ["nmap", "-sV", "-T4", "-F", target]
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
    except: return "Erro ao chamar Nmap."

def analyze_web_intelligence(url):
    results = {"cookies": [], "files": [], "tech": "Oculta", "headers": []}
    try:
        r = requests.get(url, timeout=5, verify=False)
        results['tech'] = r.headers.get("Server", "Não detectada")
        
        # Cookies & Flags (OWASP Study)
        for cookie in r.cookies:
            flags = []
            if not cookie.has_nonstandard_attr('HttpOnly'): flags.append("Sem HttpOnly")
            if not cookie.secure: flags.append("Sem Secure")
            results['cookies'].append(f"{cookie.name}: {'Seguro' if not flags else ' | '.join(flags)}")

        # Path Discovery
        for path in SENSITIVE_FILES:
            test_url = urljoin(url, path)
            if requests.get(test_url, timeout=2, verify=False).status_code == 200:
                results['files'].append(path)
    except: pass
    return results

# -------------------- RELATÓRIO PDF --------------------

def export_pdf(target, nmap_data, web_intel):
    if not PDF_OK: return
    path = f"{DOWNLOAD_PATH}/SOC_FULL_SCAN_{target.replace('.', '_')}.pdf"
    doc = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()
    
    elements = []
    elements.append(Paragraph(f"🛡️ SOC-ARX FULL AUDIT: {target}", styles['Heading1']))
    elements.append(Paragraph(f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles['Normal']))
    
    # Seção Web
    elements.append(Spacer(1, 15))
    elements.append(Paragraph("1. Inteligência de Aplicação (Python/OWASP)", styles['Heading2']))
    elements.append(Paragraph(f"<b>Servidor:</b> {web_intel['tech']}", styles['Normal']))
    
    elements.append(Paragraph("<b>Diretórios Detectados:</b>", styles['Normal']))
    for f in web_intel['files']: elements.append(Paragraph(f"• {f}", styles['Normal']))
    
    elements.append(Paragraph("<b>Segurança de Cookies:</b>", styles['Normal']))
    for c in web_intel['cookies']: elements.append(Paragraph(f"• {c}", styles['Normal']))

    # Seção Nmap
    elements.append(PageBreak())
    elements.append(Paragraph("2. Auditoria de Rede Profunda (Nmap Output)", styles['Heading2']))
    nmap_style = ParagraphStyle('Mono', fontName='Courier', fontSize=7, leading=9)
    for line in nmap_data.split('\n'):
        elements.append(Paragraph(line.replace(' ', '&nbsp;'), nmap_style))

    doc.build(elements)
    return path

# -------------------- MAIN --------------------

def main():
    logo()
    target = input(f"{B}{Y}❯ TARGET_ID (IP/URL): {E}").strip()
    if not target: return

    # 1. Scan Rápido e Barra de Progresso
    print(f"\n{C}[*] Analisando Infraestrutura Básica...{E}")
    for i in range(1, 11):
        time.sleep(0.1)
        progress_bar(i, 10, prefix='[STATUS]')
    
    # 2. Inteligência Web
    web_intel = analyze_web_intelligence(f"http://{target}")
    
    # 3. Nmap Orquestrado
    nmap_res = run_nmap_scan(target)
    
    # Visualização em Tempo Real (Terminal)
    print(f"\n\n{B}{'='*50}\nDETALHES DO ALVO\n{'='*50}{E}")
    print(f"{G}{nmap_res}{E}")
    
    if web_intel['files']:
        print(f"{Y}[!] Arquivos Críticos: {', '.join(web_intel['files'])}{E}")

    # 4. Gerar Relatório
    path = export_pdf(target, nmap_res, web_intel)
    print(f"\n{G}[✔] RELATÓRIO COMPLETO GERADO: {path}{E}\n")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nEncerrado.")
