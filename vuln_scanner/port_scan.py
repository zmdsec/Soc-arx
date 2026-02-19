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

SENSITIVE_FILES = ["/robots.txt", "/.env", "/package.json", "/ftp/", "/admin/", "/api/v1/users"]

# -------------------- MOTOR TÉCNICO --------------------

def get_cloud_provider(target):
    """Detecta se o alvo está na AWS, Google ou Heroku"""
    try:
        ip = socket.gethostbyname(target)
        hostname = socket.gethostbyaddr(ip)[0]
        if "amazonaws" in hostname: return "Amazon AWS"
        if "heroku" in hostname: return "Heroku Cloud"
        if "google" in hostname: return "Google Cloud"
        return f"Provedor Independente ({hostname})"
    except:
        return "Desconhecido"

def analyze_web_intelligence(url):
    """Coleta Cookies e Diretórios simulando um navegador real"""
    results = {"cookies": [], "files": [], "tech": "Oculta", "cloud": "Verificando..."}
    
    # Headers para evitar bloqueio do Heroku/AWS
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'
    }
    
    try:
        domain = urlparse(url).netloc
        results['cloud'] = get_cloud_provider(domain)
        
        # Uso de Session para persistência de cookies
        session = requests.Session()
        r = session.get(url, timeout=5, verify=False, headers=headers)
        
        results['tech'] = r.headers.get("Server", r.headers.get("Via", "Não detectada"))
        
        # Auditoria de Cookies
        if session.cookies:
            for cookie in session.cookies:
                flags = []
                if not cookie.has_nonstandard_attr('HttpOnly'): flags.append("Sem HttpOnly (Risco XSS)")
                if not cookie.secure: flags.append("Sem Secure (Risco Sniffing)")
                results['cookies'].append(f"{cookie.name}: {'Seguro' if not flags else ' | '.join(flags)}")
        else:
            results['cookies'].append("Nenhum cookie detectado na raiz.")

        # Path Discovery
        for path in SENSITIVE_FILES:
            test_url = urljoin(url, path)
            try:
                res = session.get(test_url, timeout=2, verify=False, headers=headers)
                if res.status_code == 200:
                    results['files'].append(f"{path} (Acesso Livre)")
                elif res.status_code == 403:
                    results['files'].append(f"{path} (Privado/Protegido)")
            except: continue
    except Exception as e:
        results['tech'] = f"Erro: {str(e)}"
    return results

def run_nmap_scan(target):
    print(f"\n{B}{Y}[NMAP] Orquestrando diagnóstico de serviços...{E}")
    try:
        cmd = ["nmap", "-sV", "-T4", "-F", target]
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
    except: return "Nmap falhou ou não instalado."

# -------------------- RELATÓRIO PDF --------------------

def export_pdf(target, nmap_data, web_intel):
    if not PDF_OK: return
    path = f"{DOWNLOAD_PATH}/SOC_V65_{target.replace('.', '_')}.pdf"
    doc = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()
    
    elements = []
    elements.append(Paragraph(f"🛡️ SOC-ARX INTELLIGENCE REPORT", styles['Heading1']))
    elements.append(Paragraph(f"<b>ALVO:</b> {target} | <b>DATA:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles['Normal']))
    elements.append(Paragraph(f"<b>INFRAESTRUTURA:</b> {web_intel['cloud']}", styles['Normal']))
    
    elements.append(Spacer(1, 15))
    elements.append(Paragraph("1. Inteligência Web (OWASP)", styles['Heading2']))
    elements.append(Paragraph(f"<b>Servidor:</b> {web_intel['tech']}", styles['Normal']))
    
    elements.append(Paragraph("<b>Diretórios e Arquivos:</b>", styles['Normal']))
    for f in web_intel['files']: elements.append(Paragraph(f"• {f}", styles['Normal']))
    
    elements.append(Paragraph("<b>Auditoria de Cookies:</b>", styles['Normal']))
    for c in web_intel['cookies']: elements.append(Paragraph(f"• {c}", styles['Normal']))

    elements.append(PageBreak())
    elements.append(Paragraph("2. Auditoria de Rede (Nmap Output)", styles['Heading2']))
    nmap_style = ParagraphStyle('Mono', fontName='Courier', fontSize=7, leading=9)
    for line in nmap_data.split('\n'):
        elements.append(Paragraph(line.replace(' ', '&nbsp;'), nmap_style))

    doc.build(elements)
    return path

# -------------------- MAIN --------------------

def main():
    os.system('clear')
    print(f"{C}{B}SOC-ARX V6.5 - ORQUESTRADOR TÁTICO{E}")
    target = input(f"\n{B}{Y}❯ TARGET_ID (IP/URL): {E}").strip()
    if not target: return

    print(f"\n{C}[*] Coletando inteligência web...{E}")
    web_intel = analyze_web_intelligence(f"http://{target}")
    
    nmap_res = run_nmap_scan(target)
    
    print(f"\n{B}{'='*50}\nRESUMO TÁTICO: {target}\n{'='*50}{E}")
    print(f"{B}Nuvem:{E} {web_intel['cloud']}")
    print(f"{B}Arquivos Encontrados:{E} {len(web_intel['files'])}")
    
    path = export_pdf(target, nmap_res, web_intel)
    print(f"\n{G}[✔] RELATÓRIO GERADO: {path}{E}\n")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nEncerrado.")
