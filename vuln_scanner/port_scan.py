import socket, os, requests, ssl, subprocess, urllib3, time, sys
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

# Tenta definir o caminho de download, mas tem um plano B (pasta local)
DOWNLOAD_PATH = "/sdcard/Download/Soc-Arx"
try:
    if not os.path.exists(DOWNLOAD_PATH): 
        os.makedirs(DOWNLOAD_PATH, exist_ok=True)
except:
    DOWNLOAD_PATH = os.getcwd() # Se falhar no SDCard, usa a pasta onde o script está

SENSITIVE_FILES = [
    "/robots.txt", "/.env", "/admin/", "/api/v1/users", 
    "/config.php", "/db.sql", "/backup.sql", "/setup.sql", 
    "/.git/", "/phpinfo.php", "/index.php.bak", "/.sql",
    "/credentials.txt", "/db_backup.sql", "/web.config", 
    "/login.aspx", "/aspnet_client/"
]

LABS = {
    "1": ("OWASP Juice Shop", "demo.owasp-juiceshop.org"),
    "2": ("Altoro Mutual (Banco)", "demo.testfire.net"),
    "3": ("Test PHP (VulnWeb)", "testphp.vulnweb.com"),
    "4": ("Test ASP.NET (Windows)", "testaspnet.vulnweb.com"),
    "5": ("Minha Câmera (Estudo IP)", "200.x.x.x") 
}

# -------------------- MOTOR TÉCNICO --------------------

def auto_installer():
    tools = ["nmap"]
    for tool in tools:
        if subprocess.getstatusoutput(f"command -v {tool}")[0] != 0:
            print(f"{Y}[!] Instalando {tool}...{E}")
            os.system(f"pkg install {tool} -y")

def check_vpn():
    try:
        ip = requests.get("https://api64.ipify.org", timeout=5).text
        if ":" in ip:
            status = f"{G}PROTEGIDA (IPv6/VPN){E}"
        else:
            status = f"{Y}IPv4 (Verificar Chave VPN){E}"
        return ip, status
    except:
        return "Detectado", f"{Y}VERIFICAR CONEXÃO{E}"

def get_telnet_banner(target):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, 23))
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner if banner else "Porta 23 aberta"
    except: return None

def analyze_web_intelligence(url):
    results = {"cookies": [], "files": [], "tech": "Oculta", "cloud": "Verificando...", "telnet": None}
    headers = {'User-Agent': 'Mozilla/5.0 SOC-ARX-V7.6'}
    
    try:
        domain = urlparse(url).netloc
        try:
            ip = socket.gethostbyname(domain)
            results['telnet'] = get_telnet_banner(ip)
            results['cloud'] = "Analise de Host completa"
        except: pass

        try:
            results['tech'] = subprocess.check_output(["whatweb", "--color=never", url], stderr=subprocess.DEVNULL).decode().strip()
        except:
            results['tech'] = "WhatWeb indisponível"

        session = requests.Session()
        r = session.get(url, timeout=5, verify=False, headers=headers)
        
        if session.cookies:
            for cookie in session.cookies:
                flags = []
                if not cookie.secure: flags.append("Sem Secure")
                results['cookies'].append(f"{cookie.name}: {flags if flags else 'OK'}")

        for path in SENSITIVE_FILES:
            test_url = urljoin(url, path)
            try:
                res = session.get(test_url, timeout=2, verify=False, headers=headers)
                if res.status_code == 200:
                    results['files'].append(f"{path} (ACHADO CRÍTICO)")
            except: continue
    except Exception as e:
        results['tech'] = f"Erro: {str(e)}"
    return results

def run_nmap_scan(target):
    print(f"\n{B}{Y}[NMAP] Escaneando...{E}")
    try:
        cmd = ["nmap", "-sV", "-T4", "-F", "-Pn", target]
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
    except: return "Nmap falhou."

# -------------------- RELATÓRIO PDF --------------------

def export_pdf(target, nmap_data, web_intel):
    if not PDF_OK: 
        print(f"{R}[!] Erro: Biblioteca ReportLab não instalada.{E}")
        return None
    
    filename = f"SOC_V76_{target.replace('.', '_')}.pdf"
    path = os.path.join(DOWNLOAD_PATH, filename)
    
    try:
        doc = SimpleDocTemplate(path, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []
        
        elements.append(Paragraph(f"🛡️ SOC-ARX V7.6 REPORT", styles['Heading1']))
        elements.append(Paragraph(f"<b>ALVO:</b> {target}", styles['Normal']))
        elements.append(Paragraph(f"<b>DATA:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles['Normal']))
        elements.append(Spacer(1, 12))
        
        elements.append(Paragraph("1. Inteligência Web", styles['Heading2']))
        for f in web_intel['files']: elements.append(Paragraph(f"• {f}", styles['Normal']))
        for c in web_intel['cookies']: elements.append(Paragraph(f"• {c}", styles['Normal']))
        
        elements.append(PageBreak())
        elements.append(Paragraph("2. Auditoria de Rede (Nmap)", styles['Heading2']))
        nmap_style = ParagraphStyle('Mono', fontName='Courier', fontSize=8)
        for line in nmap_data.split('\n'):
            elements.append(Paragraph(line.replace(' ', '&nbsp;'), nmap_style))
        
        doc.build(elements)
        return path
    except Exception as e:
        print(f"{R}[!] Erro ao gerar PDF: {e}{E}")
        return None

# -------------------- MAIN --------------------

def main():
    os.system('clear')
    print(f"{C}{B}🛡️ SOC-ARX V7.6 - ARMOR & LAB EDITION{E}")
    auto_installer()
    
    my_ip, vpn_status = check_vpn()
    print(f"{B}Sua Conexão: {my_ip} | Status: {vpn_status}{E}\n")

    print(f"{B}ESCOLHA UM LABORATÓRIO:{E}")
    for k, v in LABS.items():
        print(f"{G}{k}. {v[0]} ({v[1]}){E}")
    
    choice = input(f"\n{B}❯ SELEÇÃO: {E}").strip()
    target = LABS[choice][1] if choice in LABS else input(f"{B}❯ TARGET: {E}").strip()
    
    if not target: return

    web_intel = analyze_web_intelligence(f"http://{target}")
    nmap_res = run_nmap_scan(target)
    
    print(f"\n{B}RELATÓRIO PRONTO!{E}")
    path = export_pdf(target, nmap_res, web_intel)
    
    if path:
        print(f"\n{G}[✔] PDF SALVO EM: {path}{E}\n")
    else:
        print(f"\n{Y}[!] O PDF não pôde ser criado. Verifique as permissões.{E}\n")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nEncerrado.")
