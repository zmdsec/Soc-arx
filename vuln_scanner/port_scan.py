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

DOWNLOAD_PATH = "/sdcard/Download/Soc-Arx"
if not os.path.exists(DOWNLOAD_PATH): os.makedirs(DOWNLOAD_PATH, exist_ok=True)

# Lista expandida para caçar backups (Foco no TestPHP e Altoro)
SENSITIVE_FILES = [
    "/robots.txt", "/.env", "/admin/", "/api/v1/users", 
    "/config.php", "/db.sql", "/backup.sql", "/setup.sql", 
    "/.git/", "/phpinfo.php", "/index.php.bak", "/.sql"
]

LABS = {
    "1": ("OWASP Juice Shop", "juice-shop.herokuapp.com"),
    "2": ("Altoro Mutual (Banco)", "demo.testfire.net"),
    "3": ("Test PHP (VulnWeb)", "testphp.vulnweb.com"),
    "4": ("IP Camera (IP Público)", "200.x.x.x") # Exemplo para seu estudo
}

# -------------------- MOTOR TÉCNICO --------------------

def auto_installer():
    """Garante que o ambiente tenha as ferramentas necessárias"""
    tools = ["nmap", "whatweb"]
    for tool in tools:
        if subprocess.getstatusoutput(f"command -v {tool}")[0] != 0:
            print(f"{Y}[!] Ferramenta {tool} não encontrada. Instalando...{E}")
            os.system(f"pkg install {tool} -y")

def check_vpn():
    """Verifica se o usuário está em uma VPN"""
    try:
        r = requests.get("https://ipapi.co/json/", timeout=5).json()
        org = r.get("org", "").lower()
        is_vpn = any(v in org for v in ["nord", "proton", "express", "surfshark", "google", "cloud"])
        status = f"{G}PROTEGIDA ({org}){E}" if is_vpn else f"{R}EXPOSTA (Cuidado!){E}"
        return r.get('ip'), status
    except: return "Erro", "Desconhecido"

def get_telnet_banner(target):
    """Tenta capturar o banner da porta 23 se aberta"""
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, 23))
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner if banner else "Porta 23 aberta (Sem banner)"
    except: return None

def analyze_web_intelligence(url):
    results = {"cookies": [], "files": [], "tech": "Oculta", "cloud": "Verificando...", "telnet": None}
    headers = {'User-Agent': 'Mozilla/5.0 SOC-ARX-V7.5'}
    
    try:
        domain = urlparse(url).netloc
        # Detecção de Cloud e Telnet
        try:
            ip = socket.gethostbyname(domain)
            results['telnet'] = get_telnet_banner(ip)
            hostname = socket.gethostbyaddr(ip)[0]
            if "amazonaws" in hostname: results['cloud'] = "Amazon AWS"
            elif "heroku" in hostname: results['cloud'] = "Heroku Cloud"
            else: results['cloud'] = f"Independente ({hostname})"
        except: results['cloud'] = "Não identificado"

        # WhatWeb Intelligence
        try:
            results['tech'] = subprocess.check_output(["whatweb", "--color=never", url]).decode().strip()
        except:
            results['tech'] = "WhatWeb falhou."

        session = requests.Session()
        r = session.get(url, timeout=5, verify=False, headers=headers)
        
        # Auditoria de Cookies
        if session.cookies:
            for cookie in session.cookies:
                flags = []
                if not cookie.has_nonstandard_attr('HttpOnly'): flags.append("Sem HttpOnly")
                if not cookie.secure: flags.append("Sem Secure")
                results['cookies'].append(f"{cookie.name}: {'Seguro' if not flags else ' | '.join(flags)}")

        # Path Discovery (Backup Hunter)
        for path in SENSITIVE_FILES:
            test_url = urljoin(url, path)
            try:
                res = session.get(test_url, timeout=2, verify=False, headers=headers)
                if res.status_code == 200:
                    results['files'].append(f"{path} (ACHADO CRÍTICO)")
                elif res.status_code == 403:
                    results['files'].append(f"{path} (Protegido)")
            except: continue
    except Exception as e:
        results['tech'] = f"Erro na análise: {str(e)}"
    return results

def run_nmap_scan(target):
    print(f"\n{B}{Y}[NMAP] Iniciando varredura profunda...{E}")
    try:
        # -Pn para ignorar bloqueio de ping (comum em câmeras IP)
        cmd = ["nmap", "-sV", "-T4", "-F", "-Pn", target]
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
    except: return "Nmap falhou."

# -------------------- RELATÓRIO PDF --------------------

def export_pdf(target, nmap_data, web_intel):
    if not PDF_OK: return
    path = f"{DOWNLOAD_PATH}/SOC_V75_{target.replace('.', '_')}.pdf"
    doc = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()
    
    elements = []
    elements.append(Paragraph(f"🛡️ SOC-ARX V7.5 ARMOR REPORT", styles['Heading1']))
    elements.append(Paragraph(f"<b>ALVO:</b> {target} | <b>DATA:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles['Normal']))
    
    elements.append(Spacer(1, 15))
    elements.append(Paragraph("1. Inteligência de Infraestrutura", styles['Heading2']))
    elements.append(Paragraph(f"<b>Cloud:</b> {web_intel['cloud']}", styles['Normal']))
    if web_intel['telnet']:
        elements.append(Paragraph(f"<b>ALERTA TELNET (23):</b> {web_intel['telnet']}", styles['Normal']))
    
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("2. Auditoria Web & Backups", styles['Heading2']))
    elements.append(Paragraph(f"<b>Tecnologias:</b> {web_intel['tech']}", styles['Normal']))
    
    for f in web_intel['files']: elements.append(Paragraph(f"• {f}", styles['Normal']))
    for c in web_intel['cookies']: elements.append(Paragraph(f"• {c}", styles['Normal']))

    elements.append(PageBreak())
    elements.append(Paragraph("3. Diagnóstico de Rede (Nmap)", styles['Heading2']))
    nmap_style = ParagraphStyle('Mono', fontName='Courier', fontSize=7, leading=9)
    for line in nmap_data.split('\n'):
        elements.append(Paragraph(line.replace(' ', '&nbsp;'), nmap_style))

    doc.build(elements)
    return path

# -------------------- MAIN --------------------

def main():
    os.system('clear')
    print(f"{C}{B}🛡️ SOC-ARX V7.5 - ARMOR & LAB EDITION{E}")
    auto_installer()
    
    my_ip, vpn_status = check_vpn()
    print(f"{B}Sua Conexão: {my_ip} | Status: {vpn_status}{E}\n")

    print(f"{B}ESCOLHA UM ALVO OU DIGITE UM NOVO:{E}")
    for k, v in LABS.items():
        print(f"{G}{k}. {v[0]} ({v[1]}){E}")
    
    choice = input(f"\n{B}❯ SELEÇÃO (ou Enter para manual): {E}").strip()
    target = LABS[choice][1] if choice in LABS else input(f"{B}❯ TARGET_ID: {E}").strip()
    
    if not target: return

    print(f"\n{C}[*] Iniciando motor de inteligência...{E}")
    web_intel = analyze_web_intelligence(f"http://{target}")
    
    nmap_res = run_nmap_scan(target)
    
    print(f"\n{B}{'='*50}\nRESUMO TÁTICO: {target}\n{'='*50}{E}")
    if web_intel['telnet']: print(f"{R}[!] ALERTA: Porta Telnet aberta!{E}")
    print(f"{B}Arquivos/Backups encontrados:{E} {len(web_intel['files'])}")
    
    path = export_pdf(target, nmap_res, web_intel)
    print(f"\n{G}[✔] RELATÓRIO PDF GERADO EM: {path}{E}\n")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nEncerrado.")
