import socket, os, requests, ssl, subprocess, urllib3, time, sys, random, re
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import List, Dict

# --- SUPORTE A PDF (Recuperado) ---
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

# Caminho de download com plano B
DOWNLOAD_PATH = "/sdcard/Download/Soc-Arx"
try:
    if not os.path.exists(DOWNLOAD_PATH): 
        os.makedirs(DOWNLOAD_PATH, exist_ok=True)
except:
    DOWNLOAD_PATH = os.getcwd()

# Lista Mestra de Arquivos (PHP + ASP.NET + Configs)
SENSITIVE_FILES = [
    "/robots.txt", "/.env", "/admin/", "/config.php", "/web.config", 
    "/login.aspx", "/trace.axd", "/elmah.axd", "/.git/", "/phpinfo.php",
    "/index.php.bak", "/credentials.txt", "/db_backup.sql", "/bin/", 
    "/App_Data/", "/Global.asax"
]

LABS = {
    "1": ("OWASP Juice Shop", "demo.owasp-juiceshop.org"),
    "2": ("Altoro Mutual (Banco)", "demo.testfire.net"),
    "3": ("Test PHP (VulnWeb)", "testphp.vulnweb.com"),
    "4": ("Test ASP.NET (Windows)", "testaspnet.vulnweb.com")
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1)"
]

# -------------------- MOTOR TÉCNICO --------------------

def auto_installer():
    tools = ["nmap", "whatweb"]
    for tool in tools:
        if subprocess.getstatusoutput(f"command -v {tool}")[0] != 0:
            print(f"{Y}[!] Instalando {tool}...{E}")
            os.system(f"pkg install {tool} -y")

def check_vpn():
    try:
        ip = requests.get("https://api64.ipify.org", timeout=5).text
        status = f"{G}PROTEGIDA (IPv6/VPN){E}" if ":" in ip else f"{Y}IPv4 (CUIDADO - IP EXPOSTO){E}"
        return ip, status
    except:
        return "Detectado", f"{Y}ERRO DE CONEXÃO{E}"

def get_telnet_banner(target):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, 23))
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner if banner else "Porta 23 aberta (Sem banner)"
    except: return None

def get_asp_tokens(html):
    """Extrai os tokens do site difícil (ViewState/EventValidation)"""
    tokens = {}
    try:
        for field in ["__VIEWSTATE", "__EVENTVALIDATION", "__VIEWSTATEGENERATOR"]:
            match = re.search(f'id="{field}" value="(.*?)"', html)
            if match: tokens[field] = match.group(1)
    except: pass
    return tokens

def analyze_web_intelligence(url):
    results = {"cookies": [], "files": [], "tech": "Oculta", "asp_tokens": {}, "vulnerabilities": [], "telnet": None}
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    
    try:
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)
        results['telnet'] = get_telnet_banner(ip)
        
        session = requests.Session()
        r = session.get(url, timeout=5, verify=False, headers=headers)
        
        # O que aprendemos no TestASP: Captura de Versão e Tokens
        if "X-AspNet-Version" in r.headers:
            results['tech'] = f"ASP.NET {r.headers['X-AspNet-Version']}"
        elif "Server" in r.headers:
            results['tech'] = r.headers['Server']

        results['asp_tokens'] = get_asp_tokens(r.text)
        
        if "admin" in r.text.lower():
            results['vulnerabilities'].append("Palavra 'admin' no código (Vazamento de Informação)")

        # Scan de arquivos sensíveis
        for path in SENSITIVE_FILES:
            test_url = urljoin(url, path)
            try:
                res = session.get(test_url, timeout=2, verify=False, headers=headers)
                if res.status_code == 200:
                    results['files'].append(f"{path} (ACHADO CRÍTICO)")
                elif res.status_code == 500:
                    results['vulnerabilities'].append(f"Erro 500 em {path} (Possível falha de configuração .NET)")
            except: continue

        # Busca cookies inseguros
        if session.cookies:
            for cookie in session.cookies:
                if not cookie.secure: results['cookies'].append(f"{cookie.name} (Sem Secure Flag)")

    except Exception as e: results['tech'] = f"Erro: {str(e)}"
    return results

def xpl_suggester(intel):
    """Módulo de Dicas baseado no sucesso de hoje"""
    print(f"\n{B}{C}🛠️ ESTRATÉGIA DE ATAQUE SUGERIDA:{E}")
    if intel['asp_tokens'] or "ASP.NET" in intel['tech']:
        print(f"{R}[!] ALVO WINDOWS/IIS DETECTADO{E}")
        print(f"{Y} ❯ Use Bypass SQL: admin'--{E}")
        print(f"{Y} ❯ Payload de Tempo: admin' WAITFOR DELAY '0:0:5'--{E}")
        print(f"{Y} ❯ Bloqueio XSS detectado! Tente ofuscação com tags <img> ou <svg>.{E}")
    else:
        print(f"{G} ❯ Alvo padrão. Tente ' OR 1=1# ou injeções baseadas em Union.{E}")

def run_nmap_scan(target):
    print(f"\n{B}{Y}[NMAP] Auditando Infraestrutura...{E}")
    try:
        cmd = ["nmap", "-sV", "-T4", "-F", "-Pn", target]
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
    except: return "Nmap falhou ou não instalado."

# -------------------- RELATÓRIO PDF (Completo) --------------------

def export_pdf(target, nmap_data, web_intel):
    if not PDF_OK: return None
    filename = f"SOC_V9_{target.replace('.', '_')}.pdf"
    path = os.path.join(DOWNLOAD_PATH, filename)
    try:
        doc = SimpleDocTemplate(path, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []
        elements.append(Paragraph(f"🛡️ SOC-ARX V9.0 - AUDIT REPORT", styles['Heading1']))
        elements.append(Paragraph(f"<b>ALVO:</b> {target} | <b>DATA:</b> {datetime.now()}", styles['Normal']))
        elements.append(Spacer(1, 12))
        
        elements.append(Paragraph("1. Inteligência de Aplicação", styles['Heading2']))
        elements.append(Paragraph(f"<b>Tecnologia:</b> {web_intel['tech']}", styles['Normal']))
        for v in web_intel['vulnerabilities']: elements.append(Paragraph(f"• [!] {v}", styles['Normal']))
        for f in web_intel['files']: elements.append(Paragraph(f"• [+] {f}", styles['Normal']))
        
        elements.append(Paragraph("2. Auditoria de Rede", styles['Heading2']))
        nmap_style = ParagraphStyle('Mono', fontName='Courier', fontSize=7)
        for line in nmap_data.split('\n'):
            elements.append(Paragraph(line.replace(' ', '&nbsp;'), nmap_style))
            
        doc.build(elements)
        return path
    except: return None

# -------------------- MAIN --------------------

def main():
    os.system('clear')
    print(f"{C}{B}🛡️ SOC-ARX V9.0 - PERSISTENCE & REPORT EDITION{E}")
    auto_installer()
    
    my_ip, vpn_status = check_vpn()
    print(f"{B}Sua Conexão: {my_ip} | Status: {vpn_status}{E}\n")

    print(f"{B}SELECIONE O LABORATÓRIO:{E}")
    for k, v in LABS.items(): print(f"{G}{k}. {v[0]}{E}")
    
    choice = input(f"\n{B}❯ SELEÇÃO: {E}").strip()
    target = LABS[choice][1] if choice in LABS else input(f"{B}❯ TARGET: {E}").strip()
    
    if not target: return

    intel = analyze_web_intelligence(f"http://{target}")
    nmap_res = run_nmap_scan(target)
    
    # Interface de Saída
    print(f"\n{B}{'='*50}\nRELATÓRIO DE VARREDURA SOC-ARX\n{'='*50}{E}")
    print(f"{C}Tecnologia Detectada: {intel['tech']}{E}")
    if intel['telnet']: print(f"{Y}Banner Telnet: {intel['telnet']}{E}")
    
    xpl_suggester(intel)
    
    # Exportação
    pdf_path = export_pdf(target, nmap_res, intel)
    if pdf_path: print(f"\n{G}[✔] RELATÓRIO PDF GERADO: {pdf_path}{E}")
    
    os.system("history -c") # Limpeza Furtiva
    print(f"\n{G}[*] Processo finalizado com sucesso.{E}")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nEncerrado pelo usuário.")
