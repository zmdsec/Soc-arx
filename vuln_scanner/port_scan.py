import socket, os, requests, ssl, subprocess, urllib3, time, sys, random, re
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

# Caminho de download
DOWNLOAD_PATH = "/sdcard/Download/Soc-Arx"
try:
    if not os.path.exists(DOWNLOAD_PATH): 
        os.makedirs(DOWNLOAD_PATH, exist_ok=True)
except:
    DOWNLOAD_PATH = os.getcwd()

# Lista expandida com o aprendizado do site "Mega Difícil"
SENSITIVE_FILES = [
    "/robots.txt", "/.env", "/admin/", "/config.php", "/web.config", 
    "/login.aspx", "/trace.axd", "/elmah.axd", "/web.config.bak",
    "/bin/", "/App_Data/", "/Global.asax", "/.git/"
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

# -------------------- MOTOR TÉCNICO V9.0 --------------------

def get_asp_tokens(html):
    """Extrai tokens ocultos do ASP.NET que você viu no HTML bruto"""
    tokens = {}
    try:
        for field in ["__VIEWSTATE", "__EVENTVALIDATION", "__VIEWSTATEGENERATOR"]:
            match = re.search(f'id="{field}" value="(.*?)"', html)
            if match: tokens[field] = match.group(1)
    except: pass
    return tokens

def analyze_web_intelligence(url):
    results = {"cookies": [], "files": [], "tech": "Oculta", "asp_tokens": {}, "vulnerabilities": []}
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    
    try:
        session = requests.Session()
        r = session.get(url, timeout=5, verify=False, headers=headers)
        
        # Detecta versão do ASP.NET nos Headers
        if "X-AspNet-Version" in r.headers:
            results['tech'] = f"ASP.NET Versão: {r.headers['X-AspNet-Version']}"
        elif "Server" in r.headers:
            results['tech'] = r.headers['Server']
        
        # Pega os tokens que você analisou hoje
        results['asp_tokens'] = get_asp_tokens(r.text)
        
        # Procura por vazamento de 'admin' no código
        if "admin" in r.text.lower():
            results['vulnerabilities'].append("Palavra 'admin' encontrada no HTML (Possível User Enumeration)")

        for path in SENSITIVE_FILES:
            test_url = urljoin(url, path)
            try:
                res = session.get(test_url, timeout=2, verify=False, headers=headers)
                if res.status_code == 200:
                    results['files'].append(f"{path} (ACHADO CRÍTICO)")
                elif res.status_code == 500:
                    results['vulnerabilities'].append(f"Erro 500 em {path} (Pode ser .NET mal configurado)")
            except: continue
    except Exception as e:
        results['tech'] = f"Erro de conexão: {str(e)}"
    return results

def xpl_suggester(intel):
    """Sugestão baseada na sua vitória contra o servidor difícil"""
    print(f"\n{B}{C}🛠️ ESTRATÉGIA RECOMENDADA:{E}")
    if intel['asp_tokens'] or "ASP.NET" in intel['tech']:
        print(f"{R}[!] SERVIDOR MICROSOFT DETECTADO!{E}")
        print(f"{Y} ❯ Use o bypass: admin'--{E}")
        print(f"{Y} ❯ Cuidado com o filtro: O servidor bloqueia <script> e <img>{E}")
    else:
        print(f"{G} ❯ Servidor padrão. Testar payloads clássicos de SQLi.{E}")

def run_nmap_scan(target):
    print(f"\n{B}{Y}[NMAP] Iniciando auditoria de infraestrutura...{E}")
    try:
        # Scan rápido para não ser bloqueado
        return subprocess.check_output(["nmap", "-sV", "-F", "-Pn", target]).decode()
    except:
        return "Nmap não disponível no Termux. Instale com: pkg install nmap"

def main():
    os.system('clear')
    print(f"{C}{B}🛡️ SOC-ARX V9.0 - PERSISTENCE EDITION{E}")
    print(f"{Y}Baseado no sucesso contra infraestrutura legada Microsoft{E}\n")

    print(f"{B}SELECIONE O LABORATÓRIO:{E}")
    for k, v in LABS.items():
        print(f"{G}{k}. {v[0]} ({v[1]}){E}")
    
    choice = input(f"\n{B}❯ SELEÇÃO: {E}").strip()
    target = LABS[choice][1] if choice in LABS else input(f"{B}❯ TARGET: {E}").strip()
    
    if not target: return

    intel = analyze_web_intelligence(f"http://{target}")
    nmap_res = run_nmap_scan(target)
    
    print(f"\n{B}--- RESULTADOS DO SCAN ---{E}")
    print(f"{C}TECNOLOGIA: {intel['tech']}{E}")
    
    if intel['vulnerabilities']:
        print(f"\n{R}[!] VULNERABILIDADES POTENCIAIS:{E}")
        for v in intel['vulnerabilities']: print(f"  ❯ {v}")

    if intel['files']:
        print(f"\n{G}[+] ARQUIVOS ENCONTRADOS:{E}")
        for f in intel['files']: print(f"  ❯ {f}")

    xpl_suggester(intel)

    # Limpeza de rastros
    os.system("history -c")
    print(f"\n{G}[✔] Scan completo e histórico limpo.{E}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrompido.")
