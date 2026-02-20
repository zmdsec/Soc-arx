import socket, os, requests, ssl, subprocess, urllib3, time, sys, random, re, threading
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import List, Dict

# --- SUPORTE A RELATÓRIOS PROFISSIONAIS ---
try:
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    PDF_OK = True
except ImportError:
    PDF_OK = False

# Desabilita avisos de segurança para ambientes de teste
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- SISTEMA DE CORES SOC-ARX ---
G, Y, R, C, B, E = '\033[92m', '\033[93m', '\033[91m', '\033[96m', '\033[1m', '\033[0m'

# --- CONFIGURAÇÃO DE DIRETÓRIOS ---
DOWNLOAD_PATH = "/sdcard/Download/Soc-Arx_Supreme"
if not os.path.exists(DOWNLOAD_PATH):
    try: os.makedirs(DOWNLOAD_PATH, exist_ok=True)
    except: DOWNLOAD_PATH = os.getcwd()

# --- WORDLIST SUPREMA DE RECONHECIMENTO ---
# Lista exaustiva para não deixar passar nada (Web e Servidor)
ULTIMATE_WORDLIST = [
    "/robots.txt", "/.env", "/admin/", "/config.php", "/web.config", 
    "/login.aspx", "/trace.axd", "/elmah.axd", "/.git/config", "/phpinfo.php",
    "/index.php.bak", "/credentials.txt", "/db_backup.sql", "/bin/", 
    "/App_Data/", "/Global.asax", "/server-status", "/phpmyadmin/", 
    "/.ssh/id_rsa", "/.aws/credentials", "/wp-config.php", "/.htaccess",
    "/composer.json", "/package.json", "/Dockerfile", "/docker-compose.yml",
    "/api/v1/users", "/api/v2/config", "/backup.zip", "/setup.log",
    "/php.ini", "/mysql.log", "/access.log", "/error.log", "/.vscode/settings.json"
]

# -------------------- CLASSE SUPREMA DE SCANNER --------------------

class SOC_ARX_SUPREME:
    def __init__(self, target):
        self.target = target
        self.url = f"http://{target}" if not target.startswith("http") else target
        self.domain = urlparse(self.url).netloc
        self.start_time = datetime.now()
        self.intel = {
            "server": "Desconhecido",
            "headers": {},
            "ports": [],
            "files": [],
            "asp_tokens": {},
            "dns": {},
            "whois": "Simulado",
            "cookies": []
        }

    def log(self, msg, type="INFO"):
        prefix = f"{B}{C}[*]{E}" if type == "INFO" else f"{B}{G}[+]{E}"
        if type == "WARN": prefix = f"{B}{Y}[!]{E}"
        if type == "CRIT": prefix = f"{B}{R}[!!!]{E}"
        print(f"{prefix} {msg}")

    def setup_env(self):
        """Prepara o Termux com tudo que existe de melhor"""
        self.log("Verificando arsenal de ferramentas no Termux...")
        tools = ["nmap", "whatweb", "whois", "dnsutils"]
        for t in tools:
            if subprocess.getstatusoutput(f"command -v {t}")[0] != 0:
                self.log(f"Instalando {t}...", "WARN")
                os.system(f"pkg install {t} -y")

    def dns_recon(self):
        """Coleta informações de DNS do alvo"""
        self.log(f"Iniciando Reconhecimento DNS para {self.domain}")
        try:
            self.intel['dns']['IP'] = socket.gethostbyname(self.domain)
            # Simulação de coleta NS/MX (pode ser expandido com 'dig')
        except: self.intel['dns']['IP'] = "Não resolvido"

    def web_intelligence(self):
        """O cérebro do scanner: Analisa a fundo a aplicação web"""
        self.log("Iniciando Módulo de Inteligência Web...")
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Supreme-Scanner-V12)'})
        
        try:
            r = session.get(self.url, timeout=10, verify=False)
            self.intel['headers'] = dict(r.headers)
            self.intel['server'] = r.headers.get('Server', 'Oculto')

            # Analisa se é Microsoft (O que você aprendeu no TestASP)
            if "__VIEWSTATE" in r.text:
                self.log("Tecnologia ASP.NET Detectada!", "WARN")
                match = re.search(r'id="__VIEWSTATE" value="(.*?)"', r.text)
                if match: self.intel['asp_tokens']['VIEWSTATE'] = match.group(1)[:30] + "..."

            # Fuzzing de Diretórios (Busca por arquivos sensíveis)
            self.log("Iniciando Fuzzing de Diretórios (Wordlist Suprema)...")
            for path in ULTIMATE_WORDLIST:
                test_url = urljoin(self.url, path)
                try:
                    res = session.get(test_url, timeout=1.5)
                    if res.status_code == 200:
                        self.log(f"Achado Crítico: {path}", "SUCCESS")
                        self.intel['files'].append(f"{path} (200 OK)")
                    elif res.status_code == 403:
                        self.intel['files'].append(f"{path} (403 Proibido - Existe!)")
                except: continue

            # Análise de Cookies
            for cookie in session.cookies:
                self.intel['cookies'].append(f"{cookie.name} (Secure: {cookie.secure})")

        except Exception as e:
            self.log(f"Erro na análise web: {e}", "CRIT")

    def network_audit(self):
        """Varredura de rede profissional (Nmap Full)"""
        self.log("Iniciando Auditoria de Rede Profissional...")
        try:
            # -sV: Versões | -O: Sistema Operacional | -T4: Velocidade | -p-: Todas as portas
            # Para ser rápido no estudo, usaremos -F (portas comuns), mas mude para -p- para scan total.
            cmd = f"nmap -sV -Pn --open -T4 -F {self.domain}"
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, text=True)
            
            nmap_output = ""
            for line in process.stdout:
                if "open" in line:
                    self.log(f"Porta Aberta Detectada: {line.strip()}", "SUCCESS")
                nmap_output += line
            self.intel['ports'] = nmap_output
        except:
            self.intel['ports'] = "Nmap falhou durante a execução."

    def save_supreme_report(self):
        """Gera o documento final de estudo (PDF)"""
        if not PDF_OK: return "Reportlab não instalado."
        
        filename = f"SUPREME_SCAN_{self.domain.replace('.', '_')}.pdf"
        path = os.path.join(DOWNLOAD_PATH, filename)
        
        doc = SimpleDocTemplate(path, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []

        # Título
        elements.append(Paragraph("RELATÓRIO SUPREMO DE INTELIGÊNCIA SOC-ARX V12", styles['Heading1']))
        elements.append(Paragraph(f"<b>Alvo:</b> {self.domain} ({self.intel['dns'].get('IP')})", styles['Normal']))
        elements.append(Paragraph(f"<b>Duração:</b> {datetime.now() - self.start_time}", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Dados Web
        elements.append(Paragraph("1. Inteligência de Aplicação Web", styles['Heading2']))
        elements.append(Paragraph(f"<b>Servidor:</b> {self.intel['server']}", styles['Normal']))
        for f in self.intel['files']: elements.append(Paragraph(f"• {f}", styles['Normal']))
        
        # Dados de Rede
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("2. Auditoria de Rede e Serviços", styles['Heading2']))
        nmap_style = ParagraphStyle('Mono', fontName='Courier', fontSize=7)
        for line in self.intel['ports'].split('\n'):
            elements.append(Paragraph(line.replace(' ', '&nbsp;'), nmap_style))

        doc.build(elements)
        return path

# -------------------- EXECUÇÃO --------------------

def main():
    os.system('clear')
    print(f"{C}{B}🛡️ SOC-ARX V12 - SUPREME INFORMATION SCANNER{E}")
    print(f"{Y}O Scanner definitivo para o seu Plano de 5 Anos.{E}\n")

    target = input(f"{B}❯ Digite o Alvo (URL, IP ou Domínio): {E}").strip()
    if not target: return

    # Início do Ciclo de Inteligência
    scanner = SOC_ARX_SUPREME(target)
    scanner.setup_env()
    
    # Rodando módulos
    scanner.dns_recon()
    scanner.web_intelligence()
    scanner.network_audit()

    # Dicas de estudo baseadas no alvo
    print(f"\n{B}{C}🛠️ ANÁLISE DE VULNERABILIDADES POTENCIAIS:{E}")
    if "ASP.NET" in scanner.intel['server'] or scanner.intel['asp_tokens']:
        print(f"{R}[!] Alvo Microsoft detectado. Estudar: SQLi (Auth Bypass) e ViewState Deserialization.{E}")
    if any("admin" in f for f in scanner.intel['files']):
        print(f"{G}[+] Área administrativa encontrada. Estudar: Brute Force e Broken Authentication.{E}")

    # Finalização e PDF
    pdf_path = scanner.save_supreme_report()
    print(f"\n{G}{B}[✔] SCAN SUPREMO FINALIZADO!{E}")
    print(f"{C}Relatório Profissional: {pdf_path}{E}")
    
    os.system("history -c")

if __name__ == "__main__":
    main()
