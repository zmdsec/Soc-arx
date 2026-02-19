import socket
import json
import os
import requests
import ssl
import uuid
import urllib3
import threading
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER

# -------------------- CONFIGURAÇÕES GLOBAIS & SILENCIADOR --------------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443, 9000]
PORT_SERVICES = {
    21: "FTP (File Transfer)", 22: "SSH (Secure Shell)", 23: "Telnet (Insecure)",
    25: "SMTP (Mail)", 53: "DNS", 80: "HTTP (Web)", 110: "POP3 (Mail)",
    143: "IMAP (Mail)", 443: "HTTPS (Secure Web)", 445: "SMB (Windows)",
    3306: "MySQL (Database)", 3389: "RDP (Remote Desktop)", 5432: "PostgreSQL",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT", 9000: "Portainer/FastCGI"
}

SENSITIVE_PATHS = [
    "/admin", "/login", "/wp-admin", "/phpmyadmin", "/dashboard", "/.env", 
    "/.git", "/config.php", "/backup", "/v1/api", "/robots.txt", "/server-status",
    "/contato", "/api/users", "/LICENSE", "/README.md", "/.ssh", "/docker-compose.yml"
]

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"]
DOWNLOAD_DIR = "/storage/emulated/0/Download/Soc-Arx"
SQLI_TESTS = [
    "'", '"', "' OR 1=1 -- ", '" OR "1"="1', "admin' --", "') OR ('1'='1",
    "'; WAITFOR DELAY '0:0:5'--", "') OR SLEEP(5) AND ('1'='1"
]
SUBDOMAINS_LIST = [
    "www", "mail", "dev", "test", "api", "admin", "vpn", "ssh", "staging", 
    "mysql", "support", "webmail", "shop", "blog", "portal", "cloud"
]

RECOMENDACOES = {
    21: "FTP é obsoleto e envia dados em texto claro. Substitua por SFTP na porta 22.",
    23: "TELNET É CRÍTICO! Credenciais são capturadas facilmente. Desative e use SSH.",
    25: "SMTP pode ser usado para Relay de SPAM se não houver autenticação SPF/DKIM.",
    80: "HTTP detectado. O tráfego não é criptografado. Instale SSL e use HSTS.",
    445: "SMB exposto é a porta de entrada para Ransomwares como WannaCry. Bloqueie via Firewall.",
    3306: "BANCO DE DADOS EXPOSTO! MySQL deve ouvir apenas em 127.0.0.1 ou via VPN.",
    3389: "RDP exposto é vulnerável a BlueKeep e Brute Force. Use Gateway ou VPN.",
    "SQLi": "Vulnerabilidade Crítica de Injeção SQL. Use Parameterized Queries (PDO/Prepared Statements).",
    "Headers": "Headers de Segurança Ausentes: Implemente Content-Security-Policy e X-Frame-Options.",
    "Paths": "Diretório Sensível Exposto: Remova arquivos .env/.git e proteja o acesso administrativo.",
    "SSL": "Certificado SSL com problema. Isso afeta o SEO e a confiança do usuário final."
}

# -------------------- MÓDULOS DE RECONHECIMENTO AVANÇADO --------------------

def verificar_ssl(dominio):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((dominio, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
                expiracao = cert.get('notAfter')
                emissor = dict(x[0] for x in cert.get('issuer'))
                return {
                    "status": "Válido/Seguro",
                    "expira": expiracao,
                    "emissor": emissor.get('organizationName', 'Desconhecido')
                }
    except Exception as e:
        return {"status": "Inexistente ou Erro de Cadeia", "detalhe": str(e)}

def detectar_tecnologias(url):
    print(f"[*] Executando Fingerprinting: {url}")
    techs = []
    try:
        r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        h = r.headers
        # Analise de Headers
        if 'Server' in h: techs.append(f"Servidor: {h['Server']}")
        if 'X-Powered-By' in h: techs.append(f"Framework: {h['X-Powered-By']}")
        if 'X-AspNet-Version' in h: techs.append("Tecnologia: ASP.NET")
        # Analise de Corpo
        corpo = r.text.lower()
        if "wp-content" in corpo: techs.append("CMS: WordPress")
        if "drupal" in corpo: techs.append("CMS: Drupal")
        if "jquery" in corpo: techs.append("Lib: jQuery")
        if "react" in corpo: techs.append("Lib: React")
    except: pass
    return list(set(techs))

# -------------------- LÓGICA DE INFRAESTRUTURA --------------------

def ping_host(ip):
    try:
        socket.setdefaulttimeout(2)
        socket.gethostbyname(ip)
        return True
    except: return False

def scan_subdominios(dominio):
    print(f"[*] Iniciando Enumeração de DNS (Proteção contra Wildcard)...")
    encontrados = []
    # Teste de Wildcard (DNS Mentiroso)
    try:
        fake_sub = f"soc-arx-{uuid.uuid4().hex[:6]}.{dominio}"
        ip_falso = socket.gethostbyname(fake_sub)
        print(f"[!] Alerta: Wildcard DNS detectado em {ip_falso}")
    except:
        ip_falso = None

    for sub in SUBDOMAINS_LIST:
        alvo_sub = f"{sub}.{dominio}"
        try:
            ip_real = socket.gethostbyname(alvo_sub)
            if ip_real != ip_falso:
                encontrados.append({"host": alvo_sub, "ip": ip_real})
                print(f"  [+] Subdomínio Ativo: {alvo_sub}")
        except: continue
    return encontrados

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))
        if port in [80, 8080, 443]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner if banner else "Sem resposta no Banner"
    except: return "Conexão rejeitada"

# -------------------- AUDITORIA WEB (ANTI-FALSO POSITIVO) --------------------

def enumerar_diretorios(url):
    achados = []
    # Detecta o tamanho de uma página 404 real para evitar falsos 200
    try:
        teste_404 = requests.get(url + "/pagina_inexistente_arx_audit", timeout=3, verify=False)
        tamanho_404 = len(teste_404.content)
    except: tamanho_404 = 0

    for path in SENSITIVE_PATHS:
        try:
            r = requests.get(url + path, timeout=2, verify=False, allow_redirects=False)
            # Regra: Código 200 E tamanho diferente do 404 conhecido
            if r.status_code == 200:
                if abs(len(r.content) - tamanho_404) > 200:
                    achados.append(f"{path} (STATUS: 200 OK)")
            elif r.status_code in [301, 302]:
                achados.append(f"{path} (REDIRECT: {r.headers.get('Location')})")
            elif r.status_code == 403:
                achados.append(f"{path} (FORBIDDEN)")
        except: continue
    return achados

def verificar_metodos_http(url):
    ativos = []
    for m in DANGEROUS_METHODS:
        try:
            r = requests.request(m, url, timeout=2, verify=False)
            if r.status_code not in [405, 404]:
                ativos.append(m)
        except: pass
    return ativos

def scan_host_completo(ip):
    print(f"[*] Escaneando portas e analisando serviços em {ip}...")
    resultados = []
    for port in COMMON_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.7)
        if s.connect_ex((ip, port)) == 0:
            serv = PORT_SERVICES.get(port, f"Desconhecido ({port})")
            banner = grab_banner(ip, port)
            registro = {"porta": port, "servico": serv, "banner": banner}
            
            if port in [80, 8080, 443]:
                url = f"{'https' if port == 443 else 'http'}://{ip}"
                # Cabeçalhos de Segurança
                try:
                    r = requests.get(url, timeout=3, verify=False)
                    h = r.headers
                    registro["headers_ausentes"] = [header for header in ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options", "Strict-Transport-Security"] if header not in h]
                    registro["metodos_perigosos"] = verificar_metodos_http(url)
                    registro["diretorios"] = enumerar_diretorios(url)
                except: pass
            resultados.append(registro)
        s.close()
    return resultados

# -------------------- VULNERABILIDADES DE APLICAÇÃO (SQLi) --------------------

def scan_sqli(url_completa):
    if "http" not in url_completa: return []
    print(f"[*] Testando vulnerabilidades de injeção em {url_completa}...")
    vulneraveis = []
    parsed = urlparse(url_completa)
    if not parsed.query: return []
    
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = parsed.query.split("&")
    
    for p in params:
        key = p.split("=")[0]
        for payload in SQLI_TESTS:
            test_url = f"{base}?{key}={payload}"
            try:
                start_time = time.time()
                r = requests.get(test_url, timeout=7)
                duration = time.time() - start_time
                
                # Erros Baseados em Booleano/Erro
                if any(err in r.text.lower() for err in ["sql syntax", "mysql_fetch", "sqlite3", "pg_query", "oracle error"]):
                    vulneraveis.append(f"Parâmetro '{key}' vulnerável (Payload: {payload})")
                    break
                # Erros Baseados em Tempo (Time-Based)
                if duration > 4.5 and payload in ["'; WAITFOR DELAY '0:0:5'--", "') OR SLEEP(5) AND ('1'='1"]:
                    vulneraveis.append(f"Parâmetro '{key}' suspeito de Time-Based SQLi")
                    break
            except: continue
    return vulneraveis

# -------------------- GERAÇÃO DE RELATÓRIO PDF PREMIUM --------------------

def gerar_pdf_pro(ip, resultados, sqli, subs, ssl_data, techs):
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%d%m%Y_%H%M")
    nome_arquivo = f"{DOWNLOAD_DIR}/SOC_ARX_AUDIT_{ip}_{timestamp}.pdf"
    
    doc = SimpleDocTemplate(nome_arquivo, pagesize=A4)
    estilos = getSampleStyleSheet()
    elementos = []

    # Estilos Customizados
    estilos.add(ParagraphStyle(name='Centralizado', alignment=TA_CENTER, fontSize=18, spaceAfter=20, textColor=colors.darkblue))
    estilos.add(ParagraphStyle(name='Alerta', fontSize=10, textColor=colors.red, spaceAfter=5))

    # Capa
    elementos.append(Paragraph("🛡️ SOC-ARX PROFESSIONAL V3.0", estilos["Centralizado"]))
    elementos.append(Paragraph("RELATÓRIO DE INTELIGÊNCIA E AUDITORIA DE REDE", estilos["Heading2"]))
    elementos.append(Spacer(1, 20))

    # Resumo Executivo (Cálculo de Score)
    score_inicial = 100
    if sqli: score_inicial -= 50
    score_inicial -= (len(resultados) * 5)
    score_final = max(0, score_inicial)
    risco = "CRÍTICO" if score_final < 40 else "MÉDIO" if score_final < 75 else "BAIXO"

    data_resumo = [
        ['Métrica de Avaliação', 'Resultado do Ativo'],
        ['Endereço IP / Host', ip],
        ['Certificado SSL', ssl_data['status']],
        ['Emissor SSL', ssl_data.get('emissor', 'N/A')],
        ['Risco Geral', risco],
        ['Pontuação de Segurança', f"{score_final}/100"]
    ]
    
    t_res = Table(data_resumo, colWidths=[180, 240])
    t_res.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('BACKGROUND', (1,4), (1,4), colors.red if risco == "CRÍTICO" else colors.green),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold')
    ]))
    elementos.append(t_res)
    elementos.append(Spacer(1, 25))

    # Tecnologias & DNS
    if techs:
        elementos.append(Paragraph("<b>📊 Fingerprinting de Infraestrutura:</b>", estilos["Heading2"]))
        for t in techs: elementos.append(Paragraph(f"• {t}", estilos["Normal"]))
        elementos.append(Spacer(1, 15))

    if subs:
        elementos.append(Paragraph("<b>🌐 Mapeamento de Ativos (Subdomínios):</b>", estilos["Heading2"]))
        for s in subs: elementos.append(Paragraph(f"• {s['host']} -> {s['ip']}", estilos["Normal"]))
        elementos.append(Spacer(1, 15))

    # Portas e Serviços
    elementos.append(PageBreak())
    elementos.append(Paragraph("<b>🔍 Detalhamento de Portas e Vulnerabilidades:</b>", estilos["Heading2"]))
    
    for r in resultados:
        elementos.append(Paragraph(f"Porta {r['porta']} - {r['servico']}", estilos["Heading3"]))
        elementos.append(Paragraph(f"Banner: {r['banner'][:100]}", estilos["Normal"]))
        
        # Recomendações Automáticas
        rec = RECOMENDACOES.get(r['porta'], "Nenhuma falha crítica imediata detectada nesta porta.")
        elementos.append(Paragraph(f"<i>Recomendação SOC: {rec}</i>", estilos["Normal"]))
        
        if r.get('diretorios'):
            elementos.append(Paragraph("<b>Diretórios Sensíveis Identificados:</b>", estilos["Alerta"]))
            for d in r['diretorios']: elementos.append(Paragraph(f"  - {d}", estilos["Normal"]))
        
        if r.get('headers_ausentes'):
            elementos.append(Paragraph(f"<b>Headers de Segurança Ausentes:</b> {', '.join(r['headers_ausentes'])}", estilos["Normal"]))
        
        elementos.append(Spacer(1, 10))

    if sqli:
        elementos.append(Paragraph("<b>⚠️ VULNERABILIDADES DE INJEÇÃO SQL:</b>", estilos["Heading2"]))
        for s in sqli: elementos.append(Paragraph(f"• {s}", estilos["Alerta"]))

    doc.build(elementos)
    print(f"\n[SUCCESS] Relatório Profissional Gerado: {nome_arquivo}")

# -------------------- EXECUÇÃO PRINCIPAL --------------------

if __name__ == "__main__":
    print("""
    #######################################################
    #            SOC-ARX AUDITOR V3.0 - RELOADED          #
    #      Monitoramento e Auditoria Profissional         #
    #######################################################
    """)
    
    alvo_raw = input("Digite o Alvo para Auditoria (IP ou URL): ").strip()
    # Limpa a URL para pegar apenas o domínio
    dominio = alvo_raw.replace("http://", "").replace("https://", "").split('/')[0]

    if not ping_host(dominio):
        print("[!] Erro: Alvo offline ou DNS não resolvido. Abortando..."); exit()

    print(f"[*] Alvo {dominio} está online. Iniciando coleta...")
    
    # Processamento em Fluxo
    sub_encontrados = scan_subdominios(dominio) if "." in dominio else []
    ssl_info = verificar_ssl(dominio) if "." in dominio else {"status": "N/A"}
    tech_info = detectar_tecnologias(f"http://{dominio}")
    res_portas = scan_host_completo(dominio)
    res_sqli = scan_sqli(alvo_raw)

    # Gerar Relatório
    gerar_pdf_pro(dominio, res_portas, res_sqli, sub_encontrados, ssl_info, tech_info)
    
    print("\n✅ Auditoria Completa. O arquivo PDF está na pasta de Downloads.")
