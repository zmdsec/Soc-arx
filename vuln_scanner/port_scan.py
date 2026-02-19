import socket
import os
import requests
import ssl
import uuid
import urllib3
import time
import re
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Dict, Any

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False
    print("[AVISO] reportlab não encontrado → usando TXT como fallback")
    print("Instale com: pip install reportlab")

try:
    from termcolor import colored
    COLOR_AVAILABLE = True
except ImportError:
    COLOR_AVAILABLE = False
    def colored(text, color=None): return text

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ────────────────────────────────────────────────
# CONFIGURAÇÕES
# ────────────────────────────────────────────────

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443, 9000, 9200, 27017, 6379]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 8080: "HTTP-ALT", 8443: "HTTPS-ALT", 9000: "Portainer",
    9200: "Elasticsearch", 27017: "MongoDB", 6379: "Redis"
}

SENSITIVE_PATHS = [
    "/admin", "/login", "/wp-admin", "/phpmyadmin", "/dashboard", "/.env", "/.git",
    "/config.php", "/.aws/credentials", "/actuator", "/debug", "/swagger-ui.html",
    "/v3/api-docs", "/graphql", "/.htaccess", "/id_rsa", "/composer.json", "/backup.sql"
]

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH", "PROPFIND"]

SQLI_TESTS = [
    "'", '"', "' OR 1=1 -- ", "admin' --", "') OR ('1'='1",
    "'; WAITFOR DELAY '0:0:5'--", "') OR SLEEP(5)--",
    "1' UNION SELECT NULL,@@version--", "'; EXEC master..xp_cmdshell 'ping 127.0.0.1'--"
]

SUBDOMAINS_LIST = [
    "www", "mail", "dev", "test", "api", "admin", "staging", "beta", "app",
    "internal", "prod", "demo", "cdn", "auth", "portal", "cloud"
]

RECOMENDACOES = {
    21: "FTP inseguro → use SFTP (porta 22)",
    23: "TELNET → desative (credenciais em claro)",
    80: "HTTP → force HTTPS + HSTS",
    445: "SMB exposto → bloqueie (ransomware)",
    3306: "MySQL exposto → bind 127.0.0.1",
    3389: "RDP → use VPN/MFA",
    9200: "Elasticsearch aberto → restrinja acesso",
    27017: "MongoDB sem auth → ative autenticação",
    "SQLi": "Injeção SQL → use prepared statements",
    "CORS": "CORS vulnerável → restrinja origins",
    "Headers": "Faltam headers de segurança → CSP, HSTS, etc",
}

# Caminho corrigido (sem \ antes do \~)
DOWNLOAD_DIR = os.path.expanduser("\~/storage/shared/Download/Soc-Arx")

# ────────────────────────────────────────────────
# FUNÇÕES AUXILIARES
# ────────────────────────────────────────────────

def cprint(text: str, color: str = None):
    print(colored(text, color) if COLOR_AVAILABLE and color else text)

def garantir_diretorio():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    if not os.access(DOWNLOAD_DIR, os.W_OK):
        cprint(f"[ERRO] Sem permissão em {DOWNLOAD_DIR}", "red")
        cprint("Execute: termux-setup-storage e reabra o Termux", "yellow")
        exit(1)

def is_private_ip(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4: return False
    a, b, _, _ = map(int, parts)
    return (a == 10) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 127)

def clean_for_pdf(text: str, max_len: int = 150) -> str:
    text = re.sub(r'<[^>]+>', '', text)
    text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    text = ' '.join(text.split())
    return text[:max_len] + ("..." if len(text) > max_len else "")

def verificar_ssl(dominio: str) -> Dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((dominio, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
                return {
                    "status": "Válido",
                    "expira": cert.get('notAfter', 'N/A'),
                    "emissor": dict(x[0] for x in cert.get('issuer', [])).get('organizationName', 'N/A')
                }
    except Exception as e:
        return {"status": f"Erro / Ausente ({str(e)[:60]})"}

def detectar_tecnologias(url: str) -> List[str]:
    techs = set()
    try:
        r = requests.get(url, timeout=7, verify=False, allow_redirects=True)
        h = r.headers
        if 'Server' in h: techs.add(f"Server: {h['Server'][:50]}")
        if 'X-Powered-By' in h: techs.add(f"Powered-By: {h['X-Powered-By']}")
        body = r.text.lower()
        if "wp-content" in body: techs.add("WordPress")
        if "jquery" in body: techs.add("jQuery")
    except:
        pass
    return list(techs)

def scan_subdominios(dominio: str) -> List[Dict]:
    if is_private_ip(dominio):
        cprint("[INFO] IP privado → pulando subdomínios", "yellow")
        return []

    encontrados = []
    wildcard_ip = None
    try:
        fake = f"fake-test-{uuid.uuid4().hex[:8]}.{dominio}"
        wildcard_ip = socket.gethostbyname(fake)
        cprint(f"[!] Wildcard DNS detectado → {wildcard_ip}", "yellow")
    except:
        pass

    for sub in SUBDOMAINS_LIST:
        host = f"{sub}.{dominio}"
        try:
            ip = socket.gethostbyname(host)
            if wildcard_ip and ip == wildcard_ip:
                continue
            encontrados.append({"host": host, "ip": ip})
            cprint(f"  [+] {host} → {ip}", "green")
        except:
            continue
    return encontrados

def grab_banner(ip: str, port: int) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((ip, port))
            if port in (80, 443, 8080, 8443):
                s.send(f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
            data = s.recv(2048).decode(errors='ignore').strip()
            return data or "—"
    except:
        return "Conexão recusada"

def enumerar_diretorios(base_url: str) -> List[str]:
    achados = []
    try:
        fake_404 = f"{base_url}/404-test-{uuid.uuid4().hex[:8]}"
        resp_404 = requests.get(fake_404, timeout=4, verify=False)
        size_404 = len(resp_404.content)
    except:
        size_404 = 0

    for path in SENSITIVE_PATHS:
        try:
            r = requests.get(f"{base_url.rstrip('/')}{path}", timeout=4, verify=False, allow_redirects=False)
            size_diff = abs(len(r.content) - size_404)
            if r.status_code == 200 and size_diff > 400:
                achados.append(f"{path} → 200 OK ({len(r.content)} bytes)")
            elif r.status_code in (301, 302):
                achados.append(f"{path} → Redirect → {r.headers.get('Location','?')}")
            elif r.status_code == 403:
                achados.append(f"{path} → 403 Forbidden")
        except:
            continue
    return achados

def verificar_metodos_http(url: str) -> List[str]:
    ativos = []
    for method in DANGEROUS_METHODS:
        try:
            r = requests.request(method, url, timeout=3, verify=False)
            if r.status_code not in (404, 405, 501):
                ativos.append(f"{method} ({r.status_code})")
        except:
            pass
    return ativos

def verificar_cors_simples(url: str) -> str:
    try:
        r = requests.options(url, headers={"Origin": "http://evil-test.com"}, timeout=4, verify=False)
        if "Access-Control-Allow-Origin" in r.headers:
            acao = r.headers["Access-Control-Allow-Origin"]
            if acao == "*" or "evil-test.com" in acao:
                return "Vulnerável (CORS wildcard ou reflete origin malicioso)"
    except:
        pass
    return "OK"

def scan_host_completo(host: str) -> List[Dict]:
    resultados = []
    for port in COMMON_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.9)
        if s.connect_ex((host, port)) == 0:
            serv = PORT_SERVICES.get(port, f"Desconhecido ({port})")
            banner = grab_banner(host, port)
            info = {"porta": port, "servico": serv, "banner": banner}

            if port in (80, 443, 8080, 8443):
                proto = "https" if port in (443, 8443) else "http"
                url = f"{proto}://{host}"
                try:
                    r = requests.get(url, timeout=6, verify=False, allow_redirects=True)
                    h = r.headers
                    info["headers_ausentes"] = [k for k in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"] if k not in h]
                    info["metodos_perigosos"] = verificar_metodos_http(url)
                    info["diretorios"] = enumerar_diretorios(url)
                    info["cors"] = verificar_cors_simples(url)
                except Exception as e:
                    info["web_erro"] = str(e)[:80]
            resultados.append(info)
        s.close()
    return resultados

def scan_sqli(url_completa: str) -> List[str]:
    if "?" not in url_completa:
        return []
    vulneraveis = []
    parsed = urlparse(url_completa)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?"
    params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]

    for param in set(params):
        for payload in SQLI_TESTS:
            test_url = f"{base}{param}={payload.replace(' ', '+')}"
            try:
                t0 = time.time()
                r = requests.get(test_url, timeout=8, verify=False)
                dur = time.time() - t0
                body_low = r.text.lower()
                if any(err in body_low for err in ["sql syntax", "mysql", "sqlite", "pg_", "ora-", "mssql"]):
                    vulneraveis.append(f"[{param}] Erro SQL → {payload}")
                    break
                if dur > 5.5 and any(p in payload for p in ["SLEEP", "WAITFOR"]):
                    vulneraveis.append(f"[{param}] Time-based suspeito → {payload}")
                    break
            except:
                continue
    return list(set(vulneraveis))

# ────────────────────────────────────────────────
# GERAÇÃO DE RELATÓRIO PDF
# ────────────────────────────────────────────────

def gerar_pdf_pro(host: str, resultados: List, sqli: List, subs: List, ssl_data: Dict, techs: List):
    garantir_diretorio()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_arquivo = os.path.join(DOWNLOAD_DIR, f"SOC-ARX-AUDIT_{host.replace('.', '_')}_{ts}.pdf")

    if not REPORTLAB_OK:
        cprint("[PDF desativado] ReportLab não instalado.", "yellow")
        return False

    try:
        doc = SimpleDocTemplate(nome_arquivo, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=60, bottomMargin=40)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=22, textColor=colors.darkblue, alignment=TA_CENTER, spaceAfter=20)
        heading_style = ParagraphStyle('Heading2', parent=styles['Heading2'], fontSize=14, textColor=colors.navy, spaceAfter=12)
        normal_style = styles['Normal']
        alert_style = ParagraphStyle('Alert', parent=normal_style, textColor=colors.red, fontSize=11)
        recom_style = ParagraphStyle('Recom', parent=normal_style, textColor=colors.darkgreen, fontSize=10, italic=True)

        elements = []

        # Capa
        elements.append(Paragraph("🛡️ SOC-ARX Auditor v3.4", title_style))
        elements.append(Paragraph("Relatório de Segurança – Uso Doméstico", heading_style))
        elements.append(Spacer(1, 30))
        elements.append(Paragraph(f"Alvo: {host}", normal_style))
        elements.append(Paragraph(f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", normal_style))
        elements.append(PageBreak())

        # Resumo
        score = 100 - (len(resultados) * 6) - (50 if sqli else 0)
        score = max(10, score)
        risco = "CRÍTICO" if score < 45 else "ALTO" if score < 70 else "MÉDIO" if score < 90 else "BAIXO"
        risco_color = colors.red if risco == "CRÍTICO" else colors.orange if risco in ("ALTO", "MÉDIO") else colors.green

        resumo_data = [
            ["Métrica", "Valor"],
            ["Host / IP", host],
            ["SSL", ssl_data.get('status', 'N/A')],
            ["Risco Estimado", risco],
            ["Pontuação", f"{score}/100"]
        ]
        t_resumo = Table(resumo_data, colWidths=[180, 240])
        t_resumo.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('BACKGROUND', (1,3), (1,3), risco_color),
            ('TEXTCOLOR', (1,3), (1,3), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ]))
        elements.append(Paragraph("Resumo Executivo", heading_style))
        elements.append(t_resumo)
        elements.append(Spacer(1, 20))

        if techs:
            elements.append(Paragraph("Tecnologias Detectadas", heading_style))
            for t in techs:
                elements.append(Paragraph(f"• {t}", normal_style))
            elements.append(Spacer(1, 15))

        if subs:
            elements.append(Paragraph("Subdomínios Encontrados", heading_style))
            sub_data = [["Subdomínio", "IP"]] + [[s['host'], s['ip']] for s in subs]
            t_subs = Table(sub_data, colWidths=[240, 180])
            t_subs.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 0.5, colors.grey), ('BACKGROUND', (0,0), (-1,0), colors.lightblue)]))
            elements.append(t_subs)
            elements.append(Spacer(1, 20))

        elements.append(PageBreak())
        elements.append(Paragraph("Portas Abertas & Vulnerabilidades", heading_style))
        for r in resultados:
            elements.append(Paragraph(f"Porta {r['porta']} – {r['servico']}", heading_style))
            safe_banner = clean_for_pdf(r['banner'])
            elements.append(Paragraph(f"Banner: {safe_banner}", normal_style))
            
            rec = RECOMENDACOES.get(r['porta'], "Nenhuma recomendação crítica")
            elements.append(Paragraph(f"Recomendação: {rec}", recom_style))
            
            if r.get('diretorios'):
                elements.append(Paragraph("Diretórios Sensíveis:", alert_style))
                for d in r['diretorios']:
                    elements.append(Paragraph(f"  • {d}", normal_style))
            
            if r.get('headers_ausentes'):
                elements.append(Paragraph(f"Headers Ausentes: {', '.join(r['headers_ausentes'])}", alert_style))
            
            if r.get('cors', '').startswith('Vulnerável'):
                elements.append(Paragraph(f"CORS: {r['cors']}", alert_style))
            
            elements.append(Spacer(1, 12))

        if sqli:
            elements.append(PageBreak())
            elements.append(Paragraph("⚠️ Possíveis Injeções SQL", heading_style))
            for v in sqli:
                elements.append(Paragraph(f"• {v}", alert_style))

        doc.build(elements)
        cprint(f"\n[SUCESSO] PDF salvo em: {nome_arquivo}", "green")
        cprint("→ Abra Arquivos > Download > Soc-Arx", "yellow")
        return True
    except Exception as e:
        cprint(f"[ERRO PDF]: {str(e)}", "red")
        return False

# ────────────────────────────────────────────────
# MAIN
# ────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "═"*70)
    cprint("     SOC-ARX Auditor v3.4 – Completo e Estável     ", "cyan")
    print("═"*70 + "\n")

    alvo = input("Alvo (IP / domínio / URL completa): ").strip()

    if alvo.startswith(("http://", "https://")):
        parsed = urlparse(alvo)
        dominio = parsed.netloc or parsed.path.split("/")[0]
        alvo_url = alvo
    else:
        dominio = alvo
        alvo_url = f"http://{alvo}"

    try:
        ip = socket.gethostbyname(dominio)
        cprint(f"[+] Resolvido: {dominio} → {ip}", "green")
    except:
        cprint("[ERRO] Host não resolvido", "red")
        exit(1)

    t_start = time.time()

    subdominios = scan_subdominios(dominio) if "." in dominio else []
    ssl_info = verificar_ssl(dominio)
    techs = detectar_tecnologias(alvo_url)
    portas = scan_host_completo(dominio)
    sql_inj = scan_sqli(alvo_url)

    tempo = round(time.time() - t_start, 1)

    sucesso_pdf = False
    if REPORTLAB_OK:
        sucesso_pdf = gerar_pdf_pro(dominio, portas, sql_inj, subdominios, ssl_info, techs)

    if not sucesso_pdf:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_path = os.path.join(DOWNLOAD_DIR, f"SOC-ARX_{dominio.replace('.', '_')}_{ts}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(f"SOC-ARX AUDIT – {dominio}\n\n")
            f.write(f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n\n")
            f.write(f"Portas abertas: {len(portas)}\n")
            if portas:
                f.write("Portas:\n")
                for p in portas:
                    banner_clean = clean_for_pdf(p.get('banner', 'N/A'), 100)
                    f.write(f"  {p['porta']} - {p['servico']} | Banner: {banner_clean}\n")
            f.write(f"\nPossíveis SQLi: {len(sql_inj)}\n")
            if sql_inj:
                f.write("SQLi:\n")
                for v in sql_inj:
                    f.write(f"  • {v}\n")
            f.write("\nInstale reportlab para PDF completo: pip install reportlab\n")
        cprint(f"[TXT] Relatório salvo em: {txt_path}", "yellow")
        cprint(f"Caminho completo: {txt_path}", "cyan")

    cprint(f"\nConcluído em {tempo} segundos.", "cyan")
    print("Uso apenas em alvos autorizados!")
