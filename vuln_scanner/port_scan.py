import socket
import json
import os
import requests
import ssl
import uuid
import urllib3
import time
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Dict, Any

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
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
# CONFIGURAÇÕES (expandidas)
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
        cprint("Execute: termux-setup-storage", "yellow")
        exit(1)

# (as funções verificar_ssl, detectar_tecnologias, scan_subdominios, grab_banner,
#  enumerar_diretorios, verificar_metodos_http, verificar_cors_simples, scan_host_completo,
#  scan_sqli permanecem iguais ao script anterior – colei resumido para não repetir tudo)

# ... cole aqui as funções do script anterior que eu enviei antes ...

# ────────────────────────────────────────────────
# GERAÇÃO DE RELATÓRIO PDF (melhorado)
# ────────────────────────────────────────────────

def gerar_pdf_pro(host: str, resultados: List, sqli: List, subs: List, ssl_data: Dict, techs: List):
    garantir_diretorio()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_arquivo = os.path.join(DOWNLOAD_DIR, f"SOC-ARX-AUDIT_{host.replace('.', '_')}_{ts}.pdf")

    doc = SimpleDocTemplate(nome_arquivo, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=60, bottomMargin=40)
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=22, textColor=colors.darkblue, alignment=TA_CENTER, spaceAfter=20)
    heading_style = ParagraphStyle('Heading2', parent=styles['Heading2'], fontSize=14, textColor=colors.navy, spaceAfter=12)
    normal_style = styles['Normal']
    alert_style = ParagraphStyle('Alert', parent=normal_style, textColor=colors.red, fontSize=11)
    recom_style = ParagraphStyle('Recom', parent=normal_style, textColor=colors.darkgreen, fontSize=10, italic=True)

    elements = []

    # Capa
    elements.append(Paragraph("🛡️ SOC-ARX Auditor v3.2", title_style))
    elements.append(Paragraph("Relatório de Segurança – Uso Doméstico / Testes", heading_style))
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

    # Portas
    elements.append(PageBreak())
    elements.append(Paragraph("Portas Abertas & Vulnerabilidades", heading_style))
    for r in resultados:
        elements.append(Paragraph(f"Porta {r['porta']} – {r['servico']}", heading_style))
        elements.append(Paragraph(f"Banner: {r['banner'][:150]}...", normal_style))
        
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
    cprint(f"\n[SUCESSO] PDF gerado: {nome_arquivo}", "green")
    cprint("→ Abra com qualquer leitor de PDF no Android", "yellow")

# ────────────────────────────────────────────────
# MAIN
# ────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "═"*70)
    cprint("     SOC-ARX Auditor v3.2 – PDF Report Ready     ", "cyan")
    print("═"*70 + "\n")

    alvo = input("Alvo (IP / domínio / URL completa): ").strip()

    # Normaliza
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

    if REPORTLAB_OK:
        gerar_pdf_pro(dominio, portas, sql_inj, subdominios, ssl_info, techs)
    else:
        # Fallback simples para TXT (caso reportlab falhe)
        with open(os.path.join(DOWNLOAD_DIR, f"SOC-ARX_{dominio}_{ts}.txt"), "w", encoding="utf-8") as f:
            f.write(f"SOC-ARX AUDIT – {dominio}\n\n")
            f.write(f"Risco: {risco} | Score: {score}/100\n\n")
            # ... adicione mais se quiser
        cprint("Usando TXT como fallback (instale reportlab para PDF)", "yellow")

    cprint(f"\nConcluído em {tempo} segundos.", "cyan")
    print("Uso apenas em alvos autorizados!")
