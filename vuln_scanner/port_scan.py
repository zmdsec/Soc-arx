import socket
import json
import os
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# -------------------- CONFIG --------------------
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 8080: "HTTP-ALT"
}
SENSITIVE_PATHS = ["/admin","/login","/wp-admin","/phpmyadmin","/dashboard","/.env"]
DOWNLOAD_DIR = "/storage/emulated/0/Download/Soc-Arx"

# -------------------- UTIL --------------------
def limpar_banner(banner, limite=120):
    if not banner:
        return "Não identificado"
    banner = banner.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    banner = " ".join(banner.split())
    if len(banner) > limite:
        banner = banner[:limite] + "..."
    return banner

def classificar_severidade(registro):
    if registro["porta"] == 23:
        return "CRÍTICO"
    if registro["porta"] in [21, 3306]:
        return "ALTO"
    if registro["porta"] in [80, 8080]:
        return "MÉDIO"
    return "BAIXO"

def gerar_recomendacao(registro):
    if registro["porta"] == 23:
        return "Desativar Telnet imediatamente e utilizar SSH."
    if registro["porta"] == 21:
        return "Evitar FTP sem criptografia. Utilizar SFTP."
    if registro["porta"] in [80, 8080]:
        return "Implementar HTTPS e configurar headers de segurança."
    if registro["porta"] == 3306:
        return "Restringir acesso externo ao banco de dados."
    return "Revisar exposição da porta e necessidade do serviço."

# -------------------- NETWORK --------------------
def ping_host(ip):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, 80))
        s.close()
        return True
    except:
        return False

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        if port in [80, 8080, 443]:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore")
        s.close()
        return limpar_banner(banner)
    except:
        return "Não identificado"

# -------------------- SCAN --------------------
def scan_host(ip):
    resultados = []
    print(f"\nEscaneando {ip}...\n")
    for port in COMMON_PORTS:
        s = socket.socket()
        s.settimeout(1)
        if s.connect_ex((ip, port)) == 0:
            service = PORT_SERVICES.get(port, "Desconhecido")
            banner = grab_banner(ip, port)

            registro = {
                "porta": port,
                "servico": service,
                "banner": banner
            }

            registro["severidade"] = classificar_severidade(registro)
            registro["recomendacao"] = gerar_recomendacao(registro)

            resultados.append(registro)
        s.close()
    return resultados

# -------------------- SCORE --------------------
def calcular_score(resultados):
    score = 0
    for r in resultados:
        if r["severidade"] == "CRÍTICO":
            score += 50
        elif r["severidade"] == "ALTO":
            score += 30
        elif r["severidade"] == "MÉDIO":
            score += 15
        else:
            score += 5
    return min(score, 100)

def determinar_risco(score):
    if score >= 70:
        return "ALTO"
    if score >= 40:
        return "MÉDIO"
    return "BAIXO"

# -------------------- PDF --------------------
def gerar_pdf(ip, resultados, risco, score):
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    data = datetime.now().strftime("%Y-%m-%d_%H-%M")
    arquivo_pdf = f"{DOWNLOAD_DIR}/SOC_ARX_{ip}_{data}.pdf"

    doc = SimpleDocTemplate(arquivo_pdf, pagesize=A4)
    estilos = getSampleStyleSheet()
    elementos = []

    # CAPA / EXECUTIVO
    elementos.append(Paragraph("<b>SOC-ARX – RELATÓRIO EXECUTIVO</b>", estilos["Title"]))
    elementos.append(Spacer(1, 12))
    elementos.append(Paragraph(f"IP analisado: {ip}", estilos["Normal"]))
    elementos.append(Paragraph(f"Data: {datetime.now()}", estilos["Normal"]))
    elementos.append(Paragraph(f"Nível de risco: {risco}", estilos["Normal"]))
    elementos.append(Paragraph(f"Score geral: {score}/100", estilos["Normal"]))
    elementos.append(Spacer(1, 20))

    elementos.append(Paragraph("<b>Resumo de Exposição:</b>", estilos["Heading2"]))
    elementos.append(Spacer(1, 8))
    for r in resultados:
        elementos.append(Paragraph(
            f"Porta {r['porta']} ({r['servico']}) - Severidade: {r['severidade']}",
            estilos["Normal"]
        ))
    elementos.append(PageBreak())

    # RELATÓRIO TÉCNICO
    elementos.append(Paragraph("<b>RELATÓRIO TÉCNICO DETALHADO</b>", estilos["Title"]))
    elementos.append(Spacer(1, 12))

    tabela_dados = [["Porta","Serviço","Severidade","Banner","Recomendação"]]

    for r in resultados:
        tabela_dados.append([
            r["porta"],
            r["servico"],
            r["severidade"],
            r["banner"],
            r["recomendacao"]
        ])

    tabela = Table(tabela_dados, colWidths=[40,60,70,130,150])
    tabela.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.grey),
        ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
        ('GRID',(0,0),(-1,-1),1,colors.black),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold')
    ]))

    elementos.append(tabela)

    doc.build(elementos)

    print(f"\n📄 PDF profissional salvo em: {arquivo_pdf}")

# -------------------- MAIN --------------------
if __name__ == "__main__":
    alvo = input("IP alvo: ")

    if not ping_host(alvo):
        print("Host inativo ou inacessível.")
        exit()

    resultados = scan_host(alvo)

    if not resultados:
        print("Nenhuma porta aberta encontrada.")
        exit()

    score = calcular_score(resultados)
    risco = determinar_risco(score)

    gerar_pdf(alvo, resultados, risco, score)

    print("\n✅ SOC-ARX 2.0 finalizado com sucesso.")
