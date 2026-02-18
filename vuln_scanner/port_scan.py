import socket
import json
import os
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.platypus import Flowable

# -------------------- CONFIG --------------------
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 8080: "HTTP-ALT"
}
SENSITIVE_PATHS = ["/admin","/login","/wp-admin","/phpmyadmin","/dashboard","/.env"]
DOWNLOAD_DIR = "/storage/emulated/0/Download/Soc-Arx"
DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "OPTIONS"]

# -------------------- UTILIDADES --------------------
def ping_host(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner if banner else "Banner não identificado"
    except:
        return "Banner não identificado"

def coletar_headers_http(ip, port):
    headers = {}
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))
        s.send(b"GET / HTTP/1.1\r\nHost: alvo\r\n\r\n")
        response = s.recv(4096).decode(errors="ignore")
        s.close()
        for linha in response.split("\r\n"):
            if ":" in linha:
                k, v = linha.split(":", 1)
                headers[k.strip()] = v.strip()
    except:
        pass
    return headers

def verificar_headers_seguranca(headers):
    essenciais = ["X-Frame-Options","Content-Security-Policy","X-Content-Type-Options","Strict-Transport-Security"]
    return [h for h in essenciais if h not in headers]

def enumerar_diretorios(ip, port):
    encontrados = []
    for path in SENSITIVE_PATHS:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((ip, port))
            req = f"GET {path} HTTP/1.1\r\nHost: alvo\r\n\r\n"
            s.send(req.encode())
            resp = s.recv(1024).decode(errors="ignore")
            s.close()
            if "200 OK" in resp or "302" in resp:
                encontrados.append(path)
        except:
            continue
    return encontrados

def verificar_metodos_http(ip, port):
    metodos_ativos = []
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))
        s.send(b"OPTIONS / HTTP/1.1\r\nHost: alvo\r\n\r\n")
        response = s.recv(2048).decode(errors="ignore")
        s.close()
        for metodo in DANGEROUS_METHODS:
            if metodo in response:
                metodos_ativos.append(metodo)
    except:
        pass
    return metodos_ativos

def interpretar_banner(porta, banner):
    banner = banner.replace("<", "&lt;").replace(">", "&gt;")  # Corrige HTML
    if porta == 23:
        return "Serviço Telnet ativo com prompt de autenticação (inseguro)"
    if porta in [80, 8080, 443]:
        info = []
        if "server:" in banner.lower():
            try:
                server = banner.lower().split("server:")[1].split()[0]
                info.append(f"Servidor web identificado: {server}")
            except:
                pass
        if "set-cookie" in banner.lower():
            info.append("Cookie de sessão detectado")
        if not info:
            info.append("Serviço HTTP ativo")
        return " | ".join(info)
    return "Serviço ativo (banner genérico)"

# -------------------- SCANNER --------------------
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
            if port in [80, 8080, 443]:
                headers = coletar_headers_http(ip, port)
                registro["headers_http"] = headers
                registro["headers_seguranca_ausentes"] = verificar_headers_seguranca(headers)
                registro["diretorios_sensiveis"] = enumerar_diretorios(ip, port)
                registro["metodos_http_perigosos"] = verificar_metodos_http(ip, port)
            resultados.append(registro)
        s.close()
    return resultados

# -------------------- RISCO --------------------
def calcular_score(resultados):
    score = 0
    for r in resultados:
        if r["porta"] == 23:
            score += 50
        elif r["porta"] == 80:
            score += 20
        if "metodos_http_perigosos" in r and r["metodos_http_perigosos"]:
            score += 20
    return min(score, 100)

def resumo_executivo(ip, resultados):
    risco = "BAIXO"
    for r in resultados:
        if r["porta"] == 23:
            risco = "ALTO"
            break
        elif r["porta"] == 80:
            risco = "MÉDIO"
    score = calcular_score(resultados)
    return risco, score

# -------------------- PDF COM GRÁFICO --------------------
def gerar_pdf(ip, resultados, risco, score):
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    data = datetime.now().strftime("%Y-%m-%d_%H-%M")
    arquivo_pdf = f"{DOWNLOAD_DIR}/relatorio_{ip}_{data}.pdf"

    doc = SimpleDocTemplate(arquivo_pdf, pagesize=A4)
    estilos = getSampleStyleSheet()
    elementos = []

    elementos.append(Paragraph("<b>SOC-ARX – RELATÓRIO DE RECON WEB & REDE</b>", estilos["Title"]))
    elementos.append(Spacer(1, 12))
    elementos.append(Paragraph(f"IP analisado: {ip}", estilos["Normal"]))
    elementos.append(Paragraph(f"Data: {datetime.now()}", estilos["Normal"]))
    elementos.append(Paragraph(f"Risco: {risco}", estilos["Normal"]))
    elementos.append(Paragraph(f"Score Geral: {score}/100", estilos["Normal"]))
    elementos.append(Spacer(1, 12))

    # Tabela detalhada
    data_table = [["Porta", "Serviço", "Descrição", "Diretórios Sensíveis", "Headers Ausentes", "Métodos HTTP Perigosos"]]
    for r in resultados:
        descricao = interpretar_banner(r["porta"], r["banner"])
        dirs = ", ".join(r.get("diretorios_sensiveis", []))
        headers = ", ".join(r.get("headers_seguranca_ausentes", []))
        metodos = ", ".join(r.get("metodos_http_perigosos", []))
        data_table.append([r["porta"], r["servico"], descricao, dirs, headers, metodos])

    tabela = Table(data_table, colWidths=[40, 50, 150, 100, 100, 100])
    tabela.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('VALIGN', (0,0), (-1,-1), 'TOP')
    ]))
    elementos.append(tabela)
    elementos.append(Spacer(1, 20))

    # Gráfico de barras do score por porta
    drawing = Drawing(400, 150)
    bc = VerticalBarChart()
    bc.x = 50
    bc.y = 20
    bc.height = 100
    bc.width = 300
    bc.data = [[50 if r["porta"]==23 else 20 if r["porta"]==80 else 5 for r in resultados]]
    bc.barWidth = 20
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = 100
    bc.valueAxis.valueStep = 10
    bc.categoryAxis.categoryNames = [str(r["porta"]) for r in resultados]
    bc.bars[0].fillColor = colors.red
    drawing.add(bc)
    drawing.add(String(150, 130, "Score por Porta", fontSize=12, fillColor=colors.black))
    elementos.append(drawing)

    doc.build(elementos)
    print(f"\n📄 PDF salvo em: {arquivo_pdf}")

# -------------------- MAIN --------------------
if __name__ == "__main__":
    alvo = input("IP alvo: ")
    if not ping_host(alvo):
        print("Host inativo ou inacessível. Verifique a rede.")
        exit()

    resultados = scan_host(alvo)
    if not resultados:
        print("\nNenhuma porta aberta encontrada.")
        exit()

    risco, score = resumo_executivo(alvo, resultados)
    gerar_pdf(alvo, resultados, risco, score)

    with open(f"{DOWNLOAD_DIR}/relatorio_{alvo}_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.json", "w") as f:
        json.dump({
            "ip": alvo,
            "data": str(datetime.now()),
            "risco": risco,
            "score": score,
            "resultados": resultados
        }, f, indent=4)

    print("\n✅ Relatórios gerados com sucesso no celular.")
