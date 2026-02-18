import requests

BLACKLIST = ["login-secure", "verify-account", "free-gift"]

def check_url(url):
    for keyword in BLACKLIST:
        if keyword in url.lower():
            return True
    return False

url = input("URL para análise: ")
if check_url(url):
    print("[ALERTA] Possível phishing detectado")
else:
    print("[OK] URL aparentemente segura")
