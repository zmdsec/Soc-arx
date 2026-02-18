import threading
from ids.ids_engine import start_ids
from core.risk_engine import calculate_risk
from rich import print

def banner():
    print("""
[bold red]
███╗   ███╗ ██████╗ ██████╗ ██╗██╗     ███████╗
████╗ ████║██╔═══██╗██╔══██╗██║██║     ██╔════╝
██╔████╔██║██║   ██║██████╔╝██║██║     █████╗  
██║╚██╔╝██║██║   ██║██╔══██╗██║██║     ██╔══╝  
██║ ╚═╝ ██║╚██████╔╝██████╔╝██║███████╗███████╗
╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝╚══════╝
            MOBILE SOC v1.0
""")

if __name__ == "__main__":
    banner()
    t1 = threading.Thread(target=start_ids)
    t1.start()
