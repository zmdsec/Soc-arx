import socket

def scan(target, ports):
    open_ports = []
    for port in ports:
        s = socket.socket()
        s.settimeout(1)
        if s.connect_ex((target, port)) == 0:
            open_ports.append(port)
        s.close()
    return open_ports

if __name__ == "__main__":
    target = input("IP alvo: ")
    ports = [21,22,23,80,443,445,3389]
    result = scan(target, ports)
    print("Portas abertas:", result)
