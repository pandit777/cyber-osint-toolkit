import socket

def scan(host):

    print("Scanning common ports...\n")

    ports = [21,22,23,25,53,80,110,135,139,143,443,445,3389]

    for port in ports:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)

        result = s.connect_ex((host, port))

        if result == 0:
            print(f"Port {port} OPEN")

        s.close()