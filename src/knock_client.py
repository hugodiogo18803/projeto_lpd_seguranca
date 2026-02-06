import socket
import time
import sys

def knock(target_ip, sequence=[7000, 8000, 9000]):
    print(f"[*] A iniciar Port Knocking em {target_ip}...")
    
    for port in sequence:
        try:
            # Cria socket TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            # Tenta conectar (não precisa de completar handshake)
            sock.connect_ex((target_ip, port))
            sock.close()
            print(f"  -> Knock em {port}")
            time.sleep(0.5) # Pausa pequena entre batidas
        except Exception as e:
            print(f"[ERRO] {e}")

    print("[*] Sequência terminada. Tente aceder por SSH agora.")

if __name__ == "__main__":
    alvo = input("IP do Servidor (ex: 127.0.0.1): ")
    knock(alvo)
