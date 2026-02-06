import os
import time
import threading
from scapy.all import sniff, IP, TCP

class PortKnockerDaemon:
    def __init__(self, interface="eth0"):
        # Sequência Secreta: Portos e Ordem
        self.knock_sequence = [7000, 8000, 9000]
        # Armazena o estado de quem está a bater: { 'IP': [index_da_sequencia, timestamp] }
        self.knock_state = {}
        self.interface = interface
        self.lock = threading.Lock()

    def open_firewall(self, ip_address):
        """ Executa comando de sistema para abrir a porta 22 para este IP """
        print(f"[SUCESSO] Sequência correta de {ip_address}! A abrir porta SSH...")
        # Adiciona regra no topo (-I) para aceitar SSH deste IP
        cmd = f"iptables -I INPUT -s {ip_address} -p tcp --dport 22 -j ACCEPT"
        os.system(cmd)
        threading.Timer(30, self.close_firewall, [ip_address]).start()

    def close_firewall(self, ip_address):
        print(f"[AUTO] A fechar porta SSH para {ip_address}...")
        # Apaga a regra (-D)
        cmd = f"iptables -D INPUT -s {ip_address} -p tcp --dport 22 -j ACCEPT"
        os.system(cmd)

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            
            # Se o pacote for para um dos ports da sequência
            if dst_port in self.knock_sequence:
                with self.lock:
                    current_stage = self.knock_state.get(src_ip, 0)
                    target_port = self.knock_sequence[current_stage]
                    
                    if dst_port == target_port:
                        print(f"[KNOCK] {src_ip} bateu no port {dst_port} (Fase {current_stage + 1}/{len(self.knock_sequence)})")
                        self.knock_state[src_ip] = current_stage + 1
                        
                        # Se completou a sequência
                        if self.knock_state[src_ip] == len(self.knock_sequence):
                            self.open_firewall(src_ip)
                            self.knock_state[src_ip] = 0 # Reset
                    else:
                        # Sequência errada, reset
                        if src_ip in self.knock_state:
                            print(f"[FALHA] {src_ip} errou a sequência. Reset.")
                            self.knock_state[src_ip] = 0

    def start(self):
        print(f"[*] Knock Daemon ativo. Sequência: {self.knock_sequence}")
        print("[*] A monitorizar tráfego...")
        sniff(filter="tcp", prn=self.packet_callback, store=0, iface=self.interface)

if __name__ == "__main__":
    daemon = PortKnockerDaemon(interface="lo") 
    daemon.start()
