import re
import socket
import sys
import matplotlib.pyplot as plt
from collections import Counter
import geoip2.database # Requer: pip install geoip2

class LogAnalyzer:
    def __init__(self, db_path="GeoLite2-City.mmdb"):
        self.db_path = db_path
        self.reader = None
        
        try:
            self.reader = geoip2.database.Reader(self.db_path)
            print(f"[INIT] Base de dados GeoIP carregada: {self.db_path}")
        except FileNotFoundError:
            print(f"[ERRO] Base de dados não encontrada em '{self.db_path}'.")
            print("Download em: https://www.maxmind.com/en/geolite2/signup")
            sys.exit(1)

    def get_country(self, ip):
        # Ignorar IPs privados
        if ip.startswith(("127.", "192.168.", "10.")):
            return "Local Network"

        try:
            response = self.reader.city(ip)
            return response.country.name if response.country.name else "Unknown"
        except geoip2.errors.AddressNotFoundError:
            return "Unknown"
        except Exception as e:
            return "Error"

    def parse_file(self, file_path):
        """ Ler de um ficheiro estático """
        ips = []
        regex = r"Failed password for (?:invalid user )?.*? from (\d+\.\d+\.\d+\.\d+)"
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    match = re.search(regex, line)
                    if match:
                        ips.append(match.group(1))
        except FileNotFoundError:
            print(f"[ERRO] Ficheiro {file_path} não encontrado.")
        return ips

    def start_syslog_server(self, host="0.0.0.0", port=514):
        print(f"[SYSLOG] A escutar logs UDP em {host}:{port} (Ctrl+C para parar)...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            sock.bind((host, port))
        except PermissionError:
            print("[ERRO] É necessário root/sudo para escutar na porta 514.")
            return

        ips_detected = []
        
        try:
            while True:
                data, addr = sock.recvfrom(1024)
                line = data.decode("utf-8")
                
                # Procura padrão de ataque na mensagem recebida
                match = re.search(r"Failed password.*?from (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    attacker_ip = match.group(1)
                    country = self.get_country(attacker_ip)
                    print(f"[ALERTA] Ataque de {attacker_ip} ({country})")
                    ips_detected.append(attacker_ip)
                    
        except KeyboardInterrupt:
            print(f"\n[FIM] Servidor parado. {len(ips_detected)} ataques capturados.")
            if ips_detected:
                self.generate_report(ips_detected)

    def generate_report(self, ips):
        print("[REPORT] A gerar gráfico...")
        countries = [self.get_country(ip) for ip in ips]
        counts = Counter(countries)
        
        if not counts: return

        labels, values = zip(*counts.most_common(5))
        plt.figure(figsize=(10, 6))
        plt.bar(labels, values, color='crimson')
        plt.title('Top Origens (Análise Local GeoIP)')
        plt.savefig("relatorio_final.png")
        print("[SUCESSO] Gráfico 'relatorio_final.png' gerado.")

if __name__ == "__main__":
    analyzer = LogAnalyzer("GeoLite2-City.mmdb")

    print("Escolha o modo de operação:")
    print("1 - Analisar ficheiro estático (/var/log/auth.log)")
    print("2 - Iniciar Servidor Syslog (Tempo Real - Valorizado)")
    
    opcao = input("Opção: ")
    
    if opcao == "1":
        ips = analyzer.parse_file("/var/log/auth.log") # Ou log falso
        if ips: analyzer.generate_report(ips)
    elif opcao == "2":
        analyzer.start_syslog_server()
