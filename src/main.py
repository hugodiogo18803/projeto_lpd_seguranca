import sys
import os
import time

# Importação dos módulos desenvolvidos
try:
    from rede import NetworkTool
    from logs import LogAnalyzer
    from pass_manager import PasswordManager, verificar_2fa
    from knock_client import knock
except ImportError as e:
    print(f"[ERRO CRÍTICO] Falta um módulo: {e}")
    print("Verificar se a está a correr o script dentro da pasta 'src' ou se o venv está ativo.")
    sys.exit(1)

# --- Funções Auxiliares ---
def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def press_enter():
    input("\n[ENTER] para voltar ao menu...")

def print_header():
    clear_screen()
    print("==========================================")
    print("   LPD SECURITY SUITE - 2025/2026")
    print("==========================================")

# --- Sub-Menus ---
def menu_rede():
    tool = NetworkTool()
    while True:
        print_header()
        print(">> FERRAMENTAS DE REDE")
        print("1. Port Scanner")
        print("2. UDP Flood (DoS)")
        print("3. SYN Flood (DoS - Requer ROOT)")
        print("0. Voltar")
        
        op = input("\nOpção: ")
        
        if op == "1":
            target = input("IP Alvo: ")
            ports = [21, 22, 80, 443, 3306, 8080]
            tool.scan_ports(target, ports)
        elif op == "2":
            target = input("IP Alvo: ")
            port = int(input("Porto: "))
            dur = int(input("Duração (s): "))
            tool.udp_flood(target, port, dur)
        elif op == "3":
            if os.geteuid() != 0:
                print("[!] O SYN Flood requer privilégios de ROOT (sudo).")
            else:
                target = input("IP Alvo: ")
                port = int(input("Porto: "))
                count = int(input("Nº Pacotes: "))
                tool.syn_flood(target, port, count)
        elif op == "0":
            break
        press_enter()

def menu_logs():
    # Tenta carregar a base de dados GeoIP se existir
    db_path = "GeoLite2-City.mmdb" if os.path.exists("GeoLite2-City.mmdb") else None
    analyzer = LogAnalyzer(db_path) if db_path else LogAnalyzer()

    while True:
        print_header()
        print(">> ANÁLISE DE LOGS & REPORTING")
        print("1. Analisar /var/log/auth.log (Estático)")
        print("2. Iniciar Syslog Server UDP 514 (Tempo Real - ROOT)")
        print("0. Voltar")
        
        op = input("\nOpção: ")
        
        if op == "1":
            path = input("Caminho do log [/var/log/auth.log]: ") or "/var/log/auth.log"
            ips = analyzer.parse_file(path)
            print(f"IPs detetados: {len(ips)}")
            if ips: analyzer.generate_report(ips)
        elif op == "2":
             if os.geteuid() != 0:
                print("[!] Escutar na porta 514 requer ROOT.")
             else:
                analyzer.start_syslog_server()
        elif op == "0":
            break
        press_enter()

def menu_passwords():
    pm = PasswordManager()
    print("\n[SECURITY] Autenticação necessária.")
    mst = input("Password Mestra: ")
    
    # Simulação 2FA
    if not verificar_2fa():
        print("Falha na autenticação 2FA.")
        time.sleep(2)
        return

    try:
        pm.load_key(mst)
    except:
        print("Erro ao gerar chaves.")
        return

    while True:
        print_header()
        print(">> COFRE DE PASSWORDS (CIFRADO)")
        print("1. Adicionar Credencial")
        print("2. Recuperar Credencial")
        print("3. Listar Serviços")
        print("0. Voltar")
        
        op = input("\nOpção: ")
        
        if op == "1":
            s = input("Serviço: ")
            u = input("User: ")
            p = input("Password: ")
            pm.add_password(s, u, p)
        elif op == "2":
            s = input("Serviço: ")
            res = pm.get_password(s)
            if res: print(f"User: {res[0]} | Pass: {res[1]}")
            else: print("Não encontrado.")
        elif op == "3":
            print(pm.list_services())
        elif op == "0":
            break
        press_enter()

def menu_extra():
    while True:
        print_header()
        print(">> EXTRAS (CHAT & PORT KNOCKING)")
        print("1. Iniciar Chat Server (Bloqueante)")
        print("2. Iniciar Chat Client")
        print("3. Ler Logs de Chat (Decifrar RSA)")
        print("4. Iniciar Port Knocking DAEMON (Servidor - ROOT)")
        print("5. Enviar Sequência de Knock (Cliente)")
        print("0. Voltar")
        
        op = input("\nOpção: ")
        
        if op == "1":
            os.system("python3 chat_server.py")
        elif op == "2":
            os.system("python3 chat_client.py")
        elif op == "3":
            from chat_server import ChatServer
            srv = ChatServer()
            srv.decrypt_logs()
        elif op == "4":
            if os.geteuid() != 0: print("[!] Requer ROOT.")
            else: os.system("sudo python3 knock_server.py")
        elif op == "5":
            ip = input("IP Alvo: ")
            knock(ip)
        elif op == "0":
            break
        press_enter()

# Loop Principal
if __name__ == "__main__":
    while True:
        print_header()
        print("1. Ferramentas de Rede (Scanner/DoS)")
        print("2. Análise de Logs (GeoIP/Syslog)")
        print("3. Password Manager (AES/2FA)")
        print("4. Extras (Chat/Knocking)")
        print("0. Sair")
        
        op = input("\nEscolha: ")
        
        if op == "1": menu_rede()
        elif op == "2": menu_logs()
        elif op == "3": menu_passwords()
        elif op == "4": menu_extra()
        elif op == "0": 
            print("A sair...")
            sys.exit(0)
