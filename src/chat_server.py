import socket
import threading
import os
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class ChatServer:
    def __init__(self, host='0.0.0.0', port=9999):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen()
        self.clients = []
        
        # Gestão de Chaves RSA (Para encriptar o log)
        self.private_key, self.public_key = self._load_or_generate_keys()
        
        print(f"[INIT] Servidor a escutar em {host}:{port}")
        print("[SEC] Logs serão cifrados com RSA-2048.")

    def _load_or_generate_keys(self):
        """ Gera chaves para cifrar o histórico de mensagens """
        if not os.path.exists("server_rsa.pem"):
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            # Guardar chave privada (em caso real, proteger com password)
            with open("server_rsa.pem", "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            public_key = private_key.public_key()
            return private_key, public_key
        else:
            # Carregar existente
            with open("server_rsa.pem", "rb") as k:
                private_key = serialization.load_pem_private_key(k.read(), password=None)
            return private_key, private_key.public_key()

    def log_message(self, message):
        """ Requisito: Armazenar mensagem encriptada com chave assimétrica """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        
        # Cifrar com a Chave Pública
        encrypted = self.public_key.encrypt(
            entry.encode('utf-8'),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        
        # Append ao ficheiro binário
        with open("chat_history.enc", "ab") as f:
            f.write(encrypted + b":::END:::") # Delimitador para facilitar leitura

    def broadcast(self, message, sender_socket):
        for client in self.clients:
            if client != sender_socket:
                try:
                    client.send(message)
                except:
                    self.clients.remove(client)

    def handle_client(self, client):
        while True:
            try:
                message = client.recv(1024)
                if not message: break
                
                msg_decoded = message.decode('utf-8')
                print(f"[MSG] {msg_decoded}")
                
                # 1. Guardar no Log Seguro
                self.log_message(msg_decoded)
                
                # 2. Reenviar para outros clientes
                self.broadcast(message, client)
            except:
                self.clients.remove(client)
                client.close()
                break

    def start(self):
        print("[START] À espera de conexões...")
        while True:
            client, addr = self.server.accept()
            print(f"[CONEXÃO] {addr} conectou-se.")
            self.clients.append(client)
            thread = threading.Thread(target=self.handle_client, args=(client,))
            thread.start()

    # Função extra para demonstrar funcionamento: ler os Logs
    def decrypt_logs(self):
        print("\n--- DESENCRIPTANDO LOGS (ADMIN ONLY) ---")
        if not os.path.exists("chat_history.enc"):
            print("Sem logs.")
            return

        with open("chat_history.enc", "rb") as f:
            content = f.read()
            
        # Separar por delimitador e decifrar
        messages = content.split(b":::END:::")
        for msg in messages:
            if not msg: continue
            try:
                original = self.private_key.decrypt(
                    msg,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                print(original.decode('utf-8'))
            except Exception as e:
                print(f"[Erro decifra] {e}")

if __name__ == "__main__":
    srv = ChatServer()
    
    # Menu para testes
    opt = input("1. Iniciar Servidor | 2. Ler Logs Encriptados: ")
    if opt == "1":
        srv.start()
    elif opt == "2":
        srv.decrypt_logs()
