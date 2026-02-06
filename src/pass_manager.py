import sqlite3
import os
import pyotp
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordManager:
    def __init__(self, db_name="cofre.db"):
        self.db_name = db_name
        self.key = None
        self.cipher = None
        self._init_db()

    def _init_db(self):
        """ Cria a tabela se não existir """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password_enc TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    def load_key(self, master_password):
        """ 
        Gera uma chave de criptografia válida baseada na Password Mestre do utilizador.
        Usa KDF (Key Derivation Function) para transformar texto em chave de 32 bytes.
        """
        salt = b'salt_seguranca_lpd_2025' 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        self.key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        self.cipher = Fernet(self.key)
        print("[AUTH] Chave derivada com sucesso.")

    def add_password(self, service, username, password):
        if not self.cipher: raise Exception("Cofre bloqueado!")
        
        # Cifrar a password
        enc_pw = self.cipher.encrypt(password.encode()).decode()
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO secrets (service, username, password_enc) VALUES (?, ?, ?)",
                       (service, username, enc_pw))
        conn.commit()
        conn.close()
        print(f"[+] Senha para {service} guardada!")

    def get_password(self, service):
        if not self.cipher: raise Exception("Cofre bloqueado!")
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT username, password_enc FROM secrets WHERE service = ?", (service,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            user, enc_pw = row
            # Decifrar para mostrar ao utilizador
            dec_pw = self.cipher.decrypt(enc_pw.encode()).decode()
            return user, dec_pw
        return None

    def list_services(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT service FROM secrets")
        services = [row[0] for row in cursor.fetchall()]
        conn.close()
        return services

# 2FA
def verificar_2fa(secret_fake="JBSWY3DPEHPK3PXP"):
    """
    Simula uma validação 2FA.
    """
    totp = pyotp.TOTP(secret_fake)
    print(f"\n[2FA DEBUG] O código atual é: {totp.now()} (Use isto se não tiver App)")
    code = input("Insira o código 2FA (6 dígitos): ")
    return totp.verify(code)

# --- Execução ---
if __name__ == "__main__":
    pm = PasswordManager()
    
    print("=== COFRE DE PASSWORDS ===")
    
    # 1. Autenticação Forte (Mestra + 2FA)
    master = input("Password Mestra: ")
    if not verificar_2fa():
        print("[ERRO] Falha no 2FA. Acesso negado.")
        exit()
        
    pm.load_key(master)
    
    while True:
        print("\n1. Adicionar | 2. Recuperar | 3. Listar | 4. Sair")
        op = input("Opção: ")
        
        if op == "1":
            srv = input("Serviço: ")
            usr = input("User: ")
            pwd = input("Password: ")
            pm.add_password(srv, usr, pwd)
        elif op == "2":
            srv = input("Qual o serviço? ")
            creds = pm.get_password(srv)
            if creds:
                print(f"--> User: {creds[0]} | Pass: {creds[1]}")
            else:
                print("[!] Não encontrado.")
        elif op == "3":
            print("Serviços guardados:", pm.list_services())
        elif op == "4":
            break
