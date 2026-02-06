import socket
import threading
import sys

class ChatClient:
    def __init__(self, host='127.0.0.1', port=9999):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        
        self.nickname = input("Escolha o seu Nickname: ")

    def receive(self):
        while True:
            try:
                message = self.sock.recv(1024).decode('utf-8')
                print(message)
            except:
                print("[!] Conexão perdida.")
                self.sock.close()
                break

    def write(self):
        while True:
            text = input(f"")
            message = f"{self.nickname}: {text}"
            self.sock.send(message.encode('utf-8'))

    def start(self):
        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()
        
        write_thread = threading.Thread(target=self.write)
        write_thread.start()

if __name__ == "__main__":
    client = ChatClient()
    client.start()
