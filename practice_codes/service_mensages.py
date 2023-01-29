import os
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Gere as chaves privada e pública do servidor
private_key = rsa.generate_private_key()
public_key = private_key.public_key()

# Crie um socket TCP para o servidor
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind(("localhost", 8000))
server_sock.listen()

# Crie o diretório de armazenamento de mensagens
if not os.path.exists("messages"):
    os.makedirs("messages")

# Aceite novas conexões
while True:
    # Aceite a conexão de um novo cliente
    client_sock, client_address = server_sock.accept()