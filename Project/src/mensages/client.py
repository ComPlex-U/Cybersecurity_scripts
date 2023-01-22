import socket
import pickle
from Crypto.PublicKey import RSA

(pubkey, privkey) = RSA.newkeys(512)

HOST = 'localhost'
PORT = 1234

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

message = input("Enter message: ")
encrypted_message = RSA.encrypt(message.encode(), pubkey)
client_socket.send(pickle.dumps(encrypted_message))
client_socket.close()