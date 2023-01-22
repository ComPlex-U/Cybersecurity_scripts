import socket
import pickle
import sqlite3
from datetime import datetime
from Crypto.PublicKey import RSA
import threading


#S(pubkey, privkey) = RSA.newkeys(512)


HOST = 'localhost'
PORT = 1234

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)

# Connect to SQLite database
conn = sqlite3.connect('messages.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS messages
                  (sender TEXT, receiver TEXT, message BLOB, timestamp DATETIME)''')

# Create a dictionary to store connected clients
clients = {}

def handle_client(client):
    """Function to handle a client's request"""
    client_socket, address = client
    # Receive the client's public key
    client_pubkey = pickle.loads(client_socket.recv(1024))
    # Add the client's address and public key to the clients dictionary
    clients[address] = client_pubkey
    while True:
        try:
            # Receive the encrypted message
            message = pickle.loads(client_socket.recv(1024))
            # Decrypt the message using the server's private key
            decrypted_message = RSA.decrypt(message, privkey).decode()
            # Extract the sender's address
            sender = address
            # Extract the receiver's address
            receiver = decrypted_message.split(':')[0]
            # Extract the message
            message = decrypted_message.split(':')[1]
            # Encrypt the message using the receiver's public key
            encrypted_message = RSA.encrypt(message.encode(), clients[receiver])
            # Send the encrypted message to the receiver
            clients[receiver].send(pickle.dumps(encrypted_message))
            # Store the message in the database
            cursor.execute("INSERT INTO messages VALUES (?,?,?,?)", (sender, receiver, encrypted_message, datetime.now()))
            conn.commit()
        except:
            # Remove the client from the clients dictionary if the connection is closed
            clients.pop(address)
            client_socket.close()
            return

while True:
    client = server_socket.accept()
    client_thread = threading.Thread(target=handle_client, args=(client,))
   
