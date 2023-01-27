import socket, subprocess,sys
from securechat.server import server
from securechat.client import client
from securechat.crypto_utils import crypto_utils
from os import system, name

class SecureChat():

    def __init__(self):
        self.displayOptions()        

    def displayOptions(self):
        system('clear')
        try:
            print("What type of instance do you wish to start(select 1 for server / 2 for client) ")
            print("3 - View message file")
            print("4 - Go back")
            inpt = int(input("Select a suitable option: "))
        except ValueError:
            print("It needs to be a number:")
            self.displayOptions()
        except: 
            print("Unknown option, please try again")
            self.displayOptions()
        if inpt == 1: self.startServer()
        elif inpt == 2: self.startClient()
        elif inpt == 3: crypto_utils().decrypt_messages_file()
        elif inpt == 4: raise NameError
        else: sys.exit()
        

    def startServer(self):
        connected_server = server()
    def startClient(self):
        server_ip = input("Please insert server IP(127.0.0.1): ")
        try:
            server_port = int(input("Please insert server port: "))
        except ValueError:
            print("It needs to be a number:")
            self.displayOptions()
        except: 
            print("Unknown option, please try again")
            self.displayOptions()
        connected_client = client(server_ip, server_port)
