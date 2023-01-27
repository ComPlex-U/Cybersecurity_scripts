import socket
import select
import errno
import sys
from securechat.crypto_utils import crypto_utils

class client():

    HEADER_LENGTH = 10
    IP = "127.0.0.1"
    PORT = 1234
    own_message = True
    DST_KEY = b""
    SRC_KEY = b""

    def __init__(self, serverIP="127.0.0.1", serverPORT=1234):
        self.IP = serverIP
        self.PORT = serverPORT
        # Create a socket
        # socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
        # socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to a given ip and port
        client_socket.connect((self.IP, self.PORT))

        # Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
        client_socket.setblocking(False)

        pub_key, self.SRC_KEY = crypto_utils().generateKeyPair()

        # Prepare username and header and send them
        # We need to encode username to bytes, then count number of bytes and prepare header of fixed size, that we encode to bytes as well
        
        key_header = f"{len(pub_key):<{self.HEADER_LENGTH}}".encode('utf-8')
        client_socket.send(key_header + pub_key)

        while True:

            # Wait for user to input a message
            message = input(f'You: ')

            # If message is not empty - send it
            if message:

                # Encode message to bytes, prepare header and convert to bytes, like for username above, then send
                if len(self.DST_KEY) == 0:
                    print("No destination key detected, sending message in plaintext!") 
                    message = message.encode('utf-8')
                else:
                    message = crypto_utils().encrypt_message(message.encode('utf-8'), self.DST_KEY)
                message_header = f"{len(message):<{self.HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)

                
            try:
                # Now we want to loop over received messages (there might be more than one) and print them
                
                while True:
                    # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
                    
                    # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
                    ##encrypted_message = client_socket.recv(2048)
                    
                    message_header = client_socket.recv(self.HEADER_LENGTH)
                    decripted_msg = ""
                    message = ""
                    if not len(message_header):
                        print('Connection closed by the server')
                        sys.exit()
                    message_length = int(message_header.decode('utf-8').strip())
                    message = client_socket.recv(message_length)
                    try:
                        message = message.decode('utf-8')
                    except:
                        decripted_msg = crypto_utils().decrypt_message(message, self.SRC_KEY)
                        message = decripted_msg.decode('utf-8')

                    if 'PUBLIC KEY' in message:
                        self.DST_KEY = message
                        #print(self.DST_KEY)
                        print("received public key, all comunication will now be encrypted")
                    else:
                    # Print message
                        message = message
                        print(f'Answer: {message}')

            except IOError as e:
                # This is normal on non blocking connections - when there are no incoming data error is going to be raised
                # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
                # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
                # If we got different error code - something happened
                
                if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                    print('Reading error: {}'.format(str(e)))
                    sys.exit()

                # We just did not receive anything
                continue

            #except Exception as e:
                # Any other exception - something happened, exit
                
                #print('Reading error: {}'.format(str(e)))
                #sys.exit()