#python version 3
import socket
import os
import os.path
from _thread import *

host = "127.0.0.1" #Server address
port = 12345 #Port of Server
thread_count = 0
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.bind((host,port)) #bind server

except socket.error as e:
    print(str(e))

print("Waiting for a connection...")
s.listen(5)


def uniquify(filename, extension, path):
    '''
    Make sure that no file overwrite happens.

    Params
    ------
    filename : str
        The filename of the file to check if exists.
    extension : str
        The extension of the file.
    path : str
        The path to check if exist or not.

    Returns
    -------
    path : str
        A path that doesn't exist
    '''
    counter = 1

    while os.path.exists(path):
        path = filename + "_" + str(counter) + extension
        counter += 1

    return path


def thread_client(conn):

    client_id = conn.recv(1024)

    conn.send(client_id)
    client_id = client_id.decode()
    print("\nID Sent: " + str(client_id))

    # Check if there is a directory qith the id
    folder = client_id
    os.chdir(".")
    if os.path.isdir(folder):
        print("Exists folder")
    else:
        print("Doesn't exist folder")
        os.mkdir(folder)

    while True:
        data = conn.recv(1024)

        if b'WRITE' in data:
            path = uniquify("./" + client_id + '/file_' + str(client_id), '.txt', "./" + client_id + '/file_' + str(client_id) + '.txt')
            f = open(path,'wb')
            while(data):
                data = data.replace(b'WRITE',b'')
                f.write(data)
                data = conn.recv(1024)
            f.close()

        elif b'READ' in data:

            try:
                for filename in os.listdir("./" + folder):
                    print(filename)
                    with open(os.path.join("./" + folder, filename), 'rb') as f: # open in readonly mode
                        content = f.read()
                        conn.send(b'LIMITER'+content)
                    f.close()
                raise ValueError('A very specific bad thing happened')
            except Exception as e:
                print(e)
                conn.send(b'You have no messages!')

    print("GOODBYE")
    conn.close()


while True:
    (conn, addr) = s.accept()

    print('Connected to: ' + addr[0] + ':' + str(addr[1]))
    print("Thread Number: " + str(thread_count))

    start_new_thread(thread_client, (conn, ))
    thread_count += 1

conn.close()