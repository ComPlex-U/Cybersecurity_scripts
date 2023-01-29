import socket
import time
import threading
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen.canvas import Canvas

from queue import Queue

socket.setdefaulttimeout(0.25)
print_lock = threading.Lock()

pdf_file = open("resultados_analise_portos.pdf", "wb")
canvas = Canvas(pdf_file, pagesize=letter)

canvas.setFont("Helvetica", 12)

target = input('Enter the host to be scanned: ')
t_IP = socket.gethostbyname(target)

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
    
canvas.drawString(1 * inch, 10 * inch, "portos abertos na maquina com ip:")
for port in open:
    canvas.drawString(1 * inch, (10 - 0.5) * inch, str(t_IP), str(port))

canvas.save()
pdf_file.close()
q.join()