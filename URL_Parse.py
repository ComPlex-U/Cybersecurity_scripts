from urllib.parse import urlparse
import socket
url="codespeedy.com"

#o = urlparse('http://www.cwi.nl:80/%7Eguido/Python.html')
o = urlparse(url)
o
print(o)

o.scheme
print(o.scheme)
o.port
print(o.port)
o.geturl()
print(o.geturl())
print("IP:",socket.gethostbyname(url))