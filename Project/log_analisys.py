
import logging
import socket

# Configure o endereço e a porta do syslog server
syslog_server = "10.0.0.1"
syslog_port = 8090

# Crie um socket UDP para se conectar ao syslog server
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Crie dicionários para armazenar as informações de acesso
http_accesses = {}
ssh_accesses = {}

# Receba os logs do syslog server
while True:
    data, address = sock.recvfrom(1024)
    # Verifique se o log é de um serviço HTTP ou SSH
    if "httpd" in data.decode():
        # Extraia as informações de IP e código de resposta
        ip, response_code = data.decode().split()[0], data.decode().split()[8]
        # Verifique se o código de resposta é igual a "200" (sucesso)
        if response_code == "200":
            # Se sim, adicione o acesso ao dicionário
            if ip in http_accesses:
                http_accesses[ip] += 1
            else:
                http_accesses[ip] = 1
    elif "sshd" in data.decode():
        # Extraia as informações de IP e mensagem de log
        ip, message = data.decode().split()[0], " ".join(data.decode().split()[3:])
        # Verifique se a mensagem de log indica uma tentativa de login inválida
        if "invalid" in message.lower():
            # Se sim, adicione a tentativa de login inválida ao dicionário
            if ip in ssh_accesses:
                ssh_accesses[ip] += 1
            else:
                ssh_accesses[ip] = 1

# Imprima os resultados
print("Acessos HTTP:")
for ip, count in http_accesses.items():
    print(f"{ip}: {count} acessos")

print("\nTentativas de login SSH inválidas:")
for ip, count in ssh_accesses.items():
    print(f"{ip}: {count} tentativas de login inválidas")

# Feche o socket
sock.close()