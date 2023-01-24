import pandas as pd
from geoip import geolite2

# Carrega os arquivos de log em um DataFrame do pandas
http_logs = pd.read_csv("http_logs.log", sep=" ", names=["timestamp", "ip", "status", "url"])
ssh_logs = pd.read_csv("ssh_logs.log", sep=" ", names=["timestamp", "ip", "status"])

# Concatena os dois dataframes
logs = pd.concat([http_logs, ssh_logs])

# Cria as colunas pais e timestamp
logs["pais"] = None
logs["timestamp"] = pd.to_datetime(logs["timestamp"], format='%Y-%m-%d %H:%M:%S')

#Para cada linha do log, determina o pais de origem
for index, row in logs.iterrows():
    match = geolite2.lookup(row["ip"])
    if match is not None:
        logs.at[index, "pais"] = match.country

# Seleciona as tentativas de acesso inválidas
invalid_logs = logs[logs["status"] != "200"]
valid_logs = logs[logs["status"] == "200"]

# Agrupa os acessos por pais
access_by_country = logs.groupby("pais").count()["ip"].reset_index()

# Imprime os resultados no console
print("Origem dos acessos:")
print(access_by_country)

print("Tentativas de acesso inválidas:")
print(invalid_logs[["ip", "timestamp", "status", "url"]])

print("Tentativas de acesso válidas:")
print(valid_logs[["ip", "timestamp", "status", "url"]])