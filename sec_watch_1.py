# sec_watch_1.py -> Nytt försök av Slutuppgiften i Python-skriptet
# Skapat av: Sanna Nilsson, 5 maj 2025

# Syfte:
# Läsa Nätverkslogg
# Flagga vid misstänkt portanvändning
# Räkna IP-anslutningar
# # Skicka e-post
# Spara rapport
# Simulera IP-blockering
# 
# Kravbild:
# -> Läsa loggfilen med tid, källa, destination, port och protokoll
# -> Flagga anslutningar till port 8080 och/eller IPn med fler än 5 anslutningar
# -> Skicka e-postvarningar vid upptäckta händelser
# -> Spara en CSV-rapport med fynden
# -> Simulera UFW-blockering
# -> Logga allt
# -> Kör i en slinga för att repetera
# 
# Modulimportering-----------------------------
import os
import logging
import time
import re
import csv
import smtplib
import subprocess
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr

# Konfigurationer------------------------------

LOG_DIR = "/home/testkali/KursRepo/Test_Monitor_Dir"
LOG_FILE = os.path.join(LOG_DIR, "monitor.log")
TRAFFIC_LOG = os.path.join(LOG_DIR, "network_traffic.log")
EMAIL_FROM = "testkali@localhost"
EMAIL_TO = "testkali@localhost"


# Loggningsfunktioner---------------------------

def setup_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

def log_message(level, message):
    if level == "INFO":
        logging.info(message)
    elif level == "WARNING":
        logging.warning(message)
    elif level == "ERROR":
        logging.error(message)

# Validering---------------------------
setup_logging()
log_message("INFO", "Startar nätverkskontrollen...")

if not os.path.exists(TRAFFIC_LOG):
    log_message("ERROR", "Loggilen finns inte!")
    print("ERROR: Loggfilen saknas")
    exit(1)

# Huvudlogik-----------------------------

try:
    count = 3
    while count > 0:
        connections = {}

        with open(TRAFFIC_LOG, "r") as file:
            for line in file:
                #match = re.search(r"\b(\d{1,5})\b", line)
                parts = line.strip().split(",")
                if len(parts) >= 4:
                    port = int(parts[3].strip())
                #if match:
                #    port = int(match.group(1))
                    if port < 1024 and port not in [22, 80,443]:
                        message = f"Hittat ovanlig port {port} i raden: {line.strip()}"
                        log_message("WARNING", message)
                        print("WARNING: ", message)
                        try:
                            msg = MIMEText("Misstänkt/a port/ar under 1024 upptäckt/a i trafiken", "plain", "utf-8")
                            msg["From"] = formataddr((str(Header("Nätverksövervakning", "utf-8")), EMAIL_FROM))
                            msg["To"] = EMAIL_TO
                            msg["Subject"] = Header("Nätverksvarning", "utf-8")

                            server = smtplib.SMTP("localhost", 25)
                            server.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
                            server.quit()

                            log_message("INFO", "Skickade e-postvarning")
                            print("Skickade e-post")
                        except Exception as e:
                            log_message("ERROR", f"Kunde inte skicka epost: {str(e)}")
                            print("ERROR: Kunde inte skicka epostvarning:", str(e))
                # Låtsas att filen skriver tid, adresss
                #parts = line.split(",")
                if len(parts) >=2:
                    ip = parts[1]
                    connections[ip] = connections.get(ip, 0) + 1

                    if connections[ip] > 5:
                        message = "IP" + ip + " har för många anslutningar"
                        log_message("WARNING", message)
                        print("WARNING:", message)
        with open("/home/testkali/KursRepo/Test_Monitor_Dir/suspicious_ips.csv", "w") as file:
            file.write("IP, Antal\n")
            for ip, count in connections.items():
                file.write(ip + "," + str(count) + "\n")
        log_message("INFO", "Sparade rapporten")
        print("IP-rapport har sparats på systemet!")

#        try:
#            result = subprocess.run(["sudo", "ufw", "deny"], capture_output=True, text=True)
#            log_message("INFO", "Blockerade IP med UFW")
#        except:
#            log_message("ERROR", "Kunde inte blockera IP")
#            print("Kunde inte köra block-kommandot!")

        log_message("INFO", "Klar med en kontroll")
        print("Klar med en kontroll")
        time.sleep(10)
        count = count -1
    log_message("INFO", "Loggen kontrollerad tre gånger")
except Exception as e:
    log_message("ERROR", "Något gick fel!")
    exit(1)



