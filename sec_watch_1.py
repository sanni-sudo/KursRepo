# sec_watch_1.py -> Nytt försök - Övervakar nätverkstrafik i realtid 
# 
# Skapat av: Sanna Nilsson, 2 Maj 2025
# Syfte: Bygga ett Python-program som kan upptäcka attacker 
# mot nätverket i realtid och kan vidta åtgärder vid 
# misstänkta attacker.

# Krav
# Läsa en dynamisk loggfil (network_traffic.log) 
# Analyserar trafiken 
# Skickar e-post varningar till en administratör
# Genererar en CSV-rapport
 
# Modulimportering-----------------------------
import os
import logging
import time
import re
import csv
import smtplib
from email.message import EmailMessage 
from datetime import datetime, timedelta
import subprocess

# Konfigurationer------------------------------

LOG_DIR = "/home/testkali/KursRepo/Test_Monitor_Dir"
LOG_FILE = os.path.join(LOG_DIR, "monitor.log")
TRAFFIC_LOG = os.path.join(LOG_DIR, "network_traffic.log")
# För intern/test e-post
SMTP_SERVER = "localhost"
SMTP_PORT = 25
EMAIL_FROM = "testkali@testkalilinuxcl-2.labb.local"
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

# Funktioner---------------------------
def send_email_alert(subject, body):
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO
        msg.set_content(body)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.send_message(msg)

        log_message("INFO", "Skickade e-postvarning")
        print("E-postvarning skickad!")
    except Exception as e:
        log_message("ERROR", f"Kunde inte skicka epost: {str(e)}")
        print("ERROR: Kunde inte skicka epostvarning:", str(e))

def extract_timestamp(line):
    parts = line.strip().split(",")
    if parts:
        return datetime.strptime(parts[0].strip(), "%Y-%m-%d %H:%M:%S")
    return None

def block_ufw(IP):
    try:
        # Kör kommandot med sudo
        result = subprocess.run(
            ["sudo", "ufw", "deny", "from", IP],
            capture_output=True,
            text=True,
            check=True
        )
        print(f"Blockerade IP: {IP}")
        log_message("INFO", f"Blockerade IP:{IP} med UFW")
    except subprocess.CalledProcessError as e:
        print(f"Kunde inte blockera IP {IP}: {e.stderr}")
        log_message("ERROR" f"Kunde inte blockera IP {IP}: {e.stderr}")

# Validering---------------------------
setup_logging()
log_message("INFO", "Startar nätverkskontrollen...")

if not os.path.exists(TRAFFIC_LOG):
    log_message("ERROR", "Loggilen finns inte!")
    print("ERROR: Loggfilen saknas")
    exit(1)

# Huvudlogik-----------------------------

#suspicious_ports = []

try:
    connections = {}
    with open(TRAFFIC_LOG, "r") as file:
        start_time = None
        for line in file:
            parts = line.strip().split(",")
            current_time = extract_timestamp(line)
            if not current_time:
                continue
            if not start_time:
                start_time = current_time
                print("Starttid:", start_time)
            if (current_time - start_time) >= timedelta(minutes=5):
                print("5 minuter har passerat.")
                start_time = current_time
                print("Pausar 10 sekunder. Ny starttid: ", start_time)
                time.sleep(10)


            if len(parts) >= 4:
                port = int(parts[3].strip())
                if port < 1024 and port not in [22, 80,443]:
                    message = f"Hittat ovanlig port {port} i raden: {line.strip()}"
                    log_message("WARNING", message)
                    print("WARNING: ", message)

#                suspicious_ports.append(f"Port {port} upptäcktes i följande rad:\n{line.strip()}")

                    send_email_alert(
                    subject="IDS-varning: Misstänkt port upptäckt",
                    body=f"Port {port} upptäcktes i följande rad:\n{line.strip()}"
         )                                                                                     
            
                # Låtsas att filen skriver tid, adress               
                if len(parts) >=2:
                    ip = parts[1]
                    connections[ip] = connections.get(ip, 0) + 1

                    if connections[ip] > 100:
                        message = "IP" + ip + " har för många anslutningar"
                        log_message("WARNING", message)
                        block_ufw(ip.strip())
    with open("/home/testkali/KursRepo/Test_Monitor_Dir/suspicious_ips.csv", "w") as file:
        file.write("IP, Antal\n")
        for ip, count in connections.items():
            file.write(ip + "," + str(count) + "\n")

    log_message("INFO", "Sparade rapporten")
    print("IP-rapport har sparats på systemet!")
    
# Send a summary email with all suspicious ports
#    if suspicious_ports:
#        log_message("DEBUG", f"Sammanfattning av misstänkta portar: {suspicious_ports}")
#        summary_body = "Sammanfattning av upptäckta misstänkta portar:\n\n" + "\n".join(suspicious_ports)
#        send_email_alert(
#            subject="IDS-varning: Sammanfattning av misstänkta portar",
#            body=summary_body
#    )
#        log_message("INFO", "Sammanfattningsmail skickat.")
#    else:
#        log_message("INFO", "Inga misstänkta portar att rapportera.")
#        )

    log_message("INFO", "Klar med kontrollen")
    print("Klar med  kontroll av loggfilen")
    log_message("INFO", "Loggfilen kontrollerad")

except Exception as e:
    log_message("ERROR", "Något gick fel!")
    exit(1)



