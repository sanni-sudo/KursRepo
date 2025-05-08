# sec_watch_1.py -> Nytt försök av Slutuppgiften - Övervakar nätverkstrafik i realtid
# Skapat av: Sanna Nilsson, 2 Maj 2025
# Syfte: Bygga ett Python-program som kan upptäcka attacker mot nätverket i 
# realtid och kan vidta åtgärder vid misstänkta attacker.
  
# Krav:
# -> Läsa loggfilen med tid, källa, destination, port och protokoll
# -> Flagga anslutningar till ovanliga portar och IPn med fler än 100 anslutningar
# -> Skicka e-postvarningar vid upptäckta händelser
# -> Spara en CSV-rapport med fynden
# -> Simulera UFW-blockering
# -> Logga allt
# -> Kör i en slinga för att repetera
 
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
CSV_FILE = os.path.join(LOG_DIR, "attack_report.csv")
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

def cleanup():
    # Rensa loggfilen och CSV-filen
    # Om filen inte finns skapas den
    with open(LOG_FILE, "w") as file:
        print(f"Rensar loggfilen: {LOG_FILE}")
        log_message("INFO", f"Rensar loggfilen: {LOG_FILE}")

    with open(CSV_FILE, "w") as file:
        print(f"Rensar CSV-filen: {CSV_FILE}")
        log_message("INFO", f"Rensar CSV-filen: {CSV_FILE}")

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

    try:
        result = subprocess.run(["sudo", "ufw", "deny"], capture_output=True, text=True)
        log_message("INFO", "Blockerade IP med UFW")
    except:
        log_message("ERROR", "Kunde inte blockera IP")
        print("Kunde inte köra block-kommandot!")  
       

# Validering---------------------------
setup_logging()
cleanup()
log_message("INFO", "Startar nätverkskontrollen...")

if not os.path.exists(TRAFFIC_LOG):
    log_message("ERROR", "Loggilen finns inte!")
    print("ERROR: Loggfilen saknas")
    exit(1)

# Huvudlogik-----------------------------

try:
    connections = {}
    with open(TRAFFIC_LOG, "r") as file:
        start_time = None
        ok_con =  0
        susp_port = 0
        many_con = []
        lines = 0
        for line in file:
            parts = line.strip().split(",")
            current_time = extract_timestamp(line)
            lines += 1
            if not current_time:
                continue
            if not start_time:
                start_time = current_time
                print("Starttid:", start_time)
            if (current_time - start_time) >= timedelta(minutes=5):
                print("5 minuter har passerat.")
                start_time = current_time
                log_message("INFO", f"Pausar 20 sekunder. Ny starttid:  {start_time}")
                log_message("INFO", "Statistik för de senaste 5 minuterna")
                log_message("INFO", f"Antal anslutningar: {lines}")
                log_message("INFO", f"Antal OK anslutningar: {ok_con}")
                log_message("INFO", f"Antal misstänkta portar: {susp_port}")

                print(f"Pausar 20 sekunder. Ny starttid: ", {start_time})
                print("Statistik för de senaste 5 minuterna")
                print(f"Antal anslutningar: {lines}")
                print(f"Antal OK anslutningar: {ok_con}")
                print(f"Antal misstänkta portar: {susp_port}")

                unique_ips = set(many_con)
                for ip in unique_ips:
                    print(f"IP {ip} har fler än 100 anslutningar")
                    log_message("WARNING", f"IP {ip} har fler än 100 anslutningar")
                with open(CSV_FILE, "a") as file:
                    file.write("IP, Antal\n")
                    for ip, count in connections.items():
                        file.write(ip + "," + str(count) + "\n")  
                        file.flush()          
                ok_con = 0
                susp_port = 0
                many_con = []
                time.sleep(20)

            if len(parts) >= 4:
                port = int(parts[3].strip())
                if port < 1024 and port not in [22, 80,443]:
                    message = f"Hittat ovanlig port {port} i raden: {line.strip()}"
                    log_message("WARNING", message)
                    print("WARNING: ", message)
                    susp_port += 1
                    send_email_alert(
                    subject="IDS-varning: Misstänkt port upptäckt",
                    body=f"Port {port} upptäcktes i följande rad:\n{line.strip()}")                   
                else:
                    ok_con += 1                                                                                      
            
            # Låtsas att filen skriver tid, adress               
            if len(parts) >=2:
                ip = parts[1]
                connections[ip] = connections.get(ip, 0) + 1

                if connections[ip] > 100:
                    many_con.append(ip)
                    message = "IP" + ip + " har för många anslutningar"
                    log_message("WARNING", message)
                    print("WARNING:", message)
                    block_ufw(ip.strip())
                    send_email_alert(
                    subject="IDS-varning: Misstänkt många anslutningar upptäckt",
                    body=f"IP-adress: {ip} har fler än 100 anslutingar under senaste 5 minuters perioden. Blockerar med UFW")                   

    log_message("INFO", "Sparade rapporten")
    print("IP-rapport har sparats på systemet!")
    log_message("INFO", "Klar med kontrollen")
    print("Klar med  kontroll av loggfilen")
    log_message("INFO", "Loggfilen kontrollerad")
except Exception as e:
    log_message("ERROR", "Något gick fel!")
    exit(1)


