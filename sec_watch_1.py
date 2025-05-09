# sec_watch_1.py -> Slutuppgiften - Övervakar nätverkstrafik i realtid
# Skapat av: Sanna Nilsson, 2 Maj 2025
# Syfte: Bygga ett Python-program som kan upptäcka attacker mot nätverket i 
# realtid och kan vidta åtgärder vid misstänkta attacker.
  
# Krav:
# -> Läsa loggfilen med tid, IP, port och protokoll i 5-minuters intervaller
# -> Flagga anslutningar till ovanliga portar och IPn med fler än 100 anslutningar
# -> Skicka e-postvarningar vid upptäckta händelser
# -> Spara en CSV-rapport med fynden
# -> Simulera UFW-blockering
# -> Logga allt
 
# Modulimportering-----------------------------

import os               # För att hantera filsystemet
import logging          # För loggning
import time             # För att pausa mellan iterationer
import smtplib          # För att skicka e-post
from email.message import EmailMessage      # För att skapa e-postmeddelanden
from datetime import datetime, timedelta    
import subprocess       # För att köra systemkommandon

# Konfigurationer------------------------------

LOG_DIR = "/home/testkali/KursRepo/Test_Monitor_Dir"        # Loggfilens katalog
LOG_FILE = os.path.join(LOG_DIR, "monitor.log")             # Loggfilens namn
CSV_FILE = os.path.join(LOG_DIR, "attack_report.csv")       # CSV-filens namn
TRAFFIC_LOG = os.path.join(LOG_DIR, "network_traffic.log")  # Loggfilen för nätverkstrafik
# För intern/test e-post
SMTP_SERVER = "localhost"                                   # SMTP-serverns adress
SMTP_PORT = 25                                              # SMTP-serverns port      
EMAIL_FROM = "testkali@testkalilinuxcl-2.labb.local"        # Avsändaradress
EMAIL_TO = "testkali@localhost"                             # Mottagaradress       


# Loggningsfunktioner---------------------------

def setup_logging():                # Funktion som konfigurerar loggning
    logging.basicConfig(            # Konfigurerar loggning          
        filename=LOG_FILE,          # Loggfilens namn
        level=logging.INFO,         # Loggnivå
        format="%(asctime)s [%(levelname)s] %(message)s",   # Loggformat
        datefmt="%Y-%m-%d %H:%M:%S" # Datumformat
    )

def log_message(level, message):    # Funktion som loggar meddelanden på olika nivåer(INFO, WARNING, ERROR)
    if level == "INFO":             # Om loggnivån är INFO
        logging.info(message)       # Logga meddelandet som INFO
    elif level == "WARNING":        # Om loggnivån är WARNING
        logging.warning(message)    # Logga meddelandet som WARNING
    elif level == "ERROR":          # Om loggnivån är ERROR
        logging.error(message)      # Logga meddelandet som ERROR

# Funktioner---------------------------

def send_email_alert(subject, body):    # Funktion som skickar e-postvarningar

    try:                                                                
        msg = EmailMessage()            # Skapar e-postmeddelande
        msg["Subject"] = subject        # Ämnet för e-postmeddelandet
        msg["From"] = EMAIL_FROM        # Avsändaradressen
        msg["To"] = EMAIL_TO            # Mottagaradressen
        msg.set_content(body)           # Innehållet i e-postmeddelandet

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:   # Ansluter till SMTP-servern
            server.send_message(msg)            # Skickar e-postmeddelandet

        log_message("INFO", "Skickade e-postvarning")   # Loggar att e-postvarning skickades
        print("E-postvarning skickad!")             # Skriver ut meddelande om att e-postvarning skickades
    except Exception as e:                          # Hanterar eventuella fel
        log_message("ERROR", f"Kunde inte skicka epost: {str(e)}")  # Loggar felmeddelande
        print("ERROR: Kunde inte skicka epostvarning:", str(e))     # Skriver ut felmeddelande

def extract_timestamp(line):            # Funktion som extraherar tidsstämpel från loggfilen
    parts = line.strip().split(",")     # Dela upp raden i delar
    if parts:                           # Om det finns delar
        return datetime.strptime(parts[0].strip(), "%Y-%m-%d %H:%M:%S")     # Konvertera till datetime-objekt
    return None                # Om ingen tidsstämpel hittades, returnera None  

def cleanup():                 # Funktion som rensar tidigare logg- och CSV-filer                         
    # Om filen inte finns skapas den
    with open(LOG_FILE, "w") as file:       # Öppnar loggfilen för skrivning      
        print(f"Rensar loggfilen: {LOG_FILE}")  # Skriver ut meddelande om att loggfilen rensas     
        log_message("INFO", f"Rensar loggfilen: {LOG_FILE}")        # Loggar att loggfilen rensas

    with open(CSV_FILE, "w") as file:       # Öppnar CSV-filen för skrivning
        print(f"Rensar CSV-filen: {CSV_FILE}")  # Skriver ut meddelande om att CSV-filen rensas
        log_message("INFO", f"Rensar CSV-filen: {CSV_FILE}")        # Loggar att CSV-filen rensas

def block_ufw(IP):                      # Funktion som blockerar IP-adress med UFW
    try:
        # Kör kommandot med sudo
        result = subprocess.run(        # Kör kommandot med subprocess
            ["sudo", "ufw", "deny", "from", IP],    # Blockera IP
            capture_output=True,                    # Fånga utdata
            text=True,                              # Använd textläge           
            check=True                        # Kontrollera om kommandot lyckades       
        )

        print(f"Blockerade IP: {IP}")   # Skriver ut meddelande om att IP-blockering lyckades
        log_message("INFO", f"Blockerade IP:{IP} med UFW")  # Loggar att IP-blockering lyckades
    except subprocess.CalledProcessError as e:      # Hanterar eventuella fel
        print(f"Kunde inte blockera IP {IP}: {e.stderr}")       # Skriver ut felmeddelande
        log_message("ERROR" f"Kunde inte blockera IP {IP}: {e.stderr}") # Loggar felmeddelande

    try:            # Om det inte går att blockera IP med subprocess
        result = subprocess.run(["sudo", "ufw", "deny"], capture_output=True, text=True)
        log_message("INFO", "Blockerade IP med UFW")    # Loggar att IP-blockering lyckades
    except:             
        log_message("ERROR", "Kunde inte blockera IP")  # Loggar felmeddelande
        print("Kunde inte köra block-kommandot!")   # Skriver ut felmeddelande 
       

# Validering---------------------------
setup_logging()     # Startar loggning
cleanup()           # Rensar tidigare logg- och CSV-filer
log_message("INFO", "Startar nätverkskontrollen...")        # Loggar att övervakningen börjar

if not os.path.exists(TRAFFIC_LOG):     # Kontrollerar om loggfilen finns
    log_message("ERROR", "Loggilen finns inte!")    # Loggar felmeddelande
    print("ERROR: Loggfilen saknas")    # Skriver ut felmeddelande
    exit(1)                 # Avslutar programmet om loggfilen saknas

# Huvudlogik-----------------------------
# Huvuddelen av ett IDS-program som övervakar nätverkstrafik och letar efter misstänkta aktiviteter

try:
    connections = {}        # Ordbok för att lagra IP-adresser och deras anslutningar
    with open(TRAFFIC_LOG, "r") as file:    # Öppnar loggfilen för läsning
        start_time = None       # Starttid för övervakning
        ok_con =  0         # Antal godkända anslutningar
        susp_port = 0       # Antal misstänkta portar
        many_con = []       # Lista för att lagra IP-adresser med många anslutningar
        lines = 0           # Antal rader i loggfilen
        for line in file:           # Loopar igenom varje rad i loggfilen
            parts = line.strip().split(",")          # Dela upp raden i delar
            current_time = extract_timestamp(line)   # Extrahera tidsstämpel
            lines += 1              # Öka antalet rader
            if not current_time:    # Om ingen tidsstämpel hittades, hoppa över raden
                continue            # Hoppa över raden
            if not start_time:      # Om starttid inte är satt, sätt den till nuvarande tid
                start_time = current_time           # Sätt starttid
                print("Starttid:", start_time)      # Skriver ut starttid
            if (current_time - start_time) >= timedelta(minutes=5):    # Om 5 minuter har passerat
                print("5 minuter har passerat.")    # Skriver ut meddelande
                start_time = current_time           # Sätt ny starttid
                log_message("INFO", f"Pausar 20 sekunder. Ny starttid:  {start_time}")  
                # Loggar ny starttid                
                log_message("INFO", "Statistik för de senaste 5 minuterna")
                # Loggar statistik för de senaste 5 minuterna
                log_message("INFO", f"Antal anslutningar: {lines}")
                # Loggar antal anslutningar
                log_message("INFO", f"Antal OK anslutningar: {ok_con}") 
                # Loggar antal godkända anslutningar
                log_message("INFO", f"Antal misstänkta portar: {susp_port}")    
                # Loggar antal misstänkta portar

                print(f"Pausar 20 sekunder. Ny starttid: ", {start_time})   
                # Skriver ut ny starttid
                print("Statistik för de senaste 5 minuterna")   
                # Skriver ut statistik
                print(f"Antal anslutningar: {lines}")   
                # Skriver ut antal anslutningar
                print(f"Antal OK anslutningar: {ok_con}")   
                # Skriver ut antal godkända anslutningar
                print(f"Antal misstänkta portar: {susp_port}")  # Skriver ut antal misstänkta portar

                unique_ips = set(many_con)      # Skapar en uppsättning av unika IP-adresser
                for ip in unique_ips:           # Loopar igenom varje unik IP-adress
                    print(f"IP {ip} har fler än 100 anslutningar")  # Skriver ut meddelande
                    log_message("WARNING", f"IP {ip} har fler än 100 anslutningar") # Loggar meddelande
                with open(CSV_FILE, "a") as file:   # Öppnar CSV-filen för skrivning
                    file.write("IP, Antal\n")       # Skriver rubriker i CSV-filen
                    for ip, count in connections.items():   # Loopar igenom varje IP-adress och dess antal
                        file.write(ip + "," + str(count) + "\n")    # Skriver IP-adress och antal i CSV-filen
                        file.flush()                # Tömmer bufferten        
                ok_con = 0          # Nollställer antalet godkända anslutningar    
                susp_port = 0       # Nollställer antalet misstänkta portar
                many_con = []       # Nollställer listan med många anslutningar
                time.sleep(20)      # Pausar i 20 sekunder

            if len(parts) >= 4:     # Om det finns minst 4 delar i raden
                port = int(parts[3].strip())        # Extrahera portnumret
                if port < 1024 and port not in [22, 80,443]:    # Om portnumret är mindre än 1024 och inte är en vanlig port
                    message = f"Hittat ovanlig port {port} i raden: {line.strip()}" # Skapa meddelande
                    log_message("WARNING", message)     # Logga meddelandet
                    print("WARNING: ", message)         # Skriver ut meddelande
                    susp_port += 1                      # Öka räknaren för misstänkta portar
                    
                    send_email_alert(       # Skicka e-postvarning          
                    subject="IDS-varning: Misstänkt port upptäckt", # Ämnet för e-postvarningen
                    body=f"Port {port} upptäcktes i följande rad:\n{line.strip()}")     
                    # Innehållet i e-postvarningen                  
                else:
                    ok_con += 1             # Öka räknaren för godkända anslutningar                                                                                   
            
            # Låtsas att filen skriver tid, adress               
            if len(parts) >=2:      # Om det finns minst 2 delar i raden
                ip = parts[1]       # Extrahera IP-adressen
                connections[ip] = connections.get(ip, 0) + 1        # Öka antalet anslutningar för IP-adressen

                if connections[ip] > 100:       # Om antalet anslutningar för IP-adressen är större än 100
                    many_con.append(ip)         # Lägg till IP-adressen i listan med många anslutningar
                    message = "IP" + ip + " har för många anslutningar"     # Skapa meddelande
                    log_message("WARNING", message)     # Logga meddelandet
                    print("WARNING:", message)          # Skriver ut meddelande
                    
                    block_ufw(ip.strip())   # Blockera IP-adressen med UFW  
                    
                    send_email_alert(       # Skicka e-postvarning
                    subject="IDS-varning: Misstänkt många anslutningar upptäckt",       # Ämnet för e-postvarningen
                    body=f"IP-adress: {ip} har fler än 100 anslutingar under senaste 5 minuters perioden. Blockerar med UFW")   
                    # Innehållet i e-postvarningen                  

    log_message("INFO", "Sparade rapporten")        # Loggar att rapporten sparades
    print("IP-rapport har sparats på systemet!")    # Skriver ut meddelande om att rapporten sparades
    log_message("INFO", "Klar med kontrollen")      # Loggar att övervakningen är klar
    print("Klar med  kontroll av loggfilen")        # Skriver ut meddelande om att övervakningen är klar
    log_message("INFO", "Loggfilen kontrollerad")   # Loggar att loggfilen kontrollerades
except Exception as e:                      # Om något oväntat händer i koden (fel, krasch osv) loggas
    # ett felmeddelande och programmet avslutas
    log_message("ERROR", "Något gick fel!")         # Loggar felmeddelande
    exit(1)                      


