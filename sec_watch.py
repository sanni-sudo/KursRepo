# sec_watch.py - Övervakar nätverkstrafik i realtid 
# Skapat av: Sanna Nilsson, 2 Maj 2025
# Syfte: Bygga ett Python-program som kan upptäcka attacker 
# mot nätverket i realtid och kan vidta åtgärder vid 
# misstänkta attacker.

# Krav
# Läsa en statisk (dynamisk) loggfil (network_traffic.log) 
# Analyserar trafiken 
# Skickar e-post varningar till en administratör
# Genererar en CSV-rapport

# Importera moduler för våra behov
from datetime import datetime, timedelta    # Anger datum och tid. timedelta används för att räkna med tid
import csv          # Hanterar CSV-filer (Comma Separated Values), vilket används för att läsa och skriva loggar eller rapporter i CSV-format
import os           # Arbetar med filer och kataloger
import logging      # Skapar loggar med tidstämplar och nivåer (INFO, WARNING, ERROR)
import time         # Arbetar med tidsfördröjning och tidsfunktioner
import re           # Reguljära uttryck som används för att söka efter mönster i loggrader
from collections import defaultdict     # En smidigare version av dict som automatiskt initierar värden 
import smtplib      # Importerar SMTP-klienten för att skicka e-post
from email.message import EmailMessage  # Skapar ett e-postmeddelande i rätt format
import subprocess

# Konfiguration
LOG_DIR = "/home/testkali/KursRepo/Test_Monitor_Dir"
LOG_FILE = os.path.join(LOG_DIR, "network_traffic.log")
REPORT_FILE = os.path.join(LOG_DIR, "attack_report_test.csv")

# Inställningar för intern/test e-post
SMTP_SERVER = "localhost"  # Ingen autentisering
SMTP_PORT = 25             # Standardport
EMAIL_SENDER = "testkali@testkalilinuxcl-2.labb.local"
EMAIL_RECEIVER = "testkali@localhost"

# Funktioner

# Funktion för att konfigurera reporting
def setup_reporting():
    # Skapa katalog om den inte finns
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    # Om rapportfilen inte finns, skapa den med en header (rubrikrad)
    if not os.path.exists(REPORT_FILE):
# Öppnar filen i skrivläge ("w" = write). Om filen inte finns, skapas den
# newline="" förhindrar att extra tomma rader skrivs i CSV på Windows
        with open(REPORT_FILE, mode="w", newline="") as file:
# Skapar en CSV-skrivare som vi använder för att skriva rader i filen      
            writer = csv.writer(file)       
# Skriver header till CSV-filen. Denna header innehåller kolumnerna: "Timestamp", "Alert Type", och "Description"
            writer.writerow(["Timestamp", "Alert Type", "Description"])  
        log_message("INFO", "Rapportloggning initierad och CSV-header skapad.")
# Meddelandet säger att rapportfilen är skapad och har fått en header
    else:
        open(REPORT_FILE, 'w').close() #Om filen finns öppna den och rensa den
        log_message("INFO", "Rapportloggning initierad.")


# Funktion för att generera rapport till CSV
def log_message(level, message, timestamp=None):
    # Kontrollera om rapportfilen existerar, om inte, skapa den med en header
    if not os.path.exists(REPORT_FILE):    
        with open(REPORT_FILE, mode="w", newline="") as file:            
            writer = csv.writer(file)
# Skriver header med tre kolumner: Timestamp: tidpunkt när rapporten skapades, 
# Level: loggnivå och Message: loggmeddelandet
            writer.writerow(["Timestamp", "Level", "Message"]) 
    # Skriv rapporten till CSV
    # Öppnar rapportfilen i append-läge ("a"), dvs vi lägger till längst ner i rapporten
    with open(REPORT_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, level, message])  # Lägg till rapportposten

# Validera att loggkatalogen finns 
def setup_path():
# Loggar en informationsrad till CSV-rapporten med texten och
# använder tidigare definierade funktionen log_message().
    log_message("INFO", "Kontrollerar om katalogen finns") 
# Kontrollerar om katalogen (LOG_DIR) finns på filsystemet
# os.path.exists() returnerar False om sökvägen inte finns 
    if not os.path.exists(LOG_DIR):
# Loggar ett felmeddelande till CSV-rapportfilen
        log_message("ERROR", f"Katalogen {LOG_DIR} finns inte.")
# Skriver ut ett felmeddelande till konsolen, så att administratören ser problemet direkt
        print(f"ERROR: Katalogen {LOG_DIR} finns inte!")
# Avslutar programmet med exit-kod 1 för att ett fel uppstod (1 är fel, 0 är OK)
        exit(1)

# Funktion som väntar på nya rader i loggfilen
def tail_log_file(file_path):               # file_path (sökvägen till loggfilen network_traffic.log)
# Övervaka loggfilen i realtid och returnera nya rader när de skrivs till filen
    with open(file_path, "r") as file:      # Öppnar filen i läsläge ("r") och skapar ett filobjekt "file"
        file.seek(0, os.SEEK_END)       # Hoppar till slutet av filen och läser endast nya rader som tillkommit
# Startar en oändlig loop som kommer fortsätta så länge programmet körs
# Bevakar konstant nya rader som skrivs till loggfilen
        while True:
            line = file.readline()     # Försöker läsa nästa rad från filen
            if not line:            # Om line är tom (dvs. ingen ny rad har kommit)...
                time.sleep(1)       # Vänta en sekund på nya rader
                continue            # Hoppar tillbaka till början av loopen och väntar på nästa rad
# Om en ny rad hittas, returneras den med yield till den som använder funktionen
            yield line.strip()      # Returnera raden utan radbrytning 
            # strip() tar bort radbrytningar och mellanslag i början/slutet av raden
            # yield gör så att raderna skickas en i taget utan att avsluta funktionen

#except FileNotFoundError:
#log_message("ERROR", f"Loggfilen {file_path} hittades inte.")
#print(f"ERROR: Loggfilen {file_path} hittades inte.")
#exit(1)

# Funktion som delar upp loggrad i delar
#def parse_log_line(line):
#    parts = line.split(",")     # Delar upp raden i delar med , som avgränsare
#    if len(parts) != 5:
#        print(f"[WARNING] Fel format: {line}")
#        return None
#    return {                    # Returnerar dem som en "ordlista" 
#       "time": parts[0],
#        "src_ip": parts[1],
#        "dest_ip": parts[2],
#        "port": int(parts[3]),
#        "protocol": parts[4].upper()
#    }

# Funktionen som tar in en parameter row, vilket förväntas vara en lista
def parse_log_row(row):
# Kontrollerar om raden har färre än 5 element/kolumner. En korrekt loggrad bör ha minst 5 fält
    if len(row) < 5:
# Skriver ut en varning om raden är ogiltig, tillsammans med innehållet i raden
        print(f"[WARNING] Ogiltig rad (för få kolumner): {row}")
# Avbryter funktionen och returnerar None, eftersom datan inte går att använda
        return None
# Startar ett felhanteringsblock. Koden under try testas – om något går fel, 
# hoppar Python till except.
    try:
        timestamp = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
# Försöker tolka första kolumnen som ett datum och tid i formatet "ÅÅÅÅ-MM-DD HH:MM:SS", och konverterar det till ett datetime-objekt
        src_ip = row[1]
        dest_ip = row[2]
# Plockar ut käll-IP och destinations-IP från kolumn 2 och 3
        port = int(row[3])
# Konverterar kolumn 4 till en heltalstyp (portnummer)
        protocol = row[4]
# Hämtar kolumn 5 – t.ex. "TCP" eller "UDP"
        return {"timestamp": timestamp, "src_ip": src_ip, "dest_ip": dest_ip, "port": port, "protocol": protocol}
# Returnerar ett dictionary med de tolkade värdena, detta gör det lättare att arbeta med dessa i analysen
    except Exception as e:
# Fångar alla fel som kan uppstå under försöket att tolka raden (t.ex. fel format på tid, port ej siffra osv.)
        print(f"[ERROR] Kunde inte tolka rad: {row} - {e}")
# Skriver ut ett felmeddelande tillsammans med raden och information om själva felet (e)
        return None
# Returnerar None om ett fel inträffar, så att resten av programmet inte kraschar

# Funktionen tar in ett argument batch, vilket ska vara en lista 
# med loggposter (dictionaries med nycklar som "src_ip", "dest_ip", etc.)
def analyze_batch(batch):
# Om batchen är tom (dvs. inget att analysera), avbryt funktionen direkt
    if not batch:
        return
# Skapar tre hjälpvariabler
    src_counter = defaultdict(int)
# Räknar hur många gånger varje käll-IP förekommer
    dest_counter = defaultdict(int)
# Räknar hur många gånger varje mål-IP förekommer
    unusual_ports = []
# En lista som sparar loggrader med ovanliga portar
# Loopa igenom varje post (rad) i batchen
    for entry in batch:
# Öka räknaren för respektive käll-IP och mål-IP med 1
        src_counter[entry["src_ip"]] += 1
        dest_counter[entry["dest_ip"]] += 1
# Om porten är lägre än 1024 (vilket oftast betyder ett systemtjänst-port) och inte är en vanlig 
# port (SSH, HTTP, HTTPS), lägg till den i listan över ovanliga portar
        if entry["port"] < 1024 and entry["port"] not in (22, 80, 443):
            unusual_ports.append(entry)
# Skapa en tom lista för att lagra larmmeddelanden
    alerts = []
# Gå igenom alla käll-IP:er och om en IP har mer än 100 anslutningar som avsändare, skapa ett larm

    for ip, count in src_counter.items():
        if count > 100:
            alerts.append(f"{ip} har {count} anslutningar som källa.")
# Samma sak, men för IP:er som är mål för anslutningar
    for ip, count in dest_counter.items():
        if count > 100:
            alerts.append(f"{ip} har {count} anslutningar som mål.")
# Skapa larm för varje rad med en ovanlig port. Larmet innehåller käll-IP, mål-IP, 
# port och protokoll
    for entry in unusual_ports:
        alerts.append(
            f"Ovanlig port upptäckt: {entry['src_ip']} → {entry['dest_ip']} på port {entry['port']} ({entry['protocol']})"
        )
# Hämtar tidsstämpel för första och sista posten i batchen – används som tidsintervall för analysen
    start_time = batch[0]["timestamp"]
    end_time = batch[-1]["timestamp"]
    log_message("INFO",f"-- Batchanalys: {start_time} till {end_time} ---")
# Loggar att en batchanalys har påbörjats och anger tidsintervall
    print(f"\n--- Batchanalys: {start_time} till {end_time} ---")
# Mejlar varning till administratören 
    if alerts:

        email_body = "\n".join(alerts)
        send_email_alert(
            subject="IDS-varning: Misstänkt aktivitet",
            body=f"Följande upptäcktes mellan {start_time} och {end_time}:\n\n{email_body}"
        )

# Om det finns några larm, skriv ut dem och logga dem med nivå "WARNING"
        for alert in alerts:
            print(alert)
            log_message("WARNING",f"{alert}")
    else:
# Om inga larm hittades, skriv det till konsolen
        print("Inga misstänkta aktiviteter upptäckta.")

# Funktionen som tar ett argument: filename, namnet på CSV-rapportfilen
def process_logfile_in_batches(filename):
# Öppnar rapportfilen i läsläge ("r") och kallar rapportobjektet för file
# with ser till att rapportfilen automatiskt stängs efter användning
    with open(filename, "r") as file:
# Skapar en CSV-läsare som läser varje rad i rapportfilen som en lista av värden 
        reader = csv.reader(file)
# Skapar en tom lista data som ska fyllas med tolkade rader
        data = []
# Går igenom varje rad i CSV-filen, där varje row är en lista av strängar
        for row in reader:
# Skickar raden till funktionen parse_log_row() som försöker konvertera den 
# till en dictionary med t.ex. timestamp, src_ip, dest_ip, etc.
# Om raden är ogiltig (t.ex. för få kolumner eller dåligt format) returnerar funktionen None
            parsed = parse_log_row(row)
            if parsed:
# Om raden tolkades korrekt, lägger till resultatet i data
                data.append(parsed)
# Sorterar alla rader efter tidsstämpeln i stigande ordning, så att analysen sker i rätt tidsföljd
        data = sorted(data, key=lambda x: x["timestamp"])
# Skickar hela den sorterade listan till funktionen analyze_batch() för att analysera trafikmönster, 
# upptäcka misstänkta aktiviteter och logga resultat
        analyze_batch(data)

# Funktionen för att simulera e-post och få meddelandet som om det skickades
def send_email_alert(subject, body):
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER
        msg.set_content(body)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.send_message(msg)

        log_message("INFO", "Test-e-post skickad till administratör.")
        print("[INFO] E-postvarning skickad.")
    except Exception as e:
        log_message("ERROR", f"Kunde inte skicka e-post: {e}")
        print(f"[ERROR] Kunde inte skicka e-post: {e}")        

# Huvudfunktion
# Funktionen main() är programmets startpunkt där all logik kopplas ihop och exekveras
def main():
    
    batch = []
    current_window_start = None
    current_window_end = None
# Initiera loggning
# Anropar funktionen setup_path() för att kontrollera att loggkatalogen (LOG_DIR) finns. Om den 
# inte gör det skrivs ett fel och programmet avslutas
    setup_path()
# Skapar rapportfilen (REPORT_FILE) om den inte finns. Om den finns, rensas innehållet och en 
# ny header skrivs. Det säkerställer att vi börjar med en tom rapport för varje körning
    setup_reporting()
# Loggar ett informationsmeddelande om att programmet har börjat övervaka nätverkstrafik. Det 
# skrivs till CSV-rapportfilen med tidsstämpel och loggnivå (INFO)
    log_message("INFO", "Startar nätverksövervakning...")
# Skriver ut ett meddelande till konsolen så administratören vet att programmet körs
    print("Startar övervakning av loggfil...\n")        # Skriver ut att vi startar

    subprocess.Popen(["python","log_gen.py"])
    

    try:
        with open(LOG_FILE, "r") as logfile:
            logfile.seek(0, os.SEEK_END)  # Börja läsa från slutet

            while True:
                line = logfile.readline()
                if not line:
                    time.sleep(1)
                    continue

                parsed = parse_log_row(line)
                if not parsed:
                    continue

                timestamp = parsed["timestamp"]

                if current_window_start is None:
                    current_window_start = timestamp.replace(second=0, microsecond=0)
                    current_window_end = current_window_start + datetime.timedelta(minutes=5)

                if current_window_start <= timestamp < current_window_end:
                    batch.append(parsed)
                else:
                    if batch:
                        analyze_batch(batch)
                        batch = []

                    # Flytta fönstret framåt tills den täcker aktuell timestamp
                    while timestamp >= current_window_end:
                        current_window_start = current_window_end
                        current_window_end = current_window_start + datetime.timedelta(minutes=5)

                    batch.append(parsed)

    except KeyboardInterrupt:
        print("\nAvslutar övervakningen.")
    except Exception as e:
        log_message("ERROR", f"Körfel i huvudloopen: {e}")
        print(f"[ERROR] Körfel: {e}")
    #for line in tail_log_file(LOG_FILE):                # Går igenom varje ny rad och tolkar den
     #   log_entry = parse_log_line(line)
     #   if log_entry:
     #       print(f"[INFO] {log_entry}")        # Skriver ut tolkad information

# Analyserar hela loggfilen på en gång genom att skicka den till process_logfile_in_batches()
    process_logfile_in_batches(LOG_FILE)

# Denna kod gör att main() bara körs om filen exekveras direkt (inte importeras som modul)
# Starta programmet
if __name__ == "__main__":
    main()



#except FileNotFoundError:
#log_message("ERROR", f"Kunde inte hitta en fil i {LOG_DIR}.")
#print(f"ERROR: Kunde inte hitta en fil!")
#exit(1)

#except PermissionError:
#    log_message("ERROR", f"Tillstånd nekades för en fil i {LOG_DIR}.")
#    print(f"ERROR: Tillstånd nekades!")

#except Exception as e:
#   log_message("ERROR", f"Oväntat fel: {str(e)}")
#   exit(1)

# Konsolsammanfattning

#print(f"Övervakning av nätverkstrafik klar: {time.strtime('%Y-%m-%d %H:%M:%S')}")
#print(f"Rapport skickad: {REPPORT_FILE}")

