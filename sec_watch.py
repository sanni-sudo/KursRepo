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

# Konfiguration
LOG_DIR = "/home/testkali/KursRepo/Test_Monitor_Dir"
LOG_FILE = os.path.join(LOG_DIR, "network_traffic.log")
REPORT_FILE = os.path.join(LOG_DIR, "attack_report.csv")

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
def log_message(level, message):
    # Kontrollera om rapportfilen existerar, om inte, skapa den med en header
    if not os.path.exists(REPORT_FILE):    
        with open(REPORT_FILE, mode="w", newline="") as file:            
            writer = csv.writer(file)
# Skriver header med tre kolumner: Timestamp: tidpunkt när rapporten skapades, 
# Level: loggnivå och Message: loggmeddelandet
            writer.writerow(["Timestamp", "Level", "Message"]) 
    # Hämtar nuvarande tid och formaterar den som en tydlig sträng (t.ex. "2025-05-03 13:45:22")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Skriv rapporten till CSV
    # Öppnar rapportfilen i append-läge ("a"), dvs vi lägger till längst ner i rapporten
    with open(REPORT_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, level, message])  # Lägg till rapportposten

# Validera att loggkatalogen finns 
def setup_path():
# Loggar en informationsrad till CSV-rapporten med texten "Kontrollerar om katalogen finns" och
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

def parse_log_row(row):
    if len(row) < 5:
        print(f"[WARNING] Ogiltig rad (för få kolumner): {row}")
        return None
    try:
        timestamp = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
        src_ip = row[1]
        dest_ip = row[2]
        port = int(row[3])
        protocol = row[4]
        return {"timestamp": timestamp, "src_ip": src_ip, "dest_ip": dest_ip, "port": port, "protocol": protocol}
    except Exception as e:
        print(f"[ERROR] Kunde inte tolka rad: {row} - {e}")
        return None

def analyze_batch(batch):
    if not batch:
        return

    src_counter = defaultdict(int)
    dest_counter = defaultdict(int)
    unusual_ports = []

    for entry in batch:
        src_counter[entry["src_ip"]] += 1
        dest_counter[entry["dest_ip"]] += 1
        if entry["port"] < 1024 and entry["port"] not in (22, 80, 443):
            unusual_ports.append(entry)

    alerts = []
    for ip, count in src_counter.items():
        if count > 100:
            alerts.append(f"[ALERT] {ip} har {count} anslutningar som källa.")
    for ip, count in dest_counter.items():
        if count > 100:
            alerts.append(f"[ALERT] {ip} har {count} anslutningar som mål.")
    for entry in unusual_ports:
        alerts.append(
            f"[ALERT] Ovanlig port upptäckt: {entry['src_ip']} → {entry['dest_ip']} på port {entry['port']} ({entry['protocol']})"
        )

    start_time = batch[0]["timestamp"]
    end_time = batch[-1]["timestamp"]
    log_message("INFO",f"-- Batchanalys: {start_time} till {end_time} ---")
    print(f"\n--- Batchanalys: {start_time} till {end_time} ---")
    if alerts:
        for alert in alerts:
            print(alert)
            log_message("WARNING",f"{alert}")
    else:
        print("Inga misstänkta aktiviteter upptäckta.")

def process_logfile_in_batches(filename):
    with open(filename, "r") as file:
        reader = csv.reader(file)
        data = []
        for row in reader:
            parsed = parse_log_row(row)
            if parsed:
                data.append(parsed)
        data = sorted(data, key=lambda x: x["timestamp"])
        analyze_batch(data)


# Huvudfunktion


def main():
# Initiera loggning
    setup_path()
    setup_reporting()
    log_message("INFO", "Startar nätverksövervakning...")

    print("Startar övervakning av loggfil...\n")        # Skriver ut att vi startar
    #for line in tail_log_file(LOG_FILE):                # Går igenom varje ny rad och tolkar den
     #   log_entry = parse_log_line(line)
     #   if log_entry:
     #       print(f"[INFO] {log_entry}")        # Skriver ut tolkad information
    process_logfile_in_batches(LOG_FILE)

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

