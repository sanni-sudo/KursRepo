# sec_watch.py - Övervakar nätverkstrafik i realtid 
# Skapat av: Sanna Nilsson, 2 Maj 2025
# Syfte: Bygga ett Python-program som kan upptäcka attacker 
# mot nätverket i realtid och kan vidta åtgärder vid 
# misstänkta attacker.

# Krav
# Läsa en dynamisk loggfil (network_traffic.log) 
# Analyserar trafiken 
# Skickar e-post varningar till en administratör
# Genererar en CSV-rapport

# Importera moduler för våra behov
import os           # Arbetar med filer och kataloger
import logging      # Skapar loggar med tidstämplar och nivåer (INFO, WARNING, ERROR)
import time         # Modulen som nnehåller funktioner för att arbeta med tidsrelaterade saker
import re           # Reguljära uttryck som används för att söka efter nyckelord i loggrader

# Konfiguration
LOG_DIR = "/home/testkali/KursRepo/Test_Monitor_Dir"
LOG_FILE = os.path.join(LOG_DIR, "network_traffic.log")
REPORT_FILE = os.path.join(LOG_DIR, "attack_report.csv")
KEYWORDS = ["time", "src-ip", "dest.ip", "port", "protoc"]

# Funktioner
# Funktion för att konfigurera loggning
def setup_logging():
    logging.basicConfig(
        filename=REPORT_FILE,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
# Funktion för att loga meddelanden
def log_message(level, message):
    if level == "INFO":
        logging.info(message)
    elif level == "WARNING":
        logging.warning(message)
    elif level == "ERROR":
        logging.error(message)

# Validera loggkatalog
    log_message("INFO", "Startar nätverksövervakning...")
if not os.path.exists(LOG_DIR):
    log_message("ERROR", f"Katalogen {LOG_DIR} finns inte.")
    print(f"ERROR: Katalogen {LOG_DIR} finns inte!")
    exit(1)

# Skannar loggfilen för nyckelord




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
#print(f"Rapport skickad: {RAPPORT_FILE}")

