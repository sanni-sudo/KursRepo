# test_log_monitor.py - Testskript för log_monitor.py
# Skapat av: Sanna Nilsson, 28 April 2025
# Syfte: Testa skriptet log_monitor.py 

# Importerar moduler för våra behov = Bibiloteksbaserat
import os                   # Arbetar med filer och kataloger
import logging              # Skapar loggar med tidstämplar och nivåer (INFO, WARNING, ERROR)
import time                 # Importerar standardmodulen time, som innehåller funktioner för att arbeta med tidsrelaterade saker
import re                   # Reguljära uttryck som används för att söka efter nyckelord i loggrader

# Konfiguration
LOG_DIR = "C:\\KursRepo\\test_monitor_dir"
LOG_FILE = os.path.join(LOG_DIR, "monitor.log")
# Testar funktionen

#LOG_FILE = "C:\\Fake\\test.log"
KEYWORDS = ["error", "failed"]

# Testar variablerna för att verifiera 
#import os
#LOG_DIR = "C:\\KursRepo\\test_monitor_dir"
#LOG_FILE = os.path.join(LOG_DIR, "monitor.log")
#print(LOG_FILE)

# Funktion för att konfigurera loggning

def setup_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
        )

# Funktion för att logga meddelanden

def log_message(level, message):
    if level == "INFO":
        logging.info(message)
    elif level == "WARNING":
        logging.warning(message)
    elif level == "ERROR":
        logging.error(message)

# Validera loggkatalog

setup_logging()
log_message("INFO", "Startar loggövervakning...")       #"Testar loggning! XX")
if not os.path.exists(LOG_DIR):
    log_message("ERROR", f"Katalogen {LOG_DIR} finns inte.")
    print(f"ERROR: Katalogen {LOG_DIR} finns inte!")
    exit(1)

# Skannar loggfiler för nyckelord

try:
    for filename in os.listdir(LOG_DIR):
        if filename == "monitor.log":
            continue                    # Hoppa över loggfilen för att undvika självläsning
        filepath = os.path.join(LOG_DIR, filename)
        if os.path.isfile(filepath):
            with open(filepath, "r") as file:
                for line in file:
                    for keyword in KEYWORDS:
                        if re.search(keyword, line,re.IGNORECASE):
                            message = f"Hittade {keyword} i {filename}: {line.strip()}"
                            log_message("WARNING", message)
                            print(f"WARNING: {message}")
    log_message("INFO", "Skanning klar.")
except FileNotFoundError:
    log_message("ERROR", f"Kunde inte hitta en fil i {LOG_DIR}.")
    print(f"ERROR: Kunde inte hitta en fil!")
    exit(1)

except PermissionError:
    log_message("ERROR", f"Tillstånd nekades för en fil i {LOG_DIR}.")
    print(f"ERROR: Tillstånd nekades!")
    exit(1)

except Exception as e:   
    log_message("ERROR", f"Oväntat fel: {str(e)}")
    print(f"ERROR: Oväntat fel: {str(e)}")
    exit(1)
    
import sys

shoud_exit = True
if shoud_exit:
    print("Skanning klar. Avslutar skriptet.")
    sys.exit()
