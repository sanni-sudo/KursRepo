# test_log_monitor.py - Testskript för log_monitor.py
# Skapat av: Sanna Nilsson, 28 April 2025
# Syfte: Testa skriptet log_monitor.py 

# Importerar moduler för våra behov = Bibiloteksbaserat
import os                   # Arbetar med filer och kataloger
import logging              # Skapar loggar med tidstämplar och nivåer (INFO, WARNING, ERROR)
import time                 # Importerar standardmodulen time, som innehåller funktioner för att arbeta med tidsrelaterade saker
import re                   # Reguljära uttryck som används för att söka efter nyckelord i loggrader

# Konfiguration
LOG_DIR = "C:\\KursRepo"
LOG_FILE = os.path.join(LOG_DIR, "monitor.log")
# Testar funktionen

#LOG_FILE = "C:\\Fake\\test.log"
KEYWORDS = ["error", "failed"]

# Testar variablerna för att verifiera 
#import os
#LOG_DIR = "C:\\KursRepo"
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

