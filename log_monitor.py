# log_monitor.py - Övervakar loggfiler för misstänkta nyckelord
# Skapat av: Sanna Nilsson, 28 April 2025
# Syfte: Skanna loggfiler i C:\KursRepo för nyckelord som "error" och "failed",
# logga resultat till monitor.log och visa varningar i konsolen
# Krav:
# -Kontrollera att loggkatalogen finns
# -Skanna filer för nyckelord och logga träffar
# -Hantera fel robust
# -Logga alla åtgärder med tidsstämplar

# Importerar moduler för våra behov = Bibiloteksbaserat
import os                   # Arbetar med filer och kataloger
import logging              # Skapar loggar med tidstämplar och nivåer (INFO, WARNING, ERROR)
import time                 # Importerar standardmodulen time, som innehåller funktioner för att arbeta med tidsrelaterade saker
import re                   # Reguljära uttryck som används för att söka efter nyckelord i loggrader

# Konfiguration
LOG_DIR = "C://KursRepo"
LOG_FILE = os.path.join(LOG_DIR, "monitor.log")
KEYWORDS = ["error", "failed"]

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
log_message("INFO", "Startar loggövervakning...")
if not os.path.exists(LOG_DIR):
    log_message("ERROR", f"Katalogen {LOG_DIR} finns inte.")
    print(f"ERROR: Katalogen {LOG_DIR} finns inte!")
    exit(1)

# Skannar loggfiler för nyckelord

try:
    for filename in os.listdir(LOG_DIR):
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



