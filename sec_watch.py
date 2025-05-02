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
KEYWORDS = []