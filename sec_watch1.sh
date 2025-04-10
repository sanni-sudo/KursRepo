#!/bin/bash

#Skapat av: Sanna Nilsson, 9 april 2025 
#Namn: Övervakning och analys av säkerhetsloggar på Ubuntu Server
#Skapar ett Bash-skript som övervakar och analyserar säkerhetsloggar på 
#Ubuntu Server (/var/log/auth.log och /var/log/syslog) för att identifiera, 
#rapportera och reagera på misstänkt aktivitet.

#---------------Konfiguration - Variabler för Loggar och Rapporter(?)

readonly SYSLOG_FILE="/var/log/syslog"
readonly AUTHLOG_FILE="/var/log/auth.log"
readonly REPORT_FILE="security_report_$(date +%Y%m%d).txt"
readonly ACTIONLOG_FILE="/var/log/security_actions.log"
readonly ARCHIVEDIR_FILE="/backup/logs"
readonly ADMINEMAIL_FILE="sanna.nilsson@utb.ecutbildning.se"
readonly MIN_DISK_SPACE=5242880 
readonly MAX_FAILED=20

# readonly gör variablerna skrivskyddade för säkerhet, dvs värdet ska inte ändras senare i skriptet
# /var/log/syslog och /var/log/auth.log är sökvägar till loggfilen som ska analyseras 
# security_report_$(date +%Y%m%d).txt är fil där analysrapporten sparas med dagens datum på rapporten
# Loggar åtgärden om blockerade ip:n med ufw i /var/log/security_actions.log
# Arkiverar och komprimerar loggar till /backup/logs
# Mejlar rapporten till administratören sanna.nilsson@utb.ecutbildning.se  
# Diskutrymme definierat i KB (5KB)
# MAX_FAILED=20 anger antal misslyckade försök innan ip:n räknas som "hög risk"

#----------------Säkerhetsåtgärder - Felhantering

set -e 
set -u  
trap 'echo "Skript Avbrutet!" >&2; exit 1' INT TERM EXIT

#Felhantering och avbrott. set -e avbryter skriptet om ett fel uppstår
# set -u avbryter skriptet om man försöker använda en variabel som inte finns
#trap skriver ut meddelande om något avbryter eller tycker på Ctrl+C

#-----------------Funktioner - Loggning och Varningar

echo "Ange max antal rader att analysera: "
read MAX_LINES

#Läser användarinput för att bestämma hur många rader som ska analyseras

if [! -r "$SYSLOG_FILE" ]; then
echo "Loggfilen hittades inte!"
exit 1
fi

if ! [[ "$MAX_LINES" =~ ^[0-9]+$ ]] || (( MAX_LINES <= 0 )); then
	echo "Ogiligt antal rader, ange ett positivt heltal!"
	exit 1
fi

#Kontrollerar om loggfilen finns och är läsbar
#Validerar att MAX_LINES är ett positivt heltal







