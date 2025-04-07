#!/bin/bash
#Skapat av Sanna Nilsson, 7 april 2025 - Övervakar en katalog för misstänkta filer 

readonly LOG_FILE="$HOME/file_sentry.log"
readonly TEMP_FILE="/tmp/file_sentry_$$.tmp"
readonly SIZE_THRESHOLD=1048576
readonly TARGET_DIR="$1"

#readonly gör variablerna skrivskyddade för säkerhet
# $$ är process-ID för att undvika konflikter i temporära filer
# $1 tar katalogen från kommandoraden
#file_sentry.log - Loggfil i hemmappen
#.tmp - Temporär fil med unikt namn
# 1 MB i bytes
# "$1" - Första argumentet är katalogen

set -e  #Avsluta vid fel
set -u  #Fel om odentifierade variabler används
trap 'echo "Skript avbrutet!"; rm -f "$TEMP_FILE"; exit 1' INT TERM EXIT
#Detta skyddar mot oväntade problem och rensar upp vid avbrott

log_message(){
local level="$1"    #INFO, WARNING, ERROR
local_message="$2"
printf "%s[%s]%\n""$(date'+%Y-%m-%d %H:5M:5S')""$message" >> "$LOG_FILE"
}               #Funktionen skriver tidstämplar och nivåer till loggfilen - viktigt för spårbarhet.

if [[ -z "$TARGET_DIR" ]];then       #Kontrollera att användaren angav en katalog och att den existerar.
log_message "ERROR" "Ingen katalog angiven. Använd: ./file_sentry.sh <katalog>"
echo "Fel: Ange en katalog!" >&2
exit 1
fi

if [[ ! -d "$TARGET_DIR" ]];then
log_message "ERROR" "$TARGET_DIR är inte en katalog"
echo "Fel: $TARGET_DIR finns inte eller är ingen katalog!" >&2
exit 1
fi

