#!/bin/bash
#Skapat av: Sanna Nilsson, 8 april 2025 
#Namn: Övervakar en katalog för misstänkta filer, lägger till
#en funktion som räknar antalet misstänkta filer och skriver ut eb sammanfattningt i slutet.
#$SIZE_THESHOLD ksn anges som ett andra argument ($2) med ett standardvärde om det saknas.  

readonly LOG_FILE="$HOME/file_sentry.log"
readonly TEMP_FILE="/tmp/file_sentry_$$.tmp"
SIZE_THRESHOLD="${2:-1048576}"
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

log_message() {     #Skapar en funktion som heter log_message som man kan anropa senare med:
#log_message "INFO" "Fil skannad"
local level="$1"    #INFO, WARNING, ERROR
local message="$2"
printf "%s [%s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" >> "$LOG_FILE"
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

#Lägg till logik för att hitta och analysera filer:
log_message "INFO" "Skannar $TARGET_DIR för misstänkta filer..."

#Hitta filer och spara storlek och rättigheter till temporär fil
find "$TARGET_DIR" -type f -exec stat -c "%s %A %n" {} \; > "$TEMP_FILE"

#Analysera varje fil
while read -r size perms name; do 
    is_suspect=0

#Kontrollera storlek
if (( size > SIZE_THRESHOLD )); then
log_message "WARNING" "Stor fil:$name ($size bytes)"
echo "Varning: $name är över $SIZE_THRESHOLD bytes!" >&2
is_suspect=1
fi

#Kontrollera körbara rättigheter
if [[ "$perms" =~ x ]]; then
log_message "WARNING" "Körbar fil: $name ($perms)"
echo "Varning: $name är körbar!" >&2
is_suspect=1
fi

if (( is_suspect == 1 )); then
    ((suspect_count++))
fi

done < "$TEMP_FILE"
#Find listar alla filer ( -type f) och stat ger storlek, rättigheter och namn
#Loopen läser varje rad och använder villkor för att flagga misstänkta filer

#Lägg till avslutande kod:
log_message "INFO" "Skanning klar."
log_message "INFO" "Antal misstänkta filer: $suspect_count"
echo "Total andtal misstänkta filer: $suspect_count"

rm -f "$TEMP_FILE"
#trap rensar redan vid avbrott, men vi gör det här för normal avslutning
