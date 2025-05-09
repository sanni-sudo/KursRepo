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

# readonly gör variablerna skrivskyddade för säkerhet, dvs värdet sk inte ändras senare i skriptet
# /var/log/syslog och /var/log/auth.log är sökvägar till loggfilen som ska analyseras 
# sec_watch_report.txt är fil där analysrapporten sparas
# date +%Y%m%d ger dagens datum på rapporten
#Diskutrymme definierat i KB (5KB)
#MAX_FAILED=20 anger antal misslyckade försök innan ip:n räknas som "hög risk"

#----------------Säkerhetsåtgärder - Felhantering

set -e 
set -u  
trap 'echo "Skript Avbrutet!" >&2; exit 1' INT TERM EXIT

#Felhantering och avbrott. set -e avbryter skriptet om ett fel uppstår
# set -u avbryter skriptet om man försöker använda en variabel som inte finns
#trap skriver ut meddelande om något avbryter eller tycker på Ctrl+C

#-----------------Funktioner - Loggning och Varningar

check_file_readable() {
  local file="$1"
  if [[ -f "$file" && -r "$file" ]]; then
    log_message "INFO" "$file finns och är läsbar"
  else
    log_message "ERROR" "$file saknas eller kan inte läsas"
    echo "Fel: $file finns inte eller går inte att läsa!" >&2
    exit 1
  fi
}

check_file_readable "$AUTHLOG_FILE"
check_file_readable "$SYSLOG_FILE"

#Kontrollerar att loggarna finns
#Kontrollerar att båda loggfilenra existerar och är skrivbara
#Om någon inte finns eller saknar skrivbehörighetet, skriver ett felmeddelande och avslutar skriptet


TMP_FILE=$(mktemp)

#Skapar temporär arbetsfil där vi sparar loggrader för analys


echo "[INFO] Extraherar loggar från senaste 24 timmar ..."
awk -v Date="$(date --date='1 day ago' '+%b %_d')" '$0 ~ Date' "$AUTHLOG_FILE" "$SYSLOG_FILE" > "$TMP_FILE" 
grep "Failed password" "$AUTHLOG_FILE" > "$TMP_FILE" 

#Extraherar relevanta rader från senaste 24h
#Letar efter rader som innehåller gårdagens datum (månad + dag)
#Sparar dem i TMP_FILE


#----------------Huvudlogik - Kopierar, Räknar och Analyserar loggar

declare -A failed_attempts
declare -A invalid_users
declare -A accepted_logins
declare -A session_opened

#declare -A skapar associativa arrayer, s k nyckel-värde-par
#varje array håller koll på en viss typ av händelse


while read -r line; do
	if [[ "$line" =~ Failed\ password.*from\ ([0-9.]+).*for\ (invalid\ user|user)\ ([^[:space:]]+) ]]; then
	ip="${BASH_REMATCH[1]}"
	user="${BASH_REMATCH[3]}"
	((failed_attempts["$ip|$user"]++))
	
	elif [[ "$line" =~ Invalid\ user\ ([^[:space:]]+)\ ([0-9.]+) ]]; then
	user="${BASH_REMATCH[1]}"
	ip="${BASH_REMATCH[2]}"
	((invalid_users["$ip|$user"]++))
	
	elif [[ "$line" =~ Accepted\ password.*from\ ([0-9.]+).*for\ ([^[:space:]]+) ]]; then
	ip="${BASH_REMATCH[1]}"
	user="${BASH_REMATCH[2]}"
	((accepted_logins["$ip|$user"]++))
	
	elif [[ "$line" =~ session\ opened\ for\ user\ ([^[:space:]]+)\ ]]; then
	user="${BASH_REMATCH[1]}"
	((session_opened["$ip|$user"]++))

	fi
done < "$TMP_FILE"

#Läser varje rad och letar efter mönster med [[ "$line" =~...]]
#Använder Reguljära uttryck för att hitta ip, användare, händelser.

#Genererar rapport

echo "==== Säkerhetsrapport $(date '+%Y-%m-%d') ====" > "$REPORT_FILE"

#Öppnar eller skriver över rapportfilen
#Sedan körs report_entry för att lägga till varje ip/användare

report_entry() {
	local type="$1"
	local ip="$2"
	local user="$3"
	local count="$4"
	local risk="Låg"
#Funktionen report_entry skriver ut info pm varje inloggningsförsök
#Om count > MAX_FAILED => risk = "Hög" + blockera ip med ufw

	if [[ "$type" == "Failed" || "$type" == "Invalid" ]] && (( count > MAX_FAILED )); then
	risk="Hög"
	echo "$(date '+%F %T') [BLOCERAD] $ip flaggad som hög risk ($count försök) - $type login" >> "$ACTIONLOG_FILE"
	ufw deny from "$ip" comment "Auto-blocked by sec_watch.sh"
	fi
	printf "%-10s %-15s %-15s %-10s %-5s\n" "$type" "$ip" "$user" "$count" "$risk" >> "REPORT_FILE"

}

for key in "${!failed_attempts[@]}"; do
	IFS="|" read -r ip user <<< "$key"
	report_entry "Failed" "$ip" "$user" "${failed_attempts[$key]}"
done

for key in "${!invalid_users[@]}"; do
	IFS="|" read -r ip user <<< "$key"
	report_entry "Invalid" "$ip" "$user" "${invalid_users[$key]}"
done

for key in "${!accepted_logins[@]}"; do
	IFS="|" read -r ip user <<< "$key"
	report_entry "Accepted" "$ip" "$user" "${accepted_logins[$key]}"
done

for user in "${!session_opened["]}"; do
	printf "%-10s %-15s %-15s %-10s %-5s\n" "Session" "-" "$user" "${session_opened[$user]}" "Låg" >> "$REPORT_FILE"
done

echo "[INFO] Rapport genererad: $REPORT_FILE"

#---------------- Avslutning - Logga och Rensa 

#Skickar rapporten via e-post
if command -v mali &>/dev/null; then
	mail -s "Daglig säkerhetsrapport från $(hostname)" "$ADMINEMAIL_FILE" < "$REPORT_FILE"
	echo "[INFO] Rapport skickad till $ADMINEMAIL_FILE"
else
	echo "[VARNING] mail-kommandot saknas - kunde inte skicka e-post!"
fi

#Kontrollerar om mail-kommandot finns
#Om det finns, skickar rapporten, annars skrivs en varning

#Aktiverar loggar äldre än 7 dagar
echo "[INFO] Aktiverar äldre loggfiler..."
mkdir -p "$ARCHIVEDIR_FILE"
find /var/log -type f \( -name "*.log" -o -name "*.gz" \) -mtime +7 -exec tar -rvf "$ARCHIVEDIR_FILE/log_backup_$(date +%Y%m%d).tar" {} \; -exec rm -f {} \;

#Hittar .log och .gz-filer som är äldre än 7 dagar, sparar dem i ett tar-arkiv och tar bort originalen.

#Städar tmp-filer
rm -f "$TMP_FILE"

echo "[KLART] Säkerhetsanalys slutförd. Rapport sparad i $REPORT_FILE."
