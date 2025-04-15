#!/bin/bash

#Skapat av: Sanna Nilsson, 9 april 2025 
#Namn: Övervakning och analys av säkerhetsloggar på Ubuntu Server
#Skapar ett Bash-skript som övervakar och analyserar säkerhetsloggar på 
#Ubuntu Server (/var/log/auth.log och /var/log/syslog) för att identifiera, 
#rapportera och reagera på misstänkt aktivitet.

#---------------Konfiguration - Variabler för Loggar och Rapporter

readonly SYSLOG_FILE="/var/log/syslog"            # Sökväg till loggfilen som ska analyseras 
readonly AUTHLOG_FILE="/var/log/auth.log"         # Sökväg till loggfilen som ska analyseras 
readonly REPORT_FILE="security_report_$(date +%Y%m%d).txt"    # Fil där analysrapporten sparas med dagens datum på rapporten
readonly TMP_FILE="/tmp/sec_watch_$$.tmp"         # $$ är process-ID för att undvika konflikter i temporära filer
readonly ACTIONLOG_FILE="/var/log/security_actions.log"       # Loggar åtgärden om blockerade ip:n med ufw
readonly ARCHIVEDIR_FILE="/backup/logs"           # Hit arkiveras och komprimeras loggar
readonly ADMINMAIL_FILE="admin@example.com"      # Hit mejlas rapporten till administratören
readonly SCRIPT_NAME=$(basename "$0")             # Skriptnamn för loggning
readonly THRESHOLD=5                            # Anger tröskelvärde för försök innan ip:n räknas som "hög risk"

# readonly gör variablerna skrivskyddade för säkerhet, dvs värdet ska inte ändras senare i skriptet 


#----------------Säkerhetsåtgärder - Felhantering och avbrott

#set -e 
#set -u  
#trap 'echo "Skript Avbrutet!"; rm -f "$TMP_FILE"; exit 1' INT TERM EXIT

# set -e avbryter skriptet om ett fel uppstår
# set -u avbryter skriptet om man försöker använda en variabel som inte finns
# trap skriver ut meddelande om något avbryter eller tycker på Ctrl+C
# Detta skyddar mot oväntade problem och rensar upp vid avbrott.  

#-----------------Funktioner - Loggning och Varningar
# Logga meddelanden med tidsstämpel

log_message() {
	local level="$1"          # INFO, WARNING, ERROR
	local message="$2"
#printf "%s [%s] %s: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$SCRIPT_NAME" "$message" >> "$AUCTIONLOG_FILE"

  echo "$(date '+%F %T') [$level] $message" >> "$ACTIONLOG_FILE"
}

# ------------------- Huvudlogik ---------------------
# Kontrollerar att båda loggfilenra existerar och är läsbara
# Om någon inte finns eller saknar läsbehörighetet, skriver ett felmeddelande och avslutar skriptet


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

# Kontrollerar att /var/log/security_actions.log är skrivbar ( eller skapar den)

if [[ ! -w "$ACTIONLOG_FILE" ]]; then
  touch "$ACTIONLOG_FILE" 2>/dev/null || {
    log_message "ERROR" "Kan inte skriva till $ACTIONLOG_FILE. Kontrollera behörigheter"
    exit 1

  }
fi
# Försöker skapa filen om den inte finns och döljer eventuella felmeddelanden från touch.
# Om skapa filen misslyckas, skriver ett felmeddelande till loggen och avslutar skriptet med felkod.


# Skicka e-postvarning
send_alert() {
    local ip="$1"
    local attempts="$2"
    local subject="Hög risk varning: $ip överskred tröskelvärdet"
    local body="IP $ip hade $attempts misslyckade försök. Se $ACTIONLOG_FILE för detaljer."

    echo -e "$body" | mail -s "$subject" "$ADMINMAIL_FILE"
}

touch "$TMP_FILE"
# Skapar temporär arbetsfil där vi sparar loggrader för analys

log_message "INFO" "Extraherar loggar från senaste 24 timmar"
#grep -E "password check failed|authentication failure|session opened" $AUTHLOG_FILE | awk -v cutoff="$(date -d '4 hours ago' +%s)" > $TMP_FILE
#grep -E "password check failed|authentication failure|session opened" $SYSLOG_FILE > $TMP_FILE
#awk -v Date="$(date --date='1 day ago' '+%b %_d')" '$0 ~ Date' "$AUTHLOG_FILE" "$SYSLOG_FILE" > "$TMP_FILE"

# Skapa datumsträng för 24 timmar sen
SINCE=$(date -d '24 hours ago' --iso-8601=seconds)

echo "Filtrerar rader från loggfilen de senaste 24 timmarna..."
echo "Starttid: $SINCE"
echo "---------------------------------------------"

# Filtrera och skriv ut loggrader
awk -v since="$SINCE" '{
    log_time = substr($0, 1, 19)
    if (log_time >= since) print
}' "$AUTHLOG_FILE" "$SYSLOG_FILE" > "$TMP_FILE"

# Extraherar relevanta rader från senaste 24h och skickar dem till $TEMP_FILE
# Sparar dem i TMP_FILE 
echo "[INFO] Söker alla rader som innehåller "password check failed" "authentication failure" "session opened" i "$TMP_FILE""
grep -E "password check failed|authentication failure|session opened" "$TMP_FILE" > "$ACTIONLOG_FILE"
# grep -i "failed password" "$AUTHLOG_FILE" > "$REPORT_FILE
# echo "[KLART] Rader sparade till: $REPORT_FILE
# awk -v Date="$(date --date='1 day ago' '+%b %_d')" '$0 ~ Date' "$AUTHLOG_FILE" "$SYSLOG_FILE" > "$TMP_FILE" 
# grep "Failed password" "$AUTHLOG_FILE" > "$TMP_FILE" 
# Extraherar relevanta rader från senaste 24h Extraherar loggar från senaste 24 timmar ..."


#Städar tmp-filer
#cleanup() {
#rm -f "$TMP_FILE"
#log_message "INFO" "Rensade temporära filer"
#exit 0
#}


#----------------Huvudlogik - Kopierar, Räknar och Analyserar loggar

#declare -A failed_attempts
#declare -A invalid_users
#declare -A accepted_logins
#declare -A session_opened

#declare -A skapar associativa arrayer, s k nyckel-värde-par
#varje array håller koll på en viss typ av händelse


#while read -r line; do
#	if [[ "$line" =~ Failed\ password.*from\ ([0-9.]+).*for\ (invalid\ user|user)\ ([^[:space:]]+) ]]; then
#	ip="${BASH_REMATCH[1]}"
#	user="${BASH_REMATCH[3]}"
#	((failed_attempts["$ip|$user"]++))
	
#	elif [[ "$line" =~ Invalid\ user\ ([^[:space:]]+)\ ([0-9.]+) ]]; then
#	user="${BASH_REMATCH[1]}"
#	ip="${BASH_REMATCH[2]}"
#	((invalid_users["$ip|$user"]++))
	
#	elif [[ "$line" =~ Accepted\ password.*from\ ([0-9.]+).*for\ ([^[:space:]]+) ]]; then
#	ip="${BASH_REMATCH[1]}"
#	user="${BASH_REMATCH[2]}"
#	((accepted_logins["$ip|$user"]++))
	
#	elif [[ "$line" =~ session\ opened\ for\ user\ ([^[:space:]]+)\ ]]; then
#	user="${BASH_REMATCH[1]}"
#	((session_opened["$ip|$user"]++))

#	fi
#done < "$TMP_FILE"

#Läser varje rad och letar efter mönster med [[ "$line" =~...]]
#Använder Reguljära uttryck för att hitta ip, användare, händelser.

#Genererar rapport

#echo "==== Säkerhetsrapport $(date '+%Y-%m-%d') ====" > "$REPORT_FILE"

#Öppnar eller skriver över rapportfilen. 
#Sedan körs generate_report för att lägga till varje ip/användare

#generate_report() {
#	local type="$1"
#	local ip="$2"
#	local user="$3"
#	local count="$4"
#	local risk="Låg"
#Funktionen generate_report skriver ut info pm varje inloggningsförsök
#Om count > MAX_FAILED => risk = "Hög" + blockera ip med ufw

#	if [[ "$type" == "Failed" || "$type" == "Invalid" ]] && (( count > MAX_FAILED )); then
#	risk="Hög"
#	echo "$(date '+%F %T') [BLOCERAD] $ip flaggad som hög risk ($count försök) - $type login" >> "$ACTIONLOG_FILE"
#	ufw deny from "$ip" comment "Auto-blocked by sec_watch.sh"
#	fi
#	printf "%-10s %-15s %-15s %-10s %-5s\n" "$type" "$ip" "$user" "$count" "$risk" >> "REPORT_FILE"

#}

#for key in "${!failed_attempts[@]}"; do
#	IFS="|" read -r ip user <<< "$key"
#	report_entry "Failed" "$ip" "$user" "${failed_attempts[$key]}"
#done

#for key in "${!invalid_users[@]}"; do
#	IFS="|" read -r ip user <<< "$key"
#	report_entry "Invalid" "$ip" "$user" "${invalid_users[$key]}"
#done

#for key in "${!accepted_logins[@]}"; do
#	IFS="|" read -r ip user <<< "$key"
#	report_entry "Accepted" "$ip" "$user" "${accepted_logins[$key]}"
#done

#for user in "${!session_opened["]}"; do
#	printf "%-10s %-15s %-15s %-10s %-5s\n" "Session" "-" "$user" "${session_opened[$user]}" "Låg" >> "$REPORT_FILE"
#done
#
#echo "[INFO] Rapport genererad: $REPORT_FILE"

#---------------- Avslutning - Logga och Rensa 

#Skickar rapporten via e-post
#if command -v mail &>/dev/null; then
#	mail -s "Daglig säkerhetsrapport från $(hostname)" "$ADMINEMAIL_FILE" < "$REPORT_FILE"
#	echo "[INFO] Rapport skickad till $ADMINEMAIL_FILE"
#else
#	echo "[VARNING] mail-kommandot saknas - kunde inte skicka e-post!"
#fi

#Kontrollerar om mail-kommandot finns
#Om det finns, skickar rapporten, annars skrivs en varning

#Aktiverar loggar äldre än 7 dagar
#echo "[INFO] Aktiverar äldre loggfiler..."
#mkdir -p "$ARCHIVEDIR_FILE"
#find /var/log -type f \( -name "*.log" -o -name "*.gz" \) -mtime +7 -exec tar -rvf "$ARCHIVEDIR_FILE/log_backup_$(date +%Y%m%d).tar" {} \; -exec rm -f {} \;

#Hittar .log och .gz-filer som är äldre än 7 dagar, sparar dem i ett tar-arkiv och tar bort originalen.




#echo "[KLART] Säkerhetsanalys slutförd. Rapport sparad i $REPORT_FILE."