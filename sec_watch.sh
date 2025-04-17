#!/bin/bash

#Skapat av: Sanna Nilsson, 9 april 2025 
#Namn: Övervakning och analys av säkerhetsloggar på Ubuntu Server
#Skapar ett Bash-skript som övervakar och analyserar säkerhetsloggar på 
#Ubuntu Server (/var/log/auth.log och /var/log/syslog) för att identifiera, 
#rapportera och reagera på misstänkt aktivitet.

#---------------Konfiguration - Variabler för Loggar och Rapporter

readonly SYSLOG_FILE="/var/log/syslog"            # Sökväg till loggfilen som ska analyseras 
readonly AUTHLOG_FILE="/var/log/auth.log"         # Sökväg till loggfilen som ska analyseras 
readonly REPORT_FILE="security_report_$(date +%Y%m%d).txt" # Fil där analysrapporten sparas med dagens datum på rapporten
readonly TMP_FILE="/tmp/sec_watch_$$.tmp"         # $$ är process-ID för att undvika konflikter i temporära filer
readonly ACTIONLOG_FILE="/var/log/security_actions.log"       # Loggar åtgärden om blockerade ip:n med ufw
readonly ARCHIVEDIR_FILE="/backup/logs"           # Hit arkiveras och komprimeras loggar
readonly ADMINMAIL_FILE="testkali@testkalilinuxcl-2" # Hit mejlas rapporten till administratören
readonly SCRIPT_NAME=$(basename "$0")             # Skriptnamn för loggning
readonly THRESHOLD=5                            # Anger tröskelvärde för försök innan ip:n räknas som "hög risk"
readonly LOG=log.txt                            #Arbetfil för kontroller av skriptet

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

# Loggar meddelanden med tidsstämpel

log_message() {
	local level="$1"          # INFO, WARNING, ERROR
	local message="$2"
#printf "%s [%s] %s: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$SCRIPT_NAME" "$message" >> "$REPORT_FILE"
  echo "$(date '+%F %T') [$level] $message" >> "$REPORT_FILE"
}

# Skickar e-postvarning
send_alert() {
    local ip="$1"
    local attempts="$2"
    local subject="Hög risk varning: $ip överskred tröskelvärdet"
    local body="IP $ip hade $attempts misslyckade försök. Se $ACTIONLOG_FILE för detaljer."

    echo -e "$body" | mail -s "$subject" "$ADMINMAIL_FILE"
}
#Kontrollerar om filen är läsbar
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

# Försöker skapa filen om den inte finns och döljer eventuella felmeddelanden från touch.
# Om skapa filen misslyckas, skriver ett felmeddelande till loggen och avslutar skriptet med felkod.
check_file_writable() {
  local file="$1"
  if [[ ! -w "$file" ]]; then
  touch "$file" 2>/dev/null || {
    log_message "ERROR" "Kan inte skriva till $file. Kontrollera behörigheter"
    exit 1
  }
  fi
}

# Funktionen kontrollerar en fil och räknar misslyckade inloggningsförsök.
count_risk() {
    local input_file="$1"
    local temp_warnings="/tmp/ip_warnings_$$.txt"
    touch "$temp_warnings"

    awk -v out="$temp_warnings" -v threshold="$THRESHOLD" '{
    ip_counts[$1]++
    time[$1] = $3
    user[$1] = $2
    } 
    END {
    for (ip in ip_counts) {
        if (ip_counts[ip] > threshold) {
            printf "IP: %s | User: %s | Time: %s | Attempts: %d\n", ip, user[ip], time[ip], ip_counts[ip] > out
        }
    }
}' "$input_file"


    # Läs från tempfilen och anropa log_message rad för rad
    while IFS= read -r line; do
        log_message "ERROR" "$line"
        ip=$(echo "$line" | grep -oP 'IP:\s*\K[\d\.]+')
        attempts=$(echo "$line" | grep -oP 'Attempts:\s*\K\d+')
        send_alert "$ip" "$attempts"
    done < "$temp_warnings"

    #rm -f "$temp_warnings"
}


# Funktion för att blockera IP
block_ip() {
    local ip="$1"
    sudo ufw deny from "$ip"
    log_message "ACTION" "Blocked IP: $ip via UFW"
}

#Städar tmp-filer
#cleanup() {
#rm -f "$TMP_FILE"
#log_message "INFO" "Rensade temporära filer"
#Tömmer rapportfilen
#> "$REPORT_FILE"
#exit 0
#}


# ------------------- Huvudlogik - Kontrollerar, Filtrerar och Analyserar Loggar --------------

# Kontrollerar att båda loggfilenra existerar och är läsbara

check_file_readable "$AUTHLOG_FILE"
check_file_readable "$SYSLOG_FILE"

# Kontrollerar att filen är skrivbar
check_file_writable "$ACTIONLOG_FILE"

# Skapar temporär arbetsfil där vi sparar loggrader för analys
touch "$TMP_FILE"
touch "$REPORT_FILE"
#Tömmer rapportfilen
> "$REPORT_FILE"

log_message "INFO" "Extraherar loggar från senaste 24 timmar"
#grep -E "password check failed|authentication failure|session opened" $AUTHLOG_FILE | awk -v cutoff="$(date -d '4 hours ago' +%s)" > $TMP_FILE
#grep -E "password check failed|authentication failure|session opened" $SYSLOG_FILE > $TMP_FILE
#awk -v Date="$(date --date='1 day ago' '+%b %_d')" '$0 ~ Date' "$AUTHLOG_FILE" "$SYSLOG_FILE" > "$TMP_FILE"

# Skapar datumsträng för 24 timmar sen
SINCE=$(date -d '48 hours ago' --iso-8601=seconds)

log_message "INFO" "Filtrerar rader från loggfilen de senaste 24 timmarna..."
log_message "INFO" "Starttid: $SINCE"
log_message "INFO""---------------------------------------------"

# Filtrerar och skriver ut loggrader
awk -v since="$SINCE" '{
    log_time = substr($0, 1, 19)
    if (log_time >= since) print
}' "$AUTHLOG_FILE" "$SYSLOG_FILE" > "$TMP_FILE"

# Extraherar relevanta rader från senaste 24h och skickar dem till $TMP_FILE
# Sparar dem i $TMP_FILE 

grep -E "password check failed|authentication failure|Invalid user|session opened" "$TMP_FILE" > "$ACTIONLOG_FILE"
# grep -i "password checked failed" "$AUTHLOG_FILE" > "$REPORT_FILE
# echo "[KLART] Rader sparade till: $REPORT_FILE
# awk -v Date="$(date --date='1 day ago' '+%b %_d')" '$0 ~ Date' "$AUTHLOG_FILE" "$SYSLOG_FILE" > "$TMP_FILE" 
# grep "password checked failed" "$AUTHLOG_FILE" > "$TMP_FILE" 
# Extraherar relevanta rader från senaste 24h Extraherar loggar från senaste 24 timmar ..."

# 1. Kontrollera om "Invalid user" förekommer och skriv ut IP, user och tid
grep "Invalid user" "$ACTIONLOG_FILE" | while read -r line; do
    ip=$(echo "$line" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
    user=$(echo "$line" | grep -oP "Invalid user \K[a-zA-Z0-9._-]+")
    timestamp=$(echo "$line" | awk '{print $1, $2, $3}')
    log_message "ERROR" "Invalid user detected! IP: $ip | User: $user | Time: $timestamp"
    block_ip "$ip"
    echo "Blocked IP: $ip"
done

# 2. Extrahera IP, user och timestamp från authentication failure
awk '/authentication failure/ {
    match($0, /^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+)/, ts)
    match($0, /rhost=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/, ip)
    match($0, /user=([a-zA-Z0-9._-]+)/, usr)
    if (ip[1] && usr[1] && ts[1]) {
        print ip[1], usr[1], ts[1]
    }
}' "$ACTIONLOG_FILE" > "$LOG"

#För varje rad i loggfieln skriver vi ut WARNING och information till Rapportfieln med funktionen log_message
while read -r ip user timestamp; do
  log_message "WARNING" "Misslyckad inloggning! IP: $ip | User: $user | Time: $timestamp"

done < "$LOG"

#risk_to_log "$LOG"
count_risk "$LOG"

# Analyserar filen för misslyckade inloggningsförsök och plockar ut de viktigaste parametrarna: 
# tiden, IP och användarnamn.
# Loopen går igenom varje rad i $LOG och loggar ett varningsmeddelnade.

#Skickar rapporten via e-post
#if command -v mail &>/dev/null; then
#	mail -s "Daglig säkerhetsrapport från $(hostname)" "$ADMINEMAIL_FILE" < "$REPORT_FILE"
#	echo "[INFO] Rapport skickad till $ADMINEMAIL_FILE"
#else
#	echo "[VARNING] mail-kommandot saknas - kunde inte skicka e-post!"
#fi

#Kontrollerar om mail-kommandot finns
#Om det finns, skickar rapporten, annars skrivs en varning

#Analyserar resultatet och agera
#while read -r count ip user; do
  # Ignorerar tomma rader eller ogiltiga rader
  #[[ -z "$count" || -z "$ip" || "$user" ]] && continue

  #if (( count > THRESHOLD )); then
    #risk="HÖG RISK"
    #echo "$(date '+%F %T') -IP: $ip, Användare: $user, Försök: $count, Risk: $risk >> "$REPORT_FILE"
    #log_message "WARNING" "IP $ip med användare $user hade $count försök - $risk"
    #else
    #risk="Låg risk"
    #echo "$(date '+%F %T') -IP: $ip, Användare: $user, Försök: $count, Risk: $risk >> "$REPORT_FILE"
    #log_message "INFO" "IP $ip med användare $user hade $count försök - $risk"
  #fi
  #done < "$TMP_FILE"

# Genererar rapport och mejlar den till administrator

#mail -s "Säkerhetsrapport $(date '+%F')" "$ADMINMAIL" < "$REPORT_FILE"

#Öppnar eller skriver över rapportfilen.

# Funktion för att generera en rapport för att lägga till varje ip/användare

#generate_report() {
#  echo "Logganalysrapport - $(date)" >> "$REPORT_FILE"
#  echo "Antal felmeddelanden: $SHRESHOLD" >> "$REPORT_FILE"
#}
 
#
#echo "[INFO] Rapport genererad: $REPORT_FILE"

#---------------- Avslutning - Logga och Rensa 

# Aktiverar loggar äldre än 7 dagar
#echo "[INFO] Aktiverar äldre loggfiler..."

# Katalog där arkivet ska sparas
#mkdir -p "$ARCHIVEDIR_FILE"

# Namn på arkivfilen (datumstämpel)
#find /var/log -type f \( -name "*.log" -o -name "*.gz" \) -mtime +7 -exec tar -rvf "$ARCHIVEDIR_FILE/log_backup_$(date +%Y%m%d).tar" {} \; -exec rm -f {} \;

#Hittar .log och .gz-filer som är äldre än 7 dagar, sparar dem i ett tar-arkiv och tar bort originalen.

#echo "[KLART] Säkerhetsanalys slutförd. Rapport sparad i $REPORT_FILE."