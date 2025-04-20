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
readonly ACTIONLOG_FILE="/var/log/security_actions_$$.log"       # Loggar åtgärden om blockerade ip:n med ufw
readonly ARCHIVEDIR="/backup/logs"           # Hit arkiveras och komprimeras loggar
readonly ADMINMAIL="testkali@testkalilinuxcl-2" # Hit mejlas rapporten till administratören
readonly THRESHOLD=5                            # Anger tröskelvärde för försök innan ip:n räknas som "hög risk"
readonly LOG="log.txt"                            #Loggfil för att samla "authentication failure"
readonly SUSSPECTLOG_FILE="susspect_log.txt"      #Loggfil för misstänkta inloggningsförsök

# readonly gör variablerna skrivskyddade för säkerhet, dvs värdet ska inte ändras senare i skriptet 

#----------------Säkerhetsåtgärder - Felhantering och avbrott
# set -e avbryter skriptet om ett fel uppstår
# set -u avbryter skriptet om man försöker använda en variabel som inte finns
# trap skriver ut meddelande om något avbryter eller tycker på Ctrl+C
# Detta skyddar mot oväntade problem och rensar upp vid avbrott. 

#set -e 
#set -u  
#trap 'echo "Skript Avbrutet!"; rm -f "$TMP_FILE"; exit 1' INT TERM EXIT

 

#-----------------Funktioner - Loggning och Varningar

# Loggar meddelanden med tidsstämpel

log_message() {
	local level="$1"          # INFO, WARNING, ERROR
	local message="$2"
  printf "%s [%s] %s:\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" >> "$REPORT_FILE"
}

# Skicka en rapport till SäkAdmin
send_mail_with_attachment() {
    local subject="Daglig rapportfil Linux servermiljö"
    #local body="Här kommer den dagliga genererade loggfilen med misstänkta inloggningsförsök"
    local recipient="$ADMINMAIL"  
    local attachment="$REPORT_FILE"     

  
    # Kontrollera att rapporten verkligen finns
    if [[ ! -f "$attachment" ]]; then
        echo "[ERROR] Rapporten saknas: $attachment"
        return 1
    fi

    # Skicka meddelande med rapportinnehållet
    mail -s "$subject" "$recipient" < "$attachment"
    echo "Rapporten skickad"
}

# Om någon fil inte finns eller saknar läsbehörighetet, skriver ett felmeddelande och avslutar skriptet
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
# Testar om filen är skrivbar
# Försöker skapa filen om den inte finns och döljer eventuella felmeddelanden från touch.
# Om skapa filen misslyckas, skriver ett felmeddelande till loggen och avslutar skriptet med felkod.
check_file_writable() {
  local file="$1"

  # Om filen inte är skrivbar
  if [[ ! -w "$file" ]]; then
    # Försök skapa filen om den inte finns
    if ! touch "$file" 2>/dev/null; then
      log_message "ERROR" "Kan inte skriva till $file. Kontrollera behörigheter"
      exit 1
    fi
  fi

  log_message "INFO" "$file finns och är skrivbar"
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


    # Läs från tempfilen som bara innehåller fler än THRESHOLD försök --> HÖG RISK
    # Skriv till rapportfil
    while IFS= read -r line; do
        log_message "HÖG RISK" "$line"
        ip=$(echo "$line" | grep -oP 'IP:\s*\K[\d\.]+')
        attempts=$(echo "$line" | grep -oP 'Attempts:\s*\K\d+')
    done < "$temp_warnings"
    
    rm -f "$temp_warnings"
}


# Funktion för att blockera IP
block_ip() {
    local ip="$1"
    sudo ufw deny from "$ip"
    log_message "ACTION" "Blocked IP: $ip via UFW"
}

archive_logs() {
    # Definiera loggfil och destination
    local archive_name="security_logs_backup_$(date +%Y%m%d).tar"

    # Skapa målarkivkatalog om den inte finns
    mkdir -p "$ARCHIVEDIR"

    # Hitta loggar som är äldre än 7 dagar och arkivera dem
    find /var/log -type f -name "security_actions_*.log" -mtime +7 -exec tar -rvf "$ARCHIVEDIR/$archive_name" {} \; -exec rm -f {} \;

    # Skriv ut ett meddelande
    echo "[INFO] Loggar äldre än 7 dagar har arkiverats till $ARCHIVEDIR/$archive_name."
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

# Skapar temporär arbetsfil där vi sparar loggrader för analys
touch "$TMP_FILE"
touch "$REPORT_FILE"
#Tömmer rapportfilen om vi kört testet mer än en gång de senaste 24 timmarna.
> "$REPORT_FILE"
# Kontrollerar att båda loggfilenra existerar och är läsbara

check_file_readable "$AUTHLOG_FILE"
check_file_readable "$SYSLOG_FILE"

# Kontrollerar att filen är skrivbar
check_file_writable "$ACTIONLOG_FILE"
check_file_writable "$SUSSPECTLOG_FILE"
check_file_writable "$TMP_FILE"
check_file_writable "$REPORT_FILE"
check_file_writable "$LOG"

# Skapar datumsträng för 24 timmar bakåt formaterat på samma format som i våra loggfiler(ISO-8601)
SINCE=$(date -d '48 hours ago' --iso-8601=seconds)

# Skriver generell info till rapportfilen
log_message "INFO" "Extraherar loggar från senaste 24 timmar"
log_message "INFO" "Starttid: $SINCE"
log_message "INFO""---------------------------------------------"

# Tar syslog och auth.log från de senaste 24 h och skriver dem till en temporär fil
# Denna temporära fil används sedan för att filtrera ut misstänkta händelser
awk -v since="$SINCE" '{
    log_time = substr($0, 1, 19)
    if (log_time >= since) print
}' "$AUTHLOG_FILE" "$SYSLOG_FILE" > "$TMP_FILE"

# Extraherar relevanta rader från temporär fil och skickar 
grep -E "password check failed|authentication failure|Invalid user|session opened" "$TMP_FILE" > "$SUSSPECTLOG_FILE"

# Kontrollerar om "Invalid user" förekommer och skriver ut IP, användare tid och övrig info till rapportfil
# Om "Invalid user" förekommer blockeras denna IP i ufw på första förekomsten
grep "Invalid user" "$SUSSPECTLOG_FILE" | while read -r line; do
    ip=$(echo "$line" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
    user=$(echo "$line" | grep -oP "Invalid user \K[a-zA-Z0-9._-]+")
    timestamp=$(echo "$line" | awk '{print $1, $2, $3}')
    log_message "HÖG RISK" "Invalid user detected! IP: $ip | User: $user | Time: $timestamp"
    block_ip "$ip"
    echo "Blocked IP: $ip"
done

# Kontrollerar om "authentication failure" förekommer och skriver ut IP, användare tid och övrig info till logfil
awk '/authentication failure/ {
    match($0, /^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+)/, ts)       #Datum och tid
    match($0, /rhost=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/, ip)         #IP-adress
    match($0, /user=([a-zA-Z0-9._-]+)/, usr)                        #Användarnamn
    match($0, /([a-zA-Z]+[0-9]+)/, proto)                           #Protokoll

    if (ip[1] && usr[1] && ts[1]) {
        print ip[1], usr[1], ts[1], "Protocol" proto[1]
    }
}' "$SUSSPECTLOG_FILE" > "$LOG"

#För varje rad i loggfilen skriver vi ut WARNING och information till rapportfilen
while read -r ip user timestamp; do
  log_message "MEDEL RISK" "Misslyckad inloggning! IP: $ip | User: $user | Time: $timestamp"
done < "$LOG"

# Räknar hur många authentication failures varje unik IP finns i loggfilen
count_risk "$LOG"

# Maila rapport till säkadmin
send_mail_with_attachment
echo "[INFO] Rapport genererad: $REPORT_FILE"
echo "[KLART] Säkerhetsanalys slutförd. Rapport sparad i $REPORT_FILE."

# Arkivera loggar äldre än 7 dagar
archive_logs

