#!/bin/bash

#METADATA-KOMMENTARER
#Skript av: Sanna Nilsson 
#Datum: 2 april 2025 
#Syfte: Ett skript för att analysera loggfiler och generera en rapport.
#---------------------
#Vad:
#Hur:
#Varför:

#VARIABLER och TYPER

LOG_FILE="/var/log/syslog"
REPORT_FILE="log_report.txt"
echo "Ange max antal rader att analysera: "
read MAX_LINES


#Fil där analysrapporten sparas
#Fil där rapporten ska lagras
#Läser användarinput för att bestämma hur många rader som ska anlyseras

if [ ! -r "$LOG_FILE" ]; then
echo "Loggfilen hittades inte!"
exit 1
fi

if ! [[ "$MAX_LINES" =~ ^[0-9]+$ ]] || (( MAX_LINES <= 0 )); then
    echo "Ogiltigt antal rader, ange ett positivt heltal!" 
    exit 1
fi

#Kontrollerar om loggfilen finns och är läsbar"
#Validerar att MAX_LINES är ett positivt heltal

ERROR_COUNT=0
head -n "$MAX_LINES" "$LOG_FILE" | while read -r line;do 

ERROR_COUNT=$((ERROR_COUNT + $(echo "$line" | grep -c "error")))
done

#Loopar igenom de första MAX_LINES raderna i loggfilen rad för rad

generate_report(){
    echo "Logganalysrapport - $(date)" >> "$REPORT_FILE"
    echo "Antal felmeddelanden: $ERROR_COUNT" >> "$REPORT_FILE"
}

#Funktion för att generera en rapport baserat på logganalysen

generate_report
#Anropar rapportfunktionen

echo "Analysen är klar. $ERROR_COUNT fel hittades. Rapport sparad i $REPORT_FILE"
#Visar en sammanfattning av analysen för användaren.
