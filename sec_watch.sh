#!/bin/bash

#Skapat av: Sanna Nilsson, 9 april 2025 
#Namn: Övervakning och analys av säkerhetsloggar på Ubuntu Server
#Skapar ett Bash-skript som övervakar och analyserar säkerhetsloggar på 
#Ubuntu Server (/var/log/auth.log och /var/log/syslog) för att identifiera, 
#rapportera och reagera på misstänkt aktivitet.

readonly LOG_FILE="/var/log/syslog /var/log/auth.log"
readonly REPORT_FILE="sec_watch_report.txt"
readonly TEMP_FILE="/tmp/sec_watch_$$.tmp"
SIZE_THRESHOLD="${2:-1048576}"
readonly SIZE_THRESHOLD=1048576
readonly TARGET_DIR="$1"

#readonly gör variablerna skrivskyddade för säkerhet
# /var/log/syslog och /var/log/auth.log är sökvägar till loggfilen som ska analyseras 
# sec_watch_report.txt är fil där analysrapporten sparas
# $1 tar katalogen från kommandoraden 
# 1 MB i bytes
# "$1" - Första argumentet är katalogen

set -e  #Avsluta vid fel
set -u  #Fel om odentifierade variabler används

	echo "Ange max antal rader att analysera:"
	read MAX_LINES

#Läser användarinput för att bestämma hur många rader som ska analyseras.

