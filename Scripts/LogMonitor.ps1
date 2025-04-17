# LogMonitor.ps1 - Övervakar loggilfer för misstänkta nyckelord
# Skapat av: Sanna Nilsson, 16 april 2025
# Syfte: Skanna loggar, loggar resultat och varna om problem

#-------------- Konfiguration ----------------
$LogDir = "/home/testkali/Logs"             # Platsen där loggfilerna finns
$OutputLog = "/home/testkali/Logs/monitor.log"      # Anger var skriptets egen logg sparas
$Keywords = @("error", "failed")               # En lista/array skapad med @() med sökord

# Variabler lagrar inställningar som skriptet behöver. 
# Genom att definiera sökvägen till loggkatalogen, platsen för resultatloggen och nyckelord att 
# söka efter görs skriptet flexibelt och lätt att ändra.

#-------- Funktioner --------------
function Write-Log {
    param (
        [Parameter(Mandatory=$true)][string]$Level,
        [Parameter(Mandatory=$true)][string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$Level] $Message" | Out-File -FilePath $OutputLog -Append
}
 # Funktioner gör koden återanvändbar och organiserad
 # Write-Log-funktionen loggar meddelanden till $OutputLog med en tidsstämple, nivå
 # (t.ex. INFO, ERROR) och meddelande.
 # Parametrarna $Level och $Message definieras med param-blocket, där [string] 
 # säkerställer att de är text och [Parameter(Mandatory=$true)] gör dem
 # obligatoriska.
 # Get-Date skapar en tidstämpel i formatet "är-månad-dag time:minut:sekund"
 # Strängen "$timestamp [$Level] $Message" kombinerar tid, nivå och meddelande.
 # Out-File skriver till filen specificerad i $OutputLog.
 # -Append lägger till istället för att skriva över.
 # Detta följer bästa praxis genom att centralisera logging, vilket ger konsekvent 
 # formatering och spårbarhet.

 