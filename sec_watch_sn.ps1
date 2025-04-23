# PowerShell-skript sec_watch_sn.ps1
# Skapat av: Sanna Nilsson, 22 april 2025
# Namn: Omfattande säkerhetskontroll och härdning av Windows-servrar
# Utför en djupgående säkerhetsrevision och automatiskt härdar en Windows-server
# enligt avancerade säkerhetsstandarder.

#---------------Konfiguration - Variabler för Loggar och Rapporter-------------------

# Namn på brandväggsprofiler som ska konfigureras
#$FirewallProfiles = @("Domain", "Private", "Public")

# Lista på portar som ska tillåtas (TCP)
$AllowedTCPPorts = @(3389, 443)  # RDP, HTTPS

# Protokoll - används om vi kör samma protokoll för flera portar
# Eftersom vissa portar (DNS) används med både TCP och UDP, och DHCP använder endast UDP,
# är det bra att hålla isär dem för tydligheten
#$ProtocolTCP = "TCP"
#$ProtocolUDP = "UDP"

# Loggar alla åtgärder och resultat i loggfilen
$LogFile = "security_hardening_$(Get-Date -Format 'yyyyMMdd').log"

#----------------Funktioner---------------------------

#Funktion för att skriva till loggfil
#Parameter 1: log level INFO, WARNING, ERROR eller valfri text
#Parameter 2: Meddelandet som skall skrivas till logfilen
function log_message {
    param (
        [string]$log_level,
        [string]$message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $log_entry = "$timestamp [$log_level] $message"
    
    # Skriv till loggfilen
    Add-Content -Path $LogFile -Value $log_entry
}

function create_logfile {
    # Kontrollera om filen finns
    if (Test-Path $LogFile) {
        # Töm innehållet 
            Clear-Content -Path $LogFile
            log_message "INFO" "Loggfilen tömd"
        } else {
        # Skapa filen om den inte fanns
            New-Item -Path $LogFile -ItemType File | Out-Null
            log_message "INFO" "Skapat loggfilen $LogFile"
        }
}

# Kontrollerar om brandväggen är aktiv
function Enable-WindowsFirewall {
    param (
        [string[]]$Profiles = @("Domain", "Private", "Public")
    )
    # Kontrollerar brandväggsstatus för varje profil och aktiverar den om den är inaktiv
    foreach ($profile in $Profiles) {
        $status = (Get-NetFirewallProfile -Profile $profile).Enabled

        if ($status -eq $false) {
            Set-NetFirewallProfile -Profile $profile -Enabled True
            #Write-Host "$profile-branväggen har aktiverats"
            log_message "WARNING" "$profile-branväggen har aktiverats"
            }
    # Skriver ut ett meddelande för varje profil
        else {
            #Write-Host "$profile-branväggen är redan aktiv."
            log_message "INFO" "$profile-branväggen är redan aktiv"
        }
    }
}

# Tillåter specifika portar för angivet protokoll 
# Tillåter RDP och HTTPS (TCP)
function Enable-AllowRequiredPorts {
    # Tillåter TCP för RDP (3389) och HTTPS (443)
    foreach ($port in $AllowedTCPPorts) {
        $ruleName = "Allow TCP $port"
        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any
            log_message "INFO" "Tillåter port $port för TCP"
        } else {
            log_message "INFO" "Regeln för TCP-port $port finns redan"
        }
    }
    # Tillåter DNS (TCP port 53)
    if (-not (Get-NetFirewallRule -DisplayName "Allow DNS TCP" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "Allow DNS TCP" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow -Profile Any
        log_message "INFO" "DNS TCP-regel skapades"
    } else {
        log_message "INFO" "Regeln för DNS TCP finns redan"
    }

    # Tillåter DNS (UDP port 53)
    if (-not (Get-NetFirewallRule -DisplayName "Allow DNS UDP" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "Allow DNS UDP" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -Profile Any
        log_message "INFO" "DNS UDP-regel skapades"
    } else {
    log_message "INFO" "Regeln för DNS UDP finns redan"
    }

    # Tillåter DHCP Client (UDP portar 67-68)
    if (-not (Get-NetFirewallRule -DisplayName "Allow DHCP Client" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "Allow DHCP Client" -Direction Inbound -Protocol UDP -LocalPort @(67,68) -Action Allow -Profile Any
        log_message "INFO" "DHCP-regel skapades"
    } else {
    log_message "INFO" "Regeln för DHCP finns redan"
    }
}


#function Block-AllOtherInbound {
    # Blockera all annan inkommande trafik
#    New-NetFirewallRule -DisplayName "Block All Other Inbound" -Direction Inbound -Action Block -Profile Any
#}

# Funktion för att kontrollera och aktivera Windows Defender
function Get-WindowsDefenderStatus {
    # Hämtar information om Windows Defender
    $DefenderStatus = Get-MpComputerStatus
    
    # Kontrollerar om Windows Defender är aktiverat
    if ($DefenderStatus.AntivirusEnabled -eq $false) {
        Write-Host "Windows Defender är inte aktiverat. Vi aktiverar det nu..."
        Set-MpPreference -DisableRealtimeMonitoring $false
        #Write-Host "Windows Defender är nu aktiverat."
        log_message "WARNING" "Windows Defender var inte aktivt - aktiverades."
    } else {
        #Write-Host "Windows Defender är redan aktiverat."
        log_message "INFO" "Windows Defender är redan aktiverat."
    }
    
    # Kontrollerar om definitionsfilerna är uppdaterade
    # Om Windows Defender är inte uppdaterat startar en fullständig skanning
    if ($DefenderStatus.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-1)) {
        #Write-Host "Windows Defender definitionsfiler är inte uppdaterade. Vi uppdaterar dem nu..."
        log_message "WARNING" "Definitionsfilerna var gamla - uppdateras nu."

        Update-MpSignature
        #Write-Host "Definitionsfilerna har nu uppdaterats."
        log_message "INFO" "Definitionsfilerna har nu uppdaterats."

        #Write-Host "Startar en fullständig skanning..."
        Start-MpScan -ScanType FullScan
        log_message "INFO" "Fullständig skanning startad."
    } else {
        #Write-Host "Definitionsfilerna är aktuella. Ingen skanning behövs."
        log_message "INFO" "Definitionsfilerna är aktuella. Ingen skanning utförd."
    }
}     

# Funktion för att aktivera brandväggsprofiler ()

# -------------------- Huvudlogiken--------------------------

create_logfile
log_message
Enable-WindowsFirewall 
#Enable-AllFirewallProfiles -Profiles $FirewallProfiles
Enable-AllowRequiredPorts
#Block-AllOtherInbound

# Slår på brandväggen för varje profil (Domain, Privat, Public)
# Tillåter RDP (3389) och HTTPS (443) med TCP-protokollet

# Kontrollerar och härdar Windows Defender
Get-WindowsDefenderStatus

