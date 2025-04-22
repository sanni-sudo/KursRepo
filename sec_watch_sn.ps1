# PowerShell-skript sec_watch_sn.ps1
# Skapat av: Sanna Nilsson, 22 april 2025
# Namn: Omfattande säkerhetskontroll och härdning av Windows-servrar
# Utför en djupgående säkerhetsrevision och automatiskt härdar en Windows-server
# enligt avancerade säkerhetsstandarder.

#---------------Konfiguration - Variabler för Loggar och Rapporter-------------------

# Namn på brandväggsprofiler som ska konfigureras
$FirewallProfiles = @("Domain", "Private", "Public")

# Lista på portar som ska tillåtas (exempel: RDP=3389, HTTPS=443)
$AllowedPorts = @(3389, 443)

# Protokoll för reglerna
$Protocol = "TCP"

#----------------Funktioner---------------------------

# Kontrollerar om brandväggen är aktiv
function Enable-WindowsFirewall {
    param (
        [string[]]$Profiles = @("Domain", "Private", "Public")
    )
    foreach ($profile in $Profiles) {
        $status = (Get-NetFirewallProfile -Profile $profile).Enabled

        if ($status -eq $false) {
            Set-NetFirewallProfile -Profile $profile -Enabled True
            Write-Host "$profile-branväggen har aktiverats"
        }
        else {
            Write-Host "$profile-branväggen är redan aktiv."
        }
    }
}

# Aktiverar brandväggen för angivna profiler (Domain, Private, Public)
function Enable-AllFirewallProfiles {
    param (
        [string[]]$Profiles
        )

    foreach ($profile in $Profiles) {
        Set-NetFirewallProfile -Profile $profile -Enabled True #-WhatIf
        #Write-Host "[TEST] Skulle aktivera brandvägg för: $profile"
        Write-Host "$profile brandvägg har aktiverats"
    }
}

# Tillåter specifika portar för angivet protokoll (t.ex. TCP)
function Enable-AllowPorts {
    param (
        [int[]]$Ports,
        [string]$Protocol
    )

    foreach ($port in $Ports) {
        New-NetFirewallRule -DisplayName "Allow Port $port" -Direction Inbound -Action Allow -Protocol $Protocol -LocalPort $port -Profile Any #-WhatIf
        #Write-Host "[TEST] Skulle skapa regel för port $port via $Protocol"
        Write-Host "Tillåter port $port för $Protocol"
    }
}

# Funktion för att kontrollera och aktivera Windows Defender
function Get-WindowsDefenderStatus {
    # Hämtar information om Windows Defender
    $DefenderStatus = Get-MpComputerStatus
    
    # Kontrollerar om Windows Defender är aktiverat
    if ($DefenderStatus.AntivirusEnabled -eq $false) {
        Write-Host "Windows Defender är inte aktiverat. Vi aktiverar det nu..."
        Set-MpPreference -DisableRealtimeMonitoring $false
        Write-Host "Windows Defender är nu aktiverat."
    } else {
        Write-Host "Windows Defender är redan aktiverat."
    }
    # Kontrollerar om definitionsfilerna är uppdaterade
    if ($DefenderStatus.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-1)) {
        Write-Host "Windows Defender definitionsfiler är inte uppdaterade. Vi uppdaterar dem nu..."
        Update-MpSignature
        Write-Host "Definitionsfilerna har nu uppdaterats."
    } else {
        Write-Host "Windows Defender definitionsfiler är redan uppdaterade."
    }
    # Om definitionsfilerna inte är uppdaterade, startar en fullständig skanning
    if ($DefenderStatus.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-1)) {
        Write-Host "Startar en fullständig skanning..."
        Start-MpScan -ScanType FullScan
        Write-Host "Fullständig skanning har startat."
    }
}

# Funktion för att aktivera brandväggsprofiler ()

# -------------------- Huvudlogiken--------------------------
Enable-WindowsFirewall 
#Enable-AllFirewallProfiles -Profiles $FirewallProfiles
#Enable-AllowPorts -Ports $AllowedPorts -Protocol $Protocol 

# Slår på brandväggen för varje profil (Domain, Privat, Public)
# Tillåter RDP (3389) och HTTPS (443) med TCP-protokollet

# Kontrollerar och härdar Windows Defender
#Get-WindowsDefenderStatus

