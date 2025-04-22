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

# Aktiverar brandvöggen för angivna profiler (Domain, Private, Public)
function Enable-AllFirewallProfiles {
    param (
        [string[]]$Profiles
        )

    foreach ($profile in $Profiles) {
        Set-NetFirewallProfile -Profile $profile -Enabled True #-WhatIf
        #Write-Host "[TEST] Skulle aktivera brandvägg för: $profile"
        Write-Host "$profile firewall activated"
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


# -------------------- Huvudlogiken--------------------------
Enable-AllFirewallProfiles -Profiles $FirewallProfiles
Enable-AllowPorts -Ports $AllowedPorts -Protocol $Protocol
