# PowerShell-skript sec_watch_sn.ps1
# Skapat av: Sanna Nilsson, 22 april 2025
# Namn: Omfattande säkerhetskontroll och härdning av Windows-servrar
# Utför en djupgående säkerhetsrevision och automatiskt härdar en Windows-server
# enligt avancerade säkerhetsstandarder.

#---------------Konfiguration - Variabler för Loggar och Rapporter-------------------

# Namn på brandväggsprofiler som ska konfigureras
$FirewallProfiles = @("Domain", "Private", "Public")

# Lista på portar som ska tillåtas (TCP)
$AllowedTCPPorts = @(3389, 443, 53)     # RDP, HTTPS, DNS (TCP)

# Lista på portar som ska tillåtas (UDP)
$AllowedUDPPorts = @(53, 67,68)         # DNS (UDP), DHCP

# Protokoll - används om vi kör samma protokoll för flera portar
# Eftersom vissa portar (DNS) används med både TCP och UDP, och DHCP använder endast UDP,
# är det bra att hålla isär dem för tydligheten
$ProtocolTCP = "TCP"
$ProtocolUDP = "UDP"

#----------------Funktioner---------------------------

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
            Write-Host "$profile-branväggen har aktiverats"
            }
    # Skriver ut ett meddelande för varje profil
        else {
            Write-Host "$profile-branväggen är redan aktiv."
        }
    }
}

# Tillåter specifika portar för angivet protokoll 
# Tillåter RDP och HTTPS (TCP) protokoll
function Enable-AllowRequiredPorts {
        $tcpPorts = @(3389, 443)
#    param (
#        [int[]]$Ports,
#        [string]$Protocol
#    )
        foreach ($port in $tcpPorts) {
        New-NetFirewallRule -DisplayName "Allow TCP $port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any 
        Write-Host "Tillåter port $port för $Protocol"
    }
# DNS (TCP och UDP)
New-NetFirewallRule -DisplayName "Allow DNS TCP" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "Allow DNS UDP" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -Profile Any

# DHCP (UDP port 67-68)
New-NetFirewallRule -DisplayName "Allow DHCP Client" -Direction Inbound -Protocol UDP -LocalPort 67,68 -Action Allow -Profile Any
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
Enable-AllowPorts -Ports $AllowedTCPPorts -Protocol $ProtocolTCP 
Enable-AllowPorts -Ports $AllowedUDPPorts -Protocol $ProtocolUDP 
#Block-AllOtherInbound

# Slår på brandväggen för varje profil (Domain, Privat, Public)
# Tillåter RDP (3389) och HTTPS (443) med TCP-protokollet

# Kontrollerar och härdar Windows Defender
#Get-WindowsDefenderStatus

