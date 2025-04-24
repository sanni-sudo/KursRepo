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
    
    # Skriver till loggfilen
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
        #Write-Host "Windows Defender är inte aktiverat. Vi aktiverar det nu..."
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

    # Startar fullständig skanning
        #Write-Host "Startar en fullständig skanning..."
        Start-MpScan -ScanType FullScan
        log_message "INFO" "Fullständig skanning startad."

    # Vänta och kontrollera om skanningen körs
        Start-Sleep -Seconds 5  # Ge lite tid för skanning att starta
        $ScanStatus = Get-MpComputerStatus

        if ($ScanStatus.FullScanAge -eq 0) {
            log_message "INFO" "Fullständig skanning är pågående eller nyligen genomförd."
        } elseif ($ScanStatus.FullScanAge -gt 0) {
            log_message "INFO" "Fullständig skanning avslutades för $($ScanStatus.FullScanAge) dagar sedan."
        } else {
            log_message "WARNING" "Kunde inte bekräfta om skanningen avslutades korrekt."
        }
    } else {
        log_message "INFO" "Definitionsfilerna är aktuella. Ingen skanning utförd."
    }
}

# Funktion för att lista användare i Administrators-gruppen
function Get-ApprovedUsers {
    # Sökväg till listan med godkända användare 
    $ApprovedUsersPath = "C:\Users\Administrator\Documents\KursRepo\approved_usesrs.txt"
    # Försök läsa in filen med godkända användare och jämföra dem med listan
    try {
    $ApprovedUsers = Get-Content -Path $ApprovedUsersPath -ErrorAction Stop
    } catch [System.IO.FileNotFoundException] {
    log_message "ERROR" "Filen med godkända användare hittades inte: $ApprovedUsersPath" -ForegroundColor Red
    return
    } catch {
    log_message "ERROR" "Ett fel uppstod vid läsning av filen: $($_.Exception.Message)" -ForegroundColor Red
    return
    }
    
    # Försök hämta medlemmar i Administrators-gruppen
    try {
    $AdminGroupMembers = Get-ADGroupMember -Identity "Administrators" -ErrorAction Stop | Select-Object -ExpandProperty Name
    } catch {
    log_message "ERROR" "Ett fel uppstod vid hämtning av gruppmedlemmar: $($_.Exception.Message)" -ForegroundColor Red
    return
    }
  
    # Läser in filen som en lista
    $ApprovedUsers = Get-Content -Path $ApprovedUsersPath
    # Hämtar användare i Administrators-gruppen
    $AdminGroupMembers =  Get-ADGroupMember -Identity "Administrators" | Select-Object -ExpandProperty Name
    log_message "INFO" "Analyserar medlemmar i Administrators-gruppen..." -ForegroundColor Cyan

    # Jämför användarna 
    foreach ($member in $AdminGroupMembers) {
        if ($ApprovedUsers -contains $member) {
            log_message "INFO" "$member är godkänd" -ForegroundColor Green
        }   else {
            log_message "WARNING" "$member är INTE godkänd" -ForegroundColor Red
        }
    }
}

# Funktionen att ta bort icke-godkända användare från en Active Directory-grupp. 
# Jämför medlemmarna i gruppen med en lista över godkända användare och ta bort de som inte finns med på listan.
function Remove-UnapprovedUsers {
    param (
        [string]$ApprovedUsersPath = "C:\Users\Administrator\Documents\KursRepo\approved_usesrs.txt"
    )
    try {
        $ApprovedUsers = Get-Content -Path $ApprovedUsersPath -ErrorAction Stop
    } catch {
        log_message "ERROR" "Kunde inte läsa filen med godkända användare: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    try {
        $AdminGroupMembers = Get-ADGroupMember -Identity "Administrators" -ErrorAction Stop
    } catch {
        log_message "ERROR" "Kunde inte hämta medlemmar i gruppen 'Administrators': $($_.Exception.Message)" -ForegroundColor Red
        return
    }
 
foreach ($member in $AdminGroupMembers) {
    $memberName = $member.SamAccountName
    if ($ApprovedUsers -contains $memberName) {
        log_message "INFO" "$memberName är godkänd och behålls i gruppen" -ForegroundColor Green
    } else {
        try {
            Remove-ADGroupMember -Identity "Administrators" -Members $member -Confirm:$false -ErrorAction Stop
            log_message "INFO" "$memberName var inte godkänd och har tagits bort från Administrators-gruppen" -ForegroundColor Red
        } catch {
            log_message "ERROR" "Kunde inte ta bort $memberName från gruppen: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
}

# Inaktiverar konton som inte använts på 90 dagar
function Disable-InactiveUsers {
    param (
        [int]$InactiveDays = 90,
        [string]$LogPath = "C:\Users\Administrator\Documents\KursRepo\disabled_users.log"
    )

    # Kontrollera om loggfilen finns; om inte, skapa den
    if (-not (Test-Path -Path $LogPath)) {
        try {
            New-Item -Path $LogPath -ItemType File -Force | Out-Null
            log_message "INFO" "Loggfil skapad på: $LogPath"
        } catch {
            log_message "ERROR" "Fel vid skapande av loggfil: $_"
            return
        }
    }

    # Hämta användare som varit inaktiva i angivet antal dagar
    try {
        $inactiveUsers = Search-ADAccount -AccountInactive -UsersOnly -TimeSpan (New-TimeSpan -Days $InactiveDays)
    } catch {
        log_message "ERROR" "Fel vid sökning av inaktiva användare: $_"
        return
    }

    foreach ($user in $inactiveUsers) {
        try {
            # Inaktivera användarkontot
            Disable-ADAccount -Identity $user.SamAccountName -Confirm:$false

            # Logga åtgärden med tidsstämpel
            $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Inaktiverade användare: $($user.SamAccountName)"
            Add-Content -Path $LogPath -Value $logEntry

            log_message "INFO" "Inaktiverade användare: $($user.SamAccountName)"
        } catch {
            log_message "ERROR" "Fel vid inaktivering av användare $($user.SamAccountName): $_"
        }
    }
}

   # foreach ($member in $AdminGroupMembers) {
    #    if ($ApprovedUsers -notcontains $member.SamAccountName) {
     #       try {
      #          Remove-ADGroupMember -Identity "Administrators" -Members $member -Confirm:$false -ErrorAction Stop
       #         log_message "INFO" "$($member.SamAccountName) har tagits bort från Administrators-gruppen" -ForegroundColor Yellow
        #    } catch {
         #       log_message "ERROR" "Kunde inte ta bort $($member.SamAccountName): $($_.Exception.Message)" -ForegroundColor Red
          #  }
       # } else {
       #     log_message "INFO" "$($member.SamAccountName) är godkänd och behålls i gruppen" -ForegroundColor Green
       # }
   # }
#}

# Inaktiverar osäkra protokoll som SMBv1 via registerändringar.
# Kontrollerar och inaktiverar SMBv1-protokollet genom att ändra relevanta registerinställningar.
# Kräver administratörsbehörighet.
function Disable-InsecureProtocols {
    # Kontrollerar om SMBv1 är aktiverat
    try {
        $smb1Status = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -ErrorAction Stop
        if ($smb1Status.SMB1 -eq 1) {
            log_message "INFO" "SMBv1 är aktiverat. Försöker inaktivera..." -ForegroundColor Yellow
            # Inaktivera SMBv1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Type DWORD -Value 0 -Force
            log_message "INFO" "SMBv1 har inaktiverats. En omstart krävs för att ändringen ska träda i kraft." -ForegroundColor Green
        } else {
            log_message "INFO" "SMBv1 är redan inaktiverat." -ForegroundColor Green
        }
    } catch {
        log_message "WARNING" "SMBv1-registernyckeln hittades inte. SMBv1 kan vara aktiverat som standard." -ForegroundColor Red
        # Skapa och inaktivera SMBv1
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -PropertyType DWORD -Value 0 -Force
            log_message "INFO" "SMBv1 har inaktiverats genom att skapa registernyckeln. En omstart krävs för att ändringen ska träda i kraft." -ForegroundColor Green
        } catch {
            log_message "ERROR" "Misslyckades med att skapa och inaktivera SMBv1-registernyckeln: $_" -ForegroundColor Red
        }
    }
}

# Stoppar och inaktiverar onödiga tjänster som Telnet och FTP.
# kontrollerar om specifika tjänster är installerade, stoppar dem om de körs 
# och inaktiverar dem för att förbättra systemets säkerhet.
function Disable-UnnecessaryServices {
      # Lista över tjänster att inaktivera
    $servicesToDisable = @("TlntSvr", "FTPSVC")         # TlntSvr = Telnet, FTPSVC = FTP

    foreach ($serviceName in $servicesToDisable) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction Stop
            if ($service.Status -ne 'Stopped') {
                log_message "INFO" "Stoppar tjänsten $($service.DisplayName)..."
                Stop-Service -Name $serviceName -Force
            }
            log_message "INFO" "Inaktiverar tjänsten $($service.DisplayName)..."
            Set-Service -Name $serviceName -StartupType Disabled
        } catch {
            log_message "WARNING" "Tjänsten '$serviceName' hittades inte eller kunde inte hanteras: $_"
        }
    }
}


# -------------------- Huvudlogiken--------------------------

create_logfile
#Enable-WindowsFirewall 
#Enable-AllFirewallProfiles -Profiles $FirewallProfiles
#Enable-AllowRequiredPorts
#Block-AllOtherInbound

# Slår på brandväggen för varje profil (Domain, Privat, Public)
# Tillåter RDP (3389) och HTTPS (443) med TCP-protokollet

# Kontrollerar och härdar Windows Defender
#Get-WindowsDefenderStatus
# Listar användare i AD Administrators-gruppen
#Get-ApprovedUsers
# Tar bort icke-godkända användare
#Remove-UnapprovedUsers
# Inaktiverar konton som inte använts på 90 dagar
#Disable-InactiveUsers
# Inaktiverar osäkra protokoll, SMBv1
#Disable-InsecureProtocols
# Inaktiverar onödiga tjänster, Telnet och FTP
#Disable-UnnecessaryServices
# 