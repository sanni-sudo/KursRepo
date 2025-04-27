# PowerShell-skript sec_watch_sn.ps1
# Skapat av: Sanna Nilsson, 22 april 2025
# Namn: Omfattande säkerhetskontroll och härdning av Windows-servrar
# Utför en djupgående säkerhetsrevision och automatiskt härdar en Windows-server
# enligt avancerade säkerhetsstandarder.

#---------------Konfiguration - Variabler för Loggar och Rapporter-------------------

# Lista på portar som ska tillåtas (TCP)
$AllowedTCPPorts = @(3389, 443)  # RDP, HTTPS

# Loggar alla åtgärder och resultat i loggfilen
$LogFile = "security_hardening_$(Get-Date -Format 'yyyyMMdd').log"

#----------------Funktioner---------------------------

# Funktionen för att skriva till loggfilen
# Parameter 1: log level INFO, WARNING, ERROR eller valfri text
# Parameter 2: Meddelandet som skall skrivas till loggfilen
function log_message {
    param (
        [string]$log_level,
        [string]$message
    )
    # Tidsstämplar för varje händelse som skrivs i loggfilen
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $log_entry = "$timestamp [$log_level] $message"
    
    # Skriver till loggfilen
    Add-Content -Path $LogFile -Value $log_entry
}

# Funktionen för att kontrollera, tömma eller skapa loggfilen
function create_logfile {
    # Kontrollerar om loggfilen finns
    if (Test-Path $LogFile) {
        # Tömmer innehållet 
            Clear-Content -Path $LogFile
            log_message "INFO" "Loggfilen tömd"
        } else {
        # Skapar loggfilen om den inte fanns
            New-Item -Path $LogFile -ItemType File | Out-Null
            log_message "INFO" "Skapat loggfilen $LogFile"
        }
}

# Funktionen för att kontrollera om brandväggen är aktiv
# Namn på brandväggsprofiler som ska konfigureras: "Domain", "Private" och "Public"
function Enable-WindowsFirewall {
    param (
        [string[]]$Profiles = @("Domain", "Private", "Public")
    )
    # Kontrollerar brandväggsstatus för varje profil och aktiverar den om den är inaktiv
    foreach ($profile in $Profiles) {
        $status = (Get-NetFirewallProfile -Profile $profile).Enabled

        if ($status -eq $false) {
            Set-NetFirewallProfile -Profile $profile -Enabled True
            log_message "INFO" "$profile-branväggen har aktiverats"
            }
    # Skriver ut ett meddelande för varje profil
        else {           
            log_message "INFO" "$profile-branväggen är redan aktiv"
        }
    }
}

# Funktionen att blockera all inkommande trafik
function Block-AllOtherInbound {
    # Blockerar all inkommande trafik
    New-NetFirewallRule -DisplayName "Block All Other Inbound" -Direction Inbound -Action Block -Profile Any
    
    # Loggar åtgärden
    log_message "WARNING" "Brandväggsregel 'Block All Other Inbound' skapad - all inkommande trafik blockeras."
}

# Funktionen att tillåta specifika portar för angivet protokoll, t.ex. RDP och HTTPS (TCP)
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

# Funktionen för att kontrollera och aktivera Windows Defender
function Get-WindowsDefenderStatus {
    # Hämtar information om Windows Defender
    $DefenderStatus = Get-MpComputerStatus
    
    # Kontrollerar om Windows Defender är aktiverat
    if ($DefenderStatus.AntivirusEnabled -eq $false) {
        Set-MpPreference -DisableRealtimeMonitoring $false
        log_message "WARNING" "Windows Defender var inte aktivt - aktiverades."
    } else {
        log_message "INFO" "Windows Defender är redan aktiverat."
    }
    # Kontrollerar om definitionsfilerna är uppdaterade
    if ($DefenderStatus.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-1)) {
        log_message "WARNING" "Definitionsfilerna var gamla - uppdateras nu."
        Update-MpSignature
        log_message "INFO" "Definitionsfilerna har nu uppdaterats."

    # Om Windows Defender är inte uppdaterat startar en fullständig skanning
        Start-MpScan -ScanType FullScan
        log_message "WARNING" "Fullständig skanning startad."

    # Väntar och kontrollerar om skanningen körs
        Start-Sleep -Seconds 5           # Ger lite tid för skanning att starta
        $ScanStatus = Get-MpComputerStatus

        if ($ScanStatus.FullScanAge -eq 0) {
            log_message "INFO" "Fullständig skanning är pågående eller nyligen genomförd."
        } elseif ($ScanStatus.FullScanAge -gt 0) {
            log_message "INFO" "Fullständig skanning avslutades för $($ScanStatus.FullScanAge) dagar sedan."
        } else {
            log_message "ERROR" "Kunde inte bekräfta om skanningen avslutades korrekt."
        }
    } else {
        log_message "INFO" "Definitionsfilerna är aktuella. Ingen skanning utförd."
    }
}

# Funktionen för att lista användare i Administrators-gruppen
function Get-ApprovedUsers {
    # Sökväg till filen med godkända användare 
    $ApprovedUsersPath = "C:\Users\Administrator\Documents\KursRepo\approved_users.txt"
    
    # Försöker läsa in listan över godkända användare från filen
    try {
    $ApprovedUsers = Get-Content -Path $ApprovedUsersPath -ErrorAction Stop
    } catch [System.IO.FileNotFoundException] {
    log_message "WARNING" "Filen med godkända användare hittades inte: $ApprovedUsersPath" -ForegroundColor Red
    return
    } catch {
    log_message "ERROR" "Ett fel uppstod vid läsning av filen: $($_.Exception.Message)" -ForegroundColor Red
    return
    }
    
    # Försöker hämta medlemmar i AD Administrators-gruppen
    try {
    $AdminGroupMembers = Get-ADGroupMember -Identity "Administrators" -ErrorAction Stop | Select-Object -ExpandProperty Name
    } catch {
    log_message "ERROR" "Ett fel uppstod vid hämtning av AD gruppmedlemmar: $($_.Exception.Message)" -ForegroundColor Red
    return
    }
  
    # Läser in filen som en lista
    $ApprovedUsers = Get-Content -Path $ApprovedUsersPath
    
    # Hämtar användare i AD Administrators-gruppen
    $AdminGroupMembers =  Get-ADGroupMember -Identity "Administrators" | Select-Object -ExpandProperty Name
    log_message "INFO" "Analyserar medlemmar i AD Administrators-gruppen..." -ForegroundColor Cyan

    # Jämför varje medlem mot listan av godkända användare
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
        log_message "WARNING" "Kunde inte läsa filen med godkända användare: $($_.Exception.Message)" -ForegroundColor Red
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
            log_message "WARNING" "$memberName var inte godkänd och har tagits bort från Administrators-gruppen" -ForegroundColor Red
        } catch {
            log_message "ERROR" "Kunde inte ta bort $memberName från gruppen: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
}

# Funktionen att inaktivera konton som inte använts på 90 dagar
function Disable-InactiveUsers {
    param (
        [int]$InactiveDays = 90,
        [string]$LogPath = "C:\Users\Administrator\Documents\KursRepo\disabled_users.log"
    )
    # Kontrollerar om loggfilen finns; om inte, skapar den
    if (-not (Test-Path -Path $LogPath)) {
        try {
            New-Item -Path $LogPath -ItemType File -Force | Out-Null
            log_message "INFO" "Loggfil skapad på: $LogPath"
        } catch {
            log_message "ERROR" "Fel vid skapande av loggfil: $_"
            return
        }
    }
    # Hämtar användare som varit inaktiva i angivet antal dagar
    try {
        $inactiveUsers = Search-ADAccount -AccountInactive -UsersOnly -TimeSpan (New-TimeSpan -Days $InactiveDays)
    } catch {
        log_message "ERROR" "Fel vid sökning av inaktiva användare: $_"
        return
    }
    foreach ($user in $inactiveUsers) {
        try {
            # Inaktiverar användarkonton
            Disable-ADAccount -Identity $user.SamAccountName -Confirm:$false

            # Loggar åtgärden med tidsstämpel 
            $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Inaktiverade användare: $($user.SamAccountName)"
            Add-Content -Path $LogPath -Value $logEntry

            log_message "WARNING" "Inaktiverade användare: $($user.SamAccountName)"
        } catch {
            log_message "ERROR" "Fel vid inaktivering av användare $($user.SamAccountName): $_"
        }
    }
}
# Inaktiverar osäkra protokoll som SMBv1 via registerändringar.
# Kontrollerar och inaktiverar SMBv1-protokollet genom att ändra relevanta registerinställningar.
# Dessa konfigurationer kräver administratörsbehörighet.
function Disable-InsecureProtocols {
    # Kontrollerar om SMBv1 är aktiverat
    try {
        $smb1Status = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -ErrorAction Stop
        if ($smb1Status.SMB1 -eq 1) {
            log_message "WARNING" "SMBv1 är aktiverat. Försöker avaktivera..." -ForegroundColor Yellow
            # Inaktiverar SMBv1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Type DWORD -Value 0 -Force
            log_message "INFO" "SMBv1 har inaktiverats. En omstart krävs för att ändringen ska träda i kraft." -ForegroundColor Green
        } else {
            log_message "INFO" "SMBv1 är redan inaktiverat." -ForegroundColor Green
        }
    } catch {
        log_message "WARNING" "SMBv1-registernyckeln hittades inte. SMBv1 kan vara aktiverat som standard." -ForegroundColor Red
        # Skapar och inaktiverar SMBv1
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -PropertyType DWORD -Value 0 -Force
            log_message "INFO" "SMBv1 har inaktiverats genom att skapa registernyckeln. En omstart krävs för att ändringen ska träda i kraft." -ForegroundColor Green
        } catch {
            log_message "ERROR" "Misslyckades med att skapa och inaktivera SMBv1-registernyckeln: $_" -ForegroundColor Red
        }
    }
}

# Funktionen att stoppa och inaktivera onödiga tjänster som Telnet och FTP.
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

# Funktionen att kontrollera diskens lediga utrymme
# och flytta temporära filer till en arkivmapp om det lediga utrymmet är under 15 %
function Move-TempFilesIfLowSpace {
    param (
        [string]$TempFolder = "C:\Windows\Temp",
        [string]$ArchiveFolder = "C:\TempBackup",
        [int]$Threshold = 70
    )

    # Hämtar volumen baserat på enhetsbeteckningen (t.ex. "C") istället för etiketten.
    $driveLetter = (Get-Item $TempFolder).PSDrive.Name
    $volume = Get-Volume -DriveLetter $driveLetter


    # Beräknar procentuell ledig plats
    if ($volume.Size -gt 0) {
        $freeSpacePercent = [math]::Round(($volume.SizeRemaining / $volume.Size) * 100, 2)
    } else {
        log_message "ERROR" "Volymstorleken är 0, kan inte beräkna ledigt utrymme."
    }

    # Kontrollerar om ledigt utrymme är under tröskelvärdet
    if ($freeSpacePercent -lt $Threshold) {
        log_message "WARNING" "Ledigt utrymme är under $Threshold%. Flyttar temporära filer..."

        # Skapa arkivmappen om den inte finns
        if (-not (Test-Path -Path $ArchiveFolder)) {
            New-Item -Path $ArchiveFolder -ItemType Directory
        }

        # Flytta temporära filer till arkivmappen
        Get-ChildItem -Path $TempFolder -Recurse | ForEach-Object {
            $destination = Join-Path -Path $ArchiveFolder -ChildPath $_.Name
            Move-Item -Path $_.FullName -Destination $destination -Force
            log_message "INFO" "Flyttade: $($_.FullName) till $destination"
        }
        log_message "INFO" "Flytt av temporära filer slutförd."
    } else {
        log_message "INFO" "Tillräckligt med ledigt utrymme ($freeSpacePercent%) finns. Ingen åtgärd vidtogs."
    }
}

# Funktionen att aktivera och konfigurera BitLocker på systemdisken (c:)
function Enable-SystemDriveBitLocker {
#    param (
#        [string]$RecoveryKeyPath = "C:\BitLockerRecovery"
#        )
        # Kontrollerar om TPM är tillgänglig och aktiverad
 #       $tpm = Get-Tpm
 #       if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) {
 #           log_message "ERROR" "TPM är inte tillgänglig eller inte redo. BitLocker kan inte aktiveras." -ForegroundColor Red
 #       return
 #       }
        # Kontrollerar om återställningsnyckelns sökväg finns, annars skapar den
 #       if (-not (Test-Path -Path $RecoveryKeyPath)) {
 #           try {
 #               New-Item -Path $RecoveryKeyPath -ItemType Directory -Force | Out-Null
 #               log_message "INFO" "Återställningsnyckelns mapp skapad på: $RecoveryKeyPath" -ForegroundColor Green 
 #           } catch {
 #               log_message "ERROR" "Fel vid skapande av återställningsnyckelns mapp: $_" -ForegroundColor Red
 #               return       
<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.EXAMPLE
An example

.NOTES
General notes
#> #          }
 #           }
        # Hämtar alla volumer och itererar över dem
        $volumes = Get-BitLockerVolume
        foreach ($volume in $volumes) {
            # Kontrollerar om volumen är systemdisken (C:)
            if ($volume.MountPoint -eq "C:" -and $volume.ProtectionStatus -ne "On") {
#            if ($volume.MountPoint -eq "C:") {
 #               if ($volume.ProtectionStatus -eq "On") {
 #                   log_message "INFO" "BitLocker är redan aktiverat på $($volume.MountPoint)." -ForegroundColor Yellow
 #           } else {
 #               try {
                    Enable-BitLocker -MountPoint $volume.MountPoint -TmpProtector -UsedSpaceOnly -SkipHardwareTest                                             
                    log_message "INFO" "BitLocker har aktiverats på $($volume.MountPoint)." -ForegroundColor Green 
                } elseif ($volume.MountPoint -eq "C:") { 
                    log_message "INFO" "BitLocker är redan aktiverat på $($volume.MountPoint)." -ForegroundColor Yellow                }
            
        }
    }
# Sammanfattning till administratören i konsolen
Write-Host "`n---------- Sammanfattning av säkerhetskontroll ----------" -ForegroundColor Cyan

Write-Host "- Brandväggsprofiler kontrollerade och aktiverade" -ForegroundColor Green
Write-Host "- All annan inkommande trafik blockerad" -ForegroundColor Green
Write-Host "- Tillåtna portar öppnade: $($AllowedTCPPorts -join ', ')" -ForegroundColor Green
Write-Host "- Windows Defender kontrollerad och härdad" -ForegroundColor Green
Write-Host "- Administratörsanvändare i AD kontrollerade" -ForegroundColor Green
Write-Host "- Icke-godkända användare borttagna" -ForegroundColor Green
Write-Host "- Inaktiva användare inaktiverade" -ForegroundColor Green
Write-Host "- Osäkra protokoll och onödiga tjänster inaktiverade" -ForegroundColor Green
Write-Host "- Temporära filer flyttade vid låg diskutrymme om nödvändigt" -ForegroundColor Green
Write-Host "- BitLocker kontrollerad och aktiverad om det behövdes" -ForegroundColor Green

Write-Host "`nSäkerhetskontrollen och härdningen är slutförd!" -ForegroundColor Yellow

# -------------------- Huvudlogiken--------------------------

# Kontrollerar, tömmer eller skapar loggfilen
create_logfile
# Kontrollerar brandväggens status för varje profil (Domain, Private, Public) och slår på brandväggen 
Enable-WindowsFirewall
# Implementerar strikta brandväggsregeln som blockerar all inkommande trafik
Block-AllOtherInbound 
# Implementerar specifika brandväggsregler som tillåter RDP (3389), HTTPS (443), DNS (53) och DHCP (67-68)  
Enable-AllowRequiredPorts
# Kontrollerar och härdar Windows Defender
Get-WindowsDefenderStatus
# Listar användare i AD Administrators-gruppen
Get-ApprovedUsers
# Tar bort icke-godkända användare från Active Directory-grupp
Remove-UnapprovedUsers
# Inaktiverar konton som inte använts på 90 dagar
Disable-InactiveUsers
# Inaktiverar osäkra protokoll, SMBv1
Disable-InsecureProtocols
# Inaktiverar onödiga tjänster, Telnet och FTP
Disable-UnnecessaryServices
# Kontrollerar om det lediga utrymmet på volymen där C:\Windows\Temp finns är under 15 %. 
# Om så är fallet, flyttas alla filer från den mappen till C:\TempBackup.
Move-TempFilesIfLowSpace 
# Aktiverar och konfigurerar BitLocker på systemdisken (C:) om den inte redan är aktiverat. 
Enable-SystemDriveBitLocker 