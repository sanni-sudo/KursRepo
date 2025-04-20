#Variabeldeklarationer
$SEC_LOG = "$PSScriptRoot\security_hardening_$(Get-Date -Format 'yyyyMMdd').log"

#Funktioner
function check_defender{
    $profiles = Get-NetFirewallProfile

    Write-Host "=== Windows Defender Firewall Status per profil ==="

    foreach ($profile in $profiles) {
        $name = $profile.Name
        $enabled = $profile.Enabled

        if ($enabled) {
            Write-Host "${name}: AKTIV" -ForegroundColor Green
            log_message -log_level "INFO" -message "Defenderprofilen ${name}: AKTIV"
        } else {
            Write-Host "${name}: INAKTIV" -ForegroundColor Red
            log_message -log_level "ERROR" -message "Defenderprofilen ${name}: INAKTIV"
        }
    }
}
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
    Add-Content -Path $SEC_LOG -Value $log_entry
}
#Funktionen rensar innehållet i en fil
#Parameter 1: Filen som man vill rensa
function clear-fileContent {
    param (
        [string]$filePath
    )

    if (Test-Path $filePath) {
        Clear-Content -Path $filePath
        Write-Host "Innehållet i filen '$filePath' har rensats." -ForegroundColor Green
    } else {
        Write-Host "Filen '$filePath' finns inte." -ForegroundColor Red
    }
}
#Blockerar allt inbound förutom HTTPS, RDP, SSH och DHCP
function block_traffic {
    # Första steg: Blockera all trafik
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False

    # Tillåt specifika portar utan ddebugutskrift till terminalen
    $null = New-NetFirewallRule -DisplayName "Allow HTTPS (Port 443)" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -Profile Any
    $null = New-NetFirewallRule -DisplayName "Allow RDP (Port 3389)" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Any
    $null = New-NetFirewallRule -DisplayName "Allow SSH (Port 22)" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any
    $null = New-NetFirewallRule -DisplayName "Allow DHCP (Port 67)" -Direction Inbound -Protocol UDP -LocalPort 67 -Action Allow -Profile Any

    # Aktivera brandväggsregler igen
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    log_message -log_level "INFO" -message "Blockerar all trafik inbound förutom HTTPS,RDP,SSH och DHCP"
    Write-Host "Endast HTTPS (443), RDP (3389), SSH (22), och DHCP (67) är tillåtna. All annan trafik har blockerats." -ForegroundColor Green
}
#Kontrollerar om microsoft defender är uppdaterat
function check_defenderUpdateStatus {
    $defenderInfo = Get-MpComputerStatus

    if ($null -eq $defenderInfo) {
        Write-Host "Kunde inte hämta status från Windows Defender." -ForegroundColor Red
        return
    }

    $lastUpdate = $defenderInfo.AntispywareSignatureLastUpdated
    $definitionsVersion = $defenderInfo.AntispywareSignatureVersion

    Write-Host "===== Microsoft Defender Uppdateringsstatus =====" -ForegroundColor Cyan
    Write-Host "Senaste uppdatering: $lastUpdate"
    Write-Host "Signaturversion: $definitionsVersion"
    

    log_message -log_level "INFO" -message "===== Microsoft Defender Uppdateringsstatus ====="
    log_message -log_level "INFO" -message "Senaste uppdatering: $lastUpdate"
    log_message -log_level "INFO" -message "Signaturversion: $definitionsVersion"
    

    # Kolla om signaturerna är äldre än 3 dagar
    if (((Get-Date) - $lastUpdate).Days -gt 3) {
        Write-Host "Defender-signaturerna är äldre än 3 dagar!" -ForegroundColor Red
        log_message -log_level "ERROR" -message "För gamla signaturer för defender"
        start_fullDefenderScan
    } else {
        Write-Host "Defender är uppdaterad." -ForegroundColor Green
        log_message -log_level "INFO" -message "Aktuella signaturer för defender"
    }
}

#Starta fullständig defenderscanning efter att definitionerna uppdaterats
function start_fullDefenderScan {
    Update-MpSignature
    log_message "INFO" "Uppdaterade defender defintioner"
    log_message "INFO" "Startar fullständig Microsoft Defender-genomsökning..."
    try {
        Start-MpScan -ScanType FullScan
        log_message "INFO" "Genomsökningen har startat."
    } catch {
        log_message "ERROR" "Kunde inte starta genomsökningen: $_"
        return
    }

    # Vänta tills genomsökningen är klar
    do {
        Start-Sleep -Seconds 10
        $status = Get-MpComputerStatus
    }while ($null -eq $status.FullScanEndTime -or $status.FullScanEndTime -gt (Get-Date)) 

    log_message "INFO" "Genomsökningen är klar."

    # Kontrollera om några hot upptäcktes
    $threats = Get-MpThreat
    if ($threats) {
        foreach ($threat in $threats) {
            log_message "WARNING" "Hot upptäckt: $($threat.ThreatName) - Åtgärd: $($threat.ActionSuccess)"
        }
    } else {
        log_message "INFO" "Inga hot upptäcktes under genomsökningen."
    }
}
#låser inaktiva konton om användaren varit inaktiv mer än 90 dagar
function lock_inactiveUsers {
    param (
        [int]$DaysInactive = 90
    )

    # Hämta dagens datum minus $DaysInactive dagar
    $DateThreshold = (Get-Date).AddDays(-$DaysInactive)

    # Hämta alla aktiva användare och deras senaste inloggningsdatum
    $InactiveUsers = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate |
        Where-Object { $_.LastLogonDate -lt $DateThreshold }

    # Om inga inaktiva användare hittas, logga och avsluta
    if ($InactiveUsers.Count -eq 0) {
        log_message -log_level "INFO" -message "Inga inaktiva användare att låsa."
        return
    }

    # Lås konton för inaktiva användare och logga åtgärder
    foreach ($User in $InactiveUsers) {
        try {
            # Lås användarkontot
            Disable-ADAccount -Identity $User.SamAccountName

            # Logga åtgärden
            log_message -log_level "WARNING" -message "Användare $($User.SamAccountName) konto låst inaktiv mer än $DaysInactive dagar."
        }
        catch {
            # Logga eventuella fel
            log_message -log_level "ERROR" -message "Fel vid låsning av konto för användare $($User.SamAccountName): $_"
        }
    }
}

#Kontrollerar om SMBv1 är aktivt och inaktiverar protokollet 
function disable_SMBv1IfActive {
    $regKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $regValueName = "SMB1"

    if (Test-Path $regKeyPath) {
        $regValue = Get-ItemProperty -Path $regKeyPath -Name $regValueName -ErrorAction SilentlyContinue
        if ($null -ne $regValue) {
            if ($regValue.SMB1 -eq 1) {
                # Inaktivera SMBv1
                Set-ItemProperty -Path $regKeyPath -Name $regValueName -Value 0
                $message = "SMBv1 var aktiverat och har nu inaktiverats. En omstart krävs för att ändringen ska träda i kraft."
                Write-Host $message
                log_message "ERROR" $message
            } else {
                $message = "SMBv1 är redan inaktiverat."
                Write-Host $message
                log_message "INFO" $message
            }
        } else {
            $message = "SMBv1 är inaktiverat som standard (ingen registerpost hittades)."
            Write-Host $message
            log_message "INFO" $message
        }
    } else {
        $message = "Registernyckeln finns inte."
        Write-Host $message
        log_message "ERROR" $message
    }
}
#Inaktiverar och stoppar FTP och Telnet
function disable_insecureProtocols {
    $services = @(
        @{ Name = "FTP"; ServiceName = "FTPSVC" },
        @{ Name = "Telnet"; ServiceName = "TlntSvr" }
    )

    foreach ($svc in $services) {
        $service = Get-Service -Name $svc.ServiceName -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            if ($service.Status -eq 'Running') {
                Stop-Service -Name $svc.ServiceName -Force
                $message = "$($svc.Name)-tjänsten stoppades."
                Write-Host $message
                log_message "INFO" $message
            } else {
                $message = "$($svc.Name)-tjänsten körs inte."
                Write-Host $message
                log_message "INFO" $message
            }
            Set-Service -Name $svc.ServiceName -StartupType Disabled
            $message = "$($svc.Name)-tjänsten har inaktiverats."
            Write-Host $message
            log_message "INFO" $message
        } else {
            $message = "$($svc.Name)-tjänsten är inte installerad."
            Write-Host $message
            log_message "INFO" $message
        }
    }
}

#Kontrollerar ledigt diskutrymme och om mindre än 15% komprimerar c:/Temp till arkivfil
function check_diskSpace {
    param (
        [string]$DriveLetter = "C",
        [string]$TempPath = "C:\Temp"
    )

    # Hämta information om disken
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='${DriveLetter}:'"
    if ($null -eq $disk) {
        $message = "Kunde inte hämta information om enheten $DriveLetter"
        Write-Host $message
        log_message "ERROR" $message
        return
    }

    # Beräkna procentandel ledigt utrymme
    $freePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
    $message = "Enhet $DriveLetter har $freePercent% ledigt utrymme."
    Write-Host $message
    log_message "INFO" $message

    # Om ledigt utrymme är mindre än 15 %, komprimera temporära filer
    if ($freePercent -lt 15) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $zipPath = Join-Path -Path $TempPath -ChildPath "TempArchive_$timestamp.zip"

        try {
            Compress-Archive -Path "$TempPath\*" -DestinationPath $zipPath -Force
            $message = "Temporära filer har komprimerats till $zipPath på grund av lågt diskutrymme."
            Write-Host $message
            log_message "INFO" $message
        } catch {
            $message = "Fel vid komprimering av temporära filer: $_"
            Write-Host $message
            log_message "ERROR" $message
        }
    }
}
#Kontrollera att BitLocker är aktivet. Om inte kontrollera om TPM är tillgängligt
#och i så fall aktivera BitLocker. Spara återställningsnyckel till loggfil 
function enable_bitLocker {
    param (
        [string]$MountPoint = "C:"
    )

    $manageBdePath = "${env:windir}\System32\manage-bde.exe"

    # Kontrollera om en CD/DVD är monterad (kan stoppa BitLocker)
    $cdDrives = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' }
    if ($cdDrives) {
        $message = "Ett startbart media (CD/DVD) är monterat. Mata ut och starta om datorn innan du fortsätter."
        Write-Host $message
        log_message "ERROR" $message
        return
    }

    # Kontrollera BitLocker-status
    $bitLockerStatus = Get-BitLockerVolume -MountPoint $MountPoint
    if ($bitLockerStatus.VolumeStatus -eq 'FullyEncrypted') {
        $message = "BitLocker är redan aktiverat på $MountPoint."
        Write-Host $message
        log_message "INFO" $message
        return
    }

    # Kontrollera TPM-status
    try {
        $tpm = Get-Tpm
        if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) {
            $message = "TPM är inte tillgänglig eller redo. Kan inte aktivera BitLocker på $MountPoint."
            Write-Host $message
            log_message "ERROR" $message
            return
        }
    } catch {
        $message = "Kunde inte kontrollera TPM-status: $_"
        Write-Host $message
        log_message "ERROR" $message
        return
    }

    # Aktivera BitLocker med TPM-skyddare
    try {
        Enable-BitLocker -MountPoint $MountPoint -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector
        $message = "BitLocker har aktiverats på $MountPoint med TPM."
        Write-Host $message
        log_message "INFO" $message
        Start-Sleep -Seconds 5

        # Lägg till återställningsskyddare (om det inte redan finns)
        $existingProtectors = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector
        if (-not $existingProtectors.KeyProtectorType.Contains("RecoveryPassword")) {
            Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector
        }

        # Hämta återställningsnyckeln med manage-bde
        $protectorOutput = & $manageBdePath -protectors -get $MountPoint 2>&1
        $recoveryKeyLine = $protectorOutput | Where-Object { $_ -match "Password:\s+([0-9\-]+)" }
        if ($recoveryKeyLine) {
            $recoveryKey = ($recoveryKeyLine -split ":\s+")[1].Trim()
            $message = "Återställningsnyckel för ${MountPoint}: $recoveryKey"
            Write-Host $message
            log_message "INFO" $message
        } else {
            $message = "Kunde inte hämta återställningsnyckeln för $MountPoint."
            Write-Host $message
            log_message "ERROR" $message
        }
    } catch {
        $message = "Ett fel uppstod vid aktivering av BitLocker på ${MountPoint}: $_"
        Write-Host $message
        log_message "ERROR" $message
    }
}



# Huvudlogik

#Rensar loggfilen från föregående körning
clear-fileContent -filePath $SEC_LOG
#Kontrollerar defender status för alla profiler
check_defender
#Blockera alla portar som inte skall vara tillåtna
block_traffic
#Kontrollerar defenderstatus
check_defenderUpdateStatus
#låser konton för icke aktiva användare
lock_inactiveUsers
#deaktivera SMVv1
disable_SMBv1IfActive
#deaktiverar och stoppar FTP och Telnet
disable_insecureProtocols
#Kontrollera diskutrymme
check_diskSpace
#Kontrollera och enabla bitlocker
enable_bitLocker



