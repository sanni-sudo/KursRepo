$log_file = "network_traffic.log"

# Rensa eller skapa loggfil
if (Test-Path $log_file) {
    Clear-Content -Path $log_file
} else {
    New-Item -Path $log_file -ItemType File | Out-Null
}

function Get-RandomIP {
    return "{0}.{1}.{2}.{3}" -f (Get-Random -Minimum 1 -Maximum 255), (Get-Random -Minimum 0 -Maximum 255), (Get-Random -Minimum 0 -Maximum 255), (Get-Random -Minimum 1 -Maximum 254)
}

$common_ports = @(22, 80, 443)
$protocols = @("TCP", "UDP")

# Attack-IP:er
$heavy_src_ip = "192.168.1.200"
$weird_port_ip = "172.16.0.5"
$dst_spam_ip = "10.0.0.99"

# Funktion att logga trafikrad
function Write-LogEntry {
    param (
        [string]$src_ip,
        [string]$dst_ip,
        [int]$port,
        [string]$protocol
    )
    $line = "{0}, {1}, {2}, {3}, {4}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $src_ip, $dst_ip, $port, $protocol
    $line | Out-File -Append -FilePath $log_file
}

$end_time = (Get-Date).AddMinutes(10)

while ((Get-Date) -lt $end_time) {
    # 1. Normal trafik (3–5 poster per sekund)
    for ($i = 0; $i -lt (Get-Random -Minimum 3 -Maximum 6); $i++) {
        Write-LogEntry -src_ip (Get-RandomIP) -dst_ip (Get-RandomIP) -port ($common_ports | Get-Random) -protocol ($protocols | Get-Random)
    }

    # 2. >100 anslutningar från samma IP under en 5-minutersperiod (~1-2/s)
    if ((Get-Random -Minimum 1 -Maximum 100) -lt 25) {
        Write-LogEntry -src_ip $heavy_src_ip -dst_ip (Get-RandomIP) -port ($common_ports | Get-Random) -protocol ($protocols | Get-Random)
    }

    # 3. Ovanliga portar
    if ((Get-Random -Minimum 1 -Maximum 100) -lt 10) {
        do {
            $port = Get-Random -Minimum 1 -Maximum 1023
        } while ($common_ports -contains $port)
        Write-LogEntry -src_ip $weird_port_ip -dst_ip (Get-RandomIP) -port $port -protocol ($protocols | Get-Random)
    }

    # 4. Hög volym mot ett mål
    if ((Get-Random -Minimum 1 -Maximum 100) -lt 20) {
        Write-LogEntry -src_ip (Get-RandomIP) -dst_ip $dst_spam_ip -port ($common_ports + @(8080, 8443) | Get-Random) -protocol ($protocols | Get-Random)
    }

    Start-Sleep -Milliseconds 1000
}
