# Entrée utilisateur
$target = Read-Host "Entrez l'adresse IP ou le nom d'hôte à analyser"

$commonPorts = @(21,22,23,25,53,80,110,139,143,443,445,3389)

function Get-IPType {
    param ($ip)
    if ($ip -match '^10\.' -or
        $ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.' -or
        $ip -match '^192\.168\.') {
        return "Privée"
    } elseif ($ip -match '^127\.') {
        return "Loopback"
    } else {
        return "Publique"
    }
}

function Test-PingDetailed {
    try {
        $pingResults = Test-Connection -ComputerName $target -Count 4 -ErrorAction Stop
        $sent = 4
        $received = $pingResults.Count
        $lost = $sent - $received
        $avg = ($pingResults | Measure-Object -Property ResponseTime -Average).Average
        return "Répond ($received/$sent reçus, $lost perdus) - Moyenne: $([math]::Round($avg, 1)) ms"
    } catch {
        return "Ping échoué (0/4)"
    }
}

function Test-PingFragmented {
    # Ping avec le flag 'Don't Fragment' - pour détecter si fragmentation est bloquée
    try {
        $pingFrag = ping.exe $target -n 1 -f -l 1472 2>&1
        if ($pingFrag -match "Reçu = 1") {
            return "OK"
        } elseif ($pingFrag -match "Impossible de joindre l'hôte") {
            return "Impossible de joindre l'hôte"
        } else {
            return "bloquée ou refusée"
        }
    } catch {
        return "erreur"
    }
}

function Test-ICMPBlocked {
    # Vérifie si ICMP est bloqué par un timeout global
    try {
        $pingResults = Test-Connection -ComputerName $target -Count 1 -ErrorAction SilentlyContinue
        if (!$pingResults) {
            return "ICMP bloqué ou non répondant"
        } else {
            return "ICMP accessible"
        }
    } catch {
        return "ICMP inaccessible"
    }
}

function Do-TracerouteCondensed {
    try {
        $output = tracert -d -h 30 -w 1000 $target | Select-Object -Skip 1
        $ips = @()

        foreach ($line in $output) {
            $cleanLine = $line.Trim()
            if ($cleanLine -match "^\s*\d+") {
                if ($cleanLine -match '(\d{1,3}(\.\d{1,3}){3})') {
                    $ip = $Matches[1]
                    $ips += $ip
                }
            }
        }

        $result = @()
        $prev = ""
        foreach ($ip in $ips) {
            if ($ip -ne $prev) {
                $result += $ip
                $prev = $ip
            }
        }
        return $result -join " → "
    } catch {
        return "Traceroute non disponible"
    }
}

function Scan-CommonPorts {
    $results = @()
    foreach ($port in $commonPorts) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $async = $client.BeginConnect($target, $port, $null, $null)
            $success = $async.AsyncWaitHandle.WaitOne(1000, $false)
            if ($success -and $client.Connected) {
                $client.EndConnect($async)
                $client.Close()

                $service = switch ($port) {
                    21  { "FTP" }
                    22  { "SSH" }
                    23  { "Telnet" }
                    25  { "SMTP" }
                    53  { "DNS" }
                    80  { "HTTP" }
                    110 { "POP3" }
                    139 { "NetBIOS Session (SMB)" }
                    143 { "IMAP" }
                    443 { "HTTPS" }
                    445 { "SMB / CIFS" }
                    3389 { "RDP" }
                    default { "Inconnu" }
                }

                $results += "$port ouvert ($service)"
            }
        } catch {
            continue
        }
    }
    if ($results.Count -gt 0) {
        return $results -join "`n"
    } else {
        return "Aucun port courant ouvert détecté"
    }
}

function Check-RDP {
    try {
        $rdp = Test-NetConnection -ComputerName $target -Port 3389 -WarningAction SilentlyContinue
        if ($rdp.TcpTestSucceeded) {
            return "✅ RDP actif (port 3389 ouvert)"
        } else {
            return "❌ RDP non accessible"
        }
    } catch {
        return "Erreur lors du test RDP"
    }
}

function Check-HTTPBanner {
    try {
        $response = Invoke-WebRequest -Uri "http://$target" -UseBasicParsing -TimeoutSec 3
        if ($response.StatusCode -eq 200) {
            $server = $response.Headers['Server']
            $warn = ""
            # Exemples basiques de vulnérabilités sur serveur HTTP connus (à étoffer)
            if ($server) {
                if ($server -match "Apache/2\.2") {
                    $warn = "⚠️ Version Apache 2.2 (ancienne, vulnérabilités connues)"
                } elseif ($server -match "nginx/1\.4") {
                    $warn = "⚠️ Version nginx 1.4 (ancienne, vulnérabilités possibles)"
                } elseif ($server -match "IIS/6\.0") {
                    $warn = "⚠️ IIS 6.0 (très ancien, vulnérable)"
                }
            }
            return "✅ HTTP 200 OK - Serveur : $server $warn"
        } else {
            return "HTTP disponible - Code : $($response.StatusCode)"
        }
    } catch {
        return "HTTP non accessible ou refusé"
    }
}

function Check-FTPAnon {
    try {
        $ftp = [System.Net.FtpWebRequest]::Create("ftp://$target")
        $ftp.Credentials = New-Object System.Net.NetworkCredential("anonymous", "anonymous")
        $ftp.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        $ftp.GetResponse() | Out-Null
        return "✅ FTP anonyme accessible"
    } catch {
        return "⚠️ FTP anonyme refusé"
    }
}

function Check-SMBv1 {
    try {
        $smb = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        if ($smb.State -eq "Enabled") {
            return "✅ SMBv1 activé localement"
        } else {
            return "⚠️ SMBv1 désactivé"
        }
    } catch {
        return "Statut SMBv1 non vérifiable"
    }
}

function Check-Telnet {
    try {
        $telnet = Test-NetConnection -ComputerName $target -Port 23 -WarningAction SilentlyContinue
        if ($telnet.TcpTestSucceeded) {
            return "✅ Telnet actif (non sécurisé)"
        } else {
            return "⚠️ Telnet non accessible"
        }
    } catch {
        return "Erreur lors du test Telnet"
    }
}

# Execution
$ipType = Get-IPType -ip $target
$ping = Test-PingDetailed
$icmpBlock = Test-ICMPBlocked
$fragPing = Test-PingFragmented
$trace = Do-TracerouteCondensed
$ports = Scan-CommonPorts
$rdp = Check-RDP
$http = Check-HTTPBanner
$ftp = Check-FTPAnon
$smb = Check-SMBv1
$telnet = Check-Telnet

# Affichage
Write-Host ""
Write-Host "========== RAPPORT RÉSEAU POUR : $target ==========" -ForegroundColor Cyan
Write-Host "Type d'adresse        : $ipType"
Write-Host "Ping                  : $ping"
Write-Host "ICMP global           : $icmpBlock"
Write-Host "Test fragmentation ICMP : $fragPing"
Write-Host "Traceroute            : $trace"
Write-Host ""
Write-Host "Scan de ports         :"
Write-Host $ports
Write-Host ""
Write-Host "Tests de sécurité     :"
Write-Host "  $rdp"
Write-Host "  $http"
Write-Host "  $ftp"
Write-Host "  $smb"
Write-Host "  $telnet"
Write-Host ""
Write-Host "========== FIN DU RAPPORT ==========" -ForegroundColor Cyan