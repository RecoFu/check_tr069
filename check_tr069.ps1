# ============================================================
# check_tr069.ps1 -- Full Network Diagnostic Script
# Usage : .\check_tr069.ps1 192.168.1.1
# Output: check_tr069_192.168.1.1_20260218_1230.log
# ============================================================

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$TargetIP
)

# -- Init ----------------------------------------------------
$timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$logFile   = "check_tr069_${TargetIP}_${timestamp}.log"
$scriptVer = "v1.0 / 2026-02-18"

function Log {
    param([string]$msg, [string]$color = "White")
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $logFile -Value $line
}

function Section {
    param([string]$title)
    $bar = "=" * 60
    Log ""
    Log $bar "Cyan"
    Log "  $title" "Cyan"
    Log $bar "Cyan"
}

function Result {
    param([string]$label, $value, [bool]$ok = $true)
    $icon = if ($ok) { "[OK]" } else { "[!!]" }
    $col  = if ($ok) { "Green" } else { "Yellow" }
    Log ("  {0,-28} {1} {2}" -f $label, $icon, $value) $col
}

# -- Header --------------------------------------------------
Log ("=" * 60) "Cyan"
Log "  check_tr069.ps1 $scriptVer" "Cyan"
Log "  Target IP : $TargetIP" "Cyan"
Log "  Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Cyan"
Log "  Hostname  : $env:COMPUTERNAME" "Cyan"
Log ("=" * 60) "Cyan"


# ============================================================
# [1] Local NIC Info
# ============================================================
Section "[1] Local NIC / IP Info"

$adapters = Get-NetIPConfiguration | Where-Object { $_.IPv4Address }
foreach ($a in $adapters) {
    Log "  Adapter : $($a.InterfaceAlias)" "White"
    Result "  Local IP"       $a.IPv4Address.IPAddress
    Result "  Prefix Length"  $a.IPv4Address.PrefixLength
    Result "  Default GW"     ($a.IPv4DefaultGateway.NextHop)
    Result "  DNS Servers"    ($a.DNSServer.ServerAddresses -join ", ")
    Log ""
}


# ============================================================
# [2] DHCP Info
# ============================================================
Section "[2] DHCP Info"

$dhcpAdapters = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.PrefixOrigin -eq "Dhcp" }

if ($dhcpAdapters) {
    foreach ($d in $dhcpAdapters) {
        Result "DHCP IP"        $d.IPAddress
        Result "DHCP Adapter"   $d.InterfaceAlias
        $wmi = Get-WmiObject Win32_NetworkAdapterConfiguration |
            Where-Object { $_.IPAddress -contains $d.IPAddress }
        if ($wmi) {
            Result "DHCP Server"    $wmi.DHCPServer
            Result "Lease Obtained" $wmi.DHCPLeaseObtained
            Result "Lease Expires"  $wmi.DHCPLeaseExpires
        }
    }
} else {
    Log "  [--] No DHCP adapter found (may be static IP)" "Yellow"
}


# ============================================================
# [3] Gateway / Target Connectivity
# ============================================================
Section "[3] Gateway / Target Ping + Traceroute"

$ping = Test-NetConnection -ComputerName $TargetIP -WarningAction SilentlyContinue
Result "Ping $TargetIP" "$($ping.PingReplyDetails.RoundtripTime)ms" $ping.PingSucceeded

Log ""
Log "  Traceroute (max 10 hops):" "White"
try {
    $hops = Test-NetConnection -ComputerName $TargetIP `
            -TraceRoute -Hops 10 -WarningAction SilentlyContinue
    $i = 1
    foreach ($hop in $hops.TraceRoute) {
        Log ("    Hop {0:D2}  {1}" -f $i, $hop) "Gray"
        $i++
    }
} catch {
    Log "  [!!] Traceroute failed: $_" "Yellow"
}


# ============================================================
# [4] DNS Resolution
# ============================================================
Section "[4] DNS Resolution Tests"

$dnsTargets = @(
    "google.com",
    "hinet.net",
    "acs.hinet.net",
    "acs.hinet.com",
    "8.8.8.8",
    "168.95.1.1"
)

foreach ($d in $dnsTargets) {
    try {
        $r  = Resolve-DnsName $d -ErrorAction Stop -WarningAction SilentlyContinue
        $ip = ($r | Where-Object { $_.Type -eq "A" } | Select-Object -First 1).IPAddress
        if (-not $ip) { $ip = ($r | Select-Object -First 1).NameHost }
        Result "DNS: $d" $ip $true
    } catch {
        Result "DNS: $d" "NXDOMAIN / unresolvable" $false
    }
}

try {
    $rev = Resolve-DnsName $TargetIP -ErrorAction Stop
    Result "rDNS: $TargetIP" ($rev | Select-Object -First 1).NameHost $true
} catch {
    Result "rDNS: $TargetIP" "No PTR record" $false
}


# ============================================================
# [5] Port Scan (ONT / Gateway key ports)
# ============================================================
Section "[5] Port Scan -> $TargetIP"

$ports = @(
    @{Port=80;   Desc="HTTP Admin"},
    @{Port=443;  Desc="HTTPS Admin"},
    @{Port=23;   Desc="Telnet (should be CLOSED)"},
    @{Port=22;   Desc="SSH"},
    @{Port=7547; Desc="TR-069 CWMP"},
    @{Port=7548; Desc="TR-069 CWMP alt"},
    @{Port=8080; Desc="HTTP alt"},
    @{Port=8443; Desc="HTTPS alt"},
    @{Port=161;  Desc="SNMP"},
    @{Port=53;   Desc="DNS (if ONT serves)"}
)

foreach ($p in $ports) {
    try {
        $tc   = Test-NetConnection -ComputerName $TargetIP -Port $p.Port `
                -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        $ok   = $tc.TcpTestSucceeded
        $warn = if ($p.Port -eq 23 -and $ok) { "  <-- WARNING: Telnet OPEN, security risk!" } else { "" }
        Result ("Port {0,5}  {1}" -f $p.Port, $p.Desc) `
               (if ($ok) { "OPEN" } else { "closed" }) $ok
        if ($warn) { Log $warn "Red" }
    } catch {
        Result ("Port {0,5}  {1}" -f $p.Port, $p.Desc) "error" $false
    }
}


# ============================================================
# [6] HTTP / HTTPS Response
# ============================================================
Section "[6] HTTP / HTTPS Admin Page Response"

$urls = @(
    "http://${TargetIP}/",
    "https://${TargetIP}/",
    "http://${TargetIP}:8080/",
    "https://${TargetIP}:8443/"
)

foreach ($url in $urls) {
    try {
        $resp = Invoke-WebRequest -Uri $url -TimeoutSec 5 `
                -SkipCertificateCheck `
                -SkipHttpErrorCheck `
                -UseBasicParsing `
                -ErrorAction Stop
        $srv = $resp.Headers['Server']
        Result $url "HTTP $($resp.StatusCode)  Server: $srv" ($resp.StatusCode -lt 400)
    } catch {
        $err = $_.Exception.Message -replace "`n"," "
        Result $url ("FAIL: " + $err.Substring(0, [Math]::Min(55,$err.Length))) $false
    }
}


# ============================================================
# [7] Internet + Public IP
# ============================================================
Section "[7] Internet Connectivity + Public IP"

foreach ($t in @("8.8.8.8", "1.1.1.1", "168.95.1.1")) {
    $p = Test-NetConnection -ComputerName $t -WarningAction SilentlyContinue
    Result "Internet Ping: $t" "$($p.PingReplyDetails.RoundtripTime)ms" $p.PingSucceeded
}

try {
    $pub = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 8).ip
    Result "Public IP (ipify)" $pub $true
} catch {
    try {
        $pub2 = (Invoke-RestMethod -Uri "https://ifconfig.me/ip" -TimeoutSec 8)
        Result "Public IP (ifconfig.me)" $pub2.Trim() $true
    } catch {
        Result "Public IP" "Failed to retrieve" $false
    }
}


# ============================================================
# [8] Latency Quality (Jitter / Packet Loss)
# ============================================================
Section "[8] Latency Quality -- Jitter / Packet Loss (20 pings)"

$pingResults = @()
Log "  Pinging 168.95.1.1 x20 ..." "White"
for ($i = 1; $i -le 20; $i++) {
    $p = Test-NetConnection -ComputerName "168.95.1.1" -WarningAction SilentlyContinue
    if ($p.PingSucceeded) { $pingResults += $p.PingReplyDetails.RoundtripTime }
    Write-Host "." -NoNewline -ForegroundColor Gray
}
Write-Host ""

if ($pingResults.Count -gt 0) {
    $avg    = [Math]::Round(($pingResults | Measure-Object -Average).Average, 1)
    $min    = ($pingResults | Measure-Object -Minimum).Minimum
    $max    = ($pingResults | Measure-Object -Maximum).Maximum
    $loss   = [Math]::Round((1 - $pingResults.Count / 20) * 100, 0)
    $diffs  = @()
    for ($i = 1; $i -lt $pingResults.Count; $i++) {
        $diffs += [Math]::Abs($pingResults[$i] - $pingResults[$i-1])
    }
    $jitter = if ($diffs.Count -gt 0) {
        [Math]::Round(($diffs | Measure-Object -Average).Average, 1)
    } else { 0 }

    Result "Avg Latency"     "${avg}ms"             ($avg -lt 50)
    Result "Min / Max"       "${min}ms / ${max}ms"  $true
    Result "Jitter"          "${jitter}ms"           ($jitter -lt 10)
    Result "Packet Loss"     "${loss}%"              ($loss -eq 0)
} else {
    Log "  [!!] All pings failed" "Red"
}

# Simple download speed test (CHT 1MB file)
Log ""
Log "  Download speed test (CHT 1MB) ..." "White"
try {
    $start = Get-Date
    Invoke-WebRequest -Uri "http://speedtest.hinet.net/download/1MB.bin" `
        -OutFile "$env:TEMP\bwtest.bin" -TimeoutSec 15 -UseBasicParsing | Out-Null
    $sec     = ((Get-Date) - $start).TotalSeconds
    $mbps    = [Math]::Round((1 * 8) / $sec, 2)
    Result "Download (1MB CHT)" "${mbps} Mbps" ($mbps -gt 5)
    Remove-Item "$env:TEMP\bwtest.bin" -ErrorAction SilentlyContinue
} catch {
    Log "  [!!] Speed test failed (non-critical, skipped)" "Yellow"
}


# ============================================================
# [9] TR-069 / ACS Channel Verification
# ============================================================
Section "[9] TR-069 / ACS Channel Verification"

Log "  Checking active connections to $TargetIP ..." "White"
$activeConns = netstat -ano | Select-String $TargetIP
if ($activeConns) {
    foreach ($c in $activeConns) { Log "  $c" "Green" }
} else {
    Log "  No active connections found" "Yellow"
    Log "  (Normal within TR-069 heartbeat interval; re-run in 60s to verify)" "Yellow"
}

$tr069 = Test-NetConnection -ComputerName $TargetIP -Port 7547 -WarningAction SilentlyContinue
Result "TR-069 Port 7547" (if ($tr069.TcpTestSucceeded) { "OPEN" } else { "closed/filtered" }) $true

Log ""
Log "  NOTE: TR-069 is ONT-initiated OUTBOUND -- not inbound open." "Yellow"
Log "  Ask engineer to confirm ACS shows this ONT as [Connected]." "Yellow"


# ============================================================
# [10] Established Outbound Connections Summary
# ============================================================
Section "[10] Established Outbound TCP Connections"

$conns = netstat -ano | Select-String "ESTABLISHED" |
    Where-Object { $_ -notmatch "127\.0\.0\.1|::1|\[::1\]" }

if ($conns) {
    $conns | ForEach-Object { Log "  $_" "Gray" }
} else {
    Log "  No established outbound connections at this moment." "Yellow"
}


# ============================================================
# Footer
# ============================================================
Section "DONE"
Log "  Log saved : $((Get-Item $logFile).FullName)" "Cyan"
Log "  Target IP : $TargetIP" "Cyan"
Log "  Completed : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Cyan"
Log ("=" * 60) "Cyan"
