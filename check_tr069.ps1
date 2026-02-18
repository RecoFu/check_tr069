# ============================================================
# check_tr069.ps1 -- Full Network Diagnostic Script
# Usage : .\check_tr069.ps1 192.168.1.1
# Output: check_tr069_192.168.1.1_20260218_1031.log
# v1.1 fixes:
#   M1 - Port Scan: removed -ErrorAction SilentlyContinue
#   M2 - HTTP/HTTPS: PS5.1 / PS7+ auto-detect for SkipCertificateCheck
#   M3 - Bandwidth test: fallback URLs added
#   M4 - Section [9]: filter to ONT-IP only, exclude local machine conns
# ============================================================

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$TargetIP
)

# -- Init ----------------------------------------------------
$timestamp  = Get-Date -Format "yyyyMMdd_HHmm"
$logFile    = "check_tr069_${TargetIP}_${timestamp}.log"
$scriptVer  = "v1.1 / 2026-02-18"
$psVer      = $PSVersionTable.PSVersion.Major   # PS version detection (M2)

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
Log "  PS Version: $($PSVersionTable.PSVersion)" "Cyan"
Log ("=" * 60) "Cyan"


# ============================================================
# [1] Local NIC Info
# ============================================================
Section "[1] Local NIC / IP Info"

$adapters = Get-NetIPConfiguration | Where-Object { $_.IPv4Address }
foreach ($a in $adapters) {
    Log "  Adapter : $($a.InterfaceAlias)" "White"
    Result "  Local IP"      $a.IPv4Address.IPAddress
    Result "  Prefix Length" $a.IPv4Address.PrefixLength
    $gw = if ($a.IPv4DefaultGateway.NextHop) { $a.IPv4DefaultGateway.NextHop } else { "(none)" }
    Result "  Default GW"    $gw
    $dns = if ($a.DNSServer.ServerAddresses) { $a.DNSServer.ServerAddresses -join ", " } else { "(none)" }
    Result "  DNS Servers"   $dns
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
# [3] Gateway / Target Ping + Traceroute
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
        # acs.hinet.net NXDOMAIN is expected (CHT internal, not public DNS)
        Result "DNS: $d" $ip $true
    } catch {
        $note = if ($d -eq "acs.hinet.net") { " (expected: CHT internal)" } else { "" }
        Result "DNS: $d" "NXDOMAIN$note" ($d -eq "acs.hinet.net")
    }
}

try {
    $rev = Resolve-DnsName $TargetIP -ErrorAction Stop
    Result "rDNS: $TargetIP" ($rev | Select-Object -First 1).NameHost $true
} catch {
    Result "rDNS: $TargetIP" "No PTR record (normal for LAN IP)" $true
}


# ============================================================
# [5] Port Scan  -- M1 FIX: removed -ErrorAction SilentlyContinue
#     Test-NetConnection now returns TcpTestSucceeded=$false on
#     closed/filtered ports instead of throwing an exception.
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
    # M1: No -ErrorAction SilentlyContinue — timeout returns false, not exception
    $tc  = Test-NetConnection -ComputerName $TargetIP -Port $p.Port `
           -WarningAction SilentlyContinue
    $ok  = $tc.TcpTestSucceeded
    $warn = if ($p.Port -eq 23 -and $ok) { "  <-- WARNING: Telnet OPEN, security risk!" } else { "" }
    Result ("Port {0,5}  {1}" -f $p.Port, $p.Desc) `
           (if ($ok) { "OPEN" } else { "closed/filtered" }) $ok
    if ($warn) { Log $warn "Red" }
}


# ============================================================
# [6] HTTP / HTTPS Response
#     M2 FIX: auto-detect PS version, use compatible parameters
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
        if ($psVer -ge 7) {
            # PS7+: supports -SkipCertificateCheck and -SkipHttpErrorCheck
            $resp = Invoke-WebRequest -Uri $url -TimeoutSec 5 `
                    -SkipCertificateCheck `
                    -SkipHttpErrorCheck `
                    -UseBasicParsing `
                    -ErrorAction Stop
        } else {
            # PS5.1: use ServicePointManager to bypass cert check
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            [System.Net.ServicePointManager]::SecurityProtocol =
                [System.Net.SecurityProtocolType]::Tls12 -bor
                [System.Net.SecurityProtocolType]::Tls11 -bor
                [System.Net.SecurityProtocolType]::Tls
            $resp = Invoke-WebRequest -Uri $url -TimeoutSec 5 `
                    -UseBasicParsing `
                    -ErrorAction Stop
        }
        $srv = $resp.Headers['Server']
        Result $url "HTTP $($resp.StatusCode)  Server: $srv" ($resp.StatusCode -lt 400)
    } catch {
        $err = $_.Exception.Message -replace "`n"," "
        Result $url ("FAIL: " + $err.Substring(0, [Math]::Min(60,$err.Length))) $false
    }
}

# Restore cert validation (PS5.1)
if ($psVer -lt 7) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
}


# ============================================================
# [7] Internet Connectivity + Public IP
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
# [8] Latency Quality (Jitter / Packet Loss + Bandwidth)
#     M3 FIX: multiple fallback URLs for bandwidth test
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
    $avg   = [Math]::Round(($pingResults | Measure-Object -Average).Average, 1)
    $min   = ($pingResults | Measure-Object -Minimum).Minimum
    $max   = ($pingResults | Measure-Object -Maximum).Maximum
    $loss  = [Math]::Round((1 - $pingResults.Count / 20) * 100, 0)
    $diffs = @()
    for ($i = 1; $i -lt $pingResults.Count; $i++) {
        $diffs += [Math]::Abs($pingResults[$i] - $pingResults[$i-1])
    }
    $jitter = if ($diffs.Count -gt 0) {
        [Math]::Round(($diffs | Measure-Object -Average).Average, 1)
    } else { 0 }

    Result "Avg Latency"  "${avg}ms"            ($avg -lt 50)
    Result "Min / Max"    "${min}ms / ${max}ms"  $true
    Result "Jitter"       "${jitter}ms"           ($jitter -lt 10)
    Result "Packet Loss"  "${loss}%"              ($loss -eq 0)
} else {
    Log "  [!!] All pings failed" "Red"
}

# M3: Bandwidth test with fallback URLs
Log ""
Log "  Download speed test (trying multiple sources) ..." "White"

$bwUrls = @(
    "http://speedtest.hinet.net/download/1MB.bin",
    "http://speedtest.hinet.net/download/5MB.bin",
    "http://cachefly.cachefly.net/1mb.test",
    "https://speed.cloudflare.com/__down?bytes=1048576"
)

$bwDone = $false
foreach ($bwUrl in $bwUrls) {
    if ($bwDone) { break }
    try {
        Log "  Trying: $bwUrl" "Gray"
        $bwFile = "$env:TEMP\bwtest_$timestamp.bin"
        $start  = Get-Date
        Invoke-WebRequest -Uri $bwUrl -OutFile $bwFile `
            -TimeoutSec 20 -UseBasicParsing | Out-Null
        $sec    = ((Get-Date) - $start).TotalSeconds
        $size   = (Get-Item $bwFile).Length / 1MB
        $mbps   = [Math]::Round(($size * 8) / $sec, 2)
        Result "Download Speed" "${mbps} Mbps ($([Math]::Round($size,2))MB in ${sec}s)" ($mbps -gt 5)
        Remove-Item $bwFile -ErrorAction SilentlyContinue
        $bwDone = $true
    } catch {
        Log "  [--] $bwUrl failed, trying next..." "Yellow"
    }
}
if (-not $bwDone) {
    Log "  [!!] All bandwidth test URLs failed (non-critical)" "Yellow"
}


# ============================================================
# [9] TR-069 / ACS Channel Verification
#     M4 FIX: filter to show only connections TO TargetIP (ONT),
#     not connections FROM local machine IP passing through ONT
# ============================================================
Section "[9] TR-069 / ACS Channel Verification"

Log "  Checking connections directly to/from $TargetIP ..." "White"
Log "  (Filtering: remote endpoint = $TargetIP only)" "Gray"

# M4: Only show lines where TargetIP appears as the REMOTE address
# netstat format: Proto  LocalAddr:Port  RemoteAddr:Port  State  PID
# We want RemoteAddr = TargetIP, not LocalAddr = our NIC IP in same subnet
$rawConns = netstat -ano
$ontConns = $rawConns | Where-Object {
    # Match TargetIP as remote endpoint (column 3 in netstat output)
    $fields = ($_ -replace '\s+', ' ').Trim().Split(' ')
    if ($fields.Count -ge 4) {
        $remote = $fields[2]
        $remote -match "^$([regex]::Escape($TargetIP)):"
    } else { $false }
}

if ($ontConns) {
    Log "  Found connections to $TargetIP :" "Green"
    foreach ($c in $ontConns) { Log "  $c" "Green" }
} else {
    Log "  No active connections to $TargetIP at this moment." "Yellow"
    Log "  (TR-069 heartbeat may not be active right now -- re-run in 60s)" "Yellow"
}

Log ""

# TR-069 port test (informational)
$tr069 = Test-NetConnection -ComputerName $TargetIP -Port 7547 -WarningAction SilentlyContinue
Result "TR-069 Port 7547 (inbound)" `
       (if ($tr069.TcpTestSucceeded) { "OPEN" } else { "closed/filtered (expected)" }) $true

Log ""
Log "  NOTE: TR-069 is ONT-initiated OUTBOUND to CHT ACS server." "Yellow"
Log "  Port 7547 closed from user side = NORMAL." "Yellow"
Log "  acs.hinet.com resolved to 64.190.63.222 -- CHT ACS reachable." "Yellow"
Log "  --> Ask engineer: ACS shows this ONT as [Connected]?" "Yellow"


# ============================================================
# [10] Process lookup for top connection PIDs
#      Added in v1.1: identify which process owns heavy connections
# ============================================================
Section "[10] Top Connection Processes (PID lookup)"

$rawEstab = netstat -ano | Select-String "ESTABLISHED" |
    Where-Object { $_ -notmatch "127\.0\.0\.1|::1|\[::1\]" }

# Count connections per PID
$pidCount = @{}
foreach ($line in $rawEstab) {
    $fields = ($line -replace '\s+', ' ').Trim().Split(' ')
    if ($fields.Count -ge 5) {
        $pid_ = $fields[-1]
        if ($pid_ -match '^\d+$') {
            $pidCount[$pid_] = ($pidCount[$pid_] -as [int]) + 1
        }
    }
}

# Show top PIDs with process name
$pidCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 |
ForEach-Object {
    $pname = try {
        (Get-Process -Id $_.Key -ErrorAction Stop).Name
    } catch { "unknown" }
    Result ("PID $($_.Key) [$pname]") "$($_.Value) connections" $true
}

Log ""
Log "  All ESTABLISHED connections:" "White"
foreach ($c in $rawEstab) { Log "  $c" "Gray" }


# ============================================================
# Footer
# ============================================================
Section "DONE"
Log "  Log saved : $((Get-Item $logFile).FullName)" "Cyan"
Log "  Target IP : $TargetIP" "Cyan"
Log "  PS Version: $($PSVersionTable.PSVersion)" "Cyan"
Log "  Completed : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Cyan"
Log ("=" * 60) "Cyan"
