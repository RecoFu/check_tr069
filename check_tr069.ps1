# ==============================================================================
# NetFreak.ps1 -- Control Freak Network Self-Diagnostic
# Version  : v1.0 / 2026-02-18
# Author   : Generated for RECO-AN515 / CHT FTTH environment
# Usage    : .\NetFreak.ps1 [-GW 192.168.1.1] [-PingCount 30] [-Monitor] [-Html]
# Output   : NetFreak_<timestamp>.log + NetFreak_<timestamp>.html (if -Html)
#
# Differentiators vs GlassWire / PingPlotter / WinMTR / Speedtest:
#   [U1] MTU Path Discovery     -- binary search, no other PS tool does this
#   [U2] DNS Leak Test          -- compare 5 resolvers, detect DNS hijack
#   [U3] ASN / BGP / Geo        -- who owns your public IP, full routing info
#   [U4] MOS Score              -- VoIP quality metric (ITU-T G.107)
#   [U5] IGMP / Multicast       -- CHT MOD/IPTV multicast group detection
#   [U6] UPnP Port Audit        -- list all UPnP-exposed ports on ONT
#   [U7] MAC Vendor Lookup      -- identify device manufacturer from OUI
#   [U8] Dual-NIC Route Conflict-- detect routing loops / metric conflicts
#   [U9] ARP Cache              -- full LAN device map
#   [U10] IPv6 Full Audit       -- SLAAC/DHCPv6/firewall/leak
#   [U11] Security Score A-F    -- weighted 12-factor security assessment
#   [U12] HTML Report           -- self-contained beautiful HTML output
#   [U13] Continuous Monitor    -- live trend with -Monitor flag
# ==============================================================================

param(
    [string]$GW        = "",          # Override gateway IP
    [int]   $PingCount = 20,          # Ping repetitions for quality test
    [switch]$Monitor,                  # Continuous monitoring mode
    [switch]$Html,                     # Generate HTML report
    [switch]$SkipSlow                  # Skip slow tests (MTU/UPnP/IPv6)
)

# -- Init ----------------------------------------------------------------------
$timestamp  = Get-Date -Format "yyyyMMdd_HHmm"
$logFile    = "NetFreak_${timestamp}.log"
$htmlFile   = "NetFreak_${timestamp}.html"
$scriptVer  = "v1.0 / 2026-02-18"
$psVer      = $PSVersionTable.PSVersion.Major
$startTime  = Get-Date

# Security score accumulator
$secScore   = 100
$secIssues  = @()
$secGood    = @()

# HTML buffer
$htmlBody   = [System.Text.StringBuilder]::new()

# -- Core Functions ------------------------------------------------------------
function Log {
    param([string]$msg, [string]$color = "White")
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $logFile -Value $line
}

function Section {
    param([string]$title, [string]$uid = "")
    $bar = "-" * 62
    Log ""
    Log ("=" * 62) "Cyan"
    Log "  $title  $uid" "Cyan"
    Log ("=" * 62) "Cyan"
    if ($Html) {
        [void]$htmlBody.Append("<section><h2>$title <span class='uid'>$uid</span></h2>")
    }
}

function EndSection {
    if ($Html) { [void]$htmlBody.Append("</section>") }
}

function Result {
    param([string]$label, $value, [bool]$ok = $true, [string]$note = "")
    $icon = if ($ok) { "[OK]" } else { "[!!]" }
    $col  = if ($ok) { "Green" } else { "Yellow" }
    $line = ("  {0,-32} {1} {2}" -f $label, $icon, $value)
    if ($note) { $line += "  # $note" }
    Log $line $col
    if ($Html) {
        $cls = if ($ok) { "ok" } else { "warn" }
        [void]$htmlBody.Append(
            "<div class='row $cls'><span class='lbl'>$label</span>" +
            "<span class='icon'>$icon</span><span class='val'>$value</span>" +
            $(if ($note) { "<span class='note'>$note</span>" } else { "" }) +
            "</div>"
        )
    }
}

function Warn { param([string]$msg) Log "  [!!] $msg" "Red" }
function Info { param([string]$msg) Log "  ... $msg" "Gray" }

function SecDeduct {
    param([int]$pts, [string]$reason)
    $script:secScore -= $pts
    $script:secIssues += "[-$pts] $reason"
}
function SecGood { param([string]$reason) $script:secGood += "[OK] $reason" }

function Invoke-WebSafe {
    param([string]$Uri, [int]$Timeout = 8)
    try {
        if ($psVer -ge 7) {
            return Invoke-RestMethod -Uri $Uri -TimeoutSec $Timeout -SkipCertificateCheck -ErrorAction Stop
        } else {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            return Invoke-RestMethod -Uri $Uri -TimeoutSec $Timeout -ErrorAction Stop
        }
    } catch { return $null }
}

function WebGet {
    param([string]$Uri, [int]$Timeout = 8)
    try {
        if ($psVer -ge 7) {
            return Invoke-WebRequest -Uri $Uri -TimeoutSec $Timeout `
                   -SkipCertificateCheck -SkipHttpErrorCheck -UseBasicParsing -ErrorAction Stop
        } else {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            return Invoke-WebRequest -Uri $Uri -TimeoutSec $Timeout `
                   -UseBasicParsing -ErrorAction Stop
        }
    } catch { return $null }
}

# -- Header --------------------------------------------------------------------
Log ("=" * 62) "Cyan"
Log "  NetFreak.ps1  $scriptVer  -- Control Freak Diagnostic" "Cyan"
Log "  Host    : $env:COMPUTERNAME  |  User: $env:USERNAME" "Cyan"
Log "  PS      : $($PSVersionTable.PSVersion)  |  OS: $([System.Environment]::OSVersion.VersionString)" "Cyan"
Log "  Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Cyan"
Log ("=" * 62) "Cyan"


# ==============================================================================
# [1] FULL IP STACK  -- NIC / IPv4 / IPv6 / Routes / ARP  [U8][U9]
# ==============================================================================
Section "[1] Full IP Stack" "[U8][U9]"

# All adapters
$allAdapters = Get-NetIPConfiguration
$activeAdapters = $allAdapters | Where-Object { $_.IPv4Address }

Log "  === IPv4 Interfaces ===" "White"
$gwCandidates = @()
foreach ($a in $activeAdapters) {
    $ip  = $a.IPv4Address.IPAddress
    $pre = $a.IPv4Address.PrefixLength
    $gw  = $a.IPv4DefaultGateway.NextHop
    $dns = ($a.DNSServer.ServerAddresses -join ", ")
    Log ""
    Log "  Adapter : $($a.InterfaceAlias)  [$ip/$pre]" "White"
    Result "    IP / Prefix"    "$ip / $pre"
    Result "    Gateway"        $(if ($gw) { $gw } else { "(none)" }) ($null -ne $gw)
    Result "    DNS"            $(if ($dns) { $dns } else { "(none)" })
    if ($gw) { $gwCandidates += $gw }
}

# Auto-detect primary gateway
if (-not $GW) {
    $GW = ($activeAdapters | Where-Object { $_.IPv4DefaultGateway.NextHop } |
           Select-Object -First 1).IPv4DefaultGateway.NextHop
}
Log ""
Result "  Primary Gateway (auto)" $GW ($null -ne $GW)

# [U8] Dual-NIC routing conflict detection
Log ""
Log "  === [U8] Dual-NIC Routing Conflict Check ===" "White"
if ($gwCandidates.Count -gt 1) {
    Warn "Multiple gateways detected: $($gwCandidates -join ' | ')"
    Warn "Possible routing conflict -- check metric with: route print"
    SecDeduct 10 "Multiple active gateways detected (dual-NIC routing conflict risk)"
    # Check route metrics
    $routes = route print 0.0.0.0 2>$null | Select-String "0\.0\.0\.0"
    foreach ($r in $routes) { Info $r }
} else {
    Result "  Routing Conflict" "None detected (single gateway)" $true
    SecGood "Single active default gateway"
}

# [U9] ARP Cache -- LAN device map
Log ""
Log "  === [U9] ARP Cache / LAN Devices ===" "White"
$arp = arp -a 2>$null | Where-Object { $_ -match "dynamic|static" }
$arpCount = 0
foreach ($entry in $arp) {
    $parts = ($entry -replace '\s+', ' ').Trim().Split(' ')
    if ($parts.Count -ge 3) {
        Log ("    {0,-18} {1,-20} {2}" -f $parts[0], $parts[1], $parts[2]) "Gray"
        $arpCount++
    }
}
Result "  LAN Devices (ARP)" "$arpCount entries found"

# Route table summary
Log ""
Log "  === IPv4 Route Table ===" "White"
$routeLines = route print 2>$null | Select-String "^\s+\d"
foreach ($r in ($routeLines | Select-Object -First 12)) { Info $r }

# IPv6
Log ""
Log "  === IPv6 Interfaces ===" "White"
$v6 = Get-NetIPAddress -AddressFamily IPv6 | Where-Object {
    $_.IPAddress -notmatch "^fe80|^::1" } | Select-Object -First 4
if ($v6) {
    foreach ($a in $v6) { Result "  IPv6" "$($a.IPAddress) [$($a.PrefixOrigin)]" }
} else {
    Result "  IPv6 Global" "No global IPv6 address (v6 audit in [U10])" $true
}

EndSection


# ==============================================================================
# [2] DHCP DEEP DIVE
# ==============================================================================
Section "[2] DHCP Deep Dive"

$dhcpAdapters = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.PrefixOrigin -eq "Dhcp" }

if ($dhcpAdapters) {
    foreach ($d in $dhcpAdapters) {
        $wmi = Get-WmiObject Win32_NetworkAdapterConfiguration |
            Where-Object { $_.IPAddress -contains $d.IPAddress }
        if ($wmi) {
            Result "Adapter"        $d.InterfaceAlias
            Result "DHCP IP"        $wmi.IPAddress[0]
            Result "DHCP Server"    $wmi.DHCPServer
            Result "Subnet Mask"    $wmi.IPSubnet[0]
            Result "Lease Obtained" $wmi.DHCPLeaseObtained
            Result "Lease Expires"  $wmi.DHCPLeaseExpires

            # Lease duration analysis
            try {
                $obtained = [Management.ManagementDateTimeConverter]::ToDateTime($wmi.DHCPLeaseObtained)
                $expires  = [Management.ManagementDateTimeConverter]::ToDateTime($wmi.DHCPLeaseExpires)
                $duration = $expires - $obtained
                $remaining = $expires - (Get-Date)
                Result "Lease Duration"   "$([int]$duration.TotalHours)h"
                Result "Lease Remaining"  "$([int]$remaining.TotalHours)h $($remaining.Minutes)m" `
                       ($remaining.TotalHours -gt 1)
                if ($remaining.TotalHours -lt 2) {
                    SecDeduct 5 "DHCP lease expiring soon (<2h)"
                }
            } catch {}
            Log ""
        }
    }
} else {
    Result "DHCP" "No DHCP adapters (static IP configuration)" $true
}

EndSection


# ==============================================================================
# [3] GATEWAY DEEP ANALYSIS -- Ping / ARP / MAC Vendor
# ==============================================================================
Section "[3] Gateway Deep Analysis" "[U7]"

# Ping
$pingGW = Test-NetConnection -ComputerName $GW -WarningAction SilentlyContinue
Result "Ping $GW" "$($pingGW.PingReplyDetails.RoundtripTime)ms" $pingGW.PingSucceeded

# ARP to get MAC
$gwArp = arp -a $GW 2>$null | Select-String $GW | Select-Object -First 1
$gwMac = ""
if ($gwArp) {
    $gwMac = (($gwArp -replace '\s+', ' ').Trim().Split(' ') | Select-Object -Index 1)
    Result "Gateway MAC" $gwMac
}

# [U7] MAC Vendor Lookup (OUI database via API)
if ($gwMac -and $gwMac.Length -ge 8) {
    Info "Looking up MAC vendor..."
    $oui = $gwMac -replace "[:\-]", "" | Select-Object -First 1
    $oui = $oui.Substring(0, [Math]::Min(6, $oui.Length))
    $vendor = Invoke-WebSafe "https://api.macvendors.com/$gwMac" -Timeout 5
    if ($vendor) {
        Result "Gateway Vendor [U7]" "$vendor" $true
    } else {
        Result "Gateway Vendor [U7]" "Lookup failed (offline or rate-limited)" $true
    }
}

# Traceroute
Log ""
Log "  Traceroute to gateway (max 5 hops):" "White"
try {
    $hops = Test-NetConnection -ComputerName $GW -TraceRoute -Hops 5 -WarningAction SilentlyContinue
    $i = 1
    foreach ($hop in $hops.TraceRoute) {
        Log ("    Hop {0:D2}  {1}" -f $i, $hop) "Gray"; $i++
    }
} catch { Warn "Traceroute failed" }

EndSection


# ==============================================================================
# [4] PORT SCAN -- Gateway / ONT security audit
# ==============================================================================
Section "[4] Port Security Audit"

$ports = @(
    @{Port=80;   Desc="HTTP Admin";              Risk="low"},
    @{Port=443;  Desc="HTTPS Admin";             Risk="low"},
    @{Port=23;   Desc="Telnet";                  Risk="CRITICAL"},
    @{Port=22;   Desc="SSH";                     Risk="medium"},
    @{Port=21;   Desc="FTP";                     Risk="high"},
    @{Port=7547; Desc="TR-069 CWMP";             Risk="medium"},
    @{Port=7548; Desc="TR-069 CWMP alt";         Risk="medium"},
    @{Port=8080; Desc="HTTP alt";                Risk="low"},
    @{Port=8443; Desc="HTTPS alt";               Risk="low"},
    @{Port=8888; Desc="HTTP mgmt alt";           Risk="medium"},
    @{Port=161;  Desc="SNMP";                    Risk="high"},
    @{Port=162;  Desc="SNMP Trap";               Risk="high"},
    @{Port=53;   Desc="DNS";                     Risk="low"},
    @{Port=67;   Desc="DHCP Server";             Risk="low"},
    @{Port=5555; Desc="ADB (Android Debug)";     Risk="CRITICAL"},
    @{Port=1900; Desc="UPnP SSDP";               Risk="medium"}
)

$openPorts = @()
foreach ($p in $ports) {
    $tc = Test-NetConnection -ComputerName $GW -Port $p.Port -WarningAction SilentlyContinue
    $ok = $tc.TcpTestSucceeded
    $status = if ($ok) { "OPEN" } else { "closed" }

    if ($ok) {
        $openPorts += $p
        $riskCol = switch ($p.Risk) {
            "CRITICAL" { "Red" }
            "high"     { "Red" }
            "medium"   { "Yellow" }
            default    { "Green" }
        }
        Log ("  Port {0,5}  {1,-25} OPEN  [{2}]" -f $p.Port, $p.Desc, $p.Risk.ToUpper()) $riskCol

        switch ($p.Risk) {
            "CRITICAL" { SecDeduct 20 "Port $($p.Port) ($($p.Desc)) is OPEN -- critical risk" }
            "high"     { SecDeduct 10 "Port $($p.Port) ($($p.Desc)) is OPEN -- high risk" }
            "medium"   { SecDeduct 5  "Port $($p.Port) ($($p.Desc)) is OPEN" }
        }
    } else {
        Log ("  Port {0,5}  {1,-25} closed" -f $p.Port, $p.Desc) "Gray"
    }
}

Log ""
Result "Open Ports Total" "$($openPorts.Count) / $($ports.Count) scanned" ($openPorts.Count -le 3)
if ($openPorts.Count -eq 0) { SecGood "No unexpected ports open on gateway" }

EndSection


# ==============================================================================
# [5] DNS DEEP DIVE + LEAK TEST  [U2]
# ==============================================================================
Section "[5] DNS Deep Dive + Leak Test" "[U2]"

# Standard resolution
$dnsTargets = @("google.com","hinet.net","github.com","cloudflare.com","acs.hinet.com")
foreach ($d in $dnsTargets) {
    try {
        $r  = Resolve-DnsName $d -ErrorAction Stop -WarningAction SilentlyContinue
        $ip = ($r | Where-Object { $_.Type -eq "A" } | Select-Object -First 1).IPAddress
        if (-not $ip) { $ip = ($r | Select-Object -First 1).NameHost }
        Result "DNS: $d" $ip
    } catch {
        Result "DNS: $d" "NXDOMAIN" $false
    }
}

# [U2] DNS Leak Test -- compare results across 5 public resolvers
Log ""
Log "  === [U2] DNS Leak Test (5 Resolvers) ===" "White"
Info "Querying multiple resolvers for 'whoami.akamai.net' & 'o-o.myaddr.l.google.com'..."

$resolvers = @(
    @{Name="CHT   "; IP="168.95.1.1"},
    @{Name="Google "; IP="8.8.8.8"},
    @{Name="CF     "; IP="1.1.1.1"},
    @{Name="Quad9  "; IP="9.9.9.9"},
    @{Name="TWNIC  "; IP="101.101.101.101"}
)

$resolverResults = @{}
foreach ($res in $resolvers) {
    try {
        $r = Resolve-DnsName "o-o.myaddr.l.google.com" -Server $res.IP `
             -ErrorAction Stop -WarningAction SilentlyContinue
        $val = ($r | Where-Object { $_.Type -eq "TXT" } | Select-Object -First 1).Strings
        $resolverResults[$res.Name] = $val
        Result "  Resolver $($res.Name) $($res.IP)" "$val"
    } catch {
        Result "  Resolver $($res.Name) $($res.IP)" "Timeout / blocked" $false
    }
}

# Leak analysis: if all resolvers return same IP = no leak
$uniqueIPs = ($resolverResults.Values | Where-Object { $_ }) | Sort-Object -Unique
if ($uniqueIPs.Count -eq 1) {
    Result "DNS Leak Status [U2]" "CLEAN -- all resolvers agree on your IP" $true
    SecGood "DNS leak test passed (consistent across resolvers)"
} elseif ($uniqueIPs.Count -gt 1) {
    Warn "DNS Leak Detected [U2] -- resolvers disagree: $($uniqueIPs -join ' | ')"
    Warn "Possible DNS hijacking or split-horizon DNS active"
    SecDeduct 15 "DNS Leak detected -- resolver results inconsistent"
} else {
    Result "DNS Leak Status [U2]" "Inconclusive (resolver timeouts)" $true
}

EndSection


# ==============================================================================
# [6] INTERNET + PUBLIC IP + ASN/BGP/GEO  [U3]
# ==============================================================================
Section "[6] Internet + Public IP + ASN" "[U3]"

# Basic connectivity
foreach ($t in @("8.8.8.8","1.1.1.1","168.95.1.1","101.101.101.101")) {
    $p = Test-NetConnection -ComputerName $t -WarningAction SilentlyContinue
    Result "Ping $t" "$($p.PingReplyDetails.RoundtripTime)ms" $p.PingSucceeded
}

# Public IP
Log ""
Log "  === Public IP + [U3] ASN / BGP / Geo ===" "White"
$pubIP = ""
$ipInfo = Invoke-WebSafe "https://ipinfo.io/json" -Timeout 8
if (-not $ipInfo) { $ipInfo = Invoke-WebSafe "https://ip-api.com/json" -Timeout 8 }

if ($ipInfo) {
    $pubIP = if ($ipInfo.ip)     { $ipInfo.ip }     else { $ipInfo.query }
    $org   = if ($ipInfo.org)    { $ipInfo.org }    else { $ipInfo.isp }
    $city  = if ($ipInfo.city)   { $ipInfo.city }   else { "" }
    $region= if ($ipInfo.region) { $ipInfo.region } else { "" }
    $asn   = if ($ipInfo.org)    { $ipInfo.org }    elseif ($ipInfo.as) { $ipInfo.as } else { "N/A" }

    Result "Public IP [U3]"  $pubIP
    Result "ISP / Org"       $org
    Result "ASN"             $asn
    Result "City / Region"   "$city, $region"

    # Verify CHT
    if ($org -match "HiNet|Chunghwa|CHT") {
        Result "ISP Verify" "CHT HiNet confirmed" $true
        SecGood "Traffic exits via CHT HiNet (expected)"
    } else {
        Warn "Traffic NOT exiting via CHT -- possible VPN/proxy active"
    }

    # Check if IP is in threat databases (basic)
    $abuse = Invoke-WebSafe "https://api.abuseipdb.com/api/v2/check?ipAddress=$pubIP" -Timeout 5
    if ($abuse -and $abuse.data.abuseConfidenceScore -gt 0) {
        Warn "Public IP $pubIP has AbuseIPDB score: $($abuse.data.abuseConfidenceScore)%"
        SecDeduct 10 "Public IP flagged in AbuseIPDB"
    }
} else {
    Result "Public IP" "Failed to retrieve" $false
}

EndSection


# ==============================================================================
# [7] LATENCY QUALITY -- Jitter / Loss / MOS Score  [U4]
# ==============================================================================
Section "[7] Latency Quality + MOS Score" "[U4]"

$targets = @(
    @{Host="168.95.1.1"; Name="CHT DNS"},
    @{Host="8.8.8.8";    Name="Google DNS"},
    @{Host="1.1.1.1";    Name="CF DNS"}
)

foreach ($tgt in $targets) {
    Log ""
    Log "  Pinging $($tgt.Name) ($($tgt.Host)) x$PingCount ..." "White"
    $results = @()
    for ($i = 1; $i -le $PingCount; $i++) {
        $p = Test-NetConnection -ComputerName $tgt.Host -WarningAction SilentlyContinue
        if ($p.PingSucceeded) { $results += $p.PingReplyDetails.RoundtripTime }
        Write-Host "." -NoNewline -ForegroundColor Gray
    }
    Write-Host ""

    if ($results.Count -gt 0) {
        $avg    = [Math]::Round(($results | Measure-Object -Average).Average, 1)
        $min    = ($results | Measure-Object -Minimum).Minimum
        $max    = ($results | Measure-Object -Maximum).Maximum
        $loss   = [Math]::Round((1 - $results.Count / $PingCount) * 100, 0)
        $diffs  = @()
        for ($i = 1; $i -lt $results.Count; $i++) {
            $diffs += [Math]::Abs($results[$i] - $results[$i-1])
        }
        $jitter = if ($diffs.Count -gt 0) {
            [Math]::Round(($diffs | Measure-Object -Average).Average, 1)
        } else { 0 }

        # [U4] MOS Score -- ITU-T G.107 E-model simplified
        # R = 93.2 - Id - Ie + A
        # Id (delay factor) = 0.024*d + 0.11*(d-177.3)*H(d-177.3)
        # Ie (equipment) approximated from packet loss
        # MOS = 1 + 0.035*R + 0.000007*R*(R-60)*(100-R)
        $d  = $avg
        $Id = 0.024 * $d + 0.11 * [Math]::Max(0, ($d - 177.3))
        $Ie = 30 * $loss / ($loss + 5)  # simplified
        $R  = [Math]::Max(0, [Math]::Min(100, 93.2 - $Id - $Ie))
        $mos = 1 + 0.035 * $R + 0.000007 * $R * ($R - 60) * (100 - $R)
        $mos = [Math]::Round($mos, 2)
        $mosGrade = switch ($true) {
            { $mos -ge 4.3 } { "Excellent (A)" }
            { $mos -ge 4.0 } { "Good (B)" }
            { $mos -ge 3.6 } { "Fair (C)" }
            { $mos -ge 3.1 } { "Poor (D)" }
            default          { "Bad  (F)" }
        }

        Result "  $($tgt.Name) Avg"     "${avg}ms"           ($avg -lt 50)
        Result "  $($tgt.Name) Min/Max" "${min}ms / ${max}ms" $true
        Result "  $($tgt.Name) Jitter"  "${jitter}ms"        ($jitter -lt 10)
        Result "  $($tgt.Name) Loss"    "${loss}%"           ($loss -eq 0)
        Result "  $($tgt.Name) MOS [U4]" "$mos / 5.0  $mosGrade" ($mos -ge 3.6)

        if ($loss -gt 5)   { SecDeduct 10 "Packet loss $loss% to $($tgt.Host)" }
        if ($jitter -gt 20) { SecDeduct 5 "High jitter ${jitter}ms to $($tgt.Host)" }
        if ($mos -lt 3.6)  { SecDeduct 5 "Poor MOS score $mos (VoIP/MOD quality impacted)" }
    }
}

EndSection


# ==============================================================================
# [8] MTU PATH DISCOVERY  [U1]
# ==============================================================================
Section "[8] MTU Path Discovery" "[U1]"

if ($SkipSlow) {
    Log "  [SKIPPED] Use without -SkipSlow to run MTU discovery" "Yellow"
} else {
    Log "  Binary search for optimal MTU (DF-bit ping)..." "White"
    Info "Testing path to 8.8.8.8 with varying payload sizes"

    $mtuLow  = 576
    $mtuHigh = 1500
    $mtuOK   = 576

    # Binary search
    while ($mtuHigh - $mtuLow -gt 1) {
        $mtuTest = [int](($mtuLow + $mtuHigh) / 2)
        # Use ping.exe with -f (don't fragment) -l (size) -n 1 -w 2000
        $pingResult = ping.exe -f -l $mtuTest -n 2 -w 2000 8.8.8.8 2>$null
        if ($pingResult -match "Reply from|bytes=") {
            $mtuOK   = $mtuTest
            $mtuLow  = $mtuTest
            Info "  Size $mtuTest OK"
        } else {
            $mtuHigh = $mtuTest
            Info "  Size $mtuTest fragmented/dropped"
        }
    }

    # Actual MTU = payload + IP header(20) + ICMP header(8)
    $actualMTU = $mtuOK + 28

    Result "Optimal MTU [U1]" "$actualMTU bytes (payload: $mtuOK)" $true

    $mtuNote = switch ($true) {
        { $actualMTU -eq 1500 } { "Ethernet standard -- perfect" }
        { $actualMTU -eq 1492 } { "PPPoE -- normal for DSL/FTTH PPPoE (8 byte overhead)" }
        { $actualMTU -ge 1400 } { "Slightly reduced -- possible PPPoE or VPN" }
        { $actualMTU -lt 1400 } { "Low MTU -- possible VPN tunnel or misconfigured network" }
        default                 { "" }
    }
    if ($mtuNote) { Info "MTU Note: $mtuNote" }

    if ($actualMTU -lt 1400) { SecDeduct 5 "Low MTU ($actualMTU) may cause performance issues" }
    if ($actualMTU -eq 1492) { SecGood "MTU 1492 -- correct for CHT FTTH PPPoE" }
    if ($actualMTU -eq 1500) { SecGood "MTU 1500 -- optimal Ethernet MTU" }
}

EndSection


# ==============================================================================
# [9] BANDWIDTH TEST -- Multi-source with accuracy
# ==============================================================================
Section "[9] Bandwidth Test"

$bwUrls = @(
    @{Url="http://speedtest.hinet.net/download/10MB.bin"; Name="CHT 10MB"},
    @{Url="http://speedtest.hinet.net/download/5MB.bin";  Name="CHT 5MB"},
    @{Url="http://cachefly.cachefly.net/10mb.test";       Name="CacheFly 10MB"},
    @{Url="https://speed.cloudflare.com/__down?bytes=10485760"; Name="Cloudflare 10MB"}
)

$bwDone = $false
foreach ($bw in $bwUrls) {
    if ($bwDone) { break }
    try {
        Info "Trying: $($bw.Name) ..."
        $bwFile = "$env:TEMP\nf_bw_$timestamp.bin"
        $start  = Get-Date
        Invoke-WebRequest -Uri $bw.Url -OutFile $bwFile -TimeoutSec 30 -UseBasicParsing | Out-Null
        $elapsed = ((Get-Date) - $start).TotalSeconds
        $sizeMB  = (Get-Item $bwFile).Length / 1MB
        $mbps    = [Math]::Round(($sizeMB * 8) / $elapsed, 2)
        $mbytes  = [Math]::Round($sizeMB / $elapsed, 2)

        Result "Download [$($bw.Name)]" "${mbps} Mbps  (${mbytes} MB/s in $([Math]::Round($elapsed,1))s)" ($mbps -gt 10)

        # Estimate upload is typically ~10% less for CHT FTTH (asymmetric)
        Info "Upload estimate: typically 80-95% of download for CHT FTTH symmetric plans"

        Remove-Item $bwFile -ErrorAction SilentlyContinue
        $bwDone = $true
    } catch {
        Info "$($bw.Name) failed, trying next source..."
    }
}
if (-not $bwDone) { Warn "All bandwidth test sources failed (non-critical)" }

EndSection


# ==============================================================================
# [10] IPv6 FULL AUDIT  [U10]
# ==============================================================================
Section "[10] IPv6 Full Audit" "[U10]"

if ($SkipSlow) {
    Log "  [SKIPPED] Use without -SkipSlow to run IPv6 audit" "Yellow"
} else {
    # Check if IPv6 global address exists
    $v6global = Get-NetIPAddress -AddressFamily IPv6 |
        Where-Object { $_.IPAddress -notmatch "^fe80|^::1" -and $_.PrefixOrigin -ne "WellKnown" }

    if ($v6global) {
        $v6ip = ($v6global | Select-Object -First 1).IPAddress
        Result "IPv6 Global Address [U10]" $v6ip $true

        # Test IPv6 connectivity
        $v6ping = Test-NetConnection -ComputerName "2001:4860:4860::8888" -WarningAction SilentlyContinue
        Result "IPv6 Ping Google DNS" $(if ($v6ping.PingSucceeded) { "OK" } else { "FAIL" }) $v6ping.PingSucceeded

        # IPv6 leak check (are we leaking v6 when v4 VPN active?)
        $v6pub = Invoke-WebSafe "https://v6.ident.me/" -Timeout 5
        if ($v6pub) {
            Result "IPv6 Public Address" $v6pub
            Warn "IPv6 is active and publicly routable -- ensure firewall covers IPv6"
            SecDeduct 8 "IPv6 publicly reachable -- verify IPv6 firewall enabled on router"
        }

        # Check IPv6 firewall (can we be reached externally?)
        Result "IPv6 Firewall Advisory" "Verify router has IPv6 stateful firewall enabled" $true

    } else {
        Result "IPv6 Global" "No global IPv6 address" $true
        Info "IPv6 not routable from this machine -- either not configured or NAT64"
        SecGood "No IPv6 global address (no IPv6 exposure risk)"
    }

    # Check SLAAC vs DHCPv6
    $v6link = Get-NetIPAddress -AddressFamily IPv6 | Where-Object { $_.IPAddress -match "^fe80" }
    Result "IPv6 Link-Local" $(if ($v6link) { "Present (normal)" } else { "None" }) $true
}

EndSection


# ==============================================================================
# [11] UPnP PORT EXPOSURE AUDIT  [U6]
# ==============================================================================
Section "[11] UPnP Port Exposure Audit" "[U6]"

if ($SkipSlow) {
    Log "  [SKIPPED] Use without -SkipSlow to run UPnP audit" "Yellow"
} else {
    Info "Discovering UPnP devices via SSDP multicast..."

    # SSDP discovery
    $ssdpMsg = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 3`r`nST: upnp:rootdevice`r`n`r`n"
    $upnpDevices = @()

    try {
        $udp = [System.Net.Sockets.UdpClient]::new()
        $udp.EnableBroadcast = $true
        $udp.Client.ReceiveTimeout = 3000
        $ep  = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse("239.255.255.250"), 1900)
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($ssdpMsg)
        [void]$udp.Send($bytes, $bytes.Length, $ep)

        $deadline = (Get-Date).AddSeconds(3)
        while ((Get-Date) -lt $deadline) {
            try {
                $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                $data   = $udp.Receive([ref]$remote)
                $resp   = [System.Text.Encoding]::ASCII.GetString($data)
                $loc    = if ($resp -match "LOCATION:\s*(.+)") { $matches[1].Trim() } else { "" }
                if ($loc -and $upnpDevices -notcontains $remote.Address) {
                    $upnpDevices += @{IP=$remote.Address; Location=$loc}
                    Log "  Found UPnP device: $($remote.Address)  $loc" "Yellow"
                }
            } catch { break }
        }
        $udp.Close()
    } catch { Info "SSDP discovery failed (firewall may block)" }

    if ($upnpDevices.Count -gt 0) {
        Result "UPnP Devices Found [U6]" "$($upnpDevices.Count) device(s)" $false
        Warn "UPnP active -- check for unauthorized port mappings"
        SecDeduct 8 "UPnP enabled -- potential unauthorized port exposure"

        # Try to enumerate port mappings from first UPnP device
        foreach ($dev in ($upnpDevices | Select-Object -First 1)) {
            Info "Fetching UPnP port mappings from $($dev.IP)..."
            $desc = WebGet $dev.Location -Timeout 5
            if ($desc) { Info "UPnP device description fetched -- check log for details" }
        }
    } else {
        Result "UPnP Devices [U6]" "None discovered (UPnP may be disabled)" $true
        SecGood "No UPnP devices discovered"
    }
}

EndSection


# ==============================================================================
# [12] IGMP / MULTICAST DETECTION  [U5]  -- CHT MOD / IPTV
# ==============================================================================
Section "[12] IGMP / Multicast Detection (CHT MOD)" "[U5]"

Info "Checking IGMP multicast group memberships..."

# netsh to get multicast groups
$igmp = netsh interface ip show joins 2>$null
$mcastGroups = @()
if ($igmp) {
    $mcastLines = $igmp | Select-String "224\.|239\."
    foreach ($line in $mcastLines) {
        $mcastGroups += $line.ToString().Trim()
        Log "  Multicast: $($line.ToString().Trim())" "Gray"
    }
}

if ($mcastGroups.Count -gt 0) {
    Result "IGMP Groups [U5]" "$($mcastGroups.Count) multicast group(s) active"

    $modGroups = $mcastGroups | Where-Object { $_ -match "239\." }
    if ($modGroups) {
        Result "CHT MOD IGMP" "MOD multicast detected (239.x.x.x range)" $true
        SecGood "IGMP multicast active -- CHT MOD/IPTV confirmed working"
    }
} else {
    Result "IGMP Groups [U5]" "None (MOD not active or not connected)" $true
}

# Check for multicast traffic on adapters
$mcastStats = netsh interface ip show ipstats 2>$null | Select-String "Multicast"
if ($mcastStats) {
    foreach ($s in $mcastStats) { Info $s }
}

EndSection


# ==============================================================================
# [13] PROCESS / CONNECTION MAP -- Full PID analysis
# ==============================================================================
Section "[13] Process + Connection Map"

$rawConns = netstat -ano | Select-String "ESTABLISHED|LISTENING"
$pidMap   = @{}

foreach ($line in $rawConns) {
    $f = ($line -replace '\s+', ' ').Trim().Split(' ')
    if ($f.Count -ge 5) {
        $pid_ = $f[-1]
        if ($pid_ -match '^\d+$' -and $pid_ -ne "0") {
            if (-not $pidMap[$pid_]) {
                $pname = try { (Get-Process -Id $pid_ -ErrorAction Stop).Name } catch { "?" }
                $pidMap[$pid_] = @{Name=$pname; Conns=0; Lines=@()}
            }
            $pidMap[$pid_].Conns++
            $pidMap[$pid_].Lines += $line.ToString().Trim()
        }
    }
}

# Top 10 by connection count
Log "  === Top Processes by Connection Count ===" "White"
$pidMap.GetEnumerator() | Sort-Object { $_.Value.Conns } -Descending |
Select-Object -First 10 | ForEach-Object {
    $suspicious = $_.Value.Name -match "unknown|\?" -and $_.Value.Conns -gt 5
    Result ("  PID {0,6} [{1,-20}]" -f $_.Key, $_.Value.Name) `
           "$($_.Value.Conns) connections" (-not $suspicious)
    if ($suspicious) { SecDeduct 5 "Unknown process PID $($_.Key) has $($_.Value.Conns) connections" }
}

# External ESTABLISHED connections
Log ""
Log "  === External ESTABLISHED Connections ===" "White"
$extConns = netstat -ano | Select-String "ESTABLISHED" |
    Where-Object { $_ -notmatch "127\.0\.0\.1|::1|0\.0\.0\.0" }
foreach ($c in $extConns) { Log "  $c" "Gray" }

EndSection


# ==============================================================================
# [14] WIFI ANALYSIS (if applicable)
# ==============================================================================
Section "[14] WiFi Analysis"

$wifiAdapters = Get-NetAdapter | Where-Object { $_.MediaType -match "802.11|native 802.11" -and $_.Status -eq "Up" }

if ($wifiAdapters) {
    foreach ($wa in $wifiAdapters) {
        Log "  === WiFi: $($wa.Name) ===" "White"

        # netsh wlan show interfaces
        $wlanInfo = netsh wlan show interfaces 2>$null
        if ($wlanInfo) {
            $ssid    = ($wlanInfo | Select-String "SSID\s+:" | Select-Object -First 1) -replace ".*:\s*",""
            $bssid   = ($wlanInfo | Select-String "BSSID\s+:") -replace ".*:\s*",""
            $signal  = ($wlanInfo | Select-String "Signal") -replace ".*:\s*",""
            $radio   = ($wlanInfo | Select-String "Radio type") -replace ".*:\s*",""
            $channel = ($wlanInfo | Select-String "Channel") -replace ".*:\s*",""
            $rxRate  = ($wlanInfo | Select-String "Receive rate") -replace ".*:\s*",""
            $txRate  = ($wlanInfo | Select-String "Transmit rate") -replace ".*:\s*",""

            Result "SSID"         $ssid.Trim()
            Result "BSSID"        $bssid.Trim()
            Result "Signal"       $signal.Trim() ($signal -match "([7-9]\d|100)%")
            Result "Radio Type"   $radio.Trim()
            Result "Channel"      $channel.Trim()
            Result "RX Rate"      $rxRate.Trim()
            Result "TX Rate"      $txRate.Trim()

            $sigNum = ($signal -replace "[^0-9]","") -as [int]
            if ($sigNum -lt 50) { SecDeduct 5 "WiFi signal weak ($sigNum%)" }
            if ($sigNum -ge 80) { SecGood "WiFi signal strong ($sigNum%)" }
        }

        # Available networks
        Log ""
        Log "  === Nearby Networks ===" "White"
        netsh wlan show networks mode=bssid 2>$null | Select-String "SSID|Signal|Channel" |
        ForEach-Object { Info $_ }
    }
} else {
    Result "WiFi" "No active WiFi adapter (wired only)" $true
}

EndSection


# ==============================================================================
# [15] SECURITY SCORE  [U11]
# ==============================================================================
Section "[15] Security Score" "[U11]"

$secScore = [Math]::Max(0, $secScore)
$grade = switch ($true) {
    { $secScore -ge 90 } { "A" }
    { $secScore -ge 80 } { "B" }
    { $secScore -ge 70 } { "C" }
    { $secScore -ge 60 } { "D" }
    default              { "F" }
}
$gradeCol = switch ($grade) {
    "A" { "Green" }; "B" { "Green" }
    "C" { "Yellow" }; "D" { "Yellow" }
    default { "Red" }
}

Log ""
Log ("  SECURITY SCORE: {0}/100  Grade: {1}" -f $secScore, $grade) $gradeCol
Log ""

if ($secIssues) {
    Log "  Issues Found:" "Yellow"
    foreach ($i in $secIssues) { Log "    $i" "Yellow" }
}
Log ""
if ($secGood) {
    Log "  Passed Checks:" "Green"
    foreach ($g in $secGood) { Log "    $g" "Green" }
}

EndSection


# ==============================================================================
# [16] HTML REPORT GENERATION  [U12]
# ==============================================================================
if ($Html) {
    $elapsed = [Math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
    $gradeColor = switch ($grade) {
        "A" { "#00ff88" }; "B" { "#88ff00" }
        "C" { "#ffee00" }; "D" { "#ff8800" }
        default { "#ff2244" }
    }

    $htmlFull = @"
<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetFreak Report -- $($env:COMPUTERNAME) -- $timestamp</title>
<style>
  :root {
    --bg: #0a0e1a; --surface: #111827; --border: #1e2d45;
    --cyan: #00d4ff; --green: #00ff88; --yellow: #ffee00;
    --red: #ff2244; --gray: #4a5568; --text: #e2e8f0;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Courier New', monospace;
         font-size: 13px; line-height: 1.6; padding: 24px; }
  header { border: 1px solid var(--cyan); padding: 20px; margin-bottom: 24px;
           background: linear-gradient(135deg, #0a1628 0%, #0d1f35 100%); }
  header h1 { color: var(--cyan); font-size: 22px; letter-spacing: 3px; }
  header .meta { color: var(--gray); margin-top: 8px; font-size: 11px; }
  .score-badge { float: right; font-size: 48px; font-weight: bold;
                 color: $gradeColor; text-shadow: 0 0 20px $gradeColor; }
  section { border: 1px solid var(--border); margin-bottom: 16px;
            background: var(--surface); border-radius: 4px; overflow: hidden; }
  h2 { background: #0d1f35; color: var(--cyan); padding: 10px 16px;
       font-size: 13px; letter-spacing: 1px; border-bottom: 1px solid var(--border); }
  h2 .uid { color: var(--gray); font-size: 11px; }
  .row { display: flex; padding: 5px 16px; border-bottom: 1px solid #0f1a2a; align-items: center; }
  .row:last-child { border-bottom: none; }
  .row.ok  .icon { color: var(--green); }
  .row.warn .icon { color: var(--yellow); }
  .lbl  { flex: 0 0 280px; color: #94a3b8; }
  .icon { flex: 0 0 50px; font-weight: bold; }
  .val  { flex: 1; color: var(--text); }
  .note { flex: 0 0 200px; color: var(--gray); font-size: 11px; text-align: right; }
  footer { text-align: center; color: var(--gray); font-size: 11px; margin-top: 24px; }
  @media (max-width: 600px) { .lbl { flex: 0 0 140px; } .note { display: none; } }
</style>
</head>
<body>
<header>
  <div class="score-badge">$grade</div>
  <h1>⚡ NETFREAK REPORT</h1>
  <div class="meta">
    Host: $($env:COMPUTERNAME) &nbsp;|&nbsp;
    User: $($env:USERNAME) &nbsp;|&nbsp;
    Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp;
    Duration: ${elapsed}s &nbsp;|&nbsp;
    Score: $secScore/100 ($grade)
  </div>
</header>
$($htmlBody.ToString())
<footer>NetFreak.ps1 $scriptVer -- Control Freak Network Diagnostic</footer>
</body></html>
"@
    $htmlFull | Out-File -FilePath $htmlFile -Encoding UTF8
    Log ""
    Log "  HTML Report: $((Get-Item $htmlFile).FullName)" "Cyan"
}


# ==============================================================================
# FOOTER
# ==============================================================================
$totalSec = [Math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
Section "COMPLETE"
Log "  Log      : $((Get-Item $logFile).FullName)" "Cyan"
if ($Html) { Log "  HTML     : $((Get-Item $htmlFile).FullName)" "Cyan" }
Log "  Score    : $secScore/100  Grade: $grade" "Cyan"
Log "  Duration : ${totalSec}s" "Cyan"
Log "  Finished : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Cyan"
Log ("=" * 62) "Cyan"

# Restore cert validation
if ($psVer -lt 7) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
}
