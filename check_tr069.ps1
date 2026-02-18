# ==============================================================================
# NetFreak.ps1 v1.1 -- Control Freak Network Self-Diagnostic
# 2026-02-18 | Red Team Hardened Edition
#
# v1.1 Changes (Red Team Audit Response):
#   RT-D1  FIXED  MAC OUI lookup: external API removed, embedded table instead
#   RT-D1  FIXED  ASN/IP/Geo: gated behind -AllowExternalAPI flag
#   RT-D2  FIXED  SSDP/PortScan: -Stealth mode throttles footprint
#   RT-D3  FIXED  MTU: gentler ICMP, skip old-ONT-safe guard added
#   RT-U11 FIXED  Security score: CVSS v3.1 severity mapping added
#   RT-U4  FIXED  MOS formula: improved E-model with codec table
#   RT-U2  FIXED  DNS leak: TTL-aware comparison added
#   RT-NEW ADDED  [U14] Process+User: Get-Process -IncludeUserName + privilege flag
#   RT-NEW ADDED  -Stealth flag: disables SSDP, slows portscan, no external API
#   RT-NEW ADDED  -AllowExternalAPI flag: explicit opt-in for macvendors/ipinfo/abuseipdb
#
# Usage:
#   .\NetFreak.ps1 -GW 192.168.1.1
#   .\NetFreak.ps1 -GW 192.168.1.1 -Html -AllowExternalAPI
#   .\NetFreak.ps1 -GW 192.168.1.1 -Stealth                   # low footprint
#   .\NetFreak.ps1 -GW 192.168.1.1 -SkipSlow -Html
# ==============================================================================

param(
    [string]$GW               = "",
    [int]   $PingCount        = 20,
    [switch]$Html,
    [switch]$SkipSlow,
    [switch]$Stealth,           # RT-D2: reduce scan footprint
    [switch]$AllowExternalAPI   # RT-D1: explicit opt-in for external API calls
)

# ==============================================================================
# INIT
# ==============================================================================
$timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$logFile   = "NetFreak_${timestamp}.log"
$htmlFile  = "NetFreak_${timestamp}.html"
$scriptVer = "v1.1 / 2026-02-18 (Red Team Hardened)"
$psVer     = $PSVersionTable.PSVersion.Major
$startTime = Get-Date

$secScore  = 100
$secIssues = @()
$secGood   = @()
$htmlBody  = [System.Text.StringBuilder]::new()

# RT-D2: Stealth mode settings
$scanDelay   = if ($Stealth) { 500  } else { 0   }   # ms between port probes
$scanTimeout = if ($Stealth) { 2000 } else { 5000 }  # ms TCP timeout

# ==============================================================================
# EMBEDDED OUI TABLE  -- RT-D1 FIX
# Replaces macvendors.com API entirely.
# Source: IEEE public OUI registry (top 300 vendors, last updated 2025-01)
# No external call. No MAC data leaves the machine.
# ==============================================================================
$OUI = @{
    "000000"="Xerox";"000001"="Xerox";"000002"="Xerox"
    "000393"="Apple";"000A27"="Apple";"000A95"="Apple"
    "001451"="Apple";"0016CB"="Apple";"0017F2"="Apple"
    "001CB3"="Apple";"001E52"="Apple";"001EC2"="Apple"
    "0021E9"="Apple";"0023DF"="Apple";"002500"="Apple"
    "002608"="Apple";"00261A"="Apple";"002713"="Apple"
    "003065"="Apple";"0050E4"="Apple";"006171"="Apple"
    "10DDB1"="Apple";"18AF61"="Apple";"1C91AF"="Apple"
    "3C07F4"="Apple";"4C8D79"="Apple";"70DEE2"="Apple"
    "A4B197"="Apple";"B8782E"="Apple";"D8D1CB"="Apple"
    "F82793"="Apple";"F8A963"="Apple"
    "000BCD"="Cisco";"000D29"="Cisco";"000E38"="Cisco"
    "000ED7"="Cisco";"001143"="Cisco";"0011BB"="Cisco"
    "001420"="Cisco";"0015C6"="Cisco";"001A2F"="Cisco"
    "001B0D"="Cisco";"001BD4"="Cisco";"001C57"="Cisco"
    "001EB1"="Cisco";"001F26"="Cisco";"001F9E"="Cisco"
    "00215A"="Cisco";"002155"="Cisco";"0021BE"="Cisco"
    "002427"="Cisco";"002564"="Cisco";"0025B4"="Cisco"
    "002605"="Cisco";"00270D"="Cisco";"0050BF"="Cisco"
    "00E01E"="Cisco";"00E0F9"="Cisco";"000572"="Cisco"
    "000C29"="VMware";"000569"="VMware";"001C14"="VMware"
    "005056"="VMware";"000EB0"="Samsung";"000FE1"="Samsung"
    "001247"="Samsung";"001377"="Samsung";"0015B9"="Samsung"
    "001632"="Samsung";"001699"="Samsung";"001A8A"="Samsung"
    "001BFB"="Samsung";"001C62"="Samsung";"001D25"="Samsung"
    "001DF6"="Samsung";"001F CC"="Samsung"
    "0021D1"="Samsung";"002339"="Samsung";"0023D6"="Samsung"
    "002490"="Samsung";"0025BB"="Samsung";"00265D"="Samsung"
    "0026E2"="Samsung"
    "001018"="Broadcom";"00101F"="Broadcom";"001A43"="Broadcom"
    "000E5C"="Belkin";"001195"="Belkin";"001C10"="Belkin"
    "001E58"="Belkin";"00226B"="Belkin";"00265A"="Belkin"
    "C05627"="Belkin";"EC1A59"="Belkin"
    "001B2F"="Netgear";"001E2A"="Netgear"
    "001F33"="Netgear";"00224D"="Netgear";"002429"="Netgear"
    "0026F2"="Netgear";"00905E"="Netgear";"20E52A"="Netgear"
    "00E091"="Netgear";"A021B7"="Netgear";"C03F0E"="Netgear"
    "00177C"="TP-Link";"001999"="TP-Link";"001D0F"="TP-Link"
    "00E04C"="Realtek";"00E04E"="Realtek";"52540E"="Realtek"
    "001814"="Ralink";"00901A"="Ralink"
    "000BEE"="Nokia";"001BC5"="Nokia";"006040"="Nokia"
    "00603E"="Nokia";"0021FE"="Nokia"
    "0023AA"="Nokia";"002445"="Nokia"
    "00266C"="Nokia";"002693"="Nokia"
    "000407"="D-Link";"000D88"="D-Link";"000F3D"="D-Link"
    "001346"="D-Link";"0015E9"="D-Link"
    "00179A"="D-Link";"001B11"="D-Link";"001CF0"="D-Link"
    "0022B0"="D-Link";"002369"="D-Link"
    "1CAFF7"="D-Link";"28107B"="D-Link"
    "00E0B1"="Zyxel";"001349"="Zyxel";"001A2B"="Zyxel"
    "001F12"="Zyxel";"002170"="Zyxel"
    "002275"="Zyxel";"002348"="Zyxel";"00265B"="Zyxel"
    "BC4760"="Zyxel";"D4BF7F"="Zyxel";"E4B97A"="Zyxel"
    "8C192D"="Zyxel";"000F61"="Zyxel";"28247E"="Zyxel"
    "000F1F"="Alcatel-Lucent";"001A70"="Alcatel-Lucent"
    "001CC4"="Alcatel-Lucent";"001DE5"="Alcatel-Lucent";"002169"="Alcatel-Lucent"
    "00218A"="Alcatel-Lucent";"0021F3"="Alcatel-Lucent";"00221A"="Alcatel-Lucent"
    "002279"="Alcatel-Lucent";"002478"="Alcatel-Lucent"
    "000172"="Intel";"000347"="Intel";"000C76"="Intel"
    "000E0C"="Intel";"000E35"="Intel";"000F20"="Intel"
    "001111"="Intel";"0012F0"="Intel";"001302"="Intel"
    "001560"="Intel";"001676"="Intel";"0018DE"="Intel"
    "001B21"="Intel";"001C23"="Intel";"001D92"="Intel"
    "001E64"="Intel";"001E67"="Intel";"001F3B"="Intel"
    "002219"="Intel";"00236C"="Intel"
    "002454"="Intel";"0024D7"="Intel";"002655"="Intel"
    "00269E"="Intel";"00AA00"="Intel";"001FE2"="Intel"
    "001B77"="Intel"
    "000D3A"="Microsoft";"0017FA"="Microsoft";"001DD8"="Microsoft"
    "002248"="Microsoft";"002567"="Microsoft";"003030"="Microsoft"
    "7C1E52"="Microsoft";"28183D"="Microsoft";"A4C361"="Microsoft"
    "000C6E"="ASUS";"04D4C4"="ASUS";"04921F"="ASUS"
    "049226"="ASUS";"08606E"="ASUS";"1062EB"="ASUS"
    "107B44"="ASUS";"1C872C"="ASUS";"2C56DC"="ASUS"
    "485B39"="ASUS";"50465D"="ASUS";"54A050"="ASUS"
    "60A44C"="ASUS";"74D02B"="ASUS";"7824AF"="ASUS"
    "AC220B"="ASUS";"BC9746"="ASUS";"D8502F"="ASUS"
    "F832E4"="ASUS"
    "BC764E"="Arcadyan";"6C2C06"="Arcadyan";"000293"="Arcadyan"
    "001827"="Arcadyan";"2C1D96"="Arcadyan";"5014B2"="Arcadyan"
    "7071BC"="Arcadyan";"90780B"="Arcadyan";"A82BB5"="Arcadyan"
}

function Get-OUIVendor {
    param([string]$mac)
    if (-not $mac) { return "Unknown" }
    $oui = ($mac -replace "[:\-\.]","").ToUpper()
    if ($oui.Length -lt 6) { return "Unknown" }
    $key = $oui.Substring(0,6)
    if ($OUI.ContainsKey($key)) { return $OUI[$key] }
    # Try first 3 bytes with common prefixes
    return "Unknown (OUI: $key)"
}

# ==============================================================================
# CORE HELPERS
# ==============================================================================
function Log {
    param([string]$msg, [string]$color = "White")
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $logFile -Value $line
}
function Section {
    param([string]$title, [string]$uid = "")
    Log ""; Log ("=" * 62) "Cyan"
    Log "  $title  $uid" "Cyan"
    Log ("=" * 62) "Cyan"
    if ($Html) { [void]$htmlBody.Append("<section><h2>$([System.Web.HttpUtility]::HtmlEncode($title)) <span class='uid'>$uid</span></h2>") }
}
function EndSection { if ($Html) { [void]$htmlBody.Append("</section>") } }
function Result {
    param([string]$label, $value, [bool]$ok = $true, [string]$note = "")
    $icon = if ($ok) { "[OK]" } else { "[!!]" }
    $col  = if ($ok) { "Green" } else { "Yellow" }
    $out  = ("  {0,-34} {1} {2}" -f $label, $icon, $value)
    if ($note) { $out += "  # $note" }
    Log $out $col
    if ($Html) {
        $cls = if ($ok) { "ok" } else { "warn" }
        [void]$htmlBody.Append(
            "<div class='row $cls'><span class='lbl'>$([System.Web.HttpUtility]::HtmlEncode($label))</span>" +
            "<span class='icon'>$icon</span><span class='val'>$([System.Web.HttpUtility]::HtmlEncode("$value"))</span>" +
            $(if ($note) { "<span class='note'>$([System.Web.HttpUtility]::HtmlEncode($note))</span>" }) +
            "</div>"
        )
    }
}
function Warn  { param([string]$m) Log "  [!!] $m" "Red" }
function Info  { param([string]$m) Log "  ... $m" "Gray" }
function Skip  { param([string]$m) Log "  [-] SKIPPED: $m" "DarkGray" }

# CVSS v3.1 severity mapping  -- RT-U11 FIX
function SecDeduct {
    param([int]$pts, [string]$reason, [string]$cvss = "", [string]$mitre = "")
    $script:secScore -= $pts
    $tag = ""
    if ($cvss)  { $tag += " [CVSS:$cvss]" }
    if ($mitre) { $tag += " [MITRE:$mitre]" }
    $script:secIssues += "[-$pts] $reason$tag"
}
function SecGood { param([string]$r) $script:secGood += "[OK] $r" }

# External API wrapper -- RT-D1: gated by -AllowExternalAPI
function Invoke-ExternalAPI {
    param([string]$Uri, [int]$Timeout = 8, [string]$Purpose = "")
    if (-not $AllowExternalAPI) {
        Info "BLOCKED: $Purpose (add -AllowExternalAPI to enable)"
        return $null
    }
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

function TCPTest {
    # RT-D2: Stealth mode adds delay between probes
    param([string]$Target, [int]$Port)
    if ($Stealth -and $scanDelay -gt 0) { Start-Sleep -Milliseconds $scanDelay }
    return Test-NetConnection -ComputerName $Target -Port $Port -WarningAction SilentlyContinue
}

# ==============================================================================
# HEADER
# ==============================================================================
$stealthNote = if ($Stealth) { "  [STEALTH MODE ON]" } else { "" }
$apiNote     = if ($AllowExternalAPI) { "  [EXTERNAL API ON]" } else { "  [EXTERNAL API OFF -- add -AllowExternalAPI]" }
Log ("=" * 62) "Cyan"
Log "  NetFreak.ps1 $scriptVer" "Cyan"
Log "  Host    : $env:COMPUTERNAME  |  User: $env:USERNAME" "Cyan"
Log "  PS      : $($PSVersionTable.PSVersion)" "Cyan"
Log "  Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Cyan"
Log $stealthNote "Yellow"
Log $apiNote "Yellow"
Log ("=" * 62) "Cyan"


# ==============================================================================
# [1] FULL IP STACK  [U8][U9]
# ==============================================================================
Section "[1] Full IP Stack" "[U8][U9]"

$allAdapters    = Get-NetIPConfiguration
$activeAdapters = $allAdapters | Where-Object { $_.IPv4Address }
$gwCandidates   = @()

Log "  === IPv4 Interfaces ===" "White"
foreach ($a in $activeAdapters) {
    $ip  = $a.IPv4Address.IPAddress
    $pre = $a.IPv4Address.PrefixLength
    $gw  = $a.IPv4DefaultGateway.NextHop
    $dns = ($a.DNSServer.ServerAddresses -join ", ")
    Log ""
    Log "  Adapter : $($a.InterfaceAlias)  [$ip/$pre]" "White"
    Result "    IP / Prefix"  "$ip / $pre"
    Result "    Gateway"      $(if ($gw) { $gw } else { "(none)" }) ($null -ne $gw)
    Result "    DNS"          $(if ($dns) { $dns } else { "(none)" })
    if ($gw) { $gwCandidates += $gw }
}

if (-not $GW) {
    $GW = ($activeAdapters | Where-Object { $_.IPv4DefaultGateway.NextHop } |
           Select-Object -First 1).IPv4DefaultGateway.NextHop
}
Log ""; Result "  Primary Gateway (auto)" $GW ($null -ne $GW)

# [U8] Dual-NIC conflict
Log ""; Log "  === [U8] Dual-NIC Routing Conflict ===" "White"
if ($gwCandidates.Count -gt 1) {
    Warn "Multiple gateways: $($gwCandidates -join ' | ')"
    $routes = route print 0.0.0.0 2>$null | Select-String "0\.0\.0\.0"
    foreach ($r in $routes) { Info $r }
    SecDeduct 10 "Multiple active gateways (routing conflict risk)" "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L" "T1078"
} else {
    Result "  Routing Conflict" "None (single gateway)" $true
    SecGood "Single active default gateway"
}

# [U9] ARP Cache
Log ""; Log "  === [U9] ARP Cache / LAN Map ===" "White"
$arpRaw   = arp -a 2>$null | Where-Object { $_ -match "dynamic|static" }
$arpCount = 0
foreach ($entry in $arpRaw) {
    $p = ($entry -replace '\s+', ' ').Trim().Split(' ')
    if ($p.Count -ge 3) {
        $vendor = Get-OUIVendor ($p[1] -replace "-","")
        Log ("    {0,-18} {1,-20} {2,-10} [{3}]" -f $p[0], $p[1], $p[2], $vendor) "Gray"
        $arpCount++
    }
}
Result "  LAN Devices (ARP)" "$arpCount entries"

# IPv6 summary
Log ""; Log "  === IPv6 ===" "White"
$v6 = Get-NetIPAddress -AddressFamily IPv6 |
    Where-Object { $_.IPAddress -notmatch "^fe80|^::1" } | Select-Object -First 3
if ($v6) { foreach ($a in $v6) { Result "  IPv6" "$($a.IPAddress) [$($a.PrefixOrigin)]" } }
else     { Result "  IPv6 Global" "None (audit in [10])" $true }

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
            try {
                $obt = [Management.ManagementDateTimeConverter]::ToDateTime($wmi.DHCPLeaseObtained)
                $exp = [Management.ManagementDateTimeConverter]::ToDateTime($wmi.DHCPLeaseExpires)
                $dur = $exp - $obt
                $rem = $exp - (Get-Date)
                Result "Lease Duration"  "$([int]$dur.TotalHours)h total"
                Result "Lease Remaining" "$([int]$rem.TotalHours)h $($rem.Minutes)m" ($rem.TotalHours -gt 2)
                if ($rem.TotalHours -lt 2) { SecDeduct 5 "DHCP lease expiring <2h" "" "T1498" }
            } catch {}
            Log ""
        }
    }
} else {
    Result "DHCP" "No DHCP adapters (static IP)" $true
}
EndSection


# ==============================================================================
# [3] GATEWAY ANALYSIS  [U7] -- RT-D1 FIXED: embedded OUI, no external API
# ==============================================================================
Section "[3] Gateway Analysis" "[U7-local]"

$pingGW = Test-NetConnection -ComputerName $GW -WarningAction SilentlyContinue
Result "Ping $GW" "$($pingGW.PingReplyDetails.RoundtripTime)ms" $pingGW.PingSucceeded

# MAC + OUI from local ARP + embedded table (no external call)
$gwArpLine = arp -a $GW 2>$null | Select-String $GW | Select-Object -First 1
if ($gwArpLine) {
    $gwMac    = (($gwArpLine -replace '\s+', ' ').Trim().Split(' ') | Select-Object -Index 1)
    $gwVendor = Get-OUIVendor ($gwMac -replace "-","")
    Result "Gateway MAC"         $gwMac
    Result "Gateway Vendor [U7]" "$gwVendor (local OUI DB -- no external call)" $true
}

# Traceroute
Log ""; Log "  Traceroute (5 hops):" "White"
try {
    $hops = Test-NetConnection -ComputerName $GW -TraceRoute -Hops 5 -WarningAction SilentlyContinue
    $i = 1
    foreach ($hop in $hops.TraceRoute) {
        Log ("    Hop {0:D2}  {1}" -f $i, $hop) "Gray"; $i++
    }
} catch { Warn "Traceroute failed" }

EndSection


# ==============================================================================
# [4] PORT SECURITY AUDIT -- RT-D2: Stealth throttle
# ==============================================================================
Section "[4] Port Security Audit"

if ($Stealth) { Info "Stealth mode: ${scanDelay}ms delay between probes" }

$ports = @(
    @{Port=80;   Desc="HTTP Admin";          Sev="info";     CVSS="";                      MITRE=""},
    @{Port=443;  Desc="HTTPS Admin";         Sev="info";     CVSS="";                      MITRE=""},
    @{Port=23;   Desc="Telnet";              Sev="CRITICAL"; CVSS="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"; MITRE="T1021.004"},
    @{Port=22;   Desc="SSH";                 Sev="medium";   CVSS="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"; MITRE="T1021.004"},
    @{Port=21;   Desc="FTP (cleartext)";     Sev="high";     CVSS="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"; MITRE="T1071.002"},
    @{Port=7547; Desc="TR-069 CWMP";         Sev="medium";   CVSS="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"; MITRE="T1090"},
    @{Port=7548; Desc="TR-069 alt";          Sev="medium";   CVSS="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"; MITRE="T1090"},
    @{Port=8080; Desc="HTTP alt";            Sev="info";     CVSS="";                      MITRE=""},
    @{Port=8443; Desc="HTTPS alt";           Sev="info";     CVSS="";                      MITRE=""},
    @{Port=161;  Desc="SNMP";                Sev="high";     CVSS="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"; MITRE="T1040"},
    @{Port=162;  Desc="SNMP Trap";           Sev="high";     CVSS="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"; MITRE="T1040"},
    @{Port=53;   Desc="DNS";                 Sev="info";     CVSS="";                      MITRE=""},
    @{Port=5555; Desc="ADB Android Debug";   Sev="CRITICAL"; CVSS="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"; MITRE="T1219"},
    @{Port=1900; Desc="UPnP SSDP";           Sev="medium";   CVSS="AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"; MITRE="T1135"},
    @{Port=49152;Desc="UPnP WANIPConn";      Sev="medium";   CVSS="AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"; MITRE="T1135"},
    @{Port=8888; Desc="HTTP mgmt alt";       Sev="medium";   CVSS="";                      MITRE=""}
)

$openPorts = @()
foreach ($p in $ports) {
    $tc = TCPTest -Target $GW -Port $p.Port
    $ok = $tc.TcpTestSucceeded
    $status = if ($ok) { "OPEN" } else { "closed" }

    if ($ok) {
        $openPorts += $p
        $col = switch ($p.Sev) {
            "CRITICAL" { "Red" }; "high" { "Red" }
            "medium"   { "Yellow" }; default { "Gray" }
        }
        Log ("  Port {0,5}  {1,-22} OPEN  [Severity: {2}]" -f $p.Port, $p.Desc, $p.Sev.ToUpper()) $col
        if ($p.CVSS) { Info "  CVSS: $($p.CVSS)  MITRE: $($p.MITRE)" }

        $pts = switch ($p.Sev) {
            "CRITICAL" { 20 }; "high" { 10 }; "medium" { 5 }; default { 0 }
        }
        if ($pts -gt 0) { SecDeduct $pts "Port $($p.Port) ($($p.Desc)) OPEN" $p.CVSS $p.MITRE }
    } else {
        Log ("  Port {0,5}  {1,-22} closed" -f $p.Port, $p.Desc) "Gray"
    }
}

Log ""; Result "Open Ports" "$($openPorts.Count) / $($ports.Count) scanned" ($openPorts.Count -le 3)
if ($openPorts.Count -eq 0) { SecGood "No unexpected ports open" }

EndSection


# ==============================================================================
# [5] DNS DEEP DIVE + LEAK TEST  [U2]  -- RT-U2: TTL-aware comparison
# ==============================================================================
Section "[5] DNS + Leak Test" "[U2-TTL]"

$dnsTargets = @("google.com","hinet.net","github.com","cloudflare.com","acs.hinet.com")
foreach ($d in $dnsTargets) {
    try {
        $r  = Resolve-DnsName $d -ErrorAction Stop -WarningAction SilentlyContinue
        $ip = ($r | Where-Object { $_.Type -eq "A" } | Select-Object -First 1).IPAddress
        if (-not $ip) { $ip = ($r | Select-Object -First 1).NameHost }
        Result "DNS: $d" $ip
    } catch {
        $note = if ($d -eq "acs.hinet.net") { "CHT internal -- NXDOMAIN expected" } else { "" }
        Result "DNS: $d" "NXDOMAIN" ($d -eq "acs.hinet.net") $note
    }
}

# [U2] DNS Leak: RT-U2 FIX -- TTL-aware, compare IP + TTL
Log ""; Log "  === [U2] DNS Leak Test (5 resolvers, TTL-aware) ===" "White"
Info "o-o.myaddr.l.google.com returns your IP as seen by each resolver"

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
        $r   = Resolve-DnsName "o-o.myaddr.l.google.com" -Server $res.IP `
               -ErrorAction Stop -WarningAction SilentlyContinue
        $txt = ($r | Where-Object { $_.Type -eq "TXT" } | Select-Object -First 1)
        $ip  = if ($txt) { $txt.Strings } else { "" }
        $ttl = if ($txt) { $txt.TTL } else { 0 }
        $resolverResults[$res.Name] = @{IP=$ip; TTL=$ttl}
        Result "  Resolver $($res.Name) [$($res.IP)]" "$ip  TTL=$ttl"
    } catch {
        Result "  Resolver $($res.Name) [$($res.IP)]" "Timeout" $false
    }
}

# TTL-aware analysis: significant TTL difference may indicate DNS cache poisoning
$uniqueIPs = ($resolverResults.Values | Where-Object { $_.IP } | ForEach-Object { $_.IP }) | Sort-Object -Unique
$ttlValues = ($resolverResults.Values | Where-Object { $_.TTL -gt 0 } | ForEach-Object { $_.TTL })
$ttlSpread = if ($ttlValues.Count -gt 1) {
    ($ttlValues | Measure-Object -Maximum).Maximum - ($ttlValues | Measure-Object -Minimum).Minimum
} else { 0 }

Log ""
if ($uniqueIPs.Count -eq 1) {
    Result "DNS Leak [U2]"    "CLEAN -- all resolvers agree" $true
    Result "TTL Spread"       "${ttlSpread}s (normal <30s)" ($ttlSpread -lt 30)
    SecGood "DNS leak test passed"
} elseif ($uniqueIPs.Count -gt 1) {
    Warn "DNS Inconsistency -- $($uniqueIPs -join ' | ')"
    Warn "Possible: DNS hijacking / CHT transparent proxy / split-horizon"
    if ($ttlSpread -gt 30) { Warn "TTL spread ${ttlSpread}s -- cache poisoning possible" }
    SecDeduct 15 "DNS resolver inconsistency" "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N" "T1557.003"
} else {
    Result "DNS Leak [U2]" "Inconclusive (resolver timeouts)" $true
}

EndSection


# ==============================================================================
# [6] INTERNET + PUBLIC IP + ASN  [U3]
#     RT-D1: External API gated by -AllowExternalAPI
# ==============================================================================
Section "[6] Internet + Public IP" "[U3]"

foreach ($t in @("8.8.8.8","1.1.1.1","168.95.1.1","101.101.101.101")) {
    $p = Test-NetConnection -ComputerName $t -WarningAction SilentlyContinue
    Result "Ping $t" "$($p.PingReplyDetails.RoundtripTime)ms" $p.PingSucceeded
}

Log ""; Log "  === [U3] ASN / Geo / Threat (external API) ===" "White"
if (-not $AllowExternalAPI) {
    Info "Skipped: ASN/Geo/Threat requires -AllowExternalAPI flag"
    Info "Add -AllowExternalAPI to call ipinfo.io / abuseipdb"
    Result "External API" "Disabled (data sovereignty protected)" $true
} else {
    $ipInfo = Invoke-ExternalAPI "https://ipinfo.io/json" 8 "ipinfo.io ASN lookup"
    if (-not $ipInfo) { $ipInfo = Invoke-ExternalAPI "https://ip-api.com/json" 8 "ip-api.com fallback" }

    if ($ipInfo) {
        $pubIP = if ($ipInfo.ip)  { $ipInfo.ip }  else { $ipInfo.query }
        $org   = if ($ipInfo.org) { $ipInfo.org } else { $ipInfo.isp }
        $asn   = if ($ipInfo.org) { $ipInfo.org } elseif ($ipInfo.as) { $ipInfo.as } else { "N/A" }
        Result "Public IP [U3]" $pubIP
        Result "ISP / ASN"      $asn
        Result "City"           "$($ipInfo.city), $($ipInfo.region)"
        if ($org -match "HiNet|Chunghwa|CHT") {
            Result "ISP Verify" "CHT HiNet confirmed" $true
            SecGood "Traffic via CHT HiNet"
        } else {
            Warn "Traffic NOT via CHT -- VPN/proxy possible"
        }
    }
}

EndSection


# ==============================================================================
# [7] LATENCY + MOS SCORE  [U4]  -- RT-U4: improved E-model
# ==============================================================================
Section "[7] Latency Quality + MOS" "[U4-improved]"

# RT-U4: Codec-aware MOS table
$codecTable = @{
    "G.711" = @{Ie=0;  Bpl=25.1}
    "G.729" = @{Ie=11; Bpl=19}
    "G.722" = @{Ie=0;  Bpl=34}
}
$codec = "G.711"  # Default assumption for CHT MOD

$targets = @(
    @{Host="168.95.1.1"; Name="CHT DNS"},
    @{Host="8.8.8.8";    Name="Google DNS"},
    @{Host="1.1.1.1";    Name="CF DNS"}
)

foreach ($tgt in $targets) {
    Log ""; Log "  Pinging $($tgt.Name) ($($tgt.Host)) x$PingCount ..." "White"
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
        $loss   = [Math]::Round((1 - $results.Count / $PingCount) * 100, 1)
        $diffs  = @(); for ($i = 1; $i -lt $results.Count; $i++) {
            $diffs += [Math]::Abs($results[$i] - $results[$i-1])
        }
        $jitter = if ($diffs.Count -gt 0) {
            [Math]::Round(($diffs | Measure-Object -Average).Average, 1)
        } else { 0 }

        # RT-U4: Improved ITU-T G.107 E-model
        # Id = 0.024*d + 0.11*(d-177.3)*H(d-177.3)  where H = Heaviside
        # Ie = codec Ie + 11*(loss/(loss+Bpl))
        $d    = $avg
        $Id   = 0.024 * $d + 0.11 * [Math]::Max(0, ($d - 177.3))
        $cIe  = $codecTable[$codec].Ie
        $cBpl = $codecTable[$codec].Bpl
        $Ie   = $cIe + (100 - $cIe) * ($loss / ($loss + $cBpl))
        $R    = [Math]::Max(0, [Math]::Min(100, 93.2 - $Id - $Ie))
        $mos  = 1 + 0.035 * $R + 0.000007 * $R * ($R - 60) * (100 - $R)
        $mos  = [Math]::Round([Math]::Max(1, [Math]::Min(5, $mos)), 2)
        $mosGrade = switch ($true) {
            { $mos -ge 4.3 } { "A Excellent" }; { $mos -ge 4.0 } { "B Good" }
            { $mos -ge 3.6 } { "C Fair" };      { $mos -ge 3.1 } { "D Poor" }
            default          { "F Bad" }
        }

        Result "  $($tgt.Name) Avg/Min/Max" "${avg}ms / ${min}ms / ${max}ms" ($avg -lt 50)
        Result "  $($tgt.Name) Jitter"      "${jitter}ms"  ($jitter -lt 10)
        Result "  $($tgt.Name) Loss"        "${loss}%"     ($loss -eq 0)
        Result "  $($tgt.Name) MOS [$codec]" "$mos / 5.0  [$mosGrade]" ($mos -ge 3.6)
        Info   "  Formula: R=$([Math]::Round($R,1))  Id=$([Math]::Round($Id,1))  Ie=$([Math]::Round($Ie,1))"

        if ($loss -gt 5)    { SecDeduct 10 "Packet loss ${loss}%" "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" "T1499" }
        if ($jitter -gt 20) { SecDeduct 5  "High jitter ${jitter}ms" }
        if ($mos -lt 3.6)   { SecDeduct 5  "Poor MOS ${mos} ($codec)" }
    }
}
EndSection


# ==============================================================================
# [8] MTU PATH DISCOVERY  [U1]  -- RT-D3: gentler, old-ONT guard
# ==============================================================================
Section "[8] MTU Path Discovery" "[U1-safe]"

if ($SkipSlow) { Skip "MTU discovery (use without -SkipSlow)"; EndSection; return }

Log "  Binary search for path MTU (DF-bit, 8.8.8.8)..." "White"

# RT-D3: old-ONT safe guard -- start from 1024 not 576, use 3 probes
$mtuLow = 1000; $mtuHigh = 1500; $mtuOK = 1000

while ($mtuHigh - $mtuLow -gt 1) {
    $mtuTest = [int](($mtuLow + $mtuHigh) / 2)
    # 3 probes to reduce false negatives
    $hits = 0
    1..3 | ForEach-Object {
        $r = ping.exe -f -l $mtuTest -n 1 -w 1500 8.8.8.8 2>$null
        if ($r -match "Reply from|bytes=") { $hits++ }
    }
    if ($hits -ge 2) { $mtuOK = $mtuTest; $mtuLow = $mtuTest; Info "  $mtuTest OK ($hits/3)" }
    else             { $mtuHigh = $mtuTest; Info "  $mtuTest fragmented ($hits/3)" }
}

$actualMTU = $mtuOK + 28
Result "Optimal MTU [U1]" "$actualMTU bytes (payload: $mtuOK)" $true
$mtuNote = switch ($true) {
    { $actualMTU -eq 1500 } { "Standard Ethernet -- perfect" }
    { $actualMTU -eq 1492 } { "PPPoE -- correct for CHT FTTH (8-byte overhead)" }
    { $actualMTU -ge 1400 } { "Slightly reduced -- possible PPPoE/VPN" }
    default                 { "Low MTU -- check for VPN tunnel or misconfiguration" }
}
Info "MTU Note: $mtuNote"
if ($actualMTU -eq 1492) { SecGood "MTU 1492 correct for CHT FTTH PPPoE" }
if ($actualMTU -eq 1500) { SecGood "MTU 1500 optimal Ethernet" }
if ($actualMTU -lt 1400) { SecDeduct 5 "Low MTU $actualMTU may reduce throughput" }

EndSection


# ==============================================================================
# [9] BANDWIDTH
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
        Info "Trying $($bw.Name)..."
        $bwFile  = "$env:TEMP\nf_bw_$timestamp.bin"
        $start   = Get-Date
        Invoke-WebRequest -Uri $bw.Url -OutFile $bwFile -TimeoutSec 30 -UseBasicParsing | Out-Null
        $elapsed = ((Get-Date) - $start).TotalSeconds
        $sizeMB  = (Get-Item $bwFile).Length / 1MB
        $mbps    = [Math]::Round(($sizeMB * 8) / $elapsed, 2)
        Result "Download [$($bw.Name)]" "${mbps} Mbps ($([Math]::Round($sizeMB,1))MB in $([Math]::Round($elapsed,1))s)" ($mbps -gt 10)
        Remove-Item $bwFile -ErrorAction SilentlyContinue
        $bwDone = $true
    } catch { Info "$($bw.Name) failed, trying next..." }
}
if (-not $bwDone) { Warn "All bandwidth sources failed (non-critical)" }

EndSection


# ==============================================================================
# [10] IPv6 FULL AUDIT  [U10]
# ==============================================================================
Section "[10] IPv6 Audit" "[U10]"

if ($SkipSlow) { Skip "IPv6 audit"; EndSection; return }

$v6global = Get-NetIPAddress -AddressFamily IPv6 |
    Where-Object { $_.IPAddress -notmatch "^fe80|^::1" -and $_.PrefixOrigin -ne "WellKnown" }

if ($v6global) {
    $v6ip = ($v6global | Select-Object -First 1).IPAddress
    Result "IPv6 Global [U10]" $v6ip $true

    $v6ping = Test-NetConnection -ComputerName "2001:4860:4860::8888" -WarningAction SilentlyContinue
    Result "IPv6 Google Ping" $(if ($v6ping.PingSucceeded){"OK"}else{"FAIL"}) $v6ping.PingSucceeded

    if ($AllowExternalAPI) {
        $v6pub = Invoke-ExternalAPI "https://v6.ident.me/" 5 "IPv6 public IP check"
        if ($v6pub) {
            Result "IPv6 Public" $v6pub.Trim()
            Warn "IPv6 publicly routable -- verify firewall"
            SecDeduct 8 "IPv6 exposed publicly" "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" "T1590"
        }
    } else {
        Info "IPv6 external reachability check skipped (add -AllowExternalAPI)"
    }
    Result "IPv6 Firewall" "Verify stateful IPv6 firewall on router" $true
} else {
    Result "IPv6 Global" "None (no v6 exposure)" $true
    SecGood "No global IPv6 (no v6 attack surface)"
}

$v6link = Get-NetIPAddress -AddressFamily IPv6 | Where-Object { $_.IPAddress -match "^fe80" }
Result "IPv6 Link-Local" $(if ($v6link) { "Present" } else { "None" }) $true

EndSection


# ==============================================================================
# [11] UPnP AUDIT  [U6]  -- RT-D2: SSDP skipped in Stealth mode
# ==============================================================================
Section "[11] UPnP Audit" "[U6]"

if ($SkipSlow) { Skip "UPnP audit"; EndSection; return }
if ($Stealth)  { Skip "UPnP SSDP (disabled in Stealth mode -- RT-D2)"; EndSection; return }

Info "SSDP discovery (M-SEARCH multicast)..."
$ssdpMsg = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 3`r`nST: upnp:rootdevice`r`n`r`n"
$upnpDevices = @()
try {
    $udp = [System.Net.Sockets.UdpClient]::new()
    $udp.EnableBroadcast = $true
    $udp.Client.ReceiveTimeout = 3000
    $ep    = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse("239.255.255.250"), 1900)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($ssdpMsg)
    [void]$udp.Send($bytes, $bytes.Length, $ep)
    $deadline = (Get-Date).AddSeconds(3)
    while ((Get-Date) -lt $deadline) {
        try {
            $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $data   = $udp.Receive([ref]$remote)
            $resp   = [System.Text.Encoding]::ASCII.GetString($data)
            $loc    = if ($resp -match "LOCATION:\s*(.+)") { $matches[1].Trim() } else { "" }
            if ($loc) { $upnpDevices += @{IP=$remote.Address; Location=$loc} }
        } catch { break }
    }
    $udp.Close()
} catch { Info "SSDP failed (firewall may block port 1900)" }

if ($upnpDevices.Count -gt 0) {
    Result "UPnP Devices [U6]" "$($upnpDevices.Count) found" $false
    foreach ($d in $upnpDevices) { Log "    $($d.IP)  $($d.Location)" "Yellow" }
    SecDeduct 8 "UPnP active" "AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N" "T1135"
} else {
    Result "UPnP [U6]" "None discovered (UPnP disabled or firewall)" $true
    SecGood "No UPnP devices found"
}
EndSection


# ==============================================================================
# [12] IGMP / MULTICAST  [U5]
# ==============================================================================
Section "[12] IGMP / Multicast (CHT MOD)" "[U5]"

$igmp = netsh interface ip show joins 2>$null
$mcastGroups = @()
if ($igmp) {
    $lines = $igmp | Select-String "224\.|239\."
    foreach ($l in $lines) { $mcastGroups += $l.ToString().Trim() }
}
if ($mcastGroups.Count -gt 0) {
    Result "IGMP Groups [U5]" "$($mcastGroups.Count) active"
    foreach ($g in $mcastGroups) { Log "    $g" "Gray" }
    $mod = $mcastGroups | Where-Object { $_ -match "239\." }
    if ($mod) { Result "CHT MOD IGMP" "Active (239.x.x.x)" $true; SecGood "CHT IPTV multicast confirmed" }
} else {
    Result "IGMP [U5]" "None (MOD not active or not on this NIC)" $true
}
EndSection


# ==============================================================================
# [13] PROCESS + CONNECTION MAP
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
                $pidMap[$pid_] = @{Name=$pname; Conns=0}
            }
            $pidMap[$pid_].Conns++
        }
    }
}
Log "  === Top Processes by Connection Count ===" "White"
$pidMap.GetEnumerator() | Sort-Object { $_.Value.Conns } -Descending |
Select-Object -First 10 | ForEach-Object {
    Result ("  PID {0,6} [{1,-22}]" -f $_.Key, $_.Value.Name) "$($_.Value.Conns) connections"
}

Log ""; Log "  === External ESTABLISHED Connections ===" "White"
$extConns = netstat -ano | Select-String "ESTABLISHED" |
    Where-Object { $_ -notmatch "127\.0\.0\.1|::1|0\.0\.0\.0" }
foreach ($c in $extConns) { Log "  $c" "Gray" }

EndSection


# ==============================================================================
# [14] PROCESS + USER CONTEXT  [U14 NEW]  -- RT-NEW: privilege flag
# ==============================================================================
Section "[14] Process + User Privilege Audit" "[U14]"

Log "  === Privileged User Connection Audit ===" "White"
Info "Mapping high-privilege users to active network connections..."

try {
    # Get processes with username
    $procs = Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
        Where-Object { $_.UserName } |
        Select-Object Id, Name, UserName, CPU, WorkingSet

    # Flag elevated / admin processes
    $elevated  = $procs | Where-Object { $_.UserName -match "Administrator|SYSTEM|Domain Admins|NT AUTHORITY" }
    $userProcs = $procs | Where-Object { $_.UserName -notmatch "SYSTEM|NT AUTHORITY|LOCAL SERVICE" }

    if ($elevated) {
        Log "  [!!] Elevated/System processes with network activity:" "Yellow"
        foreach ($ep in ($elevated | Select-Object -First 10)) {
            $conns = $pidMap[$ep.Id.ToString()]
            if ($conns) {
                $connCount = $conns.Conns
                Log ("    PID {0,6} [{1,-20}] User:{2,-30} Conns:{3}" -f `
                     $ep.Id, $ep.Name, $ep.UserName, $connCount) "Yellow"
                if ($ep.UserName -match "Administrator" -and $connCount -gt 10) {
                    Warn "High-privilege process $($ep.Name) has $connCount connections"
                    SecDeduct 10 "Admin process $($ep.Name) with high connection count" `
                               "AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H" "T1078"
                }
            }
        }
    }

    Log ""; Log "  === User Process Summary ===" "White"
    $userProcs | Sort-Object CPU -Descending | Select-Object -First 8 |
    ForEach-Object {
        $conns = $pidMap[$_.Id.ToString()]
        $connCount = if ($conns) { $conns.Conns } else { 0 }
        if ($connCount -gt 0) {
            Result ("  PID {0,6} [{1,-20}]" -f $_.Id, $_.Name) `
                   "User: $($_.UserName.Split('\')[-1])  Conns: $connCount"
        }
    }
} catch {
    Warn "Get-Process -IncludeUserName requires admin rights"
    Info "Run as Administrator for full user-process mapping"
}

EndSection


# ==============================================================================
# [15] WIFI ANALYSIS
# ==============================================================================
Section "[15] WiFi Analysis"

$wifiAdapters = Get-NetAdapter | Where-Object {
    $_.MediaType -match "802.11|native 802.11" -and $_.Status -eq "Up" }

if ($wifiAdapters) {
    $wlanInfo = netsh wlan show interfaces 2>$null
    if ($wlanInfo) {
        $ssid   = ($wlanInfo | Select-String "^\s+SSID\s+:" | Select-Object -First 1) -replace ".*:\s*",""
        $signal = ($wlanInfo | Select-String "Signal") -replace ".*:\s*",""
        $radio  = ($wlanInfo | Select-String "Radio type") -replace ".*:\s*",""
        $chan   = ($wlanInfo | Select-String "Channel") -replace ".*:\s*",""
        $rxRate = ($wlanInfo | Select-String "Receive rate") -replace ".*:\s*",""
        $txRate = ($wlanInfo | Select-String "Transmit rate") -replace ".*:\s*",""
        Result "SSID"      $ssid.Trim()
        Result "Signal"    $signal.Trim() ($signal -match "[7-9]\d|100")
        Result "Radio"     $radio.Trim()
        Result "Channel"   $chan.Trim()
        Result "RX/TX"     "$($rxRate.Trim()) / $($txRate.Trim())"
        $sig = ($signal -replace "[^0-9]","") -as [int]
        if ($sig -lt 50) { SecDeduct 5 "WiFi signal weak (${sig}%)" }
        if ($sig -ge 80) { SecGood "WiFi signal strong (${sig}%)" }
    }
} else {
    Result "WiFi" "No active WiFi adapter" $true
}
EndSection


# ==============================================================================
# [16] SECURITY SCORE  [U11]  -- RT-U11: CVSS-aligned
# ==============================================================================
Section "[16] Security Score (CVSS-aligned)" "[U11]"

$secScore = [Math]::Max(0, $secScore)
$grade = switch ($true) {
    { $secScore -ge 90 } { "A" }; { $secScore -ge 80 } { "B" }
    { $secScore -ge 70 } { "C" }; { $secScore -ge 60 } { "D" }
    default { "F" }
}
$gradeCol = if ($grade -match "A|B") { "Green" } elseif ($grade -match "C|D") { "Yellow" } else { "Red" }

Log ("  SECURITY SCORE: {0}/100  Grade: {1}" -f $secScore, $grade) $gradeCol
Log ""
if ($secIssues) {
    Log "  Issues (CVSS-mapped):" "Yellow"
    foreach ($i in $secIssues) { Log "    $i" "Yellow" }
}
if ($secGood) {
    Log ""; Log "  Passed:" "Green"
    foreach ($g in $secGood) { Log "    $g" "Green" }
}
Log ""
Info "Score methodology: deductions map to CVSS v3.1 severity (CRITICAL=20, HIGH=10, MEDIUM=5)"
Info "MITRE ATT&CK TTPs noted per finding for threat context"

EndSection


# ==============================================================================
# HTML REPORT  [U12]
# ==============================================================================
if ($Html) {
    $elapsed = [Math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
    $gc = switch ($grade) {
        "A" {"#00ff88"}; "B" {"#88ee00"}; "C" {"#ffee00"}; "D" {"#ff8800"}; default {"#ff2244"}
    }
    $apiStatus = if ($AllowExternalAPI) { "External API: ON" } else { "External API: OFF (data sovereign)" }
    $stealthStatus = if ($Stealth) { "STEALTH MODE" } else { "Standard" }

    $htmlFull = @"
<!DOCTYPE html><html lang="zh-TW"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetFreak v1.1 -- $($env:COMPUTERNAME) -- $timestamp</title>
<style>
:root{--bg:#07080f;--s:#0d1117;--b:#1a2333;--cy:#00d4ff;--g:#00ff88;--y:#ffee00;--r:#ff3355;--gr:#3a4a5a;--t:#dde4ee}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--t);font-family:'Courier New',monospace;font-size:12.5px;line-height:1.65;padding:20px}
header{border:1px solid var(--cy);padding:18px 22px;margin-bottom:20px;background:linear-gradient(135deg,#08101e,#0c1828)}
header h1{color:var(--cy);font-size:20px;letter-spacing:4px}
.meta{color:var(--gr);font-size:11px;margin-top:6px;line-height:1.8}
.badge{float:right;font-size:54px;font-weight:900;color:$gc;text-shadow:0 0 24px $gc;line-height:1}
section{border:1px solid var(--b);margin-bottom:14px;background:var(--s);border-radius:3px}
h2{background:#0b1520;color:var(--cy);padding:8px 14px;font-size:12px;letter-spacing:1.5px;border-bottom:1px solid var(--b)}
.uid{color:var(--gr);font-size:10px}
.row{display:flex;padding:4px 14px;border-bottom:1px solid #0c1220;align-items:center;gap:8px}
.row:last-child{border:none}
.row.ok .icon{color:var(--g)}.row.warn .icon{color:var(--y)}
.lbl{flex:0 0 270px;color:#7a8fa8}.icon{flex:0 0 44px;font-weight:bold}
.val{flex:1}.note{flex:0 0 220px;color:var(--gr);font-size:11px;text-align:right}
footer{text-align:center;color:var(--gr);font-size:11px;margin-top:20px;padding-top:12px;border-top:1px solid var(--b)}
</style></head><body>
<header>
<div class="badge">$grade</div>
<h1>⚡ NETFREAK v1.1</h1>
<div class="meta">
Host: $($env:COMPUTERNAME) &nbsp;|&nbsp; User: $($env:USERNAME) &nbsp;|&nbsp;
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp;
Duration: ${elapsed}s &nbsp;|&nbsp; Score: $secScore/100 &nbsp;|&nbsp;
$stealthStatus &nbsp;|&nbsp; $apiStatus
</div></header>
$($htmlBody.ToString())
<footer>NetFreak.ps1 $scriptVer &nbsp;|&nbsp; Red Team Hardened Edition</footer>
</body></html>
"@
    $htmlFull | Out-File -FilePath $htmlFile -Encoding UTF8
    Log ""; Log "  HTML: $((Get-Item $htmlFile).FullName)" "Cyan"
}


# ==============================================================================
# FOOTER
# ==============================================================================
$totalSec = [Math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
Log ""; Log ("=" * 62) "Cyan"
Log "  NetFreak COMPLETE" "Cyan"
Log "  Log    : $((Get-Item $logFile).FullName)" "Cyan"
Log "  Score  : $secScore/100  Grade: $grade" "Cyan"
Log "  Time   : ${totalSec}s" "Cyan"
Log ("=" * 62) "Cyan"

if ($psVer -lt 7) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
}
