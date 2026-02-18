# check_tr069.ps1 — 全方位網路診斷腳本

> **版本** v1.0 / 2026-02-18  
> **用途** 針對家用/SOHO網路環境（尤其 CHT FTTH + ONT）的一鍵全面診斷，結果同步輸出至 `.log` 檔。

---

## 目錄

1. [需求背景](#1-需求背景)
2. [適用環境](#2-適用環境)
3. [前置需求](#3-前置需求)
4. [使用方法](#4-使用方法)
5. [輸出說明](#5-輸出說明)
6. [各區段功能說明](#6-各區段功能說明)
7. [程式碼逐行解說](#7-程式碼逐行解說)
8. [常見問題 FAQ](#8-常見問題-faq)
9. [注意事項](#9-注意事項)

---

## 1. 需求背景

本腳本源自中華電信 FTTH 光纖設備（Nokia G-040G-Q ONT）更換後的網路重建需求，涵蓋以下驗收場景：

- 中華電信工程師到府後的設備驗收確認
- TR-069 / CWMP 遠端管理通道是否正常
- DHCP / DNS / Gateway 基本連線是否正確
- 開放 Port 資安檢查（Telnet 是否意外開啟）
- 網路延遲品質（Jitter / 封包遺失）量化
- 公網 IP 確認 / 頻寬粗估

---

## 2. 適用環境

| 項目 | 需求 |
|------|------|
| 作業系統 | Windows 10 / Windows 11 |
| PowerShell 版本 | **PS 5.1**（內建）可用；**PS 7+** 完整支援（含 `-SkipCertificateCheck`） |
| 網路角色 | 有線或無線連線至目標 IP（ONT / Router / Switch 皆可） |
| 權限 | **系統管理員（Administrator）**，部分 WMI 查詢需提權 |
| 網際網路 | 區段 7/8 需要對外連線；其餘區段僅需內網可達目標 IP |

> **典型目標 IP**：ONT 管理頁面（中華電信 G-040G-Q 預設 `192.168.1.1`，或改設後之 `192.168.0.254`）

---

## 3. 前置需求

### 3-1. 執行原則解鎖（擇一）

Windows 預設封鎖未簽署的 `.ps1`，需先解除：

```powershell
# 方法 A：單次執行（最安全，不改系統設定）
powershell -ExecutionPolicy Bypass -File "D:\check_tr069.ps1" 192.168.1.1

# 方法 B：解鎖目前使用者（永久，僅限當前帳號）
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

# 方法 C：移除檔案的 Zone 封鎖標記
Unblock-File -Path "D:\check_tr069.ps1"
```

### 3-2. 以系統管理員開啟 PowerShell

```
開始功能表 → 搜尋「PowerShell」→ 右鍵 → 以系統管理員執行
```

---

## 4. 使用方法

### 基本語法

```powershell
.\check_tr069.ps1 <目標IP>
```

### 範例

```powershell
# 目標為 ONT 預設 IP
.\check_tr069.ps1 192.168.1.1

# 目標為工程師改設後的 IP
.\check_tr069.ps1 192.168.0.254

# 搭配 Bypass 一次執行（建議方式）
powershell -ExecutionPolicy Bypass -File "D:\check_tr069.ps1" 192.168.0.254
```

### 參數說明

| 參數 | 型態 | 必填 | 說明 |
|------|------|------|------|
| `$TargetIP` | String | ✅ 是 | 要診斷的目標 IP（ONT / Router 管理頁 IP） |

---

## 5. 輸出說明

### 檔名格式

```
check_tr069_<TargetIP>_<yyyyMMdd_HHmm>.log
```

**範例：**
```
check_tr069_192.168.1.1_20260218_1423.log
```

Log 檔儲存於**執行 PowerShell 時的工作目錄**（通常與 `.ps1` 同一資料夾）。

### 輸出符號說明

| 符號 | 顏色 | 意義 |
|------|------|------|
| `[OK]` | 綠色 | 測試通過 / 正常 |
| `[!!]` | 黃色 | 警告 / 異常，需注意 |
| `WARNING` | 紅色 | 高風險（如 Telnet Port 開啟） |
| `[--]` | 黃色 | 未偵測到（非錯誤，如無 DHCP 介面） |

---

## 6. 各區段功能說明

| # | 區段名稱 | 主要功能 |
|---|----------|----------|
| 1 | **Local NIC / IP Info** | 列出所有 IPv4 介面的 IP、子網路遮罩、預設閘道、DNS |
| 2 | **DHCP Info** | 確認 DHCP 取得狀況、DHCP 伺服器位址、Lease 時間 |
| 3 | **Gateway / Target Ping + Traceroute** | Ping 目標 IP + 最多 10 跳 Traceroute |
| 4 | **DNS Resolution** | 解析 google.com / hinet.net / acs.hinet.net 等，並做反向 DNS 查詢 |
| 5 | **Port Scan** | 掃描目標 IP 的 10 個關鍵 Port（含 TR-069 / Telnet 資安警告） |
| 6 | **HTTP / HTTPS Response** | 測試 4 個管理頁 URL，回傳 HTTP 狀態碼與 Server header |
| 7 | **Internet + Public IP** | Ping 8.8.8.8 / 1.1.1.1 / 168.95.1.1，並取得公網 IP |
| 8 | **Latency Quality** | 連續 Ping 20 次計算 Jitter / 封包遺失，另含 CHT 1MB 頻寬粗估 |
| 9 | **TR-069 / ACS Verification** | 確認 7547 Port 狀態、列出對目標 IP 的 active 連線 |
| 10 | **Established TCP Connections** | 列出目前所有 ESTABLISHED 對外 TCP 連線 |

---

## 7. 程式碼逐行解說

### 區塊 0：檔頭與參數宣告（L1–L10）

```powershell
# L1-5：檔頭注解，說明腳本名稱、用法、輸出格式
# ============================================================
# check_tr069.ps1 -- Full Network Diagnostic Script
# Usage : .\check_tr069.ps1 192.168.1.1
# Output: check_tr069_192.168.1.1_20260218_1230.log
# ============================================================

# L7-10：宣告輸入參數
# param() 區塊讓腳本接受命令列參數
# Mandatory=$true  → 不輸入 IP 時 PS 會主動要求輸入
# Position=0       → 第一個位置參數，不需要加 -TargetIP 旗標
# [string]         → 型態宣告，確保傳入值為字串
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$TargetIP
)
```

---

### 區塊 1：初始化變數（L13–L15）

```powershell
# L13：取得當前時間，格式化為 yyyyMMdd_HHmm（例：20260218_1423）
$timestamp = Get-Date -Format "yyyyMMdd_HHmm"

# L14：組合 log 檔名，包含目標 IP 和時間戳記
# ${} 語法：在字串中安全插入變數，避免與後面文字混淆
$logFile   = "check_tr069_${TargetIP}_${timestamp}.log"

# L15：腳本版本字串，會顯示在 header
$scriptVer = "v1.0 / 2026-02-18"
```

---

### 區塊 2：三個輔助函數（L17–L38）

```powershell
# L17-22：Log 函數 — 同時輸出至螢幕和 log 檔
function Log {
    param([string]$msg, [string]$color = "White")  # color 預設白色
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg" # 加上時間戳前綴
    Write-Host $line -ForegroundColor $color         # 彩色輸出至螢幕
    Add-Content -Path $logFile -Value $line          # 附加寫入 log 檔
}

# L24-31：Section 函數 — 輸出 Cyan 色區段標題分隔線
function Section {
    param([string]$title)
    $bar = "=" * 60             # 60 個等號組成分隔線
    Log ""                       # 空行
    Log $bar "Cyan"              # 上分隔線
    Log "  $title" "Cyan"        # 區段標題
    Log $bar "Cyan"              # 下分隔線
}

# L33-38：Result 函數 — 格式化輸出單筆測試結果
function Result {
    param([string]$label, $value, [bool]$ok = $true)
    $icon = if ($ok) { "[OK]" } else { "[!!]" }   # 依狀態選圖示
    $col  = if ($ok) { "Green" } else { "Yellow" } # 依狀態選顏色
    # {0,-28}：label 欄位左對齊佔 28 字元，{1} icon，{2} value
    Log ("  {0,-28} {1} {2}" -f $label, $icon, $value) $col
}
```

---

### 區塊 3：Header 輸出（L41–L46）

```powershell
# 輸出診斷報告標頭，包含版本、目標IP、時間、主機名稱
Log ("=" * 60) "Cyan"
Log "  check_tr069.ps1 $scriptVer" "Cyan"
Log "  Target IP : $TargetIP" "Cyan"
Log "  Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Cyan"
Log "  Hostname  : $env:COMPUTERNAME" "Cyan"  # 環境變數取電腦名稱
Log ("=" * 60) "Cyan"
```

---

### 區段 [1]：NIC Info（L52–L62）

```powershell
Section "[1] Local NIC / IP Info"

# Get-NetIPConfiguration：取得所有網路介面設定
# Where-Object { $_.IPv4Address }：過濾掉無 IPv4 的介面（如 VPN 虛擬介面）
$adapters = Get-NetIPConfiguration | Where-Object { $_.IPv4Address }

foreach ($a in $adapters) {
    Log "  Adapter : $($a.InterfaceAlias)" "White"  # 介面名稱（如 Ethernet、Wi-Fi）
    Result "  Local IP"       $a.IPv4Address.IPAddress           # 本機 IP
    Result "  Prefix Length"  $a.IPv4Address.PrefixLength        # 子網路前綴長度（如 24）
    Result "  Default GW"     ($a.IPv4DefaultGateway.NextHop)    # 預設閘道 IP
    Result "  DNS Servers"    ($a.DNSServer.ServerAddresses -join ", ")  # DNS，多筆用逗號串接
    Log ""
}
```

---

### 區段 [2]：DHCP Info（L70–L87）

```powershell
# Get-NetIPAddress：取得 IP 位址物件
# PrefixOrigin -eq "Dhcp"：只保留由 DHCP 動態取得的 IP（排除靜態/手動）
$dhcpAdapters = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.PrefixOrigin -eq "Dhcp" }

if ($dhcpAdapters) {
    foreach ($d in $dhcpAdapters) {
        Result "DHCP IP"        $d.IPAddress
        Result "DHCP Adapter"   $d.InterfaceAlias

        # Get-WmiObject Win32_NetworkAdapterConfiguration：WMI 查詢取得 DHCP 詳細資訊
        # Where-Object { $_.IPAddress -contains $d.IPAddress }：比對對應的介面
        $wmi = Get-WmiObject Win32_NetworkAdapterConfiguration |
            Where-Object { $_.IPAddress -contains $d.IPAddress }
        if ($wmi) {
            Result "DHCP Server"    $wmi.DHCPServer        # DHCP 伺服器 IP
            Result "Lease Obtained" $wmi.DHCPLeaseObtained # Lease 取得時間
            Result "Lease Expires"  $wmi.DHCPLeaseExpires  # Lease 到期時間
        }
    }
} else {
    Log "  [--] No DHCP adapter found (may be static IP)" "Yellow"
}
```

---

### 區段 [3]：Ping + Traceroute（L95–L110）

```powershell
# Test-NetConnection：PS 內建網路測試 Cmdlet
# -WarningAction SilentlyContinue：抑制不必要的警告訊息
$ping = Test-NetConnection -ComputerName $TargetIP -WarningAction SilentlyContinue

# PingReplyDetails.RoundtripTime：來回時間（ms）
# PingSucceeded：Ping 成功為 $true，帶入 Result 決定 [OK]/[!!]
Result "Ping $TargetIP" "$($ping.PingReplyDetails.RoundtripTime)ms" $ping.PingSucceeded

try {
    # -TraceRoute：啟用路由追蹤
    # -Hops 10：最多追蹤 10 跳，避免等待過久
    $hops = Test-NetConnection -ComputerName $TargetIP `
            -TraceRoute -Hops 10 -WarningAction SilentlyContinue
    $i = 1
    foreach ($hop in $hops.TraceRoute) {
        # {0:D2}：數字補零至 2 位（01, 02...）
        Log ("    Hop {0:D2}  {1}" -f $i, $hop) "Gray"
        $i++
    }
} catch {
    Log "  [!!] Traceroute failed: $_" "Yellow"  # $_ 為 catch 捕獲的例外訊息
}
```

---

### 區段 [4]：DNS（L118–L143）

```powershell
# 定義要測試的 DNS 目標陣列
$dnsTargets = @(
    "google.com",      # 外部通用測試
    "hinet.net",       # CHT 主域
    "acs.hinet.net",   # CHT TR-069 ACS 可能域名
    "acs.hinet.com",   # 備用
    "8.8.8.8",         # Google DNS（反查 PTR）
    "168.95.1.1"       # CHT DNS（反查 PTR）
)

foreach ($d in $dnsTargets) {
    try {
        # Resolve-DnsName：PS 內建 DNS 解析 Cmdlet
        # -ErrorAction Stop：解析失敗時拋出例外，進入 catch
        $r  = Resolve-DnsName $d -ErrorAction Stop -WarningAction SilentlyContinue
        # 優先取 A 記錄（IPv4），若無則取第一筆的 NameHost
        $ip = ($r | Where-Object { $_.Type -eq "A" } | Select-Object -First 1).IPAddress
        if (-not $ip) { $ip = ($r | Select-Object -First 1).NameHost }
        Result "DNS: $d" $ip $true
    } catch {
        Result "DNS: $d" "NXDOMAIN / unresolvable" $false
    }
}

# 反向 DNS 查詢（PTR record）：由 IP 查域名
try {
    $rev = Resolve-DnsName $TargetIP -ErrorAction Stop
    Result "rDNS: $TargetIP" ($rev | Select-Object -First 1).NameHost $true
} catch {
    Result "rDNS: $TargetIP" "No PTR record" $false
}
```

---

### 區段 [5]：Port Scan（L151–L176）

```powershell
# 定義要掃描的 Port 清單（雜湊表陣列）
$ports = @(
    @{Port=80;   Desc="HTTP Admin"},
    @{Port=443;  Desc="HTTPS Admin"},
    @{Port=23;   Desc="Telnet (should be CLOSED)"},  # ← 資安敏感
    @{Port=22;   Desc="SSH"},
    @{Port=7547; Desc="TR-069 CWMP"},                # ← CHT 遠端管理
    @{Port=7548; Desc="TR-069 CWMP alt"},
    @{Port=8080; Desc="HTTP alt"},
    @{Port=8443; Desc="HTTPS alt"},
    @{Port=161;  Desc="SNMP"},
    @{Port=53;   Desc="DNS (if ONT serves)"}
)

foreach ($p in $ports) {
    try {
        # Test-NetConnection -Port：TCP 連線測試，等同 telnet <ip> <port>
        $tc = Test-NetConnection -ComputerName $TargetIP -Port $p.Port `
              -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        $ok = $tc.TcpTestSucceeded  # TCP 握手成功為 $true

        # Port 23 且開啟時，額外輸出紅色警告
        $warn = if ($p.Port -eq 23 -and $ok) { "  <-- WARNING: Telnet OPEN, security risk!" } else { "" }

        # {0,5}：數字右對齊佔 5 字元（對齊顯示）
        Result ("Port {0,5}  {1}" -f $p.Port, $p.Desc) `
               (if ($ok) { "OPEN" } else { "closed" }) $ok
        if ($warn) { Log $warn "Red" }
    } catch {
        Result ("Port {0,5}  {1}" -f $p.Port, $p.Desc) "error" $false
    }
}
```

---

### 區段 [6]：HTTP / HTTPS Response（L184–L204）

```powershell
# 定義 4 個常見管理頁 URL（HTTP / HTTPS / 8080 / 8443）
$urls = @(
    "http://${TargetIP}/",
    "https://${TargetIP}/",
    "http://${TargetIP}:8080/",
    "https://${TargetIP}:8443/"
)

foreach ($url in $urls) {
    try {
        $resp = Invoke-WebRequest -Uri $url -TimeoutSec 5 `
                -SkipCertificateCheck `   # PS7+：忽略自簽憑證錯誤
                -SkipHttpErrorCheck `     # PS7+：4xx/5xx 不拋例外，仍回傳物件
                -UseBasicParsing `        # 不解析 DOM，加速且相容 PS5.1
                -ErrorAction Stop

        $srv = $resp.Headers['Server']    # 取 Server header（顯示設備軟體資訊）

        # StatusCode < 400 視為正常（200 OK, 301 Redirect 等）
        Result $url "HTTP $($resp.StatusCode)  Server: $srv" ($resp.StatusCode -lt 400)
    } catch {
        # -replace "`n"," "：移除換行，讓錯誤訊息單行顯示
        $err = $_.Exception.Message -replace "`n"," "
        # Substring(0, Min(55, len))：截斷過長的錯誤訊息
        Result $url ("FAIL: " + $err.Substring(0, [Math]::Min(55,$err.Length))) $false
    }
}
```

---

### 區段 [7]：Internet + Public IP（L212–L227）

```powershell
# 測試對 3 個外部 IP 的連通性
foreach ($t in @("8.8.8.8", "1.1.1.1", "168.95.1.1")) {
    $p = Test-NetConnection -ComputerName $t -WarningAction SilentlyContinue
    Result "Internet Ping: $t" "$($p.PingReplyDetails.RoundtripTime)ms" $p.PingSucceeded
}

# 查詢公網 IP — 主要方法：ipify.org（回傳 JSON）
try {
    $pub = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 8).ip
    Result "Public IP (ipify)" $pub $true
} catch {
    # 備用方法：ifconfig.me（回傳純文字）
    try {
        $pub2 = (Invoke-RestMethod -Uri "https://ifconfig.me/ip" -TimeoutSec 8)
        Result "Public IP (ifconfig.me)" $pub2.Trim() $true  # .Trim() 移除前後空白
    } catch {
        Result "Public IP" "Failed to retrieve" $false
    }
}
```

---

### 區段 [8]：Latency Quality（L235–L278）

```powershell
$pingResults = @()  # 空陣列，用於收集每次 Ping 的 RTT

# 對中華電信 DNS（168.95.1.1）連續 Ping 20 次
for ($i = 1; $i -le 20; $i++) {
    $p = Test-NetConnection -ComputerName "168.95.1.1" -WarningAction SilentlyContinue
    if ($p.PingSucceeded) { $pingResults += $p.PingReplyDetails.RoundtripTime }
    Write-Host "." -NoNewline -ForegroundColor Gray  # 進度點（不換行）
}
Write-Host ""  # 20 個點結束後換行

if ($pingResults.Count -gt 0) {
    # Measure-Object：統計 Cmdlet，計算平均/最小/最大值
    $avg  = [Math]::Round(($pingResults | Measure-Object -Average).Average, 1)
    $min  = ($pingResults | Measure-Object -Minimum).Minimum
    $max  = ($pingResults | Measure-Object -Maximum).Maximum

    # 封包遺失率：(1 - 成功次數/總次數) * 100
    $loss = [Math]::Round((1 - $pingResults.Count / 20) * 100, 0)

    # Jitter 計算：相鄰兩次 RTT 差值的平均（量化網路穩定性）
    $diffs = @()
    for ($i = 1; $i -lt $pingResults.Count; $i++) {
        $diffs += [Math]::Abs($pingResults[$i] - $pingResults[$i-1])
    }
    $jitter = if ($diffs.Count -gt 0) {
        [Math]::Round(($diffs | Measure-Object -Average).Average, 1)
    } else { 0 }

    Result "Avg Latency"  "${avg}ms"            ($avg -lt 50)     # >50ms 警告
    Result "Min / Max"    "${min}ms / ${max}ms"  $true
    Result "Jitter"       "${jitter}ms"           ($jitter -lt 10)  # >10ms 警告
    Result "Packet Loss"  "${loss}%"              ($loss -eq 0)     # 任何遺失即警告
}

# 簡易頻寬測試：下載 CHT 提供的 1MB 測試檔
$start = Get-Date
Invoke-WebRequest -Uri "http://speedtest.hinet.net/download/1MB.bin" `
    -OutFile "$env:TEMP\bwtest.bin"  # 存至暫存資料夾
    -TimeoutSec 15 -UseBasicParsing | Out-Null  # Out-Null 丟棄回傳物件

$sec  = ((Get-Date) - $start).TotalSeconds   # 計算耗費秒數
# 速度(Mbps) = 檔案大小(MB) × 8 / 秒數
$mbps = [Math]::Round((1 * 8) / $sec, 2)
Result "Download (1MB CHT)" "${mbps} Mbps" ($mbps -gt 5)

# 測試完成後刪除暫存檔
Remove-Item "$env:TEMP\bwtest.bin" -ErrorAction SilentlyContinue
```

---

### 區段 [9]：TR-069 驗證（L287–L300）

```powershell
# netstat -ano：列出所有 TCP/UDP 連線及對應 PID
# Select-String $TargetIP：過濾包含目標 IP 的行
$activeConns = netstat -ano | Select-String $TargetIP

if ($activeConns) {
    foreach ($c in $activeConns) { Log "  $c" "Green" }
} else {
    # TR-069 不是持續連線，心跳間隔內看不到屬正常
    Log "  No active connections found" "Yellow"
    Log "  (Normal within TR-069 heartbeat interval; re-run in 60s to verify)" "Yellow"
}

# Port 7547：TR-069 CWMP 標準 Port（CPE 端監聽，供 ACS 主動觸發）
$tr069 = Test-NetConnection -ComputerName $TargetIP -Port 7547 -WarningAction SilentlyContinue
Result "TR-069 Port 7547" (if ($tr069.TcpTestSucceeded) { "OPEN" } else { "closed/filtered" }) $true

# 重要說明：TR-069 連線是 ONT 主動對外（outbound），
# 從用戶端測 Port 7547 通常是 closed，這屬正常，
# 真正的驗證需請工程師從 ACS 系統確認。
```

---

### 區段 [10]：TCP 連線總覽（L308–L315）

```powershell
# 取出所有 ESTABLISHED 狀態的連線，排除本機迴路（127.0.0.1 / ::1）
$conns = netstat -ano | Select-String "ESTABLISHED" |
    Where-Object { $_ -notmatch "127\.0\.0\.1|::1|\[::1\]" }
    # 正規表示式：\.  → 跳脫點字元；| → OR；\[::1\] → IPv6 迴路

if ($conns) {
    $conns | ForEach-Object { Log "  $_" "Gray" }
} else {
    Log "  No established outbound connections at this moment." "Yellow"
}
```

---

### Footer（L321–L325）

```powershell
Section "DONE"
# (Get-Item $logFile).FullName：取得 log 檔的完整絕對路徑（方便用戶找檔案）
Log "  Log saved : $((Get-Item $logFile).FullName)" "Cyan"
Log "  Target IP : $TargetIP" "Cyan"
Log "  Completed : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Cyan"
Log ("=" * 60) "Cyan"
```

---

## 8. 常見問題 FAQ

**Q1：執行時出現「未經數位簽署」錯誤**
使用方法 A：`powershell -ExecutionPolicy Bypass -File "D:\check_tr069.ps1" 192.168.1.1`

**Q2：`-SkipCertificateCheck` 不被識別**
此參數需 PowerShell 7+。PS 5.1 請將該行移除，或改安裝 [PowerShell 7](https://github.com/PowerShell/PowerShell/releases)。

**Q3：區段 [8] 頻寬測試失敗**
CHT 速測伺服器位址可能變更。此測試為非必要項目（Non-critical），失敗不影響其他結果。

**Q4：TR-069 Port 7547 顯示 closed 是否正常**
是。TR-069 為 ONT 主動 outbound，不在本機監聽。請依區段 [9] 說明，要求工程師從 ACS 系統確認。

**Q5：log 檔儲存在哪裡**
儲存於執行 PowerShell 時的當前工作目錄。建議執行前先 `cd D:\` 確認位置，或查看腳本結尾輸出的完整路徑。

---

## 9. 注意事項

- 本腳本不會修改任何系統設定，僅執行**唯讀**診斷。
- 區段 [5] Port Scan 僅測試 TCP 連線，不進行任何攻擊或滲透行為。
- 頻寬測試（區段 [8]）會下載約 1MB 資料，使用計費網路請注意。
- 腳本設計用於**內網診斷**，不建議對公網 IP 執行（Port Scan 可能觸發防火牆告警）。

---

*check_tr069.ps1 README — v1.0 / 2026-02-18*
