# check_tr069.ps1 — 全方位網路診斷腳本

> **版本** v1.1 / 2026-02-18
> **PS相容** PowerShell 5.1 / 7+（自動偵測）
> **用途** CHT FTTH + ONT 換機驗收、TR-069確認、資安Port掃描、延遲品質量化

---

## 目錄

1. [需求背景](#1-需求背景)
2. [v1.1 修正說明](#2-v11-修正說明)
3. [適用環境](#3-適用環境)
4. [前置需求](#4-前置需求)
5. [使用方法](#5-使用方法)
6. [輸出說明](#6-輸出說明)
7. [各區段功能說明](#7-各區段功能說明)
8. [程式碼逐行解說](#8-程式碼逐行解說)
9. [log結果判讀指南](#9-log結果判讀指南)
10. [常見問題 FAQ](#10-常見問題-faq)
11. [注意事項](#11-注意事項)

---

## 1. 需求背景

本腳本源自中華電信 FTTH 光纖設備（Nokia G-040G-Q ONT）更換後的網路重建驗收需求：

- 中華電信工程師到府後的**設備驗收確認**
- **TR-069 / CWMP** 遠端管理通道是否正常（工程師遠端reset依賴此通道）
- DHCP / DNS / Gateway 基本連線是否正確
- 開放 Port **資安檢查**（Telnet 是否意外開啟）
- 網路**延遲品質**量化（Jitter / 封包遺失）
- **公網IP**確認 / 頻寬粗估
- **連線程序識別**（哪個PID / 程式佔用最多連線）

---

## 2. v1.1 修正說明

| ID | 問題（v1.0） | 修正方式（v1.1） |
|----|------------|----------------|
| M1 | Port Scan 全部顯示 `error`（PS5.1 在 `-ErrorAction SilentlyContinue` 下 TCP timeout 拋例外） | 移除 `-ErrorAction SilentlyContinue`，`Test-NetConnection` 正常回傳 `TcpTestSucceeded=$false` |
| M2 | HTTP/HTTPS 顯示「找不到參數 SkipCertificateCheck」（PS5.1 不支援） | 自動偵測 PS 版本：PS7+ 用原參數；PS5.1 改用 `ServicePointManager` 繞過憑證檢查 |
| M3 | 頻寬測試失敗（CHT speedtest URL 可能失效） | 加入多個備用 URL 依序嘗試（CHT / CacheFly / Cloudflare） |
| M4 | 區段[9]顯示本機所有連線（Select-String 誤比對本機IP中含target IP的行） | 改為正規表示式精確比對 Remote Endpoint = TargetIP |
| 新增 | 無法識別高連線數PID對應程式 | 新增區段[10] PID → Process Name 對照 |
| 新增 | `acs.hinet.net` NXDOMAIN 顯示 `[!!]` 造成誤解 | 已知CHT內部不公開DNS，改為 `[OK]` 並加注說明 |
| 新增 | 內網IP無PTR顯示 `[!!]` 造成誤解 | rDNS LAN IP 無PTR屬正常，改為 `[OK]` |

---

## 3. 適用環境

| 項目 | 需求 |
|------|------|
| 作業系統 | Windows 10 / Windows 11 |
| PowerShell | **PS 5.1**（Windows內建）/ **PS 7+**（完整支援） |
| 網路角色 | 有線或無線連至目標IP（ONT / Router / Switch 皆可） |
| 執行權限 | **系統管理員（Administrator）** |
| 對外連線 | 區段[7][8]需要；其餘僅需內網可達目標IP |

---

## 4. 前置需求

### 執行原則解鎖（擇一）

```powershell
# 方法A：單次執行（建議，不改系統設定）
powershell -ExecutionPolicy Bypass -File "D:\check_tr069.ps1" 192.168.1.1

# 方法B：解鎖當前使用者（永久）
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

# 方法C：移除Zone封鎖標記
Unblock-File -Path "D:\check_tr069.ps1"
```

### 以系統管理員開啟 PowerShell

```
開始功能表 → 搜尋「PowerShell」→ 右鍵 → 以系統管理員執行
```

---

## 5. 使用方法

### 語法

```powershell
.\check_tr069.ps1 <目標IP>
```

### 範例

```powershell
# ONT 預設 IP
.\check_tr069.ps1 192.168.1.1

# 工程師改設後的 IP
.\check_tr069.ps1 192.168.0.254

# 建議執行方式（Bypass + 系統管理員）
powershell -ExecutionPolicy Bypass -File "D:\check_tr069.ps1" 192.168.0.254
```

### 參數

| 參數 | 型態 | 必填 | 說明 |
|------|------|------|------|
| `$TargetIP` | String | ✅ | 目標 IP（ONT / Router 管理頁）|

---

## 6. 輸出說明

### Log 檔名格式

```
check_tr069_<TargetIP>_<yyyyMMdd_HHmm>.log
```

範例：`check_tr069_192.168.1.1_20260218_1031.log`

### 輸出符號

| 符號 | 顏色 | 意義 |
|------|------|------|
| `[OK]` | 綠 | 正常 |
| `[!!]` | 黃 | 警告／異常 |
| `[--]` | 黃 | 未偵測（非錯誤） |
| `WARNING` | 紅 | 高風險（Telnet開啟等） |

---

## 7. 各區段功能說明

| # | 區段 | 主要功能 | v1.1變更 |
|---|------|----------|---------|
| 1 | Local NIC / IP Info | 所有介面IP / GW / DNS / Prefix | GW/DNS空值改顯示"(none)" |
| 2 | DHCP Info | DHCP伺服器 / Lease時間 | 無 |
| 3 | Ping + Traceroute | 目標IP連通 + 10跳路由 | 無 |
| 4 | DNS Resolution | 解析6個目標 + rDNS反查 | acs.hinet.net NXDOMAIN改[OK]；rDNS無PTR改[OK] |
| 5 | Port Scan | 10個關鍵Port（含Telnet資安警告）| **M1修正：移除ErrorAction，正確顯示open/closed** |
| 6 | HTTP/HTTPS Response | 管理頁回應碼 + Server header | **M2修正：PS5.1自動改用ServicePointManager** |
| 7 | Internet + Public IP | 3個外部Ping + 公網IP查詢 | 無 |
| 8 | Latency Quality | 20次Ping Jitter/Loss + 頻寬粗估 | **M3修正：多個備用URL依序嘗試** |
| 9 | TR-069 / ACS | 對ONT的active連線 + 7547 Port | **M4修正：精確過濾Remote=TargetIP** |
| 10 | Process Lookup | PID → 程式名稱對照 + 連線總覽 | **新增** |

---

## 8. 程式碼逐行解說

### 區塊 0：參數 + 初始化（L7–L16）

```powershell
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$TargetIP
    # Mandatory=$true  → 未輸入時PS主動要求
    # Position=0       → 第一個位置參數，不需加 -TargetIP 旗標
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmm"   # 時間戳，用於log檔名
$logFile   = "check_tr069_${TargetIP}_${timestamp}.log"  # ${} 安全插值
$scriptVer = "v1.1 / 2026-02-18"
$psVer     = $PSVersionTable.PSVersion.Major    # v1.1新增：取PS主版本號供M2使用
```

---

### 區塊 1：三個輔助函數（L18–L38）

```powershell
function Log {
    param([string]$msg, [string]$color = "White")  # color預設白
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg" # 加時間戳前綴
    Write-Host $line -ForegroundColor $color         # 彩色輸出螢幕
    Add-Content -Path $logFile -Value $line          # 附加寫入log
}

function Section {
    param([string]$title)
    $bar = "=" * 60           # 60個等號
    Log ""                     # 空行
    Log $bar "Cyan"
    Log "  $title" "Cyan"
    Log $bar "Cyan"
}

function Result {
    param([string]$label, $value, [bool]$ok = $true)
    $icon = if ($ok) { "[OK]" } else { "[!!]" }
    $col  = if ($ok) { "Green" } else { "Yellow" }
    Log ("  {0,-28} {1} {2}" -f $label, $icon, $value) $col
    # {0,-28} = label欄左對齊28字元，整齊排列
}
```

---

### 區段 [1]：NIC Info（L52–L64）

```powershell
$adapters = Get-NetIPConfiguration | Where-Object { $_.IPv4Address }
# Where-Object 過濾掉無IPv4的介面（Loopback / 純IPv6）

foreach ($a in $adapters) {
    $gw = if ($a.IPv4DefaultGateway.NextHop) { ... } else { "(none)" }
    # v1.1：GW為空時顯示"(none)"而非空字串，避免log誤讀
    $dns = if ($a.DNSServer.ServerAddresses) { ... -join ", " } else { "(none)" }
    # -join "," 將DNS陣列轉為逗號分隔字串
}
```

---

### 區段 [2]：DHCP Info（L72–L89）

```powershell
$dhcpAdapters = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.PrefixOrigin -eq "Dhcp" }
# PrefixOrigin = "Dhcp" 代表IP由DHCP動態配發
# Manual = 靜態手設；WellKnown = 169.254.x.x APIPA

$wmi = Get-WmiObject Win32_NetworkAdapterConfiguration |
    Where-Object { $_.IPAddress -contains $d.IPAddress }
# WMI查DHCP細節（Lease時間等），-contains用於比對IP陣列
```

---

### 區段 [3]：Ping + Traceroute（L96–L113）

```powershell
$ping = Test-NetConnection -ComputerName $TargetIP -WarningAction SilentlyContinue
# -WarningAction SilentlyContinue：抑制PS內建Warning提示

$hops = Test-NetConnection -ComputerName $TargetIP -TraceRoute -Hops 10
# -TraceRoute：啟用路由追蹤（等同tracert）
# -Hops 10：最多10跳，防止等待過久

Log ("    Hop {0:D2}  {1}" -f $i, $hop)
# {0:D2} = 數字補零至2位（01, 02...10）
```

---

### 區段 [4]：DNS（L118–L145）

```powershell
# v1.1修正：acs.hinet.net NXDOMAIN改為[OK]
Result "DNS: $d" "NXDOMAIN$note" ($d -eq "acs.hinet.net")
# ($d -eq "acs.hinet.net") 回傳$true → [OK]（已知CHT內部不公開）

# v1.1修正：rDNS無PTR改為[OK]
Result "rDNS: $TargetIP" "No PTR record (normal for LAN IP)" $true
# 內網IP無PTR屬正常，$true避免顯示[!!]造成誤解
```

---

### 區段 [5]：Port Scan — M1修正（L152–L178）

```powershell
# v1.0（有問題）：
$tc = Test-NetConnection ... -ErrorAction SilentlyContinue
# PS5.1 TCP timeout 會拋例外進catch → 顯示"error"

# v1.1（修正）：
$tc = Test-NetConnection -ComputerName $TargetIP -Port $p.Port `
      -WarningAction SilentlyContinue
# 只保留 -WarningAction，移除 -ErrorAction
# timeout → TcpTestSucceeded=$false → 正常顯示"closed/filtered"
```

---

### 區段 [6]：HTTP/HTTPS — M2修正（L185–L218）

```powershell
if ($psVer -ge 7) {
    # PS7+：直接使用 -SkipCertificateCheck（此參數PS7才有）
    $resp = Invoke-WebRequest ... -SkipCertificateCheck -SkipHttpErrorCheck
} else {
    # PS5.1：用ServicePointManager全域繞過憑證驗證
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    # Lambda { $true } = 無論憑證如何都回傳"有效"
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.SecurityProtocolType]::Tls12 -bor ...
    # -bor = bitwise OR，同時啟用TLS1.0/1.1/1.2
    $resp = Invoke-WebRequest ... -UseBasicParsing
}

# 用完後還原（重要！避免影響後續連線安全性）
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
```

---

### 區段 [8]：頻寬測試 — M3修正（L265–L287）

```powershell
# v1.1：多個備用URL陣列
$bwUrls = @(
    "http://speedtest.hinet.net/download/1MB.bin",   # CHT主要
    "http://speedtest.hinet.net/download/5MB.bin",   # CHT備用
    "http://cachefly.cachefly.net/1mb.test",         # CDN測試
    "https://speed.cloudflare.com/__down?bytes=1048576"  # Cloudflare
)

$bwDone = $false
foreach ($bwUrl in $bwUrls) {
    if ($bwDone) { break }   # 成功後跳出迴圈
    try {
        ...
        $size = (Get-Item $bwFile).Length / 1MB   # 取實際下載大小（MB）
        $mbps = [Math]::Round(($size * 8) / $sec, 2)   # Mbps = MB×8 / 秒
        $bwDone = $true   # 標記成功，後續URL不再嘗試
    } catch {
        Log "  [--] $bwUrl failed, trying next..." "Yellow"
    }
}
```

---

### 區段 [9]：TR-069 — M4修正（L296–L322）

```powershell
# v1.0（有問題）：
$ontConns = netstat -ano | Select-String $TargetIP
# Select-String "192.168.1.1" 會比對到本機IP "192.168.1.101"
# 因為 .101 包含 .1 → 誤將本機所有連線都列出

# v1.1（修正）：精確比對Remote Endpoint
$ontConns = $rawConns | Where-Object {
    $fields = ($_ -replace '\s+', ' ').Trim().Split(' ')
    if ($fields.Count -ge 4) {
        $remote = $fields[2]   # netstat第3欄 = Remote Address
        $remote -match "^$([regex]::Escape($TargetIP)):"
        # [regex]::Escape()：跳脫IP中的點字元（.→\.)
        # ^...: 確保TargetIP出現在Remote欄的開頭
        # ...: 後面必須接冒號（Port分隔），防止192.168.1.1比對到192.168.1.10
    }
}
```

---

### 區段 [10]：Process Lookup（v1.1新增）（L330–L357）

```powershell
# 統計每個PID的連線數
$pidCount = @{}   # 空雜湊表
foreach ($line in $rawEstab) {
    $fields = ($line -replace '\s+', ' ').Trim().Split(' ')
    $pid_ = $fields[-1]   # [-1] = 最後一個欄位 = PID
    if ($pid_ -match '^\d+$') {   # 確認是數字
        $pidCount[$pid_] = ($pidCount[$pid_] -as [int]) + 1
        # -as [int]：若key不存在回傳$null，轉int為0，再+1
    }
}

# 取前8名 + 查程式名稱
$pidCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 |
ForEach-Object {
    $pname = try {
        (Get-Process -Id $_.Key -ErrorAction Stop).Name
        # Get-Process -Id：依PID取程式名稱（如chrome, msedge）
    } catch { "unknown" }   # PID已結束或無權限時
    Result ("PID $($_.Key) [$pname]") "$($_.Value) connections" $true
}
```

---

## 9. log結果判讀指南

### 正常情況（不需處理）

| 項目 | 結果 | 說明 |
|------|------|------|
| `DNS: acs.hinet.net` | `NXDOMAIN` | CHT ACS為內部domain，不對外解析 |
| `rDNS: 192.168.1.1` | `No PTR record` | 內網IP無PTR屬正常 |
| TR-069 Port 7547 | `closed/filtered` | ONT主動outbound，非inbound listening |
| 區段[9] 無連線 | 空結果 | TR-069心跳間隔內屬正常，60秒後再試 |

### 需要注意

| 項目 | 結果 | 處置 |
|------|------|------|
| Port 23 Telnet | `OPEN` | 立即通知工程師關閉 |
| Jitter | `>10ms` | 線路品質問題，請CHT檢測光功率 |
| Packet Loss | `>0%` | 同上，或ONT過熱 |
| 公網IP無法取得 | FAIL | 檢查DNS是否正常，PPPoE是否撥號成功 |

### TR-069 驗收口訣

```
acs.hinet.com 能解析 → ACS server可達 ✅
工程師查ACS系統確認 ONT = Connected ✅
→ TR-069通道正常，日後可遠端管理 ✅
```

---

## 10. 常見問題 FAQ

**Q1：Port Scan 顯示 closed/filtered，ONT管理頁打不開？**
Port Scan 結果顯示 closed 代表TCP連線未建立，但80/443 Port實際上可能是OPEN且正常的——請直接開瀏覽器輸入 `http://192.168.1.1` 確認，比Port Scan更直接。

**Q2：區段[8] 頻寬測試全部失敗？**
可能原因：網路防火牆封鎖HTTP下載，或所有測試URL均失效。此測試為非必要項目，不影響其他診斷結果。可改用 fast.com 或 speedtest.net 手動測試。

**Q3：PktMon.etl 是什麼？**
Windows 10 2004+ 內建的核心層封包擷取工具 (Packet Monitor) 產生的 Event Trace Log 檔。可能由先前執行的 `pktmon start` 或Windows診斷工具產生。轉換方式：
```powershell
pktmon etl2txt PktMon.etl --out PktMon.txt    # 轉文字
pktmon etl2pcap PktMon.etl --out PktMon.pcap  # 轉Wireshark格式
pktmon stop                                    # 停止仍在執行的擷取
```

**Q4：區段[9] 仍然顯示很多連線？**
v1.1已修正過濾邏輯。若仍顯示大量連線，表示你的電腦確實與目標IP（ONT）有多條active連線（如ONT提供NTP、SNMP等服務），屬正常。

**Q5：PS版本如何確認？**
```powershell
$PSVersionTable.PSVersion
```

---

## 11. 注意事項

- 本腳本為**唯讀診斷**，不修改任何系統或網路設定。
- Port Scan 僅為 TCP 連線測試，不進行任何攻擊或漏洞掃描。
- 頻寬測試下載約 1–5MB，計費網路請注意。
- `ServicePointManager` 憑證繞過（PS5.1用於HTTPS測試）僅在腳本執行期間生效，結束後自動還原。
- 建議**不對公網IP執行**，Port Scan可能觸發對方防火牆告警。

---

*check_tr069.ps1 README — v1.1 / 2026-02-18*
