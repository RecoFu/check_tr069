# ⚡ NetFreak.ps1 v1.1 — Red Team Hardened Edition

> **版本** v1.1 / 2026-02-18
> **定位** 控制狂版網路自我診斷 — 紅隊稽核後強化版

---

## v1.1 修正對照表（紅隊稽核回應）

| 稽核ID | 風險分數 | 問題 | v1.1修正 |
|--------|---------|------|---------|
| **RT-D1** | R=3.8 | MAC OUI 送出至 `macvendors.com`，洩漏內部MAC | **嵌入300廠商OUI靜態表，零外部呼叫** |
| **RT-D1** | R=3.8 | ASN/IP/Geo自動送至`ipinfo.io`/`abuseipdb` | **改為`-AllowExternalAPI`明確opt-in旗標** |
| **RT-D2** | R=4.25 | SSDP掃描+TCP多Port同時觸發EDR | **`-Stealth`旗標：加probe延遲、停用SSDP** |
| **RT-D3** | R=1.2 | MTU二元搜尋大量ICMP可能crash舊ONT | **3次probe取多數決，搜尋範圍縮至1000-1500** |
| **RT-U11** | — | 安全評分主觀，無CVSS/MITRE對應 | **每條扣分附CVSS v3.1向量 + MITRE ATT&CK TTP** |
| **RT-U4** | — | MOS公式簡化，偏差10-20% | **改用codec表（G.711/G.729/G.722）完整E-model** |
| **RT-U2** | — | DNS洩漏未考慮TTL差異 | **新增TTL比對，TTL spread>30s額外警告** |
| **RT-NEW** | — | 無法識別高權限帳號的連線程序 | **新增[U14]：`Get-Process -IncludeUserName`+特權標記** |

---

## 使用方法

### 語法

```powershell
.\NetFreak_v1.1.ps1 [-GW <IP>] [-PingCount <N>] [-Html] [-SkipSlow] [-Stealth] [-AllowExternalAPI]
```

### 新增旗標（v1.1）

| 旗標 | 說明 |
|------|------|
| `-Stealth` | 低暴露模式：Port掃描加延遲500ms、停用SSDP、禁用外部API |
| `-AllowExternalAPI` | 明確允許呼叫外部API（ipinfo.io / abuseipdb） |

### 使用情境

```powershell
# 標準診斷（外部API關閉，資料不出去）
powershell -ExecutionPolicy Bypass -File "D:\NetFreak_v1.1.ps1" -GW 192.168.1.1 -Html

# 完整診斷含ASN/威脅情報（允許外部API）
powershell -ExecutionPolicy Bypass -File "D:\NetFreak_v1.1.ps1" -GW 192.168.1.1 -Html -AllowExternalAPI

# 低暴露模式（減少EDR觸發風險）
.\NetFreak_v1.1.ps1 -GW 192.168.1.1 -Stealth

# 快速掃（跳過慢速測試）
.\NetFreak_v1.1.ps1 -GW 192.168.1.1 -SkipSlow -Html
```

---

## 核心架構改動詳解

### RT-D1：OUI嵌入表（零外部洩漏）

```
v1.0：  MAC → macvendors.com API → 廠商名稱  [洩漏內部MAC]
v1.1：  MAC → 本地$OUI雜湊表(300廠商) → 廠商名稱  [零外部呼叫]

$OUI = @{
    "001E65" = "Nokia"
    "001349" = "Zyxel"
    "001A2F" = "Cisco"
    ...  (300 entries, IEEE public OUI registry)
}
```

**覆蓋廠商**：Apple / Cisco / Nokia / Zyxel / Alcatel-Lucent / ASUS / Intel / TP-Link / D-Link / Netgear / Belkin / VMware / Samsung / Realtek / Microsoft / Broadcom / Arcadyan 等300筆。

---

### RT-D1：外部API明確opt-in

```powershell
# v1.0行為（自動送出）：
$ipInfo = Invoke-RestMethod "https://ipinfo.io/json"  # 自動執行

# v1.1行為（明確opt-in）：
function Invoke-ExternalAPI {
    if (-not $AllowExternalAPI) {
        Info "BLOCKED: $Purpose (add -AllowExternalAPI)"
        return $null          # 不呼叫，資料不出去
    }
    ...
}
```

**預設行為**：所有外部API均不呼叫，輸出提示「add -AllowExternalAPI to enable」。

---

### RT-D2：Stealth模式

```powershell
$scanDelay   = if ($Stealth) { 500  } else { 0   }   # ms probe間距
$scanTimeout = if ($Stealth) { 2000 } else { 5000 }  # TCP timeout

# SSDP在Stealth模式完全跳過：
if ($Stealth) { Skip "UPnP SSDP (RT-D2: disabled in Stealth)"; return }

# TCPTest函數加入delay：
function TCPTest { ...
    if ($Stealth) { Start-Sleep -Milliseconds $scanDelay }
    ...
}
```

---

### RT-D3：MTU安全探測（舊ONT保護）

```
v1.0：  搜尋範圍576-1500，單次probe
v1.1：  搜尋範圍1000-1500（避免576-1000的大量ICMP碎片）
        3次probe取多數決（≥2/3才判定OK）
        降低單次ICMP burst對舊ONT的衝擊
```

---

### RT-U11：CVSS v3.1對齊安全評分

```powershell
# v1.0（主觀）：
SecDeduct 20 "Telnet OPEN"

# v1.1（CVSS + MITRE對齊）：
SecDeduct 20 "Port 23 Telnet OPEN" `
           "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" `   # CVSS向量
           "T1021.004"                                    # MITRE TTP
```

**CVSS嚴重度對應扣分**：

| CVSS Severity | 扣分 | 對應MITRE TTP（部分）|
|---------------|------|---------------------|
| CRITICAL (9.0+) | -20 | T1219, T1021.004 |
| HIGH (7.0-8.9) | -10 | T1040, T1071.002 |
| MEDIUM (4.0-6.9) | -5 | T1135, T1090 |
| LOW | 0 | — |

---

### RT-U4：改進MOS E-model

```
v1.0（簡化，偏差10-20%）：
  Ie = 30 * loss / (loss + 5)

v1.1（codec-aware完整E-model）：
  $codecTable = @{
    "G.711" = @{Ie=0;  Bpl=25.1}   # POTS標準
    "G.729" = @{Ie=11; Bpl=19}     # 壓縮語音
    "G.722" = @{Ie=0;  Bpl=34}     # HD語音
  }
  Ie = cIe + (100-cIe) * (loss / (loss + Bpl))
  R  = 93.2 - Id - Ie
  MOS = 1 + 0.035R + 7e-6 * R(R-60)(100-R)
```

---

### RT-U2：TTL感知DNS洩漏測試

```
v1.0：只比對5個resolver的IP是否一致

v1.1：
  1. 比對IP一致性（同v1.0）
  2. 比對TTL值 -- TTL spread > 30s → cache poisoning警告
  3. TTL差異可區分：
     - 正常的CDN差異（TTL相近但IP略不同）
     - 真正的DNS劫持（TTL異常高 = ISP緩存/MITM）
```

---

### U14：新增 Process+User 特權稽核

```powershell
# 取得程序+使用者名稱
$procs = Get-Process -IncludeUserName | Where-Object { $_.UserName }

# 標記高權限帳號的網路程序
$elevated = $procs | Where-Object {
    $_.UserName -match "Administrator|SYSTEM|Domain Admins|NT AUTHORITY"
}

# 若Admin程序連線數>10 → 安全扣分 + MITRE T1078
```

---

## 各區段 v1.1 變更速覽

| # | 區段 | v1.0 | v1.1變更 |
|---|------|------|---------|
| 1 | IP Stack | ARP無廠商 | ARP附embedded OUI廠商 |
| 3 | Gateway | MAC→外部API | MAC→本地OUI表 |
| 4 | Port Scan | 無CVSS | 每Port附CVSS向量+MITRE TTP |
| 4 | Port Scan | 固定速度 | Stealth模式500ms間距 |
| 5 | DNS Leak | IP比對 | IP+TTL比對，TTL spread偵測 |
| 6 | Internet | 自動呼叫ipinfo | 需-AllowExternalAPI opt-in |
| 7 | MOS | 簡化公式 | Codec表E-model |
| 8 | MTU | 576-1500單probe | 1000-1500，3probe多數決 |
| 11 | UPnP | 永遠執行 | Stealth模式跳過 |
| 13 | Process | 只有PID+Name | — |
| **14** | **Process+User** | **不存在** | **新增：IncludeUserName+特權標記** |
| 16 | Security Score | 主觀扣分 | CVSS v3.1對齊 |

---

## 紅隊稽核對話摘要

原稽核的核心批評與回應：

> **「將內部網段MAC傳送至macvendors.com是在為受害者繪製精確地圖。」**
> → v1.1：MAC永不離機，嵌入OUI表300廠商覆蓋率。

> **「M-SEARCH多播掃描與全Port TCP掃描是SOC監控報警的第一順位。」**
> → v1.1：`-Stealth`旗標停用SSDP、TCP間距500ms，降低行為特徵。

> **「安全評分[U11]的加權純屬主觀臆斷，缺乏CVSS或MITRE ATT&CK的映射支持。」**
> → v1.1：每條SecDeduct附CVSS v3.1向量字串+MITRE TTP編號。

> **「最簡解釋：這是一個PowerShell命令包裝器，而非獨家診斷算法。」**
> → **承認**：NetFreak確實是高品質包裝器。OUI嵌入表、TTL-aware DNS、E-model MOS屬原創組合，但底層仍依賴系統命令。Occam正確。

---

## 仍存在的已知限制

| 限制 | 說明 | 解法方向 |
|------|------|---------|
| `netsh`/`netstat`可被Rootkit偽造 | 用戶空間工具無法抵抗Kernel-level hooking | 需ETW/WFP kernel callback（超出PS範圍）|
| OUI表覆蓋率~300廠商 | 新品牌或ODM可能顯示Unknown | 定期更新或擴充至2000+筆 |
| MOS為單向估算 | 缺少實際VoIP協商資料 | 需RTCP SR/RR封包分析 |
| `-AllowExternalAPI`用戶仍需自評風險 | 無法強制保護選擇允許的用戶 | 加warning + 確認提示 |

---

*NetFreak.ps1 v1.1 — Red Team Hardened | 2026-02-18*
*「工具的誠實在於承認它是什麼，而不是假裝它是它不是的東西。」*
