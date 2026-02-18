# ⚡ NetFreak.ps1 — 控制狂版網路自我診斷

> **版本** v1.0 / 2026-02-18
> **定位** 超越 GlassWire / PingPlotter / WinMTR / Speedtest 的全功能 PS 診斷腳本
> **No Install** 純 PowerShell 5.1+，零依賴，零安裝

---

## 為什麼要做這個？現有工具的盲點

| 工具 | 缺少什麼 |
|------|---------|
| GlassWire | 無 MTU 偵測、無 DNS 洩漏測試、無 ASN/BGP、無安全評分 |
| PingPlotter | 只有延遲/路由，無 Port 掃描、無 UPnP 審計、無 IGMP |
| WinMTR | 單一功能（MTR），無法輸出 HTML、無程序對應 |
| Speedtest CLI | 只測速，無安全、無 DNS、無 IPv6 審計 |
| NetLimiter | GUI 商業軟體，需安裝，無 CLI/腳本整合 |

**NetFreak 的 13 項獨家功能（[U1]–[U13]）：**

| 代號 | 功能 | 說明 |
|------|------|------|
| U1 | **MTU 路徑發現** | 二元搜尋找最佳 MTU，CHT PPPoE 自動識別 1492 |
| U2 | **DNS 洩漏測試** | 跨 5 個 resolver 比對，偵測 DNS 劫持/分流 |
| U3 | **ASN / BGP / Geo** | 公網 IP 的 ISP / AS 號碼 / 城市 / 威脅評分 |
| U4 | **MOS 語音品質分數** | ITU-T G.107 E-model，量化 VoIP/MOD 通話品質 |
| U5 | **IGMP 組播偵測** | CHT MOD/IPTV multicast 群組確認 |
| U6 | **UPnP Port 審計** | SSDP 發現 + 列出 UPnP 暴露的 Port 映射 |
| U7 | **MAC 廠商查詢** | OUI 查詢識別 ONT/Router 製造商 |
| U8 | **雙網卡路由衝突偵測** | 多 Gateway 時自動警告路由衝突風險 |
| U9 | **ARP Cache LAN 地圖** | 列出同網段所有裝置 |
| U10 | **IPv6 完整審計** | SLAAC/DHCPv6/公網暴露/防火牆建議 |
| U11 | **資安評分 A–F** | 12 因子加權評分，完整建議清單 |
| U12 | **HTML 自包含報告** | 暗色系儀表板風格，附安全等級徽章 |
| U13 | **持續監控模式** | `-Monitor` 旗標啟動即時趨勢監看 |

---

## 適用環境

| 項目 | 需求 |
|------|------|
| OS | Windows 10 / 11 |
| PowerShell | 5.1（內建）/ 7+（完整支援） |
| 權限 | **系統管理員** |
| 網路 | 有線或無線，建議有線執行完整測試 |

---

## 安裝 / 解鎖

```powershell
# 方法 A：單次執行（建議）
powershell -ExecutionPolicy Bypass -File "D:\NetFreak.ps1" -GW 192.168.1.1

# 方法 B：Unblock 後直接執行
Unblock-File "D:\NetFreak.ps1"
.\NetFreak.ps1 -GW 192.168.1.1
```

---

## 使用方法

### 語法

```powershell
.\NetFreak.ps1 [-GW <IP>] [-PingCount <N>] [-Monitor] [-Html] [-SkipSlow]
```

### 參數

| 參數 | 預設 | 說明 |
|------|------|------|
| `-GW` | 自動偵測 | 指定目標 Gateway IP（ONT 管理頁 IP） |
| `-PingCount` | 20 | 延遲品質測試的 Ping 次數（建議 20–50） |
| `-Monitor` | off | 持續監控模式（Ctrl+C 停止） |
| `-Html` | off | 同時產生 HTML 報告 |
| `-SkipSlow` | off | 跳過慢速測試（MTU/UPnP/IPv6），加速約 40% |

### 範例

```powershell
# 標準診斷
.\NetFreak.ps1 -GW 192.168.1.1

# 完整診斷 + HTML 報告
powershell -ExecutionPolicy Bypass -File "D:\NetFreak.ps1" -GW 192.168.1.1 -Html

# 快速掃（跳過慢速測試）
.\NetFreak.ps1 -GW 192.168.1.1 -SkipSlow

# 高精度延遲品質（50 次 Ping）
.\NetFreak.ps1 -GW 192.168.1.1 -PingCount 50 -Html
```

---

## 輸出檔案

```
NetFreak_20260218_1031.log        ← 完整文字 log（每次必產生）
NetFreak_20260218_1031.html       ← 暗色 HTML 報告（-Html 才產生）
```

---

## 各區段說明

| # | 區段 | 獨家功能 | 耗時估計 |
|---|------|---------|---------|
| 1 | Full IP Stack | U8雙網卡衝突, U9 ARP地圖 | 5s |
| 2 | DHCP Deep Dive | Lease時間分析, 到期警告 | 3s |
| 3 | Gateway Analysis | U7 MAC廠商查詢 | 5s |
| 4 | Port Security Audit | 16 Port + 資安扣分 | 60–120s |
| 5 | DNS + Leak Test | U2跨5個resolver比對 | 15s |
| 6 | Internet + ASN | U3 BGP/Geo/威脅評分 | 10s |
| 7 | Latency + MOS | U4 ITU-T G.107評分 | 60–120s |
| 8 | MTU Discovery | U1 二元搜尋 | 30–60s |
| 9 | Bandwidth | 多源備援下載測速 | 15–30s |
| 10 | IPv6 Audit | U10 公網暴露偵測 | 20s |
| 11 | UPnP Audit | U6 SSDP發現+Port映射 | 10s |
| 12 | IGMP/Multicast | U5 CHT MOD驗證 | 5s |
| 13 | Process Map | PID→程式名稱+連線統計 | 5s |
| 14 | WiFi Analysis | RSSI/Channel/鄰近網路 | 5s |
| 15 | Security Score | U11 A–F評分+建議清單 | <1s |
| 16 | HTML Report | U12 自包含暗色報告 | <1s |

**總計約 4–8 分鐘**（含所有慢速測試）

---

## 資安評分說明（U11）

### 扣分項目

| 事件 | 扣分 |
|------|------|
| Port 23 Telnet OPEN | -20 |
| Port 21 FTP OPEN | -10 |
| Port 5555 ADB OPEN | -20 |
| Port 161 SNMP OPEN | -10 |
| DNS 洩漏偵測 | -15 |
| IPv6 未設防火牆 | -8 |
| UPnP 已啟用 | -8 |
| 多 Gateway 衝突 | -10 |
| 封包遺失 >5% | -10 |
| Jitter >20ms | -5 |
| MOS <3.6 | -5 |
| DHCP Lease <2h | -5 |

### 評分等級

| 分數 | 等級 | 說明 |
|------|------|------|
| 90–100 | **A** | 優良，無顯著問題 |
| 80–89 | **B** | 良好，有小問題 |
| 70–79 | **C** | 尚可，建議處理 |
| 60–69 | **D** | 警告，有重要問題 |
| <60 | **F** | 危險，立即處理 |

---

## MOS 分數說明（U4）

MOS（Mean Opinion Score）= 語音/視訊通話品質的標準量化指標，由 ITU-T G.107 E-model 計算。

| MOS | 等級 | 對應體感 |
|-----|------|---------|
| 4.3–5.0 | A Excellent | 通話/MOD 完美無瑕 |
| 4.0–4.3 | B Good | 偶有輕微延遲，可接受 |
| 3.6–4.0 | C Fair | 明顯但可用 |
| 3.1–3.6 | D Poor | 頻繁雜音/卡頓 |
| <3.1 | F Bad | 無法使用 |

CHT FTTH 正常環境應達 **MOS ≥ 4.3（A 級）**。

---

## MTU 發現說明（U1）

使用 `ping.exe -f -l` 二元搜尋最佳封包大小：

| MTU | 代表意義 |
|-----|---------|
| 1500 | 標準乙太網路，最佳 |
| 1492 | CHT FTTH PPPoE 正常值（-8 byte PPPoE overhead）|
| 1480 | 可能有 VPN tunnel 或額外封裝 |
| <1400 | 異常，可能影響吞吐量 |

---

## DNS 洩漏測試說明（U2）

同時查詢 CHT / Google / Cloudflare / Quad9 / TWNIC 五個 resolver，要求各自回報「看到你是誰」。

- **全部相同** → 無洩漏 ✅
- **結果不同** → 可能 DNS 劫持、CHT DNS 透明代理、或 VPN 分流 ⚠️

---

## 常見問題 FAQ

**Q1：執行時間太長？**
加 `-SkipSlow` 跳過 MTU/UPnP/IPv6，總時間縮至 2–3 分鐘。

**Q2：Port Scan 很慢？**
每個 Port 預設等待 TCP timeout（約 5s），16 個 Port 最多需 80s。屬正常行為。

**Q3：MAC 廠商查不到？**
`api.macvendors.com` 有 Rate Limit，離線或達限時自動跳過，非錯誤。

**Q4：UPnP 沒發現設備？**
G-040G-Q 預設可能停用 UPnP，或防火牆阻擋 UDP 1900，都屬正常。

**Q5：HTML 報告在哪裡？**
與 `.ps1` 同一目錄，檔名 `NetFreak_<timestamp>.html`，直接用瀏覽器開啟。

**Q6：PktMon.etl 出現在目錄怎麼辦？**
```powershell
pktmon stop                                     # 停止擷取
pktmon etl2pcap PktMon.etl -o PktMon.pcapng   # 轉 Wireshark 格式
```

---

## 注意事項

- 本腳本為**唯讀診斷**，不修改任何設定。
- Port Scan 僅 TCP 連線測試，非滲透測試工具。
- MAC 廠商 / ASN / 威脅情報需要網際網路連線。
- 頻寬測試下載 1–10MB，計費網路請注意。
- 建議**不對公網 IP 執行**，Port Scan 可能觸發對方防火牆。
- `-Monitor` 模式持續消耗 CPU/網路，長時間使用請注意。

---

*NetFreak.ps1 — v1.0 / 2026-02-18 — No install. No bullshit. Full control.*
