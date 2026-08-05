# fetch_threat_intel.ps1 — 下載並合併公開黑名單 IP/CIDR 情資清單，輸出 NDJSON 供 log_analyzer
# 「④ 威脅情資本機比對清單」的「上傳清單」按鈕匯入。
#
# 用法:
#   .\log_analyzer\fetch_threat_intel.ps1
#   .\log_analyzer\fetch_threat_intel.ps1 -OutFile my_intel.ndjson -TimeoutSec 20
#   .\log_analyzer\fetch_threat_intel.ps1 -Exclude dshield,cins_army
#
# 若直接雙擊或執行時出現「因為這個系統上已停用指令碼執行，所以無法載入 xxx.ps1」，這是
# Windows 預設執行原則（多數 Windows 用戶端預設 Restricted，會擋下所有 .ps1，與本腳本內容
# 無關）造成的，非腳本本身的錯誤，二擇一即可解決：
#   (1) 單次執行、不更動全域設定（建議）：
#       powershell -ExecutionPolicy Bypass -File .\fetch_threat_intel.ps1
#   (2) 或放寬目前使用者帳號的執行原則（僅影響自己的帳號，不需系統管理員權限，之後可直接
#       用 .\fetch_threat_intel.ps1 執行）：
#       Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
# 若此檔案是從瀏覽器下載（如從 GitHub），Windows 有時會額外標記為「來自網際網路」多一層
# 封鎖，看到「未知發行者」或簽章相關警告時可先執行 Unblock-File .\fetch_threat_intel.ps1
# 解除標記再重試。
#
# 【重要】不要用「以系統管理員身分執行」開的視窗跑這支腳本——本腳本純粹下載公開清單與寫
# 一個文字檔，完全不需要系統管理員權限；上面 (1)(2) 兩種解法在一般使用者權限視窗即可運作。
# 實測發現部分企業防毒/EDR 對「提權後 PowerShell 寫出的檔案」會有額外稽核或事後清除機制，
# 導致腳本本身印出「已輸出至 xxx」成功訊息、.NET 呼叫也沒有丟例外，但檔案事後被悄悄清掉、
# Test-Path 查回 False；改用一般（非管理員）PowerShell 視窗執行即可正常保留檔案。
#
# log_analyzer 本身刻意不連網（機敏 log 去識別化工具的核心保證，見 guide.body／footer 文案），
# 本腳本獨立於瀏覽器之外執行，下載合併完成後需手動匯入，工具本身不會被此腳本改動任何連網行為。
#
# 輸出格式為 NDJSON（逐行各自一個合法 JSON 物件），每筆含 cidr／source 兩欄；source 為逗號
# 分隔的來源清單（同一網段被多個來源收錄時自動合併，不重複匯入）。log_analyzer 既有 JSON/NDJSON
# 情資匯入邏輯（IP_FIELD_RE 比對到 cidr 欄位即視為 IP 型別欄位）可直接讀取，source 欄位會保留在
# intelMeta，命中時會顯示在「問題清單」的「比對依據」欄。
#
# 各來源已於 2026-08-05 對外查證實際檔案格式（非照抄來源網站描述），見 now.md 對應段落：
# - spamhaus_drop/edrop、firehol_level1~4、emergingthreats_block、abusech_feodo、cins_army、
#   blocklist_de：皆為純文字、每行一個 IP 或 CIDR，可直接抓取。
# - dshield：實際為 tab 分隔多欄位表格（起始IP/結束IP/子網路遮罩位數/...），並非單欄 CIDR 清單；
#   若直接取每行第一欄只會拿到網段起始 IP、涵蓋率大幅降低，本腳本改用第 1+3 欄正確組成 CIDR。
# - abuse.ch SSL Blacklist 已於 2025-01-03 起標記 deprecated，未列入。AbuseIPDB 需註冊/API 金鑰，
#   非單純網址即可下載的清單，亦未列入。
# - FireHOL Level 1~4 為官方自訂風險分級（數字越大涵蓋越廣但誤判率也越高，Level 4 官方文件
#   明載「may include a large number of false positives」）：Level1 已存在多年、高信心度；
#   Level2 近 48 小時攻擊；Level3 近 30 日攻擊/間諜軟體/病毒；Level4 誤判率最高，資料量也
#   最大（實測約 11.7 萬筆），用於一般 log 分析情境時建議優先參考 Level1~3 的命中結果。

param(
    [string]$OutFile = "threat_intel_merged.ndjson",
    [int]$TimeoutSec = 30,
    [string[]]$Exclude = @()
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# spamhaus_edrop 已於實測時發現內容僅剩註解「This list has been merged into drop.txt」，
# Spamhaus 已將 EDROP 併入 DROP 本身，不再獨立維護，故不列入來源（避免每次執行多打一支必定
# 落空的請求）；drop.txt 本身已涵蓋原 EDROP 範圍
$Sources = @(
    @{ Name = 'spamhaus_drop';         Url = 'https://www.spamhaus.org/drop/drop.txt';                          Parser = 'SpamhausStyle' }
    @{ Name = 'firehol_level1';        Url = 'https://iplists.firehol.org/files/firehol_level1.netset';         Parser = 'PlainList' }
    @{ Name = 'firehol_level2';        Url = 'https://iplists.firehol.org/files/firehol_level2.netset';         Parser = 'PlainList' }
    @{ Name = 'firehol_level3';        Url = 'https://iplists.firehol.org/files/firehol_level3.netset';         Parser = 'PlainList' }
    @{ Name = 'firehol_level4';        Url = 'https://iplists.firehol.org/files/firehol_level4.netset';         Parser = 'PlainList' }
    @{ Name = 'emergingthreats_block'; Url = 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt'; Parser = 'PlainList' }
    @{ Name = 'abusech_feodo';         Url = 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt';        Parser = 'PlainList' }
    @{ Name = 'cins_army';             Url = 'https://cinsscore.com/list/ci-badguys.txt';                       Parser = 'PlainList' }
    @{ Name = 'blocklist_de';          Url = 'https://www.blocklist.de/downloads/export-ips_all.txt';           Parser = 'PlainList' }
    @{ Name = 'dshield';               Url = 'https://www.dshield.org/block.txt';                               Parser = 'DShieldTable' }
)

function Parse-PlainList {
    param([string[]]$Lines)
    $Lines | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object { ($_ -split '\s+')[0] }
}

function Parse-SpamhausStyle {
    param([string[]]$Lines)
    # 資料行為 "CIDR ; SBLID"，註解行以 ';' 開頭（跟資料行中間的 ';' 分隔符不同，不可用同一條件混淆）
    $Lines | Where-Object { $_ -and -not $_.StartsWith(';') } | ForEach-Object { ($_ -split ';')[0].Trim() }
}

function Parse-DShieldTable {
    param([string[]]$Lines)
    foreach ($line in $Lines) {
        if (-not $line -or $line.StartsWith('#')) { continue }
        $cols = $line -split "`t"
        if ($cols.Count -lt 3) { continue }
        $start = $cols[0].Trim()
        $bits = $cols[2].Trim()
        if ($start -and $bits) { "$start/$bits" }
    }
}

# Windows PowerShell 5.1 的 Invoke-WebRequest 在伺服器回傳 Content-Type: application/octet-stream
# 時（firehol_level1.netset 即此情況，經實測發現），.Content 會是 Byte[] 而非解碼過的字串，
# 直接 -split 會逐 byte 拆開變成亂碼；此處統一判斷型別後手動以 UTF8 解碼，避免此坑
function Get-ResponseText {
    param($Response)
    if ($Response.Content -is [byte[]]) {
        return [System.Text.Encoding]::UTF8.GetString($Response.Content)
    }
    return $Response.Content
}

function Test-ValidCidr {
    param([string]$Value)
    if ($Value -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/(\d{1,2}))?$') {
        foreach ($octet in @($Matches[1], $Matches[2], $Matches[3], $Matches[4])) {
            if ([int]$octet -gt 255) { return $false }
        }
        if ($Matches[6] -and [int]$Matches[6] -gt 32) { return $false }
        return $true
    }
    return $false
}

# 私有/保留位址網段一律過濾掉，不寫進輸出檔案：這些網段本身不會是真正的「外部攻擊者來源」，
# 卻常被公開清單（尤其 FireHOL Level 1）當成 bogon／偽造來源防護用途一併收錄——已實測驗證
# firehol_level1.netset 真的包含 10.0.0.0/8、172.16.0.0/12、192.168.0.0/16 整段三筆。對
# 「拿情資清單比對自己內部 log 找可疑活動」這個用途，這是純粹雜訊：會把每一筆內網對內網
# 流量都誤標成「已知情資命中」，完全淹沒真正有意義的結果
function ConvertTo-IPInt {
    param([string]$Ip)
    $p = $Ip.Split('.')
    return ([long]$p[0] * 16777216) + ([long]$p[1] * 65536) + ([long]$p[2] * 256) + [long]$p[3]
}
function Get-CidrMaskLong {
    param([int]$Bits)
    if ($Bits -eq 0) { return [long]0 }
    return [long][math]::Pow(2, 32) - [long][math]::Pow(2, 32 - $Bits)
}
$PrivateReservedRanges = @(
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'
) | ForEach-Object {
    $parts = $_ -split '/'
    $mask = Get-CidrMaskLong ([int]$parts[1])
    [pscustomobject]@{ Base = (ConvertTo-IPInt $parts[0]) -band $mask; Mask = $mask }
}
function Test-IsPrivateOrReserved {
    param([string]$Value)
    $ipInt = ConvertTo-IPInt (($Value -split '/')[0])
    foreach ($r in $PrivateReservedRanges) {
        if (($ipInt -band $r.Mask) -eq $r.Base) { return $true }
    }
    return $false
}

$merged = @{}
$summary = @()

foreach ($src in $Sources) {
    if ($Exclude -contains $src.Name) {
        Write-Host "略過（-Exclude 指定）: $($src.Name)" -ForegroundColor DarkGray
        continue
    }
    Write-Host "下載中: $($src.Name) ..." -ForegroundColor Cyan
    try {
        $resp = Invoke-WebRequest -Uri $src.Url -UseBasicParsing -TimeoutSec $TimeoutSec
        $lines = (Get-ResponseText $resp) -split "`r?`n"
    } catch {
        Write-Warning "  跳過 $($src.Name)：下載失敗（$($_.Exception.Message)）"
        $summary += [pscustomobject]@{ Source = $src.Name; Count = 0; Status = '失敗' }
        continue
    }

    $values = switch ($src.Parser) {
        'PlainList'     { Parse-PlainList $lines }
        'SpamhausStyle' { Parse-SpamhausStyle $lines }
        'DShieldTable'  { Parse-DShieldTable $lines }
    }

    $count = 0
    $skippedPrivate = 0
    foreach ($v in $values) {
        if (-not (Test-ValidCidr $v)) { continue }
        if (Test-IsPrivateOrReserved $v) { $skippedPrivate++; continue }
        if (-not $merged.ContainsKey($v)) { $merged[$v] = [System.Collections.Generic.HashSet[string]]::new() }
        [void]$merged[$v].Add($src.Name)
        $count++
    }
    Write-Host "  取得 $count 筆合法網段（另過濾 $skippedPrivate 筆私有/保留位址）" -ForegroundColor Green
    $summary += [pscustomobject]@{ Source = $src.Name; Count = $count; SkippedPrivate = $skippedPrivate; Status = 'OK' }
}

$ndjsonLines = foreach ($key in $merged.Keys) {
    [pscustomobject]@{ cidr = $key; source = ($merged[$key] -join ',') } | ConvertTo-Json -Compress
}
# Windows PowerShell 5.1 的 Set-Content -Encoding utf8 會加上 UTF-8 BOM，導致檔案第一行變成
# "﻿{...}" 讓 log_analyzer 的 JSON.parse 直接在第一筆情資就失敗；改用 .NET API 明確指定
# 不寫 BOM（UTF8Encoding($false)），比照 NDJSON/JSON 檔案不帶 BOM 的一般慣例
[System.IO.File]::WriteAllLines($OutFile, $ndjsonLines, (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "=== 各來源筆數 ===" -ForegroundColor Cyan
$summary | Format-Table -AutoSize
Write-Host "合併去重後共 $($merged.Count) 筆網段，已輸出至 $OutFile" -ForegroundColor Green
Write-Host "請至 log_analyzer 頁面「④ 威脅情資本機比對清單」→「上傳清單」匯入此檔案。" -ForegroundColor Yellow
