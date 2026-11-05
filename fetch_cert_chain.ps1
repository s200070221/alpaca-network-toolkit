<#
.SYNOPSIS
  抓取網站的憑證鏈與 TLS 版本，交給 Alpaca Network Toolkit 入口頁的「憑證檢查」離線分析。
.DESCRIPTION
  適用 Windows 內建的 Windows PowerShell 5.1 與 PowerShell 7（不需安裝任何模組）。
  只連線到你指定的主機、只記錄伺服器公開送出的憑證與協商結果，不會把資料傳到任何其他地方。
  完成後把輸出的 JSON 拖放到入口頁，或貼到「憑證檢查」卡片。
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\fetch_cert_chain.ps1 -Hosts example.com
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\fetch_cert_chain.ps1 -Hosts example.com:8443,intranet.local -Out result.json
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\fetch_cert_chain.ps1 -File hosts.txt
  （hosts.txt 一行一個主機，# 開頭為註解）
#>
param(
  [string[]]$Hosts = @(),
  [string]$File = '',
  [string]$Out = 'certchain.json',
  [int]$TimeoutSec = 10
)
$ErrorActionPreference = 'Stop'
$targets = New-Object System.Collections.Generic.List[string]
foreach ($h in $Hosts) { foreach ($p in ($h -split ',')) { if ($p.Trim()) { $targets.Add($p.Trim()) } } }
if ($File) {
  foreach ($line in (Get-Content -LiteralPath $File)) {
    $l = ($line -replace '#.*$', '').Trim()
    if ($l) { $targets.Add($l) }
  }
}
if ($targets.Count -eq 0) { Write-Host '請以 -Hosts 或 -File 指定要檢查的主機，例如：-Hosts example.com'; exit 1 }

# 各 TLS 版本（.NET 沒有定義的版本記 untested）
$protoNames = [ordered]@{ '1.0' = 'Tls'; '1.1' = 'Tls11'; '1.2' = 'Tls12'; '1.3' = 'Tls13' }
function Get-Proto([string]$name) {
  try { return [System.Security.Authentication.SslProtocols]::$name } catch { return $null }
}

# 一次 TLS 連線；回傳 @{ ok; protocol; cipher; chain; chainSource; osTrust; error }
function Invoke-Tls([string]$hostName, [int]$port, $protocols) {
  $r = @{ ok = $false; protocol = ''; cipher = ''; chain = @(); chainSource = 'server'; osTrust = $null; error = ''; code = '' }
  $tcp = New-Object System.Net.Sockets.TcpClient
  try {
    $iar = $tcp.BeginConnect($hostName, $port, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutSec * 1000)) { throw "連線逾時（$TimeoutSec 秒）" }
    $tcp.EndConnect($iar)
    $tcp.ReceiveTimeout = $TimeoutSec * 1000; $tcp.SendTimeout = $TimeoutSec * 1000
    $script:captured = $null
    # 憑證一律先接受：檢查由入口頁做，這裡只負責收集伺服器送出的內容
    $cb = [System.Net.Security.RemoteCertificateValidationCallback] {
      param($s, $cert, $chain, $errors)
      $script:captured = @{ cert = $cert; chain = $chain; errors = $errors }
      return $true
    }
    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $cb)
    try {
      $ssl.AuthenticateAsClient($hostName, $null, $protocols, $false)
      $r.ok = $true
      $r.protocol = [string]$ssl.SslProtocol
      try { $r.cipher = [string]$ssl.NegotiatedCipherSuite } catch { $r.cipher = '' }
      if (-not $r.cipher -or $r.cipher -eq '0') { $r.cipher = [string]$ssl.CipherAlgorithm + ' ' + [string]$ssl.CipherStrength }
      $c = $script:captured
      if ($c) {
        $leaf = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($c.cert)
        $list = New-Object System.Collections.Generic.List[string]
        $list.Add([Convert]::ToBase64String($leaf.RawData))
        # 伺服器送出的中繼憑證在 ExtraStore（.NET 5 以後）；拿不到時改記作業系統建出的鏈
        $extra = $null
        try { $extra = $c.chain.ChainPolicy.ExtraStore } catch { }
        if ($extra -and $extra.Count -gt 0) {
          foreach ($x in $extra) { if ($x.Thumbprint -ne $leaf.Thumbprint) { $list.Add([Convert]::ToBase64String($x.RawData)) } }
        } elseif ($c.chain -and $c.chain.ChainElements.Count -gt 1) {
          $r.chainSource = 'os'
          for ($i = 1; $i -lt $c.chain.ChainElements.Count; $i++) { $list.Add([Convert]::ToBase64String($c.chain.ChainElements[$i].Certificate.RawData)) }
        }
        $r.chain = $list.ToArray()
        $status = @()
        if ($c.chain) { foreach ($s in $c.chain.ChainStatus) { $status += [string]$s.Status } }
        $r.osTrust = @{ ok = ([string]$c.errors -eq 'None'); status = @(@([string]$c.errors) + $status | Where-Object { $_ -and $_ -ne 'None' -and $_ -ne 'NoError' } | Select-Object -Unique) }
      }
    } finally { $ssl.Dispose() }
  } catch {
    $e = $_.Exception
    while ($e.InnerException) { $e = $e.InnerException }
    $r.error = ($e.Message -replace '\s+', ' ').Trim()
    $r.code = '0x{0:X8}' -f $e.HResult
  } finally { $tcp.Close() }
  return $r
}

$results = @()
foreach ($t in $targets) {
  $hostName = ''; $port = 443
  if ($t -match '^\[([0-9A-Fa-f:]+)\](?::(\d{1,5}))?$') { $hostName = $Matches[1]; if ($Matches[2]) { $port = [int]$Matches[2] } }
  elseif ($t -match '^(?:https?://)?([A-Za-z0-9._-]+)(?::(\d{1,5}))?(?:/.*)?$') { $hostName = $Matches[1]; if ($Matches[2]) { $port = [int]$Matches[2] } }
  else { Write-Host "略過格式不正確的主機：$t"; continue }
  Write-Host "檢查 ${hostName}:$port ..."
  $all = [System.Security.Authentication.SslProtocols]::None
  $main = Invoke-Tls $hostName $port $all
  $tls = [ordered]@{}
  foreach ($k in $protoNames.Keys) {
    $p = Get-Proto $protoNames[$k]
    if (-not $main.ok -or $null -eq $p) { $tls[$k] = 'untested'; continue }
    $one = Invoke-Tls $hostName $port $p
    # 用戶端本身停用該版本（例如較新的 Windows 已停用 TLS 1.0／1.1）時無法判斷，記 untested
    if ($one.ok) { $tls[$k] = 'yes' }
    # Windows：SEC_E_ALGORITHM_MISMATCH（0x80090331，訊息依系統語言而異）；Linux／macOS：no protocols available
    elseif ($one.code -eq '0x80090331' -or $one.error -match 'no protocols available|not supported|SEC_E_ALGORITHM_MISMATCH|cannot communicate') { $tls[$k] = 'untested' }
    else { $tls[$k] = 'no' }
  }
  $results += [ordered]@{
    host = $hostName; port = $port; chain = $main.chain; chainSource = $main.chainSource; tls = $tls
    negotiated = @{ protocol = $main.protocol; cipher = $main.cipher }; osTrust = $main.osTrust; error = $main.error
  }
}
$doc = [ordered]@{
  format = 'alpaca-certchain'; version = 1; tool = 'fetch_cert_chain.ps1'; date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  client = "PowerShell $($PSVersionTable.PSVersion) / $([Environment]::OSVersion.VersionString)"; hosts = $results
}
$json = $doc | ConvertTo-Json -Depth 6
$outPath = if ([System.IO.Path]::IsPathRooted($Out)) { $Out } else { Join-Path (Get-Location).Path $Out }
[System.IO.File]::WriteAllText($outPath, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "完成：$Out（只含公開憑證與連線資訊，可拖放到入口頁的「憑證檢查」）"
