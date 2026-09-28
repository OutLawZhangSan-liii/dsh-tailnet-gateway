<#
.SYNOPSIS
  Start `dsh web` detached, capture the tokenized URL, and save it for reuse.

.DESCRIPTION
  dsh mints a fresh random launch token per process and keeps it only in memory,
  so the tokenized URL exists nowhere except the first line dsh prints at
  startup. This launcher runs dsh with stdout redirected to a log file, parses
  the URL out of it, and writes it to dsh-web-url.txt in the plugin directory.

  The URL is a bearer credential: it is what turns into the 30-day browser
  cookie. Treat the saved file accordingly.

.PARAMETER Port
  Port for the DSH web server. Default 3080, which is what the tailnet gateway
  is configured to front.

.PARAMETER Open
  Also open the URL in the desktop browser to establish this machine's cookie.

.PARAMETER TimeoutSeconds
  How long to wait for the URL line to appear.

.EXAMPLE
  .\start-dsh-web.ps1
  .\start-dsh-web.ps1 -Open
#>
[CmdletBinding()]
param(
  [int]$Port = 3080,
  [switch]$Open,
  [int]$TimeoutSeconds = 90
)

$ErrorActionPreference = 'Stop'

$pluginDir = $PSScriptRoot
$logsDir   = Join-Path $pluginDir 'logs'
$logFile   = Join-Path $logsDir 'dsh-web.log'
$errFile   = Join-Path $logsDir 'dsh-web.err.log'
$urlFile   = Join-Path $pluginDir 'dsh-web-url.txt'

if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir -Force | Out-Null }

# Refuse to start a second server on the same port: two instances would race for
# the tailnet gateway's upstream and produce confusing half-working behavior.
$existing = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalPort -eq $Port }
if ($existing) {
  $owner = ($existing | Select-Object -First 1).OwningProcess
  $proc  = Get-Process -Id $owner -ErrorAction SilentlyContinue
  Write-Host "Port $Port is already in use by PID $owner ($($proc.ProcessName))." -ForegroundColor Yellow
  Write-Host 'Nothing started. Stop that process first if you intend to restart DSH.' -ForegroundColor Yellow
  if (Test-Path $urlFile) {
    Write-Host ''
    Write-Host 'Last captured URL:' -ForegroundColor Cyan
    Get-Content $urlFile
  }
  exit 1
}

# Locate the dsh entry point.
$dshBin = Join-Path $env:APPDATA 'npm\node_modules\@deepseek-ai\dsh\lib\bin.js'
if (-not (Test-Path $dshBin)) {
  Write-Error "Could not find the dsh entry point at: $dshBin"
}

$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { Write-Error 'node was not found on PATH.' }

foreach ($f in @($logFile, $errFile)) { if (Test-Path $f) { Remove-Item $f -Force } }

Write-Host "Starting dsh web on 127.0.0.1:$Port (detached)..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $node `
  -ArgumentList @($dshBin, 'web', '--port', "$Port") `
  -RedirectStandardOutput $logFile `
  -RedirectStandardError $errFile `
  -WindowStyle Hidden `
  -PassThru

Write-Host "PID $($proc.Id); waiting for the tokenized URL..." -ForegroundColor Cyan

# The URL is announced once, after the connection plugin has settled.
$url = $null
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline) {
  if (Test-Path $logFile) {
    $match = Select-String -Path $logFile -Pattern 'https?://\S*\?token=\S+' -ErrorAction SilentlyContinue |
      Select-Object -First 1
    if ($match) {
      $url = ($match.Matches[0].Value).Trim()
      break
    }
  }
  if ($proc.HasExited) { break }
  Start-Sleep -Milliseconds 700
}

if (-not $url) {
  Write-Host ''
  Write-Host 'Did not capture a tokenized URL.' -ForegroundColor Red
  if ($proc.HasExited) { Write-Host "dsh exited with code $($proc.ExitCode)." -ForegroundColor Red }
  Write-Host "stdout: $logFile"
  Write-Host "stderr: $errFile"
  if (Test-Path $errFile) { Get-Content $errFile -Tail 25 }
  exit 1
}

Set-Content -Path $urlFile -Value $url -Encoding UTF8

Write-Host ''
Write-Host 'DSH is up. Tokenized URL (bearer credential):' -ForegroundColor Green
Write-Host "  $url" -ForegroundColor White
Write-Host ''
Write-Host "Saved to: $urlFile"
Write-Host ''
Write-Host 'For the phone, swap the host for your tailnet name:' -ForegroundColor Cyan
$tailnetUrl = $url -replace '127\.0\.0\.1(:\d+)?', 'liiiiii.tail996200.ts.net'
Write-Host "  $tailnetUrl" -ForegroundColor White
Write-Host ''
Write-Host 'The gateway stays loopback-bound; only the tailnet hostname is substituted.' -ForegroundColor DarkGray

if ($Open) { Start-Process $url }
