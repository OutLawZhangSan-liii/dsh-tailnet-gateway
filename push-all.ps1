# Push the current branch to both hosts.
#
#   .\push-all.ps1              # push main
#   .\push-all.ps1 -Branch dev  # push another branch
#
# `origin` is Gitee and `github` is GitHub. GitHub has intermittently been
# unreachable from this network over HTTPS; SSH is the transport that works, and
# it needs this machine's public key registered on BOTH accounts (they are
# separate registrations — a key trusted by one host is not trusted by the other).
[CmdletBinding()]
param(
  [string]$Branch = 'main'
)

$ErrorActionPreference = 'Continue'
$failed = @()

foreach ($remote in @('origin', 'github')) {
  $url = (git remote get-url $remote 2>$null)
  if (-not $url) {
    Write-Host "[skip] $remote is not configured" -ForegroundColor Yellow
    $failed += $remote
    continue
  }

  Write-Host "==> $remote ($url)" -ForegroundColor Cyan
  git push -u $remote $Branch 2>&1 | ForEach-Object { "    $_" }
  if ($LASTEXITCODE -ne 0) {
    Write-Host "    FAILED" -ForegroundColor Red
    $failed += $remote
  } else {
    Write-Host "    ok" -ForegroundColor Green
  }
}

Write-Host ''
foreach ($remote in @('origin', 'github')) {
  $head = (git ls-remote --heads $remote $Branch 2>$null)
  if ($head) { Write-Host ("{0,-7}: {1}" -f $remote, $head) }
}
Write-Host ("{0,-7}: {1}" -f 'local', (git rev-parse HEAD))

if ($failed.Count -gt 0) {
  Write-Host ''
  Write-Host "Failed: $($failed -join ', ')" -ForegroundColor Red
  Write-Host 'GitHub over HTTPS is blocked from this network; SSH is the working path.' -ForegroundColor DarkGray
  Write-Host 'If SSH reports "Permission denied (publickey)", this key is not registered there:' -ForegroundColor DarkGray
  Get-Content "$env:USERPROFILE\.ssh\id_ed25519.pub"
  exit 1
}
