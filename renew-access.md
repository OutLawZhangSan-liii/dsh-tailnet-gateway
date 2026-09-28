# Renew remote access (run this when a device shows the 401 page)

The session cookie is an **absolute 30-day** credential — it does not slide, so
every authorized browser needs renewal on day 31. Renewing means: mint a new
link, then open it in that device's browser.

```powershell
cd "D:\0文档\05 大三\大三上项目课\dsh-tailnet-gateway"

# 1. Point the tool at your tailnet origin.
$env:DSH_TAILNET_ORIGIN = 'https://liiiiii.tail996200.ts.net'

# 2. Mint a one-shot link and write grant-qr.png.
node grant-access.mjs
```

`grant-access.mjs` prints the link and writes `grant-qr.png`. Scan the QR with
the iOS Camera app (it opens in Safari) or open the link directly, **in the
browser you want to authorize**. Repeat per device: cookies live in the browser,
so each one holds its own.

## If the link 404s, the grant route is not published

```powershell
tailscale serve --bg --set-path=/grant http://127.0.0.1:7245
```

`serve` strips the `--set-path` prefix, so a browser opening `/grant/<secret>`
reaches the tool as `/<secret>`; the tool accepts both shapes.

## Useful variations

```powershell
node grant-access.mjs --days 90     # renew less often
node grant-access.mjs --days 7      # smaller blast radius
node grant-access.mjs --port 7246   # avoid a port clash
```

## Checking state before renewing

```powershell
# Are the listeners up, and both on loopback?
Get-NetTCPConnection -State Listen |
  Where-Object { $_.LocalPort -in 3080, 7242 } |
  Select-Object LocalAddress, LocalPort, OwningProcess

# Is Tailscale healthy? "NoState" / "starting" means tailscale-ipn.exe is not running.
& "C:\Program Files\Tailscale\tailscale.exe" status
Start-Process "C:\Program Files\Tailscale\tailscale-ipn.exe"   # the fix, no elevation

# Is the chain intact? (10/10 expected)
node verify.mjs all
```

## Revoking every device at once

There is no per-device logout. Stop dsh, delete the
`client-connection/browser-session` record from `%USERPROFILE%\.dsh\.credentials.yaml`,
then start dsh — a new signing secret is created and every existing cookie fails
verification. dsh reads that record only during Connection activation, so the
restart is required for the revocation to take effect.
