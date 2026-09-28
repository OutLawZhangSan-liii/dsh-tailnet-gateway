# dsh-tailnet-gateway

Control the DeepSeek Harness running on your own computer from your phone — or
any other device on your private [Tailscale](https://tailscale.com) network —
**without exposing dsh, your LAN, or the public internet.**

This repository contains two cooperating pieces:

| Piece | What it is |
|---|---|
| `lib/index.js` | A DSH plugin: an authenticated reverse proxy that publishes a loopback-bound dsh to your tailnet |
| `grant-access.mjs` | A companion tool that authorizes a browser you cannot hand a cookie to by hand |

Developed and verified against `dsh` 0.1.5-rc.1 (Web profile, Windows).

---

## The control logic

The whole design follows from one fact about dsh: **its browser surface is
loopback-only on purpose, and it defends that with two separate fences.**

| Fence | What it guards | Can `--trusted-host` open it? |
|---|---|---|
| Request trust (`dsh-client-connection`) | The `Host` header must be loopback or a configured trusted authority. Blocks DNS rebinding and cross-site calls. | **Yes** |
| Privileged methods | `settings.*`, `credentials.*`, `agentPreset.*`, `host.pickDirectory`, `llm.discoverModels` are served **only to loopback callers**, and that branch re-runs the check with an *empty* trust list. | **No** |

So the obvious approaches fail in a specific way:

- `dsh web --host 0.0.0.0` is **refused outright**. Its own error text says it
  "would expose remote code execution to the network".
- Binding wider plus `--trusted-host` still leaves a half-working app: chat
  works, but Settings/Models/Plugins report *"unavailable in this browser"*,
  because `dsh-client-ui-settings` picks its store via
  `ctx.remote.$host.isLoopback ? "host" : "memory"`, and `"memory"` publishes an
  `"unavailable"` status **without ever issuing an RPC**.

**This plugin does not widen either fence.** It puts a *second front door* in
front of them.

## The link chain

```
   phone (Tailscale app)
      │
      │  1. WireGuard, end-to-end encrypted, tailnet members only
      ▼
   tailscaled  ──  2. terminates TLS for the *.ts.net name
      │            3. stamps Tailscale-User-Login + X-Forwarded-For,
      │               OVERWRITING whatever the client sent
      ▼
   tailscale serve :443  ──  4. published with: tailscale serve --bg 7242
      │
      ▼
   gateway  127.0.0.1:7242   ──  5. this plugin. Two gates:
      │                             - the stamped login must be allowed
      │                             - optional per-device tailnet IP allowlist
      │                         6. rewrites Host/Origin/Referer to the
      │                            loopback authority, then forwards
      ▼
   dsh web  127.0.0.1:3080   ──  7. sees a genuine loopback call from this
                                     machine, so the privileged fence is
                                     satisfied honestly — not bypassed
```

Three properties make this sound rather than clever:

1. **The identity is evidence, not a claim.** `tailscaled` overwrites the
   identity headers on every proxied request, so a tailnet peer cannot name
   itself. A request arriving without them is refused.
2. **Nothing is exposed.** Both listeners stay on `127.0.0.1`. The gateway's
   bind address is *clamped* to loopback in two places, because a gateway
   reachable from a network interface would hand loopback trust to anyone who
   asked — and a direct caller *can* forge those headers.
3. **A refused request never reaches dsh** — not even as a probe. The decision
   happens before any upstream connection is opened.

## Security model

Load-bearing behaviors, each pinned by a test in `test/gateway.test.js`:

- Loopback-clamped bind: `resolveConfig` clamps, `startGateway` throws.
- Fail-closed admission: a missing identity header is a refusal, not a pass; a
  peer allowlist that cannot be evaluated refuses.
- `X-Forwarded-For` is read from the **first** entry (the original client).
  Reading the last would let a client that can set the header choose its identity.
- `Host`, `Origin` and `Referer` are rewritten to the loopback authority.
  Left as the tailnet URL, dsh reads the call as cross-origin and rejects it.
- The WebSocket event stream is gated identically on the upgrade path.
- `close()` settles with tunnels open. Node's `closeAllConnections()` does *not*
  include upgraded sockets, so both ends of every tunnel are destroyed explicitly.

### What this does NOT protect against

- **A local process on the machine.** It can reach `127.0.0.1:7242` directly and
  forge the identity headers, because it never passes through `tailscaled`. This
  is inherent to any loopback-trusting hop and is exactly why the loopback clamp
  is load-bearing. Such a process could already reach dsh on `127.0.0.1:3080`,
  but note the honest difference: dsh's own privileged fence would still refuse
  it the privileged methods, while this gateway would grant them. **Do not treat
  this as a boundary against code already running as you.**
- **A compromised tailnet device**, or anyone who obtains your Tailscale
  account. Tailscale ACLs and device authorization are the boundary there.
  `allowedLogins` and `allowedPeers` narrow it further.
- **Data at rest on the phone.** The session cookie is `HttpOnly` and
  `SameSite=Strict` and travels inside TLS, but it is bearer-equivalent for its
  lifetime (30 days by default).

## What works from the phone

| Capability | Over the tailnet |
|---|---|
| Chat, run agents, tools, jobs, workflows | **Works** |
| File browse / upload, session and goal views | **Works** |
| Settings, Models, Plugins, Agent presets | **Unavailable** in the browser UI |

The last row is deliberate. This plugin implements the *access* half of the
gateway, not the client-side bundle override: those pages degrade to read-only
rather than erroring, and **the server-side fence stays in force**. Widening it
would mean patching a build artifact, which breaks on upgrade and trades a real
security property for a convenience.

---

## Install

### 1. The plugin

The plugin is a single dependency-free ES module. Mount it from the Web
profile's own patch layer — `%USERPROFILE%\.dsh\profiles\web\cordis.patch.yml`:

```yaml
- insert:
    - id: tailnet-gateway
      name: '<absolute path to this repo>/lib/index.js'
      config:
        upstreamPort: 3080
```

The path must name an **entry file**, not a directory: the loader hands it to
Node's ESM resolver, which rejects directory imports
(`ERR_UNSUPPORTED_DIR_IMPORT`).

If the profile declares `patchReload: live`, the running dsh picks the row up
without a restart. Verify rather than assume:

```powershell
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 3080, 7242 } |
  Select-Object LocalAddress, LocalPort, OwningProcess
```

Both listeners must show `127.0.0.1` and the same dsh PID. A `0.0.0.0` there is
a bug worth reporting, not a convenience.

### 2. Tailscale

Two one-time browser approvals are required, and neither is scriptable:

1. **Enable Serve for the tailnet.** `tailscale serve --bg 7242` prints
   `Serve is not enabled on your tailnet` plus an authorization link.
2. **Enable HTTPS certificates** at `https://login.tailscale.com/admin/dns`
   under **HTTPS Certificates**. Until this is on, `tailscale cert` fails with
   `500 ... does not support getting TLS certs` and `tailscale serve` fails with
   `unexpected state: NoState` — the same root cause, because Serve provisions a
   real certificate for the `*.ts.net` name.

Then publish the gateway:

```powershell
tailscale serve --bg 7242
tailscale serve status
```

### 3. Authorize a browser

```powershell
$env:DSH_TAILNET_ORIGIN = 'https://<machine>.<tailnet>.ts.net'
node grant-access.mjs
```

It prints the one-shot link and writes a QR of it, then instructs you to publish
the grant route if needed:

```powershell
tailscale serve --bg --set-path=/grant http://127.0.0.1:7245
```

Open the link on the device you want to authorize. Afterwards the only URL that
matters is the bare origin:

```
https://<machine>.<tailnet>.ts.net/
```

Add it to the home screen. The cookie lasts 30 days and **survives `dsh web`
restarts**, because the signing secret is durable — you do not need a token
again on that device.

## The 30-day expiry, and what to do about it

The session cookie is an **absolute** 30-day credential. It is not a sliding
window: using the app every day does not extend it. On day 31 that browser gets
the 401 page again.

### What you will see

The 401 page reading `dsh web authentication required; reopen the URL printed by
dsh web`. Nothing is broken and nothing is lost — the browser simply has no
valid session any more. Conversations, workspaces and settings are all server
side and unaffected.

### What to do (one command, per device)

Re-run the grant tool and open the new link **in that device's browser**:

```powershell
$env:DSH_TAILNET_ORIGIN = 'https://<machine>.<tailnet>.ts.net'
node grant-access.mjs
```

It prints a fresh one-shot link and writes `grant-qr.png`. Scan the QR (the iOS
Camera app opens it in Safari) or open the link directly, and the device is good
for another 30 days. Repeat per device — cookies are per-browser, and each
device holds its own.

**If the grant route is no longer published**, re-attach it first:

```powershell
tailscale serve --bg --set-path=/grant http://127.0.0.1:7245
```

### Choosing a different lifetime

```powershell
node grant-access.mjs --days 90      # longer: less renewal, bigger blast radius
node grant-access.mjs --days 7       # shorter: more renewal, smaller blast radius
```

The trade is the usual one for a bearer credential: the cookie is
`HttpOnly` + `SameSite=Strict` and travels inside TLS, but anyone holding it can
act as you for its whole lifetime. It is stored per-browser, so it cannot be
revoked on one device only — see below.

### Revoking early

There is no per-device logout. dsh's own model is that the browser cookie is
signed with the owner-scoped `client-connection/browser-session` record, so the
way to invalidate **every** device at once is to make that record stop matching:

1. Stop dsh.
2. Delete the `client-connection/browser-session` record from
   `%USERPROFILE%\.dsh\.credentials.yaml`.
3. Start dsh. A new signing secret is created on activation, and every existing
   cookie fails signature verification.
4. Re-grant each device you still want.

Note that dsh reads this record once during Connection activation, so step 3 is
required — deleting it while dsh runs does not revoke anything until the next
start.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Run the listener at all. |
| `host` | `127.0.0.1` | Bind address. **Clamped** to loopback; a non-loopback value is refused. |
| `port` | `7242` | The port `tailscale serve` publishes. `0` requests an OS-assigned port. |
| `requireLogin` | `true` | Demand the Tailscale identity. Turning this off makes the listener an open loopback proxy. |
| `allowedLogins` | `[]` | Tailscale logins allowed. Empty means any account on the tailnet. |
| `allowedPeers` | `[]` | Optional per-device gate: tailnet IPs as `tailscale status` reports them. |
| `upstreamPort` | `3080` | The dsh web port being fronted. |

### Hardening

On a single-user tailnet the defaults are already correct. To narrow further,
fill `allowedPeers` with your phone's tailnet address — that is what makes
"my phone, never that VPS" expressible even when the VPS is signed in as you:

```yaml
      config:
        upstreamPort: 3080
        allowedLogins: ['you@example.com']
        allowedPeers: ['100.64.0.7']
```

Fill it **before** relying on it: a peer allowlist that does not match the
machine you are calling from locks you out of the tailnet surface. The local
desktop at `127.0.0.1:3080` still works, so the fix is a local edit.

## Verify

```powershell
node --test test/gateway.test.js     # 15 unit + real-socket integration tests
node verify.mjs all                  # live gateway + full TLS chain
node verify.mjs cookie "<pair>"      # a specific cookie authenticates dsh
```

Three widening rings, so a failure localises the problem: `live` failing means
the plugin is not mounted or is bound wrongly; `chain` failing means Tailscale,
DNS or the certificate; `cookie` failing means the cookie's authority does not
match this instance.

`chain` treats a **401** from `/` as success. It proves dsh's own session check
answered, so every hop in front of it worked. A 502 or 403 there means the chain
is broken.

## Operational notes

**The dsh process must stay running.** `tailscale serve` reaches the gateway on
this machine, so closing the terminal that started `dsh web` takes the tailnet
surface down with it. `start-dsh-web.ps1` starts it detached (surviving the
terminal), captures the tokenized URL to a file, and prints the phone-ready link.

**Do not skip the Tailscale GUI process.** `tailscale-ipn.exe` must be running.
Without it the service is up but reports `BackendState: NoState` and *every*
`tailscale` command fails, including Serve. A reinstall or upgrade commonly kills
it:

```powershell
Start-Process "C:\Program Files\Tailscale\tailscale-ipn.exe"   # no elevation needed
```

There is often no autostart entry for it, so enable **Run unattended** in the
tray menu if you want remote access to survive reboot.

**`tailscale cert` writes a private key into the current directory.** Serve does
not need those copies (tailscaled keeps its own), so delete any `*.key` it drops.

**Non-obvious Serve behavior, learned the hard way:** `--set-path=/grant`
**strips** the prefix before forwarding, so a browser opening `/grant/<secret>`
arrives at the grant server as `/<secret>`. `grant-access.mjs` accepts both
shapes so they never have to agree. A mismatched assumption here makes the
server consume the grant while answering 404 — a genuinely confusing failure.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `tailscale status` says "starting", `NoState` | `tailscale-ipn.exe` not running | start it (see above) |
| `tailscale cert` 500, `serve` `NoState` | HTTPS certificates not enabled | enable at admin/dns |
| Port-qualified URL shows `404 page not found` | only `:443` is published; `--set-path` routes 404 at their root | use the bare origin |
| 401 page, but `/check`-style probe shows no cookie | that browser was never granted a session (cookie stores are per-app, and private windows discard them) | open a grant link **in that specific browser** |
| 401 on the bare origin after a grant | cookie authority mismatch, or the grant went to a different browser | re-run `grant-access.mjs`, open it in the same browser |

## Rollback

Remove the `tailnet-gateway` insert from `cordis.patch.yml` and restart dsh, then
`tailscale serve --https=443 off`. The plugin writes no files and needs no
package install, so nothing else on the machine changes.

## License

MIT
