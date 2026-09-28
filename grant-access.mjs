/**
 * Grant a browser session over the tailnet, and print the link plus a QR code.
 *
 * ## Why this exists
 *
 * dsh mints a random launch token per process and keeps it in a `WeakMap`, so
 * the tokenized URL exists nowhere except the first line dsh prints. Lose that
 * line and there is no way back — *except* that the cookie signing secret is
 * durable (`~/.dsh/.credentials.yaml`, `client-connection/browser-session`).
 * This tool re-derives the exact cookie the server would have issued, using the
 * same construction, and hands it to one browser over HTTPS.
 *
 * ## Usage
 *
 *   node grant-access.mjs                       # mint a link, print it, write a QR
 *   node grant-access.mjs --serve               # ...and print the serve command
 *   node grant-access.mjs --authority 127.0.0.1:3080 --days 30
 *   node grant-access.mjs --url-only            # just print a minted cookie header
 *
 * Serving the grant route:
 *
 *   tailscale serve --bg --set-path=/grant http://127.0.0.1:7245
 *   node grant-access.mjs --serve
 *
 * Note: `tailscale serve` STRIPS the `--set-path` prefix, so the browser opens
 * `/grant/<secret>` while the grant server receives `/<secret>`. Both are
 * accepted below so the two never have to agree.
 *
 * ## Security posture
 *
 *   - the grant path is 32 random bytes, held only in memory
 *   - the request must carry the expected Tailscale login, so a caller outside
 *     the tailnet cannot use the link even if they learn it
 *   - exactly one grant is issued per path; later hits redirect to `/`
 *   - the signing secret never leaves this machine
 *
 * @module dsh-tailnet-gateway/grant-access
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir } from 'node:os';
import { join } from 'node:path';

/** Shared constants — these mirror dsh-client-connection exactly. */
const COOKIE_PREFIX = 'dsh-auth-';
const COOKIE_PAYLOAD_VERSION = 1;
const SECRET_BYTES = 32;

const b64url = (buf) =>
  Buffer.from(buf).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');

/** Parse `--flag value` pairs without a dependency. */
function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) {
      out._.push(token);
      continue;
    }
    const key = token.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) {
      out[key] = true;
      continue;
    }
    out[key] = next;
    i += 1;
  }
  return out;
}

/**
 * Read the browser-session signing secret from this machine's credential store.
 *
 * The store is a small YAML document. Parsing it line-wise keeps this tool free
 * of a YAML dependency; the shape we need is a flat `secret: <base64url>` under
 * the `client-connection/browser-session` record.
 *
 * @returns {{secret: Buffer, path: string}} the 32-byte secret and its source.
 */
function readSigningSecret() {
  const path = join(homedir(), '.dsh', '.credentials.yaml');
  const lines = readFileSync(path, 'utf8').split(/\r?\n/);
  let inRecord = false;
  let recordIndent = -1;
  for (const line of lines) {
    if (/^\s*client-connection\/browser-session\s*:/.test(line)) {
      inRecord = true;
      recordIndent = line.length - line.trimStart().length;
      continue;
    }
    if (!inRecord) continue;
    const indent = line.length - line.trimStart().length;
    const trimmed = line.trim();
    // A non-blank line at or below the record's indent ends the record.
    if (trimmed !== '' && indent <= recordIndent) {
      inRecord = false;
      continue;
    }
    const match = /^secret\s*:\s*(\S+)\s*$/.exec(trimmed);
    if (match) {
      const bytes = Buffer.from(match[1].replaceAll('-', '+').replaceAll('_', '/'), 'base64');
      if (bytes.byteLength !== SECRET_BYTES) {
        throw new Error(`browser-session secret is ${bytes.byteLength} bytes, expected ${SECRET_BYTES}`);
      }
      return { secret: bytes, path };
    }
  }
  throw new Error(`no browser-session secret found in ${path}`);
}

/**
 * Build the cookie pair the server would have set for `authority`.
 *
 * The authority is the value the gateway rewrites `Host` to — for the shipped
 * composition that is `127.0.0.1:3080`, NOT the tailnet name. The cookie's name
 * and payload both bind to it, so a mismatch is silently rejected.
 *
 * @param {Buffer} secret - the signing secret.
 * @param {string} authority - `host:port` the cookie is bound to.
 * @param {number} days - lifetime in days.
 * @returns {{name: string, pair: string, setCookie: string, expiresAt: number}} the cookie.
 */
function mintCookie(secret, authority, days) {
  const name = COOKIE_PREFIX + b64url(createHash('sha256').update(authority).digest());
  const issuedAt = Date.now();
  const expiresAt = issuedAt + days * 24 * 60 * 60 * 1000;
  const body = b64url(
    Buffer.from(JSON.stringify({ version: COOKIE_PAYLOAD_VERSION, authority, issuedAt, expiresAt }), 'utf8'),
  );
  const value = `v1.${body}.${b64url(createHmac('sha256', secret).update(body).digest())}`;
  const pair = `${name}=${value}`;
  const setCookie =
    `${pair}; Max-Age=${days * 24 * 60 * 60}; Path=/; ` +
    `Expires=${new Date(expiresAt).toUTCString()}; HttpOnly; SameSite=Strict`;
  return { name, pair, setCookie, expiresAt };
}

/** Start the one-shot grant server. Stays up so repeat taps are handled. */
function startGrantServer({ port, authority, days, login, secret }) {
  const cookie = mintCookie(secret, authority, days);
  const grantPath = `/grant/${b64url(randomBytes(32))}`;
  // serve strips the --set-path prefix, so accept both shapes.
  const accepted = new Set([grantPath, grantPath.replace(/^\/grant/, '')]);
  let used = false;

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://grant.invalid');
    console.log(`<- ${req.method ?? '?'} ${url.pathname}`);

    // A retry, a second tap, or a link preview must not error: the cookie from
    // the first tap is already in the browser, so just send it to the app.
    if (used) {
      res.writeHead(303, { location: '/', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
      res.end();
      console.log('repeat tap: redirected to / without issuing a second cookie');
      return;
    }
    if (!accepted.has(url.pathname)) {
      res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('not found\n');
      console.log(`404: ${url.pathname} is not the grant path`);
      return;
    }

    const header = req.headers['tailscale-user-login'];
    const who = (Array.isArray(header) ? header[0] : header ?? '').trim().toLowerCase();
    if (who === '' || who !== login) {
      res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
      res.end(`forbidden: this endpoint grants a session to ${login} over the tailnet only\n`);
      console.log(`refused ${req.socket.remoteAddress}: login=${who === '' ? '(none)' : who}`);
      return;
    }

    used = true;
    res.writeHead(303, {
      location: '/',
      'set-cookie': cookie.setCookie,
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
    });
    res.end();
    console.log(`granted the session cookie to ${who}`);
    console.log('that device is now authorized for ' + days + ' days; the app is at the bare origin');
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(`grant server listening on 127.0.0.1:${port}`);
    console.log(`authority     : ${authority}`);
    console.log(`cookie expires: ${new Date(cookie.expiresAt).toISOString()} (${days} days)`);
  });

  return { cookie, grantPath, server };
}

/** Render a QR code for `text` to `outPath`, using the qrcode package if present. */
async function writeQr(text, outPath) {
  try {
    const { default: QRCode } = await import('qrcode');
    await QRCode.toFile(outPath, text, { errorCorrectionLevel: 'M', width: 420, margin: 4 });
    return true;
  } catch {
    // The QR is a convenience; a missing dep must not block the run.
    return false;
  }
}

const args = parseArgs(process.argv.slice(2));
const authority = String(args.authority ?? '127.0.0.1:3080');
const days = Number(args.days ?? 30);
const port = Number(args.port ?? 7245);
const login = String(args.login ?? 'outlawzhangsan.liii@gmail.com').toLowerCase();
const origin = String(args.origin ?? process.env.DSH_TAILNET_ORIGIN ?? '');

const { secret, path: secretPath } = readSigningSecret();

// --url-only: print a cookie to install by hand (devtools, curl, tests).
if (args['url-only'] || args['print-cookie']) {
  const cookie = mintCookie(secret, authority, days);
  console.log(`secret source : ${secretPath}`);
  console.log(`authority     : ${authority}`);
  console.log(`expires       : ${new Date(cookie.expiresAt).toISOString()} (${days} days)`);
  console.log('');
  console.log('Cookie header value:');
  console.log(cookie.pair);
  console.log('');
  console.log('Set-Cookie line:');
  console.log(cookie.setCookie);
  process.exit(0);
}

if (origin === '') {
  console.error('Set DSH_TAILNET_ORIGIN (e.g. https://liiiiii.tail996200.ts.net) or pass --origin.');
  console.error('The grant server is still starting so you can attach it manually.');
}

const { grantPath } = startGrantServer({ port, authority, days, login, secret });

// Announce the link and, when possible, a QR of it. This happens at startup so
// the QR exists before anyone scans it.
const link = origin === '' ? undefined : `${origin}${grantPath}`;
if (link !== undefined) {
  console.log('');
  console.log('Browser URL — open this on the device you want to authorize:');
  console.log(`  ${link}`);
  const qrPath = String(args.qr ?? 'grant-qr.png');
  const wrote = await writeQr(link, qrPath);
  console.log(
    wrote
      ? `QR written to ${qrPath} (scan with the iOS Camera app to open it in Safari)`
      : 'QR skipped: run `npm i qrcode` to enable it',
  );
} else {
  console.log('');
  console.log('Browser URL — substitute your tailnet origin:');
  console.log(`  https://<host>${grantPath}`);
}

console.log('');
console.log('If the route is not published yet:');
console.log(`  tailscale serve --bg --set-path=/grant http://127.0.0.1:${port}`);
console.log('');
console.log('Serve strips the --set-path prefix; this server accepts both shapes.');

