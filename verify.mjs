/**
 * Verification for the tailnet gateway, in three widening rings.
 *
 *   node verify.mjs live                 # the gateway mounted in the RUNNING dsh
 *   node verify.mjs chain                # full remote chain over real TLS
 *   node verify.mjs cookie "<pair>"      # a specific cookie authenticates dsh
 *   node verify.mjs all                  # live + chain
 *
 * Why three: a failure at one ring localises the problem.
 *
 *   - `live`  fails  -> the plugin is not mounted, or is bound wrongly
 *   - `chain` fails  -> Tailscale serve, DNS, or the certificate
 *   - `cookie` fails -> the cookie's authority does not match this instance
 *
 * `chain` treats a **401** from `/` as SUCCESS: it proves dsh's own session
 * check answered, so every hop in front of it worked. A 502 or 403 there means
 * the chain is broken, not that authentication is working.
 *
 * @module dsh-tailnet-gateway/verify
 */

import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';

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

/** Issue one request and resolve with its outcome, never rejecting. */
function fetchOnce({ protocol, host, port, path, headers, timeoutMs = 20000 }) {
  return new Promise((resolve) => {
    const request = protocol === 'https' ? httpsRequest : httpRequest;
    const req = request({ host, port, path, method: 'GET', headers, agent: false, timeout: timeoutMs }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () =>
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
          socket: res.socket,
        }),
      );
    });
    req.on('error', (error) => resolve({ error: `${error.code ?? ''} ${error.message}`.trim() }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ error: 'timeout' });
    });
    req.end();
  });
}

const results = [];
const check = (name, ok, detail) => results.push({ name, ok: Boolean(ok), detail });

/** Ring 1: the gateway inside the running dsh process, over loopback. */
async function ringLive(gatewayPort, dshPort) {
  const status = await fetchOnce({
    protocol: 'http',
    host: '127.0.0.1',
    port: gatewayPort,
    path: '/_dsh/tailnet-gateway/status',
    headers: { host: '127.0.0.1', 'tailscale-user-login': 'verify@example.com' },
  });
  check('gateway answers its status route', status.status === 200, `status=${status.status ?? status.error}`);
  if (status.status === 200) {
    const payload = JSON.parse(status.body);
    check('gateway fronts the expected dsh port', payload.upstream === `127.0.0.1:${dshPort}`, payload.upstream);
    check('gateway is loopback-bound', payload.host === '127.0.0.1', payload.host);
    check('login gate is enabled', payload.requireLogin === true, String(payload.requireLogin));
  }

  const anon = await fetchOnce({
    protocol: 'http',
    host: '127.0.0.1',
    port: gatewayPort,
    path: '/',
    headers: { host: 'phone.tailnet.ts.net' },
  });
  check('anonymous request is refused', anon.status === 403, `status=${anon.status ?? anon.error}`);

  const identified = await fetchOnce({
    protocol: 'http',
    host: '127.0.0.1',
    port: gatewayPort,
    path: '/',
    headers: {
      host: 'phone.tailnet.ts.net',
      'tailscale-user-login': 'verify@example.com',
      'x-forwarded-for': '100.64.0.7',
    },
  });
  // 401 proves the request reached dsh's session check; a broken proxy gives 502.
  check(
    'identified request reaches dsh (401 = forwarded, not broken)',
    identified.status === 401,
    `status=${identified.status ?? identified.error}`,
  );
}

/** Ring 2: the whole chain over real TLS, the way the phone sees it. */
async function ringChain(host, targetPort = 443) {
  const index = await fetchOnce({ protocol: 'https', host, port: targetPort, path: '/' });
  if (index.error !== undefined) {
    check('DNS resolves and TLS verifies against the system CA store', false, index.error);
    return;
  }
  check('DNS resolves and TLS verifies against the system CA store', true, 'ok');

  const cert = index.socket?.getPeerCertificate?.();
  if (cert?.subject) {
    check(
      'certificate covers the tailnet name',
      String(cert.subjectaltname ?? '').includes(host),
      String(cert.subjectaltname ?? '').slice(0, 60),
    );
  }
  check('unauthenticated request reaches dsh auth (401)', index.status === 401, `status=${index.status}`);

  const status = await fetchOnce({ protocol: 'https', host, port: targetPort, path: '/_dsh/tailnet-gateway/status' });
  check(
    'gateway status route is reachable over the tailnet',
    status.status === 200,
    `status=${status.status ?? status.error}`,
  );
}

/** Ring 3: a specific cookie authenticates dsh through the chain. */
async function ringCookie(host, pair) {
  const withCookie = await fetchOnce({ protocol: 'https', host, port: 443, path: '/', headers: { cookie: pair } });
  const without = await fetchOnce({ protocol: 'https', host, port: 443, path: '/' });
  check(
    'the cookie serves the app (200 with an app shell)',
    withCookie.status === 200 && /<html|__DSH_BOOT__/i.test(withCookie.body ?? ''),
    `status=${withCookie.status} bytes=${(withCookie.body ?? '').length}`,
  );
  check('without the cookie the same URL is 401', without.status === 401, `status=${without.status}`);
}

const args = parseArgs(process.argv.slice(2));
const mode = String(args._[0] ?? 'all');
const gatewayPort = Number(args['gateway-port'] ?? 7242);
const dshPort = Number(args['dsh-port'] ?? 3080);
const host = String(args.host ?? process.env.DSH_TAILNET_HOST ?? 'liiiiii.tail996200.ts.net');
const pair = args.pair ?? args._[1];

if (mode === 'live' || mode === 'all') await ringLive(gatewayPort, dshPort);
if (mode === 'chain' || mode === 'all') await ringChain(host);
if (mode === 'cookie') {
  if (!pair) {
    console.error('usage: node verify.mjs cookie "<cookie-pair>"');
    process.exit(2);
  }
  await ringCookie(host, String(pair));
}

const failed = results.filter((r) => !r.ok);
for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}${r.detail ? `  [${r.detail}]` : ''}`);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
