/**
 * Behavior tests for dsh-tailnet-gateway.
 *
 * The important properties are the ones a code read cannot confirm: that a
 * refused request never reaches DSH at all, that the hop is rewritten or the
 * upstream fence rejects it, that an upgrade is tunnelled rather than answered,
 * and that the listener refuses a non-loopback bind.
 *
 * Run with: node --test test/*.test.js
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer, request as httpRequest } from 'node:http';
import { connect } from 'node:net';
import { once } from 'node:events';

import {
  admit,
  peerAddress,
  peerLogin,
  proxyHeaders,
  resolveConfig,
  startGateway,
} from '../lib/index.js';

/** Start a stand-in DSH that records what actually reached it. */
async function startUpstream() {
  /** @type {{url: string|undefined, headers: import('node:http').IncomingHttpHeaders}[]} */
  const seen = [];
  // Upgraded sockets are excluded from closeAllConnections(), so a stub that
  // does not hold them deadlocks its own close() exactly as the gateway would.
  const upgraded = new Set();
  const server = createServer((req, res) => {
    seen.push({ url: req.url, headers: req.headers });
    if (req.url === '/api/whoami') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ host: req.headers.host, origin: req.headers.origin ?? null }));
      return;
    }
    if (req.url === '/redirect') {
      res.writeHead(303, { location: `http://127.0.0.1:${String(server.address().port)}/` });
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('upstream-ok');
  });
  // A WebSocket-shaped upgrade endpoint.
  server.on('upgrade', (req, socket, head) => {
    seen.push({ url: req.url, headers: req.headers });
    upgraded.add(socket);
    socket.once('close', () => upgraded.delete(socket));
    socket.write('HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n');
    if (head?.length) socket.write(head);
    socket.on('data', (chunk) => socket.write(`echo:${chunk.toString('utf8')}`));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    port: server.address().port,
    seen,
    async close() {
      for (const socket of upgraded) socket.destroy();
      upgraded.clear();
      server.closeAllConnections();
      await new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

/** Start the gateway against a stub upstream on an OS-assigned port. */
async function startTestGateway(upstream, config = {}) {
  const resolved = resolveConfig({ port: 0, upstreamPort: upstream.port, ...config });
  const gateway = await startGateway({ config: () => resolved, log: () => {} });
  return gateway;
}

/** One proxied request through the gateway. */
function callGateway(port, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, path, headers }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () =>
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }),
      );
    });
    req.on('error', reject);
    req.end();
  });
}

test('resolveConfig clamps a non-loopback bind to 127.0.0.1', () => {
  assert.equal(resolveConfig({ host: '0.0.0.0' }).host, '127.0.0.1');
  assert.equal(resolveConfig({ host: '192.168.1.10' }).host, '127.0.0.1');
  assert.equal(resolveConfig({ host: '::1' }).host, '::1');
  assert.equal(resolveConfig({ port: 'nonsense' }).port, 7242);
  assert.equal(resolveConfig({ port: 99999 }).port, 65535);
  assert.equal(resolveConfig({}).port, 7242);
  assert.equal(resolveConfig({ requireLogin: false }).requireLogin, false);
  assert.equal(resolveConfig({}).requireLogin, true, 'the login gate is on by default');
});

test('resolveConfig preserves port 0 as an OS-assigned request', async () => {
  // Clamping 0 to 1 would ask for a privileged port and make every instance
  // collide on it. Pin that 0 survives and really yields a free port.
  assert.equal(resolveConfig({ port: 0 }).port, 0);
  const upstream = await startUpstream();
  const gateway = await startTestGateway(upstream, { port: 0 });
  try {
    assert.ok(gateway.port > 0, 'an OS-assigned port is reported back');
    assert.notEqual(gateway.port, 1);
  } finally {
    await gateway.close();
    await upstream.close();
  }
}, { timeout: 15000 });

test('startGateway refuses to bind anything but loopback', async () => {
  await assert.rejects(
    () => startGateway({ config: () => ({ ...resolveConfig({}), host: '0.0.0.0' }) }),
    /refusing to bind 0\.0\.0\.0/,
  );
}, { timeout: 15000 });

test('peerLogin and peerAddress read only what tailscaled stamps', () => {
  assert.equal(peerLogin({ 'tailscale-user-login': 'Me@Example.com' }), 'me@example.com');
  assert.equal(peerLogin({ 'tailscale-user-login': '   ' }), undefined);
  assert.equal(peerLogin({}), undefined);
  // The FIRST forwarded entry is the original client; the last would let a
  // client that can set the header choose its own identity.
  assert.equal(peerAddress({ 'x-forwarded-for': '100.64.0.7, 10.0.0.1' }), '100.64.0.7');
  assert.equal(peerAddress({ 'x-forwarded-for': '100.64.0.7:5555' }), '100.64.0.7');
  assert.equal(peerAddress({ 'x-forwarded-for': '[fd7a:115c::1]:443' }), 'fd7a:115c::1');
  assert.equal(peerAddress({}), undefined);
});

test('admit fails closed on a missing fact', () => {
  const gated = resolveConfig({});
  assert.equal(admit({}, gated).ok, false, 'no identity header means no admission');
  assert.equal(admit({ 'tailscale-user-login': 'me@example.com' }, gated).ok, true);

  const allowlisted = resolveConfig({ allowedLogins: ['me@example.com'] });
  assert.equal(admit({ 'tailscale-user-login': 'me@example.com' }, allowlisted).ok, true);
  assert.equal(admit({ 'tailscale-user-login': 'other@example.com' }, allowlisted).ok, false);

  const peerGated = resolveConfig({ allowedPeers: ['100.64.0.7'] });
  assert.equal(
    admit({ 'tailscale-user-login': 'me@example.com', 'x-forwarded-for': '100.64.0.7' }, peerGated).ok,
    true,
  );
  assert.equal(
    admit({ 'tailscale-user-login': 'me@example.com', 'x-forwarded-for': '100.64.0.9' }, peerGated).ok,
    false,
  );
  assert.equal(admit({ 'tailscale-user-login': 'me@example.com' }, peerGated).ok, false);
});

test('proxyHeaders states the loopback hop instead of hiding it', () => {
  const out = proxyHeaders(
    {
      host: 'laptop.tailnet.ts.net',
      origin: 'https://laptop.tailnet.ts.net',
      referer: 'https://laptop.tailnet.ts.net/chat?x=1',
      cookie: 'a=b',
      connection: 'keep-alive',
      'transfer-encoding': 'chunked',
    },
    '127.0.0.1:3080',
  );
  assert.equal(out.host, '127.0.0.1:3080');
  assert.equal(out.origin, 'http://127.0.0.1:3080');
  assert.equal(out.referer, 'http://127.0.0.1:3080/chat?x=1');
  assert.equal(out.cookie, 'a=b', 'the session cookie passes through');
  assert.equal(out.connection, undefined, 'hop-by-hop headers are dropped');
  assert.equal(out['transfer-encoding'], undefined);
});

test('a denied request never reaches the upstream', async () => {
  const upstream = await startUpstream();
  const gateway = await startTestGateway(upstream);
  try {
    const res = await callGateway(gateway.port, '/api/whoami', { host: 'laptop.tailnet.ts.net' });
    assert.equal(res.status, 403);
    assert.match(res.body, /no Tailscale identity/);
    assert.equal(upstream.seen.length, 0, 'nothing may reach DSH, not even a probe');
  } finally {
    await gateway.close();
    await upstream.close();
  }
}, { timeout: 15000 });

test('open admission is reachable only by turning the login gate off on purpose', async () => {
  // Documents the one configuration that admits an unidentified caller, so the
  // default is never mistaken for it.
  const gateOff = resolveConfig({ requireLogin: false });
  assert.equal(admit({}, gateOff).ok, true, 'the gate is the only thing standing here');

  const upstream = await startUpstream();
  const gateway = await startTestGateway(upstream, { requireLogin: false });
  try {
    const res = await callGateway(gateway.port, '/api/whoami', { host: 'laptop.tailnet.ts.net' });
    assert.equal(res.status, 200);
    assert.equal(upstream.seen.length, 1);
  } finally {
    await gateway.close();
    await upstream.close();
  }
}, { timeout: 15000 });

test('a denied request with a bad peer never reaches the upstream', async () => {
  const upstream = await startUpstream();
  const gateway = await startTestGateway(upstream, { allowedPeers: ['100.64.0.7'] });
  try {
    const res = await callGateway(gateway.port, '/api/whoami', {
      host: 'laptop.tailnet.ts.net',
      'tailscale-user-login': 'me@example.com',
      'x-forwarded-for': '100.64.0.99',
    });
    assert.equal(res.status, 403);
    assert.match(res.body, /not allowed/);
    assert.equal(upstream.seen.length, 0);
  } finally {
    await gateway.close();
    await upstream.close();
  }
}, { timeout: 15000 });

test('an admitted request is proxied with the hop rewritten', async () => {
  const upstream = await startUpstream();
  const gateway = await startTestGateway(upstream);
  try {
    const res = await callGateway(gateway.port, '/api/whoami', {
      host: 'laptop.tailnet.ts.net',
      origin: 'https://laptop.tailnet.ts.net',
      'tailscale-user-login': 'Me@Example.com',
      'x-forwarded-for': '100.64.0.7',
      cookie: 'dsh=bearer',
    });
    assert.equal(res.status, 200);
    assert.deepEqual(JSON.parse(res.body), {
      host: `127.0.0.1:${String(upstream.port)}`,
      origin: `http://127.0.0.1:${String(upstream.port)}`,
    });
    assert.equal(upstream.seen.length, 1);
    assert.equal(upstream.seen[0].headers.cookie, 'dsh=bearer');
    // The identity headers are NOT stripped: DSH may want to log who called.
    assert.equal(upstream.seen[0].headers['tailscale-user-login'], 'Me@Example.com');
  } finally {
    await gateway.close();
    await upstream.close();
  }
}, { timeout: 15000 });

test('an absolute loopback redirect is made relative for the peer', async () => {
  const upstream = await startUpstream();
  const gateway = await startTestGateway(upstream);
  try {
    const res = await callGateway(gateway.port, '/redirect', {
      host: 'laptop.tailnet.ts.net',
      'tailscale-user-login': 'me@example.com',
    });
    assert.equal(res.status, 303);
    assert.equal(res.headers.location, '/', 'a loopback authority would be unreachable from the phone');
  } finally {
    await gateway.close();
    await upstream.close();
  }
}, { timeout: 15000 });

test('an upgrade is gated and then tunnelled', async () => {
  const upstream = await startUpstream();
  const gateway = await startTestGateway(upstream);
  try {
    // Denied first: no 101, and the upstream must not see the handshake.
    const denied = await rawUpgrade(gateway.port, '/api/events.mux', { host: 'laptop.tailnet.ts.net' });
    assert.match(denied.head, /403 Forbidden/);
    assert.equal(upstream.seen.length, 0);

    // Admitted: a real 101 and a working bidirectional tunnel.
    const admitted = await rawUpgrade(gateway.port, '/api/events.mux', {
      host: 'laptop.tailnet.ts.net',
      'tailscale-user-login': 'me@example.com',
    });
    assert.match(admitted.head, /101 Switching Protocols/);
    admitted.socket.write('ping');
    const echoed = await readUntil(admitted.socket, (text) => text.includes('echo:ping'));
    assert.match(echoed, /echo:ping/);
    admitted.socket.destroy();
    assert.equal(upstream.seen.at(-1)?.headers.host, `127.0.0.1:${String(upstream.port)}`);
  } finally {
    await gateway.close();
    await upstream.close();
  }
}, { timeout: 15000 });

test('the status route answers locally and is never proxied upstream', async () => {
  const upstream = await startUpstream();
  const gateway = await startTestGateway(upstream, { allowedLogins: ['me@example.com'] });
  try {
    const local = await callGateway(gateway.port, '/_dsh/tailnet-gateway/status', {
      host: '127.0.0.1',
      'tailscale-user-login': 'me@example.com',
    });
    assert.equal(local.status, 200);
    const payload = JSON.parse(local.body);
    assert.equal(payload.listening, true);
    assert.equal(payload.upstream, `127.0.0.1:${String(upstream.port)}`);
    assert.equal(payload.sample.ok, true);

    // The guard is the SOCKET address, and tailscale serve always connects from
    // loopback, so a tailnet Host alone does not deny it. What must hold is that
    // this path is answered here and never reaches DSH, so it cannot become a
    // way to probe the upstream through the gateway.
    const withTailnetHost = await callGateway(gateway.port, '/_dsh/tailnet-gateway/status', {
      host: 'laptop.tailnet.ts.net',
      'tailscale-user-login': 'me@example.com',
    });
    assert.equal(withTailnetHost.status, 200);
    assert.equal(JSON.parse(withTailnetHost.body).listening, true);
    assert.equal(upstream.seen.length, 0, 'the status route must never be proxied to DSH');
  } finally {
    await gateway.close();
    await upstream.close();
  }
}, { timeout: 15000 });

test('the listener closes cleanly and stops accepting', async () => {
  const upstream = await startUpstream();
  const gateway = await startTestGateway(upstream);
  const port = gateway.port;
  await gateway.close();
  await assert.rejects(() => callGateway(port, '/', { host: '127.0.0.1', 'tailscale-user-login': 'me@x.com' }));
  await upstream.close();
}, { timeout: 15000 });

test('close() settles even with a live tunnel open', async () => {
  // node's closeAllConnections() does NOT include upgraded sockets, so without
  // explicit destroy of both tunnel ends this close() would never resolve and
  // a reconfiguration or shutdown would wedge forever.
  const upstream = await startUpstream();
  const gateway = await startTestGateway(upstream);
  const admitted = await rawUpgrade(gateway.port, '/api/events.mux', {
    host: 'laptop.tailnet.ts.net',
    'tailscale-user-login': 'me@example.com',
  });
  assert.match(admitted.head, /101 Switching Protocols/);

  const settled = await Promise.race([
    gateway.close().then(() => 'closed'),
    new Promise((resolve) => setTimeout(() => resolve('timed-out'), 4000)),
  ]);
  assert.equal(settled, 'closed', 'close() must not wait on an endless tunnel');
  admitted.socket.destroy();
  await upstream.close();
}, { timeout: 15000 });

/**
 * Perform a raw HTTP upgrade handshake.
 *
 * Listener attachment races the response, so this records every chunk from the
 * moment the socket connects instead of awaiting one `data` event: awaiting
 * after the write can miss a chunk that already arrived and then hang forever.
 *
 * @param {number} port - the gateway port.
 * @param {string} path - the request path.
 * @param {Record<string,string>} headers - extra headers.
 * @returns {Promise<{head: string, textAfterHead: string, socket: import('node:net').Socket}>}
 *   the status line and headers, plus anything received after them.
 */
async function rawUpgrade(port, path, headers) {
  const socket = connect(port, '127.0.0.1');
  /** @type {Buffer[]} */
  const chunks = [];
  socket.on('data', (chunk) => chunks.push(chunk));
  await once(socket, 'connect');

  const lines = [
    `GET ${path} HTTP/1.1`,
    `host: ${headers.host ?? 'localhost'}`,
    'connection: Upgrade',
    'upgrade: websocket',
  ];
  for (const [key, value] of Object.entries(headers)) {
    if (key === 'host') continue;
    lines.push(`${key}: ${value}`);
  }
  socket.write(`${lines.join('\r\n')}\r\n\r\n`);

  const separator = Buffer.from('\r\n\r\n');
  // Bounded so a regression fails the test instead of hanging the runner.
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const joined = Buffer.concat(chunks);
    const at = joined.indexOf(separator);
    if (at !== -1) {
      return {
        head: joined.subarray(0, at).toString('utf8'),
        textAfterHead: joined.subarray(at + separator.length).toString('utf8'),
        socket,
      };
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  socket.destroy();
  throw new Error(`rawUpgrade: no response head for ${path} within 3s`);
}

/**
 * Read from a socket until `predicate` matches the accumulated text.
 * @param {import('node:net').Socket} socket - the open socket.
 * @param {(text: string) => boolean} predicate - what to wait for.
 * @returns {Promise<string>} the accumulated text that matched.
 */
async function readUntil(socket, predicate) {
  let text = '';
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const [chunk] = await Promise.race([
      once(socket, 'data'),
      new Promise((resolve) => setTimeout(() => resolve([Buffer.alloc(0)]), 25)),
    ]);
    text += chunk.toString('utf8');
    if (predicate(text)) return text;
  }
  throw new Error(`readUntil: no match within 3s; saw ${JSON.stringify(text)}`);
}




