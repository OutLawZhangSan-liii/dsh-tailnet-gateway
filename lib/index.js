/**
 * dsh-tailnet-gateway — reach a loopback-bound DeepSeek Harness from your own
 * Tailscale devices.
 *
 * ## Why this exists
 *
 * DSH's `/api` carrier puts two fences in front of a remote browser:
 *
 *  1. The request-trust fence (`dsh-client-connection`): the `Host` must be
 *     loopback or match a `trustedHosts` entry. `dsh web --trusted-host` opens
 *     this one.
 *  2. The privileged-method fence: `settings.*`, `credentials.*`,
 *     `agentPreset.*`, `host.pickDirectory` and `llm.discoverModels` are served
 *     ONLY to loopback callers, and that branch deliberately re-runs the check
 *     with an EMPTY trust list. `--trusted-host` cannot open it.
 *
 * So pointing a browser at a non-loopback `Host` yields an app that loads and
 * chats but cannot reach Settings, Models or Plugins. That is by design, not a
 * bug to route around by widening the fence.
 *
 * ## The shape of the fix
 *
 * DSH keeps listening on `127.0.0.1` and is never exposed to the network. This
 * plugin listens on a SECOND loopback port, and `tailscale serve` publishes
 * that port to the tailnet over TLS. Every request arriving here has already
 * been through `tailscaled`, which terminates TLS and stamps
 * `Tailscale-User-Login` and `X-Forwarded-For` while OVERWRITING whatever the
 * client sent — which is what makes the identity unforgeable from the network.
 * A request that passes the gate is forwarded to DSH as what it truly is: a
 * loopback call from this same machine.
 *
 * ## The security contract
 *
 *  - The listener is clamped to loopback. This process converts an
 *    authenticated remote request into a loopback-trusting one, so binding it
 *    to a network interface would hand that trust to anyone who can reach the
 *    port. `resolveConfig` clamps; `startGateway` re-checks and throws.
 *  - A local (loopback) caller can forge the identity headers, because it does
 *    not pass through tailscaled. That is inherent to any loopback-trusting
 *    hop and is why the clamp above is load-bearing: the forged headers are
 *    only reachable from this machine.
 *  - No admission fact defaults to "allow". A request with no identity header
 *    is refused when the login gate is on; a peer allowlist that cannot be
 *    evaluated refuses rather than passes.
 *  - `Host`, `Origin` and `Referer` are rewritten to the upstream loopback
 *    authority, because left as the tailnet URL DSH's fence reads them as a
 *    cross-origin call.
 *
 * No import outside `node:*` is used, so the plugin loads in any DSH
 * installation regardless of which `@deepseek-ai/*` peers are hoisted into the
 * profile's `node_modules`.
 *
 * @module dsh-tailnet-gateway
 */

import { createServer, request as httpRequest } from 'node:http';

/** Stable Cordis plugin name. */
export const name = 'tailnet-gateway';

/** Services required before the gateway mounts; deliberately none. */
export const inject = [];

/** Hosts this server may bind to. Anything else forfeits the whole model. */
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

/** Loopback address used for the upstream hop regardless of the bind form. */
const UPSTREAM_HOST = '127.0.0.1';

/** Headers that describe one hop and must not be forwarded to the next. */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

/** Only the loopback control route answers, so diagnostics never leak remotely. */
const STATUS_PATH = '/_dsh/tailnet-gateway/status';

/**
 * Coerce one config value to a bounded integer, falling back when unusable.
 * @param {unknown} input - the stored value.
 * @param {number} fallback - value used when `input` is not a usable number.
 * @param {number} min - inclusive lower bound.
 * @param {number} max - inclusive upper bound.
 * @returns {number} the bounded integer.
 */
function boundedInt(input, fallback, min, max) {
  const numeric =
    typeof input === 'number'
      ? input
      : typeof input === 'string' && input.trim() !== ''
        ? Number(input)
        : Number.NaN;
  if (!Number.isFinite(numeric)) return fallback;
  return Math.min(max, Math.max(min, Math.round(numeric)));
}

/**
 * Coerce a listen port, preserving 0 as "let the OS pick a free one".
 *
 * `0` is a documented DSH convention for an OS-assigned port and must survive
 * resolution; clamping it to 1 would instead ask for a privileged port and make
 * every instance collide on it.
 *
 * @param {unknown} input - the stored value.
 * @param {number} fallback - value used when `input` is not a usable number.
 * @returns {number} a port in `0..65535`, or the fallback.
 */
function portOf(input, fallback) {
  const numeric =
    typeof input === 'number'
      ? input
      : typeof input === 'string' && input.trim() !== ''
        ? Number(input)
        : Number.NaN;
  if (!Number.isFinite(numeric) || numeric < 0) return fallback;
  return Math.min(65535, Math.round(numeric));
}

/**
 * Normalize a string array, dropping non-strings and blanks.
 * @param {unknown} input - the stored value.
 * @returns {string[]} the cleaned entries.
 */
function stringList(input) {
  if (!Array.isArray(input)) return [];
  const out = [];
  for (const entry of input) {
    if (typeof entry !== 'string') continue;
    const trimmed = entry.trim();
    if (trimmed !== '' && !out.includes(trimmed)) out.push(trimmed);
  }
  return out;
}

/**
 * Resolve plugin config against safe defaults.
 *
 * The bind host is CLAMPED rather than honoured: a non-loopback value is
 * silently reduced to `127.0.0.1` here and rejected outright in
 * {@link startGateway}, so no configuration mistake can publish loopback trust
 * to a network.
 *
 * @param {object} [input] - the raw plugin config.
 * @returns {object} the resolved config.
 */
export function resolveConfig(input) {
  const value = input ?? {};
  return {
    enabled: value.enabled !== false,
    host: value.host === '::1' ? '::1' : '127.0.0.1',
    port: portOf(value.port, 7242),
    // The identity served by `tailscale serve`. On by default and only
    // disengageable on purpose; with it off this becomes an unauthenticated
    // loopback proxy and the peer allowlist is the only gate left.
    requireLogin: value.requireLogin !== false,
    // Empty means "any account", which is only sane on a single-user tailnet.
    allowedLogins: stringList(value.allowedLogins),
    // Optional per-device gate: tailnet IPs as `tailscale status` reports them
    // in `TailscaleIPs` (for example `100.64.0.7`).
    allowedPeers: stringList(value.allowedPeers),
    upstreamPort: boundedInt(value.upstreamPort, 3080, 1, 65535),
  };
}

/**
 * The Tailscale login `tailscale serve` stamped on a request, lowercased.
 *
 * tailscaled overwrites this header on every proxied request, so a tailnet peer
 * cannot name itself. Absence means the request did not come through serve.
 *
 * @param {import('node:http').IncomingHttpHeaders} headers - inbound headers.
 * @returns {string|undefined} the login, or undefined when absent/blank.
 */
export function peerLogin(headers) {
  const raw = headers['tailscale-user-login'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim().toLowerCase();
  return trimmed === '' ? undefined : trimmed;
}

/**
 * The peer IP `tailscale serve` recorded for a request.
 *
 * `X-Forwarded-For` may carry a list when something else proxied first; the
 * FIRST entry is the original client. Reading the last would let a client that
 * can set the header choose its own identity.
 *
 * @param {import('node:http').IncomingHttpHeaders} headers - inbound headers.
 * @returns {string|undefined} the peer IP, or undefined when absent.
 */
export function peerAddress(headers) {
  const raw = headers['x-forwarded-for'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string') return undefined;
  const first = value.split(',')[0]?.trim();
  if (first === undefined || first === '') return undefined;
  // A bracketed IPv6 literal, and any :port suffix a proxy may have added.
  if (first.startsWith('[')) {
    const end = first.indexOf(']');
    return end > 0 ? first.slice(1, end) : undefined;
  }
  const parts = first.split(':');
  return parts.length === 2 ? parts[0] : first;
}

/**
 * Decide whether one request may pass.
 *
 * Both gates read an absent fact as a refusal, so a request that did not come
 * through `tailscale serve` fails rather than passes.
 *
 * @param {import('node:http').IncomingHttpHeaders} headers - inbound headers.
 * @param {object} config - the resolved config.
 * @returns {{ok: true, login: string|undefined, peer: string|undefined}
 *   | {ok: false, reason: string}} the verdict.
 */
export function admit(headers, config) {
  const login = peerLogin(headers);
  const peer = peerAddress(headers);

  if (config.requireLogin) {
    if (login === undefined) {
      return { ok: false, reason: 'no Tailscale identity on this request' };
    }
    if (
      config.allowedLogins.length > 0 &&
      !config.allowedLogins.some((entry) => entry.trim().toLowerCase() === login)
    ) {
      return { ok: false, reason: `login ${login} is not allowed` };
    }
  }

  if (config.allowedPeers.length > 0) {
    if (peer === undefined) {
      return { ok: false, reason: 'no peer address on this request' };
    }
    if (!config.allowedPeers.includes(peer)) {
      return { ok: false, reason: `peer ${peer} is not allowed` };
    }
  }

  return { ok: true, login, peer };
}

/**
 * Rewrite inbound headers for the loopback hop.
 *
 * `host`, `origin` and `referer` all name the tailnet URL the browser typed;
 * left as they are, the upstream fence reads the call as cross-origin.
 * Rewriting them to the upstream authority states the truth about the hop
 * being made rather than deleting them, which would also pass but would hide
 * the relationship in DSH's logs.
 *
 * @param {import('node:http').IncomingHttpHeaders} headers - inbound headers.
 * @param {string} authority - the upstream `host:port`.
 * @returns {Record<string, string|string[]>} outbound headers.
 */
export function proxyHeaders(headers, authority) {
  /** @type {Record<string, string|string[]>} */
  const out = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined || HOP_BY_HOP.has(key)) continue;
    out[key] = value;
  }
  out.host = authority;
  if (out.origin !== undefined) out.origin = `http://${authority}`;
  if (typeof out.referer === 'string') {
    try {
      const referer = new URL(out.referer);
      out.referer = `http://${authority}${referer.pathname}${referer.search}`;
    } catch {
      delete out.referer;
    }
  }
  return out;
}

/** Refuse a request, saying why, without disclosing any allowlist. */
function deny(res, reason) {
  const body = `Forbidden: ${reason}.\n`;
  res.writeHead(403, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}

/** Whether a socket address is loopback, for the control route only. */
function isLoopbackAddress(address) {
  return (
    address === '127.0.0.1' ||
    address === '::1' ||
    (typeof address === 'string' && address.startsWith('::ffff:127.'))
  );
}

/**
 * Start the gateway.
 *
 * @param {object} options - startup inputs.
 * @param {() => object} options.config - returns the live resolved config; read
 *   per request so a settings change applies without a restart.
 * @param {(level: string, message: string) => void} [options.log] - log sink.
 * @returns {Promise<{port: number, host: string, close: () => Promise<void>}>}
 *   the live listener.
 */
export async function startGateway({ config, log = () => {} }) {
  const settings = config();
  if (!LOOPBACK_HOSTS.has(settings.host)) {
    throw new Error(
      `tailnet-gateway: refusing to bind ${settings.host}; this gateway grants loopback trust and must not be reachable directly`,
    );
  }

  // Sockets this server handed to us on upgrade. node stops counting a
  // connection once it is upgraded, and `closeAllConnections()` deliberately
  // excludes upgraded sockets, so `server.close()` would otherwise wait forever
  // on a tunnel that by nature never ends. Both ends of every tunnel are held
  // here so `close()` can end them explicitly. Verified by the "close() settles
  // with a tunnel open" test.
  const tunnels = new Set();

  const upstreamAuthority = () => `${UPSTREAM_HOST}:${String(config().upstreamPort)}`;

  const server = createServer((req, res) => {
    const now = config();

    // Loopback-only diagnostics. Never proxied, so it cannot be reached
    // through `tailscale serve` no matter how the tailnet is configured.
    if (req.url === STATUS_PATH) {
      if (!isLoopbackAddress(req.socket.remoteAddress)) {
        deny(res, 'the status route answers only on loopback');
        return;
      }
      const verdict = admit(req.headers, now);
      const body = `${JSON.stringify(
        {
          listening: true,
          host: now.host,
          port: server.address()?.port ?? now.port,
          upstream: upstreamAuthority(),
          requireLogin: now.requireLogin,
          allowedLogins: now.allowedLogins,
          allowedPeers: now.allowedPeers,
          sample: verdict,
        },
        null,
        2,
      )}\n`;
      res.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        'content-length': Buffer.byteLength(body),
        'cache-control': 'no-store',
      });
      res.end(body);
      return;
    }

    const verdict = admit(req.headers, now);
    if (!verdict.ok) {
      log('warn', `denied ${req.method ?? '?'} ${req.url ?? '?'}: ${verdict.reason}`);
      deny(res, verdict.reason);
      return;
    }

    const authority = upstreamAuthority();
    const proxied = httpRequest(
      {
        host: UPSTREAM_HOST,
        port: config().upstreamPort,
        method: req.method,
        path: req.url,
        headers: proxyHeaders(req.headers, authority),
      },
      (upstreamRes) => {
        const headers = { ...upstreamRes.headers };
        // An absolute redirect naming the loopback authority would send the
        // browser to a port that does not exist on the peer's machine.
        const location = headers.location;
        if (typeof location === 'string' && location.startsWith(`http://${authority}`)) {
          headers.location = location.slice(`http://${authority}`.length) || '/';
        }
        res.writeHead(upstreamRes.statusCode ?? 502, headers);
        upstreamRes.pipe(res);
      },
    );
    proxied.on('error', (error) => {
      log('warn', `upstream error for ${req.url ?? '?'}: ${String(error?.message ?? error)}`);
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
      }
      res.end('Bad gateway\n');
    });
    req.pipe(proxied);
  });

  // The event stream (`events.mux`) is a WebSocket, so the same gate has to sit
  // on the upgrade path; without it the app would authenticate and then idle on
  // a dead socket.
  server.on('upgrade', (req, socket, head) => {
    tunnels.add(socket);
    socket.once('close', () => tunnels.delete(socket));

    const now = config();
    const verdict = admit(req.headers, now);
    if (!verdict.ok) {
      log('warn', `denied upgrade ${req.url ?? '?'}: ${verdict.reason}`);
      socket.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n');
      return;
    }

    const headers = proxyHeaders(req.headers, upstreamAuthority());
    headers.connection = 'Upgrade';
    headers.upgrade = req.headers.upgrade ?? 'websocket';

    const proxied = httpRequest({
      host: UPSTREAM_HOST,
      port: now.upstreamPort,
      method: req.method,
      path: req.url,
      headers,
    });

    proxied.on('upgrade', (upstreamRes, upstreamSocket, upstreamHead) => {
      const lines = ['HTTP/1.1 101 Switching Protocols'];
      for (const [key, value] of Object.entries(upstreamRes.headers)) {
        for (const one of Array.isArray(value) ? value : [value]) {
          lines.push(`${key}: ${String(one)}`);
        }
      }
      socket.write(`${lines.join('\r\n')}\r\n\r\n`);
      // Bytes the upstream sent immediately after the 101 arrive here rather
      // than on the socket, so they are written on — not unshifted, which would
      // push them back into OUR read buffer and strand the first frame.
      if (upstreamHead?.length) socket.write(upstreamHead);
      if (head?.length) upstreamSocket.write(head);
      upstreamSocket.on('error', () => {
        upstreamSocket.destroy();
        socket.destroy();
      });
      socket.on('error', () => {
        upstreamSocket.destroy();
        socket.destroy();
      });
      upstreamSocket.pipe(socket);
      socket.pipe(upstreamSocket);
      tunnels.add(upstreamSocket);
      upstreamSocket.once('close', () => tunnels.delete(upstreamSocket));
    });
    proxied.on('response', (upstreamRes) => {
      // The upstream declined the upgrade; nothing to tunnel.
      socket.end(`HTTP/1.1 ${String(upstreamRes.statusCode ?? 502)}\r\nconnection: close\r\n\r\n`);
    });
    proxied.on('error', () => socket.destroy());
    if (head?.length) proxied.write(head);
    proxied.end();
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(settings.port, settings.host, () => {
      server.off('error', reject);
      resolve();
    });
  });

  return {
    port: server.address()?.port ?? settings.port,
    host: settings.host,
    async close() {
      // Drop live sockets rather than waiting them out: the connections most
      // likely open are the long-lived event streams whose admission may be
      // exactly what changed, and a tunnelled socket never goes idle. Both the
      // client-side and upstream-side ends must go, because node's
      // `closeAllConnections()` does not cover upgraded sockets at all.
      for (const socket of tunnels) socket.destroy();
      tunnels.clear();
      server.closeAllConnections();
      await new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

/**
 * Mount the gateway.
 *
 * @param {import('@deepseek-ai/cordis').Context} ctx - host plugin context.
 * @param {object} [rawConfig] - plugin config from the profile patch.
 */
export function apply(ctx, rawConfig) {
  const log = (level, message) => {
    const logger = ctx?.logger;
    const sink = logger?.[level];
    if (typeof sink === 'function') sink.call(logger, `tailnet-gateway: ${message}`);
  };

  let current = resolveConfig(rawConfig);
  /** @type {{port: number, host: string, close: () => Promise<void>}|undefined} */
  let live;
  let starting;

  const reconcile = async () => {
    if (starting !== undefined) return starting;
    starting = (async () => {
      try {
        if (live !== undefined) {
          await live.close().catch(() => {});
          live = undefined;
        }
        if (!current.enabled) {
          log('info', 'disabled');
          return;
        }
        live = await startGateway({ config: () => current, log });
        log(
          'info',
          `listening on ${live.host}:${String(live.port)} -> ${UPSTREAM_HOST}:${String(current.upstreamPort)}; ` +
            `publish it with: tailscale serve --bg ${String(live.port)}`,
        );
      } catch (error) {
        log('warn', `could not start: ${String(error?.message ?? error)}`);
      } finally {
        starting = undefined;
      }
    })();
    return starting;
  };

  ctx?.effect?.(() => () => {
    if (live !== undefined) void live.close().catch(() => {});
    live = undefined;
  }, 'dsh-tailnet-gateway: listener');

  void reconcile();

  return {
    /** Current resolved config. */
    get config() {
      return current;
    },
    /** The live listener, or undefined when disabled or failed to bind. */
    get live() {
      return live;
    },
    /**
     * Replace the config and re-reconcile the listener.
     * @param {object} next - a raw config object.
     */
    async reconfigure(next) {
      current = resolveConfig(next);
      await reconcile();
    },
    /** Stop the listener. */
    async stop() {
      if (live !== undefined) await live.close().catch(() => {});
      live = undefined;
    },
  };
}
