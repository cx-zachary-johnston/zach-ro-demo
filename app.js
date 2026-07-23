'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const { exec, execFile } = require('child_process');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '64kb' }));

const PORT = Number(process.env.PORT || 3000);
const DATA_ROOT = path.resolve(__dirname, 'data');
const PUBLIC_ROOT = path.resolve(__dirname, 'public');

const users = new Map([
  ['100', { id: '100', name: 'Alice', role: 'user', bio: 'Hello <world>' }],
  ['101', { id: '101', name: 'Bob', role: 'admin', bio: 'Security & reliability' }]
]);

const orders = [
  { id: 'o-100', ownerId: '100', total: 42.50, status: 'paid' },
  { id: 'o-101', ownerId: '101', total: 9.99, status: 'pending' }
];

function htmlEscape(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function shellSafeToken(value) {
  const token = String(value);
  if (!/^[a-zA-Z0-9._-]{1,64}$/.test(token)) {
    throw new Error('invalid shell token');
  }
  return token;
}

function safeRelativeRedirect(value, fallback = '/') {
  if (typeof value !== 'string') return fallback;
  if (!value.startsWith('/') || value.startsWith('//')) return fallback;

  const parsed = new URL(value, 'https://example.invalid');
  if (parsed.origin !== 'https://example.invalid') return fallback;
  return `${parsed.pathname}${parsed.search}${parsed.hash}`;
}

function resolveInside(root, userPath) {
  const candidate = path.resolve(root, String(userPath || ''));
  const relative = path.relative(root, candidate);

  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('path escapes allowed root');
  }
  return candidate;
}

function exactOutboundUrl(raw) {
  const parsed = new URL(String(raw));
  const allowedHosts = new Set(['api.example.com', 'status.example.com']);

  if (parsed.protocol !== 'https:') throw new Error('https required');
  if (!allowedHosts.has(parsed.hostname)) throw new Error('host denied');
  if (parsed.username || parsed.password) throw new Error('credentials denied');
  if (parsed.port && parsed.port !== '443') throw new Error('port denied');

  return parsed;
}

function positiveInteger(value, max = 1000000) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1 || number > max) {
    throw new Error('expected positive integer');
  }
  return number;
}

function allowedSort(value) {
  const sortMap = {
    newest: 'created_at DESC',
    oldest: 'created_at ASC',
    price_asc: 'price ASC',
    price_desc: 'price DESC'
  };
  return sortMap[value] || sortMap.newest;
}

function fakeDbQuery(sql, params = []) {
  return Promise.resolve({ sql, params, rows: [] });
}

function currentUser(req) {
  const id = String(req.header('x-user-id') || '100');
  return users.get(id) || null;
}

function requireAdmin(req, res, next) {
  const user = currentUser(req);
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: 'admin required' });
  }
  req.user = user;
  next();
}

/*
 * SAFE BAIT 1: encoded HTML response.
 * A shallow source-to-res.send rule may still report this.
 */
app.get('/safe/xss/escaped', (req, res) => {
  const name = htmlEscape(req.query.name || 'guest');
  res.type('html').send(`<h1>Hello ${name}</h1>`);
});

/* SAFE BAIT 2: same source and sink, encoder hidden behind a local wrapper. */
app.get('/safe/xss/wrapped-escape', (req, res) => {
  const renderName = value => htmlEscape(value);
  res.type('html').send(`<p>${renderName(req.query.name)}</p>`);
});

/* SAFE BAIT 3: JSON serialization, not HTML interpretation. */
app.get('/safe/xss/json', (req, res) => {
  res.json({ echoed: String(req.query.value || '') });
});

/* SAFE BAIT 4: fixed content type plus encoded body. */
app.post('/safe/xss/profile-card', (req, res) => {
  const bio = htmlEscape(req.body.bio || '');
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(`<section data-kind="profile">${bio}</section>`);
});

/*
 * Fixed: reflected XSS — HTML-encode the query parameter before embedding
 * it in the HTML response so that special characters cannot be interpreted
 * as markup or script by the browser.
 */
app.get('/vuln/xss/reflected', (req, res) => {
  const name = htmlEscape(req.query.name || 'guest');
  res.type('html').send(`<h1>Hello ${name}</h1>`);
});

/*
 * SAFE BAIT 5: fixed SQL text with positional parameters.
 */
app.get('/safe/sql/user', async (req, res) => {
  const result = await fakeDbQuery(
    'SELECT id, name, role FROM users WHERE id = ?',
    [String(req.query.id || '')]
  );
  res.json(result);
});

/* SAFE BAIT 6: dynamic ORDER BY selected from a closed map. */
app.get('/safe/sql/products', async (req, res) => {
  const orderBy = allowedSort(req.query.sort);
  const result = await fakeDbQuery(
    `SELECT id, name, price FROM products ORDER BY ${orderBy} LIMIT ?`,
    [positiveInteger(req.query.limit || 20, 100)]
  );
  res.json(result);
});

/* SAFE BAIT 7: numeric coercion before interpolation. */
app.get('/safe/sql/order', async (req, res) => {
  const id = positiveInteger(req.query.id);
  const result = await fakeDbQuery(
    `SELECT id, owner_id, total FROM orders WHERE numeric_id = ${id}`
  );
  res.json(result);
});

/*
 * TRUE POSITIVE 2: SQL injection-style string construction.
 * fakeDbQuery is intentionally a stand-in sink so the fixture remains dependency-free.
 */
app.get('/vuln/sql/search', async (req, res) => {
  const term = req.query.q || '';
  const result = await fakeDbQuery(
    `SELECT id, name FROM products WHERE name LIKE '%${term}%'`
  );
  res.json(result);
});

/*
 * SAFE BAIT 8: exact HTTPS hostname allowlist before fetch.
 */
app.post('/safe/ssrf/fetch', async (req, res) => {
  try {
    const target = exactOutboundUrl(req.body.url);
    const response = await fetch(target, {
      redirect: 'error',
      signal: AbortSignal.timeout(2000)
    });
    res.json({ status: response.status });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/* SAFE BAIT 9: user controls only an encoded path segment, never the host. */
app.get('/safe/ssrf/status/:service', async (req, res) => {
  const service = encodeURIComponent(req.params.service);
  const target = `https://status.example.com/services/${service}`;
  try {
    const response = await fetch(target, {
      redirect: 'error',
      signal: AbortSignal.timeout(2000)
    });
    res.json({ status: response.status });
  } catch {
    res.status(502).json({ error: 'upstream unavailable' });
  }
});

/*
 * TRUE POSITIVE 3: unrestricted server-side request.
 */
app.post('/vuln/ssrf/fetch', async (req, res) => {
  const response = await fetch(req.body.url);
  res.json({ status: response.status });
});

/*
 * SAFE BAIT 10: relative-only redirect validation.
 */
app.get('/safe/redirect', (req, res) => {
  res.redirect(302, safeRelativeRedirect(req.query.next, '/'));
});

/* SAFE BAIT 11: fixed internal prefix and encoded route segment. */
app.get('/safe/redirect/user/:id', (req, res) => {
  const id = encodeURIComponent(req.params.id);
  res.redirect(302, `/users/${id}`);
});

/*
 * TRUE POSITIVE 4: open redirect.
 */
app.get('/vuln/redirect', (req, res) => {
  res.redirect(req.query.next);
});

/*
 * SAFE BAIT 12: resolve then verify containment under DATA_ROOT.
 */
app.get('/safe/files/read', (req, res) => {
  try {
    const filename = resolveInside(DATA_ROOT, req.query.name);
    const contents = fs.readFileSync(filename, 'utf8');
    res.type('text/plain').send(contents);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/* SAFE BAIT 13: closed filename allowlist. */
app.get('/safe/files/report', (req, res) => {
  const reports = {
    daily: path.join(DATA_ROOT, 'daily.txt'),
    weekly: path.join(DATA_ROOT, 'weekly.txt')
  };
  const selected = reports[req.query.type] || reports.daily;
  res.type('text/plain').send(fs.readFileSync(selected, 'utf8'));
});

/*
 * TRUE POSITIVE 5: path traversal.
 */
app.get('/vuln/files/read', (req, res) => {
  const filename = path.join(DATA_ROOT, req.query.name || '');
  res.type('text/plain').send(fs.readFileSync(filename, 'utf8'));
});

/*
 * SAFE BAIT 14: execFile with a validated token passed as a separate argument.
 */
app.get('/safe/command/hash', (req, res) => {
  try {
    const algorithm = shellSafeToken(req.query.algorithm || 'sha256');
    const allowed = new Set(['sha256', 'sha512']);
    if (!allowed.has(algorithm)) throw new Error('algorithm denied');

    execFile(
      process.execPath,
      ['-e', `console.log(require("crypto").createHash("${algorithm}").update("demo").digest("hex"))`],
      { timeout: 1000, shell: false },
      (error, stdout) => {
        if (error) return res.status(500).json({ error: 'command failed' });
        res.json({ digest: stdout.trim() });
      }
    );
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/* SAFE BAIT 15: closed command mapping; user data never enters a shell string. */
app.get('/safe/command/tool', (req, res) => {
  const tools = {
    node: [process.execPath, ['--version']],
    platform: [process.execPath, ['-e', 'console.log(process.platform)']]
  };
  const selected = tools[req.query.name] || tools.node;

  execFile(selected[0], selected[1], { timeout: 1000, shell: false }, (error, stdout) => {
    if (error) return res.status(500).json({ error: 'command failed' });
    res.json({ output: stdout.trim() });
  });
});

/*
 * TRUE POSITIVE 6: command injection through shell concatenation.
 */
app.get('/vuln/command/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, { timeout: 2000 }, (error, stdout) => {
    if (error) return res.status(500).json({ error: 'command failed' });
    res.type('text/plain').send(stdout);
  });
});

/*
 * SAFE BAIT 16: authorization check before object access.
 */
app.get('/safe/orders/:id', (req, res) => {
  const user = currentUser(req);
  const order = orders.find(item => item.id === req.params.id);

  if (!user || !order) return res.status(404).json({ error: 'not found' });
  if (order.ownerId !== user.id && user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  res.json(order);
});

/*
 * TRUE POSITIVE 7: IDOR/BOLA; no ownership check.
 */
app.get('/vuln/orders/:id', (req, res) => {
  const order = orders.find(item => item.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'not found' });
  res.json(order);
});

/*
 * SAFE BAIT 17: admin middleware dominates the sensitive action.
 */
app.delete('/safe/admin/users/:id', requireAdmin, (req, res) => {
  users.delete(String(req.params.id));
  res.status(204).end();
});

/*
 * TRUE POSITIVE 8: sensitive action without authorization.
 */
app.delete('/vuln/admin/users/:id', (req, res) => {
  users.delete(String(req.params.id));
  res.status(204).end();
});

/*
 * SAFE BAIT 18: allowlisted object fields and null-prototype target.
 */
app.post('/safe/preferences', (req, res) => {
  const allowed = ['theme', 'locale', 'timezone'];
  const result = Object.create(null);

  for (const key of allowed) {
    if (Object.hasOwn(req.body, key) && typeof req.body[key] === 'string') {
      result[key] = req.body[key];
    }
  }
  res.json(result);
});

/*
 * TRUE POSITIVE 9: unsafe recursive merge permits __proto__/constructor keys.
 */
function unsafeMerge(target, source) {
  for (const key of Object.keys(source || {})) {
    if (source[key] && typeof source[key] === 'object') {
      target[key] = unsafeMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.post('/vuln/preferences', (req, res) => {
  const defaults = { theme: 'light', locale: 'en-US' };
  res.json(unsafeMerge(defaults, req.body));
});

/*
 * SAFE BAIT 19: cryptographically random reset token.
 */
app.post('/safe/reset-token', (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  res.json({ token });
});

/*
 * TRUE POSITIVE 10: predictable security token.
 */
app.post('/vuln/reset-token', (req, res) => {
  const token = `${Date.now()}-${Math.random()}`;
  res.json({ token });
});

app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    safeBaits: 19,
    plantedTruePositives: 10
  });
});

app.use((error, _req, res, _next) => {
  res.status(500).json({ error: 'internal error', detail: error.message });
});

app.listen(PORT, () => {
  console.log(`FAE benchmark listening on http://localhost:${PORT}`);
});
