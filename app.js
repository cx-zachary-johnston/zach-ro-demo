'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const { exec, execFile } = require('child_process');
const crypto = require('crypto');

// Mock requires for libraries used in vulnerability examples
// These would normally be installed via npm
const jwt = { 
  sign: (payload, secret, options) => 'mock.jwt.token',
  verify: (token, secret, options) => ({ sub: 'user123' })
};
const Handlebars = { 
  compile: (template) => (data) => template.replace(/{{(\w+)}}/g, (_, key) => data[key] || '') 
};
const Mustache = { 
  render: (template, data) => template.replace(/{{(\w+)}}/g, (_, key) => data[key] || '') 
};
const emailValidator = { 
  validate: (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) 
};
const libxmljs = {
  parseXml: (xml, options) => ({
    root: () => ({ name: () => 'root' }),
    toString: () => xml
  })
};
const AdmZip = class {
  constructor(buffer) { this.buffer = buffer; }
  getEntries() { return [{ entryName: 'file.txt' }]; }
  extractEntryTo() {}
};
const bcrypt = {
  hash: async (password, rounds) => `$2b$${rounds}$hashedpassword`,
  compare: async (password, hash) => true
};
const depthLimit = (max) => (query) => true;

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
 * TRUE POSITIVE 1: reflected XSS.
 */
app.get('/vuln/xss/reflected', (req, res) => {
  res.type('html').send(`<h1>Hello ${req.query.name || 'guest'}</h1>`);
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

/*
 * SAFE BAIT 20: hardcoded credential-like string, but it's a test/example value.
 */
app.get('/safe/config/example', (req, res) => {
  const exampleConfig = {
    apiKey: 'EXAMPLE_KEY_12345',
    endpoint: 'https://api.example.com',
    note: 'Replace with actual credentials'
  };
  res.json(exampleConfig);
});

/*
 * TRUE POSITIVE 11: hardcoded sensitive credential.
 */
const API_SECRET = 'sk_live_51HqKyH2eZvKYlo2C9qDfJ6nh7wXyZ4pQ3rT8sV';
app.post('/vuln/payment/charge', (req, res) => {
  res.json({ secret: API_SECRET, amount: req.body.amount });
});

/*
 * SAFE BAIT 21: regex with quantifiers on structured input (email validation).
 */
app.post('/safe/validate/email', (req, res) => {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const email = String(req.body.email || '').slice(0, 254);
  const isValid = emailRegex.test(email);
  res.json({ valid: isValid });
});

/*
 * TRUE POSITIVE 12: ReDoS vulnerability with catastrophic backtracking.
 */
app.post('/vuln/validate/complex', (req, res) => {
  const complexRegex = /^(a+)+$/;
  const input = String(req.body.input || '');
  const isValid = complexRegex.test(input);
  res.json({ valid: isValid });
});

/*
 * SAFE BAIT 22: JWT verification with proper secret.
 */
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

app.post('/safe/auth/verify', (req, res) => {
  try {
    const decoded = jwt.verify(req.body.token, JWT_SECRET, { algorithms: ['HS256'] });
    res.json({ valid: true, user: decoded.sub });
  } catch (error) {
    res.status(401).json({ valid: false, error: error.message });
  }
});

/*
 * TRUE POSITIVE 13: JWT verification without algorithm restriction (algorithm confusion).
 */
app.post('/vuln/auth/verify', (req, res) => {
  try {
    const decoded = jwt.verify(req.body.token, JWT_SECRET);
    res.json({ valid: true, user: decoded.sub });
  } catch (error) {
    res.status(401).json({ valid: false, error: error.message });
  }
});

/*
 * SAFE BAIT 23: Deserialization of JSON (safe).
 */
app.post('/safe/deserialize/json', (req, res) => {
  const data = JSON.parse(req.body.data || '{}');
  res.json({ parsed: data });
});

/*
 * TRUE POSITIVE 14: Unsafe deserialization (eval on user input).
 */
app.post('/vuln/deserialize/eval', (req, res) => {
  const result = eval(`(${req.body.code})`);
  res.json({ result });
});

/*
 * SAFE BAIT 24: Cookie with httpOnly and secure flags.
 */
app.post('/safe/auth/login', (req, res) => {
  const sessionId = crypto.randomBytes(16).toString('hex');
  res.cookie('session', sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 3600000
  });
  res.json({ status: 'logged in' });
});

/*
 * TRUE POSITIVE 15: Cookie without security flags (missing httpOnly/secure).
 */
app.post('/vuln/auth/login', (req, res) => {
  const sessionId = crypto.randomBytes(16).toString('hex');
  res.cookie('session', sessionId, { maxAge: 3600000 });
  res.json({ status: 'logged in' });
});

/*
 * SAFE BAIT 25: Rate limiting present on sensitive endpoint.
 */
const rateLimits = new Map();
app.post('/safe/auth/password-reset', (req, res) => {
  const email = String(req.body.email || '');
  const key = `reset:${email}`;
  const now = Date.now();
  const lastAttempt = rateLimits.get(key) || 0;
  
  if (now - lastAttempt < 60000) {
    return res.status(429).json({ error: 'too many requests' });
  }
  
  rateLimits.set(key, now);
  res.json({ status: 'reset email sent' });
});

/*
 * TRUE POSITIVE 16: No rate limiting on authentication endpoint.
 */
app.post('/vuln/auth/password-reset', (req, res) => {
  const email = String(req.body.email || '');
  res.json({ status: 'reset email sent', email });
});

/*
 * SAFE BAIT 26: CORS with specific origin allowlist.
 */
app.get('/safe/api/public', (req, res) => {
  const allowedOrigins = ['https://app.example.com', 'https://mobile.example.com'];
  const origin = req.header('origin');
  
  if (origin && allowedOrigins.includes(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
  }
  res.json({ data: 'public data' });
});

/*
 * TRUE POSITIVE 17: Overly permissive CORS (wildcard with credentials).
 */
app.get('/vuln/api/cors', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Credentials', 'true');
  res.json({ sensitive: 'user data' });
});

/*
 * SAFE BAIT 27: XML parsing with external entities disabled.
 */
const libxmljs = require('libxmljs');
app.post('/safe/xml/parse', (req, res) => {
  try {
    const doc = libxmljs.parseXml(req.body.xml, { noent: false, dtdload: false });
    res.json({ parsed: true, root: doc.root().name() });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/*
 * TRUE POSITIVE 18: XXE vulnerability (external entity processing enabled).
 */
app.post('/vuln/xml/parse', (req, res) => {
  try {
    const doc = libxmljs.parseXml(req.body.xml, { noent: true, dtdload: true });
    res.json({ parsed: true, content: doc.toString() });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/*
 * SAFE BAIT 28: File upload with type and size validation.
 */
app.post('/safe/upload/avatar', (req, res) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
  const maxSize = 5 * 1024 * 1024; // 5MB
  
  if (!allowedTypes.includes(req.body.type)) {
    return res.status(400).json({ error: 'invalid file type' });
  }
  
  if (req.body.size > maxSize) {
    return res.status(400).json({ error: 'file too large' });
  }
  
  res.json({ status: 'uploaded', filename: `avatar-${Date.now()}.jpg` });
});

/*
 * TRUE POSITIVE 19: Unrestricted file upload (no validation).
 */
app.post('/vuln/upload/document', (req, res) => {
  const filename = req.body.filename || 'upload.bin';
  const uploadPath = path.join(PUBLIC_ROOT, filename);
  fs.writeFileSync(uploadPath, req.body.content || '');
  res.json({ status: 'uploaded', path: uploadPath });
});

/*
 * SAFE BAIT 29: Constant-time comparison for secrets.
 */
app.post('/safe/auth/api-key', (req, res) => {
  const providedKey = String(req.body.apiKey || '');
  const validKey = process.env.API_KEY || 'default-key-12345';
  
  if (crypto.timingSafeEqual(Buffer.from(providedKey), Buffer.from(validKey))) {
    res.json({ authenticated: true });
  } else {
    res.status(401).json({ authenticated: false });
  }
});

/*
 * TRUE POSITIVE 20: Timing attack vulnerability (non-constant-time comparison).
 */
app.post('/vuln/auth/api-key', (req, res) => {
  const providedKey = String(req.body.apiKey || '');
  const validKey = process.env.API_KEY || 'sk_live_key_12345';
  
  if (providedKey === validKey) {
    res.json({ authenticated: true });
  } else {
    res.status(401).json({ authenticated: false });
  }
});

/*
 * SAFE BAIT 30: Logging with sanitized sensitive data.
 */
app.post('/safe/logging/request', (req, res) => {
  const sanitized = {
    ...req.body,
    password: req.body.password ? '***REDACTED***' : undefined,
    apiKey: req.body.apiKey ? '***REDACTED***' : undefined
  };
  console.log('Request received:', sanitized);
  res.json({ status: 'logged' });
});

/*
 * TRUE POSITIVE 21: Sensitive data exposure in logs.
 */
app.post('/vuln/logging/request', (req, res) => {
  console.log('Full request body:', req.body);
  res.json({ status: 'logged' });
});

/*
 * SAFE BAIT 31: Template rendering with auto-escaping enabled.
 */
const Handlebars = require('handlebars');
app.get('/safe/template/welcome', (req, res) => {
  const template = Handlebars.compile('<h1>Welcome {{name}}</h1>');
  const html = template({ name: req.query.name || 'guest' });
  res.type('html').send(html);
});

/*
 * TRUE POSITIVE 22: Server-Side Template Injection (SSTI).
 */
const Mustache = require('mustache');
app.post('/vuln/template/render', (req, res) => {
  const template = req.body.template || 'Hello {{name}}';
  const html = Mustache.render(template, { name: req.body.name });
  res.type('html').send(html);
});

/*
 * SAFE BAIT 32: Cryptographically secure random for session ID.
 */
app.post('/safe/session/create', (req, res) => {
  const sessionId = crypto.randomBytes(32).toString('base64');
  const csrf = crypto.randomBytes(24).toString('base64');
  res.json({ sessionId, csrf });
});

/*
 * TRUE POSITIVE 23: Weak random for security-critical operation.
 */
app.post('/vuln/session/create', (req, res) => {
  const sessionId = Math.random().toString(36).substring(2, 15);
  const csrf = Math.random().toString(36).substring(2, 10);
  res.json({ sessionId, csrf });
});

/*
 * SAFE BAIT 33: Input validation with allowlist on numeric parameter.
 */
app.get('/safe/api/limit', (req, res) => {
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 10));
  res.json({ limit, items: [] });
});

/*
 * TRUE POSITIVE 24: Integer overflow in limit parameter.
 */
app.get('/vuln/api/limit', (req, res) => {
  const limit = parseInt(req.query.limit) || 10;
  const items = new Array(limit).fill('item');
  res.json({ limit, items });
});

/*
 * SAFE BAIT 34: Error handling with generic message.
 */
app.get('/safe/database/query', async (req, res) => {
  try {
    const result = await fakeDbQuery('SELECT * FROM users WHERE id = ?', [req.query.id]);
    res.json(result);
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

/*
 * TRUE POSITIVE 25: Information disclosure through detailed error messages.
 */
app.get('/vuln/database/query', async (req, res) => {
  try {
    const result = await fakeDbQuery('SELECT * FROM users WHERE id = ?', [req.query.id]);
    res.json(result);
  } catch (error) {
    res.status(500).json({ 
      error: error.message,
      stack: error.stack,
      query: 'SELECT * FROM users WHERE id = ?'
    });
  }
});

/*
 * SAFE BAIT 35: Object creation with allowlisted properties.
 */
app.post('/safe/profile/update', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  
  const allowedFields = ['name', 'bio', 'avatar'];
  const updates = {};
  
  for (const field of allowedFields) {
    if (req.body[field] !== undefined) {
      updates[field] = String(req.body[field]);
    }
  }
  
  res.json({ updated: updates });
});

/*
 * TRUE POSITIVE 26: Mass assignment vulnerability.
 */
app.post('/vuln/profile/update', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  
  Object.assign(user, req.body);
  res.json({ user });
});

/*
 * SAFE BAIT 36: NoSQL query with parameterized operator.
 */
const fakeMongoQuery = (collection, query) => {
  return Promise.resolve({ collection, query, results: [] });
};

app.get('/safe/nosql/users', async (req, res) => {
  const username = String(req.query.username || '');
  const result = await fakeMongoQuery('users', { username: { $eq: username } });
  res.json(result);
});

/*
 * TRUE POSITIVE 27: NoSQL injection.
 */
app.get('/vuln/nosql/users', async (req, res) => {
  const query = req.query.filter ? JSON.parse(req.query.filter) : {};
  const result = await fakeMongoQuery('users', query);
  res.json(result);
});

/*
 * SAFE BAIT 37: LDAP query with proper escaping.
 */
function escapeLdap(str) {
  return String(str)
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

app.get('/safe/ldap/search', (req, res) => {
  const username = escapeLdap(req.query.username || '');
  const filter = `(uid=${username})`;
  res.json({ filter, results: [] });
});

/*
 * TRUE POSITIVE 28: LDAP injection.
 */
app.get('/vuln/ldap/search', (req, res) => {
  const username = req.query.username || '';
  const filter = `(uid=${username})`;
  res.json({ filter, results: [] });
});

/*
 * SAFE BAIT 38: Response header with validated input.
 */
app.get('/safe/download/file', (req, res) => {
  const allowedFiles = {
    'report': 'monthly-report.pdf',
    'invoice': 'invoice-2024.pdf'
  };
  const filename = allowedFiles[req.query.type] || 'document.pdf';
  res.set('Content-Disposition', `attachment; filename="${filename}"`);
  res.send('file content');
});

/*
 * TRUE POSITIVE 29: HTTP response header injection.
 */
app.get('/vuln/download/file', (req, res) => {
  const filename = req.query.filename || 'document.pdf';
  res.set('Content-Disposition', `attachment; filename="${filename}"`);
  res.send('file content');
});

/*
 * SAFE BAIT 39: Pagination with proper bounds checking.
 */
app.get('/safe/api/posts', (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize) || 20));
  const offset = (page - 1) * pageSize;
  
  res.json({ page, pageSize, offset, items: [] });
});

/*
 * TRUE POSITIVE 30: Unbounded resource allocation.
 */
app.get('/vuln/api/posts', (req, res) => {
  const pageSize = parseInt(req.query.pageSize) || 20;
  const items = new Array(pageSize).fill(null).map((_, i) => ({ id: i, title: 'Post' }));
  res.json({ items });
});

/*
 * SAFE BAIT 40: Email header with validation.
 */
const emailValidator = require('email-validator');
app.post('/safe/email/send', (req, res) => {
  const to = String(req.body.to || '');
  
  if (!emailValidator.validate(to) || to.includes('\n') || to.includes('\r')) {
    return res.status(400).json({ error: 'invalid email' });
  }
  
  res.json({ status: 'sent', to });
});

/*
 * TRUE POSITIVE 31: Email header injection.
 */
app.post('/vuln/email/send', (req, res) => {
  const to = req.body.to || 'default@example.com';
  const subject = req.body.subject || 'No subject';
  const headers = `To: ${to}\nSubject: ${subject}`;
  res.json({ status: 'sent', headers });
});

/*
 * SAFE BAIT 41: Archive extraction with path validation.
 */
const AdmZip = require('adm-zip');
app.post('/safe/archive/extract', (req, res) => {
  try {
    const zip = new AdmZip(Buffer.from(req.body.zipData, 'base64'));
    const entries = zip.getEntries();
    const extracted = [];
    
    for (const entry of entries) {
      const entryPath = entry.entryName;
      if (entryPath.includes('..') || path.isAbsolute(entryPath)) {
        continue; // Skip dangerous paths
      }
      const targetPath = resolveInside(DATA_ROOT, entryPath);
      extracted.push(entryPath);
    }
    
    res.json({ extracted });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/*
 * TRUE POSITIVE 32: Zip Slip vulnerability (path traversal in archive).
 */
app.post('/vuln/archive/extract', (req, res) => {
  try {
    const zip = new AdmZip(Buffer.from(req.body.zipData, 'base64'));
    const entries = zip.getEntries();
    const extracted = [];
    
    for (const entry of entries) {
      const targetPath = path.join(DATA_ROOT, entry.entryName);
      extracted.push(targetPath);
      // In real code: zip.extractEntryTo(entry, DATA_ROOT, false, true);
    }
    
    res.json({ extracted });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/*
 * SAFE BAIT 42: CSV export with proper escaping.
 */
function escapeCSV(field) {
  const str = String(field || '');
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

app.get('/safe/export/csv', (req, res) => {
  const data = [
    { name: req.query.name || 'John', email: 'john@example.com' }
  ];
  const csv = data.map(row => 
    `${escapeCSV(row.name)},${escapeCSV(row.email)}`
  ).join('\n');
  
  res.type('text/csv').send(`Name,Email\n${csv}`);
});

/*
 * TRUE POSITIVE 33: CSV injection.
 */
app.get('/vuln/export/csv', (req, res) => {
  const name = req.query.name || 'John';
  const email = req.query.email || 'john@example.com';
  const csv = `Name,Email\n${name},${email}`;
  res.type('text/csv').send(csv);
});

/*
 * SAFE BAIT 43: GraphQL query with depth limiting.
 */
const depthLimit = require('graphql-depth-limit');
app.post('/safe/graphql', (req, res) => {
  const query = req.body.query || '';
  const maxDepth = 5;
  
  // Simplified depth check
  const depth = (query.match(/{/g) || []).length;
  if (depth > maxDepth) {
    return res.status(400).json({ error: 'query too deep' });
  }
  
  res.json({ data: {} });
});

/*
 * TRUE POSITIVE 34: GraphQL query without depth limiting (DoS).
 */
app.post('/vuln/graphql', (req, res) => {
  const query = req.body.query || '';
  // Execute without depth limit - allows deeply nested queries
  res.json({ data: {}, query });
});

/*
 * SAFE BAIT 44: File inclusion with allowlist.
 */
app.get('/safe/include/template', (req, res) => {
  const templates = {
    'header': path.join(__dirname, 'templates', 'header.html'),
    'footer': path.join(__dirname, 'templates', 'footer.html')
  };
  
  const templatePath = templates[req.query.template] || templates.header;
  
  try {
    const content = fs.readFileSync(templatePath, 'utf8');
    res.type('html').send(content);
  } catch (error) {
    res.status(404).json({ error: 'template not found' });
  }
});

/*
 * TRUE POSITIVE 35: Local File Inclusion (LFI).
 */
app.get('/vuln/include/template', (req, res) => {
  const templatePath = path.join(__dirname, 'templates', req.query.template || 'default.html');
  
  try {
    const content = fs.readFileSync(templatePath, 'utf8');
    res.type('html').send(content);
  } catch (error) {
    res.status(404).json({ error: 'template not found' });
  }
});

/*
 * SAFE BAIT 45: JWT with expiration check.
 */
app.post('/safe/auth/token', (req, res) => {
  const payload = {
    sub: req.body.userId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
  };
  const token = jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
  res.json({ token });
});

/*
 * TRUE POSITIVE 36: JWT without expiration.
 */
app.post('/vuln/auth/token', (req, res) => {
  const payload = {
    sub: req.body.userId,
    iat: Math.floor(Date.now() / 1000)
  };
  const token = jwt.sign(payload, JWT_SECRET);
  res.json({ token });
});

/*
 * SAFE BAIT 46: Server resource with timeout.
 */
app.post('/safe/api/process', async (req, res) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  
  try {
    const response = await fetch(req.body.url, {
      signal: controller.signal,
      redirect: 'error'
    });
    clearTimeout(timeout);
    res.json({ status: response.status });
  } catch (error) {
    clearTimeout(timeout);
    res.status(500).json({ error: 'request failed' });
  }
});

/*
 * TRUE POSITIVE 37: Resource exhaustion (no timeout).
 */
app.post('/vuln/api/process', async (req, res) => {
  try {
    const response = await fetch(req.body.url);
    const data = await response.text(); // Could be infinite stream
    res.json({ size: data.length });
  } catch (error) {
    res.status(500).json({ error: 'request failed' });
  }
});

/*
 * SAFE BAIT 47: Privilege escalation prevention with proper check.
 */
app.post('/safe/users/:id/promote', requireAdmin, (req, res) => {
  const targetUser = users.get(req.params.id);
  if (!targetUser) return res.status(404).json({ error: 'user not found' });
  
  targetUser.role = 'admin';
  res.json({ user: targetUser });
});

/*
 * TRUE POSITIVE 38: Privilege escalation (user can promote themselves).
 */
app.post('/vuln/users/:id/promote', (req, res) => {
  const user = currentUser(req);
  const targetUser = users.get(req.params.id);
  
  if (!user || !targetUser) return res.status(404).json({ error: 'not found' });
  
  targetUser.role = 'admin';
  res.json({ user: targetUser });
});

/*
 * SAFE BAIT 48: URL parameter with proper encoding.
 */
app.get('/safe/search/redirect', (req, res) => {
  const query = encodeURIComponent(req.query.q || '');
  const url = `https://search.example.com/results?q=${query}`;
  res.redirect(302, url);
});

/*
 * TRUE POSITIVE 39: URL parameter injection.
 */
app.get('/vuln/search/redirect', (req, res) => {
  const query = req.query.q || '';
  const url = `https://search.example.com/results?q=${query}`;
  res.redirect(302, url);
});

/*
 * SAFE BAIT 49: Password hashing with bcrypt.
 */
const bcrypt = require('bcrypt');
app.post('/safe/auth/register', async (req, res) => {
  const password = String(req.body.password || '');
  const hashedPassword = await bcrypt.hash(password, 12);
  res.json({ success: true, hash: hashedPassword });
});

/*
 * TRUE POSITIVE 40: Weak password hashing (MD5).
 */
app.post('/vuln/auth/register', (req, res) => {
  const password = String(req.body.password || '');
  const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
  res.json({ success: true, hash: hashedPassword });
});

app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    safeBaits: 49,
    plantedTruePositives: 40
  });
});

app.use((error, _req, res, _next) => {
  res.status(500).json({ error: 'internal error', detail: error.message });
});

app.listen(PORT, () => {
  console.log(`FAE benchmark listening on http://localhost:${PORT}`);
});
