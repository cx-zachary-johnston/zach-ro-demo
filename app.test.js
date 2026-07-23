'use strict';

/**
 * Tests for the reflected XSS fix on the /vuln/xss/reflected endpoint.
 *
 * Uses the Node.js built-in test runner (node:test) and assert module —
 * no additional dependencies required (requires Node >= 18, project uses >= 20).
 *
 * Run with: node --test app.test.js
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

// ---------------------------------------------------------------------------
// Minimal inline test helpers
// ---------------------------------------------------------------------------

/**
 * Sends an HTTP GET request and resolves with { statusCode, headers, body }.
 * @param {string} urlString
 * @returns {Promise<{statusCode: number, headers: object, body: string}>}
 */
function get(urlString) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const options = {
      hostname: url.hostname,
      port: Number(url.port),
      path: url.pathname + url.search,
      method: 'GET'
    };

    const req = http.request(options, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
    });

    req.on('error', reject);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Import the app and start a test server on an ephemeral port
// ---------------------------------------------------------------------------

// We need to isolate app loading so it listens on a random free port.
// Override the PORT env var before requiring the module.
const ORIGINAL_PORT = process.env.PORT;
process.env.PORT = '0'; // 0 = OS assigns a free port

// app.js calls app.listen() at module load time and exports nothing useful for
// testing; we intercept the server through the listening event instead.
let server;
let baseUrl;

// Patch net.Server.listen to capture the assigned port from PORT=0.
const net = require('node:net');
const originalListen = net.Server.prototype.listen;
let capturedServer = null;
net.Server.prototype.listen = function (...args) {
  capturedServer = this;
  return originalListen.apply(this, args);
};

require('./app');

// Restore
net.Server.prototype.listen = originalListen;
if (ORIGINAL_PORT !== undefined) {
  process.env.PORT = ORIGINAL_PORT;
} else {
  delete process.env.PORT;
}

// ---------------------------------------------------------------------------
// Wait until the server is actually listening before running tests
// ---------------------------------------------------------------------------

before(() => new Promise((resolve) => {
  if (!capturedServer) {
    throw new Error('Could not capture the Express HTTP server');
  }
  server = capturedServer;
  if (server.listening) {
    const { port } = server.address();
    baseUrl = `http://127.0.0.1:${port}`;
    resolve();
  } else {
    server.once('listening', () => {
      const { port } = server.address();
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  }
}));

after(() => new Promise((resolve) => {
  if (server && server.listening) {
    server.close(resolve);
  } else {
    resolve();
  }
}));

// ---------------------------------------------------------------------------
// Tests for the reflected XSS fix
// ---------------------------------------------------------------------------

describe('GET /vuln/xss/reflected — reflected XSS remediation', () => {

  test('returns 200 with text/html content-type', async () => {
    const { statusCode, headers } = await get(`${baseUrl}/vuln/xss/reflected?name=Alice`);
    assert.equal(statusCode, 200);
    assert.match(headers['content-type'], /text\/html/);
  });

  test('renders safe plain-text name without alteration', async () => {
    const { body } = await get(`${baseUrl}/vuln/xss/reflected?name=Alice`);
    assert.ok(body.includes('Hello Alice'), `Expected "Hello Alice" in: ${body}`);
  });

  test('uses "guest" as default when name query param is absent', async () => {
    const { body } = await get(`${baseUrl}/vuln/xss/reflected`);
    assert.ok(body.includes('Hello guest'), `Expected "Hello guest" in: ${body}`);
  });

  // ----- XSS attack vectors that MUST be escaped --------------------------

  test('HTML-escapes a <script> tag injection attempt', async () => {
    const payload = '<script>alert(1)</script>';
    const { body } = await get(`${baseUrl}/vuln/xss/reflected?name=${encodeURIComponent(payload)}`);

    // The literal tag must NOT appear verbatim in the response.
    assert.ok(!body.includes('<script>'), `Raw <script> tag found in response: ${body}`);
    // The opening angle-bracket must be entity-encoded.
    assert.ok(body.includes('&lt;script&gt;'), `Expected &lt;script&gt; in response: ${body}`);
  });

  test('HTML-escapes an img onerror XSS payload', async () => {
    const payload = '<img src=x onerror=alert(1)>';
    const { body } = await get(`${baseUrl}/vuln/xss/reflected?name=${encodeURIComponent(payload)}`);

    assert.ok(!body.includes('<img'), `Raw <img> tag found in response: ${body}`);
    assert.ok(body.includes('&lt;img'), `Expected &lt;img in response: ${body}`);
  });

  test('HTML-escapes a double-quote to prevent attribute breakout', async () => {
    const payload = '"onmouseover="alert(1)';
    const { body } = await get(`${baseUrl}/vuln/xss/reflected?name=${encodeURIComponent(payload)}`);

    // The raw double-quote must be replaced with &quot;
    assert.ok(!body.includes('"onmouseover='), `Unescaped attribute breakout found in: ${body}`);
    assert.ok(body.includes('&quot;'), `Expected &quot; encoding in: ${body}`);
  });

  test("HTML-escapes a single-quote to prevent attribute breakout", async () => {
    const payload = "'onmouseover='alert(1)'";
    const { body } = await get(`${baseUrl}/vuln/xss/reflected?name=${encodeURIComponent(payload)}`);

    assert.ok(!body.includes("'onmouseover="), `Unescaped single-quote attribute breakout found in: ${body}`);
    assert.ok(body.includes('&#39;'), `Expected &#39; encoding in: ${body}`);
  });

  test('HTML-escapes an ampersand to prevent HTML entity injection', async () => {
    const payload = '&lt;script&gt;';
    const { body } = await get(`${baseUrl}/vuln/xss/reflected?name=${encodeURIComponent(payload)}`);

    // The raw & must become &amp; so the pre-encoded sequence cannot be
    // re-decoded by the browser into a script tag.
    assert.ok(body.includes('&amp;lt;script&amp;gt;'), `Expected double-encoded output in: ${body}`);
  });

  test('HTML-escapes angle brackets in a full XSS polyglot', async () => {
    const payload = '"><svg onload=alert(1)>';
    const { body } = await get(`${baseUrl}/vuln/xss/reflected?name=${encodeURIComponent(payload)}`);

    assert.ok(!body.includes('"><svg'), `Raw polyglot found in response: ${body}`);
    assert.ok(body.includes('&quot;&gt;'), `Expected encoded output in: ${body}`);
  });

  // ----- Regression: safe baits must still work correctly -----------------

  test('safe bait /safe/xss/escaped still encodes correctly (regression)', async () => {
    const payload = '<b>bold</b>';
    const { body } = await get(`${baseUrl}/safe/xss/escaped?name=${encodeURIComponent(payload)}`);

    assert.ok(!body.includes('<b>'), `Raw tag should not appear in safe bait response: ${body}`);
    assert.ok(body.includes('&lt;b&gt;'), `Expected &lt;b&gt; in safe bait response: ${body}`);
  });

  test('safe bait /safe/xss/json returns JSON, not HTML (regression)', async () => {
    const payload = '<script>evil()</script>';
    const { statusCode, headers, body } = await get(
      `${baseUrl}/safe/xss/json?value=${encodeURIComponent(payload)}`
    );

    assert.equal(statusCode, 200);
    assert.match(headers['content-type'], /application\/json/);
    // JSON serialisation must escape the string — raw tag must not appear.
    assert.ok(!body.includes('<script>'), `Raw script tag found in JSON response: ${body}`);
  });

});
