// Disposable HTTPS client for staging only. Never print bearer tokens or passwords.
const assert = require('node:assert/strict');
const dns = require('node:dns').promises;
const fs = require('node:fs');
const https = require('node:https');
const path = require('node:path');

const host = 'hs.aaaagen.com';
const secret = '/staging/secret';
const base = `https://${host}`;

function hidden(html) {
  const match = html.match(/name="csrf" value="([A-Za-z0-9_-]{43})"/);
  assert.ok(match, 'missing form CSRF');
  return match[1];
}
function cookie(headers, name) {
  const value = (headers['set-cookie'] || []).find(line => line.startsWith(`${name}=`));
  assert.ok(value, `missing ${name} cookie`);
  return value.split(';', 1)[0];
}
function form(fields) { return new URLSearchParams(fields).toString(); }
function request(route, method = 'GET', body, sessionCookie) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (body !== undefined) {
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      headers.Origin = base;
    }
    if (sessionCookie) headers.Cookie = sessionCookie;
    const req = https.request(new URL(route, base), {method, headers, timeout: 8000}, res => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { data += chunk; if (data.length > 65536) req.destroy(new Error('response too large')); });
      res.on('end', () => resolve({status: res.statusCode, headers: res.headers, body: data}));
    });
    req.on('timeout', () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    req.end(body);
  });
}
async function preflight() {
  const answers = await dns.lookup(host, {all: true});
  assert.ok(answers.length > 0 && answers.every(answer => answer.address === '172.30.88.3'), 'DNS alias does not point exclusively to staging Traefik');
  const health = await request('/local-auth/enroll');
  assert.equal(health.status, 200, 'trusted CA/hostname/HTTPS staging preflight failed');
  console.log('PASS internal DNS alias and test CA HTTPS validation');
}
async function enroll() {
  const link = fs.readFileSync(path.join(secret, 'invitation'), 'utf8').trim();
  const url = new URL(link);
  assert.equal(url.origin, base);
  assert.equal(url.pathname, '/local-auth/enroll');
  assert.match(url.hash, /^#[A-Za-z0-9_-]{43}$/);
  const page = await request(url.pathname);
  assert.equal(page.status, 200);
  const result = await request('/local-auth/enroll', 'POST', form({csrf: hidden(page.body), password: fs.readFileSync(path.join(secret, 'password'), 'utf8').trim(), token: url.hash.slice(1)}), cookie(page.headers, '__Host-hs-local-enroll-csrf'));
  assert.equal(result.status, 204, 'enrollment must consume the invitation');
  console.log('PASS staging invitation redeemed over CA-verified HTTPS');
}
function authPath() {
  const output = fs.readFileSync(path.join(secret, 'login.out'), 'utf8');
  const found = output.match(/https:\/\/hs\.aaaagen\.com\/register\/[A-Za-z0-9_-]+/);
  assert.ok(found, 'no staging registration URL from real client');
  const url = new URL(found[0]);
  assert.equal(url.origin, base);
  return url.pathname;
}
async function login() {
  const pagePath = authPath();
  const page = await request(pagePath);
  assert.equal(page.status, 200, 'pending real client did not reach local login page');
  const session = await request(pagePath.replace('/register/', '/register/login/'), 'POST', form({csrf: hidden(page.body), name: 'staging-test-user', password: fs.readFileSync(path.join(secret, 'password'), 'utf8').trim()}), cookie(page.headers, '__Host-hs-local-login-csrf'));
  assert.equal(session.status, 200, 'password login failed');
  assert.match(session.body, /Approve this device/);
  const approval = {path: pagePath.replace('/register/', '/register/confirm/'), csrf: hidden(session.body), cookie: cookie(session.headers, '__Host-hs-local-approval')};
  fs.writeFileSync(path.join(secret, 'approval.json'), JSON.stringify(approval), {mode: 0o600});
  console.log('PASS real client pending; password login displays explicit review, no approval submitted');
}
async function approve() {
  const approval = JSON.parse(fs.readFileSync(path.join(secret, 'approval.json'), 'utf8'));
  const body = form({csrf: approval.csrf});
  const accepted = await request(approval.path, 'POST', body, approval.cookie);
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body, 'Device approved.\n');
  const replay = await request(approval.path, 'POST', body, approval.cookie);
  assert.equal(replay.status, 403, 'confirmation replay must fail');
  console.log('PASS explicit confirmation registered device; replay rejected');
}
(async () => {
  const action = process.argv[2];
  if (action === 'preflight') await preflight();
  else if (action === 'enroll') await enroll();
  else if (action === 'login') await login();
  else if (action === 'approve') await approve();
  else throw new Error('usage: client-flow.cjs preflight|enroll|login|approve');
})().catch(() => {
  // Assertion errors can quote input, including the invitation fragment.
  console.error('staging flow failed; inspect only sanitized status evidence');
  process.exitCode = 1;
});
