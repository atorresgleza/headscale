// Disposable HTTPS client for staging only. Never print bearer tokens or passwords.
const assert = require('node:assert/strict');
const dns = require('node:dns').promises;
const fs = require('node:fs');
const https = require('node:https');
const path = require('node:path');

const host = 'hs.aaaagen.com';
const secret = '/staging/secret';
const base = `https://${host}`;
let enrollStage = 'link-read';
let enrollStatus = 'none';

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
  enrollStage = 'link-parse';
  const url = new URL(link);
  enrollStage = 'link-validate';
  assert.equal(url.origin, base);
  assert.equal(url.pathname, '/local-auth/enroll');
  assert.match(url.hash, /^#[A-Za-z0-9_-]{43}$/);
  enrollStage = 'page';
  const page = await request(url.pathname);
  enrollStatus = Number.isInteger(page.status) && page.status >= 100 && page.status <= 599 ? page.status : 'none';
  assert.equal(page.status, 200);
  enrollStage = 'form';
  const csrf = hidden(page.body);
  const enrollCookie = cookie(page.headers, '__Host-hs-local-enroll-csrf');
  enrollStage = 'submit';
  enrollStatus = 'none';
  const result = await request('/local-auth/enroll', 'POST', form({csrf, password: fs.readFileSync(path.join(secret, 'password'), 'utf8').trim(), token: url.hash.slice(1)}), enrollCookie);
  enrollStatus = Number.isInteger(result.status) && result.status >= 100 && result.status <= 599 ? result.status : 'none';
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
})().catch(error => {
  // Never print the exception: assertion messages can contain bearer fragments.
  if (process.argv[2] === 'enroll') {
    const code = error instanceof Error && Object.prototype.hasOwnProperty.call(error, 'code') ? error.code : null;
    let category = 'other';
    if (error instanceof assert.AssertionError) category = 'assertion';
    else if (enrollStage === 'link-read' && code === 'ENOENT') category = 'file-missing';
    else if (enrollStage === 'link-read' && (code === 'EACCES' || code === 'EPERM')) category = 'file-denied';
    else if (enrollStage === 'link-parse' && code === 'ERR_INVALID_URL') category = 'invalid-url';
    else if (['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH'].includes(code) &&
      (enrollStage === 'page' || enrollStage === 'submit')) category = 'transport';
    console.error(`staging flow failed stage=${enrollStage} status=${enrollStatus} category=${category}`);
  } else {
    console.error('staging flow failed; inspect only sanitized status evidence');
  }
  process.exitCode = 1;
});
