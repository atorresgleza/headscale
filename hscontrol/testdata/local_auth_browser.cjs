// Run against the build-tagged, disposable TLS fixture. Install
// playwright-core@1.58.0 into a container-local /tmp directory and set
// NODE_PATH=/tmp/node_modules; never target the deployed server.
const assert = require('node:assert/strict');
const { chromium } = require('playwright-core');

(async () => {
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox']});
  try {
    const context = await browser.newContext({ignoreHTTPSErrors: true});
    const page = await context.newPage();
    const requests = [];
    page.on('request', request => requests.push(request.url()));
    // A client-supplied transport header must be overwritten by the fixture.
    await page.setExtraHTTPHeaders({'X-Forwarded-Proto': 'http'});
    const url = 'https://localhost:18765/local-auth/enroll';
    const response = await page.goto(url + '#browser-fixture-token', {waitUntil: 'domcontentloaded'});
    assert.equal(response.status(), 200);
    assert.equal(page.url(), url);
    assert.equal(await page.evaluate(() => location.hash), '');
    assert.equal(await page.evaluate(() => document.cookie), '');
    assert.ok(requests.every(requestURL => !requestURL.includes('browser-fixture-token')));
    const cookies = await context.cookies('https://localhost:18765');
    const csrf = cookies.find(cookie => cookie.name === '__Host-hs-local-enroll-csrf');
    assert.ok(csrf);
    assert.equal(csrf.secure, true);
    assert.equal(csrf.httpOnly, true);
    assert.equal(csrf.sameSite, 'Strict');
    assert.equal(csrf.path, '/');
    await page.getByLabel('Password').fill('correct horse battery staple');
    await page.getByRole('button', {name: 'Set password'}).click();
    await page.getByRole('status').getByText('Unable to enroll.').waitFor();
    assert.equal(page.url(), url);
    const done = await context.request.get('https://localhost:18765/__fixture_done');
    assert.equal(done.status(), 204);
    console.log('PASS isolated browser fragment, host cookie, spoofed XFP and generic rejection');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
