'use strict';
/*
 * Headless-Chrome driver for the issuer.eudiw.dev reference issuer test flow.
 * Automates the parts a human would click in a browser so the whole PID issuance
 * runs headless (paired with the Kotlin LiveIssuanceTest for PAR + token exchange).
 *
 *   node drive.js offer <out-offer-file>
 *       Drive the credential-offer portal (pick PID SD-JWT VC, submit) and write the
 *       resulting `haip-vci://credential_offer?...` deep link.
 *
 *   node drive.js auth <authorization-url-file> <out-redirect-file> [--data data.json]
 *       Open the authorization URL, select the FormEU (FC) test country, fill the test
 *       PID form, click Authorize, and write the final `https://<redirect>?code=...` URL.
 *
 *   node drive.js preauth <out-offer-file> <out-txcode-file> [--data data.json]
 *       Drive the portal in pre-authorized mode (fills the FormEU test form, authorizes),
 *       and write the resulting pre-authorized `haip-vci://…` offer plus its transaction
 *       code (PIN). Redeem headlessly with no authorization endpoint / browser.
 *
 *   node drive.js verifier <out-request-file>
 *       Drive verifier.eudiw.dev to request PID (dc+sd-jwt, family_name + given_name) over
 *       OpenID4VP and write the `openid4vp://…` request URL the wallet consumes.
 *
 * Requires a local Chrome; set CHROME_PATH to override /usr/bin/google-chrome.
 */
const fs = require('fs');
const puppeteer = require('puppeteer-core');

const CHROME = process.env.CHROME_PATH || '/usr/bin/google-chrome';
const PORTAL = 'https://issuer.eudiw.dev/credential_offer';

// Superset of the SD-JWT VC and mdoc PID test-form field names (they differ: the mdoc form uses
// `birth_date` and singular `nationality[...]`, the SD-JWT form `birthdate` and `nationalities[...]`).
// Fields absent from a given form are skipped, so this fills whichever form is shown.
const DEFAULT_DATA = {
  family_name: 'Han',
  given_name: 'Jongho',
  // SD-JWT VC PID form
  birthdate: '1990-05-15',
  'nationalities[0][country_code]': 'LU',
  // mdoc PID form
  birth_date: '1990-05-15',
  'nationality[0][country_code]': 'LU',
  // shared optional
  'place_of_birth[0][country]': 'LU',
  'place_of_birth[0][region]': 'Luxembourg',
  'place_of_birth[0][locality]': 'Luxembourg',
};

async function launch() {
  return puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
  });
}

async function getOffer(outFile, configId) {
  const browser = await launch();
  try {
    const page = await browser.newPage();
    await page.goto(PORTAL, { waitUntil: 'networkidle2', timeout: 45000 });
    await page.evaluate((cfg) =>
      document.querySelector(`input[name="${cfg}"]`).click(), configId);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 45000 }),
      page.click('#btncheck'),
    ]);
    const offer = await page.evaluate(() => {
      const m = document.documentElement.outerHTML
        .match(/haip-vci:\/\/credential_offer\?credential_offer=[^\s"'<>]+/);
      return m && m[0];
    });
    if (!offer) throw new Error('no credential offer found on QR page');
    fs.writeFileSync(outFile, offer);
    console.log('offer written to', outFile);
  } finally {
    await browser.close();
  }
}

async function getPreAuthOffer(outOfferFile, outTxCodeFile, data, configId) {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const browser = await launch();
  try {
    const page = await browser.newPage();
    await page.goto(PORTAL, { waitUntil: 'networkidle2', timeout: 45000 });
    // select the credential (SD-JWT VC or mdoc PID) and the Pre-Authorization Code Grant radio
    await page.waitForSelector(`input[name="${configId}"]`, { timeout: 25000 });
    await page.evaluate((cfg) => {
      document.querySelector(`input[name="${cfg}"]`).click();
      const r = document.querySelector('input#check2'); // pre_auth_code
      r.checked = true;
      r.dispatchEvent(new Event('change', { bubbles: true }));
    }, configId);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 45000 }),
      page.click('#btncheck'),
    ]);
    // pre-auth skips country selection and goes straight to the test form; wait for it to settle
    await page.waitForSelector('[name=family_name]', { timeout: 30000 }).catch(() => {});
    await sleep(500);
    if (!/display_form/.test(page.url())) throw new Error('did not reach test form: ' + page.url());
    await page.evaluate((fields) => {
      for (const [name, value] of Object.entries(fields)) {
        const e = document.querySelector(`[name="${name}"]`);
        if (e) { e.value = value; e.dispatchEvent(new Event('input', { bubbles: true })); e.dispatchEvent(new Event('change', { bubbles: true })); }
      }
    }, data);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 }).catch(() => {}),
      page.click('button[name=proceed][type=submit]'),
    ]);
    // The issuer opens the QR/offer in a second tab, so scan every open page: click Authorize
    // where present, then read the pre-auth offer + tx_code from whichever page has them.
    let result = { offer: null, txCode: null };
    for (let i = 0; i < 12; i++) {
      await sleep(1200);
      result = await scanPages(browser, () => {
        const offer = (document.documentElement.outerHTML.match(/haip-vci:\/\/credential_offer\?credential_offer=[^\s"'<>]+/) || [])[0];
        const txCode = [...document.querySelectorAll('input')].map((e) => e.value).find((v) => /^\d{4,6}$/.test(v));
        return offer ? { offer, txCode } : null;
      }) || { offer: null, txCode: null };
      if (process.env.DRIVE_DEBUG) {
        const urls = [];
        for (const pg of await browser.pages()) { try { urls.push(pg.url()); } catch (e) { urls.push('<err>'); } }
        console.error(`  [preauth iter${i}] offer=${!!result.offer} tx=${result.txCode || '-'} pages=${JSON.stringify(urls)}`);
      }
      if (result.offer && result.txCode) break;
      await scanPages(browser, () => {
        const t = [...document.querySelectorAll('button,input[type=submit],a')]
          .find((x) => /authori|send/i.test(x.textContent || x.value || ''));
        if (t) { t.click(); return true; }
        return null;
      });
    }
    if (!result.offer) throw new Error('no pre-authorized offer captured');
    if (!result.txCode) throw new Error('no transaction code found on the QR page');
    fs.writeFileSync(outOfferFile, result.offer);
    fs.writeFileSync(outTxCodeFile, result.txCode);
    console.log('pre-auth offer + tx_code written');
  } finally {
    await browser.close();
  }
}

async function getVerifierRequest(outFile, format) {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const browser = await launch();
    try {
        const page = await browser.newPage();
        await page.setViewport({ width: 1400, height: 1000 });
        await page.goto('https://verifier.eudiw.dev/home', { waitUntil: 'networkidle2', timeout: 60000 });
        await sleep(1500);

        // 1. select PID, then Specific attributes + dc+sd-jwt format
        await page.evaluate(() => {
            const el = [...document.querySelectorAll('*')].find((e) => e.textContent.trim() === 'Person Identification Data (PID)');
            if (el) el.click();
        });
        await sleep(1000);
        await selectMatOption(page, 0, 'Specific attributes');
        await selectMatOption(page, 1, format);
        await clickEnabled(page, (t) => t === 'Next');
        await sleep(1200);

        // 2. Select Attributes -> Given name + Family name -> Select
        await clickEnabled(page, (t) => /Select Attributes/.test(t));
        await sleep(1000);
        await page.evaluate(() => {
            const c = document.querySelector('mat-dialog-container');
            for (const label of ['Given name', 'Family name']) {
                const cb = [...c.querySelectorAll('mat-checkbox')].find((x) => x.textContent.trim() === label);
                if (cb) (cb.querySelector('label') || cb).click();
            }
        });
        await sleep(600);
        await page.evaluate(() => {
            const c = document.querySelector('mat-dialog-container');
            const b = [...c.querySelectorAll('button')].find((x) => /^Select \d/.test(x.textContent.trim()));
            if (b) b.click();
        });
        await sleep(1000);
        await clickEnabled(page, (t) => t === 'Next');
        await sleep(1200);

        // 3. OpenID4VP + GET, then Submit
        await clickToggle(page, 'OpenID4VP');
        await sleep(400);
        await clickToggle(page, 'GET');
        await sleep(400);
        await clickEnabled(page, (t) => t === 'Submit');
        await sleep(5000);

        const url = await page.evaluate(() => {
            const a = [...document.querySelectorAll('a')].find((x) => /^openid4vp:\/\//.test(x.href));
            return a ? a.href : null;
        });
        if (!url) throw new Error('no openid4vp request URL on the verifier QR page');
        fs.writeFileSync(outFile, url);
        console.log('verifier request written to', outFile);
    } finally {
        await browser.close();
    }
}

async function selectMatOption(page, index, text) {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    await page.evaluate((i) => document.querySelectorAll('mat-select')[i].click(), index);
    await sleep(600);
    await page.evaluate((t) => {
        const o = [...document.querySelectorAll('mat-option')].find((x) => x.textContent.trim() === t);
        if (o) o.click();
    }, text);
    await sleep(500);
}

async function clickEnabled(page, predSrc) {
    const pred = predSrc.toString();
    return page.evaluate((predStr) => {
        const pred = eval('(' + predStr + ')');
        const b = [...document.querySelectorAll('button')].find((x) => pred(x.textContent.trim()) && !x.disabled);
        if (b) { b.click(); return true; }
        return false;
    }, pred);
}

async function clickToggle(page, label) {
    return page.evaluate((label) => {
        const t = [...document.querySelectorAll('mat-button-toggle')].find((x) => x.textContent.trim() === label);
        if (t) { (t.querySelector('button') || t).click(); return true; }
        return false;
    }, label);
}

async function driveAuth(authUrlFile, outRedirectFile, data) {
  const url = fs.readFileSync(authUrlFile, 'utf8').trim();
  const browser = await launch();
  try {
    const page = await browser.newPage();
    let captured = null;
    page.on('request', (req) => {
      if (req.url().includes('code=') && /\/cb(\?|$)/.test(req.url()) && !captured) captured = req.url();
    });

    await page.goto(url, { waitUntil: 'networkidle2', timeout: 60000 });
    if (!/display_countries/.test(page.url())) {
      throw new Error('did not reach country selection: ' + page.url());
    }

    // FormEU test country
    await page.evaluate(() => {
      const r = document.querySelector('input#FC');
      r.checked = true;
      r.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 }),
      page.click('button[name=proceed]'),
    ]);
    if (!/display_form/.test(page.url())) throw new Error('did not reach test form: ' + page.url());

    // fill the mandatory test PID attributes
    await page.evaluate((fields) => {
      for (const [name, value] of Object.entries(fields)) {
        const e = document.querySelector(`[name="${name}"]`);
        if (e) {
          e.value = value;
          e.dispatchEvent(new Event('input', { bubbles: true }));
          e.dispatchEvent(new Event('change', { bubbles: true }));
        }
      }
    }, data);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 }).catch(() => {}),
      page.click('button[name=proceed][type=submit]'),
    ]);

    // consent / authorize, then the redirect carrying the code
    for (let i = 0; i < 4 && !captured; i++) {
      if (page.url().includes('code=')) { captured = page.url(); break; }
      const clicked = await page.evaluate(() => {
        const btns = [...document.querySelectorAll('button,input[type=submit],a')];
        const t = btns.find((x) => /allow|authori|approve|share|proceed|continue|confirm/i
          .test(x.textContent || x.value || ''));
        if (t) { t.click(); return true; }
        return false;
      });
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 }).catch(() => {});
      if (!clicked && !captured) break;
    }

    const finalUrl = captured || page.url();
    if (!finalUrl.includes('code=')) {
      const body = await page.evaluate(() => document.body.innerText.slice(0, 400));
      throw new Error('no authorization code captured. page: ' + finalUrl + '\n' + body);
    }
    fs.writeFileSync(outRedirectFile, finalUrl);
    console.log('redirect written to', outRedirectFile);
  } finally {
    await browser.close();
  }
}

// The issuer chains client-side redirects and opens a second tab, which can transiently detach
// the main frame's execution context. Retry (re-focusing the page) through the transition.
async function safeEval(page, fn) {
  let last;
  for (let i = 0; i < 15; i++) {
    try { return await page.evaluate(fn); }
    catch (e) {
      last = e;
      if (/detached Frame|Execution context|Cannot find context|Target closed/.test(e.message)) {
        await page.bringToFront().catch(() => {});
        await new Promise((r) => setTimeout(r, 1000));
        continue;
      }
      throw e;
    }
  }
  throw last;
}

// Evaluate fn on every open tab (the issuer spreads its flow across tabs), returning the first
// truthy result and tolerating pages that are mid-navigation or closed.
async function scanPages(browser, fn) {
  for (const pg of await browser.pages()) {
    try {
      const r = await pg.evaluate(fn);
      if (r) return r;
    } catch (e) { /* detached/closed/cross-origin page — skip */ }
  }
  return null;
}

function flag(rest, name, fallback) {
  const i = rest.indexOf(name);
  return i >= 0 ? rest[i + 1] : fallback;
}

(async () => {
  const [cmd, ...rest] = process.argv.slice(2);
  const dataIdx = rest.indexOf('--data');
  let data = DEFAULT_DATA;
  if (dataIdx >= 0) data = JSON.parse(fs.readFileSync(rest[dataIdx + 1], 'utf8'));
  // credential_configuration_id (issuer checkbox) and verifier format, default to SD-JWT VC PID.
  const configId = flag(rest, '--config', 'eu.europa.ec.eudi.pid_vc_sd_jwt');
  const format = flag(rest, '--format', 'dc+sd-jwt');

  if (cmd === 'offer') {
    await getOffer(rest[0] || 'offer.txt', configId);
  } else if (cmd === 'auth') {
    await driveAuth(rest[0], rest[1], data);
  } else if (cmd === 'preauth') {
    await getPreAuthOffer(rest[0], rest[1], data, configId);
  } else if (cmd === 'verifier') {
    await getVerifierRequest(rest[0], format);
  } else {
    console.error('usage: node drive.js offer <out> | auth <authurl> <out-redirect> | preauth <out-offer> <out-txcode> | verifier <out-request> [--config <id>] [--format <fmt>] [--data f.json]');
    process.exit(2);
  }
})().catch((e) => { console.error('ERROR:', e.message); process.exit(1); });
