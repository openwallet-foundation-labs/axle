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
 * Requires a local Chrome; set CHROME_PATH to override /usr/bin/google-chrome.
 */
const fs = require('fs');
const puppeteer = require('puppeteer-core');

const CHROME = process.env.CHROME_PATH || '/usr/bin/google-chrome';
const PORTAL = 'https://issuer.eudiw.dev/credential_offer';

const DEFAULT_DATA = {
  birthdate: '1990-05-15',
  family_name: 'Han',
  given_name: 'Jongho',
  'nationalities[0][country_code]': 'LU',
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

async function getOffer(outFile) {
  const browser = await launch();
  try {
    const page = await browser.newPage();
    await page.goto(PORTAL, { waitUntil: 'networkidle2', timeout: 45000 });
    await page.evaluate(() =>
      document.querySelector('input[name="eu.europa.ec.eudi.pid_vc_sd_jwt"]').click());
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

(async () => {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === 'offer') {
    await getOffer(rest[0] || 'offer.txt');
  } else if (cmd === 'auth') {
    const dataIdx = rest.indexOf('--data');
    let data = DEFAULT_DATA;
    if (dataIdx >= 0) data = JSON.parse(fs.readFileSync(rest[dataIdx + 1], 'utf8'));
    await driveAuth(rest[0], rest[1], data);
  } else {
    console.error('usage: node drive.js offer <out> | auth <authurl-file> <out-redirect> [--data f.json]');
    process.exit(2);
  }
})().catch((e) => { console.error('ERROR:', e.message); process.exit(1); });
