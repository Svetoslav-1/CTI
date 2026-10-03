# Operation Grid Relief — Bulgarian "Energy Compensation" Card-Harvesting Kit

> **Status:** Draft teardown · **First observed:** 2026-10-03 · **Analyst:** Svetoslav (`Svetoslav-1`)
> **Classification:** Phishing-as-a-Service (PhaaS), financial-data theft
> **Disclosure:** IOCs defanged. Report to Cloudflare, registrar, GovCERT.bg, impersonated banks and ЕСО ЕАД **before** public release.

---

## 1. Summary

A multi-stage, multi-country **card-harvesting phishing kit** impersonating a Bulgarian
government energy-compensation program. The front end promises households up to **150 EUR**
in electricity-cost compensation with a 24-hour review window; the actual payload is a
bank-card capture modal. Behind the single lure sits a **reusable "receive money" template
engine** that reskins across themes (energy compensation, property-rental payout) and
localises a bank picker for multiple countries. Multiple anti-analysis layers (JS challenge,
fake captcha, base64 shadow-DOM cloaking, RU geo-exclusion) indicate a **Russian-speaking
operator** running a maintained kit rather than a one-off page.

**Primary host:** `bulgaria-isplashanie[.]me` (Cloudflare-fronted, colo SOF).
Note the `.me` TLD — no legitimate Bulgarian state service is hosted here.

---

## 2. Lure

| Element | Detail |
|---|---|
| Impersonated brand | "Държавен портал за енергийни компенсации" (fake State portal for energy compensations) |
| Authority props | Logos/cards for **ЕСО ЕАД** (grid operator) and **АИКБ** (Association of Banks in Bulgaria) |
| Offer | "Компенсация на разходите за електроенергия" — up to **150 EUR** |
| Urgency | Deadline **31.12.2026**; review **"до 24 часа"** |
| Reassurance | Fake *"криптирана SSL връзка"* + *"защитени от стандарта PCI DSS"* banners |
| Payload | Modal **"Добавете банкова карта"** → PAN, expiry, CVC, cardholder name, Visa/MC marks |

The amount, deadline and review-hours are **URL parameters**, not hard-coded:

```
hxxps://bulgaria-isplashanie[.]me/receive/4920130?a=150&d=31.12.2026&h=24
                                           │         │   │             └ h = review hours (24)
                                           │         │   └ d = deadline (31.12.2026)
                                           │         └ a = amount (150)
                                           └ campaign / victim id
```

---

## 3. Delivery chain — anti-analysis

Three gates execute before a human sees the lure, each designed to burn automated crawlers:

### Stage 1 — JS spinner challenge
A spinner page runs `anusX(min,max)` (crypto `getRandomValues` RNG) to generate a random
`unqid`, writes it via `sc1()`, and calls `location.reload()` after 500 ms. Crawlers that do
not execute JS and persist cookies never advance.

### Stage 2 — Fake captcha gate
`window.CAPTCHA_AUTH` carries `token`, `uidHash`, `hashCaptchaName`, `hashCaptchaKey`.
`captchaPassedPost()` **auto-fires at ~823 ms** (no user interaction), writes `unqid`,
`captcha`, and the dynamic hash cookie, POSTs `_recaptcha=108`, and reloads. This is **not a
real captcha** — it is a session-priming + bot-filter stage that mints the cookies the real
page requires.

### Stage 3 — Shadow-DOM cloaking (T1027)
The real lure is base64-encoded inside:

```html
<script type="application/octet-stream" id="shadow-page-data">PCFET0NUWVBFIG...
```

and rendered into a shadow host at runtime. **Static HTML scanners and URL crawlers see only
a spinner.** Decoded header confirms the hidden content:

```html
<!DOCTYPE html>
<html lang="bg">
  <title>Компенсация на разходи за електроенергия</title>
```
(full decode in `decoded-shadow-page.html`)

### Geo-cloaking tell
The kit module is `/server/captcha-v2/index-no-ru-6499928a-250ms.js`. The **`no-ru`** token
excludes Russian-speaking visitors — a CIS-actor TTP to avoid local jurisdiction. Reinforced
by **Russian-language developer comments** in the fake app-page CSS (`Во время установки…`,
`Что нового`).

---

## 4. Kit architecture — Phishing-as-a-Service

- **Theme reskinning:** OpenGraph tags on the captured page describe a *rental-payment*
  confirmation ("Средствата за недвижимост номер 4920130 … на стойност 10 EUR") while the
  rendered page is *energy compensation, 150 EUR*. Same engine, swapped lure — ID `4920130`
  reused as a campaign/victim handle.
- **Multi-country bank picker:** config JSON ships localised bank lists for **ES, GB, RO**
  (schema implies more), each with its own `title` / `description` / `country` / `error_card`.
  Bank logos scraped from `play-lh.googleusercontent.com`; low-quality tells include typos
  `LIoyds` and `Fist Bank`.
- **Fake app-store page (`#idv_page`):** a Google-Play-style install screen — "what's new,"
  screenshot slider, blue-masked star ratings, testimonials — likely a trust-builder or a
  stage to push a malicious banking APK.
- **Live operator channel:** `POST /receive/{id}  type=support&uniq={n}` returns a Bulgarian
  support-chat script — a human-in-the-loop to coach victims through card entry / OTP.

---

## 5. MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Resource Development | T1583.001 Acquire Infrastructure: Domains |
| Resource Development | T1583.006 Acquire Infrastructure: Web Services (Cloudflare) |
| Resource Development | T1608 Stage Capabilities |
| Initial Access | T1566.002 Phishing: Spearphishing Link |
| Collection / Recon | T1598 Phishing for Information (financial data) |
| Defense Evasion | T1027 Obfuscated/Encoded Payload (base64 shadow DOM) |
| Defense Evasion | Cloaking: JS/cookie gating + `no-ru` geo-exclusion |

---

## 6. IOCs

Full machine-readable set in [`iocs.csv`](./iocs.csv). Highlights (defanged):

- **Domain:** `bulgaria-isplashanie[.]me`
- **URL pattern:** `/receive/{id}?a={amount}&d={deadline}&h={hours}`
- **Kit assets:** `/server/captcha-v2/index-no-ru-6499928a-250ms.js`, `/server/captcha-v2/index-H51BxVaW.css`
- **Cookies:** `uid`, `unqid`, `captcha`, dynamic hash `1a33eed4272a1bc11724183d35b4376e`
- **Tokens:** captcha `54bc571b814855a83136e0c57601d9c5`; uidHash `f23b3e0e8ed58df29aff75e217e6c7ec`
- **JS fingerprints:** `anusX`, `captchaPassedPost`, `shadow-page-data`, `no-ru`
- **Operator endpoint:** `POST /receive/{id}  type=support&uniq={n}`
- **Hosting:** Cloudflare (colo SOF)

---

## 7. Hunting & detection

- **Pivot** on the JS fingerprints (`anusX`, `captchaPassedPost`) and the `shadow-page-data` +
  `no-ru` markers across urlscan.io / VirusTotal / Censys — the cluster is almost certainly a
  family of `*-isplashanie` / payout-themed `.me` domains.
- **Proxy/EDR detection:** alert on the `/receive/?a=&d=&h=` URL shape and on the literal
  strings `shadow-page-data` / `anusX` in response bodies.
- **Block** the domain at DNS/web-proxy.

## 8. Responsible disclosure checklist

- [ ] Cloudflare abuse report (reverse-proxy takedown)
- [ ] Domain registrar abuse
- [ ] GovCERT.bg / CERT Bulgaria
- [ ] Google Safe Browsing + Microsoft SmartScreen submissions
- [ ] APWG eCrime report
- [ ] Fraud teams of impersonated banks + ЕСО ЕАД notification
- [ ] Publish write-up only after takedown / CERT acknowledgement

---

## Files
- `README.md` — this teardown
- `iocs.csv` — machine-readable IOC set (defanged)
- `decoded-shadow-page.html` — decoded shadow-DOM lure (partial, as captured)
