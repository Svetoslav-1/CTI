# operation-mvr-fine — Bulgarian MVR Traffic-Violation Card-Harvesting Kit (Darcula / Magic Cat)

> **Status:** Draft teardown · **First observed:** 2026-05-08 · **Analyst:** Svetoslav (`Svetoslav-1`)
> **Classification:** Phishing-as-a-Service (PhaaS), financial-data theft
> **Disclosure:** IOCs defanged. Reported to ГДБОП (gdbop@mvr.bg). Report to Google Safe Browsing, registrars (Dynadot, GoDaddy), hosting (Tencent Cloud, Alibaba Cloud), and impersonated institution (МВР) before public release.

---

## 1. Summary

A multi-stage, multi-domain **card-harvesting phishing kit** impersonating Bulgaria's
Ministry of Interior (МВР) electronic-services portal. The front end presents a fake traffic
violation — a speeding fine generated for **any** registration number entered — with a 30%
"early-payment discount" to pressure victims; the actual payload is a bank-card capture form
plus a live **3D Secure OTP relay**. Behind the lure sits the **Darcula / Magic Cat** Chinese
PhaaS platform: a configurable "receive money" template engine that reskins across brands
(МВР → Министерство на транспорта) and localises for multiple countries. A real-time operator
dashboard (Socket.IO) lets the attacker drive the victim's screen while laundering a live card
transaction. Multiple anti-analysis layers (commercial bot detection, heavy JS obfuscation,
static AES-encrypted C2) and **Chinese-language strings** inside the encrypted channel
indicate a **maintained Chinese-operated kit** rather than a one-off page.

**Primary host:** `mvrx[.]lat` (Tencent Cloud, nginx). Note the `.lat` TLD — no legitimate
Bulgarian state service is hosted here. 12 domains observed across Tencent + Alibaba Cloud.

---

## 2. Lure

| Element | Detail |
|---|---|
| Impersonated brand | "Република България — Министерство на вътрешните работи — Портал за електронни административни услуги на МВР" (Republic of Bulgaria — Ministry of Interior — Portal for Electronic Administrative Services of the MoI) |
| Brand variant | "Министерство на транспорта на България" (Ministry of Transport of Bulgaria) |
| Page title | "Регистрирано нарушение по КАТ" (Registered traffic violation by KAT) |
| Authority props | Republic of Bulgaria coat of arms, МВР and КАТ logos; clones visual identity of e-uslugi[.]mvr[.]bg |
| Offer / hook | Fake speeding violation (e.g. 79 km/h in a 50 km/h zone) generated for **any** plate entered; **30% discount** 100лв → 70лв if paid within 48h |
| Urgency | First variant: pay within 48h for discount, cites Art. 189 ЗДвП. Second variant: "Второ предупреждение — Започнато е съдебно производство" (court proceedings initiated); 8% daily interest; 6-month licence suspension; forced collection; deadline 24:00 on 19 May 2026; fake camera "SVK-889" |
| Reassurance | *"Плащането се обработва в защитена и криптирана среда, съгласно действащите стандарти за защита на данните на МВР"* banner; Visa/MC/AMEX/JCB/Discover/Diners card marks |
| Payload | **"Приети начини на плащане"** modal → cardholder name, PAN, expiry, CVV; followed by live 3DS SMS/OTP, PIN, email-code stages |

The amount, deadline and violation date are **config-driven**, not hard-coded (`Gi{}` object):

```
money: "70 лв."
violationDateOffsetDays: 6      // violation date = today − 6 days
formInfoFields: [fullName, address, city, state, zipCode, phone, email]
```

**Captured fields (`mc{}` object):**
`vehicleReg`, `cardNumber` (client-side Luhn-validated), `fullName` / `cardHolder`,
`expiryDate`, `expressCvv`, `pin`, `code` (3DS/OTP), `customCode`, `phone`, `email`,
`address`, `city`, `zipCode`, `amount`, `totalAmount`, `merchant`, `merchantName`, `branchNo`.

---

## 3. Delivery chain — anti-analysis

### Stage 0 — SMS/Viber lure
Victim receives an SMS/Viber message impersonating МВР / Ministry of Transport with a link to
`hxxps://[domain]/bg`. A per-victim tracking hash in the HTML `<meta name="keywords">` tag
ties the specific SMS recipient to their session.

### Stage 1 — SPA load + bot detection (T1027)
Vue.js single-page app loads (`<div id="app">`). Before rendering the lure, the kit calls
**FingerprintJS BotD** (`hxxps://m1[.]openfpcdn[.]io/botd/v2.0.0/npm-monitoring`) and checks an
`isSpider` flag. The beacon is gated behind a `window.__fpjs_d` marker and a 0.1% sampling
rate (`Math.random() >= 0.001`) — this doubles as **kit-developer telemetry**, letting the
Darcula authors monitor every deployment independently of the operator.

### Stage 2 — Dynamic fake-violation generation
Victim enters any registration number → backend generates a convincing speeding violation
(measured speed, allowed speed, excess, fine, "discount"). **No connection to real databases** —
pure social engineering. `vehicleReg` "FCKYOU" produced a full 79-in-50 violation.

### Stage 3 — Card capture + live 3DS relay (T1557)
1. Victim submits card → `notice/submitData` over encrypted WebSocket → operator receives in real time
2. Operator initiates a **real transaction** with the stolen card
3. Bank sends genuine 3DS SMS to victim's phone
4. Operator pushes `waitVerificationPhoneCode` → victim's browser shows "enter SMS code"
5. Victim enters the real code → `notice/submitCode` → operator completes the transaction

The aggressive Socket.IO ping (`pingInterval: 1000, pingTimeout: 3000`) exists to give the
operator a live view of the victim so the OTP relay happens inside the code's validity window.

### Obfuscation / encryption
- Heavy JS obfuscation: rotated base64 lookup arrays (`ze()`, `oe()`, `Ko()`), decoder
  functions (`Se()`, `ie()`, `Oo()`) with index offsets (141, 398, 404), self-executing
  shuffling loops targeting magic numbers (877836, 958605, 133821).
- All WebSocket traffic **AES-128-CBC** encrypted (CryptoJS, PKCS7). Chinese strings hidden
  inside the encrypted payloads.

### Decoded payloads

Encrypted WebSocket frame:
```
42["message","9J/UwM0nsmrdXqUVWny6zjo8nD559AWv58L4xtEANxKlUbA6w8MLB2dTanus8jfpD+v39pA5K6n5OzTD7JV4lQ=="]
```
Decoded:
```json
{"event":"changleField","data":{"router":"支付页"}}
```
("支付页" = "Payment page")

```
42["message","9J/UwM0nsmrdXqUVWny6zjo8nD559AWv58L4xtEANxJvzzOxau4HFNC5UpSjSiPAtTS4+ZFZhWHeY+ukww708g=="]
```
Decoded:
```json
{"event":"changleField","data":{"router":"资料页"}}
```
("资料页" = "Information page")

All Chinese page labels (`cc()` calls):
`首页` Home · `资料页` Information · `支付页` Payment · `手机验证页` Phone verify ·
`PIN验证页` PIN verify · `APP验证页` App verify · `邮箱验证页` Email verify ·
`自定义验证码页` Custom-code · `运通CVV验证页` Amex-CVV · `完成页` Complete

Chinese error strings: `加密失败` (encryption failed), `加密异常!` (encryption exception),
`解密结果为空` (decryption result empty), `解密异常!` (decryption exception).

### Geo / language tell
Chinese-language page labels and error strings throughout the encrypted protocol; typo
`changleField` (for `changeField`) is a Chinese-English transliteration artefact and a unique
kit fingerprint. Hosting exclusively on Chinese cloud (Tencent + Alibaba).

---

## 4. Kit architecture — Phishing-as-a-Service

- **Identified as:** Darcula / Magic Cat — Chinese PhaaS, previously documented by Mnemonic and NRK.
- **Stack:** Vue.js SPA (static, nginx) → Node.js + Socket.IO (Engine.IO v4) backend in a **Docker container (Ubuntu 24)** → web-based operator dashboard receiving victim data in real time via a Socket.IO "admin" room.
- **Theme reskinning:** `Gi{}` config drives institution text (`logoMain`, `logoService`), currency, amounts, form fields, violation-date offset. Observed brand rotation МВР → Министерство на транспорта within one campaign.
- **Multi-country:** form-field localisation structure present; kit is known to target multiple countries with the same engine.
- **Live operator channel:** operator controls the victim's page flow via status commands (`waitVerificationPhoneCode`, `waitVerificationExpressCvv`, `waitVerificationCustomCode`, `waitVerificationEmail`) — enabling the live 3DS relay.
- **Reused template:** identical JS bundle `D8qkvwBg.js` + static AES keys across all 12 domains.
- **App/APK stage:** not observed (an `AppCode` / `/app` route exists for a "banking-app confirmation" step, but no APK was retrieved).
- **Kit-developer backdoor/telemetry:** FingerprintJS beacon embedded by the Darcula authors (not the operator), allowing them to monitor all deployments.

---

## 5. MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Reconnaissance | T1598.003 Phishing for Information: Spearphishing Link |
| Resource Development | T1583.001 Acquire Infrastructure: Domains |
| Resource Development | T1583.003 Acquire Infrastructure: Virtual Private Server |
| Resource Development | T1588.002 Obtain Capabilities: Tool (Darcula PhaaS) |
| Resource Development | T1608.005 Stage Capabilities: Link Target |
| Initial Access | T1566.002 Phishing: Spearphishing Link (SMS/Viber) |
| Collection | T1056.003 Input Capture: Web Portal Capture |
| Collection | T1557 Adversary-in-the-Middle (live 3DS OTP relay) |
| Credential Access | T1539 Steal Web Session Cookie (potential, operator dashboard XSS) |
| Defense Evasion | T1027 Obfuscated Files or Information (JS obfuscation, AES) |
| Defense Evasion | T1036.005 Masquerading: Match Legitimate Name or Location (МВР brand) |
| Command and Control | T1071.001 Application Layer Protocol: Web Protocols (WebSocket/Socket.IO) |
| Command and Control | T1573.001 Encrypted Channel: Symmetric Cryptography (AES-128-CBC) |
| Command and Control | T1105 Ingress Tool Transfer (FingerprintJS BotD from CDN) |
| Exfiltration | T1041 Exfiltration Over C2 Channel (encrypted WebSocket) |

---

## 6. IOCs

Full machine-readable set in [`iocs.csv`](./iocs.csv). Highlights (defanged):

**Domains**
```
mvrx[.]lat          mvrbg[.]ink         mvrbg[.]sbs        mvr-bg[.]shop
mvro[.]lat          mvrbg[.]cyou        mvr-bg[.]sbs       mvr-bg[.]autos
mvrbg[.]life        gav[.]mvrbg[.]cam   mvr[.]bggov[.]cam  mvr[.]govbg[.]one
```

**URL pattern**
```
hxxps://[domain]/bg/#/index                       — entry point
hxxps://[domain]/bg/static/D8qkvwBg.js            — app bundle (361 KB)
hxxps://[domain]/bg/static/BVwPKGM5.js            — vendor bundle (308 KB)
hxxps://[domain]/bg/static/DdSK5oDi.css           — stylesheet
wss://[domain]/console/?uuid={UUID}&EIO=4&transport=websocket  — C2
```

**IPs / hosting**
```
43.153.72.244   Tencent Cloud AS132203  — mvrx[.]lat, mvro[.]lat
43.160.221.174  Tencent Cloud           — mvrbg[.]cyou, mvrbg[.]sbs, mvr-bg[.]autos
43.165.0.190    Tencent Cloud           — mvr-bg[.]sbs, mvr-bg[.]shop
43.160.250.19   Tencent Cloud           — mvr[.]bggov[.]cam, mvr[.]govbg[.]one
47.245.142.76   Alibaba Cloud AS45102   — mvrbg[.]ink, mvrbg[.]life
47.91.88.57     Alibaba Cloud           — gav[.]mvrbg[.]cam
```
Registrars: Dynadot LLC (mvrx/mvro), GoDaddy (others). NS: ns1/ns2.dyna-ns[.]net.
TLS: Let's Encrypt (R12/R13), auto-provisioned. Web server: nginx + HSTS. All domains 0–2 days old at observation.
External dependency: `m1[.]openfpcdn[.]io` (FingerprintJS BotD — legitimate, used by kit).

**JS / protocol fingerprints**
```
Bundle:        D8qkvwBg.js, BVwPKGM5.js
Typo sig:      changleField   (unique)
Obfuscation:   ze()/oe()/Ko() arrays; Se()/ie()/Oo() decoders (offsets 141/398/404)
Shuffle magic: 877836, 958605, 133821
Config object: Gi{}      page tracker: cc()     encrypt fn: Ee()
Bot check:     isSpider via FingerprintJS $o class
Socket.IO:     pingInterval 1000, pingTimeout 3000
```

**Tokens / hashes**
```
Per-victim tracking hash (meta keywords): 64-byte hex, e.g.
  039a81299d2829456c1cb804f44a471ad9864b11f5ca679e2514301f2500fb309f52bc1b37504599a3a08988750ba0674089baef6c6acdf155122922a3b891c1
Socket.IO session ID: UUID v4, e.g. dfe91e28-664d-424c-b69f-5daf62ffa434
```

**Cryptographic material** (AES-128-CBC / PKCS7 / CryptoJS — STATIC, identical across all builds)
```
Key 1 (WebSocket):  key ZQMWLSPXJRDHKTNV   iv YFBCUENAGPQLXJWR
Key 2 (secondary):  key PABGJJPIFELIOJMD   iv HOPNMFQOBCAAGKBN
```

**WebSocket protocol events**
```
Client→Server:  changleField {router/status/data} · notice {submitData|submitCode|resendCode|enterAccount}
Server→Client:  config userSiteConfig · status {waitVerificationPhoneCode|waitVerificationExpressCvv|
                waitVerificationCustomCode|waitVerificationEmail|complete/success}
```

**POST endpoints**
```
api/Users/Login   — present in cloned UI markup (from e-uslugi template); not confirmed active — not observed server-side
```

---

## 7. Hunting & detection

- **Pivot** on the JS fingerprints (`D8qkvwBg.js` filename, `changleField` typo, `isSpider`
  FingerprintJS pattern) across urlscan.io / VirusTotal / Censys — the cluster is a family of
  `mvr*` / `*bg*` payout-themed `.lat` / `.ink` / `.sbs` / `.cam` domains on Chinese cloud.
  (urlscan pivot on `filename:D8qkvwBg.js` surfaced the 12-domain set.)
- **Proxy/EDR detection:** alert on the `/bg/#/index` + `/console/?uuid=&EIO=4` URL shape and
  on the literal strings `changleField` / `D8qkvwBg.js` in response bodies.
- **Decryptor:** with the static AES keys above, all WebSocket C2 is decryptable offline
  (`decrypt.js` / `ws_monitor.js` in this repo).
- **Block** the domains at DNS/web-proxy; block the IP `43.153.72.244` (shared across domains).

---

## 8. Responsible disclosure checklist

- [x] ГДБОП / CERT Bulgaria (gdbop@mvr.bg)
- [ ] Google Safe Browsing + Microsoft SmartScreen submissions
- [ ] Registrar abuse — Dynadot (abuse@dynadot.com), GoDaddy (abuse@godaddy.com)
- [ ] Hosting abuse — Tencent Cloud, Alibaba Cloud
- [ ] Impersonated institution notification — МВР
- [ ] APWG eCrime report
- [ ] Publish write-up only after takedown / CERT acknowledgement

---

## Appendix A — Raw capture

**WebSocket handshake**
```http
GET /console/?uuid=0af6eca5-97bb-4280-bb35-b33db10e0948&EIO=4&transport=websocket HTTP/1.1
Host: mvrx.lat
Connection: Upgrade
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Upgrade: websocket
Origin: https://mvrx.lat
Sec-WebSocket-Version: 13
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Sec-WebSocket-Key: o7oiTydzOTzVb8EWMXOhaA==
```
```http
HTTP/1.1 101 Switching Protocols
Server: nginx
Connection: upgrade
upgrade: websocket
sec-websocket-accept: RFrDY8WZ3ppu3pe98KyE4GN0fjk=
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

**Socket.IO handshake frame**
```
0{"sid":"dfe91e28-664d-424c-b69f-5daf62ffa434","upgrades":[],"pingInterval":1000,"pingTimeout":3000}
```

**Encrypted data frames + decodes**
```
42["message","9J/UwM0nsmrdXqUVWny6zjo8nD559AWv58L4xtEANxKlUbA6w8MLB2dTanus8jfpD+v39pA5K6n5OzTD7JV4lQ=="]
→ {"event":"changleField","data":{"router":"支付页"}}

42["message","9J/UwM0nsmrdXqUVWny6zjo8nD559AWv58L4xtEANxJvzzOxau4HFNC5UpSjSiPAtTS4+ZFZhWHeY+ukww708g=="]
→ {"event":"changleField","data":{"router":"资料页"}}
```

---

## Files
- `README.md` — this teardown
- `iocs.csv` — machine-readable IOC set (defanged)
- `decrypt.js` — AES-128-CBC WebSocket decryptor/encryptor
- `ws_monitor.js` — passive WebSocket traffic monitor
- `protocol-map.txt` — full reverse-engineered protocol map
