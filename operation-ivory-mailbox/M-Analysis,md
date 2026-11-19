# Operation Ivory Mailbox — uni-sofia.bg Webmail Credential-Harvesting Kit

> **Status:** Draft teardown — internal impact **pending** · **Observed on-host:** 2026-11-19 · **Cluster active since:** 2026-11-05 · **Analyst:** Svetoslav (`Svetoslav-1`)
> **Classification:** Phishing-as-a-Service (PhaaS), credential harvesting (webmail)
> **Disclosure:** IOCs defanged. Report to AbuseRadar/IPXO, MultaCom, Namecheap and CERT Bulgaria **before** public release. Victim address redacted.

---

## 1. Summary

A **multi-tenant webmail credential-harvesting kit** targeting `uni-sofia.bg`. The landing page
is a generic **Roundcube-skinned** login re-parameterised for `zimbra.uni-sofia.bg`, served from
a bare IP behind a document-sharing lure. Credentials are POSTed as JSON to `/submit`; the server
then bounces the victim to the **real** Zimbra login, so the theft looks like a normal re-login.

The kit is a maintained platform, not a one-off page:
- a per-tenant `key` (campaign `VA3WHW`), and the authors' own source comment says **keyless captures go to the admin**
- two page modes, **"cloned" and "general"**, with a form hook that grabs *any* form on a copied page
- a server-rendered config (`window.__GC__`), a **decoy "Under development" page** on bare-IP hits, and a Node/Express + Helmet backend

Infrastructure follows a disciplined pattern: **aged Namecheap domains** (registered Dec 2025,
activated Sep–Oct 2026), **leased IP space** (IPXO/AbuseRadar lessee announced by MultaCom AS35916),
`mail.<domain>` PTRs on the same hosts that serve the kit, and **DNS changed or cleared right before each
infrastructure wave**.

**Live kit hosts (2026-11-19):** `148.135.10[.]58`, `148.135.106[.]233`, `148.135.46[.]241`.

---

## 2. Lure

| Element | Detail |
|---|---|
| Impersonated brand | `zimbra.uni-sofia.bg` webmail (rendered with a **Roundcube** template, which looks wrong to Zimbra users) |
| Pretext | Shared document: *"Login to your webmail to view the document."* |
| Personalisation | Victim email pre-filled from the URL |
| Delivery | Link to bare IP over HTTPS (valid LE cert for `mail.*` hostname, so the browser shows a name-mismatch warning on IP) |
| Payload | Email + password, then redirect to the real Zimbra |

```
hxxps://148.135.10[.]58/?k=VA3WHW&url=https://zimbra.uni-sofia[.]bg&user=<redacted>@uni-sofia.bg
                          │        │                               └ user = victim, pre-filled
                          │        └ url  = brand target; becomes pageUrl, then the post-submit redirect
                          └ k    = tenant / campaign key
```

On load, `history.replaceState(null, "", location.pathname)` **strips the query string** from the
address bar, so the victim never sees their address in the URL and shared screenshots don't leak it.

---

## 3. Kit architecture

### 3.1 Backend fingerprint
- `nginx/1.24.0 (Ubuntu)` (stock 24.04) → **Node.js / Express + Helmet**
  - Helmet default header set: `X-DNS-Prefetch-Control: off`, `X-Download-Options: noopen`,
    `X-Permitted-Cross-Domain-Policies: none`, `X-XSS-Protection: 0`, `Origin-Agent-Cluster: ?1`, COOP/CORP `same-origin`, `Referrer-Policy: no-referrer`
  - Express weak ETag format `W/"<hexlen>-<b64sha1>"`
- Helmet CSP **deliberately overridden** to `frame-ancestors *` plus `Access-Control-Allow-Origin: *`,
  so the page is meant to be framed / called from other origins (fits HTML-attachment or redirector lures). This overrides `X-Frame-Options: SAMEORIGIN`.
- No cookies; session state = `key` only.

### 3.2 Page rendering — `GET /`
- **With params:** server renders the login page and injects
  `window.__GC__={"key":"VA3WHW","pageUrl":"https://zimbra.uni-sofia.bg"}` plus `body[data-host]`.
- **Without params:** 626-byte **decoy**, `<title>Under development</title>` with spinner/gear,
  `/p/css/index.css?v=11`. Anyone hitting the bare IP sees a harmless placeholder.
- Markup is lifted from **Roundcube Elastic** (`rcmloginpwd`, `rcmloginsubmit`, `propform`,
  `layout-content`, `formbuttons`, `login-footer`).
- Hidden fields `_subject="General Login"`, `Website="General"`, `_software=""` act as **template
  selectors**. `_honey` is a FormSubmit-style bot honeypot. The email is duplicated as `email`, `sentemail`, `_email`.

### 3.3 `form.js` — capture hook (unobfuscated, commented)
- Capture-phase `submit` listener on `document` **and** overrides
  `HTMLFormElement.prototype.submit`, so it catches programmatic submits too.
- Serialises **every string field of any form** (duplicate names are joined).
- `POST /submit` JSON `{key, pageUrl, fields}`, then `location.replace(data.redirect || '/')`.
- Author comments: *"Submission handler for cloned and general pages"*, *"the server routes keyless
  captures to the admin"*. This confirms a **clone mode** (real target page with the hook injected) and a
  **multi-tenant panel**.
- **No client-side exfil** (no Telegram/webhook in the browser). Forwarding happens on the server only.

### 3.4 `/submit` behaviour
Test with a fake account, empty key:

```
POST /submit  {"key":"","pageUrl":"https://example.org","fields":{...}}
→ 200 {"redirect":"https://example.org"}
```

- The redirect **echoes `pageUrl`**, so victims land on the real `zimbra.uni-sofia.bg`.
- Accepts arbitrary unauthenticated input and redirects anywhere: an **open redirector**.
- Any "wrong password" loop would be decided by the server (redirect `/`); none is visible in the client.

### 3.5 `general.js` — branding
- Logo from `google.com/s2/favicons?sz=256&domain=<host>` (used only if ≥64 px), fallback
  `/p/images/roundcube-logo.svg`.
- Favicon from `google.com/s2/favicons?sz=64&domain=<host>`, fallback `https://<host>/favicon.ico`.
  Google returns a default icon for unknown domains, so the fallback rarely fires.

### 3.6 Developer tells (weak, for attribution)
- `general.js` saved **with a UTF-8 BOM**; `general.css` has **CRLF** line endings → written on Windows, deployed to Ubuntu.
- Mixed script style: ES5 `var` in `form.js`, ES6 `const` in `general.js`.
- Clean English comments explaining design decisions, which is unusual for commodity kits.
- `index.css?v=11` → kit under active iteration.

---

## 4. Infrastructure

### 4.1 Hosts (Shodan `http.html_hash:1672167971`, 8 records / 5 IPs)

| IP | PTR / hostname | Network | nginx | Seen | Status 2026-11-19 |
|---|---|---|---|---|---|
| `217.60.102[.]87` | `gjn6qy2j1y4q.server.swissnetwork[.]io` | SWISSNET LLC (Istanbul) | 1.28.3 | Nov 5 | down (empty `form.js`) |
| `217.60.195[.]96` | `rqirp3qh18f4.` / `47cw9nlavl39.server.swissnetwork[.]io` | SWISSNET LLC (Tokyo) | 1.28.3 | Nov 5 | down, host reassigned |
| `148.135.46[.]241` | none | AS35916 MultaCom (LA) | 1.24.0 | Nov 9, 15 | **live**, `form.js` match |
| `148.135.106[.]233` | `mail.spilworld[.]com` | AS35916 MultaCom (LA) | 1.24.0 | Nov 12, 19 | **live**, `form.js` match |
| `148.135.10[.]58` | `mail.ivorexim[.]com` → **PTR removed ~Nov 19** | AS35916 MultaCom (LA) | 1.24.0 | Nov 18, 19 | **live**, `form.js` match |

- `148.135.0.0/17`: ex-ARIN ERX space now at RIPE; inetnum netname `BGXO`, org
  `Company 64d3456fRJhdnz7J` (AU), abuse `report@abuseradar.com`. This is a **leased block (IPXO/AbuseRadar)**
  with a placeholder lessee, originated by **AS35916 MULTA-ASN1 (MultaCom Corp, US)**.
- `.10.58` exposes IMAP/POP (143, 993, 995, STARTTLS); `.106.233` exposes 110 and 22. With the
  `mail.*` PTRs, this suggests the hosts **double as lure senders** (rDNS set to pass checks). Port 25/587 not yet verified.
- Two waves: SWISSNET / nginx 1.28.3 (Nov 5), then MultaCom / nginx 1.24.0 (Nov 9 onward). Same kit, different build image.

### 4.2 Domains

| Domain | Registrar | Created | Expires | NS | Status |
|---|---|---|---|---|---|
| `ivorexim[.]com` | Namecheap | 2025-12-01 | 2026-12-01 | `ns1.gcorelabs.net`, `ns2.gcdn.services` | `clientTransferProhibited` only |
| `spilworld[.]com` | Namecheap | 2025-12-18 | 2026-12-18 | same | same |

- Both are **1-year registrations**, WHOIS updated **Oct 23 / Oct 27 2026**.
- Generic trading-company personas ("Ivor Ex-Im", "Spil World"), which fit B2B document lures.
- **CT history shows a dormant period, then activation:**
  - Dec 2025 – Sep 2026: only apex/wildcard certs (`ivorexim` renews every ~2 months; `spilworld` CA-style `00:00:00` timestamps). Consistent with **domain aging**.
  - `mail.spilworld.com` first cert **2026-09-01**; `mail.ivorexim.com` first cert **2026-10-01**.
  - **Both `mail.*` certs issued 2026-10-05, ~75 min apart** (04:16 / 05:31 UTC) → same operator / automation.
- **Live DNS is gone:** delegation intact, zones exist (`SOA` NOERROR) but `mail.<d>` returns
  `NXDOMAIN` and the apex has no A/MX/TXT. Historical records must come from passive DNS.

### 4.3 DNS change timeline vs. rollout *(hypothesis)*
GCore SOA serials appear to be Unix timestamps of the last zone change:

| When (UTC) | Event |
|---|---|
| 2025-12-01 / 12-18 | Domains registered |
| 2026-09-01 | `mail.spilworld.com` cert |
| 2026-10-01 → 10-05 | `mail.ivorexim.com` cert; paired `mail.*` issuance Oct 5 |
| 2026-10-23 / 10-27 | WHOIS updates |
| **2026-11-04 13:02** | `ivorexim.com` zone last modified (serial `1793797365`) |
| 2026-11-05 | SWISSNET kit hosts appear |
| **2026-11-09 02:33** | `spilworld.com` zone last modified |
| 2026-11-09 06:17 | `148.135.46.241` first seen (**~4 h later**), first MultaCom host |
| 2026-11-12 | `148.135.106.233` |
| 2026-11-18 | `148.135.10.58` |
| 2026-11-19 ~09:54 | PTR for `.10.58` no longer resolves; kit still live |

Each zone edit **precedes a new infrastructure wave** by hours to a day. That fits a deployment routine
that rewrites or clears DNS per rollout, rather than a single cleanup at the end. Two data points only, so treat this as a working hypothesis.

---

## 5. MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Resource Development | T1583.001 Acquire Infrastructure: Domains (aged Namecheap domains) |
| Resource Development | T1583.003 Acquire Infrastructure: Virtual Private Server (leased IPXO space, SWISSNET) |
| Resource Development | T1608.005 Stage Capabilities: Link Target |
| Resource Development | T1650 Acquire Access *(n/a)* / PhaaS tenancy, `key` routing |
| Initial Access | T1566.002 Phishing: Spearphishing Link |
| Reconnaissance | T1598.003 Phishing for Information: Spearphishing Link |
| Credential Access | T1056.003 Input Capture: Web Portal Capture |
| Defense Evasion | T1036 Masquerading (webmail login) |
| Defense Evasion | Decoy page on bare-IP hits; URL param stripping (`history.replaceState`) |
| Defense Evasion | Infrastructure rotation; DNS / PTR teardown between waves |

---

## 6. IOCs

All defanged. Hashes are SHA-256 unless noted.

**Network**
- `148.135.10[.]58` · `148.135.106[.]233` · `148.135.46[.]241` (live)
- `217.60.195[.]96` · `217.60.102[.]87` (historical, Nov 5)
- `ivorexim[.]com` · `mail.ivorexim[.]com` · `spilworld[.]com` · `mail.spilworld[.]com`
- ASN: AS35916 (MultaCom), netname `BGXO`, org `Company 64d3456fRJhdnz7J`

**URL / HTTP**
- Landing: `/?k=<6 chars>&url=<https brand URL>&user=<email>`
- Exfil: `POST /submit` JSON `{"key","pageUrl","fields":{_subject,Website,_software,email,password,sentemail,_domain,_email,_honey}}`
- Response: `{"redirect":"<pageUrl>"}`
- Static: `/p/css/general.css`, `/p/css/index.css?v=11`, `/p/js/form.js?v=1`, `/p/js/general.js`, `/p/images/roundcube-logo.svg`
- Campaign key: `VA3WHW`

**Content fingerprints**
| Artifact | Hash |
|---|---|
| Decoy `/` (626 B) | `eec05dac3c4d05881981461409eb10636c13d36de890bcad23c6da98f36f12bb` · Shodan mmh3 `1672167971` |
| `form.js?v=1` (1791 B) | `51583dd9da2fa2a0cbb35b83a1ba6ff64ce0452ebe7565e5fd207b7552386486` |
| `general.js` (2252 B) | `5a8bb59d2ae1c2ae66b4dbf5b6b9b3e3324311ba9258b6a494161e3e69eeca2e` |
| `general.css` (2117 B) | `e5f06bb0b0e794628d28c0f8a4d3fd893b5a3518d4f554ce890f29f756fc5f1a` |

**HTML markers:** `window.__GC__=`, `id="useEmailLogofromurl"`, `class="honey"`, `name="_honey"`,
`<link rel="icon" href="data:,">`, `<title>Under development</title>`.

> Don't pivot on the login page ETag. The body contains the victim email, so it varies per victim.

---

## 7. Hunting & detection

**Internal: mail (Zimbra)**
```bash
zgrep -hE '148\.135\.(10\.58|106\.233|46\.241)|217\.60\.(195\.96|102\.87)|ivorexim\.com|spilworld\.com' \
  /var/log/zimbra.log* | grep -E 'postfix/(smtpd|cleanup|qmgr)'
```
Look for `connect from mail.ivorexim.com[...]` / HELO, envelope senders, message IDs → recipients.
Also search message bodies for `148.135.` and `?k=`.

**Internal: web / proxy**
- Connections from clients to the kit IPs; a `POST` / larger upload means credentials were submitted.
- `google.com/s2/favicons?…domain=zimbra.uni-sofia.bg` (requires TLS inspection). Rare from legitimate sources.
- Zimbra auth logs: logins by recipients from new IPs/ASNs after their click time.

**Network signature (TLS-inspected egress)**
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PhaaS webmail kit credential POST (Ivory Mailbox)";
  flow:established,to_server; http.method; content:"POST"; http.uri; content:"/submit"; endswith;
  http.request_body; content:"\"_honey\""; content:"\"sentemail\""; content:"\"pageUrl\"";
  classtype:credential-theft; sid:9100001; rev:1;)
```

**External pivots**
- Shodan `http.html_hash:1672167971`; `http.title:"Under development" http.html:"index.css?v="` (other kit versions)
- urlscan `filename:"form.js"` + hash; `page.title:"Under development" AND filename:"index.css"`
- Censys `services.http.response.html_title="Under development"` + nginx
- Passive DNS (VT / SecurityTrails / Validin) on both domains → historical A/MX/SPF and co-hosted domains
- TLS cert SAN on `148.135.46.241` → likely third domain *(pending)*
- Track stable markers (hashes, `mail.<domain>` naming, Namecheap + GCore + Dec-2025 registration), not IPs.

**Containment**
- Block all five IPs at the edge; add both domains to the Zimbra / gateway sender blocklist.
- Force password reset + session revoke for any user who submitted.

---

## 8. Open items

- [ ] **Internal impact:** Zimbra log hunt (recipients, senders, message IDs, any submissions)
- [ ] TLS cert / SAN on `148.135.46.241` → third domain
- [ ] Passive DNS history for `ivorexim[.]com`, `spilworld[.]com`
- [ ] Verify SMTP (25/587) on kit hosts
- [ ] Confirm "clone mode" in the wild (urlscan hits with `__GC__` injected into real login pages)

## 9. Responsible disclosure checklist

- [ ] AbuseRadar / IPXO, `report@abuseradar.com` (lease revocation takes out all 3 live hosts)
- [ ] MultaCom (AS35916) abuse contact
- [ ] Namecheap, `abuse@namecheap.com` (both domains)
- [ ] GCore (authoritative DNS), optional
- [ ] SWISSNET LLC (historical hosts), FYI
- [ ] Google Safe Browsing + Microsoft SmartScreen
- [ ] CERT Bulgaria / GovCERT.bg
- [ ] Internal notice to uni-sofia.bg users (shared-document lure, Roundcube look-alike)
- [ ] Publish only after takedown / CERT acknowledgement

---

## Files
- `operation-ivory-mailbox.md`: this teardown
- Raw captures (local): `~/cases/VA3WHW/raw/` (`_.body`, `_p_js_form.js_v_1.body`, `_p_js_general.js.body`, `_p_css_general.css.body`, headers)
