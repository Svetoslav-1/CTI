# Operation Colibri Mask

A short OSINT teardown of a live credential-phishing operation that reuses one
piece of shared hosting to run more than one lure at a time. I ran into it after
a fake "your mailbox password expires today" email pointed at a cloned Zimbra
login page, and pulled the thread from there using only passive lookups and
public sandboxes.

Everything here was gathered from the outside: DNS, certificate transparency,
WHOIS, passive DNS and public reverse-IP data. I did not log in to anything, did
not submit test credentials to the collector, and did not scan or probe any of
the hosts. Live phishing URLs and attacker infrastructure are defanged
(`hxxps`, `[.]`) so this page is safe to read and so it is not a working link
list. The raw, un-defanged command log is kept in a separate private file and is
not part of this repository.

## Contents

- Summary
- How it started
- The phishing flow
- The fake login page
- Infrastructure
- A second lure on the same infrastructure
- Assessment
- Indicators of compromise
- Who to notify
- Limitations
- Method and tools

## Summary

| | |
|---|---|
| Theme | Credential harvesting |
| Primary lure | Fake Zimbra webmail "password expiry" notice |
| Second lure | French traffic-fine / government impersonation (`amendes-gouv-controlroutier`) |
| Delivery quirk | A short domain (`s5[.]cl`) used as a redirect into the phishing page |
| Signature trick | A trusted-looking domain glued on as a subdomain label of the attacker domain |
| Path signature | Misspelled `/imbra/` directory with a `zdts.php` collector |
| Hosting | Compromised / abused shared cPanel hosting (PDR / hostgweb, `207[.]174[.]215[.]130`) |
| My conclusion | One operator, several disposable lookalike domains, at least two lures, sitting on one shared server |

## How it started

The starting point was a phishing email dressed up as a Zimbra system notice. It
claimed the mailbox password expired "today" and offered two buttons, one to
"keep the same password" and one to "change" it. The sender was spoofed as
`admin@zimbra[.]org`, which is not even Zimbra's real domain.

The button led to a Zimbra login clone hosted at:

```
hxxps://colegiocolibri[.]com[.]br/mat/wp/logs/ssl/dz01/zm/z/imbra/zm
```

`colegiocolibri[.]com[.]br` is a Brazilian school. The `/wp/` in the path and the
long fake `logs/ssl/dz01` directory structure point at a compromised WordPress
install being used to host the kit. The site itself is a victim here, not the
attacker.

## The phishing flow

Watching the requests the browser makes (no credentials submitted), the chain is:

```
Spoofed Zimbra email
    -> hxxps://s5[.]cl/zimbraweb-com          (redirect hop)
    -> hxxps://colegiocolibri[.]com[.]br/.../imbra/zm   (login clone)
    -> POST to .../imbra/zdts.php             (credential collector)
```

`s5[.]cl/zimbraweb-com` redirects *into* the phishing page rather than being a
second stage after it. A public sandbox report of the URL confirmed the redirect
target and flagged the destination as a password-input page.

The login form posts to `zdts.php` with these fields:

```
loginOp=login
login_csrf=<uuid>
domain=<email>
username=<user>
password=<password>
epassword=<password again>
client=preferred
```

A few things stand out from the saved page source:

- `login_csrf` is a **static, hard-coded value** baked into the HTML. It is not a
  real per-session token, so it is cosmetic and is not validated server-side.
- `loginOp` and `client=preferred` are copied straight from the genuine Zimbra
  login form to make the request look authentic.
- The form asks for the password twice (`password` and `epassword`). The real
  Zimbra sign-in has no "Confirm Password" field. That extra field is the
  clearest single tell, and it exists to grab a clean second copy.

`zdts.php` executes server-side, so the browser never receives its source, only
its output (the redirect). The actual collector code and any harvested-credential
log live only on the compromised server's disk. There is no public copy of
`zdts.php` on urlscan, VirusTotal or GitHub, which is consistent with a freshly
deployed kit that has not been scraped yet.

## The fake login page

The clone is a lightly modified copy of the standard Zimbra `login.jsp`. The
CSS and favicon are hot-linked from `zimbra.met.hu`, the real Zimbra instance of
the Hungarian Meteorological Service, so that is the template's origin. The
attacker only had to change the form `action` to `zdts.php`, add the second
password field, and drop the whole thing onto a hacked site.

## Infrastructure

Two separate pieces of hosting are involved.

**The redirect (`s5[.]cl`).** It resolves to `104[.]131[.]95[.]103`
(DigitalOcean). WHOIS shows a brand-protection registrar (Marcaria) with
`trademarkarea.com` nameservers and a corporate-looking registrant, which does
not fit a throwaway phishing domain. Reverse IP and passive DNS on that address
return a small set of unrelated domains. The most likely reading is that `s5[.]cl`
is a legitimate short domain being **abused as an open redirect**, i.e. another
victim in the chain, not attacker-owned. Because of that, it should be reported
to its registrar and registry, not probed.

**The phishing host and its lookalikes.** Certificate transparency on the school
domain surfaced two hostnames that do not belong to it:

```
app.colegiocolibri.com.br.roveyo.in
app.colegiocolibri.com.br.railwaymcq.com
```

Read the registrable part from the right: the real domains are `roveyo[.]in` and
`railwaymcq[.]com`. The attacker prepended `app.colegiocolibri.com.br.` as a
subdomain label of their own domains, so a victim skimming the address bar sees a
string containing `colegiocolibri.com.br` and trusts it. This is the "mask" the
project is named after.

Both `roveyo[.]in` and `railwaymcq[.]com` resolve to `207[.]174[.]215[.]130`.
WHOIS on that IP returns `NetName: PUBLICDOMAINREGISTRY-NETWORKS` / `OrgName: PDR`
(PublicDomainRegistry, part of Endurance/Newfold), and the reverse-IP list is
dominated by cPanel service hostnames (`cpanel.*`, `autodiscover.*`,
`cpcalendars.*`) and a large number of `*.hostgweb.com.br` entries. That is the
fingerprint of a shared cPanel reseller hosting hundreds of unrelated tenant
sites. `roveyo[.]in` is registered through the same PDR/Endurance family
(created 2025-12-29, registrant in Uttar Pradesh, India, Cloudflare nameservers).

Two readings are possible and I cannot separate them from the outside:

1. the attacker bought cheap PDR/hostgweb hosting under these throwaway domains
   and stood the kits up themselves, or
2. they are abusing compromised neighbour accounts and pointing their lookalike
   domains at them.

Either way the practical takeaway is the same: `207[.]174[.]215[.]130` is a
shared server full of innocent third-party sites, so it must not be scanned or
enumerated. The provider's abuse desk is the single most useful place to report,
because PDR is both registrar and host for this strand and one report can take
down the domains and the hosting together.

## A second lure on the same infrastructure

Enumerating certificate transparency for the two attacker domains turned up more
masked hostnames, and they are not Zimbra at all:

```
ww2-amendes-gouv-controlroutier.colibriathenas.com.br.railwaymcq.com
ww3-amendes-gouv-controlroutier.colibriathenas.com.br.roveyo.in
```

`amendes-gouv-controlroutier` is French for "fines / gov / road-traffic-control".
That is a French traffic-fine government-impersonation lure, using the same
subdomain-masking trick, this time spoofing `colibriathenas[.]com[.]br` as the
front brand, and sitting on the same two attacker domains.

So the operation is not a single Zimbra page. It is at least two different
campaigns (a Bulgarian-language Zimbra webmail lure and a French government-fines
lure) run by one operator off the same disposable domains and the same shared
host.

`railwaymcq[.]com` also has a `mcqforstudents.railwaymcq.com` subdomain, which
looks like a thin, on-theme cover ("railway MCQ" quiz content) sitting in front
of the malicious use.

## Assessment

- One operator, multiple lures, low-cost disposable infrastructure. This is
  ordinary criminal credential theft, not a targeted or state-linked actor. The
  cloned Zimbra kit matches the well-documented family of Zimbra phishing that
  relies on compromised sites plus a PHP collector, rather than any exploit.
- The distinctive, trackable parts of this specific operator are the
  `/imbra/` + `zdts.php` path signature and the
  `victim.tld.<attacker-domain>` subdomain-masking pattern. Those are better
  pivots than the Zimbra theme, which is generic.
- The valuable artifacts (the `zdts.php` source and the stolen-credential log)
  exist only on the hosts' disks. The lawful way to reach them is through the
  hosting provider and the national CERTs, not by touching the servers.

## Indicators of compromise

Defanged. Treat every entry as malicious or abused.

| Indicator | Type | Role |
|---|---|---|
| `admin@zimbra[.]org` | Email (spoofed sender) | Zimbra lure |
| `hxxps://s5[.]cl/zimbraweb-com` | URL | Redirect into phishing page (abused legit domain) |
| `104[.]131[.]95[.]103` | IPv4 | Host of `s5[.]cl` (DigitalOcean) |
| `hxxps://colegiocolibri[.]com[.]br/mat/wp/logs/ssl/dz01/zm/z/imbra/zm` | URL | Zimbra login clone (compromised WordPress) |
| `hxxps://colegiocolibri[.]com[.]br/mat/wp/logs/ssl/dz01/zm/z/imbra/zdts.php` | URL | Credential collector |
| `app.colegiocolibri[.]com[.]br[.]railwaymcq[.]com` | Hostname | Masked Zimbra variant |
| `app1.colegiocolibri[.]com[.]br[.]roveyo[.]in` | Hostname | Masked Zimbra variant |
| `ww2-amendes-gouv-controlroutier.colibriathenas[.]com[.]br[.]railwaymcq[.]com` | Hostname | French gov-fines lure |
| `ww3-amendes-gouv-controlroutier.colibriathenas[.]com[.]br[.]roveyo[.]in` | Hostname | French gov-fines lure |
| `roveyo[.]in` | Domain | Attacker-registered lookalike base |
| `railwaymcq[.]com` | Domain | Attacker-registered lookalike base |
| `207[.]174[.]215[.]130` | IPv4 | PDR / hostgweb shared hosting origin |
| `/imbra/` + `zdts.php` | Path pattern | Kit signature |
| `victim.tld.<attacker-domain>` | Pattern | Subdomain masking |

Impersonated / victim brands (not attacker-controlled): `colegiocolibri[.]com[.]br`,
`colibriathenas[.]com[.]br`, and Zimbra / `zimbra.met.hu` as the cloned template.

## Who to notify

- **PDR / hostgweb** (`abuse@publicdomainregistry.com`) — registrar and host for
  `roveyo[.]in`, `railwaymcq[.]com` and `207[.]174[.]215[.]130`. Highest-leverage
  single report. Ask for takedown and for preservation of the kit and any log.
- **CERT.br** — for the compromised Brazilian host `colegiocolibri[.]com[.]br`.
- **CERT-In** — for the `.in` domain and Indian registrant/hosting.
- **CERT-FR / ANTAI** — for the French government-impersonation lure.
- **NIC Chile** (`abuse@nic.cl`) and **Marcaria** — for the abused `s5[.]cl`
  redirect.

Report first, publish after takedown, so the operator is not tipped off to
rotate before the infrastructure is killed.

## Limitations

- I could not recover the server-side `zdts.php` or confirm where it sends the
  stolen data (local file, email, or onward POST). That is inferred from the kit
  family, not proven.
- Whether the two attacker domains are freshly registered by the operator or are
  compromised legitimate accounts is unresolved.
- Passive DNS and reverse-IP data are never complete, so the host list is a floor,
  not a ceiling.

## Method and tools

Everything was passive or sandbox-based:

- `dig` and `whois` for DNS and registration data
- `crt.sh` for certificate transparency (the pivot that exposed the masked hosts)
- `api.hackertarget.com` and `api.mnemonic.no` for reverse IP and passive DNS
- VirusTotal and a public URL sandbox for the redirect chain, read-only
- The saved page source for the form and `login_csrf` analysis

No credentials were submitted, no host was scanned, and no server was accessed.
The full command log is retained privately and is deliberately excluded from this
repository.
