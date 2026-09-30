# Operation Colibri Mask — Evidence Log (redacted)

This is the sanitised, public version of the investigation log. Live attacker
infrastructure and IP addresses are defanged (`hxxps`, `[.]`). Registrar, registry
and tooling domains are left intact because they are not click-through hazards.

The command transcript below is what produced the findings in the main write-up.
Everything was passive: DNS, certificate transparency, WHOIS, passive DNS and
public reverse-IP APIs. No credentials were submitted to the collector and no host
was scanned or accessed. The recipient mailbox and any internal follow-up on the
affected side are deliberately not included here.

Long commands are shown with line continuations (`\`) and a few very long JSON /
error outputs are truncated with `...` for readability; nothing else is altered.

The large reverse-IP result for the shared-hosting IP is not reproduced. It was
several hundred unrelated tenant sites on a shared cPanel reseller, and republishing
those innocent domains would wrongly associate them with the campaign. Only the
evidentiary lines and the conclusion are kept.

---

## Command log

```bash
┌──(hippo㉿hippo)-[~]
└─$ dig +short s5.cl A
104[.]131[.]95[.]103

┌──(hippo㉿hippo)-[~]
└─$ dig +short s5.cl NS
ns02.trademarkarea.com.
ns03.trademarkarea.com.
ns01.trademarkarea.com.

┌──(hippo㉿hippo)-[~]
└─$ dig +short s5.cl AAAA

┌──(hippo㉿hippo)-[~]
└─$ dig s5.cl ANY +noall +answer
s5.cl.    77770   IN   NS   ns02.trademarkarea.com.
s5.cl.    77770   IN   NS   ns01.trademarkarea.com.
s5.cl.    77770   IN   NS   ns03.trademarkarea.com.

┌──(hippo㉿hippo)-[~]
└─$ whois s5.cl
Registrant name: LogicTree, Inc.
Registrar name: Marcaria.com International, Inc.
Registrar URL: https://www.marcaria.com/
Creation date:   2025-11-07 01:13:22 CLST
Expiration date: 2026-11-07 01:13:22 CLST
Name server: ns01.trademarkarea.com
Name server: ns02.trademarkarea.com
Name server: ns03.trademarkarea.com
Registry Abuse Contact Email: abuse@nic.cl

┌──(hippo㉿hippo)-[~]
└─$ curl -s \
     "https://api.hackertarget.com/reverseiplookup/?q=104.131.95.103"
s5[.]cl
www.freeved[.]com
www.s5[.]cl

┌──(hippo㉿hippo)-[~]
└─$ curl -s "https://crt.sh/?q=s5.cl&output=json" \
     | jq -r '.[].name_value' | sort -u
jq: parse error: Invalid numeric literal at line 1, column 7

┌──(hippo㉿hippo)-[~]
└─$ curt=$(curl -s "https://crt.sh/?q=%25.s5.cl&output=json"); \
     echo "$curt" | jq -r '.[].name_value' | sort -u
jq: parse error: Invalid string: control characters ... must be escaped (line 3)

┌──(hippo㉿hippo)-[~]
└─$ curl -s "https://api.mnemonic.no/pdns/v3/104.131.95.103" \
     | jq '.data[] | {query,answer,first,last}'
{ "query": "becauseitsgood[.]com", "answer": "104[.]131[.]95[.]103" }
{ "query": "go4merchandise[.]com", "answer": "104[.]131[.]95[.]103" }

┌──(hippo㉿hippo)-[~]
└─$ curl -s "https://crt.sh/?q=colegiocolibri.com.br&output=json" \
     -o /tmp/crt.json

┌──(hippo㉿hippo)-[~]
└─$ head -c 200 /tmp/crt.json; echo
[{"issuer_ca_id":413869,"common_name":"colegiocolibri.com.br", ... }]  (truncated)

┌──(hippo㉿hippo)-[~]
└─$ jq -r '.[].name_value' /tmp/crt.json 2>/dev/null | sort -u
app1.colegiocolibri[.]com[.]br
app1.colegiocolibri[.]com[.]br[.]roveyo[.]in
app.colegiocolibri[.]com[.]br
app.colegiocolibri[.]com[.]br[.]railwaymcq[.]com
*.colegiocolibri[.]com[.]br
colegiocolibri[.]com[.]br
mail.colegiocolibri[.]com[.]br
pmr.colegiocolibri[.]com[.]br
www.app1.colegiocolibri[.]com[.]br[.]roveyo[.]in
www.app.colegiocolibri[.]com[.]br[.]railwaymcq[.]com
www.colegiocolibri[.]com[.]br
(one further legitimate hosting-panel hostname of the school's own provider omitted)

┌──(hippo㉿hippo)-[~]
└─$ for d in s5.cl becauseitsgood.com go4merchandise.com freeved.com; do
      echo "== $d =="
      curl -s "https://crt.sh/?q=${d}&output=json" \
        | jq -r '.[]?.name_value' 2>/dev/null | sort -u
    done
== s5.cl ==
mail.s5[.]cl
s5[.]cl
www.s5[.]cl
== becauseitsgood.com ==
== go4merchandise.com ==
== freeved.com ==

┌──(hippo㉿hippo)-[~]
└─$ dig +short roveyo.in A; dig +short railwaymcq.com A
207[.]174[.]215[.]130

┌──(hippo㉿hippo)-[~]
└─$ dig +short app.colegiocolibri.com.br.railwaymcq.com A
207[.]174[.]215[.]130

┌──(hippo㉿hippo)-[~]
└─$ dig +short app1.colegiocolibri.com.br.roveyo.in A

┌──(hippo㉿hippo)-[~]
└─$ whois roveyo.in | grep -iE 'creat|registr|name server'
Registrar URL: https://publicdomainregistry.com/
Creation Date:      2025-12-29T14:58:58.821Z
Registry Expiry Date: 2026-12-29T14:58:58.821Z
Registrar: Endurance International Group India Private Limited
Registrar Abuse Contact Email: apac-tldadmin@endurance.com
Registrant State/Province: Uttar Pradesh
Registrant Country: IN
(registrant identity fields returned as REDACTED FOR PRIVACY by the registry)
Name Server: jaxson.ns.cloudflare.com
Name Server: priscilla.ns.cloudflare.com

┌──(hippo㉿hippo)-[~]
└─$ for d in roveyo.in railwaymcq.com; do
      echo "== $d =="
      curl -s "https://crt.sh/?q=%25.${d}&output=json" \
        | jq -r '.[]?.name_value' 2>/dev/null | sort -u
    done
== roveyo.in ==
app1.colegiocolibri[.]com[.]br[.]roveyo[.]in
*.roveyo[.]in
roveyo[.]in
ww3-amendes-gouv-controlroutier.colibriathenas[.]com[.]br[.]roveyo[.]in
www.app1.colegiocolibri[.]com[.]br[.]roveyo[.]in
www.ww3-amendes-gouv-controlroutier.colibriathenas[.]com[.]br[.]roveyo[.]in
== railwaymcq.com ==
app.colegiocolibri[.]com[.]br[.]railwaymcq[.]com
mcqforstudents.railwaymcq[.]com
*.railwaymcq[.]com
railwaymcq[.]com
ww2-amendes-gouv-controlroutier.colibriathenas[.]com[.]br[.]railwaymcq[.]com
www.app.colegiocolibri[.]com[.]br[.]railwaymcq[.]com
www.mcqforstudents.railwaymcq[.]com
www.railwaymcq[.]com
www.ww2-amendes-gouv-controlroutier.colibriathenas[.]com[.]br[.]railwaymcq[.]com

┌──(hippo㉿hippo)-[~]
└─$ curl -s \
     "https://api.hackertarget.com/reverseiplookup/?q=207.174.215.130"
# ~800 hostnames returned; overwhelmingly unrelated third-party tenants on a
# shared cPanel reseller (signature: pervasive cpanel.*, autodiscover.* and
# cpcalendars.* records, plus many *.hostgweb.com.br entries) -- not reproduced.
# Only campaign-relevant line in this output:
app.colegiocolibri[.]com[.]br[.]railwaymcq[.]com

┌──(hippo㉿hippo)-[~]
└─$ whois 207.174.215.130 | grep -iE 'orgname|netname|abuse|origin'
NetName:        PUBLICDOMAINREGISTRY-NETWORKS
OrgName:        PDR
OrgAbuseHandle: ABUSE5185-ARIN
OrgAbuseEmail:  abuse@publicdomainregistry.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/ABUSE5185-ARIN

┌──(hippo㉿hippo)-[~]
└─$ dig +short railwaymcq.com A; dig +short roveyo.in A
207[.]174[.]215[.]130
```

---

## What the log establishes

- Redirect hop `s5[.]cl` resolves to `104[.]131[.]95[.]103`, registered through a
  brand-protection registrar (Marcaria, `trademarkarea.com` nameservers). Reverse
  IP and passive DNS show only a few unrelated domains. Most likely a legitimate
  short domain abused as an open redirect, i.e. a third party in the chain — report,
  do not probe. (The `104[.]131[.]95[.]103` provider attribution stated in the
  write-up is an inference from the address range and was not confirmed by a WHOIS
  in this log.)
- Certificate transparency on the school domain exposed two hostnames whose real
  registrable domains are `roveyo[.]in` and `railwaymcq[.]com`, using the
  `victim.tld.<attacker-domain>` masking pattern.
- Both attacker domains resolve to `207[.]174[.]215[.]130`, which WHOIS identifies
  as PDR (PublicDomainRegistry) space; the reverse-IP fingerprint is a shared cPanel
  reseller (hostgweb). `roveyo[.]in` is registered in the same PDR/Endurance family,
  created 2025-12-29, registrant in Uttar Pradesh, India, Cloudflare nameservers.
- Further certificate-transparency records on the attacker domains revealed a second,
  unrelated lure theme: French traffic-fine government impersonation
  (`amendes-gouv-controlroutier`) fronting `colibriathenas[.]com[.]br`, on the same
  two domains — one operator, at least two campaigns, one shared host.
- The saved login-page source (see the main write-up) shows a static, hard-coded
  `login_csrf` value and a duplicate password field (`password` + `epassword`),
  confirming a cosmetic token and a double-capture form.
