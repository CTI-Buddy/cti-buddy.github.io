---
layout: post
title: "Certificate Transparency Gives You Ten Days, or It Gives You Nothing"
date: 2026-09-21
tagline: "Measuring the head start on 52 malicious HTTPS hosts, and getting two answers instead of one"
image: /IMG/092126.png
tags: [Threat Intelligence, Phishing, Threat Analysis]
---

A certificate can give you ten days of warning -- but it can also give you four years.  Neither number is necessarily "wrong". The problem is that they're describing two very different things.

Certificate Transparency monitoring is usually sold as an early-warning system: an attacker registers a domain, gets a certificate, and defenders see the certificate before the phishing campaign starts. Some vendors will sell you on days of head start, while others will talk about hours.

I wanted to know what that head start actually looked like in the wild, so I measured it.

I sampled malicious HTTPS hosts from URLhaus and looked for their earliest certificates in CT. The result wasn't a single distribution. It was distinctly *two*. One group looked like infrastructure the attacker had built, with certificates issued shortly before the abuse was reported. The other looked like infrastructure the attacker had taken, with certificates that predated the campaign by years.

That's an important distinction. CT can give you a head start when the attacker needs to build the infrastructure. When they compromise somebody else's infrastructure, the certificate may have been there long before the attacker arrived.

The vendors aren't lying about the head start. They're letting you assume it generalizes.
I wanted a distribution behind the Certificate Transparency monitoring pitch. [Expiring.at](https://expiring.at/blog/building-a-real-time-threat-detection-pipeline-with-certificate-transparency-logs/) says an actor can register a typosquatted domain and launch a credential-harvesting campaign "in under 15 minutes" with a free TLS certificate. Yet [VigilDNS](https://vigildns.com/learn/certificate-transparency-monitoring) puts issuance "often days before the first phishing email goes out." [GlobalSign](https://support.globalsign.com/ssl/general-information/rolling-out-certificate-transparency-ssl-certificates) describes CT surfacing suspect certificates "in a few hours" instead of weeks or months - though that is about spotting misissuance, not about phishing lead time, which is the slippage this whole pitch rests on. None gives a distribution. The sources are free, so I measured it.

<br>

**TL;DR:** 

I sampled 75 of the 464 distinct named HTTPS hosts in the [URLhaus recent-URLs feed](https://urlhaus.abuse.ch/downloads/csv_recent/) and [found certificates for 52 of them.](https://crt.sh/) The median lead to the URLhaus report was 196.5 days, but that number hides two very different populations. A 92.4-day Otsu cut separates 23 short-lead hosts with a median of 10.3 days from 29 long-lead hosts with a median of 1,418.4 days.

The short group looks like infrastructure the attacker [built](https://attack.mitre.org/techniques/T1583/001/). The long group looks like infrastructure the attacker [compromised](https://attack.mitre.org/techniques/T1584/001/), but these are just my theories, not proven rules.  I'd probably "Medium Confidence" a call that generally speaking short certificates are attacker owned while old certificates are attacker compromised.  That said, certificate count provides a surprisingly strong shortcut: fewer than nine certificates tracks the short-lead population in this sample, while nine or more tracks the long-lead population with an AUC of 0.960.

That's useful for triage, but it isn't proof that CT gives you ten days of warning. The measurement is lead time to a malware-feed report, not lead time to the start of a phishing campaign, and CT can't see infrastructure hidden behind provider wildcards.

<br>

**Why the logs can be measured at all**

Every publicly trusted TLS certificate ends up in an append-only public log because [Chrome won't validate one that doesn't](https://googlechrome.github.io/CertificateTransparency/ct_policy.html). [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) describes the mechanics. The CA submits a precertificate and gets a signed timestamp; the entry goes public within the merge delay. An attacker who wants the padlock has no opt-out.

The pitch skips how much warning those logs actually gave, rather than how much they could give at best.

<br>

**The measurement, so you can rebuild it**

One bulk download and one CT query per host, plus some arithmetic. Pull the URLhaus recent CSV: URLs added in the last 30 days, with a `dateadded` timestamp. Query CT once per host, sequentially; the request is in the artifact block. Subtract the minimum `not_before` from `dateadded` for lead in days. Note what that measures - the certificate's own validity start, not the moment it appeared in a CT log. Those are close but not identical, and the difference cuts against the warning you actually get.

De-duplicate on serial. The precertificate and final certificate appear as separate rows sharing a serial, an artifact of CT 1.0 that [RFC 9162 changed](https://www.rfc-editor.org/rfc/rfc9162.html). Here, 1,795 raw entries collapsed to 1,022 distinct serials: 1.76x inflation. Using `len(json)` overstates the count by three quarters.

`dateadded` is when URLhaus was *told*, not when abuse began. Every lead here is an upper bound on the real head start. And URLhaus is a malware-distribution corpus that [declines phishing submissions](https://urlhaus.abuse.ch/api/). The marketing mostly sells credential-phishing detection, so this result may not transfer.

The 75 of 464 hosts are a convenience sample: sorted alphabetically, first 75 queried, two errors. Arbitrary with respect to lead time, but not random.

<br>

<img width="939" height="522" alt="Histogram of Certificate Transparency lead time for 52 malicious HTTPS hosts, with 23 short-lead and 29 long-lead hosts and an Otsu cut at 92.4 days on the log10 scale" src="https://github.com/user-attachments/assets/47f53114-1f70-4691-8ac6-90edbac52a23" />

_Editorial Note: source: URLhaus recent CSV and crt.sh, pulled 2026-09-16. The 52 hosts split at 92.4 days; the figure rounds the label to 92._

<br>

**The gap is real, not a trick of the binning**

Forty percent were reported within 30 days of their first certificate; four of 52 had under a day of lead. Then the histogram empties out until past 150 days. Sixteen of the long cluster's 29 hosts sit beyond three years.

I checked whether the split was a binning artifact. Otsu picks 92.4 days on the log10 lead times. The largest gap in the sorted values is between 52 and 163 days. A two-component Gaussian mixture puts its means at 9.9 and 991.8 days, with weights 0.46 and 0.54. Its BIC is 157.86 against 164.74 for one component, an improvement of 6.88; lower is better.

<br>

**Built, or stolen**

The short cluster behaves like the marketing says: one certificate, issued days before the malware report, mostly from [Let's Encrypt](https://letsencrypt.org/). The short-lead artifact below has one certificate dated 2026-09-03 and a report six days later. That reads like a domain acquired for the operation, with the certificate request its first public trace: [T1583.001](https://attack.mitre.org/techniques/T1583/001/).

The long-lead example has 20 distinct certificates going back to August 2022, the earliest issued by cPanel's certificate authority. Nobody registers that four years ahead of a campaign. I read it as a shared-hosting site serving malware after years of legitimate use: [T1584.001](https://attack.mitre.org/techniques/T1584/001/), compromise rather than acquisition. On that reading, the certificates predate the attacker. CT warning doesn't exist for this group.

<br>

<img width="939" height="522" alt="Certificate count against lead time for 52 hosts, with a threshold of nine certificates, balanced accuracy 0.931 and AUC 0.960 for separating the lead-time clusters" src="https://github.com/user-attachments/assets/47b9dca1-2e32-45b1-9771-68fd21fc2c62" />

_Editorial Note: source: URLhaus recent CSV and crt.sh, pulled 2026-09-16. The threshold is nine distinct certificates across 52 hosts; displayed scores are rounded._

<br>

**The count is the tell, and it needs no dates**

I didn't expect certificate count to separate the groups on its own. Nine distinct certificates gets balanced accuracy 0.931 and AUC 0.960. Every short-cluster host sits below it; 86.2% of the long cluster sits at or above.

That's one request without timestamp reasoning. On a live case it sorts the host into a young-certificate population or an old-certificate one, free, in roughly the time a crt.sh query takes - measured here at four to eleven seconds.

Be careful what you claim from that, though. What the data separates is certificate *age*, and the built-versus-stolen reading is my inference on top of it, not a measured label. There's at least one way the inference breaks: [T1583.001](https://attack.mitre.org/techniques/T1583/001/) explicitly covers acquiring *expired* domains, and an attacker who buys a lapsed domain inherits its whole certificate history. That host would land in the long cluster while being entirely attacker-controlled. So treat a long history as evidence the domain existed before this campaign, which is useful on its own, rather than as proof somebody else still owns it.

The issuer tells you nothing either: Let's Encrypt is roughly half of both clusters. Only cPanel's CA leaned, four hosts, all long-lead - consistent with shared hosting, and too few to carry weight.

<br>

**What CT never sees**

Of 73 clean queries, 21 found no certificate: 71.2% coverage. Twelve sit behind provider wildcards on shared platforms. The certificate belongs to the provider, so a per-host CT search can never match those hosts. VigilDNS acknowledges this in its [limitations section](https://vigildns.com/learn/certificate-transparency-monitoring). Six other misses were deep subdomains; three were bare names with nothing logged.

That's a ceiling, not a gap you can tune away. Twelve of 73 hosts - 16 percent - sit behind a provider wildcard the operator doesn't control, so per-host CT search can never see them, and they lean toward the free-tier cloud services attackers keep moving onto. Another six missed on deep subdomains, where the cause is less clear-cut; counted together that's a quarter of the sample CT didn't reach.

<br>

**Artifacts**

- **Short-lead example:** `02teste[.]cc`, 1 certificate, earliest `not_before` 2026-09-03, Let's Encrypt, URLhaus `dateadded` 2026-09-09, lead 6.3 days
- **Long-lead example:** a shared-hosting subdomain, 20 distinct serials, earliest `not_before` 2022-08-30, cPanel Inc. Certification Authority, lead 1,471.8 days. Host not named: on this post's own reading its owner is a victim, and the name adds nothing to the measurement.
- **Platform-wildcard misses:** hosts under `b-cdn[.]net`, `screenconnect[.]com`, `workers[.]dev`, `edgeone[.]dev`, `aliyuncs[.]com`, `s3[.]amazonaws[.]com`, `cdn[.]discordapp[.]com`
- **Feed:** [URLhaus recent CSV](https://urlhaus.abuse.ch/downloads/csv_recent/)
- **Query:** `hxxps[:]//crt[.]sh/?q=<host>&output=json`, de-duplicated on `serial_number`

_Editorial Note: pulled 2026-09-16. The feed had 13,147 rows: 1,159 HTTPS URLs, 245 on bare IPs and 914 across 464 distinct named hosts. Both sources are live; re-running changes the numbers. The 12 platform / 6 deep-subdomain / 3 flat misses are my classification, not source fields. On the reading above, long-lead hosts are most likely victims rather than operators._

<br>

**What to actually do with this**

- **Ask for the certificate count first.** Under nine and you're probably looking at purpose-built infrastructure; well over nine and it's probably somebody's compromised website. That changes notification and takedown.
- **Expect zero warning on half of it.** CT alerting covers adversary-registered domains, not [compromised infrastructure](https://attack.mitre.org/techniques/T1584/001/), the larger group here.
- **Accept the platform blind spot.** A provider wildcard leaves no per-host trace.
- **De-duplicate on serial.** Raw row counts ran 1.76x high here and would distort a count threshold.

And stop accepting a single median. If a vendor quotes one lead-time figure, ask for the distribution.

<br>

**Conclusion**

The vendors aren't lying about the head start. They're letting you assume it generalizes.

Run it yourself and tell me if the split holds on a phishing corpus. I'd genuinely like to know.

<img src="http://canarytokens.com/traffic/static/si79fpgv9320rhhexq4a70dy4/post.jsp" style="display: none;" />
