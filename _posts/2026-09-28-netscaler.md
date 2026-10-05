---
layout: post
title: "You Can't Image a Firewall"
date: 2026-09-28
tagline: "KEV is asking for forensic triage on boxes the SOC doesn't own"
image: /IMG/092826.png
tags: [Detection Engineering, Threat Intelligence, Threat Analysis]
---

Stop me if you’ve heard this one.

CISA says: investigate whether this appliance was compromised.... The SOC says: we don't own the appliance.
The patch ticket has an owner.... The forensic investigation might not.

That's the problem I keep seeing in the [KEV entries](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) that carry `forensicTriage: Yes`. CISA isn't only telling someone to remediate a vulnerable appliance. It's telling them to find out whether the appliance was already compromised, sometimes on a three-day clock.

And the appliance may belong to the network team, the email team, or a vendor-managed service. The SOC may have no agent on it, no disk image, no shell, and sometimes no administrative access at all.

After about fifteen years working and running SOCs, that's the part of a KEV deadline I read first: *who actually has to do the work?*

In [catalog version 2026.09.14](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), 52 of 1,710 KEV entries carry `forensicTriage: Yes`. Nine were added in one week. The patch is only part of the job.
So what does triage look like when the compromised host is a security appliance the SOC doesn't own?
CVE-2026-76461 is a useful example.

<br>

**TLDR/EXSUM:** Of fifteen CVEs CISA added between September 8 and September 14, six affect network or security edge appliances: Fortinet, Citrix NetScaler, Cisco Firewall Management Center, two MikroTik RouterOS bugs and Cisco Secure Email Gateway. Five carry `forensicTriage: Yes`. Their `requiredAction` cites [BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) and separate [Forensics Triage Requirements](https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk): a second obligation alongside patching, on the same clock. Cisco's [advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-inj-2bLVGmhX) for [CVE-2026-76461](https://www.rapid7.com/blog/post/etr-cve-2026-76461-critical-cisco-secure-email-gateway-vulnerability-exploited-in-the-wild) publishes a grep against `mail_logs`, then warns that the attacker has root and the evidence may be gone. Patching has an owner. Triage frequently doesn't.

_Editorial Note: counts use catalog version 2026.09.14, checked September 15. Re-pull the JSON before reusing them._

<br>

**Cisco's worked example**

CVE-2026-76461 is a useful place to start because Cisco gives you something unusually concrete: a forensic check you can actually run.

It's a SQL injection in AsyncOS email parsing, CVSS 9.8, CWE-89. An unauthenticated attacker can send a crafted message through the gateway and execute commands as root. There are no workarounds. It [entered KEV on September 14, with a September 17 deadline](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json). Rapid7 reads the same-day listing as evidence of [zero-day exploitation](https://www.rapid7.com/blog/post/etr-cve-2026-76461-critical-cisco-secure-email-gateway-vulnerability-exploited-in-the-wild); SecurityWeek calls it the [second Secure Email Gateway flaw to reach KEV](https://www.securityweek.com/root-rce-zero-day-in-cisco-secure-email-gateway-under-active-exploitation/). There's no public attribution.

Cisco's indicator check is simple:

```text
cisco-esa> grep -i "COPY.*TO PROGRAM" [IronPort Text Mail Logs Log name - Default: mail_logs]
```

Any result may indicate malicious activity. Check every cluster member. 

That sounds straightforward until you read the next part of the advisory. The attacker has root, which means the evidence on the appliance may already have been [removed or hidden](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-inj-2bLVGmhX). Cisco recommends cross-checking network and firewall logs outside the device. That's the part I find more interesting than the grep itself.

The advisory gives you a detection and, in the same breath, the threat model that can defeat it. The appliance is where the attack happened, but it may not be the place you should trust most to tell you what happened.
That's [T1070](https://attack.mitre.org/techniques/T1070/) in practice. ATT&CK's M1029 mitigation, forwarding events off-system, lines up with Cisco's hardening advice for exactly this reason. If your logs only exist on the compromised appliance, you are asking the compromised appliance to preserve your evidence for you.

And access is another problem. On Secure Email Cloud, administrators without CLI access may not be able to run the check independently. Cisco contacted affected customers directly, but for those administrators even the vendor's recommended check may be out of reach.

So the question changes: It's no longer just *“What should I grep?”* It's *“What evidence still exists somewhere I control?”*

<br>

**What FMC triage has to answer**

The other Cisco entry, [CVE-2026-20079](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), makes that question considerably harder.

It's an FMC authentication bypass with `forensicTriage: Yes` and a three-day clock. Talos describes [three post-compromise clusters](https://blog.talosintelligence.com/fmc-ongoing-exploitation/), and the activity goes well beyond a single web request. UAT-12197 used a JSP web shell in the CSM Tomcat webroot and a JAR executor calling `OmniQuery.pl` to extract `name, auth_data` from the user database. UAT-11823, whose tooling Talos says overlaps with Sandworm, replaced `license.tmp` with a Makeself package so `package_info.pl` would run a Netcat reverse shell as root. UAT-11988 entered with static credentials and staged a Python SOCKS5 proxy plus a reverse SSH tunnel forwarding 389, 636, 88, 445, 135 and 5985 back to its host. Then it deployed Qilin.

At that point, triage has to answer a much bigger question than whether a known indicator exists. Did LDAP, Kerberos, SMB or WinRM traverse the manager outbound? For how long? What did the operator reach from there? And what evidence survives on the manager itself?

The last question matters because the compromise changes the evidentiary value of the box. A compromised management appliance isn't simply another endpoint with some suspicious files on it. It is an infrastructure device that may have been used to reach other systems, while also being capable of losing or altering the local evidence you're trying to reconstruct.

Sophos identifies UAT-11823's implant as a [2026 Cyclops Blink variant](https://www.sophos.com/en-gb/blog/-eye-spy-cyclops-blink-returns-with-extended-capabilities). It assesses a Russia-nexus with high confidence and association with IRON VIKING, also tracked as Sandworm, with moderate confidence, while noting that there is no conclusive evidence tying that group to the 2026 deployments. The malware first [surfaced in 2022](https://www.darkreading.com/cyberattacks-data-breaches/sandworm-chains-cisco-vulnerabilities-cyclops-blink) against WatchGuard and later ASUS devices, and has now been rebuilt for management appliances.

I'm keeping that story separate from the email-gateway zero-day. Stapling it to a Sandworm narrative because both products are Cisco is the laziness this field keeps rewarding.

The useful part of the FMC reporting isn't the attribution anyway... It's what the implant tells us about where to look when the appliance itself is a questionable source of evidence.

<br>

**Why hunt from outside**

Cyclops Blink gives us a good example of why that matters.

Its [controller](https://www.sophos.com/en-gb/blog/-eye-spy-cyclops-blink-returns-with-extended-capabilities) masquerades as `[kworker/0:1]`. Persistence uses `/lib/tz/timezone_check` and SysV links named `89timezone_check`, and the original executable is unlinked. Its capture module opens an `AF_PACKET` raw socket and uses an Aho-Corasick automaton to retain operator-supplied terms from credential-bearing packets, including cookies and tokens.
Those are useful artifacts, provided you can reach the host and trust what is still there. But.... the [network behavior](https://attack.mitre.org/techniques/T1040/) gives you another option.

The file-transfer module bypasses configured DNS. It opens TLS directly to Google's public resolver on port 443 and POSTs binary queries to `/dns-query`. Sophos says this avoids evidence in local DNS logs. That's exactly the kind of behavior I'd rather catch in flow records than depend on finding it later in the appliance's own logs.

The scanner module sends raw frames across connected networks, which Sophos says may also be detectable. Again, the interesting telemetry doesn't have to live on the compromised device. The appliance is the source of the activity. It doesn't have to be the source of the evidence.

Sophos also warns that compatible x86-64 Linux appliances beyond FMC belong in scope. The implant isn't tied to one vendor, which makes the external-hunting lesson broader than this particular Cisco case.

<br>

**The queue this lands in**

This is where the technical problem becomes an organizational one.... Patching usually has an owner and a change window. Triage may have neither.

Someone needs access to the appliance, access to the off-box logs, enough knowledge to understand normal egress from a mail gateway or management appliance, and enough authority to start a hunt within three days. Those people may not sit in the SOC. The team that owns the appliance may not own the SIEM. The team that owns the SIEM may not have access to the appliance.
That is the gap `forensicTriage: Yes` exposes.

The remediation workflow can end with a clean scanner report and a signature while the actual hunt remains unassigned. A patch record is easy to file. Proving that nobody was already inside the appliance is a different ticket entirely.

<br>

**What to actually do**

- **Assign triage before the next entry.** The [KEV `requiredAction`](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) puts internet-exposure evaluation on the stakeholder and offers "discontinue use" as the alternative. Settle ownership before day two of three.
- **Get logs off the appliance.** Cisco's [hardening guidance](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-inj-2bLVGmhX) calls for external logging with enough retention to investigate; ATT&CK recommends [M1029](https://attack.mitre.org/techniques/T1070/). Do this before the clock starts.
- **Hunt appliance egress.** Cisco asks for [unexpected uploads to external IPs](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-inj-2bLVGmhX). Add TLS to public DNS resolvers on 443 and appliance-sourced internal scanning.
- **Check management-port direction.** Forwarding 389, 636, 88, 445, 135 and 5985 outbound is [what the Qilin operator built](https://blog.talosintelligence.com/fmc-ongoing-exploitation/). Toward an appliance, those ports can be routine. From one, back out, they aren't. Worth being precise about where that shows up, though: those services ride inside the tunnel, so they won't appear as destination ports in external flow records - what you'd see leaving the estate is the tunnel itself. The port list is a signal on internal flow between the appliance and your domain controllers, and the tunnel is the signal on egress.
- **Preserve before rebuilding.** Cisco's [virtual-appliance recovery](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-inj-2bLVGmhX) starts with "record forensics information" and warns that a new instance destroys configuration and logs. Redeploying clean can delete the answer.
- **Use available network coverage.** Talos published [Snort SIDs 66075-66080, 66883, 66960 and 66961](https://blog.talosintelligence.com/fmc-ongoing-exploitation/); Cisco lists [67109-67110 for the email gateway](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-inj-2bLVGmhX). These don't require instrumenting the appliance.

<br>

**Indicators**

- **Cyclops Blink C2:** `89[.]34[.]96[.]56`, TCP 43856 or 49172
- **Netcat C2 (UAT-11823):** `208[.]123[.]119[.]215`, `91[.]214[.]78[.]118`
- **CVE-2026-20079 scanner:** `104[.]218[.]165[.]253`
- **UAT-11988 intrusion source:** `43[.]204[.]2[.]142`
- **Google public DNS used by the implant:** `8[.]8[.]8[.]8`
- **Implant path and service:** `/lib/tz/timezone_check`, `/etc/init.d/timezone_check`, `S89timezone_check` in rc2.d through rc5.d
- **Process masquerade:** `[kworker/0:1]`
- **User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Chrome/129.0.0` - Firefox tokens with a Chrome product token
- **Fixed AsyncOS releases:** 15.5.5-014, 16.0.4-302, 16.5.0-780

_Editorial Note: a subset from [Talos](https://blog.talosintelligence.com/fmc-ongoing-exploitation/) and [Sophos](https://www.sophos.com/en-gb/blog/-eye-spy-cyclops-blink-returns-with-extended-capabilities), which also publish hashes. Sophos says embedded RSA key material varies by build. Treat network indicators as perishable; filesystem artifacts are the durable half._

<br>

**Conclusion**

I give it a year before `forensicTriage` starts getting marked complete on patch records. Assign the hunt now and look at *all* your data streams, while there's time to argue about whose ticket it is.



<img src="http://canarytokens.com/images/9ty82hf48gsuja7k08qedykcm/post.jsp" style="display: none;" />
