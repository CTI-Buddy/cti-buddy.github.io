---
layout: post
title: "Automating the Simple Blocks with Blackwall"
date: 2025-07-01
tagline: "Another Simple Auto-Refresh ASN Blocklist"
image: /IMG/070125.png
tags: [Threat Hunting, Infrastructure Tracking, Threat Intelligence]
---

# Automating ASN-Based Threat Intelligence with Blackwall

Not every problem in cybersecurity needs to be solved with machine learning or a [15-layer detection stack](https://www.trolleyesecurity.com/articles-five-ways-to-simplify-your-security-stack/#:~:text=A%20complex%20security%20stack%20can,vulnerabilities%20rather%20than%20mitigating%20them.). Sometimes, effective defense begins with the fundamentals.  In this case, that means simple, structural blockades, especially when it comes to controlling external exposure.  I’ve also seen enough shops attempt to maintain massive, in many times manually curated IP blocklists.  These are done piecemeal and get out of control very quickly, and are generally reactive.  It’s not uncommon to intake information about an event that has already occurred and a SOC will block indicators that have already been torn down or rotated.  In many cases, it can be [security theater](https://www.recordedfuture.com/threat-intelligence-101/legal-ethical-considerations/security-theater) and creates an illusion of control.

[**Blackwall**](https://github.com/CTI-Buddy/BLACKWALL)  is a small project that mostly solves a headache for myself, but I thought it might be useful as a free tool for the wider community: **block what doesn’t need to talk to you, and just be done with it.**  I think there’s an assumption that most mature shops are already doing something like this, but this problem seemed common enough to me that I’d just make my own humble offering that solves the problem conservatively but effective enough that it might help whomever might be nodding along to that first paragraph.

Sometimes the simplest defenses are the most effective, and that’s the idea behind building a lightweight, automated blocklist that merges known abusive IP ranges with dynamically resolved IPs tied to low-reputation ASNs. Many of the worst actors on the internet operate from network infrastructure that’s already well-known to threat researchers: entire IP ranges used for malware staging, spam, C2, or phishing kits. In many cases, these hostile networks have a consistent track record of abuse, questionable ownership, and minimal action in response to takedown requests.

The result is a rolling list of suspect IP space, refreshed daily, that can be used with firewalls, proxies, or SIEM enrichment pipelines. It doesn’t try to do everything. It’s just a fast way to say “no” to the obvious.  And yes - it is a [Cyberpunk 2077 reference](https://cyberpunk.fandom.com/wiki/Blackwall). <br>


## Why Block by ASN?

<br> 

[Autonomous Systems (ASNs)](https://www.cloudflare.com/learning/network-layer/what-is-an-autonomous-system/)  are large blocks of IP ranges registered to specific organizations. Some ASNs are repeatedly abused for bulletproof hosting, phishing infrastructure, or botnet C2 staging. While not surgical, blocking entire ASNs that have no legitimate business interacting with your infrastructure can reduce attack surface significantly.  Add in the additional variable of analysis of what these ASNs are typically used for over time, and you can shut the door to commonly used infrastructure for attacks that your legitimate users are most likely not going to be using.

![image](https://github.com/user-attachments/assets/f41bd681-8662-4aae-9e0a-f401d23c1114)

While most ASNs belong to reputable providers, others serve as havens for **bulletproof hosting**, **botnet operations**, or **persistent phishing infrastructure**.  Blocking by ASN is a definitely a **coarse control**, but it’s often justified when entire networks are designed to facilitate abuse.  Essentially, there are a number of ASNs that meet two critical requirements to justify a widescale block: 1) they are demonstrated to exist primarily for less than reputable activity and 2) you don’t have much need for their traffic, inbound or outbound. If you never expect to receive a request from a sketchy VPS provider in Moldova or a hosting company in Indonesia that’s been tied to a half-dozen ransomware campaigns, it’s a pretty safe bet to just block them.

### The Dark Side of VPS Infrastructure

<br> 
[Virtual Private Server (VPS)](https://aws.amazon.com/what-is/vps/)  providers offer cheap, fast, and globally distributed compute that powers everything from hobby projects to enterprise SaaS platforms. But that same accessibility and scale make VPS services a hotbed for malicious activity, especially among low-cost or offshore providers with minimal oversight.  These can also be located in places that are going to ignore any takedown requests, abuse reports, or subpoenas. 

Unlike major cloud platforms (AWS, GCP, Azure), many VPS hosts operate with **bare-minimum** [**KYC (Know Your Customer)**](https://www.okta.com/identity-101/kyc/) **processes**, weak abuse enforcement, and rapid provisioning. For a few dollars, an attacker can spin up an instance, deploy a phishing kit, mass-scanning exploiter or malware payload, exfiltrate stolen data, and tear it all down, sometimes in under an hour. These operations often cycle across the same **repeat-offender ASNs**, many of which are tied to budget VPS companies that rely on anonymity and high turnover.

Some of the most commonly abused ASNs belong to providers offering "**bulletproof hosting**", or infrastructure explicitly marketed as resilient to takedown requests, law enforcement pressure, or abuse complaints. Others may not advertise that intent but end up effectively serving the same role due to inaction or volume.
<br> 
________________________________________
<br> 

### Bulletproof Hosting: Infrastructure for the Unlawful

<br> 
While many VPS providers end up facilitating abuse through inaction or loose policies, [**bulletproof hosting (BPH)**](https://www.sentinelone.com/cybersecurity-101/threat-intelligence/bulletproof-hosting/) takes it a step further, in some cases actively marketing to criminals by offering infrastructure intentionally designed to withstand takedowns, legal complaints, and abuse reports.

A bulletproof host will often ignore DMCA notices, delay or deflect law enforcement inquiries, and provide obfuscation services like **WHOIS privacy**[**, falsified registration data**](https://icannwiki.org/False_Whois)**,** obfuscated payment flows **and offshore jurisdictions** to shield both their customers and themselves.

Many bulletproof hosts operate out of countries with weak or uninterested law enforcement, such as parts of Eastern Europe, Central Asia, or the Middle East. They often rebrand frequently, swap out netranges or operate through shell companies to avoid blacklisting, which is one reason why **the ASN itself becomes a more stable target than any individual IP or domain**.
<br> 
________________________________________
<br> 


### Why Blackwall Targets These Networks

<br> 
Many of the ASNs targeted by Blackwall belong to a familiar category: [low-reputation VPS providers and bulletproof hosting operations](https://www.akamai.com/blog/security/determining-malicious-probabilities-through-asns) that serve as the internet’s most reliable sources of malicious infrastructure. While technically distinct, the line between the two is increasingly blurred. Bulletproof hosts often resell capacity from permissive VPS platforms, and many VPS providers drift into bulletproof territory through simple inaction.

From a defensive perspective, the strategy is simple: if your organization never needs to hear from a shady Romanian VPS host or a throwaway server in Kazakhstan, why let them try? Blackwall leverages this principle by treating entire [abuse-heavy ASNs](https://www.excedo.se/en/blog-articles/how-cybercriminals-are-abusing-autonomous-system-numbers-asn-for-bulletproof-hosting) as suspect and preemptively excluding them from the equation.

By regularly resolving ASN IP ranges and layering in trusted feeds like [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/), Blackwall gives defenders a fast, low-friction way to block known repeat offenders. It doesn’t aim to detect every attacker or attribute every campaign, but rather aims to reduce surface area, cut out noise, and free up analyst time for other telemetry.

![image](https://github.com/user-attachments/assets/3b1a7bb5-b53e-4f7a-bf13-af53024b2f07)


### A Note on Other Routes: Evasion via Residential and ORB Networks

<br> 
While many malicious campaigns still rely on predictable infrastructure, more sophisticated actors are taking a different path. Rather than staging attacks from noisy, abuse-heavy networks that are easy to block, they’re increasingly operating through **residential proxy services and** [**“ORB” (Operational Relay Box) networks**](https://www.team-cymru.com/post/an-introduction-to-operational-relay-box-orb-networks-unpatched-forgotten-and-obscured) designed to make malicious traffic appear indistinguishable from everyday users.

[**Residential proxy networks**](https://nordvpn.com/blog/residential-proxies/) (like those sold by services such as Bright Data, ProxyRack, or even malware-powered botnets like [911.re before its takedown](https://krebsonsecurity.com/2022/07/911-proxy-service-implodes-after-disclosing-breach/)) allow threat actors to route traffic through the IP addresses of unsuspecting home users. These IPs often belong to **major ISPs in the U.S., Europe, and Asia**, and show up in logs as **legitimate consumer traffic**. From a defender’s perspective, this makes blocking extremely difficult. For example, you’re not looking at a shady data center in Romania; you’re looking at a Comcast customer in Nebraska.

![image](https://github.com/user-attachments/assets/fc7f19e4-c561-42d8-b705-7c8a2ceb5741)

[**ORB (Operational Relay Box) networks**](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks) are collections of compromised or co-opted devices (often home routers, IoT hardware, or poorly secured servers) that are used by threat actors as **intermediary relay nodes**. These relays help obscure the origin of malicious activity by forwarding traffic through devices that appear **benign and geographically diverse**.

![image](https://github.com/user-attachments/assets/131b42a9-15eb-4fe0-aeda-593734756327)

The result is that some threat actors have gone from renting cheap VPS boxes to operating like they’re behind a **full CDN of hijacked or leased residential IP space**. It’s more expensive and more complex, but also far more effective at bypassing traditional IP-based filtering.
<br> 
________________________________________
<br> 

## What This Means for Blackwall

<br> 
Blackwall’s strength lies in eliminating the **predictable**, **recycled**, and **structurally abusive** IP ranges. These are ranges known to many analysts, but lack a persistent and repeatable way to deny it at scale. This does not target residential proxies or ORB networks because it simply isn’t going to work. It’s not designed to detect adversaries **masquerading as your customers**, and you’re going to run into issues [trying to prevent that at scale](https://danaepp.com/evade-ip-blocking-by-using-residential-proxies). Instead, the goal is to **narrow the field**. If you can confidently block the loud infrastructure, you can better focus your detection and response efforts on the quiet, deceptive ones: the residential proxy logins, the anomalous Tor traffic, the sudden surge of cloud activity in your MFA logs.

## Paid Solutions That Are Better Than This

<br> 
Blackwall is intentionally simple: it blocks what’s obviously bad, using public data and a curated ASN list. It’s effective in **reducing noise and risk** in environments where resources are limited or bespoke solutions are preferred. But when it comes to depth, context, and adaptability, there are commercial tools that go much further. Blackwall isn’t here to compete with those tools. It’s here to augment your existing defenses with something transparent, auditable, lightweight and free. In highly locked-down environments, or places where vendors aren’t an option, it gives defenders a fast, local, and autonomous option for reducing exposure to well-known infrastructure abuse.

If you’re already using a threat intel platform or commercial IP reputation feed, think of Blackwall as **the low floor, not the ceiling**, i.e. a good place to start, but not where you stop. Paid tools that are dedicated to this concept that I like include [GreyNoise](https://www.greynoise.io/) and [Spur](https://spur.us/). You can definitely implement a similar mass-block using their telemetry that’s much more targeted and elegant than this. They also cost money, obviously.. so the intent here is to do something “good enough for free” by just shutting the door on ASNs you don’t need to bother with.


## So What’s the Point?

<br> 
Really, the headache I was primarily looking to solve for myself was that ASN net-ranges change around [MUCH more frequently than I would have initially assumed](https://stackoverflow.com/questions/50955013/for-how-long-does-a-given-asn-stay-valid). Generally speaking, the infrastructure behind abusive ASNs isn’t static and tends to be highly fluid. Many of the networks Blackwall targets frequently shift their advertised IP space by buying, selling, or temporarily leasing new net ranges semi-frequently. This churn can happen daily, which makes any static list quickly outdated. The best way to keep up is to track the infrastructure itself, not just one-time indicators.

After running this daily for a little over two weeks, I had between 10 and 15 ASNs identified for daily pulls. Within that dataset, the ASNs in question on average swap out between 1-5 net-ranges daily, typically smaller /24s but as large as /18s. That’s frequent enough to render a static list [pretty significantly degraded](https://blog.cloudflare.com/consequences-of-ip-blocking/) by the end of the week. And that’s basically the annoyance I sought to sidestep here. Blackwall is built to be simple, repeatable, and automated. At its core, it’s a daily script that takes a preset of targeted ASNs pulls fresh IP ranges in CIDR format. It then merges that list with the well-known [Spamhaus DROP list](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) that does similar tracking. The goal is to keep an up-to-date snapshot of the IP infrastructure most commonly abused by threat actors, with a focus on reducing inbound exposure from networks that serve no legitimate purpose to most environments.


## Technical Details / How This Works

<br> 
Each day at 12:00 UTC, Blackwall performs a series of operations: 

It begins by reaching out to a curated set of Autonomous System Numbers (ASNs) known for their persistent association with malicious activity. Using a public feed service powered by [RIPE NCC](https://www.ripe.net/), Blackwall resolves those ASNs to their current advertised IP netblocks. Since IP allocations can change frequently, this step ensures the list always reflects the most accurate view of what infrastructure is actively being used.

![image](https://github.com/user-attachments/assets/e85d5650-d9a3-491d-8fe6-ca352417f596)

Alongside this, Blackwall pulls in the [**Spamhaus Don’t Route or Peer (DROP) list**](https://www.spamhaus.org/blocklists/do-not-route-or-peer/), a well-established feed of known bad IP ranges. These are combined with the ASN-derived data into a single blocklist file, updated daily and pushed to a GitHub repository. The result is a fresh, consolidated list of IP networks that organizations can use in firewalls, proxy configurations, or enrichment pipelines. There is almost certainly going to be overlap between the manually curated Blackwall list and DROP. That’s fine, it won’t break anything.

Blackwall also maintains a [second file that logs which ASNs are being monitored](https://raw.githubusercontent.com/CTI-Buddy/BLACKWALL/refs/heads/main/ASN_list.txt), along with their organizational names, pulled dynamically from the [RIPEstat API](https://stat.ripe.net/docs/data-api/ripestat-data-api). This helps defenders understand the scope of what’s being blocked, and keeps the project transparent and auditable. If the list of ASNs changes, Blackwall automatically rebuilds that metadata; otherwise, it just refreshes the IP data.

From here, a shop would need to implement Blackwall into its firewall solution, most commonly through what’s known as an [External Dynamic List (EDL)](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/policy/use-an-external-dynamic-list-in-policy/external-dynamic-list). From there, you’re done. The firewall does the rest, refreshing the ASN CIDR ranges as Blackwall updates daily.

By design, Blackwall avoids complexity. There’s no agent, no integration overhead, and no learning curve, just predictable, structural defense against infrastructure that doesn’t deserve to be trusted. Plug it into a border firewall or proxy and be done with it.


## How to Use It

<br> 
I have first-hand experience with a few of these, but referencing the technical docs for others suggests that most of these solutions will support an External Dynamic List (EDL)..  These should work, but as always – test first.


**🟧** [**Palo Alto Networks (PAN-OS)**](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/policy/use-an-external-dynamic-list-in-policy/configure-the-firewall-to-access-an-external-dynamic-list)
1. Navigate to Objects → External Dynamic Lists
2. Click “Add” →
    *	Name: Blackwall-IP-Blocklist
    *	Type: IP List
    *	Source: [https://raw.githubusercontent.com/CTI-Buddy/BLACKWALL/main/THEBLACKWALL.txt](https://raw.githubusercontent.com/CTI-Buddy/BLACKWALL/main/THEBLACKWALL.txt)
3. Create a Security Policy blocking traffic from this EDL.
4. Commit and deploy.

✅ *EDL refreshes automatically; use in firewall rules directly.*

<br> 
________________________________________
<br> 

**🟥** [**Fortinet FortiGate**](https://docs.fortinet.com/document/fortigate/7.6.3/administration-guide/379433/configuring-a-threat-feed)

1. Go to Objects → Threat Feeds → IP Address
2. Add a new feed:
    *	Name: BlackwallFeed
    *	URL: [https://raw.githubusercontent.com/CTI-Buddy/BLACKWALL/main/THEBLACKWALL.txt](https://raw.githubusercontent.com/CTI-Buddy/BLACKWALL/main/THEBLACKWALL.txt)
3. Go to Policy & Objects → Addresses, add a new address:
•	Type: External IP List
•	Link to Feed: BlackwallFeed
4. Use that address object in a firewall policy → Action: Block.

✅ *Refreshes on schedule; native feed support.*

<br> 
________________________________________
<br> 


**🟦** [**Cisco Firepower / FMC**](https://www.cisco.com/c/en/us/td/docs/security/firepower/610/configuration/guide/fpmc-config-guide-v61/security_intelligence_blacklisting.pdf)

1. Navigate to Objects → Object Management → Security Intelligence → Network Lists and Feeds
2. Add new feed:
    *	Name: Blackwall-IP-Feed
    *	URL: [https://raw.githubusercontent.com/CTI-Buddy/BLACKWALL/main/THEBLACKWALL.txt](https://raw.githubusercontent.com/CTI-Buddy/BLACKWALL/main/THEBLACKWALL.txt)
    *	Type: IP Feed
3. Apply in Access Control Policy → Security Intelligence tab.
4. Select Block action.

⚠️ *Ensure HTTPS feed accessibility from FMC.*

<br> 
________________________________________
<br> 


**🟩** [**pfSense (with pfBlockerNG)**](https://edepree.com/2021/03/07/pfsense-dynamic-blocking-of-threat-feeds.html)

1. Install pfBlockerNG via package manager
2. Go to Feeds → IPv4
3. Add custom list:
    *	Name: Blackwall
    *	URL: [https://raw.githubusercontent.com/CTI-Buddy/BLACKWALL/main/THEBLACKWALL.txt](https://raw.githubusercontent.com/CTI-Buddy/BLACKWALL/main/THEBLACKWALL.txt)
4. Set action: Deny Both (inbound and outbound)
5. Apply changes and reload.

<br> 
________________________________________
<br> 


**🟨** [**OPNsense**](https://docs.opnsense.org/manual/aliases.html)

1. Use built-in Firewall → Aliases
2. Add new alias:
    *	Type: URL Table (IPs)
    *	Name: blackwall_blocklist
    *	URL: [https://raw.githubusercontent.com/CTI-Buddy/BLACKWALL/main/THEBLACKWALL.txt](https://raw.githubusercontent.com/CTI-Buddy/BLACKWALL/main/THEBLACKWALL.txt)
    *	Update Frequency: Daily
3. Use in firewall rule (e.g., Block if Destination matches alias).
4. Apply changes.

✅ *No need for plugins if using native alias support.*

<br> 
________________________________________
<br> 

## Wrap-Up

<br>
Blackwall isn’t meant to be a silver bullet, and as I mentioned – it’s mostly to solve a personal annoyance of mine.  It is, however, a pragmatic, low-friction tool for shrinking your attack surface by targeting infrastructure that consistently enables malicious activity. In a threat landscape dominated by noise and velocity, it offers defenders a way to decisively filter out known-abuse networks using open data and repeat-offender patterns. Whether deployed at the edge, fed into enrichment pipelines, or used to harden internal services, Blackwall gives teams a simple but strategic advantage: it stops the traffic that doesn’t need to be there, so you can focus on what does.


<img src="http://canarytokens.com/terms/static/articles/0s6izgrh745q7mhyff27ergl7/contact.php" style="display: none;" />
