---
layout: post
title: "East, Fast, Cheap Deception in the Cloud"
date: 2025-06-22
tagline: "Leveraging External IdP for Easy Honeynets"
image: /IMG/062225.jpg
tags: [Threat Hunting, Deception Tech, Threat Intelligence]
---

# Why a Cloud Honeypot?

<br> 
In an era where threat actors increasingly target cloud infrastructure, many organizations overlook the fact that they already possess the tools to proactively monitor malicious activity, without purchasing expensive commercial detection technology solutions. This blog post walks through how to build a lightweight honeypot and/or honeynet using common cloud services (like Azure or AWS) coupled with an [external IdP](https://developer.okta.com/docs/concepts/identity-providers/), making use of resources you probably already have access to. Inspired by previous implementations by [Colton Hicks](https://coltonhicks.medium.com/heres-how-i-used-azure-cloud-to-build-a-honeynet-detect-live-threats-and-respond-to-soc-9c4eec7c05d5) and [9purp0se](https://medium.com/@stevenrim/building-a-cloud-honeynet-soc-in-azure-980f84fb5147), this guide provides a modern, no-frills approach to capturing attacker behavior and generating actionable SOC telemetry, all while keeping costs and complexity to a minimum.

As someone who strongly believes in relevance as the cornerstone of good threat intelligence, I’ve always felt that defenders miss a critical opportunity when they overlook their own telemetry. It’s one thing to consume third-party IOCs from feeds or vendors, but quite another to observe firsthand what adversaries are probing for in your own cloud space. That kind of data isn’t just timely, but it’s also obviously tailored to your own threat model. By deploying a honeypot or a lightweight honeynet in infrastructure you already own or manage, you can generate relevant, high-signal telemetry that reflects the real interests and tactics of threat actors targeting your sector, tech stack, or geography. It’s one of the most honest, grounded ways to inform detection engineering and drive SOC maturity.

Yet, as I began mapping out the architecture, I kept running into the same trade off: the safest designs, those in completely separate cloud tenants, force you to abandon your corporate domain, while the most realistic designs, those living inside your main tenant, introduce unacceptable risk if a misconfiguration lets an attacker pivot. The solution that finally threads that needle is to front the entire deception layer with an **external identity provider** such as [Okta](https://www.okta.com/).  A standalone Okta tenant lets you issue convincingly real looking ```@yourcorp.com``` credentials without ever touching the production directory, then route any “successful” logins into a fully sandboxed cloud environment. In other words, you retain brand realism for the attacker and keep the blast radius at arm’s length for the defender, making external IdPs the linchpin of the approach outlined in the rest of this write up.
<br> 

## What You’ll Need to Get Started

<br> 

Standing up a cloud deception environment doesn’t necessarily require spinning up virtual machines or purchasing enterprise logging tools (although you’ll find yourself wanting to do this after you start). In fact, with a bit of creative configuration, you can build a convincing honeynet using free-tier services and publicly available tooling. At its core, this approach requires only a standalone identity provider like [**Okta Developer Edition**](https://developer.okta.com/), a few **static** [**HTML decoy apps**](https://dev.to/progrium/apptron-demo-zero-config-html5-native-apps-29f8) hosted on platforms like **Azure Static Web Apps** or **Cloudflare Pages**, and a **basic telemetry pipeline** to collect logs. This drastically lowers the barrier to entry: no need for full cloud subscriptions, firewall tuning, or heavy infrastructure. Because your apps live behind a fake SSO portal, the attacker experience still feels cohesive and real, but your costs stay near zero. For teams looking to experiment with deception without going through procurement or provisioning cycles, this is a fast, safe, and effective entry point.

Since we’re opting for using a standalone IdP tenant such as Okta as our front door, most of the labor load consists of setting up user accounts and registering a few decoy applications or portals within it. Fortunately, Okta’s free developer tier is more than sufficient for standing up a basic SSO dashboard and simulating a realistic corporate login experience to get you started, though later on you will be paying for at least the basic plan to get the ```subdomain.okta.com``` naming convention for realistic bait. You’ll provision a handful of believable honeypot accounts using your real corporate domain (e.g., ```j.smith@yourcorp.com```) and configure them to “authenticate” into fake apps, VPNs, or admin tools, each of which points to infrastructure you control in an isolated cloud environment. While this step adds a bit of overhead compared to a traditional honeypot setup, it unlocks much higher realism, especially for detecting identity-based attacks like password spraying, MFA fatigue, or credential stuffing. The rest of this post will walk through how to tie these components together into a safe, disposable, and convincingly realistic trap.

## The Primary Bait: Honeypot Accounts

<br> 
While [exposed VMs and open ports](https://github.com/robertdavidgraham/masscan) still catch their share of scanners and exploit attempts, today’s more capable adversaries often lead with identity-based access, credential stuffing, password spraying, or phishing campaigns that aim to walk in the front door. That makes it crucial to populate your decoy environment with realistic-looking user accounts, especially if you're leveraging a standalone identity provider like Okta. These honeypot identities should mirror your actual naming conventions (```it.admin@yourcorp.com```, ```vpn.engineer@yourcorp.com```), but exist only within the fake IdP tenant, with no connection to production systems. You can enroll them in decoy SSO apps, assign them weak or recycled passwords, and even script behavioral lures (like scheduled logins or app usage) to boost authenticity. Because they live entirely outside your corporate directory, any login attempt is inherently suspicious, and all activity tied to them becomes high-signal telemetry. This setup gives you a front-row seat to the tactics attackers use against your brand, with zero operational risk.

## A Quick but Critical Disclaimer

<br> 
Before diving deeper, it’s important to emphasize that this entire approach is built around **strict isolation**. The honeynet environment should never be connected to your production or enterprise network, and should not have access to any sensitive data, credentials, or internal services. Think of it as a self-contained sandbox: a decoy environment purpose-built for observation, not interaction. For existing Okta customers, this means setting up a second tenant.  For non-Okta customers, you’re likely about to become at least a Basic plan customer strictly for this honeynet.  That said, the goal here is to let attackers think they’ve found something interesting, without ever giving them a chance to pivot, escalate, or cause real harm. This is why infrastructure-as-code tools like Terraform or Bicep are so valuable here: they allow you to spin up a disposable, instrumented environment quickly and tear it down just as easily if anything looks risky or out of scope. Honeynets and deception tech should feed your visibility, not become a liability.

## Finding the Middle Ground 

<br> 
One of the common challenges I’ve seen with deception technology solutions is balancing the realism of baiting your real resources with keeping the honeynet segregated from said resources.  Sure, setting up a few misconfigured VMs is going to get attention, but did you really learn anything about your adversary when your honeynet gets mass-scanned, [Bloodhounded](https://bloodhound.readthedocs.io/en/latest/), and handed off to some ransomware crew?  We already knew that would happen.  It happens every day.  Essentially, what we’re hoping to catch here is not just the everyday garbage (which can also be useful! Just not _as_  useful), but also who has a particular interest in your network and may be explicitly targeting it.  For that, we need to ensure not just that there is robust honeynet telemetry in place, but also that it is realistic enough to attract the good stuff. For cloud in particular, that’s primarily going to involve the usage of the same domain names and infrastructure identifiers that your production environment is currently using, and that comes with some tradeoffs.

So on the topic of isolation, some pros and cons are at play. Clearly the safest option is to build it inside a **completely separate Cloud provider tenant**, which guarantees that nothing in the environment can be accessed from or grant access to your production systems. This hard boundary is ideal from a security perspective, but it comes with a drawback: you [**can’t reuse**](https://techcommunity.microsoft.com/discussions/deploymentnetworking/splitting-company-into-2-tenants/1604025)  your organization’s primary domain name in the new tenant. Since Azure, for instance, requires domain verification at the tenant level, you'd have to stand up your honeynet using a different domain altogether. This breaks the illusion for attackers, who might quickly recognize that corp-honeynet.net doesn’t match your actual brand. In an attack simulation or opportunistic scanning scenario, that divergence can make all the difference between a successful deception and being ignored.

To preserve that domain realism, some teams consider building the honeynet in a **separate Azure subscription within the same tenant**. This keeps the look and feel consistent, you can use your real domain (```yourcorp.com```), real SSO settings, and even similar resource naming. However, this comes with serious trade-offs: privilege boundaries between subscriptions aren’t always airtight, and subtle misconfigurations in role assignments, conditional access, or shared resource policies can open the door to [unintended lateral movement or privilege escalation](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48). In a worst-case scenario, an attacker who successfully compromises a honeypot resource could begin probing or pivoting into production systems, turning a deception exercise into a real incident.  This would be a disaster.  Good luck ever doing this in your org ever again, if you ever got the leadership signoff to do so in the first place.

That’s where using an **external identity provider like Okta**  presents a compelling middle ground. With a standalone Okta tenant, you can create honeypot accounts that look and feel exactly like real ones, complete with the **actual corporate domain in the username** (e.g., ```vpn.admin@yourcorp.com```), all without requiring domain verification or linking to your production directory. From the attacker’s perspective, they’ve compromised valid credentials and landed in a legitimate corporate SSO portal. But behind the scenes, everything they touch is tied to **tied to isolated, disposable infrastructure**  in a sandboxed Azure tenant, other cloud environment or fake apps. This gives you the realism of shared domains with the safety of total segmentation, enabling high-fidelity deception without risking your core environment.

## The Detailed Technical Differences

<br> 
It’s important to clarify that while this setup still relies on separate cloud tenants for security isolation, the use of an external identity provider like Okta adds a critical layer of **plausible realism**, and that is sort of the critical point here. In a native Azure-only design, the separation between tenants is obvious, an attacker might notice the domain name doesn't match, or the login page looks unfamiliar. But with an external IdP, you're able to replicate your branding, domain structure, and authentication flow in a completely fake environment, all without requiring DNS control or domain verification. This obfuscation blurs the line between the honeynet and your real enterprise infrastructure. 
 
| ![image](https://github.com/user-attachments/assets/780b48aa-56c6-4488-a635-ab4e2ee1031f) | 
|:--:| 
| *Come on in* |

<br> 

To an attacker, logging into a convincingly branded Okta portal using a ```@yourcorp.com``` identity and landing in a dashboard full of "legitimate" apps feels authentic, even though they’re in a sandboxed trap you control end-to-end.  In other words, setting up another Azure tenant (```company.onmicrosoft.com``` vs ```company-hub.onmicrosoft.com```) might look a little suspect, but using an external IdP allows for some creativity in the deception, like presenting a login portal at login.company-secure.net that (critically) **_accepts ```@company.com```_** **_usernames,_** mimics your corporate branding, and leads to a fake SSO dashboard with tiles for “Internal VPN,” “Admin Console,” and “HR Portal”, all pointing to isolated infrastructure designed to monitor and log attacker behavior.  You would want to closely mimic your real environment, not necessarily for realism (though still a factor), but for your own intelligence collection purposes.  You want to know what the attacker is particularly interested about in your resources, whether that is data exfiltration, establishing long-term persistence, or any other tactics you can understand from their logged behavior.

From here, you’d be ingesting the logging from your Okta portal to see what the attacker is doing inside the application, and what integrated apps they are interested in.  Following that, you’re just limited by your own time, effort and funding as far as integrating follow-on honeypot apps that they would then access.  For a low-interaction setup, this might just be a bunch of static html dummy logins that don’t lead anywhere.  For a high-interaction setup, this might include dummy instances of the same apps you use in your corporate environment – Sharepoint, Workspace, AWS services, maybe even a full-blown OpenVPN honeynet.. the sky (and your budget) is the limit.

To recap – the benefit to this approach is two-fold.  First, you are able to notionally log the entire kill-chain from the initial access via Okta all the way through app access, rather than setting up a random misconfigured honeypot system or service.  Second, you’re able to leverage additional legitimacy through the usage of Okta by using fake users using your real email domain, which makes things a little less suspicious when attackers are accessing apps that might otherwise not look like they are part of your corporate environment… sort of a reverse phish.  This allows for a super dynamic, homebrewed and modular approach to deception tech that you can do on the relative cheap, versus buying something out of the box.

## The Set Up: Building the Front Door
<br> 

Start by logging into the **Workforce Identity Developer Edition**  tenant you just spun up. From the admin console’s landing page, jump straight to **Customisations ➜ Branding**. Swapping in your company’s real logo, color palette and favicon takes only a few clicks but pays enormous dividends in believability; I also like to add the genuine corporate copyright line in the footer so the page survives a quick visual “is this legit?” sniff test. Leave the default Okta domain (```yourtenant.okta.com```) untouched, for attackers, the familiar look and the ```@yourcorp.com``` usernames matter far more than the URL itself, and it keeps cost (and DNS paperwork) at zero.  If you search around, you’ll find that many other organizations are also using the ```subdomain.okta.com``` convention anyway, so your deception solution is in good legitimate company.
 
| ![image](https://github.com/user-attachments/assets/0373eddc-b306-4f6d-b255-26603fedf1ea) | 
|:--:| 
| *Mr. Wonka will NOT be pleased* |

<br> 

Next, move to **Directory ➜ People** and start seeding your honeypot identities. Mimic the job titles and departmental email prefixes your real users would have, ```vpn.engineer@yourcorp.com```, ```it.helpdesk@yourcorp.com```, maybe even ```cfo.office@yourcorp.com```, but keep passwords intentionally weak or recycled (e.g., ```Summer2025!```). Keep in mind you will more than likely be using fake, created personas that exist only for this tenant.  You could mimic real users, but this will require some coordination with your organization (this should be happening anyway!), ensuring no legitimate users stumble upon your honeynet and attempt to use it.  If you want extra realism, schedule a tiny automation (Okta Workflows or an external script) that logs each account in once a day; a bit of baseline “noise” helps fool both bots and humans.


| ![image](https://github.com/user-attachments/assets/346a7b10-c716-45ff-9641-e1cde6075b60) | 
|:--:| 
| *Typical nepotism at work* |

<br> 

With users in place, head over to **Applications ➜ Applications ➜ Create App Integration**. For lightweight traps, choose **Bookmark App**, it’s nothing more than a tile that points to a URL (your static HTML dummy VPN login, fake Jira splash screen, or canary token document share). For higher interaction lures, pick **OIDC → Web App** or **SAML 2.0**, paste in the ACS/redirect URL of your honeynet service, and accept the default settings. Either way, upload the official icon of the product you’re spoofing (the [Jenkins logo](https://www.jenkins.io/), the GitHub [Octocat](https://github.com/octocat), the “lock” glyph from [GlobalProtect](https://www.paloaltonetworks.com/sase/globalprotect)) so the dashboard feels crowded with recognizable corporate tooling. Finally, assign each app to **Everyone**, as there’s no need to segregate apps (unless you want to), and verify you can sign in end to end with a test account.  For high-interaction lures, you’ll be configuring the SSO for passthrough authentication.  You want the attacker to think they’ve gotten all the keys through your Okta dashboard.  This obviously will take quite a bit of effort to build on the backend, and we’ll cover that further down.


| ![image](https://github.com/user-attachments/assets/31d2d9a0-572e-49bb-abb1-9345fae91e2c) | 
|:--:| 
| *Mixing fake apps with real-ish ones is easy with tiles* |

<br> 
 
The last mile is **telemetry**. In the developer tier you can’t enable log streaming, but the System Log API is wide open. Create an API token (**Security ➜ API ➜ Tokens**) and point a small Lambda or Azure Function at the ```/api/v1/logs``` endpoint every few minutes; ship the JSON events into Sentinel, Elastic, or even a simple SQLite file. You’ll capture who hit the login page, which account they tried, whether MFA was challenged, and, most importantly, exactly which dummy app tile they clicked next. Tie that to web server logs from the backend honeynet VMs and you now have a full, timestamp aligned picture of every step the intruder takes from “Okta credential spray” to “lateral movement recon”, all without exposing a single production asset.

|  ![image](https://github.com/user-attachments/assets/97de6011-feb0-44e0-9a89-f8d4637d6d50) | 
|:--:| 
| *Simple export to SIEM or your choice of reviewer* |

<br> 

### A Note on Lightweight Custom Apps

<br> 
As mentioned, the easiest way to populate your honeynet dashboard is with **lightweight, static decoy apps**, simple HTML pages that mimic login portals, internal tools, or document shares. These pages don’t need to do anything beyond looking plausible; their value lies in what gets clicked, what gets typed, and what behavior follows. That’s often more useful than a high-fidelity backend, especially if your goal is signal over spectacle.
But realism without control can backfire. If an attacker discovers your dummy GitHub portal or VPN login directly, say, by stumbling onto it via Shodan or running recon across a cloud IP range, that click doesn't tell you much. Worse, you lose context: was the attempt part of your honeynet campaign, or just noise?

To enforce flow and context, it's worth applying access restrictions at the web server layer, and NGINX makes this easy. A simple ```nginx.conf``` rule that checks for a valid Referer (i.e., traffic must originate from your Okta honeynet portal) ensures that your static apps only respond to requests coming through the path you’ve designed. This way, you maintain ownership over the attacker’s journey, and any interaction with your apps inherently implies they compromised one of your fake accounts and successfully navigated the SSO flow, raising the value and fidelity of the telemetry you collect. In short, _don’t let attackers just trip over your bait_.  Make them move through the funhouse you have built for them.

That NGINX config could look something like this:

<br> 

```nginx
server {
    listen 443 ssl;
    server_name dummyapp.yourdomain.com;

    ssl_certificate     /etc/ssl/certs/fullchain.pem;
    ssl_certificate_key /etc/ssl/private/privkey.pem;

    access_log /var/log/nginx/dummyapp_access.log;
    error_log  /var/log/nginx/dummyapp_error.log;

    location / {
        # Only allow if referrer matches Okta portal
        if ($http_referer !~* "^https:\/\/([a-zA-Z0-9\-]+)\.okta\.com\/") {
            return 403;
        }

        root /var/www/dummyapp;
        index index.html;
    }
}
```

<br> 

## Another Benefit: Account Diversity

<br> 
One of the underappreciated advantages of using an external identity provider like Okta is the ability to **diversify your honeypot accounts** to mirror the messiness of a real enterprise. Not every attacker gets tripped up by a brute-force trap, as many are testing identity posture, probing for weak MFA enforcement, or just waiting for someone to tap “Approve” out of fatigue. In this setup, you can configure some honeypot accounts with simple username/password access to simulate technical debt or legacy applications, while enrolling others in MFA via Okta Verify. These MFA-enabled accounts can be paired to defender-controlled mobile devices or emulators, allowing you to **manually approve logins after repeated push attempts**. The result is a controlled environment for studying attacker behavior under real-world conditions, including tactics like MFA bombing, while maintaining full containment and visibility. Just be aware that Okta Verify only allows one account per tenant to be active per device, so scaling this technique will require multiple devices, emulators, or thoughtful rotation.

### Tools & Tips: Managing MFA Simulation at Scale

<br> 
Because Okta Verify only supports one account per org per device, scaling out push-based honeypot accounts takes a little planning. Fortunately, you’ve got options:

* **Emulators:** Tools like [Android Studio](https://developer.android.com/studio) or [Genymotion](https://www.genymotion.com/) let you spin up multiple virtual Android devices, each running its own instance of Okta Verify. Perfect for testing multiple honeypot accounts in parallel.
  
* **Burner Devices:** Older phones or tablets can serve as physical Okta Verify clients. This works well if you're running a persistent honeynet and want a low-maintenance setup.
  
* **Account Rotation:** If you're simulating one attacker flow at a time, you can reassign Okta Verify enrollment between honeypot accounts as needed. It’s slower, but keeps things simple.

So in order to diversify what you can catch in the initial access phase, it’s valuable to mix in the brute-forceable password logins with a few MFA pushes.  The additional level of effort that comes with push spam also can assist an analyst in potentially differentiating between spray-and-pray trash that hits everyone versus an adversary that may have a targeted interest in your organization specifically.  I’d say it’s worth the extra effort to set this up for at least a few accounts.

## Counterintelligence Considerations

<br> 
This leads to another benefit.  If your honeynet is designed to attract not just random opportunists but more deliberate threat actors, it’s worth thinking beyond simple traps and toward **controlled leaks and counterintelligence**. One effective technique is to intentionally expose certain honeypot user credentials, either in staged breach data, fake GitHub repos, or dark web-adjacent paste sites, to simulate a realistic compromise. This not only helps test how attackers consume leaked data, but also gives you a chance to observe how they behave with partial access, particularly when MFA stands in their way.

For example, let’s say you've configured your honeypot accounts with TOTP-based MFA and assigned each a dummy phone number (using a burner SIM, Twilio, or Google Voice). If a threat actor gains the username, successfully sprays the password, but can’t log in without the 6-digit code, you may observe them **attempting to phish the code directly**. This could take the form of SMS messages impersonating IT support (_“Please reply with your login code to confirm your identity”_) or calls asking the “employee” to read their MFA prompt. If you’re logging both authentication attempts and incoming communications to the defender-controlled honeypot number, you’ll have visibility into the entire sequence — from credential use to social engineering follow-up.  A “leaked” employee list with a mobile number accomplishes this cleanly. 

This kind of deception adds a counterintelligence element to your wider detection strategy.  By watching how adversaries engage with what they believe is real data, you gain insight into their techniques, tooling, and level of sophistication. It also provides an opportunity to observe how actors pivot, adapt, or escalate their tactics when confronted with basic security friction. Done carefully, this level of instrumentation can turn your honeynet from a passive trap into an active lens on attacker behavior, and one that serves both detection and strategic intel goals.

Essentially the concept here is known as [“leak seeding”](https://en.wikipedia.org/wiki/Canary_trap), or the deliberate act of publishing fake but realistic-looking credentials, secrets, or internal data in locations where threat actors are likely to find them. The goal isn’t necessarily to protect real assets, but to lure attackers into engaging with a controlled honeynet environment. By planting staged leaks in public code repositories, paste sites, or breach forums, defenders can simulate the fallout of a compromise, then monitor how adversaries interact with that bait to study their tools, techniques, and priorities. It’s a proactive counterintelligence tactic that turns “being breached” into an opportunity to learn.

## Possible App Layer Options

<br> 
This is where you can get really creative, but for the purposes of this writeup, I’ll stick to as many free options as I can.  So once you’ve stood up your Okta identity layer and configured a handful of honeypot users, the next step is to give those users somewhere to go. In a real enterprise environment, authenticated users land on a dashboard with icons for internal tools, productivity suites, or admin consoles. We want to recreate that same experience for our fake users, and by extension, for any attacker who manages to log in.


|  ![image](https://github.com/user-attachments/assets/d7a477c5-67e0-4bbe-bf2c-612af5cac1c2) | 
|:--:| 
| *Some of these are fake custom built HTML, some are real.  Can you tell which is which?* |

<br> 
 
This is where **static web apps**  come in. While they aren’t full-blown enterprise tools under the hood, they can look convincing enough to fool an attacker into interacting. For example, you can clone the look and feel of SharePoint Online using a simple HTML/CSS template and deploy it to a free-tier Azure Static Web App or Cloudflare Pages site. These platforms let you host and serve static content globally, often with built-in CI/CD from GitHub, making it easy to spin up or tear down environments at will. Each fake app, whether it’s “SharePoint,” “VPN Console,” or “IT Admin Portal”,  should live at its own endpoint, with URLs like ```https://sharepoint-secure.pages[.]dev```  or ```https://internal-console.azurestaticapps[.]net```.  This would look sketchy under normal circumstances, but we’re relying on the added legitimacy that Okta has afforded us via our faked login portal and dashboard.  Additionally, the custom bookmark app afforded by Okta means you can dress these up to look like real Sharepoint, but the attacker will be accessing a simple html with file host clone.  This took me less than 10 minutes to build, with each link mapping to a CanaryToken-ed dummy document.  You can imagine what is feasible in a day or a week of building:
 

|  ![image](https://github.com/user-attachments/assets/d7f2ce85-d35f-4d68-a47e-950f4b2f335d) | 
|:--:| 
| *Real enough - but you can really sell it with some more effort* |

<br> 

With that said, static content alone obviously isn’t enough. You also need to control access. If someone stumbles upon one of your fake apps via Google, a misconfigured DNS entry, or a leaked URL, you don’t want them bypassing your Okta SSO trap. To enforce this, you can use a lightweight **JavaScript referrer check**. This script examines the ```document.referrer``` header and automatically redirects or blocks access if the visitor didn’t come through the legitimate Okta dashboard. It’s not a foolproof defense (attackers can spoof headers), but it does provide a useful gating mechanism that reinforces the illusion: real users go through Okta; anyone else gets kicked out. If you’re using Cloudflare Pages, you can bolster this even further by writing firewall or page rules that restrict traffic based on referrer headers, all without touching server-side code.

## Turning Fake Apps into Intelligence Assets

<br> 
Now that your attacker has landed inside a visually realistic fake app, the goal is to observe what they try to do. Do they browse a file repository? Try to download documents? Look for admin panels or submit forms? One easy way to capture this behavior is by seeding your static sites with **Canarytokens**: free, prebuilt traps that alert you when interacted with.

For example, [Canarytokens.org](Canarytokens.org) allows you to generate Word or Excel files that “call home” when opened, as well as web bug tokens, DNS beacons, and even cloned login forms. You might embed a fake Excel spreadsheet called ```2024-Bonus-Projections.xlsx``` in your SharePoint clone, or link to a "VPN credentials export" that’s actually a Canarytoken-powered PDF. These serve not just as decoys but as telemetry producers. Once clicked, they’ll send alerts to your inbox or webhook endpoint, giving you visibility into what piques an attacker’s interest. That insight can inform everything from SOC alert tuning to phishing lure design to credential stuffing detection rules.

If you want to go deeper, you can add logging to the static apps themselves via services like [Plausible Analytics](https://plausible.io/), or self-hosted collectors that log user-agent strings, behavior flows, and button clicks. The key is to treat these apps not just as traps, but as **intelligence sensors** designed to reveal attacker preferences and priorities. If you opted for Cloudflare, the free tier of [Cloudflare Workers](https://workers.cloudflare.com/) provide a powerful and cost-effective way to add custom telemetry and logging to your honeypot environment, with a generous free tier that supports up to 100,000 requests per day. By leveraging Workers, you can capture detailed request metadata, enforce access controls, and even integrate with external logging or alerting systems, helping you gain deeper insight into attacker behavior while keeping your infrastructure simple and affordable.

## Monitoring the Funnel: From Login to Lure

<br> 
Your deception technology solution should tell a story, and that means correlating data from multiple layers. Okta provides detailed logs for user logins, failed password attempts, and MFA prompts, which can show you exactly how an attacker gained access and what tactics they used. If you’ve configured some honeypot accounts with password-only access and others with MFA, you’ll be able to see whether they spray common passwords across accounts, attempt MFA fatigue attacks, or skip accounts that require a second factor.

Downstream, you’ll receive alerts from your Canarytokens when files are opened or forms are submitted, completing the picture. You can correlate “User X authenticated via Okta” with “User X accessed the SharePoint tile,” followed by “User X triggered a canary document alert”, with user telemetry from Cloudflare Workers.  That kind of kill-chain visibility is nearly impossible to get from traditional honeypots.

Best of all, all of these components live outside your real infrastructure. Okta’s developer tenant, your static web apps, and your telemetry tooling are completely disconnected from your corporate systems, which means any interaction is inherently suspicious and your production environment is never at risk. If someone’s in your fake SharePoint portal using a known username, they didn’t just stumble upon it via mass-scan, they’re operating with intent. That makes your alerts not only high-signal, but often early warning indicators of a broader campaign.

## Further Maturity: Getting into Full-Fledged Virtual Honeynets

<br> 
As your deception setup matures and you begin to demand deeper interaction or greater realism, you may find yourself moving beyond static sites and lightweight telemetry. This is where traditional compute platforms like **AWS EC2** or **Azure VMs** come into play. While these options typically introduce some cost, they also open the door to high-interaction honeypots.  These are systems that can fully emulate services like SSH, RDP, web apps, or even internal admin tools. Running full operating systems in isolated cloud environments allows you to capture everything from command execution and lateral movement attempts to file uploads and privilege escalation behaviors.  

I won’t get into technical walkthroughs as these are very well covered elsewhere. I would recommend the [AWS guide](https://aws.amazon.com/blogs/security/how-to-detect-suspicious-activity-in-your-aws-account-by-using-private-decoy-resources/) to start, as well as deeper dives from [Steve Gathof](https://medium.com/@sudojune/deploying-a-honeypot-on-aws-5bb414753f32) and [BohanSec](https://bohansec.com/2023/11/28/Deploy-T-Pot-Honeypot-To-AWS/). The latter two utilize heavy usage of [T-Pot](https://github.com/github-rashelbach/-T-Pot-Honeypot), a T-Mobile multi-honeypot solution that is easy to standup in a solution like AWS EC2.


|  ![image](https://github.com/user-attachments/assets/ce85509a-f24b-49e1-9b8f-5dd6abe4cc64) | 
|:--:| 
| *Putting the T-Pot on* |

<br> 

So imagine you deploy T-Pot on an AWS EC2 instance, but instead of exposing it to the open internet like most public T-Pot deployments, you lock it behind a fake VPN tile in your Okta SSO dashboard. This means the only path to the honeypot is through a seemingly legitimate @yourcorp.com identity and an SSO login page that mirrors your corporate branding.
Once “logged in,” the attacker is presented with what looks like a corporate VPN or internal access portal, which silently proxies them to the T-Pot interface or forwards traffic to the EC2 instance via a private listener. The attacker now believes they’ve made it past the perimeter and are sitting on internal infrastructure, all while you’re collecting telemetry across every emulated service, from SSH and SMB to ElasticPot and Honeytrap.


|  ![image](https://github.com/user-attachments/assets/8e5fc552-f10e-40c5-94dc-29128e8b3ce9) | 
|:--:| 
| *The Gold Standard* |

<br> 

**Why this is better than an open honeypot:**

* **Targeted access** – You can control who reaches the honeypot and under what conditions. Open honeypots get flooded with mass scans; this setup filters for more targeted activity (e.g., credential stuffing, phishing).
  
* **Realism without risk** – From the attacker’s view, they walked in through a real SSO portal and landed inside the network. From your side, everything is fake and instrumented.
  
* **Identity-layer telemetry** – You capture login attempts, password spray, MFA spam, and app selection before a single packet hits the honeypot—critical intel that’s invisible in traditional T-Pot deployments.
  
* **Controlled kill chain** – By staging access through Okta, you decide which apps, systems, and services the attacker can “find” next. It’s a curated deception path, not a junkyard of unguarded bait.

Overall, this finely tunes your captured telemetry.  Where an open honeypot infrastructure will see a lot of drive-by opportunism, this approach filters attacker behavior to just those specifically interested in your organization enough to overcome the barriers you placed in front of this infrastructure.  Now you can see what exactly happens and what exactly an adversary is interested in, as well as their level of sophistication, should they actually breach your network.  

## Wrapping It All Up: Deception as a Force Multiplier

<br> 
The reality is that attackers are getting smarter, stealthier, and more tailored in their operations, so your defenses should be too. What this blog post has outlined is a way to trap bad actors, but also a way to transform your cloud presence into a source of intelligence. By building a deception environment around external identity providers like Okta, isolating infrastructure in sandboxed tenants, and layering in believable static or interactive lures, you turn passive decoys into active sensors. This approach is preferred because it doesn’t just tell you _that_ someone knocked on your door; it tells you _who_, _how_, and _why_.

And crucially, it does all this without needing enterprise-grade security budgets or specialized software. Most of the building blocks, like Azure, Cloudflare, Okta, static site hosting, even alerting pipelines are free or already available in your environment. The key is combining them strategically, with just enough realism to attract interest, and just enough control to stay safe.

Whether you're looking to better understand how you're being targeted, feed detection engineering with more relevant signals, or simply raise your defensive posture through proactive telemetry, this model gives you a powerful toolset. Start small, tune as you go, and remember: deception isn’t just about catching the adversary, it’s about learning from them. That results in intelligence that is highly modular, and scales to your needs and budget.


