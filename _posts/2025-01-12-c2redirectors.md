---
layout: post
title: "C2 Redirector Usage and You"
date: 2025-01-12
tagline: "A Blue Teamer's Guide to Obfuscated Command & Control"
image: /IMG/011225.jpg
tags: [Cobalt Strike, Infrastructure Tracking, Threat Intelligence]
---

I'm a fan of chasing down command & control (C2) traffic for whatever reason, probably comes from my PCAP-exclusive analyst roots (ah, the pre-SSL everywhere days).  That understandably has gotten increasingly harder to do, and not only because of the embrace of SSL (which, to be clear, is a *good thing*), but because of all the various obfuscation quirks that make red teaming easier and blue teaming harder.  One of those quirks I tend to find more interesting is the usage of C2 redirectors, where C2 traffic is essentially "laundered" through a legitimate-looking server or cloud as a means of hiding origin, providing an air of legitimacy to what is likely high-frequency traffic, etc.  I say this, yet even in the year 2024 this technique has came and went in favor of keeping things simple with OAuth in the cloud rather than bothering with on-prem at all.  While that's certainly here to stay, I suspect C2 redirector usage will similarly be a long-term base-level of OPSEC for offense forever.

Maybe I'm just reading the wrong blogs, but I've noticed that everything on this topic seems to be written from the red team's perspective.  This makes sense -- there isn't *really* a fantastic way to detect these on the blue team side -- at least no way that I'm aware of currently.  Another thing I've noticed is that there doesn't seem to be any definitive blue team resource for all the different ways this could happen, nor any resource that clearly defines the various sub-terms or correlated techniques that tend to get conflated (and oh boy, do we love to conflate our terms).  Is a C2 Redirector actually just Domain Fronting? Is Domain Fronting even still a thing? Is Domain Hiding the new Domain Fronting? Which one of those things is C2 over Telegram?

So to kick this blog off, I thought I'd try and provide a definitive guide for C2 Redirection as a technique from the Blue Team's perspective, and try to package up the most easily understandable (and as a result, probably most utilized) mechanisms for redirecting C2.  I'll define those other related terms without getting too into the weeds on each, and try to give a quick history of various campaigns that were found to be using C2 Redirection within its attack path.  While we're at it, we'll see if we can't find a detection technique or two in the process.

**First Things First: What is a C2 Redirector?**

In short, a C2 Redirector functions as an intermediate step in traditional C2 traffic as a means of hiding or obfuscating what would otherwise be more detectable for a defender.  Essentially, C2 traffic that would otherwise frequently connect to <imabadyguy.xyz> will instead jump through a more legitimate looking domain like <im-a-good-guy-d8eigjaek3i09.z02.azurefd.net> before forwarding that traffic through to <imabadguy.xyz>.  This is handy for an attacker, because it blends in better with normal traffic, uses a trusted domain (in this case, Azure's CDN), and in more sophisticated schemes, can alternate between a few different Redirectors to avoid frequency patterning the traffic.

<p align="center">
  <img src="https://github.com/user-attachments/assets/e410c5d7-411b-4f25-957b-1f642d3cf0c3" alt="image">
</p>

**C2 Redirector versus Domain Fronting**

Okay so is this different from Domain Fronting?  Yes, kind of.  Enough so that they should be considered distinct, at least.  An attacker might use many of the same domains for Domain Fronting that could otherwise be used as a C2 Redirector -- really the primary difference is how each is configured.  [Cobalt Strike documentation probably defines it best](https://www.cobaltstrike.com/blog/high-reputation-redirectors-and-domain-fronting), where "a redirector is a server that sits between your malware controller and the target network. Domain fronting is a collection of techniques to make use of other people's domains and infrastructure as redirectors for your controller."  In short, Domain Fronting uses a high-reputation domain to hide the actual C2 server, while C2 redirectors are services specifically designed for directing traffic to a different location.

What's the difference? It mostly comes down to packet trickery. In Domain Fronting, the TLS SNI (Server Name Indication) field shows a legit front domain (e.g., [allowed.example)](http://www.google.com)/), but the Host header in the HTTP request is actually pointing to the C2 server (forbidden.example). 

<p align="center">
  <img src="https://github.com/user-attachments/assets/b248018d-2a61-4117-91a9-b95d9289d135" alt="image">
</p>


Whereas with a C2 Redirector, the attacker controls the intermediary step and redirects the traffic onward to the C2 server.

**What about Domain Hiding?**

Domain Fronting is still a viable technique today, but there's much less availability on the provider side to make it happen.  In April 2018, [Google and Amazon blocked the capability](https://www.bleepingcomputer.com/news/cloud/amazon-follows-google-in-banning-domain-fronting/), though you'll still find some providers out there where it is [still viable](https://blog.compass-security.com/2025/03/bypassing-web-filters-part-3-domain-fronting/).  A twist on the technique, however, is Domain Hiding, as coined by [Erik Huntstad in a DEFCON 28 talk](https://github.com/SixGenInc/Noctilucent).  Domain Hiding uses the quirks of TLS 1.3 to place essentially dummy values in the HTTPS connection's plaintext fields that show up in logs, but the connection's encrypted fields contain the actual connection information.


<div style="text-align: center;">
  <table style="border-collapse: collapse; margin: auto; width: 100%;">
    <tbody>
      <tr>
        <td style="border: 1px solid #ccc; padding: 8px;">TLSHost — microsoft.com (plaintext/visible)</td>
      </tr>
      <tr>
        <td style="border: 1px solid #ccc; padding: 8px;">SNI — microsoft.com (plaintext/visible)</td>
      </tr>
      <tr>
        <td style="border: 1px solid #ccc; padding: 8px;">HTTP Host header — badguyc2.com (encrypted/not visible)</td>
      </tr>
      <tr>
        <td style="border: 1px solid #ccc; padding: 8px;">ESNI — badguyc2.com (encrypted/not visible)</td>
      </tr>
    </tbody>
  </table>
</div>
<br />

So again, packet trickery rather than wholesale traffic redirection.  In [Huntstad's use-case](https://youtu.be/TDg092qe50g), this requires DNS record management via Cloudflare in order for it to work, but the actual C2 servers can obviously be hosted anywhere.

**What about Telegram or Discord C2?**

Unrelated!  But also kind of not!  Using an instant messenger's API capability can be utilized as a Domain Fronting technique, but it can also be used as a simple C2 mechanism in itself.  This is where the term conflation can start to get confusing.  If we use [MITRE ATT&CK](https://attack.mitre.org/), we might break it down this way:


<table style="border-collapse: collapse; width: 100%;">
  <thead>
    <tr>
      <th style="border: 1px solid #ccc; padding: 8px;">ID</th>
      <th style="border: 1px solid #ccc; padding: 8px;">Subtechnique</th>
      <th style="border: 1px solid #ccc; padding: 8px;">Name</th>
      <th style="border: 1px solid #ccc; padding: 8px;">What we’ve discussed</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="border: 1px solid #ccc; padding: 8px;">T1090 - Proxy</td>
      <td style="border: 1px solid #ccc; padding: 8px;">T1090.002</td>
      <td style="border: 1px solid #ccc; padding: 8px;">External Proxy</td>
      <td style="border: 1px solid #ccc; padding: 8px;">C2 Redirector</td>
    </tr>
    <tr>
      <td style="border: 1px solid #ccc; padding: 8px;">T1090 - Proxy</td>
      <td style="border: 1px solid #ccc; padding: 8px;">T1090.004</td>
      <td style="border: 1px solid #ccc; padding: 8px;">Domain Fronting</td>
      <td style="border: 1px solid #ccc; padding: 8px;">Domain Fronting<br /><br />Domain Hiding (?)</td>
    </tr>
    <tr>
      <td style="border: 1px solid #ccc; padding: 8px;">T1102 - Web Service</td>
      <td style="border: 1px solid #ccc; padding: 8px;">T1102.002</td>
      <td style="border: 1px solid #ccc; padding: 8px;">Bidirectional Communication</td>
      <td style="border: 1px solid #ccc; padding: 8px;">Telegram/Discord C2</td>
    </tr>
  </tbody>
</table>
<br />


But that isn't perfect either.  A C2 Redirector could be considered a mechanism of Bidirectional Communication, just as Telegram/Discord C2 could just be a Domain Fronting technique, depending on configuration.  Domain Hiding doesn't have a specific label, so there isn't really a way to cleanly categorize it -- though it probably fits best as a variation of Domain Fronting considering the packet customization as the method of redirect rather than the wholesale traffic forwarding that occurs in a C2 Redirector.

The conflation could probably be it's own post.. anyway.

**Types of C2 Redirectors**

Let's talk about some common ways to set up and use a C2 Redirector.  Much of this has been individually better covered elsewhere, so I'll link to those posts from better authors and give a more high level summary of each, as well as cut to the chase regarding what those domains may look like for hunting.  This is not all-encompassing and there are other clever ways to do this, but this allows us to look at some of the larger solutions that are probably more likely to be seen at scale.  This will set us up to craft some querying and searches that lean on C2's general dependence on persistence and periodicity (even if obfuscated) to drill down on some suspect traffic.

***Azure FrontDoor CDN***

My hypothetical above was Azure so we might as well start with Azure.  I really like the [write-up from r3d-buck3t](https://medium.com/r3d-buck3t/red-teaming-in-cloud-leverage-azure-frontdoor-cdn-for-c2-redirectors-79dd9ca98178) that explains this use-case better than I could.  In short, this is essentially accomplished via enabling Microsoft.CDN Provider and then configuring some VM firewalls... and it can be done within a free Azure trial.  This method also allows for creation of azurefd subdomains for further obfuscation, though directing this through Azure FrontDoor but with a custom domain is doable as well.  In short, it's relatively easy, simple, and uses Microsoft infrastructure.

Azure FrontDoor has long been a favorite among adversaries looking to blend malicious traffic into the background hum of enterprise cloud chatter. It's fast, flexible, and (perhaps most importantly) carries Microsoft's implied legitimacy in the eyes of most firewall and proxy logs. Attackers tend to spin up temporary custom subdomains within the AzureFD namespace, attach them to a Front Door instance, and configure that instance to forward traffic onto a backend C2 server. What makes this effective isn't just the hiding in plain sight aspect, it's also the caching, routing, and WAF capabilities that, when misused, can obscure fingerprinting or mislead defenders into thinking traffic is heading to a benign cloud workload.

<p align="center">
  <img src="https://github.com/user-attachments/assets/6a9adf73-4eb8-4e6c-8fad-ebc00efcca53" alt="image">
</p>


What's notable from a detection perspective is that most AzureFD URLs follow a somewhat predictable naming structure, often ending in .azurefd.net or .trafficmanager.net, and typically resolve to Azure's IP space. Obviously, part of it's allure as a viable C2 Redirector is that legitimate orgs use these same domains too. That said, the key isn't in the domain itself, but in the context: are you seeing regular beaconing to a random Azure subdomain that doesn't appear anywhere in your inventory or vendor list? Is that domain relatively new, with a high connection frequency but a low volume of data transfer? These are small flags, but they can be used to bubble up interesting leads.

***Cloudflare Workers***

Things will start looking similar very quickly now, as each of these solutions basically offer the same perks -- free or low cost traffic redirection and the trust level of an otherwise legitimate domain.  [Alfie Champion's post here](https://ajpc500.github.io/c2/Using-CloudFlare-Workers-as-Redirectors/) describes the use-case utilizing Cloudflare's workers.dev domain to essentially accomplish the same thing.

Cloudflare Workers offer another compelling redirector option, largely because they allow an attacker to effectively write and deploy lightweight JavaScript that handles traffic directly at the edge. In this case, the attacker sets up a Worker that listens on a Cloudflare-served domain and proxies or forwards traffic to the real C2 server. Unlike traditional redirectors which might rely on simple HTTP forwarding or 302s, Workers can inspect, modify, and reshape the request before passing it along---or even embed a full client-side logic to perform decision-based redirection.

<p align="center">
  <img src="https://github.com/user-attachments/assets/2c5b9a00-674b-4def-a4e6-6c044f55fdf9" alt="image">
</p>


From a defender's viewpoint, this one's especially annoying. The TLS cert is legit. The domain is served from Cloudflare's anycast edge nodes. And because Workers run serverless, there's no traditional infrastructure to enumerate or scan. That said, hunting still isn't impossible. Workers-based redirectors tend to be high-frequency but low-volume---think regular check-ins with little payload. They may also show up as subdomains with no public presence, no SPF/DKIM records, and no backlinks. DNS over time and connection frequency analysis can help here, as can paying close attention to HTTP headers that deviate slightly from the norm (e.g., odd user-agents, no referrers, or uncommon methods).

***AWS Lambda***

AWS Lambda redirectors usually come in two flavors: either they're behind an API Gateway or served directly through custom domain integration. In both cases, the concept is the same: requests hit the Lambda endpoint, which executes a small chunk of code that does some quick logic and then passes the connection on to the C2 server. These setups are particularly attractive to red teams because they can spin up infrastructure only when needed, keeping logs minimal and reducing the infrastructure's overall fingerprint.  [Adam Chester has a great writeup here](https://blog.xpnsec.com/aws-lambda-redirector/).

<p align="center">
  <img src="https://github.com/user-attachments/assets/47a45f2d-66c4-4ec4-9277-b50796d5294f" alt="image">
</p>


From the blue team's angle, Lambda-based redirectors can often look like strange spikes of activity to AWS API endpoints that don't seem to correspond to any deployed application internally. If your organization doesn't use Lambda or API Gateway, this is easier to spot---but for those that do, anomaly detection gets harder. One thing to watch for: Lambda endpoints tend to follow region-specific URL structures (<random>.execute-api.<region>.amazonaws.com). If you're seeing beacon-style traffic to these, it might be worth checking if the endpoint corresponds to an actual internal function or someone else's Lambda quietly relaying commands.

***Google Cloud***

Google Cloud Platform (GCP) options for redirectors are a bit more varied---App Engine, Cloud Run, Firebase Hosting, or even simple Google Sites pages have all been seen in the wild as makeshift redirectors. The flexibility and generous free tiers make these appealing for low-cost and high-durability redirection. App Engine and Cloud Run, in particular, can host small services that behave just like a redirector with very little effort, and---just like the other cloud providers---come with the bonus of Google's implied trust.  [CTFIOT has a writeup here (this is mostly in Chinese fwiw).](https://www.ctfiot.com/108324.html)

Detection here hinges on knowing what Google-hosted services are in use internally. If you're not using Firebase or App Engine, and yet you see persistent connections to *.appspot.com, *.cloudfunctions.net or *.firebaseapp.com, that's something to investigate. Google's infrastructure also shares IPs across tenants, making passive DNS tracking less useful. Instead, defenders can lean on behavioral analysis: is this domain newly registered? Has it changed its hosting recently? Does the traffic have unusual timing patterns that suggest polling behavior? And again, headers can be revealing if anything looks hand-rolled or stripped down beyond typical browser-based use.

***Redirectors in the Wild: The Lesser-Known Services that Show Up in Campaigns***

While enterprise-grade infrastructure like Azure FrontDoor, Cloudflare Workers, or AWS Lambda often get most of the attention when it comes to redirector setups, it's worth noting that there's a whole cottage industry of simpler, more disposable services that see frequent use in red team ops and real-world threat activity alike. These services aren't always designed with redirection in mind---but they can be easily co-opted for it. They're quick to spin up, rarely inspected closely, and often fly under the radar in most orgs' logging posture.

Take **Webhook[.]site**, for instance. It's built to let developers quickly test and capture HTTP requests --- but that same functionality means an actor can point a payload to a webhook endpoint that relays or logs traffic. If the webhook forwards the request or responds in a controlled way, it can serve as a stealthy handoff to a real C2 server. Similar logic applies to **FrgeIO**, which offers temporary API endpoints for demo and development use. These endpoints may appear totally benign to casual inspection and usually aren't included in threat feeds, meaning traffic to them rarely raises alarms unless you're actively hunting for oddities.

**InfinityFree** is another example: a free web hosting platform that, while meant for personal websites and hobby projects, has been abused in several campaigns to stand up basic redirectors, stagers, or payload delivery pages. Because the infrastructure is shared and the domains rotate frequently (e.g., subdomains off epizy.com or rf.gd), defenders often have a hard time tracking or blocking them consistently.

Even services like **Dynu**, originally designed for dynamic DNS management, can be bent into redirector duty. A common trick involves using Dynu to register short-lived subdomains that point to cloud-hosted redirectors, which are then swapped out regularly to rotate infrastructure while keeping DNS records consistent. This level of abstraction can make threat actor infrastructure frustratingly agile---especially for defenders who are relying solely on static domain or IP lists.

Other redirection-friendly platforms include **Mocky**, **Mockbin[.]org**, and **Pipedream** --- all of which cater to developers needing quick HTTP endpoints to test with. These services usually offer minimal validation, few rate limits, and public accessibility by design. That combination makes them perfect for lightweight redirector use in phishing campaigns or post-exploitation communication. And because they serve a legitimate developer function, blocking them outright may break things internally or draw resistance from dev teams.

The throughline with all of these platforms is this: the simpler and more disposable the redirector, the more likely it is to go unnoticed. Many of these services are essentially pre-configured redirect platforms without needing to stand up infrastructure yourself. From a detection standpoint, they exist in a gray area---often hosted on trusted clouds, appearing legitimate at a glance, and unlikely to show up in any IOC feed until long after they've served their purpose. Which is all the more reason they deserve to be on the blue team's radar.

**Hunting the Anomalous: Detection Through Behavior, Not Signature**

When it comes to catching C2 redirectors in the wild, it's important to accept up front that you're rarely going to catch them through traditional signature-based detection. There's no magic domain, IP, or ASN that'll give it away --- especially if the redirector is hosted on a major cloud provider. What *can* tip your hand, though, is behavioral anomaly detection and pattern-of-life analysis. Redirectors still behave like C2: they beacon. They check in regularly. They have a rhythm, even if it's intentionally jittered.

One of the first places an analyst might want to start is with frequency analysis --- how often a host is reaching out to a domain over time. C2 tends to involve repeated, low-volume traffic to a small set of external hosts, usually at regular intervals. Even when jitter is introduced, statistical models can surface those patterns. In Splunk, you might use tstats to baseline DNS or proxy traffic over a 24--72 hour period and calculate the standard deviation of connection intervals. In Elastic, you'd lean into aggregations and visualizations --- using date histograms to bucket communication patterns and identify outliers. Chronicle can be particularly effective here, with its entity-based timeline views and automatic enrichment allowing for quick correlation between destination domains, hosting infrastructure, and behavioral timelines.

**Beaconing Analysis in Practice**

Say you want to hunt for periodic outbound connections that could indicate C2. In Splunk, a simple starting point might look like this:

<pre><code>
| tstats count where index=proxy by _time, src, dest

| timechart span=1m count by dest

| eventstats avg(count) as avg_count, stdev(count) as stdev_count by dest

| eval zscore=(count - avg_count)/stdev_count

| where zscore > 3
</code></pre>

This query gives you a rough idea of destinations that deviate significantly from their own baseline --- possibly indicating C2 beaconing. You can tweak the threshold or focus by domain type (e.g., .cloudfront.net, .azurefd.net) for more targeted results. Similarly, in Elastic's Kibana, you might use scripted fields to compute connection intervals per host and visualize the regularity of outbound requests. The key here isn't volume---it's *repetition* and *consistency*. Even slow beacons stand out when seen over time.

**Contextual Enrichment and Cross-Correlation**

Of course, a domain beaconing every hour isn't *inherently* malicious---maybe it's just a software updater. That's where enrichment comes in. Chronicle's strength lies in its ability to automatically tie domains to WHOIS data, passive DNS, and even third-party threat intel. Splunk and Elastic can get there too with the right integrations (VirusTotal, AbuseIPDB, internal asset inventories). Cross-referencing destinations against known business applications, or labeling internal assets by role (e.g., user laptop vs. internal server) can drastically improve your signal-to-noise ratio. Why is this finance user's laptop beaconing to an AWS Lambda API endpoint in the eu-west-1 region every 90 seconds, when nobody else in finance has ever talked to that service?

Another underrated tactic: look for *low-diversity communication patterns*. Redirectors, by nature, are often one-to-one: a single endpoint beaconing to a single hostname or IP with little deviation. In contrast, legitimate apps usually speak to several subdomains, APIs, or CDNs. A Splunk or Elastic search that identifies hosts with an unusually narrow set of egress destinations over time can help bubble these up.

**Putting It All Together**

At the end of the day, you're not trying to flag all C2 redirectors. You're trying to bubble up *the weird*. That's where statistical models, even simple ones like z-scores or percentiles, can start to work in your favor. No solution is perfect, and every environment has its own background noise---but periodicity, rarity, and low-diversity are telltale traits of redirectors that stand out just enough to be hunted, if you're looking in the right places. The trick is to move away from chasing domains and move toward identifying patterns.

Here's a **Blue Team Cheatsheet** section that consolidates the redirector services I've covered (Azure FrontDoor, Cloudflare Workers, AWS Lambda, Google Cloud, the rest) and frames out how an analyst can start building detection queries in Splunk, Elastic, or Chronicle. It focuses on the *how* and *why*, not just throwing regex at a wall.

<br />
* * * * *
<br />

**C2 Redirector Cheatsheet: Pivot Points and Search Starters**

So what do you actually search for when you suspect redirector use, or when you just want to go hunting? A lot of redirector infrastructure won't show up in traditional threat intel feeds. But the nature of how C2 works means it usually gives itself away in volume, repetition, or timing --- even if the destination is cloud-hosted and the traffic is encrypted. You're not always looking for a smoking gun. Sometimes you're just looking for a slightly warm barrel.

Here are the redirector services we've discussed so far, along with the pivot points you can use in DNS, proxy, or HTTP logs to begin triaging:

**Redirector Domain Indicators:**

-   *.azurefd.net → Azure FrontDoor
-   *.cloudflareworkers.com / workers.dev → Cloudflare Workers
-   *.lambda-url.*.on.aws or execute-api..amazonaws.com → AWS Lambda URLs
-   *.cloudfunctions.net or *.appspot.com → Google Cloud Functions
-   webhook.site → Webhook capture service
-   *.frge.io → FrgeIO redirector endpoints
-   *.epizy.com, *.rf.gd → InfinityFree web hosting
-   *.dynu.com or *.dynu.net → Dynu dynamic DNS
-   api.mocky.io → Mocky HTTP response mocking
-   *.pipedream.net → Pipedream integration endpoints
-   *.mockbin.org → Mockbin response generator

<br />

**Log Sources to Pivot From:**

-   DNS logs: Filter by query or domain fields for the above indicators. Use wildcard matches if supported.
-   Proxy logs: Look at url, referrer, and user-agent fields. Atypical user-agents making repeated requests to these domains can signal abuse.
-   HTTP logs (Chronicle, Zeek, etc.): Look for repeated POST or GET traffic to these hosts, especially with unusual URI paths or consistent beaconing intervals.

<br />
<br />

**Sample Splunk Query:**

<pre><code>
index=proxy OR index=dns

(domain IN ("*.azurefd.net", "*.cloudflareworkers.com", "*.lambda-url.*.on.aws", "*.cloudfunctions.net", "webhook.site", "*.frge.io", "*.epizy.com", "*.rf.gd", "*.dynu.com", "api.mocky.io", "*.pipedream.net", "*.mockbin.org"))

| stats count by src_ip, domain, uri_path, user_agent

| where count > 5
</code></pre>

This gives you a frequency snapshot --- how many times a given IP hit one of these services, with what paths and user-agents. Adjust the threshold (count > 5) depending on your baseline.

**Elastic (Lucene) Query Equivalent:**

<pre><code>
domain:(*.azurefd.net OR *.cloudflareworkers.com OR *.lambda-url.*.on.aws OR *.cloudfunctions.net OR webhook.site OR *.frge.io OR *.epizy.com OR *.rf.gd OR *.dynu.com OR api.mocky.io OR *.pipedream.net OR *.mockbin.org)
</code></pre>

From there, you can build visualizations of request frequency, URI patterns, or anomalies in response sizes.

**Google Chronicle YARA-L (for Domain Match):**

<pre><code>
rule Redirector_Domains {

  domain /.*(azurefd\.net|cloudflareworkers\.com|lambda-url.*\.on\.aws|cloudfunctions\.net|webhook\.site|frge\.io|epizy\.com|rf\.gd|dynu\.com|mocky\.io|pipedream\.net|mockbin\.org)/

}
</code></pre>
<br />
**Detection Tips:**

-   Look for **beaconing behavior**: periodic DNS or HTTP requests at regular intervals.
-   Cross-pivot: if you see one endpoint beaconing to multiple redirector services, that's often a stronger signal of post-exploitation traffic.
-   Inspect **JA3 or JA3S fingerprints** (if available): adversaries often reuse similar TLS profiles when standing up redirectors.
-   Apply a **known-good allowlist**: filter out known legitimate internal or dev use of services like Pipedream or Mocky so you're not chasing dev noise.

<br />

Keep in mind --- this doesn't catch everything, and by the time you're seeing redirector traffic, the initial foothold may have already been gained. But it gives you a lens into C2 staging activity, and more importantly, it gives you a chance to force attackers into noisier, more detectable infrastructure if they're forced to rotate off these services.
