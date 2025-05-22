---
layout: post
title: "C2 Redirector Usage and You"
date: 2025-01-12
tagline: "A Blue Teamer's Guide to Obfuscated Command & Control"
image: /IMG/011225.jpg
tags: [Cobalt Strike, Infrastructure Tracking, Threat Intelligence]
---

I’m a fan of chasing down C2 for whatever reason, probably comes from my PCAP-exclusive analyst roots (ah, the pre-SSL everywhere days).  That understandably has gotten increasingly harder to do, and not only because of the embrace of SSL (which, to be clear, is a *good thing*), but because of all the various obfuscation quirks that make red teaming easier and blue teaming harder.  One of those quirks I tend to find more interesting is the usage of C2 redirectors, where C2 traffic is essentially “laundered” through a legitimate-looking server or cloud as a means of hiding origin, providing an air of legitimacy to what is likely high-frequency traffic, etc.  I say this, yet even in the year 2024 this technique has came and went in favor of keeping things simple with OAuth in the cloud rather than bothering with on-prem at all.  While that’s certainly here to stay, I suspect C2 redirector usage will similarly be a long-term base-level of OPSEC for offense forever.
<br>
Maybe I’m just reading the wrong blogs, but I’ve noticed that everything on this topic seems to be written from the red team’s perspective.  This makes sense – there isn’t *really* a great way to detect these on the blue team side – at least no way that I’m aware of currently.  Another thing I’ve noticed is that there doesn’t seem to be any definitive blue team resource for all the different ways this could happen, nor any resource that clearly defines the various sub-terms or correlated techniques that tend to get conflated (and oh boy, do we love to conflate our terms).  Is a C2 Redirector actually just Domain Fronting? Is Domain Fronting even still a thing? Is Domain Hiding the new Domain Fronting? Which one of those things is C2 over Telegram?
<br>
So to kick this blog off, I thought I’d try and provide a definitive guide for C2 Redirection as a technique and try to package up the most easily understandable (and as a result, probably most utilized) mechanisms for redirecting C2.  I’ll define those other related terms without getting too into the weeds on each, and we’ll see if we can’t find a detection technique or two in the process.
<br>
# First Things First: What is a C2 Redirector?
