---
layout: post
title: "Catching North Koreans & Laptop Farms"
date: 2025-06-02
tagline: "Detection Techniques for Farms on Your Network"
image: /IMG/060225.jpg
tags: [Threat Intelligence, Threat Hunting, Threat Hunting]
---

Since this is the latest hotness these last few months, I thought I'd write up some techniques for detecting laptop farms, commonly utilized by North Korean tech workers, and what analysts can do to drill down into available data.  This is mostly endpoint based, though there's a few network tricks in here as well that should be able to help.

##Background: North Korea’s Remote Worker Deception##

In recent years, the U.S. government has publicly warned of a quiet but sophisticated campaign by North Korea to infiltrate the global tech workforce—not with malware, but with people. According to joint advisories from the FBI, Department of State, and the Department of the Treasury, the DPRK has deployed thousands of highly skilled IT professionals to work remotely for companies worldwide. Disguised as freelance developers or contractors, these operatives aim to generate revenue for the North Korean regime while gaining access to potentially sensitive technologies and internal corporate systems.

The scheme is both clever and troubling. These remote workers often present forged documents, including fake U.S. passports or stolen identities, to create credible profiles on platforms like LinkedIn, Upwork, and GitHub. Their resumes typically show legitimate-sounding job histories and technical skills—Python development, mobile app engineering, blockchain smart contracts. Many even go as far as staging video calls with manipulated visuals or avatars to mask their real identities. Payment is often laundered through intermediaries, crypto wallets, or foreign bank accounts, making detection especially challenging.

What's particularly insidious is how these individuals embed themselves into the software supply chain. By working for startups and small tech firms—often in roles with elevated privileges—they gain indirect access to larger systems and source code. In some cases, they've attempted to get jobs at cryptocurrency exchanges or fintech companies, likely to feed Pyongyang’s appetite for digital assets used to circumvent international sanctions. The U.S. government estimates that these operations may generate millions of dollars annually, funding everything from weapons programs to surveillance infrastructure.

This campaign differs from traditional cyber intrusion tactics by blending social engineering, fraud, and covert infrastructure. It's not just one individual posing as a freelancer—it’s an entire backend operation involving laptop farms, VPN obfuscation, and remote-control systems like PiKVM to simulate legitimate activity across dozens of devices. The objective isn't simply espionage; it’s financial survival for a regime increasingly isolated from the global economy. And as detection methods evolve, so too does the DPRK’s playbook—making it imperative for defenders to understand not just the actors, but the infrastructure that supports them – and tactics and indicators for discovering them.
