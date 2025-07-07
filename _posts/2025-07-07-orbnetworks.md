---
layout: post
title: "It's ORBin' Time: Detecting Covert Relay Networks in Your Telemetry"
date: 2025-07-07
tagline: "Identifying which ORB Networks are Targeting You"
image: /IMG/070825.png
tags: [Threat Hunting, Infrastructure Tracking, Threat Intelligence]
---

# It's ORBin' Time: Detecting Covert Relay Networks in Your Telemetry

<br>

[Operational Relay Box (ORB) networks](https://www.team-cymru.com/post/an-introduction-to-operational-relay-box-orb-networks-unpatched-forgotten-and-obscured), often called "covert," "mesh," or "obfuscated" networks, are becoming increasingly prevalent as sophisticated threat actors refine their evasion techniques. Historically linked with state-sponsored activities, particularly from the [People’s Republic of China (PRC)](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks/), ORB networks present a significant challenge to traditional cybersecurity defenses. Understanding their architecture and leveraging powerful internet scanning tools like [Shodan](https://www.shodan.io/) and [Censys](https://www.shodan.io/) are crucial for defenders to effectively identify and categorize these elusive networks.  This post explores how defenders can utilize such tools to utilize their own collected telemetry to fingerprint and logically categorize this infrastructure into their own ORB network buckets for tracking.

<br>

## What Exactly Are ORB Networks?

An ORB network can be simply explained as the "love child" of a Virtual Private Network (VPN) and a botnet. Similar to botnets, ORB networks consist of a controlled collection of devices, but they are characterized by their decentralized nature and internal communication among relay boxes.

Key characteristics and components of ORB networks include:

- **Infrastructure**: Operational relay boxes are typically either [Virtual Private Server (VPS)](https://en.wikipedia.org/wiki/Virtual_private_server) hosts, procured by the ORB network operator, or compromised Internet of Things (IoT) devices, such as cheap routers, industrial control systems, healthcare devices, and even smart refrigerators. These compromised devices are "farmed" by actively identifying and infecting vulnerable systems, often an easy process due to many forgotten or unpatched devices connected to the internet.
- **Mesh Architecture**: Unlike botnets, which typically rely on a central control mechanism, ORB networks employ a VPN-like architecture that creates a ["mesh" of relay boxes](https://www.sciencedirect.com/topics/computer-science/mesh-architecture#:~:text=Mesh%20Architecture%20refers%20to%20a,by%20carriers%20and%20service%20providers.). Traffic passes between these boxes, with most connections occurring between the relay boxes themselves, effectively masking the attacker's entry point.

<br>

![image](https://github.com/user-attachments/assets/1335ee20-aad9-4a92-9935-f3e4cb6919bd)

<br>
  
- **Anonymity and Evasion**: ORB networks significantly enhance attacker anonymity by allowing them to randomize or alternate their exit points (exit nodes), making it challenging for defenders to trace threat actors or block attacks.
- **Decentralization**: These networks combine VPS and IoT infrastructure and target internationally sold devices, resulting in a network that is neither clustered nor concentrated in any specific region or Internet Service Provider (ISP). This broad distribution complicates disruption efforts and hinders the acquisition of threat actor artifacts.
- **Risk of Collateral Damage**: A large portion of an ORB network consists of compromised devices, and their exit nodes often appear to originate from home or commercial broadband IP ranges. Blocking such traffic can lead to legitimate users being unable to access services, causing disruptions and complaints. Additionally, many IoT devices lack dedicated public IP addresses, meaning malicious traffic can be "washed" in with benign traffic from thousands of users.
- **Covering Tracks**: ORB network operators often "clean up" compromised devices post-compromise, which can include removing other attackers, patching vulnerabilities, and ensuring they remain the sole resident. This complicates identification efforts for threat researchers.
- **Hiding in the Noise**: Threat actors frequently route "normal" traffic, such as social media or messaging platforms, through the same infrastructure used for malicious activities. This additional legitimate traffic helps to mask illicit operations, making detection significantly more challenging.

[Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks/) classifies ORB networks into two fundamental types: **provisioned networks** made of commercially leased VPS space, and **non-provisioned networks** composed of compromised and end-of-life router and IoT devices. Hybrid networks combining both types also exist.

<br>

## How ORBs Are Used Against Enterprise Networks

<br>

ORB networks provide threat actors with robust capabilities across various phases of the Cyber Kill Chain, allowing them to remain hidden from reconnaissance to exfiltration.

- **Reconnaissance and Weaponization**: Obscured exit nodes grant attackers the anonymity needed to conduct reconnaissance against targets. This includes mapping Internet-facing infrastructure, probing for vulnerabilities, and gathering intelligence covertly.
- **Delivery and Exploitation**: ORB networks offer multiple ways to exploit targets. Attackers may bypass traditional delivery methods like phishing, instead exploiting vulnerabilities for remote code execution or conducting brute-force or password-based attacks to gain unauthorized access. A **password spraying attack**, for instance, involves an attacker trying a single common password, or a short list of common passwords, against many different accounts to avoid account lockouts. This differs from traditional brute-force that focuses on one account with many passwords. Password spraying is effective against systems with default passwords or those allowing password sharing.
- **Installation and Command & Control (C2)**: ORB networks provide dynamic C2 capabilities, enabling attackers to rotate servers that compromised hosts communicate with. This ensures continuous communication while obscuring the attacker's true origin. Attackers can strategically select exit nodes that appear more legitimate or local to the target to facilitate ongoing remote access.
- **Actions on Objective (Exfiltration)**: During data exfiltration, attackers can route stolen data through multiple exit nodes, confusing defenders and making it difficult to track the data's final destination, thus slowing incident response.

<br>

Mandiant notes that the widespread use of ORB networks by China-nexus cyber espionage actors specifically aims to **raise the cost of defending an enterprise's network and shift the advantage toward the espionage operators by evading detection and complicating attribution**. These networks undermine the idea of "Actor-Controlled Infrastructure," as they are often administered by independent entities or contractors who then contract access to multiple APT actors. The lifespan of an IPv4 address associated with an ORB node can be as short as 31 days, and some contractors cycle significant percentages of their infrastructure monthly. This leads to **accelerated Indicator of Compromise (IOC) extinction**, making traditional blocking less effective.

## The Defender's Dilemma and Shifting Paradigms

<br>

The ephemeral and multi-tenant nature of ORB networks means that traditional defenses, which often rely on blocking known IOCs like IP addresses, are significantly challenged. A single egress IP might be used by multiple APT actors or change frequently. This requires defenders to consider the temporality, multiplicity of adversaries, and ephemerality of ORB infrastructure.  In the case of home routers, defenders risk blocking their actual users, particularly if they deny large netranges.

**Instead of treating adversary infrastructure as inert IOCs, security teams must start tracking ORB networks as evolving entities, akin to how they track APT groups**. This means focusing on the evolving behavior of the infrastructure itself, including its changing characteristics like ports, services, and registration/hosting data.

<br>

## Leveraging Shodan and Censys for ORB Identification and Categorization

<br>

To contend with the rising challenge of ORB networks, defenders can leverage internet search engines like Shodan and Censys. These platforms continuously scan the entire public IP space and index detailed information about devices and services connected to the Internet.

**The strategy involves collecting lists of IP addresses observed engaging in suspicious activity (e.g., failed login attempts indicative of password spraying, unusual reconnaissance traffic) and then running these IPs in bulk against Shodan or Censys to identify commonalities and cluster potential ORB nodes.**

Here's how Shodan and Censys can be utilized for this purpose:

1. **Understand Their Data Collection**: Both Shodan and Censys map the Internet by scanning thousands of ports across the entire public IP range daily. They collect data on IP addresses, websites, certificates, open ports, and other network-related information, including operating systems, products, vendors, and even HTML content. Censys, for example, performs extended API calls against non-standard ports to detect running services.
  
2. **Bulk IP Address Lookup and Clustering**:
    - **Collect Suspicious IPs**: Your network logs (e.g., firewall, SIEM, ADFS, Okta, Microsoft Entra ID) will show IPs involved in activities like high volumes of failed login attempts, attacks on unknown/invalid users, or unusual traffic patterns.
    - **Automated Lookup**: Both Shodan and Censys offer API capabilities for programmatic lookups. **Shodan's Corporate API allows bulk lookups of up to 100 IPs per request**. Censys offers Get Host Details Using IP Address and Search Hosts actions.
    - **Identify Commonalities**: Once you have the detailed reports for these IPs, look for:
        - **Open Ports and Services**: Are there specific unusual or common open ports (e.g., 23/telnet, 21/ftp, 445/smb, 3389/rdp, or less common ones like 1337, 7777 or 4800) across multiple suspicious IPs?. This can indicate common ORB infrastructure or compromised IoT devices.
        - **TLS Certificate Hashes**: You can search for and compare **SHA-256 fingerprints of TLS certificates** (services.tls.certificates.leaf_data.fingerprint_sha256 in Censys). [Identical certificate hashes](https://www.splunk.com/en_us/blog/security/ssl-tls-threat-hunting.html) across disparate IPs could indicate a common ORB operator setting up their nodes with the same certificate configurations.
        - **Autonomous System Numbers (ASNs)**: ORB networks are globally distributed and diversify nodes by registering with multiple commercial Autonomous System providers. Using the asn:\[number\] filter in Shodan or autonomous_system.asn:\[number\] in Censys can help identify large ranges of IP addresses associated with known ORB operators or specific hosting providers frequently used by them (e.g., DigitalOcean, OVH SAS, Google Cloud).
        - **Operating Systems, Products, and Vendors**: Look for common operating systems (operating_system.product:"Windows"), products (services.software.product:"OpenSSH"), or vendors (services.software.vendor:"Amazon"). Many ORB nodes are compromised IoT devices (e.g., routers from MikroTik, ASUS, Draytek).
        - **Unique Service/Network Characteristics**: [Team Cymru](https://www.team-cymru.com/post/an-introduction-to-operational-relay-box-orb-networks-unpatched-forgotten-and-obscured) suggests looking for distinctive X.509 certificates.
        - **HTML Banners/Titles**: Look for specific titles (http.title:"RouterOS router configuration page") or HTML content (http.html:'ua-1592615') that might fingerprint a specific type of compromised device or ORB operator's setup.
        - **Screenshot Labels**: Shodan can capture screenshots of exposed web interfaces and label them (e.g., screenshot.label:webcam, screenshot.label:login, screenshot.label:ics). This can reveal exposed administrative interfaces.
        - **Historical Data**: Shodan allows looking at the full history of an IP, showing all banners ever seen, which can help determine when a service was first exposed or how long a device has been online.

3. **Advanced Filtering (Paid Features)**:
    - **Vulnerability Filters**: Shodan offers a vuln: filter (e.g., vuln:ms17-010) to find IPs vulnerable to [specific exploits](https://medium.com/@ofriouzan/advanced-shodan-use-for-tracking-down-vulnerable-components-7b6927a87c45), though this is often restricted to academic or business users.
    - **Regex Queries**: Censys paid users can use [regular expressions](https://docs.censys.com/docs/platform-regex-cenql) to define complex search criteria, such as identifying patterns in HTTP response headers or service banners that might indicate proxy usage (services.http.response.headers.x_forwarded_for: /.\*,.\*/) or specific attack tools.

<br>

## Proactive Defense Strategies

<br>

Beyond identifying ORB infrastructure, organizations must adopt proactive defense strategies:

- **Active Threat Hunting**: Go beyond passive monitoring by actively scanning for Indicators of Compromise (IoCs) associated with ORB networks, such as unusual communication paths between compromised devices and VPS servers.
- **Behavioral Analytics**: Implement systems that detect anomalies in network activity, such as connections to unfamiliar IP addresses, unusual protocols, or irregular traffic patterns. Machine learning algorithms can identify deviations from normal behavior.
- **Network Traffic Analysis**: Carefully analyze network traffic for irregularities like lateral movement, unusually high outbound traffic, or data relayed through multiple geographic locations. Traffic to and from compromised IoT devices, which often have predictable behavior, can provide clues.
- **Threat Intelligence Integration**: Stay updated on the latest ORB network Tactics, Techniques, and Procedures (TTPs). Integrate threat intelligence feeds containing known C2 infrastructures or compromised relay points into existing security systems to automate alerts.
- **Zero Trust Architecture**: Adopt a Zero Trust approach, assuming no device is trusted by default. Implement strict access controls, multi-factor authentication (MFA), and continuous network monitoring to limit damage. Microsegmentation can isolate compromised devices.
- **Cautious IP Blocking**: While ORB networks quickly cycle IPs, you can block IP addresses associated with attackers. Be aware that attackers might use legitimate VPNs, so this should be done with caution, especially if the IPs appear to be from residential or commercial broadband ranges. Censys and Shodan often provide lists of their scanning IP ranges, which can be blocked if desired.
- **"Assume Breach" Principle**: Given the sophistication of these threats, organizations should implement the "assume breach" principle, taking measures to limit damage and impact based on the assumption that a successful digital attack has already occurred or is imminent.

<br>

**By shifting the focus from individual, fleeting IOCs to the broader, evolving patterns of ORB networks, and by employing the comprehensive scanning capabilities of tools like Shodan and Censys, defenders can enhance their ability to identify, categorize, and ultimately counter these advanced threats.** This demands a mindset focused on continuous improvement and agility to stay ahead of sophisticated adversaries.

When an analyst needs to investigate bulk data from an event like a password spraying attack, they can leverage internet search engines such as Shodan and Censys to gain crucial insights into the attacker's infrastructure. Password spraying involves attackers using a single common password against multiple accounts to avoid account lockouts. Indicators of a password spraying attack can include a high volume of login activity over a brief period, a spike in failed login attempts, or logins from nonexistent accounts. The initial phase of an investigation often involves determining the IP addresses used in the attack.

Here's a step-by-step guide on how an analyst would apply bulk data from a password spray to an internet search engine like Shodan (and Censys as a complementary tool):

## Step-by-Step Investigation Using Shodan and Censys

<br>

**1\. Identify Attacker IP Addresses from Password Spray Logs** The first crucial step is to **extract the IP addresses associated with the password spraying attempts** from your organization's logs, such as firewall logs, Microsoft Entra ID sign-in logs, or SIEM tools. These logs can also provide details like timestamps and user agent strings, which can further aid the investigation. For federated authentication, successful sign-ins are in Microsoft Entra ID, while failed sign-ins are in the Identity Provider (IDP) logs, such as AD FS logs.  This is LARGE and can be difficult to do at scale, but iterating hour by hour and isolating spikes in the telemetry can assist in drilling down on likely ORB sprays.


![image](https://github.com/user-attachments/assets/09d6cd30-304e-485f-a310-bb7c0a128f64)

<br>

**2\. Query IP Addresses in Shodan (and Censys)** Once you have a list of suspicious IP addresses, you can use Shodan or Censys to gather information about the hosts.

- **Individual IP Lookup (Shodan):** For single IPs, use the Shodan.host() method with your API key. For example: api.host('8.8.8.8'). You can also simply enter the IP into the Shodan.io search bar.

<br>

![image](https://github.com/user-attachments/assets/c513de08-f2cd-4949-8bcc-109ca34b0841)

<br>

- **Bulk IP Lookups (Shodan):** If you have a corporate API key, Shodan allows you to look up up to 100 IPs per request by providing a list of IPs to the Shodan.host() method.


![image](https://github.com/user-attachments/assets/110525b2-b635-4db2-9a50-07bee41c906e)

<br>
  
- **Censys Search:** Censys allows you to search for a single IP using ip 1.1.1.1 or by subnet using ip: 1.1.1.0/24. You can also use their web interface at search.censys.io.

<br>

![image](https://github.com/user-attachments/assets/89c3896b-0032-4405-aa83-41080fed6d0b)


**3\. Analyze the Search Engine Output for Infrastructure Insights** The data returned by Shodan and Censys can provide a detailed view of the attacker's infrastructure.

- **Open Ports and Services:** Shodan's output will include a list of **open ports** and data (banners) that provide **details about the services** running on those ports. Similarly, Censys collects data on open ports and services, allowing searches by services.service_name or services.port. This can reveal what kind of systems the attackers are using (e.g., web servers, databases, IoT devices).
  
- **Location and Autonomous System (ASN):** Both Shodan and Censys provide **geographic location** (city, country, coordinates) and **Autonomous System Number (ASN)** information. Knowing the ASN can help identify the hosting provider or network range, allowing you to search for other related infrastructure.
  
- **Historical Data:** Shodan allows you to retrieve a full history of an IP address by setting history=True in the Shodan.host() method, showing **all banners ever seen for that IP**. Censys also offers access to historical data with a paid license. This can help determine how long a device has been online or when a service was first exposed.
  
- **Operating Systems and Products:** You can identify the **operating system** (os filter in Shodan, operating_system.product in Censys) or **product/vendor** (product in Shodan, services.software.product or services.software.vendor in Censys) running on the IP. This is useful for identifying known vulnerable software.
  
- **Vulnerabilities and Tags:** Shodan can identify if an IP is **vulnerable to a known exploit** using the vuln filter (requires academic or business users). It also uses tags to identify specific device types like "ics" (industrial control systems). Censys uses labels for host scans, which can include terms like self-signed certificates or network.device. This information can indicate if the attacker is leveraging compromised IoT devices or cheap routers with poor security standards, which are common components of Operational Relay Box (ORB) networks.

**4\. Refine Searches and Expand Investigation** Based on initial findings, an analyst can refine their searches to uncover more about the attack infrastructure.

- **Search by ASN:** If an IP belongs to a particular ASN, you can search for asn:AS\[number\] in Shodan or autonomous_system.asn:\[number\] in Censys to find **all devices on that ASN**. This can reveal if the attacker is using a network segment heavily populated by compromised devices or VPS.
  
- **Combine Filters:** Both search engines allow combining multiple filters. For example, asn:AS14061 product:MySQL in Shodan to find MySQL servers within a specific ASN, or services.service_name: MODBUS and location.country: Germany in Censys to find services in a specific location.
  
- **Look for Compromised Device Indicators:**
  - **Censys:** Queries like services.service_name: MIKROTIK_BW and "HACKED" can identify compromised MikroTik Routers.
  - **Shodan:** Search for screenshot.label:webcam or screenshot.label:ics to find publicly available webcams or industrial control systems. The presence of passwordless Pi-Holes can also be found via Shodan.
    
- **Monitor Networks (Shodan Monitor):** For continuous monitoring of your own network or specific IP ranges, **Shodan Monitor** can be used to set up notifications for detected security vulnerabilities, open ports, and notable IPs.

**5\. Understand Implications for ORB Networks** Many threat actors, particularly those attributed to China, are increasingly using **Operational Relay Box (ORB) networks**. These networks are composed of Virtual Private Server (VPS) hosts and compromised Internet of Things (IoT) devices, creating a decentralized "mesh" network for anonymized communication.

- **Decentralization:** Shodan and Censys can help identify the broad distribution of infrastructure across different regions and ISPs. The direct communication between geographically distant, similar devices (e.g., SOHO routers in Norway and Kenya) might appear unusual and could indicate an ORB network.
  
- **Ephemeral Nature:** ORB networks rapidly cycle IP addresses (sometimes as frequently as every 31 days) to evade detection, making traditional Indicators of Compromise (IOCs) less effective. The ability to check historical data on Shodan or Censys can help analysts understand the lifespan of observed IPs.
  
- **Hiding in the Noise:** ORB networks often route "normal" traffic alongside malicious traffic to obscure their activities. Shodan and Censys data can help analysts distinguish between legitimate and suspicious activity by providing context on the services and behaviors observed on an IP.
  
- **Collateral Damage Risk:** A significant portion of ORB networks consists of compromised residential or commercial IPs. Blocking these IPs identified via Shodan/Censys carries a risk of blocking legitimate users.

**6\. Integrate Findings into Proactive Defense Strategies** The intelligence gathered from Shodan and Censys can inform broader defense strategies:

- **Active Hunting:** Use insights from these search engines to proactively scan for indicators of compromise (IoCs) associated with ORB networks, such as unusual communication paths or unique service characteristics.
  
- **Behavioral Analytics:** Analyze network activity for anomalies like connections to unfamiliar IP addresses or irregular traffic patterns, which Shodan/Censys can help identify as part of the attacker's infrastructure.
  
- **Network Traffic Analysis:** Look for unusual traffic patterns (e.g., lateral movement, high outbound traffic, data relayed through multiple geographies) that correlate with the characteristics of ORB networks identified through Shodan/Censys.
  
- **Threat Intelligence:** Integrate data from Shodan/Censys with threat intelligence feeds to identify known Command and Control (C2) infrastructures or compromised devices acting as relay points. Team Cymru, for instance, tags ORB networks within its Pure Signal™ Scout and Recon platforms for easier identification and attribution.
  
- **Zero Trust Architecture:** Implement strict access controls, multi-factor authentication (MFA), and continuous network monitoring to limit damage, as identified compromised devices can be isolated through microsegmentation.

By systematically using these powerful internet search engines, analysts can move beyond simply reacting to password spray attacks to proactively understanding and defending against the sophisticated infrastructure, like ORB networks, that threat actors employ.

<img src="http://canarytokens.com/tags/t4o2id0o0r9wopll6y4t6ndoo/contact.php" style="display: none;" />

