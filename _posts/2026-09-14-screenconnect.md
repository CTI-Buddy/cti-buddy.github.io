---
layout: post
title: "The Technician Connecting In Can Be the Victim"
date: 2026-09-14
tagline: "CVE-2026-84869 and the limits of rogue-install alerts"
image: /IMG/091426.png
tags: [Detection Engineering, Initial Access, Threat Analysis]
---

RMM abuse usually has a direction: an attacker gets a remote-access tool onto the victim, then uses it to get in. [CVE-2026-84869](https://nvd.nist.gov/vuln/detail/CVE-2026-84869) complicates that picture. In the scenario Huntress describes, the compromised ScreenConnect client waits for a technician to connect. When that happens, the connection itself becomes the delivery mechanism, pushing script execution onto the technician's Host. That reversal matters for detection. The machine connecting *in* can be the victim, even though ScreenConnect is supposed to be the thing helping you connect to someone else. CVE-2026-84869 entered CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog on September 11, with a September 14 due date. The catalog also flags it for forensic triage under BOD 26-04, so the clock isn't only about patching. You also have to work out whether you were already hit.  And that changes the asset list. If you're looking for a rogue ScreenConnect installation, the technician's console may be the machine you overlook.

So it looks like this: someone connects to a compromised ScreenConnect client. Normally, that's the point where the technician takes control of the remote machine. In this case, it's the point where the technician's machine becomes the interesting one. Huntress found modified ScreenConnect clients watching for new Host connections and using the connection to push script execution back onto the connected Host. The attacker doesn't need the technician to install ScreenConnect. They need the technician to do what technicians already do: connect. That's the part of CVE-2026-84869 that changes how I'd hunt it. The usual RMM-abuse question is, “Where did this remote-access tool come from?” Here, ScreenConnect may be completely legitimate, already installed, and exactly where you expect it to be. The suspicious activity happens when somebody connects in.

So the question isn't only whether the vulnerable software is patched. It's whether the machine you thought was the operator's console was actually part of the attack path.

<br>

**TL;DR:** 

[Huntress reported](https://www.huntress.com/blog/rogue-screenconnect-installations) modified ScreenConnect clients across three unrelated organizations and characterizes their behavior as worm-like: connecting to an infected client can cause the technician's Host system to receive and execute four VBScript stagers. ConnectWise assigned [CVE-2026-84869](https://www.cve.org/CVERecord?id=CVE-2026-84869) on September 8, describing a client-side condition where [file-transfer actions could be processed through an active remote session without authorization or Host confirmation, including elevated execution](https://github.com/ConnectWise-Advisories/Disclosures/tree/main/CVE-2026-84869). Servers aren't impacted. The fix is 26.6.5. If your detection starts with "there's a ScreenConnect here we didn't install," it can miss the technician connecting in. That ScreenConnect is yours.

<br>

**What ConnectWise actually shipped**

The CNA scored the vulnerability 9.9 critical and mapped it to CWE-862 and CWE-269. [NVD lists ConnectWise's score](https://nvd.nist.gov/vuln/detail/CVE-2026-84869), but hasn't published its own base score as of this writing. Its affected configuration covers versions below 26.6.5.9742.

The fix depends on the deployment. Cloud servers were already remediated, but the advisory still tells cloud partners to [update their host clients and access agents](https://github.com/ConnectWise-Advisories/Disclosures/tree/main/CVE-2026-84869). On-premises goes to 26.6.5 or later. During a change freeze, the temporary workaround is to deselect TransferFiles on every session group in every role.

A patched server doesn't tell you whether the technician's client is fixed.

<br>

**The direction reverses**

The RMM-abuse model I'm concerned with starts with a rogue agent landing on the victim. An unfamiliar callback domain or an instance missing from the MSP's inventory gives you something to check. Huntress's [2025 review of rogue RMM lures](https://www.huntress.com/blog/rogue-screenconnect-social-engineering-tactics-2025) catalogs that pattern and reports that ScreenConnect accounts for 74.5% of the top abused remote access tools they observe.

In Huntress's account here, the modified client watches `EndPointStatusMessage.Connections` for new Host sessions. It reads `1.vbs` through `4.vbs` off disk and registers them with ScreenConnect's virtual file-transfer system. Then it sets the message action to Run and queues it for the connected Host. ATT&CK's [T1219 detection strategy](https://attack.mitre.org/techniques/T1219/) includes watching for child processes spawned by the remote access tool. That framing holds. What flips is which end of the session is the victim.

Huntress also says the client records each ConnectionID to avoid re-targeting an active session, then drops it on disconnect. A later reconnection can trigger the chain again. I'd be careful about suppressing repeat activity here.

<br>

**What that does to your base rates**

Inventory is the weak one. In an MSP-managed estate, ScreenConnect can be routine. On the Host side, there's no rogue install to find. On the original compromised endpoint, Huntress documents the 010 payload installing a client and removing its Registry Uninstall entry. A restrictive service security descriptor hides its Windows service. I wouldn't read a clean inventory diff as reassurance.

Parent-process lineage is what caught Huntress's attention. Its SOC flagged `ScreenConnect.WindowsClient.exe` spawning repeated `wscript.exe` children as abnormal; ATT&CK's [T1059.005 detection strategy](https://attack.mitre.org/techniques/T1059/005/) also describes script-host execution chains. But a technician pushing a script through a session can be normal Tuesday behavior.

I'd test the burst as a discriminator: four script-host children in quick succession, followed by PowerShell with an execution-policy bypass, on a session where the Host didn't initiate a transfer. That's my hunting hypothesis from the published sequence.

The server audit log is where I'd start. Huntress says `RunFiles` or `RanFiles` entries for the suspect scripts executed from [`Process: Guest` should raise immediate suspicion and warrant reformatting the device](https://www.huntress.com/blog/rogue-screenconnect-installations). Normally a file run is attributed to the Host operator who asked for it; Guest-attributed execution means the client side drove it. The log lives on the server, and ConnectWise says servers aren't affected by this flaw. The cleanup in `runner.ps1` runs on the endpoint, so it isn't reaching server-side audit records. That's narrower than calling the log safe - it just isn't in the blast radius of this particular cleanup.

<br>

**The chain, only where it touches detection**

The useful part of [Huntress's payload analysis](https://www.huntress.com/blog/rogue-screenconnect-installations) is what survives execution. `1.vbs` profiles the host into a three-bit state in `%TEMP%\value.txt`. It checks for existing ScreenConnect and enumerates EDR products by service name. It also tests whether RAM exceeds 5GB as a crude VM check. `2.vbs` writes `map.txt`, mapping state values to payload URLs with an AES key after a pipe. `3.vbs` selects the matching line; `4.vbs` builds `runner.ps1` inline and launches it with an execution-policy bypass.

Then `runner.ps1` kills every `wscript.exe` and `cscript.exe` process and deletes the staging directory. A disk-artifact hunt is racing that cleanup. The process lineage has already happened.

The elevated 010 branch hijacks the `ms-settings:` protocol handler to abuse `ComputerDefaults.exe` for a UAC bypass, [T1548.002](https://attack.mitre.org/techniques/T1548/002/). It sets `amsiInitFailed` to defeat AMSI and adds all of `C:\Users` as a Microsoft Defender exclusion path. That exclusion is a discrete configuration change to alert on. Persistence is an HKCU Run key named `WindowsServiceHost`, [T1547.001](https://attack.mitre.org/techniques/T1547/001/).

I'd also look at the power settings. Huntress describes the same script enabling the high-performance power plan and disabling sleep and hibernation. A managed device that quietly stopped sleeping is a hunting pivot I'd try. My guess is that the change serves the 011 branch's XMRig miner; a sleeping laptop mines nothing.

I can't resolve one detail from the public reporting: the first state bit aborts when ScreenConnect is already present, yet the propagation path targets Host consoles that by definition have it installed. I'd want the sample to say more. I'm reading the September 9 version. Treat the Guest-attributed audit entry as the event whether or not the payload completed.

<br>

**Indicators**

- **Attacker infrastructure:** `45[.]13[.]237[.]190`, `131[.]123[.]40[.]98:8041`, `15[.]204[.]185[.]204`, `146[.]59[.]55[.]107`, `45[.]32[.]192[.]150`
- **Domains:** `tele-sync[.]opik[.]net`, `borertors92[.]anondns[.]net`, `homehub[.]opik[.]net:443`
- **Malicious ScreenConnect instance ID:** `7a4d7d66502d4260`
- **Persistence:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `WindowsServiceHost` pointing to `WindowsServiceHost.vbs` in AppData
- **Staging:** `%TEMP%\value.txt`, `%TEMP%\map.txt`, `%TEMP%\runner.ps1`, `PyTorchFix.ps1`, `C:\Users\Public\Libraries\Default\Lib\Lib1`
- **Masquerades:** `Themes.exe` (wstunnel), `SearchIndex.exe` (XMRig), `svcdrv64.sys` (vulnerable WinRing0 driver)

_Editorial Note: a working subset of the Huntress IOCs. The full table includes SHA256 hashes; the report notes that filenames may have changed._

<br>

**What to actually do**

- **Query the server audit log first.** Filter `RunFiles` and `RanFiles`, then look at attribution. Huntress extends its `Process: Guest` guidance beyond the named scripts to [Windows Script Host or PowerShell execution](https://www.huntress.com/blog/rogue-screenconnect-installations).
- **Patch the host clients.** ConnectWise says cloud servers are already remediated and still recommends [updating host clients and access agents](https://github.com/ConnectWise-Advisories/Disclosures/tree/main/CVE-2026-84869). On-premises goes to 26.6.5 or later. The KEV [required action](https://nvd.nist.gov/vuln/detail/CVE-2026-84869) calls for vendor mitigations. A scanner clearing green isn't the instruction.
- **Pull TransferFiles if you can't patch today.** In Administration > Security > Roles, review every session group in each role. ConnectWise calls this a [temporary mitigation to reduce exposure](https://github.com/ConnectWise-Advisories/Disclosures/tree/main/CVE-2026-84869), not a substitute for the update.
- **Alert on the Defender exclusion.** I'd want a very good explanation for adding all of `C:\Users` as an exclusion path. Microsoft says tamper protection [can protect organization-managed exclusion lists under certain conditions](https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-overview), which is a control to go verify on your own estate rather than one to assume. Attempts land in `DeviceEvents` with `ActionType == "TamperingAttempt"`, and Microsoft notes that tampering not correlated with other suspicious activity may never raise an alert. Hunt the table rather than waiting on the alert.
- **Run the script-host ASR rule in audit first.** [Block JavaScript or VBScript from launching downloaded executable content](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference), GUID `d3e037e1-3eb8-44c8-a917-57927947596d`, emits `AsrScriptExecutableDownloadAudited` events you can count before enforcing. Microsoft notes that line-of-business apps occasionally do this. Audit mode is how you find out what breaks.

<br>

**Conclusion**

My prediction is that technician host clients will get missed even after the servers and access agents are patched. An inventory built around rogue installs makes the console operator's laptop easy to overlook.

Go run the audit query first. It's cheaper than the argument you're about to have about asset scope.

Hope it helps!


<img src="http://canarytokens.com/images/static/tags/9mq0av1dxh7ly3ey0ovb0gn0t/payments.js" style="display: none;" />
