---
layout: post
title: "Hunting VectraRAT With the Telemetry You Actually Have"
date: 2026-10-19
tagline: "The report gives you the artifacts. Your schema decides what you can hunt."
image: /IMG/101926.png
tags: [Threat Hunting, Threat Intel, Threat Analysis]
---

I thought I'd throw out another analysis 101 post after reading up on VectraRAT.  [SOCRadar's report](https://socradar.io/blog/vectrarat-undocumented-stack-maas/) ends with a useful hunting list. The report gives you a mutex, a config file, twelve hashes, and a list of C2 addresses. Let's talk about how you hunt that, where each of those artifacts actually exists in your telemetry, all that good stuff.

Some orgs have documented fields. Some have only partial coverage. Others have no representation in the schemas you're using.

That distinction obviously matters. A malware report describes behavior; your data source determines which parts you can test. An empty query can mean no matching event, a missing collection prerequisite, or an artifact your telemetry cannot represent at all.

So I thought I'd map SOCRadar's reported VectraRAT artifacts to Microsoft Defender advanced hunting fields and Sysmon events, then working through three read-only hunts. The goal isn't to claim coverage I haven't measured. It's to show what each query can establish, what it can't, and how one might write up the difference.

<br>

**What the report says**

[SOCRadar's Threat Research Unit published on September 14, 2026](https://socradar.io/blog/vectrarat-undocumented-stack-maas/), and [Dark Reading relayed the findings on the 15th](https://www.darkreading.com/endpoint-security/vectrarat-hack-windows-enterprises). That's one malware-research lineage. Dark Reading adds outside commentary, but presents no independent examination of the malware. The behavioral findings here are SOCRadar's. I did not run a sample or independently validate its behavior; the work here is public-source comparison and passive infrastructure checks.

The reported architecture pairs a Go control server called VectraHub, with a Vue3 operator panel compiled in, with a native C++ Windows implant. They use a proprietary TCP protocol on port 3308 with a 5-byte header and MessagePack payloads. Rental starts at $250 a month.

Delivery is somebody else's problem. SOCRadar attributes the observed Amadey and ClickFix campaigns, including TurboTax lures, to buyers rather than the developer. It dates its first observation of live infrastructure to June 23, 2026, through an open directory. That is not a collection date for every published indicator: the investigation continued across other infrastructure and samples.

The [69-page report requires a marketing form](https://socradar.io/resources/whitepapers/vectrarat-threat-research-report/) but is worth a read.

<br>

**The hash list has a coverage problem**

The IOC section publishes 12 SHA-256 values. Before pasting them into a hunt, check the destination column.

Microsoft documents `SHA256` and `InitiatingProcessSHA256` as usually unpopulated in [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) and [DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table), with advice to use SHA-1 when available. [DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) has `InitiatingProcessSHA256`, with the same warning; it does not have a file-level `SHA256` column.

You can't derive SHA-1 from SHA-256. Matching across those hash types needs a source that already maps both to the same file, such as an authorized intelligence feed or hash inventory. Nobody needs to fetch live malware to bridge that gap.

Run the lookback over the available SHA-256 fields anyway, but scope it deliberately. A short window alone doesn't guarantee a cheap query. "No match among events with the searched hash field populated" is defensible; "clean" isn't. The file-table documentation also lists reasons a hash may be missing altogether, including remote storage, a lock held by another process, compression, or a file marked virtual.

There's another limit. [SOCRadar describes a builder](https://socradar.io/blog/vectrarat-undocumented-stack-maas/) that patches the C2 address into 256-byte null placeholder blocks and rewrites VERSIONINFO resources from Linux, recalculating the PE checksum. Changing configuration or metadata bytes can change the hash. Identical builds can still be distributed repeatedly, so the published values remain worth checking. They aren't a family signature.

The public list doesn't map individual hashes to sample types or collection dates. Don't assume all 12 are Windows implant files.

<br>

**Which artifacts have a field, and which just have a paragraph**

This compares [SOCRadar's reported artifacts](https://socradar.io/blog/vectrarat-undocumented-stack-maas/) with the three schemas above and [Sysmon's published event list](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). The last column is what stops a plausible query becoming an implausible conclusion.

<img width="1400" height="860" alt="The key pillars of observability" src="https://github.com/user-attachments/assets/9e6d3f0e-c57c-43d9-8f7d-11d62b3a0ac7" />
*Credit to https://medium.com/%40imJenal/observability-deconstructed-a-comparative-study-of-logs-metrics-and-traces-d5bfe34feb8c*

| Reported artifact | Documented field or event | What a hit does not establish |
| --- | --- | --- |
| Seven IP addresses, one delivery domain | `RemoteIP`, `RemoteUrl`, `RemotePort` in DeviceNetworkEvents; Sysmon event 3 | The reported roles include delivery and staging as well as C2. An address match doesn't establish successful communication or infection |
| Default PE metadata: Product and Company `Vectra`, description `Vectra client`, version `0.2` | `ProcessVersionInfoCompanyName`, `ProcessVersionInfoProductName`, `ProcessVersionInfoFileDescription`, `ProcessVersionInfoProductVersion` | Version metadata isn't signing evidence. SOCRadar's builder description also makes these strings operator-editable |
| `callback.json` in the temp directory | `FileName`, `FolderPath`, `ActionType` in DeviceFileEvents; Sysmon event 11, for create or overwrite | A file event doesn't reveal the JSON contents or establish that the implant read it |
| Outbound TCP 3308 | `RemotePort`, `Protocol`, initiating-process columns; Sysmon event 3 | These mapped fields don't establish session duration or concurrency. Repeated events aren't duration measurements |
| `winver.exe` launched and terminated, then `computerdefaults.exe` in the elevation path | Process lineage, `ProcessIntegrityLevel`, `ProcessTokenElevation`; Sysmon events 1 for creation and 5 for termination | This is an optional build branch. The reported final step declares a spoofed parent, so lineage needs corroboration |
| The ntdll debug-object sequence | No dedicated field in these three tables. Sysmon event 10 reports process access | Opening another process isn't comprehensive debug API tracing |
| Mutex `LocalVectra.Client.SingleInstance` | No mutex field in these schemas or mutex event in Sysmon's published list; events 17 and 18 cover named pipes | A negative result through this mapping cannot test the mutex indicator |
| Bursts of reads across `.env`, `.conf`, `.config` | DeviceFileEvents covers file creation, modification, and other file-system events | The page doesn't document general file-read coverage. File events don't establish exfiltration |

_Editorial Note: the source renders the strings as `LocalVectra.Client.SingleInstance` and `%TEMP%callback.json`. The separators are uncertain. I haven't normalized either; the file query below matches only the basename._

"No match in available fields" and "not represented by this mapping" are different results. If Sysmon is your source, the relevant event also needs to be enabled and collected. [The Defender tables require Defender for Endpoint records](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table); a license alone doesn't supply them.

I haven't measured column population in any environment. Actual coverage depends on collection and retained history, not the existence of a schema page. And this mapping says nothing about every other EDR's capabilities.

<br>

**Query one: keep the reported roles attached**

Start with the address lookback, keeping SOCRadar's role labels attached. An Amadey staging address and the reported primary C2 address shouldn't land in the same bucket in the hunt notes. These are historical indicators to check against retention, not a verified current server map.

All three queries below use published fields and have had a manual review. They haven't been compiled or run against a Defender tenant. They're read-only hunt starting points, not validated detections. Check the in-portal schema and your collection before interpreting an empty result.

```kusto
let LookbackWindow = 7d;
let ReportedAddresses =
    datatable(DefangedAddress: string, ReportedRole: string)
    [
        "86[.]109[.]75[.]168", "Primary C2 and panel, exposed directory",
        "86[.]109[.]75[.]161", "ClickFix distribution, resolves reported delivery domain",
        "178[.]16[.]54[.]148", "ClickFix panel serving VectraRAT and NetSupport",
        "195[.]20[.]115[.]77", "Secondary cluster, exposed panel and directory",
        "91[.]219[.]236[.]179", "Related infrastructure reached during pivoting",
        "91[.]92[.]242[.]236", "Amadey panel and VectraRAT staging",
        "195[.]63[.]145[.]106", "Shared TCP 3308 infrastructure with Vidar"
    ]
    | extend RemoteIP = replace_string(DefangedAddress, "[.]", ".");
ReportedAddresses
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(LookbackWindow)
    | where isnotempty(RemoteIP)
    | project Timestamp, DeviceId, DeviceName, NetworkAction = ActionType,
        RemoteIP, RemotePort, Protocol,
        InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessUniqueId
    ) on RemoteIP
| project Timestamp, DeviceName, DeviceId, RemoteIP, ReportedRole, NetworkAction,
    RemotePort, Protocol,
    InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessUniqueId
| top 200 by Timestamp asc
```

`replace_string` refangs the static inputs inside the query; it doesn't contact the addresses. Choose an authorized lookback your retention supports. Seven days is an example, and certainly not a promise of low cost or coverage back to June.

`NetworkAction` preserves `ActionType` in all three examples. [DeviceNetworkEvents covers connections and related events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table), so check your tenant's documented action values for success and direction. A `RemoteIP` hit is an event associated with a published address, not proof of communication or infection.

<br>

**Query two: default metadata plus network activity from the same process**

Version `0.2` on its own is weak. Pairing the reported name strings with that version makes a more useful lead, especially when the same process has network events. That means joining on identity rather than hoping a PID holds still.

[Microsoft defines `ProcessUniqueId` as the Windows Process Start Key](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table); the network table exposes the initiating process's key as `InitiatingProcessUniqueId`. Aliasing the former to the latter and joining with `DeviceId` avoids a PID-only match. Sysmon's `ProcessGUID` serves a similar correlation purpose when Windows reuses PIDs.

```kusto
let LookbackWindow = 7d;
let DefaultMetadataProcesses =
    DeviceProcessEvents
    | where Timestamp > ago(LookbackWindow)
    | where ProcessVersionInfoCompanyName =~ "Vectra"
        or ProcessVersionInfoProductName =~ "Vectra"
        or ProcessVersionInfoFileDescription =~ "Vectra client"
    | where ProcessVersionInfoProductVersion == "0.2"
        or ProcessVersionInfoProductVersion startswith "0.2."
    | where isnotempty(DeviceId) and isnotempty(ProcessUniqueId)
    | project ProcessTimestamp = Timestamp, DeviceId, DeviceName, AccountName,
        FileName, FolderPath, ProcessCommandLine, ProcessIntegrityLevel, ProcessTokenElevation,
        ProcessVersionInfoCompanyName, ProcessVersionInfoProductName,
        ProcessVersionInfoProductVersion, InitiatingProcessUniqueId = ProcessUniqueId;
DefaultMetadataProcesses
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(LookbackWindow)
    | where isnotempty(DeviceId) and isnotempty(InitiatingProcessUniqueId)
    | project NetworkTimestamp = Timestamp, DeviceId, NetworkAction = ActionType,
        RemoteIP, RemotePort, Protocol, InitiatingProcessUniqueId
    ) on DeviceId, InitiatingProcessUniqueId
| where NetworkTimestamp >= ProcessTimestamp
| project ProcessTimestamp, NetworkTimestamp, DeviceId, DeviceName, AccountName,
    FileName, FolderPath, ProcessIntegrityLevel, ProcessTokenElevation,
    ProcessVersionInfoCompanyName, ProcessVersionInfoProductName,
    ProcessVersionInfoProductVersion, NetworkAction, RemoteIP, RemotePort, Protocol,
    InitiatingProcessUniqueId
| top 200 by NetworkTimestamp asc
```

The name filter accepts a match in any one of the company, product or description fields. The separate version filter must also match. It accepts exactly `0.2` or a `0.2.` prefix, a formatting assumption that accommodates a value such as `0.2.0.0` without also taking `0.20`. I haven't observed those variants in data.

The chronology filter requires a network event at or after the retained process event's `Timestamp`. There is no process `ActionType` filter here, so that timestamp isn't necessarily the process's first creation time. The query also requires a matching process row inside the lookback. An older-running process with no such row will be missed.

This query and the next only pair events attributed to the matching process itself. If a child makes the connection, following that needs another hop through process lineage.

Both joins discard empty device or process identities on each side. Count those exclusions when assessing the hunt's inputs, but don't turn excluded-row counts into a percentage of devices covered. That's a different denominator.

<br>

**Query three: a file event, then network activity**

The C2 override is the artifact I find most interesting operationally. [SOCRadar describes the implant's startup check](https://socradar.io/blog/vectrarat-undocumented-stack-maas/) for `callback.json` in `%TEMP%`: if it exists and contains `"callback": true`, the implant takes its C2 address from the file instead of the PE's embedded configuration. In the reported panel-driven flow, an operator requests the change and the override is written on the endpoint. I haven't reproduced that flow.

<img width="1448" height="1086" alt="Same-Process Correlation Explained" src="https://github.com/user-attachments/assets/c42d348b-7d11-47c7-8dda-cf9c5749b6a8" />

That isn't the only possible origin of a file with this name. `callback.json` is generic, and an infected host where the override wasn't used may not have it at all. The query looks for a file event followed by network activity attributed to the same process, without assuming the file was created or its contents used. This is a same-process correlation, and not a claim that the file controls the connection. Specifically, it prioritizes a sequence for investigation. It does *not* establish that the process read the file or used its contents.

```kusto
let LookbackWindow = 7d;
let CorrelationWindow = 10m;
let CallbackFileEvents =
    DeviceFileEvents
    | where Timestamp > ago(LookbackWindow)
    | where FileName =~ "callback.json"
    | where isnotempty(DeviceId) and isnotempty(InitiatingProcessUniqueId)
    | project FileTimestamp = Timestamp, DeviceId, DeviceName, FileAction = ActionType,
        FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath,
        InitiatingProcessCommandLine, InitiatingProcessUniqueId;
CallbackFileEvents
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(LookbackWindow)
    | where isnotempty(DeviceId) and isnotempty(InitiatingProcessUniqueId)
    | project NetworkTimestamp = Timestamp, DeviceId, NetworkAction = ActionType,
        RemoteIP, RemotePort, Protocol, InitiatingProcessUniqueId
    ) on DeviceId, InitiatingProcessUniqueId
| where NetworkTimestamp >= FileTimestamp
| where NetworkTimestamp <= FileTimestamp + CorrelationWindow
| project FileTimestamp, NetworkTimestamp, DeviceId, DeviceName, FileAction, FolderPath,
    InitiatingProcessFileName, InitiatingProcessFolderPath, NetworkAction,
    RemoteIP, RemotePort, Protocol, InitiatingProcessUniqueId
| top 200 by FileTimestamp asc
```

Ten minutes is an analyst's starting window, not a measured property of VectraRAT. Delayed activity from the same process can fall outside it; widen the interval if the investigation calls for it. Widening cannot bridge different process identities across a reboot.

`kind=inner` keeps matching pairs rather than deduplicating left-side keys as the default `innerunique` join would. One process can therefore produce multiple file/network pairs. The retained `FileAction` and `NetworkAction` values let you inspect the event types instead of assuming creation followed by a successful connection.

Nor does the sequence establish a destination change. That needs retained network history for comparison. The file event supplies no JSON contents, so it can't establish configuration use either.

The `top 200` in each example returns at most 200 rows, earliest by its sort column. It limits the displayed result, not the work required by the join or the total matching events. For operational use, narrow the time slices and retrieve all matches before drawing coverage conclusions; don't mistake the cap for a complete handover.

<br>

**The port is context, not a verdict**

TCP 3308 can help prioritize results, but where you apply it matters. SOCRadar reports it as the C2 port; the delivery and staging addresses weren't all claimed to serve C2 there. Filtering the indicator query on 3308 would drop other reported roles.

And a port isn't a family signature. It's a configuration choice. These mapped fields contain no protocol payload, so the reported 5-byte header and MessagePack framing are outside this layer.

If [Sysmon supplies your network events](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), event 3 needs to be enabled and configured. Microsoft's default-install example uses SHA-1 image hashing and no network monitoring. Those are Sysmon's defaults, not a statement about Defender's separate data path. Collection volume depends on the filtering you choose; I haven't measured it. Know what your selected source records before writing "no evidence of C2 activity."

<br>

**What I could not confirm about the infrastructure**

I tried to turn the embedded Vue3 panel into a reusable search fingerprint. The passive checks didn't validate one. They didn't prove that one cannot exist.

On September 18, 2026, InternetDB lookups returned records for all seven published addresses, with none listing TCP 3308. [InternetDB's response schema](https://internetdb.shodan.io/openapi.json) provides no observation timestamp or port history. This describes the returned records, not host liveness or a current C2 map; some addresses have delivery or related roles anyway. No reported host was contacted.

The [saved urlscan.io searches](_pipeline/research_out/vectrarat_passive_checks_2026-09-18.json) found zero VectraHub title matches and zero primary-page IP matches for three reported panel or related seeds, with date bounds of June 1 to September 19, 2026. A separate Nyxel title search returned 12 name matches, none corroborated as VectraRAT infrastructure. The [title and primary-page fields](https://urlscan.io/docs/search/) don't provide complete coverage of resource contacts or panel exposure.

The automated Shodan VectraHub search showed no results, while the filtered storage-key attempt stopped at a login requirement. That's an access restriction, not a zero-match result. I also got no hits in the manual Shodan and Censys follow-up. [Shodan's default search covers collected banner `data`](https://help.shodan.io/the-basics/search-query-fundamentals), so it doesn't necessarily include a separately served JavaScript bundle.

The two Nyxel storage keys in SOCRadar's report remain a possible, untested route. [urlscan's `content.storageNames` field](https://urlscan.io/docs/search/) requires Professional-tier access or higher and indexes storage items set by a page. A string in JavaScript doesn't prove an unauthenticated page sets that item.

No verified TLS certificate, favicon hash or distinctive HTTP asset hash emerged as a seed. The raw protocol remains untested, including whether TLS is used. There is no known certificate here to support a Certificate Transparency pivot. A corroborated panel artifact would be needed before calling this a reusable fingerprint. SOCRadar's ownership inference from a shared /24 and provider remains an inference; these checks don't confirm it.

_Editorial Note: [The September 18 checkpoint](_pipeline/research_out/vectrarat_passive_checks_2026-09-18.json) records the automated requests and outcomes. The manual Shodan and Censys results are author-reported, not independently reproduced; their exact queries weren't captured. All collection described here was passive retrieval of existing third-party records or public documentation._

<br>

**Artifacts**

- IP addresses and reported roles: the defanged datatable in query one
- Delivery domain: `verify-cloud[.]digital`
- Mutex, as rendered in the source: `LocalVectra.Client.SingleInstance`
- C2 override file, as rendered in the source: `%TEMP%callback.json`
- Default stub metadata: Product `Vectra`, Company `Vectra`, description `Vectra client`, version `0.2`
- C2 port: TCP 3308. Panel ports: TCP 8080, 8888. Auxiliary: TCP 4457, 6667
- The 12 SHA-256 values remain in [SOCRadar's IOC section](https://socradar.io/blog/vectrarat-undocumented-stack-maas/), intact and copy-pasteable

<br>

**Working a hit, and writing up a miss**

Start a query-one hit with `NetworkAction` and the address's reported role. Don't treat a failed attempt as proof of communication. On the returned `DeviceId`, review the initiating image and its execution context before treating the address association as family evidence.

For query two, use file evidence already available through your authorized investigation. Editable version strings don't answer the signing question. [The DeviceProcessEvents page's example joins the created process's `SHA1` to certificate information](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table), rather than using the initiating process's signature status as a substitute.

For query three, inspect `FileAction` and `FolderPath`, then any file contents available through that investigation. Compare the process's destinations with retained history. The sequence isn't automatic family confirmation; escalate according to the actual evidence.

If the hunts return nothing, record the queried dates and which fields were populated. Separate a zero-match result from missing collection prerequisites. Different builds can evade these published hashes, and the joins still need usable identity fields and a matching record inside the window. None of that clears the environment.

Leave artifacts not represented by this published mapping as named follow-up work. Missing telemetry is a troubleshooting task, not a reason to dismiss evidence that you do have.


<img src="http://canarytokens.com/about/epl1cn7v5e12j5sxbsge1sopo/index.html" style="display: none;" />
