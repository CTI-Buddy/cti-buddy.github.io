---
layout: post
title: "What a Cobalt Strike Config Match Actually Buys You"
date: 2026-08-24
tagline: "Working a ten-row configuration match into a SOC handover"
image: /IMG/082426.png
tags: [Malware, Threat Intelligence, Threat Analysis]
---

One of the things I like about OSINT is that a useful investigation doesn't have to start with anything particularly sophisticated. Sometimes it's a public dataset, a handful of matching fields, and a question about what those matches really mean. I wanted to put together a small worked example that shows how to turn that kind of observation into something another analyst can reproduce and build on. You don't need a malware sample or access to a commercial threat intelligence platform to do useful infrastructure analysis. Public datasets can support meaningful investigative leads, provided you understand their limitations and keep your conclusions tied to the evidence. This is a small, reproducible example of working through that process with publicly available Cobalt Strike metadata.

Ten rows in a public Cobalt Strike configuration export carry identical values in all fifteen of their exported configuration fields, and they sit on ten different carrier IP addresses.

That gives an analyst a configuration group to investigate. It doesn't establish ten command servers or one operator. Whether it warrants escalation depends on the surrounding evidence, including what happened in the environment you're investigating.

The useful job is to test how far a configuration match extends and turn it into a lead another analyst can check. I worked through that using published metadata, without acquiring a sample or contacting the listed infrastructure. The example is frozen and dated so you can check the arithmetic.

The method is the part that keeps.

<br>

_Editorial Note: the worked example uses two archived, hash-pinned snapshots of a public research feed, taken on 2026-09-10 and 2026-09-18, plus one historical export pinned at the same revision. Those dates are fixed on purpose. No listed host was contacted or resolved; no scanning was performed and no sample was acquired._

<br>

**Freeze the data before you touch it**

<img width="899" height="677" alt="C2IntelFeeds - Know it and Use it" src="https://github.com/user-attachments/assets/931b8dcd-8704-4924-bea1-a1b5f04d8d91" />

The source is [drb-ra/C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds/tree/0a50c31c9bb016d66355ddc8bb14958f1f196f49/C2_configs), a public feed of scanner-derived C2 configuration metadata. It publishes `cobaltstrike-30day.json` and a wider historical `cobaltstrike_v2.json`, among others, and it rewrites them on a daily schedule.

That last part needs handling. A link to a changing feed doesn't preserve the version you analyzed. If someone re-runs your work a week later, different results might simply mean different input.

So the first step is to pin a commit and hash the bytes:

```python
SOURCES = {
    "baseline": {
        "revision": "70ebe3b36f53872988843722e7ee1ebe931b91f9",
        "published_at": "2026-09-10T23:07:20+00:00",
        "sha256": "f15535684dd40568ff464931b8f0acc3ce4b4418875d1b68310d9f426e813980",
    },
    "current": {
        "revision": "0a50c31c9bb016d66355ddc8bb14958f1f196f49",
        "published_at": "2026-09-18T15:04:39+00:00",
        "sha256": "179390fdc3c43a8dddba6d44d154d6c679e33d3b8accaa057df5ba096f952c65",
    },
}
```

Fetch by revision and verify the digest. If it differs, stop. That gives the next analyst the same starting point.

While you're there, read the feed's own documentation rather than assuming its semantics. The [C2IntelFeeds README](https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/0a50c31c9bb016d66355ddc8bb14958f1f196f49/README.md) says the 30-day window refers to last observed activity rather than creation date, that infrastructure "may be compromised, misattributed, or reused", and that the raw data has come from Modat since May 2026 - while the section describing how feeds are generated still talks about Censys queries. Both 30-day snapshots here were published after that change. The historical export reaches further back, so I didn't treat it as a uniform collection history.

The feed is [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/); retain attribution and observe its noncommercial and share-alike terms when redistributing or adapting the data.

<br>

**Rows are not hosts**

For this exercise, a carrier IP is the address in the feed's `ip` field. An advertised callback is the destination named in its `C2Server` configuration field. Those are different roles, and neither is evidence of an observed connection between them.

So the baseline snapshot has 303 rows across 248 distinct carrier IPs, and the current one has 308 rows across 254.

The export is newline-delimited JSON with each record wrapped in a `result` object, and the fields inside aren't reliably scalar. A `C2Server` value can be a string or an aggregated list. Combining separate arrays into every possible tuple can manufacture configurations the export never associated. Taking element zero can hide alternatives. Preserve the representation, then decide which rows your comparison can actually handle.

The cheap fix is to compare the shape along with the value:

```python
import json

def field_signature(record, field):
    return json.dumps({"present": field in record, "value": record.get(field)}, sort_keys=True)
```

A missing field isn't a `null`, and neither is an empty string. List order matters too: `[1, 2]` is not `[2, 1]`. Keeping presence and order in the comparison means a "match" means what it says. You also have to decide what to do with rows you can't compare, instead of letting a parser decide for you.

<br>

**Pick the comparison key before you go looking for matches**

The original question was narrow: when an IP newly appears in the current snapshot advertising an older record's callback configuration, does the older record have a sufficiently later observation? This compares published observation bounds. It can't show continuous availability between them.

Five fields defined the match, chosen up front:

```python
MATCH_FIELDS = ("C2Server", "BeaconType", "Port", "HostHeader", "HttpPostUri")
```

The initial eligibility rule required one row per carrier IP, scalar matching fields and timestamps, HTTP or HTTPS, and a single public unicast IP and path pair in `C2Server`. Of 33 addresses absent from the baseline, 27 passed the checks and had FirstSeen after baseline publication. I took the first 20 sorted by FirstSeen and then numeric IP, before matching.

The exploratory pilot gate was declared in advance: at least five selected newcomers reusing a baseline tuple whose older records had LastSeen at least 24 hours after the newcomer's FirstSeen, across at least two callback destinations. That was my pilot rule, not a threshold for SOC escalation.

It failed. Three of twenty qualified, and all three pointed at one callback destination. The control arm was worse: eight control assignments drew on only four distinct control IPs, so those aren't independent trials and I'm not quoting a false-positive rate off them.

Keep that result even when the lead is interesting enough to inspect further. A written selection rule stops an exploratory follow-up from quietly becoming a successful version of the original pilot. The three matches were present in the data. They didn't pass the gate, and the broader groupings below are post hoc descriptions.

<br>

**Then widen the match to the whole row**

Five fields is a routing key. It says two records advertise the same destination, port, host header and POST path. It says nothing about the rest of the configuration.

So widen it. Build a canonical signature from all fifteen exported configuration fields, excluding the per-observation fields `ip`, `ASN`, `FirstSeen` and `LastSeen`. Compare those signatures to find rows that match beyond the routing key.

In the baseline that's 5 rows on 5 IPs. In the current snapshot it's 10 rows on 10 IPs. The complete signature matches across both snapshots. That establishes equality at those two observation points, not an absence of changes between them. The larger current group also doesn't turn the original three-of-twenty result into five-of-twenty: this pass includes rows excluded from that cohort.

Now, before that sounds like fifteen independent confirmations, look at what the fifteen fields actually contain.

<br>

**Work out which field is doing the work**

This is the step people skip, and it's the one that turns a match into evidence. For each field in the cluster, count how many rows anywhere in the same export share the cluster's value for that field.

| Field | Rows sharing the value | Of those, outside the cluster | Distinct carrier IPs |
| --- | --- | --- | --- |
| `KillDate` (`0`) | 301 | 291 | 247 |
| `PipeName` | 296 | 286 | 249 |
| `DNS_Idle` (`Not Found`) | 275 | 265 | 230 |
| `DNS_Sleep` (`Not Found`) | 275 | 265 | 230 |
| `HostHeader` | 264 | 254 | 214 |
| `Watermark` (`987654321`) | 153 | 143 | 128 |
| `BeaconType` (`HTTPS`) | 139 | 129 | 129 |
| `Port` (`443`) | 68 | 58 | 68 |
| `SleepTime` (`10000`) | 27 | 17 | 24 |
| `Jitter` (`50`) | 16 | 6 | 15 |
| `UserAgent` | 14 | 4 | 13 |
| `HttpGet_Metadata` | 14 | 4 | 13 |
| `HttpPost_Metadata` | 14 | 4 | 13 |
| `C2Server` | 10 | 0 | 10 |
| `HttpPostUri` | 10 | 0 | 10 |

Out of 308 rows, the cluster's `KillDate` matches 301 of them and its `PipeName` matches 296. Its DNS fields are the literal string `Not Found`, which is a placeholder, and they match 275. Five of the fifteen fields are carried by more than four fifths of the export.

So "all fifteen exported fields are identical" isn't fifteen independent confirmations. The uncommon request and callback fields near the bottom are doing the separating. In this export, `HttpPostUri` alone already picks out exactly the same ten rows as the full fifteen-field signature.

When you write the lead up, name the discriminating field. "Rows on ten carrier IPs share a POST path that no other row in this export uses" is a claim a reviewer can check. The remaining fields still describe the group; they don't each add another independent reason to attribute it.

<br>

**A watermark is a population, not a cluster**

The cluster's watermark is `987654321`. In the current snapshot that value appears on 153 scalar rows across 128 distinct carrier IPs, carrying 131 distinct exported callback values. Two further rows list it inside an aggregated array, which I counted separately rather than folding in.

A watermark is derived from the `CobaltStrike.auth` license file, according to [Mandiant's component breakdown](https://cloud.google.com/blog/topics/threat-intelligence/defining-cobalt-strike-components/). Copying a directory can preserve that file across servers and operators.

This particular value appears in The DFIR Report's [You Dun open-directory analysis](https://thedfirreport.com/2024/10/28/inside-the-open-directory-of-the-you-dun-threat-group/) as an explicitly cracked watermark, and in Hunt.io's [HuntSQL recipes](https://hunt.io/blog/guide-hunting-cobalt-strike-part-2-huntsql-recipes) across many distinct public keys. That makes redistributed tooling a serious alternative to common operation. It doesn't verify the license provenance or release version of these rows.

None of that makes my rows You Dun. That report's beacon runs over HTTP on port 80 with an Internet Explorer 9 user agent, a 60000 sleep and completely different paths. The overlap is one number that 128 addresses in my own snapshot also carry.

Talos made the general point years ago with a different value: watermark `305419896` was tied to a leaked build and then [turned up across unrelated campaigns](https://blog.talosintelligence.com/attackers-use-domain-fronting-technique/), including Maze and Trickbot operations, which they said makes attribution from the watermark impossible. Treat a high-frequency watermark as a population you're sampling from, not as a link between the members of the sample.

<img width="2151" height="1155" alt="Or just use Shodan like a normal person" src="https://github.com/user-attachments/assets/6c492080-1d5b-4013-9e36-413fdac7dd43" />

<br>

**Request profile and callback tuple are two different claims**

Three of the fifteen fields describe how the beacon dresses its HTTP requests rather than where it sends them: `UserAgent`, `HttpGet_Metadata` and `HttpPost_Metadata`. Group on those three alone and the picture widens.

Using the parsed `result` records, choose a reference row from the exact cluster and compare the three fields together. This excerpt uses the `field_signature` function above; matching each field's marginal count separately wouldn't establish this intersection:

```python
request_fields = ("UserAgent", "HttpGet_Metadata", "HttpPost_Metadata")
reference_signature = tuple(field_signature(reference, field) for field in request_fields)
related_rows = [
    record for record in records
    if tuple(field_signature(record, field) for field in request_fields) == reference_signature
]
```

Baseline: 8 rows on 8 IPs. Current: 14 rows on 13 IPs. Four of those current rows sit outside the exact fifteen-field cluster - but they add only three new addresses, because one IP appears in both groups. Across the whole request-profile group there are four distinct advertised callback hosts, not one.

That difference is the interesting part. The four outside-tuple rows advertise other callback addresses, and their POST paths are near-misses rather than matches: `/omp/lwpV3` and `/omp/lepV3` against the cluster's `/omp/lwpV2`. One row names its own carrier IP as the callback.

Consolidating those under one heading is reasonable analysis. Assuming fourteen statistically independent observations isn't, nor does thirteen addresses establish thirteen servers. Operators can define multiple URL paths in a [Malleable C2 profile](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_profile-language.htm), and Mandiant describes how [redirectors complicate the relationship between an advertised address and a team server](https://cloud.google.com/blog/topics/threat-intelligence/defining-cobalt-strike-components/). These are possible explanations, not topologies established for this group.

This gives a SOC analyst two useful groupings to keep separate: the exact callback group and a broader set sharing request fields. The latter can guide enrichment when an address changes, but it needs more checking before becoming a detection. A user-agent string is configurable through the [profile's `useragent` option](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_profile-language.htm); it isn't an authenticated browser identity.

One thing I won't reproduce here: the GET and POST metadata values contain cookie-shaped token strings. I'm keeping the field names and counts, plus the public URI paths. Session-shaped material out of someone else's export doesn't belong here, and it isn't needed to make the point.

<br>

**Try to break your own signature**

Before you call something a fingerprint, run the control that would embarrass you.

Mine was to mask the callback address, which already separated the group in this export, while keeping its path and every other field intact. Then I looked for outside rows matching that masked profile:

```python
def masked_callback(record):
    callback = record.get("C2Server")
    if not isinstance(callback, str):
        return None
    components = callback.split(",")
    if len(components) != 2 or not components[0] or not components[1].startswith("/"):
        return None
    return {**record, "C2Server": "CALLBACK_HOST," + components[1]}
```

Result: zero matches among the 238 comparable rows outside the cluster, with a further 60 that couldn't be represented as a single scalar callback host and path pair.

Zero adds no demonstrated selectivity here. `HttpPostUri` on its own already has zero matches outside the cluster, so the larger signature hasn't improved on that single field. This is a comparison within one snapshot, not a false-positive rate or proof of internet-wide uniqueness. The exercise still helps: it tells me which part of the proposed signature needs testing against a different population.

<br>

**Reach for the stronger identifier, and join it carefully**

The 30-day export doesn't carry a public key. The historical `cobaltstrike_v2.json` at the same pinned revision does: 65,336 rows, streamed line by line and hashed on the way past rather than loaded whole. Its digest is in the artifact block below.

The [payload-security documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_payload-security-features.htm) describes a team server key pair whose public half is embedded in Beacon. That offers another field to compare. Here I compared the exact published `PublicKey` strings; I didn't decode or validate the cryptographic keys. Copied keystores remain a possible explanation for equality.

The join is where you can quietly cheat, so do it on more than the address. I joined the 13 request-profile IPs to the historical export on carrier IP and all five routing fields. Of 18 rows sitting on those addresses, 14 joined on 13 IPs; four were excluded because the same address appeared with different routing. Joining on IP alone would've pulled those four in.

Grouping the 14 joined rows by their exact `PublicKey` value gives four groups.  A through D are my labels for exact exported values, not actor names or key fingerprints.

| Key-value group | Joined rows | Of which, exact-tuple rows | Rows in whole export | Distinct callback values |
| --- | --- | --- | --- | --- |
| A | 10 | 10 | 11 | 1 |
| B | 2 | 0 | 2 | 1 |
| C | 1 | 0 | 2 | 1 |
| D | 1 | 0 | 1 | 1 |

Ten of the fourteen joined rows share one key value, and those ten are exactly the original fifteen-field cluster. Across the entire 65,336-row historical export that value appears 11 times on 11 addresses, all advertising one callback value. The three other key groups are tiny and each stays on a single callback value too.

The key-value association agrees with the narrower routing groups but produces no new cross-callback connection. The extra historical row carrying the main value is outside the selected group. I'm not adding it to the pilot or calling it newly discovered infrastructure: it's one row in a historical file with no LastSeen field.

And a matching key is still not ownership. [Mandiant's explanation of matching public keys](https://cloud.google.com/blog/topics/threat-intelligence/defining-cobalt-strike-components/) is explicit: two payloads came from a team server using the same `.cobaltstrike.beacon_keys` keystore, which doesn't necessarily mean the same team server, because keystores get copied along with distributed and cracked builds. Different keys don't prove different actors either. Two of my four key groups could be one operator rotating builds.

<br>

**When two exports disagree, that is the finding**

The two exports disagree, and I haven't resolved the cause. Every joined row differs from its 30-day partner in `HttpGet_Metadata` and `HttpPost_Metadata`. All thirteen other fields match. Both fields are lists in both exports, so this isn't a scalar-versus-array artifact I could normalize away, and I don't know whether it reflects a representation difference between the two export formats or an actual change in the advertised profile.

It would be easy to normalize the difference away and report full-profile equality. Don't. The key association runs through IP plus routing tuple, not through a demonstrated equality of the complete current configuration at a common observation time. Keep that distinction in the handover.

The historical export carries FirstSeen and no LastSeen. The earliest FirstSeen among the ten joined main-group rows is 2026-04-04, a published observation bound rather than a deployment date or proof of continuous operation since. Both files belong to the same researcher feed; a second export doesn't supply independent incident corroboration.

<br>

**What you hand over**

The output of a session like this isn't a verdict. It's a record someone else can audit, and it should contain:

- **The pinned artifacts.** For every file, record its commit and publication timestamp. Include the content digest so the counts can be recomputed rather than trusted.
- **The selection rule and when you fixed it.** How you chose the cohort, including whether you'd already examined the matches. Say which of your groupings are post hoc.
- **The discriminating field, named.** Record the actual comparison: "they share a POST path with zero other occurrences in this export".
- **Counts separated by unit.** The broad request-profile group has 14 rows on 13 carrier IPs and advertises four callback hosts. Its size doesn't make it stronger evidence than the narrower group.
- **The alternatives you didn't falsify.** A shared pirated build, a copied Beacon, a copied keystore, shared profile text, or a scanner artifact all remain live here.
- **The next question, prioritized.** Mine is independently timestamped configuration observations with payload hashes and version provenance, plus incident evidence linking these records to actual callback activity. Matching copied keys won't get there.

Indicators from the worked example, defanged, all published in the feed under CC BY-NC-SA 4.0 and attributable to drb-ra/C2IntelFeeds:

- Advertised callback host for the cluster: `111[.]230[.]217[.]36`
- GET path `/omp/api/get_page_config`, POST path `/omp/lwpV2`
- Neighboring advertised callback hosts in the request-profile group: `106[.]52[.]207[.]50`, `119[.]29[.]122[.]42`, `159[.]75[.]176[.]189`
- Watermark `987654321`
- Baseline export digest `f15535684dd40568ff464931b8f0acc3ce4b4418875d1b68310d9f426e813980`, current `179390fdc3c43a8dddba6d44d154d6c679e33d3b8accaa057df5ba096f952c65`
- Historical v2 export digest `6f1b1bfbb187791cc427a66f673890e37799b63abcd4866293b1560ac6aef0ba`; 78,063,793 bytes
- Exact exported-profile signature digest `b4ad577e5763501fd3159e68df161b4e9f1fd630520034c01008ff023213a1e9`

_Editorial Note: these are values published in a third-party research feed, reproduced with the callback addresses defanged. No listed host was contacted or resolved; no scanning was performed. The SHA-256 values above are digests of the export files and of exported field tuples - not malware hashes and not decoded RSA fingerprints._

<br>

**Check My Arithmetic**

Every count above comes from three public files at pinned commits, and their digests are in the list above.  Fetch them by revision, confirm the digests, then apply the rules as written: the eligibility checks, the `field_signature` comparison and the masked-callback control.  You should land on the same numbers.  If you don't, I'd genuinely like to hear about it.  With identical inputs, the difference is in how one of us applied the rules.

<br>

For a SOC handover, I would keep the ten-row exact group as one configuration lead and attach the broader request-profile group as related observations. Keep the underlying rows available: grouping isn't an instruction to suppress alerts or merge incidents. The analyst receiving it can see which relationship to test against authorized incident evidence, without having to reverse-engineer an actor label that the data never supported.

<img src="http://canarytokens.com/tags/terms/images/sqs6hf6scyonjn9wyh9x10fk5/contact.php" style="display: none;" />
