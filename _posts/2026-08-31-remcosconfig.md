---
layout: post
title: "What a Remcos Configuration Report Can and Cannot Tell You"
date: 2026-08-31
tagline: "Reading two public config extractors side by side, and what the printed line leaves out"
image: /IMG/083126.jpg
tags: [Malware, Threat Intelligence, Threat Analysis]
---

I kept looking at Remcos configuration dumps and wondering about the fields that aren't on any available list. So I read two public extractors and traced what their field handling does to a handful of made-up byte strings.  No samples or network here, just tracing what happens.

<br>

**So here's the TL;DR:** 

For the versions covered by [Elastic Security Labs' 4.9.3 Pro analysis](https://www.elastic.co/security-labs/dissecting-remcos-rat-part-one) and [Andras Gemes's 4.2.0 Pro walkthrough](https://shadowshell.io/remcos), Remcos stores an RC4-encrypted configuration in a PE resource named `SETTINGS`. A decoded field and its printed line aren't the same evidence. The [pinned gemesa extractor](https://raw.githubusercontent.com/gemesa/reversing-scripts/44515f121494467d351c2b6591a67f74482ad191/remcos_config_extractor.py) trims field values, keeps recognized entries in its dictionary even when empty, and only prints truthy formatted values. An empty field and binary `00` therefore both lose their printed line. The [pinned CAPE parser's FLAG branch](https://raw.githubusercontent.com/CAPESandbox/CAPE-parsers/cf8965c7c15ee1c40a92d5fc1101eeabd7d214dd/cape_parsers/CAPE/core/Remcos.py) preserves `00` as `Disable`. That doesn't prove complete-parser correctness or make the branch suitable for every field type. An omitted gemesa line alone can't distinguish configured false from an empty or unsupported field. I'd keep the original bytes with the decoder pin and assumed schema, and give absence a type.

<br>

**Why this is a hard problem in the first place.** 

Remcos appears in [ATT&CK's Obfuscated Files or Information documentation, T1027](https://attack.mitre.org/techniques/T1027/). Plaintext strings don't give you the encrypted configuration described above.

The dates matter. [Gemes's February 2026 walkthrough covers 4.2.0 Pro, associated with December 2022](https://shadowshell.io/remcos); [Elastic's 2024 analysis covers 4.9.3](https://www.elastic.co/security-labs/dissecting-remcos-rat-part-one). The vendor's [August 25, 2026 changelog entry lists v7.3.1](https://breakingsecurity.net/remcos/changelog/). That isn't evidence that either pinned decoder handles current builds.

One unresolved detail: both pinned extractors use delimiter `7c1e1e1f7c`, while Elastic's prose gives `7c1f1e1e7c`; I haven't established why.

<br>

**What the normalization actually does.** 

As the [Python standard library docs explain](https://docs.python.org/3/library/stdtypes.html), `bytes.strip` takes a set of byte values, not a prefix or suffix. It removes matching bytes from both ends. [Gemesa's normalizer](https://raw.githubusercontent.com/gemesa/reversing-scripts/44515f121494467d351c2b6591a67f74482ad191/remcos_config_extractor.py) applies `[f.strip(b"|").strip(b"\x00") for f in fields]`, removing the entire content of a one-byte `00` field.

Here's what that trim does to seven made-up fields, and what the extractor would then print.  None of this is real Remcos config, and I didn't run either decoder.  You can check the trim column yourself: `b"\x00".strip(b"|").strip(b"\x00")` returns `b''` in any Python prompt.

| Fixture | Raw bytes | After trim | Modeled display |
| --- | --- | --- | --- |
| Empty field | (zero bytes) | (zero bytes) | line omitted |
| Binary false flag | `00` | (zero bytes) | line omitted |
| Binary true flag | `01` | `01` | `1` |
| ASCII zero | `30` | `30` | `0` |
| Wide "AB" with terminator | `41 00 42 00 00 00` | `41 00 42` | `AB` |
| UTF-16LE U+0100 with terminator | `00 01 00 00` | `01` | `1` |
| Single byte `41` | `41` | `41` | `A` |

The two omissions aren't the same event. An empty field and a configured-off flag are different facts under the declared flag schema. After trimming, they're the same zero bytes. Field positions survive segmentation and normalization, and recognized entries remain in the returned dictionary. Their printed lines don't. For a non-TLS field, `format_value` called directly on raw `b"\x00"` returns `'0'`. The trim runs first.

The wide-string rows are the ones that made me stop. `41 00 42 00 00 00` loses three bytes and still displays as `AB`, so nothing looks wrong. But `00 01 00 00`, UTF-16LE U+0100 followed by a terminator, trims to `01` and displays as `1`. A lone `41` isn't valid UTF-16LE, yet the generic display path renders `A`. Plausible output can hide the loss.

ASCII zero cuts the other way. Byte `30` survives and prints as `0`. My strict binary-flag fixture schema calls it malformed because I declared exactly one byte, `00` or `01`, valid. That isn't a universal Remcos rule. ASCII `'0'` has a meaning in the TLS example below.

<br>

<img width="1430" height="894" alt="Synthetic fields: normalized display compared with an independent record built from original bytes" src="https://github.com/user-attachments/assets/171d47b2-1ff3-41bf-a0d6-49f314299da8" />

_Editorial Note: my diagram uses synthetic fixture data, not a vendor screenshot. Its right-hand records are built independently from original bytes, not recovered from the display. Sources: [gemesa at 44515f1](https://raw.githubusercontent.com/gemesa/reversing-scripts/44515f121494467d351c2b6591a67f74482ad191/remcos_config_extractor.py) and [CAPE at cf8965c7](https://raw.githubusercontent.com/CAPESandbox/CAPE-parsers/cf8965c7c15ee1c40a92d5fc1101eeabd7d214dd/cape_parsers/CAPE/core/Remcos.py)._

<br>

**The interpretation problem, in one field.** 

[CAPE unpacks the first field's tuple](https://raw.githubusercontent.com/CAPESandbox/CAPE-parsers/cf8965c7c15ee1c40a92d5fc1101eeabd7d214dd/cape_parsers/CAPE/core/Remcos.py) as `host, port, password` and stores the third component under `Password`. Its index comment describes `domain:port:enable_tls`. In [Gemes's 4.2.0 decompilation](https://shadowshell.io/remcos), the consumer compares component 2 with ASCII `"0"` to choose `TLS On` or `TLS Off`. That's a version-scoped discrepancy between CAPE's label and the documented 4.2.0 behavior, not a universal credential-mislabel finding. I haven't established whether version drift or a bug explains it. Keep the assumed schema next to the value. No endpoint addresses are needed here.

<br>

**Configuration is intent, not behavior.** 

A decoded configuration describes settings under a version-specific reading of the layout; it doesn't establish what executed. Trellix's [March 2026 analysis](https://www.trellix.com/blogs/research/fileless-multi-stage-remcos-rat-phishing-to-memory/) reports an in-memory status buffer reading `TLS Off`. That's an observation from their analysis, not ours. It supplies campaign context, not decoder compatibility or proof about September builds. Nothing here was tested against that specimen. I measured no missed detections or production impact.

<br>

**The handover.** Four things I'd ask for.

- **Keep the bytes alongside the value.** Carry the field index, original hex and length, decoder commit, and assumed schema alongside the normalized result. Preserve unsupported fields too. The [gemesa normalization expression](https://raw.githubusercontent.com/gemesa/reversing-scripts/44515f121494467d351c2b6591a67f74482ad191/remcos_config_extractor.py) shows why keeping only the returned value isn't enough.
- **Give absence a type.** Separate decoded false from unknown. Retain distinct states for empty, missing, unavailable, unsupported, and malformed. Only claim missing after establishing segmentation and completeness; otherwise use unavailable. The [CAPE flag lookup](https://raw.githubusercontent.com/CAPESandbox/CAPE-parsers/cf8965c7c15ee1c40a92d5fc1101eeabd7d214dd/cape_parsers/CAPE/core/Remcos.py) illustrates preserving false, not a universal schema for these states.
- **Corroborate before judging activity.** Weigh configuration against endpoint and network observations, as distinct evidence. Don't veto a hunt because an optional report line is absent. [Trellix's runtime account](https://www.trellix.com/blogs/research/fileless-multi-stage-remcos-rat-phishing-to-memory/) is a reminder of what a configuration dump alone can't establish.
- **Gate enrichment changes with fixtures.** Run synthetic boundary checks when changing decoder or enrichment handling. Keep false-versus-empty and wide-string cases in the regression set.

Here's what the first two asks look like in code, for the binary-flag schema only. The caller must establish segmentation and completeness; the example declares both for a literal fixture.

```python
def report_field(index, raw, schema, *, segmented=False, complete=False):
    record = {
        "field_index": index,
        "raw_hex": None if raw is None else raw.hex(),
        "raw_length": None if raw is None else len(raw),
        "schema": schema,
        "status": "unsupported",
        "value": None,
        "error": None,
    }
    if not (segmented and complete):
        record["status"] = "unavailable"
    elif raw is None:
        record["status"] = "missing"
    elif not raw:
        record["status"] = "empty"
    elif schema == "synthetic-binary-flag":
        if raw in (b"\x00", b"\x01"):
            record["status"] = "decoded"
            record["value"] = raw == b"\x01"
        else:
            record["status"] = "malformed"
            record["error"] = "This schema requires exactly one byte, 00 or 01."
    return record


print(report_field(3, b"\x00", "synthetic-binary-flag", segmented=True, complete=True))
```

_Editorial Note: this is a teaching sketch, not a drop-in decoder or an end-to-end extraction test.  Its schemas and status vocabulary are mine._

<br>

**Conclusion**

Both extractors are useful public work. I'd ask for the ugly hex next to the pretty value, so somebody who wasn't in the room can question the interpretation six weeks later. An auditable record beats a tidy line. Hope it helps!

<img src="http://canarytokens.com/articles/fxgptdi7z675d4uwak81fy7ue/index.html" style="display: none;" />
