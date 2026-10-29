---
layout: post
title: "A Detection Baseline, If You Can Keep It"
date: 2026-10-29
tagline: "A versioned reference that says what you promised to detect. It was never meant to hold every detection worth running."
image: /IMG/102926.jpg
tags: [Detection Engineering, Security Operations, Evaluation]
---

Detection inventories have a peculiar way of growing. Someone finds a rule worth adding, someone else finds another, and the answer to whether either one was needed is often a search through whatever happens to be deployed today. A technique label matches, so the new rule is called a duplicate. The logic differs, so it's called new coverage. A new incident kicks off and its intended detection did not fire, better create a new one for this new variant.  None of this tells us what the organization intended to detect, or whether the detections it already had ever delivered it.

Someone wants to add a detection. Maybe it's a rule a teammate wrote after a hunt turned something up, a community Sigma rule that looks relevant, an entry in a vendor content update, or a request from an application team that knows what abuse of its own system would look like. Wherever it comes from, a sensible first question in review is some version of *don't we already have this?*

Two quick answers are always available. The proposed rule maps to the same ATT&CK technique as something already deployed, so it's a duplicate. Or its logic differs from anything deployed, so it's a new capability. Both answers can be wrong, and each costs something different when it is. The first can retire a detection that was watching something nothing else watches, or paper over the fact that the existing rule never delivered what it claimed. The second grows the inventory without anyone saying what the organization meant to detect in the first place, so nobody can tell whether the new rule fills a hole or just sits next to one.

My argument is that you need something fixed to compare against, and it shouldn't be the inventory. A detection baseline, as I'll use the term, is a static, versioned reference of selected detection capabilities: the condition you intend to establish and keep, written down at a point in time. It isn't a snapshot of whatever happens to work today, and it isn't the statistical picture of normal activity that an anomaly model compares against. The concrete rules, their deployments and the dated evidence about how they behave are separate records that point back at it. And the reference isn't the whole portfolio. Outside it sit satellites: supported detections whose purposes fall outside the baseline's selected scope. A satellite can be as critical and as mature as anything in the core, and it may never need to move.

Here's the route. I'll start with what a baseline promises that an inventory can't, then credit what MITRE ATT&CK, MITRE's Cyber Analytics Repository (CAR), Sigma, Palantir's Alerting and Detection Strategy (ADS) framework and the Center for Threat-Informed Defense's (CTID) Summiting the Pyramid project already solve. Then I'll lay out the arrangement I'm proposing, and work it through three illustrative cases: an Office-to-PowerShell capability whose first implementation delivered less than the reference promised; a payment-approval detection that is critical, permanent and deliberately outside the baseline; and a parser regression set beside a deliberate decision to widen scope. What you should come away with is four defensible answers to "don't we already have this?" - already addressed, correct it within the core, keep it as a satellite, or not yet comparable - and a clear sense of why none of them, on its own, means delete, merge or promote.

<br>

**A Reference, Not an Inventory**

An inventory answers "what do we run?" You need one. But an inventory can't tell you a detection is missing, because the missing detection isn't in it. It can't tell you whether a deployed rule does what anyone intended either, because it records the rule, not the intention.

A baseline answers a different question: what did we commit to detecting, for which population, on what evidence? Two words in my definition carry most of the weight.

*Static* means a given version doesn't move. Call it B1. B1 says which capabilities the organization selected, what each is supposed to detect, where each applies and what evidence each requires. When the commitment changes, you get B2, and B1 stays available for everything that was compared against it. The versioning is the point. Without it, the reference becomes whatever someone last edited, and an old comparison quietly changes meaning underneath you.

*Reference* means it describes the condition you're trying to establish and maintain, not the condition you're in. That sounds abstract, but it's the property that makes a baseline worth having. A baseline defined as "what currently works" can't be failed: every broken parser and every stalled deployment silently shrinks it until it matches reality again. A reference written as an intended condition can have gaps on the day it's adopted, because some promised capabilities don't have implementations yet, and it can develop gaps later, when something that worked stops working. Neither kind of gap changes the reference. Both are findings against it.

The general idea isn't new. NIST's glossary, drawing on SP 800-128, defines a [baseline configuration](https://csrc.nist.gov/glossary/term/baseline_configuration) as a set of specifications "formally reviewed and agreed on at a given point in time," one that "can be changed only through change control procedures" and is "used as a basis for future builds, releases, and/or changes." That definition is about systems and configuration items, and I'm not suggesting NIST says anything about detection portfolios. I'm borrowing its shape: an agreed reference, fixed per version, that reality gets compared against.

The portfolio is everything the organization actually supports: the core - the baseline's capabilities and the implementations serving them - plus the satellites. These are the working definitions I'll hold for the rest of the post:
<br>
  - **Capability:** a stable, bounded detection purpose with declared applicability, the observable behavior it covers, the evidence it requires and its meaningful limits.
  - **Baseline:** a versioned snapshot identifying selected capability definitions and their intended reference condition.
  - **Core:** the capabilities included in a declared baseline, and the implementations serving them.
  - **Satellite:** a supported detection purpose retained outside that baseline's selected scope or organizing criteria.
  - **Implementation:** concrete analytic logic, together with the mappings, configuration and deployment context needed to interpret what it does.
  - **Assurance:** evidence supporting a bounded statement about a particular implementation, in a particular scope, at a particular time.

<br>

<img width="1448" height="1086" alt="Diagram of the detection portfolio, divided into core and satellite detections. The core contains capabilities selected for the detection baseline, while satellites are supported detections outside its selected scope. Both are organized around capability, implementation, and assurance records. A bottom panel shows the three linked records: capability reference, implementation record, and evidence record." src="https://github.com/user-attachments/assets/24a9e6c7-66d8-4c96-ab43-8ad38ce14675" />

<br>

Two consequences follow from those definitions.

First, baseline membership isn't a ranking. A capability is in the core because it fits the criteria the organization used to select its reference - reusable technical behavior across a declared fleet, for instance. That says nothing about how important it is, how mature its implementation is or how long it will last. Existing practice already keeps related judgments apart. The [Sigma rules specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html) records a rule's `status` (stable, test, experimental and so on) separately from its `level`, which "describes the criticality of a triggered rule." Palantir's [ADS template](https://github.com/palantir/alerting-detection-strategy-framework/blob/master/ADS-Framework.md) gives priority its own section with its own criteria, separate from categorization against ATT&CK. Baseline membership is another judgment of that kind, and it shouldn't be smuggled into the others.

Second, a satellite isn't a waiting room. The word invites an orbit picture: something circling the core, held in place by it, waiting to be pulled in. Membership carries none of that, because the baseline is a reference for comparison, not a runtime architecture. Whether a detection sits inside or outside it doesn't tell you how the detection is built. A satellite might read the same telemetry as a core capability, go through the same collector and parser, correlate with a core detection's alerts or even take another analytic's output as one of its inputs. It might share nothing with core at all. Those are facts about implementations, and they belong in implementation records, where someone can check them when a shared piece breaks. Membership neither implies them nor rules them out.

Nor does it put a satellite in a queue. A satellite is a detection with a legitimate purpose that doesn't fit the reference's selected scope, and it can stay that way for as long as the purpose exists - owned, tested and fully supported the whole time. If an organization later chooses to change what its baseline is about, a satellite might fall inside the next version. That's a voluntary decision about the reference's scope, not graduation, and being a satellite never obliges it.

A few things the word "baseline" tends to drag along don't belong here either. There's no correct number of capabilities, or of rules per capability. One capability can be served by several implementations, so the unit of comparison is a capability with its implementations, not one universal query per technique. There's no single release gate every detection must pass. And there's no particular governance structure this requires; I'll come back to who should own the reference near the end.

<br>

**None of This Starts From Scratch**

Most of the pieces already exist in public practice. The gap I'm interested in is narrow, and I'd rather credit the borrowed parts than dress them up as new.

MITRE ATT&CK already separates a detection approach from the analytics that carry it out. Its [detection strategies](https://attack.mitre.org/detectionstrategies/) "define high-level approaches for detecting specific adversary techniques" and "serve as containers that organize multiple platform-specific analytics into cohesive detection methodologies." That's the intent-versus-implementation split in public, maintained form. The PowerShell strategy, [DET0455](https://attack.mitre.org/detectionstrategies/DET0455/), is a good example, and I'll lean on it in the first case: a Windows analytic, AN1252, with listed log sources and a table of "mutable elements" describing what can be adjusted, such as which parent processes count as abnormal.

CAR goes further toward the implementation side. Each analytic in the [Cyber Analytics Repository](https://car.mitre.org/) carries "a hypothesis which explains the idea behind the analytic," references to the ATT&CK techniques it detects, a pseudocode description and "a unit test which can be run to trigger the analytic." CAR "defines a data model that is leveraged in its pseudocode representations, but also includes implementations directly targeted at specific tools," and it describes its focus as "a set of validated and well-explained analytics, in particular with regards to their operating theory and rationale." Rationale, data model, tool-specific implementations and a test hook cover most of the anatomy of a well-documented detection.

Sigma handles identity, lineage and scope at the rule level. The [specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html), version 2.1.0, identifies rules by UUID and says it's better to write a rule with a new ID for major changes - its example is "a different rule logic" - for derivations where both rules stay active, and for merges. The `related` field records whether a rule was `derived` from others "which may remain active," makes them `obsolete`, was `merged` or `renamed`, or is merely `similar`, for instance "same detection content applied to different log sources." The `logsource` section abstracts the telemetry a rule needs, an approach that "does not limit the rule to a specific telemetry source," with an optional `definition` describing configuration the source requires. `scope` lists "the intended scopes of the rule," and `status` and `modified` say how settled the rule is and when it last changed.

Palantir's [ADS framework](https://github.com/palantir/alerting-detection-strategy-framework/blob/master/ADS-Framework.md) covers the operational record. A strategy starts from a goal, "the intended purpose of the alert," and works through categorization, a strategy abstract, technical context, blind spots and assumptions, false positives, validation, priority and response. Two of those matter a great deal for what follows. Blind spots and assumptions are "the recognized issues, assumptions, and areas where an ADS may not fire" - an explicit place to say what a detection doesn't cover. Validation is "the steps required to generate a representative true positive event which triggers this alert," which the framework describes as "similar to a unit test," and it says each strategy "must have true positive validation."

Last, there's CTID's [Summiting the Pyramid](https://ctid.mitre.org/projects/summiting-the-pyramid/) release, dated September 10, 2026, which aims to help defenders "measure the depth and quality of detection coverage beyond an ATT&CK heatmap." Its project summary distinguishes "implementation coverage, which measures how many behaviorally distinct ways of performing a technique an analytic can observe," from "detection quality, which evaluates the robustness and precision of the signals behind that visibility." I've read the summary, not the detailed method, so I won't characterize how it scores anything. The distinction alone is the one I need: a technique label on an analytic doesn't tell you which behaviorally distinct variations it actually sees.

So intent separated from implementation, structured rationale, implementation and test artifacts, rule lineage, telemetry abstraction, blind spots, validation and a public argument for looking beneath technique labels are all established. What the material I read leaves to the implementing organization - CAR says outright that it's ["up to the organization implementing them to determine what works best for their environment and the threats they face"](https://car.mitre.org/) - is the portfolio decision. Which capabilities does *this* organization promise, and for which population? When a new detection arrives, which promise is it compared against, at which version? What happens to a strong detection that doesn't fit the promise at all? Those are the questions the rest of this post takes on.

<br>

**Three Records, Three Speeds**

For any detection purpose there are three kinds of record, and they change at different rates.

The capability reference says what's promised: the behavior, where it applies, the evidence it requires and its explicit limits. It should change rarely, and only on purpose.

The implementation is what actually runs: analytic logic plus the parser, field mappings, exception lists and deployment scope it depends on. It changes whenever someone fixes a bug, tunes a filter, moves to a new collector or ships a parser update.

Assurance is evidence about an implementation - a test result, a review of production behavior, an exercise. Every piece of it is dated and scoped. It says a particular implementation behaved a particular way, on a particular population, during a particular interval, within stated limitations. That's no guarantee about tomorrow, but it isn't silent about tomorrow either. It supports a conditional expectation: if the implementation, what it depends on, the population and the behavior it's meant to catch stay as they were, there's reason to expect similar results. When one of those changes, the evidence doesn't become false. It stops carrying forward on its own.

Collapse those into one record and you lose the ability to answer basic questions. A rule's last-modification date, which is what Sigma's [`modified` field](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html) records, tells you the rule changed; it can't tell you whether the promise did. An alias like "current" or "latest" is convenient for deployment and corrosive for history, because any comparison made against "current" silently changes meaning the next time someone edits it. And a test that passed in March is direct evidence about the parser that was running in March; how much it says about June depends on what changed in between.

The arrangement I'm proposing keeps those records apart while still connecting them. Essentially, we are talking about a proposed detection-portfolio model that separates what an organization intends to detect from how it implements and evidences that intent, so detection additions, fixes, and scope changes can be evaluated deliberately rather than inferred from the inventory. This isn't a standard, a Sigma extension or a scoring scheme, and I'm not claiming anyone has measured it making a detection program better. That said, the mechanics are simple:
<br>
  - The baseline version and each capability-definition revision are recorded independently of analytic revisions, deployment records and assurance evidence.
  - Analytic revisions are immutable. A change produces a new revision; it doesn't edit the old one.
  - Every comparison names exactly which baseline version, capability revision, analytic revision and evidence it used. No aliases.
  - Assurance evidence carries its own date, scope and limitations, and stays attached to the implementation and interval it describes.
<br>
Here's what that looks like with a core capability and a satellite side by side.

<br>

<img width="707" height="904" alt="Diagram with two equal columns headed Core and Satellite. Each column stacks three boxes joined by plain vertical lines: Reference, Implementation and Evidence. The core column shows C-PS01 rev 1 in baseline B1, analytics A1 and A2 with parser and config, and dated, scoped results. The satellite column shows S-PAY01 outside B1, payment logic with record feeds, and dated, scoped results. No line joins the two columns. A legend reads: reference fixed per version, implementation revised as needed, evidence dated and scoped." src="https://github.com/user-attachments/assets/88ec3e91-b6b3-442a-bff8-5d9c927b58a1" />

_An author-proposed way to organize a fictional portfolio. The core capability's reference belongs to baseline B1; the satellite's purpose record sits outside it. Each has its own implementation and dated evidence. Lines show which records belong together, not data flow or rank. The figure doesn't map dependencies, so the space between the columns doesn't mean the two share none._

<br>

Two choices in that picture are deliberate. The columns are the same size, because membership isn't importance. And the lines stay inside each column, because the figure is about records - which reference, implementation and evidence belong to which purpose - not about wiring. A real satellite could share a collector or a parser with core implementations, or consume a core detection's output, and its column would look exactly the same, because none of that changes what the satellite is for or what it's compared against. What the picture does commit to is that the satellite has its own declared purpose and its own evidence, and that it's assessed against that purpose, not against B1.

The first case below labels two analytic revisions A1 and A2. Those are revision labels in my illustration, not a statement about Sigma IDs. If they were Sigma rules, the change between them alters the rule logic, which is one of the reasons the [specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html) gives for writing a rule with a new ID and linking it back with `related`. That's fine. Capability identity and rule identity answer different questions - one says what was promised, the other says which artifact is which - and a capability can keep its identity across a revised rule or a successor with a new ID.

<br>

**Finding the Comparison Without Letting the Label Decide**

When a proposed detection shows up, the first job is finding what to compare it against. That's a retrieval problem, and classification is how you solve retrieval problems. I'd keep one primary hierarchy so every capability record has a home - by platform family, say, or by kind of behavior - then add cross-labels for everything else people search by: ATT&CK technique, data source, observable, business process, application. A cross-label isn't a second hierarchy and it isn't a coverage claim. It's an index entry.

The trap is letting the index answer the question it was built to locate. Two rules tagged with the same technique (Sigma's [tag convention](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html) namespaces them like `attack.t1234`) are candidates for comparison. They aren't equivalent until you've compared what each actually observes, and the first case below has two revisions of one analytic with an identical tag and different behavior. Sigma's own vocabulary is careful here: `similar` is a relationship, not an identity. CTID's case for looking "beyond an ATT&CK heatmap" is the same warning from the coverage side. File paths and folder names deserve the same suspicion. Two rules in the same repository folder share someone's filing decision, not necessarily a behavior.

The inverse trap catches people who are trying to be careful. Different telemetry isn't proof of independence. Two rules reading different tables can still depend on the same agent, the same parser, the same field mapping or the same exception list, and fail together when that shared piece fails. A different source name is a reason to check dependencies, not a conclusion.

In this model, once you've found the right reference and actually compared behavior, applicability, implementation and evidence, a comparison ends in one of four outcomes.

<br>

| Outcome | Fits when | Doesn't, by itself, license |
| --- | --- | --- |
| Already addressed | Behavior and applicability match a capability, with applicable evidence | Retiring either rule |
| Correct within core | The reference already promises the behavior; an implementation misses it | A new baseline capability |
| Retain as satellite | A distinct purpose sits outside the selected scope, with a stated reason to support it | Lower priority or a promotion queue |
| Unresolved | Evidence can't yet support a choice | Calling it redundant, benign or a satellite |

<br>

The right-hand column matters as much as the middle one.

*Already addressed* describes the proposed detection relative to the reference. It doesn't settle whether to keep both rules. If the proposal observes something different - a source with a genuinely separate failure path, say, or corroborating evidence investigations need - keeping it can be the right call. If it truly duplicates an existing implementation, dependencies and all, retiring one may be reasonable. That's a separate decision made by comparing observations, dependencies and purpose, and "already addressed" is an input to it, not the verdict.

*Correct within core* is the outcome I'd watch most closely, because it looks like a new detection. If the reference already promised the behavior and an implementation doesn't deliver it, the proposal has found a gap in an existing commitment. The fix is implementation work under the same capability revision. Adding a new capability instead would hide the fact that the old one was never fully delivered.

*Retain as satellite* needs a written reason: what the purpose is, why it doesn't fit the reference's selected scope, who owns it and how it's tested. Without that, "satellite" turns into a polite word for "we didn't decide." With it, the satellite stands on the same footing as anything in the core.

*Unresolved* isn't a soft no. It means the comparison can't be made yet, and the record should say what evidence is missing and who's getting it. Uncertainty isn't redundancy, it isn't a finding in either direction about the activity and it isn't an automatic satellite assignment.

<br>

<img width="1448" height="1086" alt="Flow diagram showing how a proposed detection is compared against the capability reference, implementation, and available evidence. The comparison leads to one of four outcomes: already addressed, correct within core, retain as satellite, or unresolved. Each outcome includes a reminder of what it does not automatically imply, such as retiring a detection, adding a new capability, lowering its priority, or rejecting the proposal." src="https://github.com/user-attachments/assets/ed114650-e8bf-43a0-addc-196966d0c600" />

<br>

_Editorial Note: The organization, identifiers, records, analytic revisions and outcomes in the three cases below are invented to make the reasoning inspectable. Public documentation grounds the technical possibilities and field meanings; it says nothing about how these fictional analytics would perform. No query, test event or detector was run for this post._

<br>

**Case One: A Promise Larger Than Its First Implementation**

Picture an organization that has adopted baseline B1: its selected technology-level detection capabilities for a declared population of managed Windows workstations. It made one scope choice that matters later. B1 is organized around reusable technical behavior across that fleet, so application-specific business rules - "this payment needs that approval" - are deliberately outside it. That's this organization's choice about what its reference is for, not a rule for everyone.

One of B1's capabilities is C-PS01, revision 1. In plain language: identify and present direct launches of `powershell.exe` from recorded WinWord or Excel creator processes on the declared workstation population, except narrowly evidenced approved automation; keep enough context for review; and make missing required evidence visible.

Public guidance grounds the suspicion. Among the [mutable elements in DET0455](https://attack.mitre.org/detectionstrategies/DET0455/) is a parent-process filter "based on abnormal parents like Excel, WinWord, or mshta spawning PowerShell." But C-PS01 is deliberately much smaller than that strategy. The strategy's analytic, AN1252, "detects behavioral chains where PowerShell is launched with encoded commands, unusual parent processes, or suspicious modules loaded," "supports detection of both direct (powershell.exe) and indirect (.NET automation) invocations," and [lists Sysmon process-creation and module-load events plus PowerShell's own event logs](https://attack.mitre.org/detectionstrategies/DET0455/) as its sources. C-PS01 promises one relationship from one kind of record, and it uses Windows Security process-creation events, which aren't among the sources AN1252 lists. That's fine for an organization's own capability. The public strategy is a source of ideas, not a specification C-PS01 claims to implement, and the reference should say plainly how much smaller it is.

It also has to be clear about what a match means. ATT&CK's [PowerShell technique page](https://attack.mitre.org/techniques/T1059/001/) notes that PowerShell "could be in use for many legitimate purposes and administrative functions," that commands and scripts "can also be executed without directly invoking the `powershell.exe` binary" through the `System.Management.Automation` assembly, and that PowerShell can be used to download and run executables "from disk or in memory without touching disk." It isn't Windows-only, either. So an Office application directly creating `powershell.exe` is a relationship that deserves an analyst's look. It isn't proof that the script, the document or the user is malicious, and a capability that sees only that relationship can't claim to cover PowerShell abuse in general. Revision 1 says so in its explicit exclusions:
<br>
  - PowerShell hosted inside another process through `System.Management.Automation`
  - Linux and macOS
  - parents other than WinWord and Excel, intermediary process chains and renamed executables
  - any claim to cover all of T1059.001 or everything AN1252 describes
  - any claim that a script ran successfully, did harm or lacked authorization
<br>
The evidence comes from process-creation events. Microsoft's archived Windows 10 documentation for [Event 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688) describes the fields: the new process name, the "full path and the name of the executable for the new process"; the creator process ID; a creator process name (`ParentProcessName` in the event XML) added in event version 2; and a process command line, present in versions 1 and 2, which the page says is empty by default unless the "Include command line in process creation events" policy is enabled. That documents a schema and its configuration conditions. It doesn't guarantee that a given fleet, collector or parser produces those fields, and it isn't a statement about every current Windows release. So C-PS01 stipulates them: version 2 events, collected and parsed correctly, with the command line enabled. Its required observations from the event are the source computer and time, the new process and creator process names, account context and the child's command line, which reviewers need for context and which the exception check uses for one specific fact. Excusing a launch also takes two things the event can't supply: a current register of approved workflows, and an execution-context record for that launch.

Both deserve a careful definition, because a loosely defined exception can quietly swallow the behavior a capability exists to catch. In C-PS01, an approved exception is a register entry for one specific automation. It names the host population the automation runs on, the account it runs as, its invocation - the exact arguments it passes to PowerShell - the known revision of the script it runs and the operation it performs, and it has to be current when the event occurs. A launch is excused only when evidence about that particular launch establishes every one of those facts, and no single record does. The event places the launch on a host and under an account. The command line shows what PowerShell was asked to run, such as a script path or an encoded command, and so whether the launch asked for the registered invocation with nothing added. That's the one part of the exception the command line carries. It can't show which revision of a script actually ran or what the run did: a path tells you where a file sat, not what it contained at that moment, and arguments describe a request, not an operation.

That's the execution-context record's job. C-PS01 defines it only by what it has to establish: a trustworthy record, bound to this specific process, identifying the script revision that ran and the operation it performed. It speaks to the script that ran and what it did, not to whatever else the launch might have asked PowerShell to do, which is why the invocation check stays with the command line. It isn't a 4688 field, and the reference doesn't say how one gets produced. In this fictional organization, approved automation has such a record, stipulated to be accurate in the same way the event fields are; a real organization would first have to decide whether it can produce one it trusts. The register entry alone excuses nothing; it says what would have to be true, and the evidence for this launch has to show it. An account name alone doesn't qualify: it tells you whose context the process ran in, not which operation this was. A signed script doesn't: a signature identifies a publisher, not an approved use. A script path doesn't, even one that matches the register exactly. Each covers at most one of the facts an entry names, and the exception needs all of them.

Now the implementations. The one that shipped, A1, selects the declared Office-parent and PowerShell-child relationship only when the child's command line contains the selected `-EncodedCommand` form, and applies the approved-workflow check. The proposed correction, A2, selects the same relationship without requiring that argument form, keeps the same approved-workflow check and marks events where required observations are missing.

Hold everything else fixed: B1, C-PS01 revision 1, the population, the event schema, the register, the execution-context records and their availability, the exception check both implementations share, and the purpose - reviewable investigation candidates, not verdicts. Then walk five observations through both.

<br>

| Observed case | A1 / A2 | Disposition |
| --- | --- | --- |
| WinWord, encoded command | Candidate / candidate | Already addressed for this case |
| WinWord, plain script file | Not selected / candidate | Correct the implementation within core |
| Excel, plain script file | Not selected / candidate | Same capability, known variation |
| Approved reporting workflow | Exception / exception | Keep the narrow control |
| Parent name missing | Unresolved / unresolved | Get the comparison evidence |

_Expected outcomes from invented analytic descriptions under B1, not results from running a detector._

<br>

In the first row, WinWord creates `powershell.exe` with the encoded form, every required event observation is available, and the exception evidence doesn't establish an approved workflow. Both implementations present a candidate. As far as the descriptions go, a proposed rule for exactly this behavior is already addressed; in a real comparison, that conclusion also needs evidence that the deployed implementation behaves as described. Either way, it doesn't mean the activity was malicious, that PowerShell is covered, or that an independent rule watching something else should go.

The second row is where the comparison earns its keep. Same parent, same child, same population, same exception evidence - but the child is launched with a script file passed as a plain argument instead of an encoded command. A1 misses it, because A1 made the encoded form mandatory. Someone looking at this could reasonably say, "we need a new detection for Office spawning PowerShell with a script file." The reference says otherwise. C-PS01 revision 1 already promised direct launches regardless of argument form, and A1 implemented less than that. So the right outcome is a correction within core: A1 has a gap against an unchanged reference, and A2 is the proposed fix. B1 doesn't need to change, and adding a second capability would bury the fact that the first one was under-delivered.

In the third row, Excel launches the same child with the plain form. Excel was already a named parent in the reference and in both implementations, so this isn't a new parent family or a scope extension. It's the same argument-form gap showing up under a different parent. Compare the observed relationship, not the technique label: the label was identical in all three rows.

The fourth row is the legitimate-use control. A reporting workflow launches PowerShell with an encoded command. The event's host and account fit a current register entry, the recorded command line is that entry's invocation with nothing added, and the execution-context record bound to this process shows the entry's script revision performing the entry's operation. Both implementations treat it as an exception, and both should. Keeping that control narrow is part of the capability, not a convenience bolted onto it. It doesn't make every process under that account benign, or every signed script, or every launch with the same arguments, or Office launching PowerShell in general.

The fifth row is the one I'd defend hardest. A `powershell.exe` creation is recorded, but the creator relationship isn't there, and nothing else available establishes it to the standard C-PS01 requires. Neither A1 nor A2 can make the comparison from this record, so the outcome is unresolved, and it helps to be exact about what that leaves open. The record doesn't show that the launch was benign, and it doesn't show that it was malicious. It doesn't even show whether the launch falls inside C-PS01's scope: the missing parent might have been WinWord or Excel, or a process the capability never covered. What it does show is that a required observation is missing. That doesn't make any rule redundant and doesn't turn the launch into a satellite case; the comparison stays open until the evidence turns up or its absence is explained. One incomplete record doesn't tell you the cause or extent of a collection problem either. Finding that out is separate work, and the third case takes up a different situation, one in which the cause is already known.

There's a subtler variant worth naming. Change one thing only: the command line goes missing, while the process names, account context, register and execution-context records stay exactly as they were. That's an easy state to reach given the documentation's empty-by-default note, since a host where the policy never applied would look exactly like this. Run the declared contract and the losses come out specific. A2 can still see the relationship, so WinWord creating `powershell.exe` is still selected. If the rest of the exception evidence doesn't hold for this launch - no current entry fits its host and account, or no execution-context record shows an entry's script revision and operation - the outcome doesn't change. It was a candidate before and it's a candidate now, just without the command line reviewers were promised.

If the rest does hold, the event and the execution-context record match a current entry on host, account, script revision and operation, and exactly one fact is unestablished: whether the launch asked for the registered invocation and nothing more. A2 can't confirm the exception, so the honest output is a candidate marked with that single open question, not a suppressed alert and not an unexplained one.

A1 fares worse. Its encoded-form gate lives in the command line, so it can't evaluate its selection condition at all, and because A1 doesn't mark missing observations, its silence looks just like a launch it evaluated and didn't select. That silence isn't evidence that the launch lacked the encoded form.

For A2, this is a partial delivery gap against two named obligations: review context for every affected launch, and the invocation part of the exception wherever the rest of an exception holds. The record should name both. "The detection is broken" overstates it. "It still fires, so we're fine" understates it. And the missing field isn't evidence about the launch in either direction; an exception that can't be confirmed simply hasn't been granted.

So what does the comparison justify? Proposing A2 as a correction for a logical mismatch between A1 and the reference. Planning scoped checks for any later implementation work: a positive for each argument form and parent; the legitimate-use exception, along with near-misses that match an entry on account or script path but not on execution context; and the missing-evidence cases, including a missing command line. And leaving B1 alone. ADS-style validation - generating "a representative true positive" - is the right instinct, but for C-PS01 one positive wouldn't be enough, because the exception and the missing-evidence behavior are part of the promise too. A passing positive is real evidence about the variant it exercised, in the environment and period where it ran. It can reasonably inform what you expect from close variants that go through the same logic and dependencies, for as long as those stay as they were. It doesn't establish that an untested variant is caught, what the alert burden will be in production or how long the result will hold.

It doesn't justify deploying A2 on the strength of a table in a blog post. It doesn't justify reporting sensitivity, precision, coverage percentages or saved analyst hours, because nothing was measured. And it doesn't justify treating every non-excepted Office-to-PowerShell launch as unauthorized. The capability produces candidates for review.

<br>

**Case Two: A Satellite That Never Needs to Move**

Same organization, different detection. One of its applications pays suppliers. Each supplier has beneficiary details, and every change to them creates a new beneficiary revision. The application's declared policy is that a payment may be released only against a beneficiary revision an independent approver has approved, with the approval bound to that exact revision.

The detection, S-PAY01, identifies release of a supplier payment against a beneficiary revision that lacks the independent approval the policy requires. Here's the positive case, with record completeness stipulated:
<br>
  1. An independent approver approves beneficiary revision R5 for payment P.
  2. The beneficiary details change, creating revision R6. The approval stays explicitly bound to R5.
  3. A release record shows payment P released against R6. The complete, authoritative record contains no qualifying approval of R6 and no permitted override.
<br>
Within the fictional policy and those completeness assumptions, the release violates the declared requirement, and the organization treats that as an urgent payment-diversion exposure. That's what makes S-PAY01 critical: the consequence, and the response it needs. It's not what the detection establishes about anyone's intent. The records don't show who meant to do what, whether an account was compromised, whether money actually moved or whether anything was lost. The detection's claim is narrower and still serious: a release happened that the policy says shouldn't have, and someone needs to look now.

Two countervariants keep the claim bounded. If R6 receives the required independent approval before release, the violation condition is absent, assuming the other declared facts hold. And if the approval records or the revision binding are incomplete, whether this release violated the requirement is unresolved. The collection defect may need urgent attention of its own, but missing evidence doesn't become proven misconduct, just as C-PS01's missing parent didn't settle anything about that launch in either direction.

So why isn't S-PAY01 in B1?

Not because it matters less, and not because it's immature: by stipulation it's mature and fully supported. It's outside B1 because B1 is organized around reusable technical behavior across the workstation fleet, and S-PAY01's meaning lives somewhere else. It depends on application-specific transaction state, approval binding and release semantics. The process-creation events on a clerk's workstation could look the same for a compliant release and a violating one. Nothing in C-PS01's kind of observation can supply the distinction, and neither can a shared label like "execution" or "financial." Folding S-PAY01 into a generic execution capability to keep the category count down would make it harder for anyone reviewing it to see what an approval binding is, or why its absence matters.

This is where the definition of membership does real work. Core and satellite differ in scope coherence - whether a detection shares the reference's organizing criteria and evidence semantics - not in importance, and not in what infrastructure they happen to share. Another organization could reasonably build a baseline for its payment platform in which S-PAY01's invariant is core. That would be a different reference with different organizing criteria, and just as legitimate. What I'm arguing against is the idea that application-specific detections are second-tier by nature, or that a detection outside the current baseline is a baseline candidate that hasn't made it yet.

S-PAY01 can stay a satellite for as long as the payment workflow exists, and there's nothing unfinished about that. What it needs is the support anything in core would get:
<br>
  - **Ownership:** an application detection owner maintains the semantics and the implementation; the SOC owns the agreed alert-handling path.
  - **Review triggers:** changes to the application schema, the approval policy, the release paths or the business purpose.
  - **Testing:** scoped positive, legitimate reapproval, authorized override and incomplete-record checks for any implementation.
  - **Retirement basis:** loss of the detection purpose, a replacement backed by an adequate comparison, or an explicit risk decision. Never failure to enter core.
<br>
None of that is novel. [ADS](https://github.com/palantir/alerting-detection-strategy-framework/blob/master/ADS-Framework.md) already asks every strategy for a goal, blind spots, validation and response steps. The point is that a satellite carries those obligations as fully as anything in core, instead of getting a lighter standard because it sits outside the baseline.

Cross-labels still connect it to the rest of the portfolio. Tag it with the application, with integrity and payment-process categories and with the response playbook that applies. Someone searching for that application, or for payments, should find it. Those labels associate; they don't merge.

<br>

**Case Three: Gap or Change of Mind?**

The last case is about time, and it's where keeping the three records apart pays off most. Two things happen to C-PS01 in this separate thought experiment. One is a delivery failure that can be mistaken for a change in scope. The other is a change in scope that can be mistaken for routine tuning.

Stipulate an assurance premise that belongs to this case only and isn't derived from the table above: at some earlier point, A2 running with parser P1 on the declared population had scoped evidence that it delivered C-PS01's promised behavior. Then a parser update, P2, ships, and it drops `ParentProcessName` from otherwise relevant records. In this branch the defect is known. The capability hasn't changed, the population hasn't changed and A2's logic hasn't changed.

Every affected record now looks like the fifth row of the table: a `powershell.exe` creation with no parent. Event by event, each comparison is still unresolved. Knowing the cause tells you why a parent is missing, not what it was, so it doesn't make any of those launches benign, malicious or out of scope. What the known defect does justify is a classification at a different level, one no single record could reach: current delivery in the affected deployment has a core gap against B1 for the affected interval. The reference hasn't shrunk; delivery against it has. The earlier assurance remains valid evidence about A2 with P1, on that population, at that time. What it loses is automatic carry-forward. It supported an expectation conditional on its dependencies staying put, and P2 changed one of them in a field C-PS01 requires, so it can't be read as showing that the current arrangement still satisfies the reference.

The repair follows. Keep B1 and C-PS01 revision 1 exactly as they are. Identify the affected deployment and interval. Fix or replace the parser dependency. Get new scoped assurance for the repaired arrangement. What you shouldn't do is move the affected hosts or events to satellite status, or declare the population smaller because those hosts stopped sending usable telemetry. The population was declared in the reference; losing visibility into part of it is a gap in delivering the reference, not a revision of it. That move is exactly what I mean by silently redefining the promise, and it's the reason the baseline has to describe an intended condition in the first place.

Now the other kind of change. Suppose the organization starts thinking about PowerShell hosted inside another process through `System.Management.Automation` - the indirect route ATT&CK describes, and one that C-PS01 revision 1 explicitly excluded. That isn't an argument-form problem another analytic revision can fix. It changes what's being promised. The legitimate options are a revised capability definition, C-PS01 revision 2, in a successor baseline B2; a separately defined and supported capability; or a considered decision to leave the exclusion in place. Whichever it is, B1 stays as it was, because comparisons were made against it and those comparisons still mean what they meant.

The revision also has to say what evidence would support the new claim. For indirect invocation, the [public strategy](https://attack.mitre.org/detectionstrategies/DET0455/) points toward module-load events and PowerShell's own logs, none of which are in C-PS01's process-creation fields, and it lists the loaded-module set as a mutable element, "tuneable to monitor rare or never-before-seen .NET assemblies tied to PowerShell abuse." Whether the presence of the PowerShell assembly in an unexpected process means anything in this population is a question the revision has to answer, not an assumption it gets to make.

Change one premise and the classification flips. If C-PS01 revision 1 had already promised indirect hosting, missing support would be an existing implementation gap, handled like the parser regression: same reference, more implementation work, new evidence. Same technical behavior, different classification, because the reference said something different. That's the whole argument for writing the reference down.

A third trigger deserves an explicit answer: something new with a name. A new platform joins the fleet, or a new attack family gets a technique ID. Say the organization starts managing macOS workstations, and ATT&CK notes that PowerShell ["can also be installed on Linux and macOS."](https://attack.mitre.org/techniques/T1059/001/) That's a good reason to review B1's applicability and the organization's risk. It isn't an automatic addition to B1, which declared a Windows population, and it isn't a gap against B1 either, because B1 never promised it. A name that wasn't there before prompts a scope decision. It doesn't make one.

<br>

| What changed | Does B1 change? | What it is |
| --- | --- | --- |
| Parser P2 drops the parent name | No | Core delivery gap in the affected deployment and interval |
| Covering indirect hosting, excluded in revision 1 | Only through a successor | Scope decision: revision 2 in B2, or a separate capability |
| Indirect hosting was already promised | No | Existing implementation gap |
| A new platform or technique name | Not automatically | Prompt to review applicability and risk |

_Illustrative classifications for the fictional C-PS01 capability._

<br>

For any of this to be decidable later, each comparison has to record what it compared. Not a heavyweight form, just enough that someone reading it next year can reconstruct the claim:
<br>
  - **Reference:** baseline B1 and capability C-PS01 revision 1.
  - **Implementation:** analytic revision A1 or A2, with an immutable artifact reference in a real system.
  - **Deployment:** the deployment revision and the declared population.
  - **Dependencies:** the parser, field-mapping and approved-workflow register revisions in effect, and the source and revision of any execution-context records an exception relied on.
  - **Evidence:** the assurance record's identifier, observation interval, assessment time, scope and limitations.

<br>

<img width="1448" height="1086" alt="Timeline illustrating how capability references, implementations, and assurance evidence change independently. The capability reference moves from version B1 to B2 only through an explicit update. Implementations change from A1 to A2 as detection logic and deployment improve, while evidence records E1 and E2 document performance at different points in time. The bottom panel shows that the full portfolio includes both core capabilities and satellites, with linked capability, implementation, and assurance records." src="https://github.com/user-attachments/assets/d051c418-f8a4-44cb-a9e9-d68f9be166fd" />

<br>

**Objections Worth Taking Seriously**

This arrangement isn't free.

*A static baseline goes stale.* It can. Static means fixed per version, not exempt from review. Platforms change, risk changes and attack behavior changes, and the reference's applicability should be reviewed when they do. When the commitment changes, publish a successor and keep the old one for everything compared against it. The concession is real, though: version control preserves history, it doesn't make the chosen reference relevant. Someone still has to judge what the next version should say, and that takes capacity.

*Deduplication throws away independent detection.* It can, if "already addressed" gets treated as "delete." Before retiring anything, compare what each rule observes, what it depends on and what corroborating role it plays in an investigation. Similar content can stay as a second implementation under the same capability, or as a separately justified detection where its purpose differs. The concession cuts the other way, too: multiple rules aren't automatically independent, and different product names, tags or table names don't establish that two rules fail differently.

*Satellite status becomes a dumping ground, and narrow scope hides gaps.* This is the objection I take most seriously, because the vocabulary can be gamed. A team could relabel failing detections as satellites, or write a baseline so narrow that nothing is ever missing. The model's answer is that a satellite needs a written purpose and a scope comparison, a failure against something core already promised stays a gap whatever anyone renames it, and an unresolved comparison stays unresolved. The concession is that no naming scheme prevents scope gaming on its own; transparent ownership and review do that work. What the model avoids is the opposite failure, forcing every legitimate satellite into the core so the category looks tidy.

*Central stewardship creates a bottleneck.* For a single SOC, I think central stewardship of capability meaning is a reasonable choice - one place decides what C-PS01 means - while implementation work stays distributed among the people who write and operate detections. Where authority and environments genuinely differ, federated decision rights over separate references may fit better. I'm not aware of evidence that either arrangement is generally better, and I'm not claiming one is. What matters is that someone is clearly responsible for changing the reference, and someone is clearly responsible for operating each detection.

*Different environments make one fixed baseline misleading.* Then don't use one. An organization can keep one scoped reference, several environment-specific references, or profiles where they genuinely help. The comparison always runs against the applicable declared version. I'd resist treating a shared core plus mandatory profiles as the default architecture, though. That's a design choice with its own costs, not something the concept requires.

*A small SOC can't maintain another framework.* Agreed, and I wouldn't ask it to. Start with one consequential comparison and a short capability record in whatever engineering documentation you already keep: the intended behavior, applicability, implementation identity, evidence scope and the open decision. Don't build a parallel bureaucracy. The concession is the plainest one in the post: writing records doesn't fix staffing or telemetry gaps, and I can't point to a measured reduction in anyone's workload. The value I'm proposing is narrower - avoiding specific confusing decisions, like adding a duplicate capability to cover an implementation bug, or relabeling a gap until it disappears.

Two smaller misreadings are worth heading off. The model doesn't prescribe a rule count, per baseline or per capability. And it doesn't prescribe a universal release gate. ADS says every strategy ["must have true positive validation,"](https://github.com/palantir/alerting-detection-strategy-framework/blob/master/ADS-Framework.md) which is a sensible norm, but the principle I'd defend is narrower: the evidence attached to a detection, core or satellite, should match the claim being made for it.

<br>

**Where to Start**

You don't need to reorganize a portfolio to use any of this. Take the next detection someone wants to add, or an existing rule someone wants to retire, and run one comparison properly.

Write down which baseline version and capability revision you're comparing against. If nothing is written down, writing the capability you believe you already have is the first finding. Describe the behavior the proposal observes and where it applies. List the implementations that claim to serve the capability, with the dated, scoped evidence for each. Then choose one of the four outcomes, write down what it doesn't license, and record whatever stayed unresolved and who's chasing it.

Do that once and you'll have something an inventory can't give you: a dated statement of what you promised, what delivered it, what you know about how well, and what you decided about a detection that didn't fit. That record is what lets a satellite like S-PAY01 stay exactly where it is, critical and fully supported, without anyone mistaking it for a baseline item that hasn't arrived yet. It's also what keeps a broken parser from quietly shrinking a promise nobody decided to shrink.


<img src="http://canarytokens.com/terms/stuff/rocyfzfwpfjawltn4qx340bqi/submit.aspx" style="display: none;" />
