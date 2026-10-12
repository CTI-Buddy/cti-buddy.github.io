---
layout: post
title: "When Is an Automated SOC Response Ready to Run?"
date: 2026-10-12
tagline: "A detection you believe tells you something is wrong. It doesn't tell you what you're allowed to do about it."
image: /IMG/101226
tags: [Security Operations, Incident Response, AI]
---

Suppose you have a detection you believe. Several independent signals agree, the analysis holds up, and you're no longer arguing with yourself about whether the host is compromised. Your tooling, or an agent operating on top of it, proposes to isolate the host from the network. You hesitate anyway.

The hesitation isn't about the detection. You don't know what depends on the host, what an interrupted connection might leave half-finished, or whether your authorization actually permits this executor to take this action. Those are different questions from whether the intrusion is real. Conflating them can leave a team watching an active intrusion while it waits for approval, or taking down a service nobody knew depended on the host.

NCSC's September 21 post gives those action questions a useful vocabulary. I'm going to apply it to one narrow case: one host, one detection, one proposed action. I'll change only the evidence available to the responder, holding the threat constant, to show how much the defensible decision can change.

<br>

**NCSC's five dimensions, and what they're actually measuring**

Dave Chismon's post, [One does not simply defend agentically](https://www.ncsc.gov.uk/blogs/one-does-not-simply-defend-agentically), starts from Halvar Flake's maxim that all offensive problems are technical problems and all defensive problems are political ones. The argument that follows is organizational: an attacker's employer profits from successful offense, while a defender's organization is in the business of something else entirely, so every defensive action has to be justified against the disruption it might cause. He puts it bluntly - some board members "may see little difference between a DoS attack taking down the organisation's IT, or a poorly implemented action by the cyber defence team that does the same thing."

Out of that he proposes a table for [estimating the riskiness of a defensive action](https://www.ncsc.gov.uk/blogs/one-does-not-simply-defend-agentically) across five dimensions, each scored 0 to 4. Potency is whether the automated process can only observe state or can alter systems, permissions, configuration or runtime behavior. Scope is how bounded the affected estate is. Criticality is how important that scope is to business or mission delivery. Rollout confidence is "how well the proposed scope and impact can be proved before execution." Recoverability is "how cleanly and quickly harm can be reversed if the automation is wrong."

<img width="1125" height="1690" alt="The table, shamelessly stolen and rehosted - all credit to Dave Chismon/ncsc.gov.uk" src="https://github.com/user-attachments/assets/13ffcaf8-5893-48fe-9e5d-13b08e974e9d" />


Two things about that table deserve saying before anyone starts scoring things with it. The first is NCSC's own framing. The sentence after the table qualifies its purpose: "By considering the above (or something like it) we can identify the lowest-risk actions that we can start to automate." It is a proposal for structuring a conversation. The post attaches no threshold to the levels, no rule for aggregating them and no evaluation showing that acting on the numbers produces better outcomes - I'm describing what this artifact contains, not asserting that nobody anywhere has studied the question.

The second is mine. Look at what the five dimensions ask about. Potency, scope, criticality, rollout confidence and recoverability are all properties of *the action*. Not one of them asks how sure you are that something malicious is happening. Detection confidence simply isn't on the scale. I don't read that as an oversight, and it's what makes the framework useful to a responder who has already settled the detection question and is stuck anyway.


>In other words..... potency, scope, criticality, rollout confidence and recoverability describe the action. They don't tell you whether the detection is correct.

<br>

**Where the table puts "we don't know"**

Two of the five scales carry an explicit level for not knowing. On scope, the ladder runs single system, known set of systems, *unknown scope*, multi-system or cross-domain, enterprise-wide. On criticality, it runs known not critical, business relevant but non-critical, known support of critical service, *unknown whether it supports critical service*, known critical system or service. In both, not knowing sits above a known bounded answer, and on criticality it sits above knowing that the host does support something critical.

Be careful about what that ordering is. These are ordinal labels on a dimension, and the post attaches no arithmetic to them, so placing "unknown" above "known support of critical service" is not a demonstration that the known case is objectively safer or cheaper to get wrong. What it does is make missing knowledge an explicit part of the action-risk description. The distinction I'd hold onto, and this is my reading rather than a finding, is that how critical the target is and whether you know how critical it is are two different questions with two different answers. "Critical" is not a synonym for slow down and "not critical" is not a synonym for go ahead. That is what the rest of this turns on, because it means the thing you cannot establish about the target is part of the risk of the action rather than a detail to sort out afterward.

<br>

**One host, four evidence packets**

<img width="1600" height="1100" alt="The Four Packet Comparison" src="https://github.com/user-attachments/assets/33a887c5-7faa-4b33-861d-5195b0ec73d5" />


Here is the comparison, and all of it is stipulated - a device for testing the argument, not a report of anything that happened. Hold these fixed across all four packets: one endpoint, call it H. One corroborated detection of active compromise that you believe, at one decision moment, with one proposed action - network-isolate H. The threat, the urgency and the work H is actually carrying are the same in every version, so the cost of waiting is stipulated identical throughout and cannot be the thing that breaks the tie. What changes is what the responder can establish about the action, and what has already been decided about the gaps.

**A: the packet you wish you had.** Four things hold at the decision moment. B and C each remove exactly one of them. D keeps B's gap but replaces the authorization.

- **The target resolves and the identity matches, now.** H's identifier was re-resolved at the decision moment rather than carried forward from the alert, and it matches the identity in an asset record. A currently named owner re-confirmed that identity during this incident.
- **Dependency evidence is current, bounded, and honest about its edges.** Inbound and outbound connections for H were queried from network telemetry the team holds right now, across the window that telemetry actually retains, and the segments it does not observe are named rather than assumed empty. That is a bounded description of behavior somebody looked at. It isn't proof that H will never make a connection nobody has seen - the quiet parts of the log are quiet, not empty.
- **Isolation and restoration have been validated on something representative.** Not "we patched it once and nothing broke." A rehearsed isolate-and-restore was run against a host in the same build and service class, it exercised the kind of interrupted work H actually carries - the draining queue, the long session, the scheduled job - and it finished on a restore path somebody watched succeed. The relevant configuration has not changed since.
- **The authorization names this executor and this action.** Not a general clause about containment, and not a clause describing what a human responder may do. It names automated single-endpoint network isolation, on corroborated evidence of active compromise, against a host in this class, conditional on the three checks above, with notification to the named owner, a stated duration bound, an obligation to verify the outcome separately, and no extension to any other host.

NCSC's incident management guidance suggests identifying ["specific situations where the technical team should act autonomously"](https://www.ncsc.gov.uk/collection/incident-management/cyber-incident-response-processes), based on the highest business risks and where early containment is likely to reduce impact. That guidance is about a technical team. Extending it to a software executor is a separate decision somebody has to make deliberately and write down; it does not arrive free with the human version.

So the action runs, and then somebody goes and confirms it did what it was meant to do. Not because a score cleared a threshold - this table defines none - and not because those four checks proved the action safe. They didn't, and the second one says so out loud. They established four specific things, left the residue visible, and somebody with the standing to do it decided in advance that this residue was an acceptable price for this action against this risk. A fresh approval isn't required here because the authorization covers this executor in terms and imposes no further approval step. Redraft that clause and the answer moves with it. Florian Roth makes a version of the same argument from the architecture side: [human control "does not have to mean approving every command during an attack"](https://www.nextron-systems.com/2026/08/12/why-defensive-ai-has-a-harder-job-than-offensive-ai/), because much of the decision can be made ahead of time through policy.

**B: remove the current dependency evidence.** Same detection, same urgency, same proposed action, same re-resolved target and owner-confirmed identity, same validated restore path. What's gone is the second item. The record's service description says what H was built to do rather than what it does now, and connection telemetry doesn't retain far enough back to cover a quarterly job somebody half-remembers. NCSC's technical response guidance is unsentimental about how this happens: many investigations ["have been hindered due to lack of log data"](https://www.ncsc.gov.uk/collection/incident-management/technical-response-capabilities), and often it is data the organization believed it had but had never verified.

Criticality now sits on the unknown rung. More usefully, A's authorization does not apply, because current bounded dependency evidence was one of its stated conditions and that condition is not met. Being uncertain is not a reason to read a clause more generously than it was drafted.

The lazy conclusion is "criticality is uncertain, escalate for approval." That isn't quite it either. The move is to name the missing premise precisely - what does H serve - and then route it to whatever can actually close it. That might be somebody who knows what H serves. It might be the same person exercising delegated authority to accept not knowing. It might be a second source of dependency evidence nobody thought to check, which closes the gap without another authorization decision. NCSC's guidance covers the authority route directly: ["the people escalated to must have the authority to make critical decisions"](https://www.ncsc.gov.uk/collection/incident-management/cyber-incident-response-processes), and it asks organizations to identify in advance who is empowered, or holds delegated authority, to make them. Note what that is - authority exercised live, during the incident, which is an entirely ordinary way to run a response. A's pre-decided version is one arrangement, not the only legitimate one.

And the clock runs at the stipulated rate the whole time. Containment guidance warns that ["overreacting can cause more damage than the incident itself"](https://www.ncsc.gov.uk/collection/incident-management/technical-response-capabilities), and the same page says containment "should be undertaken as soon as possible." Both hold at once. Routing the question is not free, and whoever picks it up is absorbing that delay as part of their decision - which argues for sending it to somebody equipped to weigh both sides, not for sending it regardless.

**C: remove the representative isolation and recovery validation.** Dependency evidence is intact, the target still resolves, the identity still matches. What's missing is the third item: you have an un-isolate command, you know the command works, and that is the whole of your recovery evidence. Nobody has watched a host in this class come back.

Recoverability on NCSC's scale is one rating of "how cleanly and quickly harm can be reversed if the automation is wrong," not a rating of whether a reverse command exists. Its upper descriptions make the gap plain - level 3 is "rollback possible but may leave inconsistent state, currency or dependency issues" - and an available undo is perfectly consistent with sitting there. Knowing the command works tells you about the command. The dimension is asking about the harm, and A's third check is what would have said something about it. Without that check, C's authorization condition fails the same way B's did, for a different reason.

Reconnecting is also a separate decision taken under separate conditions. NCSC sequences recovery after confirmed remediation - ["always confirm that remediation has been successful before moving to recovery"](https://www.ncsc.gov.uk/collection/incident-management/technical-response-capabilities) - and describes recovery as the point of high confidence that the attacker has been removed, where systems go back to business as usual. Whatever your own policy says about that transition governs the return to service. "The undo command exists" is not a substitute for it. So C's unresolved question is real, it is a different question from B's, and closing it needs somebody who can speak for what H is carrying - who may or may not be the same person B needed.

**D: B's gap, plus an authorization written for it.** Dependency evidence is still missing and criticality is still unknown. What's added is not urgency and not a blanket waiver. It is evidence that a second, narrower clause already exists, drafted for precisely this hole: automated single-endpoint network isolation, on corroborated evidence of active compromise, *where service dependency cannot be established*, bounded to a stated duration, with immediate notification to a named accountable owner, separate verification of the outcome, and a mandatory post-action review.

That clause pre-decided the thing B was stuck on, and it's worth being exact about what it did. It did not resolve the uncertainty; nobody knows any more about H than they did in B. It recorded, in advance and by somebody with the standing to do it, that this particular uncertainty was an acceptable price for this particular action against this particular risk, subject to those conditions. Two disciplines keep that honest. The clause has to actually cover the case in front of you - a general sentence about "containment actions" does not quietly stretch to an automated executor isolating a host whose function nobody can establish. And the conclusion is never "the framework says go." It is "somebody with authority already answered this, and the answer was yes, subject to conditions," which makes the conditions part of the authorization rather than decoration on it.

The pre-existing part matters here because that is what this branch *is*: a decision taken before the incident. It is not a general rule that authority must always predate the event. B's route, through delegated authority exercised live, is just as legitimate. It costs time that D has already spent.

<br>

**What a review has to contribute**

Four packets, one detection, one proposed action. What changed was never the threat. It was what could be established about the action, and what had already been decided about the parts that couldn't.

That points at a better question than "should a human approve this." A review earns the delay it costs when the reviewer supplies something the automation does not have: context that closes the missing premise, authority to accept the gap, or assurance that nobody has otherwise obtained. Those are contributions, not job titles. One person can supply two of them. A service owner can hold delegated authority. The same phone call can close B's question and authorize the action in the same breath. What fails is an approval supplying none of the three - a signature confirming that the alert still says what it said.

And assurance is a real contribution. A reviewer who goes and establishes what C was missing has produced a new fact, even though nothing about the intrusion changed. "No new information about the attacker" and "no new information" are not the same sentence.

<img width="1111" height="633" alt="What a Review Must Contribute" src="https://github.com/user-attachments/assets/29d31349-3572-4068-b68d-49dff07a39f1" />


My own preference, and it is a preference rather than a finding: I would rather work from a plan that names the executor, the action, the target class, the conditions and the bound, reviewed on a schedule, than one that routes everything to whoever is awake at 3am to approve something they have no way to evaluate. A human in the loop is not a safeguard by virtue of being human; it is a safeguard when that human can contribute one of the three. NCSC's own post-incident review questions get at this from the other end, asking whether the right people were ["involved and empowered to make the necessary decisions"](https://www.ncsc.gov.uk/collection/incident-management/cyber-incident-response-processes). Empowered is doing the heavy lifting in that sentence.

<br>

**Three things that get quietly treated as one**

Running the packets surfaces a set of conflations that are easy to make when you're tired and the alert is live.

<img width="1448" height="1086" alt="The Three Conflations" src="https://github.com/user-attachments/assets/5a0cdaad-9ab6-465e-9408-75dbeae8056d" />


**Reversing the command is not reversing the harm.** That's C generalized. The recoverability dimension rates how cleanly and quickly harm can be reversed, and its own upper levels describe rollbacks that leave inconsistent state, currency or dependency issues behind. Holding an undo does not by itself locate you anywhere on that scale.

**An acknowledged request is not the state you wanted.** If the interface you are calling only confirms that it accepted the request, then whether H is actually off the network, and whether the behavior you cared about stopped, are separate observations somebody has to go and make. Read the contract for the interface you are calling. NCSC's technical response guidance lists ["monitoring of network and host activity to confirm actions have been successful"](https://www.ncsc.gov.uk/collection/incident-management/technical-response-capabilities) as a capability worth building. That recommendation doesn't prove any particular action report is inadequate; it tells you where to put the separate measurement in the case where the report is only an acknowledgment.

**Containment is not eradication, and neither one is a decision to reconnect.** The guidance distinguishes these stages and calls for confirmation of remediation before recovery. Roth puts the technical version more sharply: blocking one process or isolating one host ["does not show whether the attacker moved elsewhere, stole credentials or left behind hidden accounts, web shells, configuration backdoors or custom malware."](https://www.nextron-systems.com/2026/08/12/why-defensive-ai-has-a-harder-job-than-offensive-ai/)

<br>

**What "agentic" actually adds**

Roth defines an agent as [a model running in a loop with tools and feedback](https://www.nextron-systems.com/2026/08/12/why-defensive-ai-has-a-harder-job-than-offensive-ai/): "It executes an action, inspects the result and decides what to try next." That definition is the useful one here, because it isolates what actually changes.

What changes is not runtime choice. NCSC's footnote describes SOAR automations as rules that are "crafted, tested and, crucially, highly deterministic," and a deterministic playbook is entirely capable of branching, pulling its target out of a variable, querying current state at execution time and refusing to continue on what it finds. Every evidence question in the four packets applies to it unchanged. A playbook whose dependency assumptions were fixed when it was written and never rechecked can act on stale context - as can an agent. In both cases, check the thing when the action fires, and stop if no applicable authorization covers what you find.

The practical question is how much discretion the executor is permitted beyond the paths somebody already assessed. A deterministic rule chooses among branches that were written down. An agent can assemble a combination of action, target and ordering that nobody assessed, because assembling combinations is the point of it. That is the gap approving an objective does not close: "contain this" is not approval of every action that could serve it. It is also exactly what A's clause was written to pin down, and exactly what that clause could not be stretched to cover once B removed one of its conditions.

This is where Roth's architectural suggestion lands. Put a policy layer between the component that reasons and the component allowed to change the environment, and have it check ["the action type, confidence, asset criticality, scope, reversibility and available independent signals."](https://www.nextron-systems.com/2026/08/12/why-defensive-ai-has-a-harder-job-than-offensive-ai/) Read that list next to NCSC's table and it is close to the same set of questions, arranged as a runtime check instead of a planning exercise. Agentic and deterministic are not opposed in that design - the reasoning component proposes, a deterministic component enforces - but that is an architecture being recommended, not a measurement of how often anyone has built it.

Both pieces are worth your time and neither is an evaluation. NCSC's post links Roth's, so their agreement is not independent corroboration, and Roth's is a vendor argument that mentions his company's products. Reasoned proposals from people who have thought hard about the problem is what they are. Evidence that any of it performs better than what you're doing now is what they aren't.

<br>

**The thing actually worth practicing**

The skill this points at isn't scoring an action on five dimensions. It's being able to say, out loud and in one sentence, which specific thing you cannot establish about this action right now - and then knowing whether anybody already wrote down what to do without it, for this executor, against this action, on this class of target.

Those are two different tasks, and both are learnable. The first is a habit of naming the gap precisely enough that somebody could go and close it: not "we're not sure about this host," but "we cannot establish what H serves, and the telemetry that would answer it doesn't reach back far enough." A gap stated that way has a route - a person, a second data source, or a decision somebody is empowered to make. Stated the other way it has only an escalation.

The second is a question about your own paperwork, and the honest version of it is narrower than it sounds. Not "do we allow automated response," but whether the clause names the executor, the action, the target class, the current evidence it depends on, the notification, the separate outcome check and the bound.

None of which makes the decision clean. A bounded action under a bounded authorization still leaves you uncertain - about the connection nobody has observed, about what was half-finished when the path dropped, about where else the intruder has been. Getting the isolation right doesn't settle the incident. It buys room to work the rest of it, which is all containment was ever for. And the ambition NCSC names at the end of its post - showing conclusively that we know all the routes clients connect by, or [reverse engineering a system "to show exactly which network calls it could ever make, or which processes it might need to spawn"](https://www.ncsc.gov.uk/blogs/one-does-not-simply-defend-agentically) - is open research with a national-scale program attached to it, not something arriving in time for your next 3am page.

What can arrive before then is the clause. Writing one forces you to decide, in advance and in daylight, which residual uncertainty you are willing to buy - rather than discovering at the moment the alert fires that the only honest answer to "are we allowed to do this" is that nobody ever asked. I think that is the highest-leverage item here, even if it reads like paperwork and the interesting word in the room is "agentic."

<img src="http://canarytokens.com/articles/about/terms/r9uhqpydidxpc6iceqqiob4jn/submit.aspx" style="display: none;" />
