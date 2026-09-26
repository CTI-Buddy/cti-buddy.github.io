---
layout: post
title: "What Actually Changes Hands When a SOC Case Escalates?"
date: 2026-09-20
tagline: "An assignment-only record can't tell you whether the team asked for help or handed over the case"
image: /IMG/090726.jpg
tags: [Security Operations, Human Factors, Incident Response]
---

Check what your case system actually writes down the next time somebody escalates. If all it captured is a field changing - the assignee moves from one name or group to another, or a tag flips - then you know something moved. You don't know what kind of move it was.

At least two different events can hide behind that field change. One is a request for help: I need somebody who knows this system to answer a specific question so I can keep working my case. The other is a request to take over: the next phase belongs to your team, please own it. They have different consequences for who chases the next decision and who is supposed to notice at 4 a.m. that nothing has moved in six hours.

Your workflow may already carry that distinction in a request type or a linked record, perhaps with receiver confirmation before the assignment changes. If it does, you already have much of what this post is arguing for. Where the record shows only the assignment, it can't tell the two apart.

The part that hurts is the gap between raising the escalation and somebody agreeing to it. In that gap a case can have a name on it and nobody behind the name. What follows is a proposed way to close it: distinguish the two request types and make coordination explicit while a request is outstanding, including across a shift change. I'll give both arrangements their strongest form, because the cases worth arguing about are the ones where either could be right.

None of the public sources here offers a controlled comparison of SOC case-ownership models, and I'm not offering one either. The costs I attach to each arrangement are judgments about risks, not measured results. The last section proposes a local trial.

<br>

**Three things "escalate" can mean**

The word does three different jobs. Collapsing them is where the trouble starts.

The first is a technical task. Somebody with different access or subject knowledge does a piece of analysis. The FIRST CSIRT Services Framework names this function [detailed analysis coordination](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1), whose stated purpose is to "initiate and track any other technical analysis" when experts elsewhere will do that analysis. It sits inside the incident analysis service, which the framework scopes to a confirmed incident. I'm borrowing the principle rather than claiming FIRST applies it to an alert nobody has qualified yet.

The outcome of that function is a list of pending analysis, held from the viewpoint of the handler coordinating the response. Delegating the work does not delegate the tracking.

The edition I'm quoting is the HTML version 2.1, which the page labels as being for review purposes. Its opening section says the framework [does not look at implementation](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1) or propose a specific way to implement any particular service, and makes no suggestions about capability, capacity, maturity or quality. It identifies the coordinating function and what it produces. It won't tell you who does it in your SOC at 2 a.m.

The second is case coordination: keeping the case moving, with current status and a record of findings and actions that somebody is due to check. The UK NCSC calls for a [central point of coordination](https://www.ncsc.gov.uk/collection/incident-management/creating-incident-response-team). The person holding it "need not be a cyber security expert"; their job is to keep track of actions and findings, correlate them and make sure the right people are told. FIRST separates this out too, as [activities coordination](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1), whose purpose is to track the status of all communication and activities.

Coordination is not seniority. It doesn't confer the right to overrule the specialist's technical judgment or approve containment. It's a function rather than a new post: on a quiet shift, the analyst working the case can coordinate it, and no new supervisor appears. The Google SRE chapter on incident management argues that [clear separation of responsibilities](https://sre.google/sre-book/managing-incidents/) gives people more autonomy, since they don't have to second-guess colleagues. It also reserves system changes for the operations role. In the arrangement I'm proposing, coordination keeps progress visible and makes sure somebody follows up.

The third is decision authority - who may approve an action with real consequences. NCSC requires that the people escalated to [have the authority to make critical decisions](https://www.ncsc.gov.uk/collection/incident-management/cyber-incident-response-processes) when a decision may cause major business impact, with deputies so the decision can still be made when the primary contact isn't there. Authority comes from your organization's policy. It does not come from a ticket field.

A queue field tells you where the case has been routed, whether a rule did it or a person did. On its own it isn't the receiver's answer. Accepting a task isn't accepting a case, and copying a role into a ticket confers no managerial or legal authority that person didn't already hold.

FIRST does describe acknowledgment, but of a different thing: its intake function has the receiving team report an initial acknowledgment to whoever submitted a report. That's a receipt, running from receiver to sender. Treating a receiving team's agreement to coordinate as its own recorded event is my rule, not theirs.

This isn't a call to argue about RACI letters. All three functions can sit with one person on a quiet shift, and often should - NCSC allows that, provided the responsibilities are accounted for and available. They can also be split by policy, with coordination held at a level that can convene people and technical judgment left with the specialist. The SEI's second lesson is that [no one organizational structure fits all](https://www.sei.cmu.edu/blog/10-lessons-in-security-operations-and-incident-management/) teams. Where the work sits in separate units, those units have to work out who performs what role. Either shape is workable. Leaving it unstated until the case is underway isn't.

<br>

**What the public guidance covers, and what it leaves to you**

Coordination needs cover when the person holding it isn't available. NCSC says to [always provide for deputies](https://www.ncsc.gov.uk/collection/incident-management/creating-incident-response-team), and that you may need more than one person in-house capable of each key role, specifically naming leading and coordinating the response.

Some of the guidance reaches into the triage queue. FIRST's event analysis service includes a [correlation function](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1) that groups potential incidents pertaining to the same assets or identities so they're handled together instead of twice. Detailed analysis coordination sits inside the analysis of a confirmed incident. Applying that coordination principle to routine workflow is the adaptation here.

Qualifying something as an incident is one call, made against your own definition and criteria; FIRST's qualification function is where a triage queue makes it. Activating major-incident command is a separate call under your policy. A case can be an incident by your definition without anybody standing up a command structure over it.

These sources differ in how far into implementation they go. FIRST explicitly leaves it out. NCSC and the SRE chapter offer practical procedures: NCSC covers deputy arrangements and contact methods, while SRE describes an outgoing commander making an explicit handoff. The SEI's lessons, drawn from [more than 35 years of capacity building](https://www.sei.cmu.edu/blog/10-lessons-in-security-operations-and-incident-management/) with response teams, address how you structure a capability. The third tells teams to [define their interactions](https://www.sei.cmu.edu/blog/10-lessons-in-security-operations-and-incident-management/) with other groups, down to "inputs, outputs, mechanisms, triggers, time frames, and POCs", and institutionalize those in standard operating procedures. The fourth calls for documenting and institutionalizing process so operations remain resilient when staff move on.

None of these sources sets out a case-level record for this particular decision or puts the two arrangements side by side. This isn't a discovery or a claimed hole in the literature. It's an adaptation small enough to use on a moderate-severity case.

The SEI's list of common problems from its capability evaluations includes duplicate or redundant functions and undefined roles and responsibilities. The problems listed are organizational rather than technical. Those are practitioners' experiences across evaluations, not a prevalence survey; they don't tell you what share of teams has each problem.

The Google SRE chapter needs a different limit. Its first guideline for declaring an incident is [whether you need to involve a second team](https://sre.google/sre-book/managing-incidents/) to fix the problem. The author introduces those guidelines as his team's practice, and the chapter is about outages. Transplanting that threshold into every SOC would put incident command around ordinary specialist escalations, which isn't a claim the chapter makes. I'm borrowing its handoff practice and separation of roles.

<br>

**The case for handing over the whole case**

Whole-case transfer deserves its due. When the next phase belongs to the receiving team, it's the right answer.

Suppose the remaining work is host forensics on a managed endpoint. The endpoint team has the acquisition tooling and authority to isolate, and its mandate and coverage include the remaining response. They'll also be talking to the system owner. Keeping somebody else in place to "coordinate" that work may be mostly friction. Let them hold it.

Transfer also removes a category of ambiguity: afterward there's one coordinator, and the question "who chases this" has a boring answer.

FIRST supports the routing half of that, describing report triage that may conclude a case should be [forwarded to the entity responsible for handling it](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1) when the receiving team doesn't provide services for the identified target. That tells you where the case ought to go. It says nothing about the next team having agreed to take it.

There are costs to weigh. The receiving team has to pick up context the originating analyst already had. Where the case record doesn't carry the earlier checks or the user's account of what happened, detail can go missing. Unless something routes the outcome back, the analyst who raised it may never learn whether their read was right. To me, that's a potential tax on triage quality worth checking for.

And transfer relocates coordination rather than deleting it. The receiving team still needs somebody covering the case across its shift boundaries, with responsibility for deciding when it closes.

Before reaching for transfer, check that the receiver's mandate covers all the remaining work and that it has the necessary authority and coverage. A team that can answer the host question but holds no mandate over the identity thread is not a home for the whole case. Then get agreement: sending a transfer request is still only a proposal until the receiver accepts it and confirms when it takes effect.

<br>

**The case for keeping the case and asking a question**

The alternative is to keep the case, delegate a bounded technical task and track it as an outstanding item until the answer lands.

This fits when the specialist question is one thread of several. You might be waiting on a user callback while checking whether a second account shows the same pattern. Asking the endpoint team one question about one host doesn't give that thread ownership of the whole case. Somebody has to hold the picture. For a confirmed incident, FIRST's detailed analysis coordination function describes that division of work. Its stated outcome - a tracked list of pending analysis, held from the coordinating handler's viewpoint - is the artifact a shift lead needs.

The specialist also receives a smaller commitment. A bounded request names the data to examine and the output wanted. Ask what the activity on this host supports and what it makes unlikely on the evidence available, with a statement of what would settle the remaining uncertainty. That's work somebody can agree to return inside a shift. "Here, own this" is a bigger thing to say yes to.

A properly accepted transfer still defines what completion looks like and what the sender retains. The difference is how much the receiver agrees to carry, not whether the work has an agreed end.

Retaining coordination has costs too. Status can become dependent on one person's attention, and when that person is also carrying a triage queue, the case may wait on them rather than on anybody's analysis. Repeated bounded questions interrupt somebody else's focus; several across a shift can cost a specialist more than one transferred case would.

Coordination also has to be trained and covered, which is the practical force of NCSC's insistence on deputies and on more than one person capable of the role. And without discipline you can end up with two people who both believe they're tracking the case, the duplicate-function problem in the SEI's list.

Neither arrangement is the sophisticated one. Choose what fits the case in front of you. Whether that should become the default for a recurring request type is something you can assess locally, which is what the last section is for.

<br>

**One case, two arrangements**

_Editorial Note: the case below and every variant are invented for this post. They contain no customer or product details, query logic or indicators. The clock times put a shift boundary in the story; none is a service-level target or a measured result._

The evidence is the same in both branches. An alert on a user account shows a sign-in pattern that doesn't match that account's history. A separate endpoint alert fires on the same user's laptop inside the same window. The analyst has confirmed the sign-in is anomalous against the account's own baseline but hasn't established whether either activity caused the other or the alerts are unrelated. Settling that needs somebody who knows the endpoint tooling and data. It's 02:10 and shift change is 04:00.

In this invented organization, local policy puts the case under the ordinary response process at this point, with no major-incident command activated. That isn't a finding about how these alerts would qualify in yours. Severity remains a live judgment against your own criteria as the evidence changes.

Grouping the alerts isn't the decision being compared: FIRST's correlation function already groups potential incidents pertaining to the same identity for combined qualification. What changes between the branches is what the receiving team can take on.

**Branch one - bounded assistance, accepted.** The analyst raises an assist request naming the host and window. It separates what's known from what's uncertain and links both alert records. The output requested is an assessment of what the host's process activity supports and makes unlikely, with the evidence needed to settle the rest.

The case stays with the SOC, and the record says so. Coordination sits with the on-duty SOC shift lead, reached through the duty line rather than a personal number. NCSC similarly advises holding [two or more contact methods and contacts for multiple people or a group](https://www.ncsc.gov.uk/collection/incident-management/cyber-incident-response-processes) for key contacts.

At 02:35 the endpoint on-call answers by name and accepts a specific task: this host, this window, analysis only, with a written assessment of the process tree back by 03:15. Acquisition and isolation are outside that accepted scope. Either would require the applicable authorization and a scope change agreed by both sides. The documented urgent path below is the exception; an interesting finding isn't permission to expand the task.

Coordination hasn't moved. The SOC shift lead still follows up and remains the business unit's contact, responsible for deciding what the answer means for the rest of the case.

**Branch one, the other way - declined.** Rewind to 02:10 and send the same request, except that this time nobody picks it up. The 03:15 checkpoint arrives with nothing back and no acceptance. The entry is: no answer yet, checked at 03:15 by the shift lead. Nobody has declined anything. Inventing a refusal time to fill a field is how a record starts lying.

The shift lead calls the endpoint duty lead, who says their on-call is committed elsewhere and can't take this tonight. Now there's a decline: the endpoint duty lead declined at 03:22. Record the reason and a pointer to the call log or message where they said it. That isn't an appointment for the morning, because nobody has agreed to a start time.

The shift lead then records a covered next plan. It could be a narrower question the on-duty team can answer from data it already has. Alternatively, agree a specific window and named person with someone who can commit to them, or escalate the staffing gap rather than the case.

The original request remains declined while the underlying work stays unresolved, visibly, with the SOC coordinating it. An assignee-only record can't express that distinction.

**The 04:00 boundary.** This applies to whichever thread is still open when the shift ends. Coordination moves through an explicit handoff to the incoming shift lead, who confirms it. The outstanding request or re-scoped plan is updated so the endpoint team knows who they're talking to. Being next on the roster is not acknowledgment of the case. The SRE version has an outgoing commander stay on the call until receiving firm acknowledgment, then tell everyone else who's leading.

If nobody has acknowledged - whether there's no successor rostered or the rostered person hasn't picked up - the duty lead arranges cover under the existing deputy policy before the outgoing lead signs off. NCSC calls for deputies when a key person is [unavailable or needs a break](https://www.ncsc.gov.uk/collection/incident-management/creating-incident-response-team) during a long response.

An outstanding request shouldn't trap somebody past their shift. Nor should the clock leave the case without a coordinator. Arranging cover is the duty lead's job.

**Branch two - whole-case transfer, accepted.** The evidence is unchanged at 02:10. What's different is the receiving team. Here, the endpoint group is a full IR function whose agreed mandate includes identity follow-up on a case it holds. It runs its own out-of-hours coverage and holds authority to isolate. The proposed transfer covers the host analysis and identity thread, along with the user callback and the decision about when the case closes.

The request names the receiving duty role and the decision that needs making, with the evidence attached. It explicitly requests the transfer of case coordination. At 02:40 the endpoint IR on-call confirms acceptance by name and duty role, effective now.

That effective time matters. A commitment to pick up the case at 08:00 is a scheduled transfer; coordination stays with the SOC until the transfer is confirmed as effective.

From 02:40 the receiving team coordinates. The SOC lead no longer chases the case or acts as its business contact, and stops keeping a parallel follow-up schedule. Anything the SOC retains is a named task. Here there's one: the SOC already left a callback with the user and will pass whatever comes back to the new coordinator.

The receiver can take the whole case because its mandate and authority cover the remaining work, with coverage to carry it. Owning the tooling for the largest technical question wouldn't be enough. If this team could speak only to the host, the identity thread would be left unowned by a whole-case transfer.

**The boundary that overrides both branches.** If the sign-in were confirmed as an active compromise and cutting the session sits inside the applicable standing authority, the authorized responder acts now. That doesn't wait on an acceptance record. NCSC recommends identifying in advance the [situations where the technical team should act autonomously](https://www.ncsc.gov.uk/collection/incident-management/cyber-incident-response-processes), where early containment is likely to reduce impact. FIRST's containment function covers short-term measures to limit further harm.

Nothing here grants authority. If the action is outside what the person on shift is authorized to do, use the existing approver or documented deputy path. The record catches up afterward; authority doesn't move through it.

<br>

**When the answer is bigger than the question**

An accepted assist can grow beyond what anyone agreed to carry.

Back in the accepted-assist branch, the specialist returns at 03:10 with more than was asked for. The process activity on this host is consistent with credential access, they say. Records already supplied for that analysis show the same process pattern against two other hostnames. They haven't investigated those hosts. Nobody has. This is an indication that two more machines may be involved, not a finding about them.

What was accepted covered one host and one window. Now there's a question that may be multi-host and may change the severity. The failure mode is an unspoken expansion: the specialist follows the new thread while the shift lead continues tracking the original task. That can grow into a substantial investigation nobody explicitly accepted.

A material scope change needs a fresh decision, starting with impact and priority. Assess the possible change in severity and affected parties against local criteria, including the authority needed for the next action. If those criteria call for authorized urgent action, take that path immediately. It doesn't wait for agreement on an amended scope.

Otherwise, there are two legitimate outcomes. Amend the assist: the receiver agrees to the new task scope and checkpoint, while coordination stays where it is. Or decide that the case now belongs with the receiving team and use the accepted-transfer path, confirming when it becomes effective. Until one is agreed, the specialist works within the accepted scope.

Scope growth alone doesn't move ownership or activate command. It can meet existing escalation criteria, in which case that policy applies.

You can write some triggers down in advance. NCSC includes [escalation criteria and a process for critical decisions](https://www.ncsc.gov.uk/collection/incident-management/cyber-incident-response-processes) in a basic response plan, with severity and category matrices to help determine the response and who needs to be involved. Additional hosts or identities can prompt reassessment. So can a confirmed credential-access finding, or a next step needing authority the current owner doesn't hold. Put those in a written list of conditions for reconsidering the scope. Somebody still has to notice the change and say so.

<br>

**A record that names what changed hands**

Here's the artifact. It's my design, not a requirement from FIRST, NCSC or anybody else. It needs to be small enough to complete during a shift. A record nobody fills in is worse than no record at all - it looks like coverage. If your platform already captures scope and attributable receiver confirmation, reuse those fields instead of adding a parallel set. The point is to distinguish the states, not duplicate the interface.

| Field | What it's for | Example entry |
| --- | --- | --- |
| Case reference | Ties to the case you already have. No new ID scheme. | Existing case ID |
| Request type | Distinguishes an assist from a transfer. One or the other, never blank. | Assist |
| Coordination held by | Current coordinating role and acknowledged on-duty holder, with a duty contact. A roster entry alone isn't a handoff. | SOC shift lead, named; duty line |
| Asked of | Who received the request. A duty role is fine if that's all you have. | Endpoint on-call |
| Decision needed | The specific question or decision, and the output wanted. Difficulty stating it is a reason to clarify the request. | What does the process activity on this host support, and what would close the rest? |
| What's known | Current finding, with its uncertainty intact. | Sign-in anomalous against this account's own history |
| What's unknown | The gap the request is meant to address. | Whether the endpoint alert relates to the sign-in at all |
| Evidence | Links into the existing case record. Keep secrets out. | Case timeline and both alert records |
| Acceptance | Receiver decision, with identity, time and confirmation reference. If no answer yet, record the sender's check separately from any receiver decision. | Accepted 02:35; named endpoint on-call; confirmation reference |
| Scope and checkpoint | Current agreed scope and output. For an assist, the review time; for a transfer, the confirmed effective time for coordination to move. | This host and window; analysis only; written process-tree assessment by 03:15 |
| Chase and fallback | When the coordinator follows up, and who they call if there's no answer. Passing a checkpoint doesn't reject or close anything. | 03:15; endpoint duty lead |

Request type identifies which commitment was sought. Acceptance distinguishes the receiver's accepted or declined decision from no answer yet. In that last state, the identity and time belong to the coordinator's check, not an invented response. "We sent it" is never acceptance.

The receiver doesn't need write access to your case system. If they can't update it, whoever is authorized to keep the record writes down what was confirmed, by whom and when, with a pointer to the call log or message. Attributable confirmation is the requirement, not a permissions project.

Scope and checkpoint describes the currently agreed work. For an assist it sets when the task gets reviewed, not when coordination expires. For a transfer it records when the accepted change becomes effective. A case stays with its coordinator until that effective transfer is confirmed or a covered successor acknowledges the handoff. Accepting an assist doesn't move it.

Explicit handoff acknowledgment is established practice. The SRE chapter has the outgoing commander [not leave the call until receiving firm acknowledgment](https://sre.google/sre-book/managing-incidents/), then communicate the change to everyone working the incident. This record adapts that practice to routine cases and distinguishes two request types that an assignment-only record renders identically.

<br>

**Six rules for the gaps**

The worked example can be reduced to six rules for use alongside the record.

**An outstanding request doesn't move coordination.** The current coordinator keeps it until an accepted case transfer is confirmed effective or a covered successor acknowledges the handoff. Accepting an assist doesn't do that. The duty role continues through an acknowledged shift handoff, not an automatic roster change.

**A decline and silence are different states.** Record silence as no answer yet, with the coordinator's check time and fallback. A decline needs an actual receiver response, named and referenced. The coordinator arranges a covered next step: a narrower task, or a specific window agreed with someone who can commit to it. Where neither is available, escalate the staffing gap. Keep the original request's decline distinct from the unresolved work behind it.

**Shift handoff needs an acknowledged successor.** An outstanding request doesn't travel home with the departing person. The successor confirms, and the specialist team is told who now coordinates. If nobody confirms, the duty lead arranges cover under existing policy before sign-off. The answer is neither an indefinite extension of the outgoing person's shift nor an unowned case.

**Urgent response follows existing authority.** Authorized urgent action doesn't wait for routine paperwork. Outside standing authority, use the approver or documented deputy path. An acceptance record supplies no extra permission.

**Declared major incidents follow your command policy.** Case coordination reports into that structure or hands over as policy requires; it doesn't become a second command chain. FIRST describes a crisis in which a high-ranking role takes responsibility and [the usual line of command changes](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1). It also requires a decision about whether other open work continues or is set aside, and communication of that decision.

**A completed transfer ends the former owner's coordination.** The sender stops chasing the case and being its business contact, without keeping a parallel coordination schedule. Write down any retained task. "Staying across it" is not a role. Decision authority is unaffected; it never moved through the ticket.

<br>

**How you'd find out this is wrong**

Here's the trial I'd propose. It has not been run; these are proposed measures, not results.

Pick one recurring specialist-request type - the same question your team asks the same other team most weeks. Compare bounded assistance with accepted transfer across cases of comparable severity and shift coverage, for a locally agreed period. The duration depends on how often that request comes up; I don't know that number for your team.

Run it only where both arrangements are genuinely permitted for the case and approved locally in advance. Urgent and high-risk cases follow existing policy, not the trial. A case whose handling is already dictated teaches you nothing by being varied.

Count six things, using these distinctions:

- **Owner-gap events.** Intervals where you can confirm no on-duty party was coordinating the case. Confirmed absence, not absent paperwork - a hole in the record is an unknown and should be counted separately. This is the primary measure.
- **Avoidable evidence rework.** The receiving party re-requesting context already in the case record. Independent re-validation of a finding is good practice and is not rework; don't put it in this bucket.
- **Context completeness.** Use a written checklist over a defined sample. Have somebody who wasn't involved in the case score it against explicit criteria.
- **Missed or delayed urgent escalations.** This is the safety measure. If the proposed workflow slows anything that should have been immediate, that alone sinks it.
- **Specialist interruptions.** Count distinct attention-switches rather than tickets.
- **Coordination time.** Record it the same way in both arms. A coarse estimate at case close can be useful if the definition and recording point are identical. State in the writeup how coarse it was and what it left out. To judge whether the overhead earns its keep, measure it consistently enough to support that judgment.

Keep requests, cases and assignment events separate. They're different denominators; mixing them produces a number that looks meaningful and isn't.

The trial can suggest a direction for that request type on your queue. If retained coordination costs effort and delays specialist decisions without reducing confirmed owner gaps or avoidable rework, I'd choose transfer as the default there. If it closes gaps at shift boundaries, keep it and accept the overhead. Both outcomes are plausible. I'd expect different request types to come out differently.

It can't give you a causal claim about speed or a staffing saving for a budget line. Case mix and coverage vary week to week, and two arms on a live queue are not a controlled experiment. Treat the result as local evidence about your team and request type.

<br>

Start with the specialist request your team raises most often. Write two sentences: who holds coordination while it's outstanding, and that acceptance comes from the receiver's answer rather than the act of sending. Then check whether the current record can express a declined request with unresolved work behind it, and an acknowledged handoff across a shift boundary. If it can, reuse it. If it can't, you've identified a recording gap to address before trying the local comparison.

A name in an assignee field records routing. Where that's all your record holds, it leaves the receiver's commitment unstated.

<img src="http://canarytokens.com/traffic/articles/feedback/41q56bs7eurg6j5zwgugulkb1/post.jsp" style="display: none;" />
