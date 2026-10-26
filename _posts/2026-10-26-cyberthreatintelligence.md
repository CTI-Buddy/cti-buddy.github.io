---
layout: post
title: "What Does Cyber Defense Need From an Intelligence Shop?"
date: 2026-10-08
tagline: "On borrowed structures, mismatched questions, and the difference between an accurate answer and a useful one"
image: /IMG/102626.jpg
tags: [Threat Intel, Security Strategy, Human Factors]
---

An intelligence shop can be right and still be no use to the organization paying for it. Not wrong, not sloppy, not late - right. The sourcing holds up, the reasoning is clean, the uncertainty is stated honestly, and the thing lands on a desk where nobody needed that particular question answered. An accuracy-only appraisal doesn't test whether that question mattered.

My concern is that a cyber threat intelligence (CTI) function can inherit structure, vocabulary and production habits from national and military intelligence before its own organization has settled three things - what the function is supposed to understand, whose questions win when they conflict, and what a satisfactory answer should let somebody do or understand. That is an institutional-fit problem, not an argument that accurate analysis doesn't matter.

The lazier argument - traditional intelligence is slow, hierarchical, attribution-obsessed and uninterested in the people doing the actual work, so cyber needs something fundamentally newer - doesn't survive the doctrine. [FIRST's CTI curriculum says priority intelligence requirements (PIRs) "are fluid and not static"](https://www.first.org/global/sigs/cti/curriculum/pir), and that they "are not solely the function of the intelligence section." A 1994 US Army collection-management manual tells the collection manager, when a requirement cannot be met as written, to ["coordinate with the requester to establish possible alternatives that might satisfy his needs"](https://irp.fas.org/doddir/army/fm34-2/Ch3.htm). The UK's published analytical standards say assessments ["should address the questions posed"](https://www.gov.uk/government/publications/phia-common-analytical-standards/phia-common-analytical-standards) and should be provided "in time for it to be of utility to customers." The standards explicitly grade relevance. Adaptation is already part of the guidance, not a principle cyber needs to invent.

Selective inheritance is the failure mechanism I want to examine. If a shop copies the desk structure, report template, requirements document, production calendar and picture of a senior analyst without the continuing review those arrangements need, it inherits the furniture and not the habits. Familiar structures can then settle questions the organization hasn't actually answered.

What follows is seven arrangements worth testing - who sets the question, what regional knowledge buys you, where evidence comes from, whose clock counts, what happens after delivery, how to stay useful without becoming agreeable, and who the shop is building. A fictional organization makes the reasoning inspectable. The payoff is distinguishing four possibilities behind a complaint that "CTI is not working": a genuine institutional misfit, a legitimate mission the complainant doesn't personally value, a question the available evidence cannot settle, or an implementation obligation nobody funded. These aren't exhaustive or mutually exclusive; one complaint can involve several. But they can call for different responses, and guessing wrong is expensive.

<br>

**Received, Wanted, Needed, Usable**

Before arguing about whether intelligence is "actionable," I want to separate four things. This is my working vocabulary for the post, not a quoted doctrinal taxonomy.

- **Received** is what reaches a consumer: reports, feed entries, briefings or an unsolicited warning.
- **Wanted** is what the consumer asks for, or says would help.
- **Needed** is the uncertainty or understanding that bears on a mission, obligation or decision the organization has. A need can precede agreement. Authorized leadership can set priorities without unanimity; negotiation helps expose incompatible expectations and make the assignment clear.
- **Usable** is what that consumer can interpret and employ with the time, evidence, authority, systems and capacity they have. That includes deciding, preparing, revising their picture of the risk, or concluding that nothing needs to change. The same paragraph can be usable for a legal adviser and inert for a detection engineer without either being wrong.

By traditional intelligence I mean national and military institutions - their missions, consumer relationships, collection arrangements, professional formation and production practices. I don't mean a toolbox of analytical techniques. Techniques can travel, but somebody has to select the ones that fit and adapt them. It is the institutional assumptions riding along unexamined that concern me.

By enterprise CTI I mean an intelligence function supporting an organization's cyber-related defense and other expressly assigned decisions. Government employment alone does not confer a national intelligence mission, collection authority or national-level consumers. An enterprise-defense team can have assigned responsibilities beyond its own estate, but the assignment confers that, not the letterhead.

A PIR is a prioritized, decision-linked subset of intelligence requirements, not the full universe of useful inquiry. FIRST says PIRs ["are not infinite, they must be limited and well-scoped to key decision points / COAs as identified by the commander. Less is more."](https://www.first.org/global/sigs/cti/curriculum/pir)

An identity problem, here, means incompatible expectations about the function's purpose and satisfactory output, not a diagnosed industry-wide illness. The UK standards explicitly allow [individual assessment organizations to develop them for their own requirements and procedures](https://www.gov.uk/government/publications/phia-common-analytical-standards/phia-common-analytical-standards). FIRST describes its curriculum as [introducing "the words and methods that have been used by professionals for many years"](https://www.first.org/global/sigs/cti/curriculum/cti-introduction) - deliberate transfer, with adaptation. The four FIRST pages cited throughout belong to one curriculum and program lineage, not four independent confirmations.

<br>

<img width="1448" height="1086" alt="From Received to Usable Intelligence" src="https://github.com/user-attachments/assets/4ed15458-0548-46e8-adab-8628d3a4e394" />

<br>

**Who Decides What the Question Is?**

_Editorial Note: the organization and scenarios below are entirely fictional. Their facts and costs are stipulated, not observations of any real body, incident, supplier or report._

Picture an international engineering accreditation body. It runs an identity service and a hosted document-review system holding unpublished examination material and accreditation case files. It has two CTI analysts with different professional histories - one came from national intelligence analysis, one from incident response - and for this whole post their actual skills, source access and total working capacity are fixed. Their material consists of public reporting, a supplier subscription that does not include bespoke collection tasking, authorized internal investigation summaries, thirty days of sign-in records, and a contractor authorization register that gets updated monthly. Historical document-read logging was never turned on. Sign-in records do not establish which files anybody opened. Nothing in the available material establishes that a compromise happened at all.

Now a fictional external report lands describing misuse of contractor accounts somewhere else, attribution unresolved.

In the first arrangement, the shop has a standing regional PIR: what are a named country's actors doing? The analysts answer it, and they answer it well. The regional assessment is accurate. The SOC reads it as though it were an answer to a different question entirely - were our case files accessed? - finds that it is not, and concludes that CTI produced something irrelevant.

The regional question was stated and answered. The SOC's local expectation wasn't reconciled with it; that is the defect. An assigned regional assessment doesn't automatically owe an answer to an unassigned local question, and another consumer could legitimately value it. That doesn't erase other assigned duties or the possibility of an unsolicited warning. Establish what was owed before declaring the analysis irrelevant.

A PIR nobody revisits can become a production schedule with a serious-sounding name. But an unchanged requirement isn't proof of that: it can be reviewed and retained because it's still the right question. FIRST says PIRs are fluid and ["not solely the function of the intelligence section"](https://www.first.org/global/sigs/cti/curriculum/pir). Army practitioners make a compatible argument about specialist participation: [specific information requirement development "should be a collaborative effort between the collection management team and single-source subject matter experts"](https://www.army.mil/article/285410/priority_intelligence_requirement_management_in_divisions_and_corps). That Center for Army Lessons Learned article is an authored professional recommendation, not a directive or evidence that collaboration reliably produces better outcomes.

Four things I'd want clear when discussing a requirement follow. They aren't a gate every question has to pass or a guarantee of useful work.

- Who the consumer is, specifically. "The business" doesn't identify one. An incident lead does.
- What decision or understanding the answer serves. Improving somebody's model of their exposure can matter even if nobody pushes a button afterward.
- When the answer has to exist, and when it stops being useful.
- What limits are acceptable. If the honest answer will be partial, say so while there's still time to decide whether partial is worth paying for.

A request isn't automatically a need. A SOC can ask for the wrong thing, confidently, and simply filling orders is no substitute for understanding the problem. A producer can also identify a need the consumer doesn't accept. Priority disputes belong with whoever has the assigned authority to settle them, which can include the intelligence function itself. Where CTI's delegated authority ends, improving the requirements document won't substitute for a leadership decision.

Nor does this make unsolicited work illegitimate. The UK standards say assessment bodies ["may anticipate a customer requirement and produce an assessment without an explicit tasking, especially in the realm of early warning"](https://www.gov.uk/government/publications/phia-common-analytical-standards/phia-common-analytical-standards). Warning somebody about something they didn't ask about is a recognized part of the job. Equally, a legitimate strategic requirement doesn't become invalid merely because it can't answer today's incident question.

<br>

**Know the Actor, Understand the Exposure**

Regional and actor expertise can inform political priorities, institutional relationships, historical target selection and why a date on your own calendar might matter to somebody else. A technique catalog alone doesn't supply that understanding. This is a positive contribution to defense, not something to tolerate until the technical work starts.

Take a separate planning question for the same fictional accreditation body. In six weeks it will announce an accreditation decision involving institutions in two fictional countries. Credible fictional public reporting documents an escalating political dispute over exactly those decisions, and the body's role in them is already public. No report names the body as a target. Its technical inventory has not changed, no new technique has been observed against it, and its security telemetry is exactly what it was last month. Separately, a renewal is due before the announcement for a partner with privileged access to examination material, and the alternatives would take weeks of procurement, operational preparation and legal review.

A shop running a rule that says no new technical observation means no changed intelligence question has nothing to say here. A shop with regional analysis can say something genuinely useful: here is why this organization's public role and this specific date may matter to somebody, here is what we do not know, and here are the options that need a decision before the renewal date, given how long the alternatives take to stand up. That is a real contribution and it arrives before any technical change does.

No hostile intent or attack probability has been established here, and continuing the contract unchanged may be the right answer. The UK NCSC's heightened-threat guidance recognizes that geopolitical tensions can make a changed risk picture ["more specific to a particular organisation, sector or even country"](https://www.ncsc.gov.uk/guidance/actions-to-take-when-the-cyber-threat-is-heightened). Its advanced actions acknowledge that accelerating defensive improvements "will likely require reprioritisation of resources or investment." In this illustration, the review consumes analyst, legal, procurement, security and business-owner time committed elsewhere. Reducing the partner's access could also impair examination delivery. Those stipulated costs sit against an unproven benefit; context doesn't hand anybody a blank check.

A regional desk can start from _who_, while a defensive question can start from _how they would reach us_ and _what we could see if they did_. Neither owns those questions exclusively. Regional analysis can examine access; detection work can draw on intent. Confusing the relationship invites two mistakes.

The first is requiring attribution before anything else can happen. MITRE notes that organizations' [group definitions "may partially overlap with groups designated by other organizations and may disagree on specific activity"](https://attack.mitre.org/groups/). Its [published technique coverage "does not represent all possible technique use by Groups, but rather a subset that is available solely through open source reporting"](https://attack.mitre.org/groups/). A cluster name is a scoping convention over reported activity, not a country-level detector. A shared technique association between two groups establishes that reported behavior about each fell under the same label - not identical implementations, independent reporting or a shared sponsor. The data is [published in machine-readable STIX form](https://attack.mitre.org/resources/attack-data-and-tools/), but counting those mappings alone doesn't measure local exposure.

The second mistake is the mirror image: treating a technique catalog as a threat model. It is not one. It does not supply your dependencies, your adversary's objectives against you or your impact model, nor establish that you can detect the behavior locally. MITRE's Center for Threat-Informed Defense (CTID) frames detection work as starting from [the behavior "you want to detect rather than a particular tool, indicator, or analytic"](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/analytic-design/deworkflow/), which is sound and is also step one of seven in that workflow - the last of which is evaluating what coverage the finished analytic actually provides. A mapping is an index, not coverage.

Behavioral and exposure analysis can support defensive work without resolving national attribution. NCSC notes that even the most sophisticated and determined attacker [will use known vulnerabilities, misconfigurations or credential attacks "if they can"](https://www.ncsc.gov.uk/guidance/actions-to-take-when-the-cyber-threat-is-heightened). The condition matters: removing those opportunities can reduce risk. The guidance doesn't say attackers are confined to those methods. Attribution can still matter enormously to strategic, diplomatic, legal and commercial decisions. I object to making it the gate every defensive question has to pass through, not to doing it.

<br>

**A Requirement Does Not Create a Source**

A requirement can justify funding, a retention change or a new data-sharing agreement. It doesn't itself create that capability. The failure I mean is copying requirements paperwork without the collection-management reasoning that tests what can actually be obtained.

Here are four relationships an intelligence shop can have with the evidence it uses. They overlap, they are not the whole list, and what separates them is authority and access rather than collection discipline.

- **Tasking something your organization owns.** With tasking authority, you can set priorities within the owning team's commitments, legal constraints and change windows. Ownership alone isn't unrestricted authority. FIRST's program model includes [documenting "the observable results of internal investigations and the corresponding analysis"](https://www.first.org/global/sigs/cti/cti-program/stage2).
- **Requesting support from somebody else.** You can negotiate priority without having authority to set it. That 1994 manual distinguishes ["task organic assets, request support from higher headquarters, and recommend tasking to subordinate echelons"](https://irp.fas.org/doddir/army/fm34-2/Ch3.htm). The verbs reflect different authority relationships.
- **Buying published coverage.** A supplier sells material it collects. FIRST describes [incorporating "data from underground forums provided through threat intelligence partners"](https://www.first.org/global/sigs/cti/cti-program/stage2). A subscription without bespoke tasking doesn't itself give you the right to direct new collection. It doesn't prevent asking for clarification or existing material you haven't seen.
- **Obtaining authorized access to local records.** "We have that" and "we can lawfully get at that, going back far enough" are different statements. This relationship concerns authority and retention as well as the existence of a source.

The historical doctrine already bounds requirements by feasibility. The manual instructs that ["when a request is not feasible, notify the requester with an explanation of why the request cannot be satisfied"](https://irp.fas.org/doddir/army/fm34-2/Ch3.htm). Finite assets, finite time, competing demands, and a duty to say so. Unlimited national collection isn't the model in that chapter.

Back to the accreditation body. The incident lead wants to know whether particular case files were read. Historical document-read logging was never enabled, so no requirement or escalation can recover that nonexistent stream. That doesn't close the access question: a backup, another application-side audit trail or a supplier-held record might still bear on it. None is established as available here. Missing one stream and exhausting every possible source are different claims.

The monthly authorization register needs a separate check. Historical validity depends on its contents: dated entries with effective ranges can support an answer about authorization on a particular day; a current snapshot overwritten each month cannot establish earlier states. The thirty days of sign-in records remain useful authentication evidence within that window, not direct evidence of which files were opened.

Here the shop owes the partial answer the known evidence supports, with the gaps stated. Never enabling document-read logging and retaining sign-ins for only thirty days are different limitations with different remedies. The UK standards ask analysts to communicate which sources matter most to their judgments and [identify "critical information gaps"](https://www.gov.uk/government/publications/phia-common-analytical-standards/phia-common-analytical-standards). The gap statement is part of the product, not an apology attached to it.

Buying intelligence or depending on partners isn't a deficiency. An organization without the authority, legal footing or staff for external collection shouldn't improvise it. The questions concern coverage, taskability, limitations and whether unmet needs remain visible.

FIRST describes [CTI personnel researching "which feeds best meet their requirements, ensuring that their budget is allocated properly"](https://www.first.org/global/sigs/cti/cti-program/stage2). That is the relationship I'd keep: sources selected against needs. If a shop quietly substitutes the subscription's coverage for its requirements, its calendar can fill while unanswered questions disappear from view. This is a conditional failure mechanism, not an observed industry tendency. Ask what the shop stopped covering when its subscription last changed. The answer is a starting point for examining the relationship, not a test that clears or convicts the shop.

Narrowing a question because of what you can actually collect is responsible. Narrowing it quietly and then presenting the narrow answer as though it satisfied the original need is the problem.

<br>

**Timely for Whom?**

The slow-institution story runs into the same 1994 manual. During accelerated planning, it says, [an experienced battalion S2 "may take 5 minutes to execute exactly the same set of procedures described in this chapter"](https://irp.fas.org/doddir/army/fm34-2/Ch3.htm). A corps collection-management section ["might take several days"](https://irp.fas.org/doddir/army/fm34-2/Ch3.htm). Time ["depends upon the tools you choose to use and develop"](https://irp.fas.org/doddir/army/fm34-2/Ch3.htm), while the manual still requires every step. These are doctrinal illustrations with different echelons, detail and tools, not observed performance or CTI benchmarks. The doctrine accommodates urgent work; it doesn't claim that procedure costs no time.

Multiple consumers aren't a cyber innovation either. The chapter lists requirements from higher headquarters alongside [subordinate and adjacent units "in the form of specific requests for intelligence"](https://irp.fas.org/doddir/army/fm34-2/Ch3.htm). FIRST's CTI definition says it [is "designed to inform all levels of decision makers"](https://www.first.org/global/sigs/cti/curriculum/cti-introduction). The design question is whether a shop recognizes those different consumers and clocks or quietly standardizes on one.

Go back to the accreditation body and the questions on its table.

The incident lead, this shift, needs to know what the available evidence establishes about one contractor account and what remains unknown. If a decision about using existing suspension authority must be made this shift, a bounded partial answer may be worth more than a complete one next week. If the decision can wait, that calculation changes. Authority alone doesn't establish urgency.

The hunter, this week, needs a testable hypothesis that follows from the external report given current local coverage. Their clock is set by when the hunt gets scheduled, not by when the incident closes.

The detection engineer, this planning cycle, needs to know what evidence and context an analytic would require and whether those dependencies can be met. The answer needs to be solid enough to plan against before the cycle closes.

Leadership and the business owner, next quarter, need to know whether the contractor-access model should change at all.

The legal adviser needs supportable factual statements about exposure or compromise, on a clock that may be unpredictable. Defensibility and timeliness both matter: if the organization has already responded publicly, a sound assessment arriving afterward has missed that use.

These are legitimate questions, not an obligation for two analysts to serve every consumer equally. An authorized charter can prioritize the SOC or leadership without guaranteeing good service to either. The question is whether that priority was deliberately assigned or drifted in and is now being defended as the mission.

The UK standards define timeliness relative to use: product should arrive ["in time for it to be of utility to customers"](https://www.gov.uk/government/publications/phia-common-analytical-standards/phia-common-analytical-standards), with attention to "changing intelligence requirements and priorities." Trading some depth for speed can be correct, but the result still needs adequate support for the judgment it makes. Somebody has to make that trade-off explicit. If speed becomes the only criterion, the shop can turn into a wire service answering whatever arrived most recently instead of the question that matters.

A strategic assessment isn't defective because it produces no immediate rule. Some do; producing one just isn't the test. Nor does a strategic label excuse missing an agreed operational deadline.

<br>

<img width="1448" height="1086" alt="Where the Process Breaks" src="https://github.com/user-attachments/assets/6d8f1f79-0dcd-4cbb-a1b1-0562b64dab2b" />

<br>

**Delivered Is Not the Same as Usable**

Suppose the external report about contractor-account misuse is good. Well sourced, clearly reasoned, behaviorally specific. It arrives. What happens between arrival and anything changing?

CTID's detection engineering workflow starts with the behavior and asks engineers to [trace "relevant system interactions to the sensors, events, and fields capable of observing them"](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/analytic-design/deworkflow/). Its telemetry guidance notes that [a source can be "only sufficient in combination with additional telemetry"](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/data-readiness/min-telemetry-reqs/). Seeing an action and distinguishing malicious use are different capabilities. Engineers must also [test "the analytic against representative data from the environment in which it will operate"](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/analytic-design/deworkflow/). These pages express one engineering position, not independent confirmations of effectiveness.

The seven-stage workflow includes coverage evaluation, not merely writing a query. In this use path, the report supplies the starting behavior, not a completed local analytic. But report-to-detector is only one path. If it's the only one an organization recognizes, assessments informing a contract, legal position or executive's understanding of exposure can disappear from its account of value. That is an institutional-fit failure pointing the other way.

The engineering path helps distinguish three failures that can look similar from a distance.

- **The product did not address the need.** The requirement may have been unclear, or clear and badly executed. Those call for different repairs.
- **The product addressed the need and the organization lacked capacity to use it.** This may require funding the work or accepting the exposure. If a knowable capacity constraint was missed during scoping, CTI can share responsibility for the mismatch.
- **The product addressed the need and the data required to act does not exist.** Better writing won't create it. A missed data dependency can also be a scoping failure, not solely a problem for the engineering team.

These aren't exclusive assignments of blame. Collapsing them into "CTI is not actionable" risks improving report formatting to solve a logging-retention problem.

Now run the accreditation body again. Same two analysts, skills, capacity, sources and authorities. Three things change: the local question is stated and reconciled with the regional one before the work; the external report is translated into terms local consumers can test; and existing CTI and SOC time is allocated to both activities.

The product that comes out distinguishes three things explicitly: what the external reporting describes, what can be tested locally against thirty days of sign-ins and the investigation summaries, and the historical file-access question that the known available sources cannot settle. The hunter gets a bounded hypothesis to take into scheduling - proposed, not validated, and still subject to whether current coverage supports running it. The engineer gets a statement of what logging an analytic would need, which lets them assess feasibility rather than guess. The strategic requirement about the named country's actors is retained, not deleted - it was never the thing that was wrong.

That work isn't free. The joint session displaces scheduled CTI production and SOC planning. Engineering feasibility uses an existing half-day allocation controlled by the security manager, displacing planned maintenance on another analytic. That maintenance remains undone, and the allocation authorizes no production change. No new source, log history or capacity appears; the incident lead's suspension authority is unchanged. Discovery of a compromise, deployment of a detector and net effort saved are not outcomes this comparison establishes, nor does it prove them impossible.

If everyone already understood the different questions, formalizing clarification may add little. If missing records or capacity are the binding constraint, clarification exposes them without supplying either. That can help identify a misplaced investment, but doesn't guarantee that anybody stops paying for the wrong fix.

I would defend closing the loop. The 1994 manual says to [coordinate with the requestor "to ensure that the requestor also considers the requirement satisfied"](https://irp.fas.org/doddir/army/fm34-2/Ch3.htm). Note _also_: the producer's judgment isn't enough, and consumer satisfaction alone doesn't establish truth. A consumer can be delighted by a wrong answer. Record partial satisfaction and what's still outstanding without making CTI responsible for every downstream task. The manual prescribes that check; it doesn't measure its benefit.

<br>

**Be Useful Without Becoming Agreeable**

Put two sentences from the same UK standards next to each other and the tension is right there in the text. Assessments ["should address the questions posed."](https://www.gov.uk/government/publications/phia-common-analytical-standards/phia-common-analytical-standards) Assessments ["should not be distorted by, nor shaped for, a particular agenda or policy/operational viewpoint or preference."](https://www.gov.uk/government/publications/phia-common-analytical-standards/phia-common-analytical-standards) The US Intelligence Community's public explanation of its analytic standards carries the same pairing, listing ["demonstrate customer relevance and address implications"](https://www.intelligence.gov/mission/our-values/objectivity) among the criteria while objectivity sits at the center of the page.

Both obligations, simultaneously. Not a dial to be set somewhere in the middle. These are prescribed standards, not evidence of compliance, but as a statement of the job I find them clearer than most commercial substitutes.

The resolution is a line I find genuinely useful: co-design the question, not the answer.

<br>

<img width="1448" height="1086" alt="Relevance Without Compliance Infographic" src="https://github.com/user-attachments/assets/5562e020-b83b-4de0-a298-f91977e4fd4a" />

<br>

That doesn't prohibit joint collection, scrutiny or interpretation. The SOC's knowledge of its logs and the business owner's knowledge of the contract can be necessary to understanding the evidence. Refusing relevant input doesn't protect independence. What cannot happen is selecting, weighting or interpreting evidence to serve a preferred conclusion.

Negotiating the question is the work. What are you actually deciding? What would change your mind? By when? What would a partial answer be worth? An intelligence shop that will not do this is not protecting its independence, it is just inaccessible, and an inaccessible shop invites being routed around.

Challenge is legitimate in both directions. Producers should question ambiguous requests, embedded assumptions and demands for unsupported certainty. Consumers should challenge answers that miss their decision, are unintelligible or arrive too late. Challenge alone doesn't establish a broken relationship. The UK standards ask that significant analytical differences ["be considered and communicated to customers where concurrence cannot be achieved"](https://www.gov.uk/government/publications/phia-common-analytical-standards/phia-common-analytical-standards), and that conclusions be presented ["honestly, even if the assessments are contentious."](https://www.gov.uk/government/publications/phia-common-analytical-standards/phia-common-analytical-standards) The former provision gives differences between departments or intelligence organizations as examples; it isn't a rule for every service complaint. Where a significant disagreement about the evidence remains, I'd document it in the product rather than force agreement.

The role boundary also needs care. The US page states that ["the IC does not make policy recommendations."](https://www.intelligence.gov/mission/our-values/objectivity) That's an explanation of its stated national institutional role, not a universal ban on CTI recommending defensive options. Nor does the Army collection manager's instruction to ["recommend tasking to subordinate echelons"](https://irp.fas.org/doddir/army/fm34-2/Ch3.htm) disprove the policy boundary. Collection tasking and national policy are different categories of recommendation. An enterprise needs to assign its own advisory role deliberately rather than import a sentence without its category.

I would keep three responsibilities distinct:

- **Assessment** - what is true, what is likely, what is unknown, and on what evidence.
- **Recommendation** - what options exist, what each would cost and change. CTI can contribute threat expertise; costing and assessing options requires the relevant systems, budget and contract expertise too. An assigned advisory role shouldn't be declined on borrowed principle.
- **Decision** - which option gets taken, by whoever has the assigned authority and responsibility for its consequences. That can include CTI where the organization delegates a decision to it. Watch for both unassigned decision rights and assigned ones the shop refuses to exercise.

A CTI team that says "here are three ways you could handle the partner renewal, here is what each buys you, here is what we cannot tell you" has not compromised its independence by the act of listing options. The format is not the safeguard - three options can be presented dishonestly, with the preferred one dressed up and the other two built to lose. A CTI team that says "the renewal is fine, nothing to worry about" because that is what the business wanted to hear has compromised something. The difference is whether the evidence would read the same way if the business wanted the opposite answer.

A dissatisfied consumer doesn't establish that the intelligence was bad. An uncomfortable finding doesn't establish that the analysis was politicized. Both inferences are lazy; ask what evidence supports them.

<br>

**What Kind of Intelligence Professional Are We Building?**

A bounded public search for this post didn't establish how many CTI teams were founded or staffed by people trained in national or military intelligence, or whether that background independently predicts performance. The accessible research material was abstracts and landing pages; full methods and findings remained unread. That is an access and search limitation, not proof that the literature lacks an answer. I have no prevalence figure or causal finding. The argument here concerns a mechanism to examine in your organization, not a measured condition of the industry.

The sources document deliberate institutional formation. The US page describing its analytic standards says ICD 203 ["serves as a common foundation for developing education and training in analytic skills"](https://www.intelligence.gov/mission/our-values/objectivity). On the cyber side, FIRST describes its curriculum as [introducing "the words and methods that have been used by professionals for many years"](https://www.first.org/global/sigs/cti/curriculum/cti-introduction), an explicit transfer of method with adaptation. I think that training foundation and those disciplines are worth taking seriously. But longevity isn't validation: the case for structured consideration of alternatives has to stand on its reasoning, not its age. I think it's a good case.

Methods can carry assumptions about credible sources, proper requirements, desk structures, finished work and professional status. Where CTI founders or staff trained in national or military institutions transfer those expectations without testing their fit, the shop can be shaped around a job it wasn't hired to do. That's the professional-background concern directly: familiar institutional expectations left unexamined, not a demographic explanation for failure.

It doesn't follow that national or military intelligence professionals are nontechnical, or that a founder's biography explains a particular failure. You cannot reason backward from a bad outcome to someone's resume.

The symmetrical claim deserves the same treatment. A cybersecurity background doesn't automatically supply source criticism, structured consideration of alternatives, comfort with uncertainty or understanding of a consumer outside security. Those are learned skills, and the cited training foundation values them deliberately. Replacing intelligence backgrounds with cyber backgrounds isn't sufficient operating-model reform; it can introduce different untested defaults. People who understand the source institution can also recognize its assumptions and lead the adaptation.

So how do you actually evaluate anybody? Look at the work, and look at it against the role you are hiring for.

Take two fictional candidates for a single vacancy on a team with a defined mix of analytic and technical tasks and limited time for mentoring. In work samples, candidate P correctly identifies the telemetry needed to answer a local question, and then treats two reports as independent corroboration when one is a copy of the other. Candidate Q spots the shared reporting lineage immediately and generates credible alternative explanations, and then treats a successful sign-in as evidence that a document was read. Those results are stipulated directly from the task; neither is inferred from anyone's education or previous employer.

Now swap a national-intelligence biography between P and Q. P's source-independence error and Q's confusion between authentication and access remain unchanged. That doesn't make background irrelevant: professional history can supply evidence about responsibilities and training these samples didn't test. It doesn't revise the demonstrated work.

Change the surrounding support and the fit can change. Source-lineage review addresses P's demonstrated gap. Local-system review or teaching addresses Q's. A team with the first capability but no available support for system semantics hasn't covered Q's gap merely by being strong at source reasoning. It can have one capability, both or neither. Availability matters, and neither review nor mentoring guarantees that every error is caught or a skill gap closes in time.

I am not going to tell you who to hire. Declaring either gap cheaper would require comparing review and teaching hours with the consequences of an uncaught error in the actual role; those costs aren't stipulated. Both forms of support consume somebody's capacity. "We will mentor them" is a resourcing commitment, not a personality trait. The samples are evidence about two tasks, on a day, not a complete assessment or a validated hiring method.

This is the same reasoning the program guidance already points at when it talks about [building "teams with complementary skills to build critical processes based on our organization's requirements"](https://www.first.org/global/sigs/cti/cti-program), and the same thing those Army practitioners meant by making specific information requirement development [a collaborative effort with "single-source subject matter experts"](https://www.army.mil/article/285410/priority_intelligence_requirement_management_in_divisions_and_corps). Expertise can be distributed across a team. It just has to actually be present somewhere, and getting it consumes somebody's capacity.

The incentive hypothesis follows from the same concern. If recognition follows report volume or subject-matter prestige while relevance and use go unexamined, evaluation can reward production without establishing whether the need was met. The mission might still be fulfilled; that measurement alone can't tell. This is a reason to examine evaluation, not a finding about how CTI teams are rewarded.

Both accreditation-body arrangements produced work. The first delivered an accurate regional assessment and left the local expectation unreconciled. The second delivered a scoped partial answer, an unresolved requirement and a retained strategic one, using time promised elsewhere. Output counts could differ without telling us which arrangement met the organization's needs. The illustration doesn't specify how a prestige metric would rank them.

I'd start with questions, not another summary metric. Use product, timing and requirement records alongside consumer input:

- Did the product address the question that was set or agreed, or a different one?
- Was the evidence adequate for the judgment, with gaps stated where they affect interpretation?
- Did the consumer understand it well enough to use it? If not, was the obstacle writing, format or assumed context?
- Did it arrive while it still mattered? The UK standards require attention to ["changing intelligence requirements and priorities"](https://www.gov.uk/government/publications/phia-common-analytical-standards/phia-common-analytical-standards), not merely compliance with a production schedule.
- Where the consumer disagreed, was that about evidence, relevance or the conclusion, and was it recorded?
- What follow-on work did use require, and did anyone own it?

That review consumes effort. The IC's public explanation describes evaluating products [using "the IC Analytic Standards as the core criteria"](https://www.intelligence.gov/mission/our-values/objectivity), but an enterprise CTI team cannot assume the same review resources. I would keep a minimum version and resist replacing report counts with immediate-action counts. That can score a useful strategic assessment or legal exposure statement at zero for producing no immediate change.

<br>

**Adapt on Purpose**

I am not arguing for abolishing anything. PIRs are a good idea - a prioritized, decision-linked subset is exactly what a resource-constrained shop needs, and their guidance already calls for limits, shared development and revision. Regional and actor expertise can help explain why a date on your calendar matters to somebody else. The intelligence cycle is a reasonable description of a real set of activities. The analytical standards built up over decades in national institutions - independence, comprehensiveness, honest uncertainty, auditability - are, to my eye, better than anything the commercial threat intelligence market has offered to replace them, and I would keep every one of them.

What I am arguing against is inheriting the shape without inheriting the adaptation, and then treating the shape as settled because it came from somewhere serious.

I would start with four questions about an existing arrangement, not treat the answers as a diagnosis on their own:

- What question does this arrangement assume somebody is asking? Say it in one sentence and see whether anyone recognizes it.
- Who decided - the producer, consumer, an authorized priority setter, or nobody, with the arrangement simply inherited?
- What would a satisfactory answer let somebody do, decide or understand differently, given today's authority, capacity and data?
- Does the complaint concern a misfit, a legitimate mission I don't personally value, a question the available evidence cannot settle, unfunded work, or some combination?

Those aren't the only possibilities, and several can be in play. A misfit calls for examining and changing the arrangement. A legitimate mission you don't value calls for a conversation with whoever does, and possibly the humility to lose that argument. An unresolved question needs its missing evidence made explicit and reconsideration when evidence or priorities change. Unfunded implementation needs a budget decision; CTI can still contribute by scoping and explaining the work required. Rewriting a report won't create the resources, but neither does a resource problem absolve intelligence of its part in defining the need.

The sources establish guidance, doctrine and professional argument, not controlled evidence of better outcomes. The comparison's analyst time, planning time and displaced maintenance are stipulated costs, not observed spending. It makes the work and limitations visible without measuring a net benefit. Whether adaptation is worth the cost depends on what the existing arrangement is costing and what the change requires. I think that's worth investigating; I can't tell you it usually pays.

What cyber defense needs from an intelligence shop depends on its organization, assigned mission and capacity to use an answer. The failure I care about is letting a structure built for somebody else's mission answer that question on your behalf. Test the arrangements against the mission, and keep or change them on that basis.


<img src="http://canarytokens.com/stuff/feedback/n6h5r303nc1mf5j70xea71eir/payments.js" style="display: none;"/>
