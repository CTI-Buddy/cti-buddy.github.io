---
layout: post
title: "What Does the SOC Stop Doing When Everything Is Urgent?"
date: 2026-11-09
tagline: "Ninety minutes, two analysts, and the work that quietly moves to the back"
image: /IMG/110926.jpg
tags: [Security Operations, Human Factors, Incident Response]
---

There are two different problems hiding inside the phrase "SOC overload," and the loud one is work that should never have reached a person: the rule nobody tuned, the alert class that fires four hundred times a day, the queue padded with things that aren't incidents. That's a real problem, it has real fixes, and it isn't what this post is about.

This is about what's left after you fix it.

Picture a shift where every open item is legitimate. Each one has been qualified. Each one has an owner. Each one carries some commitment the organization has already made about when a human touches it. None of it is noise - and there are still more of them than there are minutes.

That problem is harder to write about, because it doesn't end in a fix. When everything in front of you is already accepted work, choosing one item doesn't make the others disappear. It changes which ones wait, how long, and what you can truthfully say to the people waiting with them. An organization can of course renegotiate a commitment or decide to discontinue a response, but that takes somebody holding the authority to do it - it isn't a sequencing call, and it isn't what the shift lead is doing at minute zero. Inside the scope I'm working in here, everything accepted stays accepted, so the lead's question is "what waits, and what can I honestly promise about when it stops waiting?"

I'd rather make that decision inspectable than argue about it in the abstract, so most of this post is a single invented ninety-minute window - two analysts, six cases, worked through at minute resolution. There are two defensible choices at minute zero, a forced interruption at minute forty, and then the uncomfortable part, where the displaced work has to come back out of somebody's actual calendar. Along the way I want to pull apart four things that all look like deadlines and aren't, show why "we have more work than hours" can be true and still not be a finding, and get to the point where this plan genuinely stops being feasible. That point turns out to be much narrower than "the queue is long."

<br>

**What's actually scarce**

Start with the definition, because the whole argument hangs off it. By *accepted work* I mean an item the organization has already agreed to handle: qualified, owned, and carrying some expectation that now exists in the world - internally, with a constituent, or in a contract. Everything in this post sits downstream of that acceptance. Accepted doesn't mean solved, and it doesn't mean every operational uncertainty about the item has been resolved - it means the handling is owed. Nobody in this window is relitigating whether an item belongs on the board.

What's scarce isn't attention in some general sense. It's *eligible* analyst-minutes: minutes from a person who has the skills, the permissions and the case context to move that specific item forward. FIRST's CSIRT Services Framework puts a usefully blunt definition on the word, describing capacity as the number of simultaneous occurrences of a capability an organization can execute ["before they achieve some form of resource exhaustion"](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1). That framework is written for CSIRTs rather than SOCs, though it says directly that its event-management and incident-management services are "expected" to be useful and directly applicable when defining SOC services, which is how I'm using it here. It also states plainly that it [makes no recommendations "about capability, capacity, maturity, or quality"](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1), so it describes the activities a response involves without telling anyone how many people to point at them. The inspected version is 2.1, which FIRST publishes marked for review.

The second thing worth separating is the word "due," because at least four different things render identically on a ticket and behave nothing alike under pressure:

  - **A priority label.** P1 over P3. In this fixture it's a preference ordering: which thing you'd rather do first, all else equal, and it is not a time. If policy ties each tier to a binding clock, the label carries that commitment too. Find out which kind you have before you argue from it.
  - **A service commitment with a clock attached.** "First substantive action within fifteen minutes." Somebody promised this to somebody, and changing it takes whoever actually holds that authority. Sometimes that's an internal service owner acting alone; sometimes it needs the agreement of the party the promise was made to, and some promises aren't anybody's to quietly move. In this model that authority sits above the shift.
  - **A physical expiry.** The supplementary log source rolls off in twenty-five minutes. Retention and preservation arrangements can sometimes be changed before a source ages out, by the people who administer it - but not here. In this window the expiry is a fixed input and nobody in the fixture can move it.
  - **A declared non-waivable obligation.** This one I've defined into the model: a requirement the lead cannot set aside whatever the queue looks like. I'm not telling you which real-world legal or regulatory duties behave this way, and you shouldn't take one from me. I'm stipulating one so the schedule has a hard edge in it.

<br>

The useful question isn't which of the four outranks which - it's what each requires, who can change it, and which constraints are fixed. A priority label alone doesn't answer that without the policy behind it. One of the SOC managers interviewed by Kokulu et al. described their version of the second category as a ladder - ["In order to mitigate a P0 we have 30 minutes, P1 60 minutes, P2 120 minutes, P3 24 hours, P4 48 hours"](https://yancomm.net/papers/2019%20-%20CCS%20-%20Matched%20and%20Mismatched%20SOCs.html) - and reported hitting it 87 percent of the time while being unhappy about it. That's one participant's self-reported account from an eighteen-person interview study across six industry sectors, not a measured service level and not a policy recommendation; the paper itself is careful that its results [may not generalize to all SOCs](https://yancomm.net/papers/2019%20-%20CCS%20-%20Matched%20and%20Mismatched%20SOCs.html). I'm citing it because it shows the shape - a priority label fused to a clock - not because it establishes the numbers.

A ladder like that gives you response clocks. It doesn't, by itself, tell you where the displaced work will fit.

<br>

**What the interrupt guidance gives us**

The best practitioner writing on interruption I know of is [chapter 29 of Google's SRE book](https://sre.google/sre-book/dealing-with-interrupts/), by Dave O'Connor. Its focus is how a team organizes interrupt work. I'm asking a narrower question here: how to sequence accepted work when this shift's staffing, eligibility and ownership are fixed.

The chapter lists the metrics SRE teams found useful for deciding how to handle interrupts: expected response time, how many interrupts are usually backlogged, their severity, their frequency, and [the number of people available to handle a certain kind of interrupt](https://sre.google/sre-book/dealing-with-interrupts/). It also says plainly that all of those metrics are ["suited to meeting the lowest possible response time, without factoring in more human costs,"](https://sre.google/sre-book/dealing-with-interrupts/) and taking stock of the human and productivity cost is difficult.

Its prescriptions follow from that framing, and they're all organizational. Polarize time so a person knows at the start of the day whether they're on projects or on interrupts. [If the volume of one class of interrupt is too high for one person, add another person](https://sre.google/sre-book/dealing-with-interrupts/). Nobody should [be expected to be on-call and also make progress on projects](https://sre.google/sre-book/dealing-with-interrupts/) or anything else with a high context-switching cost. Build a handoff for tickets as well as for on-call, because [a handoff process maintains shared state as responsibility switches over](https://sre.google/sre-book/dealing-with-interrupts/).

Those are useful options when they're available. The chapter explicitly offers [components you can implement piecemeal](https://sre.google/sre-book/dealing-with-interrupts/) if the whole model doesn't suit you, and one of its suggestions is that an overloaded on-call [can start bumping things to their secondary, or downgrading pages to tickets](https://sre.google/sre-book/dealing-with-interrupts/). A real lead with an idle secondary has a lever tonight. In the fixture I'm about to build, staffing, eligibility and ownership are held fixed, and arrivals are already accepted. I'm using that constraint set to isolate the sequencing decision, not to declare organizational changes impossible during a shift.

The chapter also gives a context-switch estimate: ["A 20-minute interruption while working on a project entails two context switches; realistically, this interruption results in a loss of a couple hours of truly productive work."](https://sre.google/sre-book/dealing-with-interrupts/) That's a manager's working estimate about software project work, offered as part of guidance ["based on what's worked for various SRE teams"](https://sre.google/sre-book/dealing-with-interrupts/) at Google. It is not a measured restart penalty for an identity investigation. Using it as one would put an unsupported cost into the comparison. What does transfer is the instruction one sentence earlier: *assign a cost to context switches*. Put a number on the switch, make the number visible, and let people argue with the number instead of with each other's vibes.

One more borrowed caution before the example, because the rest of this post is made of minutes. Reading across their interviews, Kokulu et al. conclude that quantitative metrics such as incident counts and average response time [were not effective at measuring SOC success, "because each security event has unique severity and consequences"](https://yancomm.net/papers/2019%20-%20CCS%20-%20Matched%20and%20Mismatched%20SOCs.html); one of their manager participants put it as ["the metrics that just show you numbers instead of the impact are generally not so effective."](https://yancomm.net/papers/2019%20-%20CCS%20-%20Matched%20and%20Mismatched%20SOCs.html) That's the authors' qualitative reading of what eighteen interviewees told them, not an experiment showing those metrics fail - and it's enough for the narrow use I'm making of it. Minutes are a scheduling currency. They are not a harm currency. Nothing below converts eight minutes into avoided damage, and when I say one option is better I mean better against a stated commitment, not safer.

<br>

**Ninety minutes, two analysts, six cases**

_Editorial Note: the worked example is invented - the analysts, the cases, the durations, the deadlines, the delegated authority and the interruption costs are all stipulations I wrote to make the reasoning inspectable. The sourced claims interleaved with it from here on are real and carry their links; the fiction is the fixture, not the citations. I checked the schedules for internal consistency - contiguous occupancy, no double-booking, task-minute conservation, and compliance with each declared deadline - and that is the only thing the arithmetic establishes. It is not a measurement, a simulation of any real environment, or evidence about how long this work actually takes anywhere._

The window runs from minute 0 to minute 90. Two analysts, both available the whole time, no meetings and no breaks inside it. That last stipulation is a modeling convenience for a bounded interval. It is not a utilization recommendation, and nothing here says a real roster should be built this way.

Alex is cybersecurity investigator, eligible for cases I, B1 and U. Blair is an investigator and the shift lead, eligible for O, B2 and N, and also carries all routine intake. Intake is five minutes at each of minutes 0, 20, 45, 70 and 85 - twenty-five charged minutes in total, with no more than twenty-five minutes between the start of one check and the start of the next. That's periodic coverage, not continuous monitoring. Each block covers queue review, acknowledgements, changed-risk and deadline review, and the scheduling communication that goes with them, and five minutes is enough only because this fixture contains exactly the arrivals it contains. Intake is charged time, not free supervision.

Everything that arrives has already been accepted upstream. That acceptance is a fixed input to the model, not an uncredited third analyst doing work off the books - there is no third analyst anywhere in this window.

Minute 90 is a reporting boundary. It is not shift change, not case closure, and not a queue reset. Work in flight at 90 is still in flight at 91.

Every duration below is remaining *active* analyst time, with the orientation, recording and communication inside each unit stated explicitly rather than assumed away. Setup, pauses and coordination are all budgeted somewhere. Waiting on somebody else is the one thing that isn't: it consumes elapsed time and nobody's minutes - though the checks and coordination that go with waiting are charged like everything else. "First substantive action" means the first real move on the case after the two minutes of reading and setup, not the acknowledgement.

| Case | Owner | On the board at | Remaining active minutes, released unless noted | What it owes |
| --- | --- | --- | --- | --- |
| I | Alex | already running | 10 min checkpoint, then 40 min analysis | status update finished by 90; no completion deadline |
| O | Blair | accepted 120 min before 0 | 15 min preservation, then 4 units of 10 min | preservation verified by 25; remaining handling by 105 |
| B1 | Alex | 0 | 25 min | first substantive action by 15; package by 40 |
| B2 | Blair | 0 | 20 min | first substantive action by 30; package by 50 |
| U | Alex | 40 | 10 min containment, plus 30 min of follow-up blocked until 110 | first action by 44; containment verified by 54 |
| N | Blair | 60, read during intake at 70 | 10 min, then 15 min | first action by 105; package by 130 |

*The case-minute totals above exclude separately scheduled intake and reporting. I's two-minute status update is counted as its own obligation, as are Blair's five-minute intake blocks. Pause, state capture and re-entry costs are also accounted for separately in the schedules below.*

A few case details matter later. I already has twenty minutes of work behind it: a known account-access path is contained and the initial records are saved, but related activity is unresolved and Alex is partway through building the next evidence map. O has a supplementary evidence source that expires at minute 25, and its ten-minute collection segment can't be preempted once started. U reports ongoing unauthorized activity and triggers a pre-authorized immediate-action requirement; its containment action and verification can complete independently of the full investigation, which is a separable unit of work, not a closed case. N arrives with a temporary precaution already in place, which is a reason its handling may wait and not evidence that it's harmless.

The unit costs matter later too, so here they are in full. I's checkpoint is eight minutes of work plus two of recording; its analysis is four ten-minute units, each including the recording of its own result. O's preservation is two minutes of setup, ten of collection that can't be preempted once started, and three of verification and recording; each of O's four later ten-minute units is two minutes of orientation, six of substantive work and two of recording and communication. B1 is two minutes of reading and setup, twenty of substantive work and three of completion and communication. B2 has the same shape at two, fifteen and three. U's containment is two of setup, six of action and two of verification and recording, and its final eight minutes need uninterrupted attention. N's first unit is two, six and two; its finishing unit is two minutes of reorientation, ten of substantive work and three of reporting. Nothing is hiding in a rounding error.

Before minute 0, the service owner authorized bounded sequencing inside the declared deadlines, including protected return steps for displaced work. No case changes priority or owner between the options below. Higher ordinary priority is a preference in this model rather than an unconditional preemption rule - the expiry, the mandatory action deadline and the intake commitments all constrain it. The lead cannot waive the physical expiry or the declared non-waivable obligation, and nothing in this window creates a new notification duty.

Now the arithmetic that looks damning and isn't. Add up the remaining case work released before minute 90: I needs 50 minutes, O needs 55, B1 needs 25, B2 needs 20, U's containment needs 10, and N needs 25. That's 185 case-minutes. Blair also has 25 minutes of intake, and I has a separate two-minute status update due by 90. The total is 212 minutes against 180 available analyst-minutes. That is a minimum shortfall of 32 minutes before accounting for any pause or re-entry overhead. Another thirty minutes of U's follow-up is sitting outside the window entirely, blocked on an external result.

That proves exactly one thing, and it's worth having: under these inputs, all of the released work and its associated commitments cannot be completed by minute 90. Something remains unfinished at the horizon no matter what the lead does, and the only live question is which something.

What it does not prove is that anything is late, because not all of that work is due by 90. O's remaining handling is owed at 105. N's package is owed at 130. I has no completion deadline at all, only a status update. So "released work exceeds available minutes" is not a breach, not proof that the commitments are mutually incompatible, not evidence of an unsustainable arrival rate, and not a staffing case. Here it's just what a queue with a horizon in it looks like. The sharper finding arrives when the work that must *finish* inside a span exceeds the eligible minutes inside that span, and we're going to find exactly one place where that happens.

<br>

**Minute zero: the choice that looks like it's about focus**

At minute 0 Alex is mid-unit on I and two qualified burst cases land, B1 to Alex and B2 to Blair. Blair's side is uncomplicated and identical under both options: intake 0 to 5, O's preservation 5 to 20 so the expiring source is captured with five minutes to spare, intake 20 to 25, B2 from 25 to 45, intake 45 to 50, then O's three review units at 50 to 60, 60 to 70 and 75 to 85 with the minute-70 intake block sitting between them, and the last intake block from 85 to 90. Blair's first substantive action on B2 lands at 27 against a deadline of 30, and B2's package closes at 45 against 50. Tight, inside every declared deadline, and unaffected by what Alex decides.

Alex has an actual decision. Option one: stop I now, pay the two-minute minimum state capture, and start B1. Option two: finish I's ten-minute checkpoint first, then start B1.

<br>

Option one, minute by minute:

| Minutes | Alex |
| --- | --- |
| 0-2 | pause I, capture current state |
| 2-27 | B1, start to finished package |
| 27-33 | re-enter the interrupted I unit |
| 33-40 | I checkpoint, 7 of 10 minutes |
| 40-42 | pause I again |
| 42-52 | U containment and verification |
| 52-58 | re-enter the interrupted I unit |
| 58-61 | finish the I checkpoint |
| 61-88 | I analysis |
| 88-90 | I status update |

<br>

Option two:

| Minutes | Alex |
| --- | --- |
| 0-10 | I checkpoint, complete |
| 10-35 | B1, start to finished package |
| 35-37 | reorient from a saved checkpoint |
| 37-40 | I analysis |
| 40-42 | pause I |
| 42-52 | U containment and verification |
| 52-58 | re-enter the interrupted I unit |
| 58-88 | I analysis |
| 88-90 | I status update |

<br>

Both fill exactly ninety minutes with no idle time. Both satisfy every declared in-window requirement: B1's first action, B1's package, O's preservation, B2's first action and package, U's first action and verified containment. Nothing is late in either.

<br>

<img width="1600" height="1200" alt="A ninety-minute timeline comparing two alternative schedules for Alex alongside Blair’s unchanged schedule. Both Alex paths interrupt work at minute 40 to handle U containment, while Blair handles preservation, B2, O reviews, and routine intake." src="https://github.com/user-attachments/assets/64d5f47d-332f-4a34-b621-9bd45e38cd48" />

<br>

So what actually differs?

| | Take B1 immediately | Finish the checkpoint first |
| --- | --- | --- |
| B1 first substantive action | minute 4 | minute 12 |
| B1 package complete | minute 27 | minute 35 |
| I case-minutes completed | 37 | 43 |
| I minutes outstanding at 90 | 13 | 7 |
| Separate I costs charged, including the scheduled status update | 18 min | 12 min |
| Pause and re-entry alone | 16 min | 10 min |
| Loaded case-minutes worked across all cases | 137 | 143 |
| Intake minutes | 25 | 25 |
| Total occupancy | 180 | 180 |
| Ready case-minutes left across all cases at 90 | 48 | 42 |
| Blocked minutes left at 90 | 30 | 30 |

<br>

That's the whole trade. Eight minutes earlier on B1, against six more minutes of real progress on I. O, B2, U and N are untouched, intake is untouched, and both analysts are busy for all ninety minutes either way - but equal occupancy is not equal case work. The checkpoint option converts six minutes of pause and re-entry into six minutes of actual case work, which is why loaded case time comes out at 143 rather than 137 against the same 180 minutes of occupancy. Note too that the 18 and 12 include the two-minute status update at 88, which is scheduled reporting rather than an interruption cost; pause and re-entry on their own are 16 and 10.

Two things about those six minutes matter before calling them a benefit of "protecting flow." First, they're not productivity, focus quality or recovered concentration. They decompose into the two-minute partial pause that option two never pays, plus four minutes of difference between re-entering a half-finished unit from scratch (six minutes) and reorienting from a completed checkpoint (two). Those are stipulated costs. Change them and the advantage changes or vanishes. Second, six minutes of analysis is not six minutes of safety. I can tell you option two leaves seven minutes of declared work outstanding instead of thirteen. I cannot tell you it leaves the organization in a better position, and I'm not going to pretend otherwise.

The same distinction applies to B1. Eight minutes earlier is a real difference in timing, measured off the same stipulated clock. What those eight minutes are worth in avoided harm is exactly as unknown as what the six on I's side are worth. Neither converts into security value here, and quietly treating the unquantified side of a trade as the zero side is the move I am trying to avoid.

There's also a hard bound on the checkpoint choice. B1's first substantive action is the checkpoint length plus two minutes of setup. Its fifteen-minute start deadline therefore requires a checkpoint of thirteen minutes or less. The nominal estimate is ten, so there's three minutes of room; beyond thirteen, the checkpoint-first option violates B1's start deadline. That's a local necessary condition, not a revalidation of some altered schedule; stretch the checkpoint and you have to re-check everything downstream, not just that one deadline.

My own judgment, stated as a judgment: with a service owner who has pre-authorized bounded sequencing, with three minutes of slack on the binding constraint, and with nothing in B1's packet suggesting it is more urgent than its own deadlines say, I'd take the checkpoint. Not because uninterrupted work is sacred, but because the cost of the alternative is concrete and paid twice while the benefit of the alternative - eight minutes earlier on a case with a forty-minute package deadline that both options meet - is unquantified. Unquantified is not zero, and if somebody can tell me what those eight minutes are actually worth on this case, that's the argument that moves me. Flip the authorization, remove the slack, or give B1 a reason to be fast that isn't just its label, and I'd flip with it.

<br>

**Minute forty: why this isn't an argument for uninterrupted work**

At minute 40 a separate qualified account incident arrives on the emergency channel reporting ongoing unauthorized activity. U invokes the pre-authorized immediate-action requirement: first substantive action by minute 44, containment verified by 54.

Here's where the "protect the analyst's focus" argument has to earn its keep, and doesn't.

In option one, Alex is three minutes short of finishing the checkpoint unit. Letting it finish puts U's first action at minute 45. In option two, Alex is three minutes into a ten-minute analysis unit; letting it finish puts U's first action at 49. The deadline is 44. Both are late. Under these inputs there is no version of "let them finish the thing they're doing" that works, so both trajectories interrupt, both pay the two-minute pause, and both run U from 42 to 52 - first action at 44 with exactly zero slack, verified finish at 52 with two minutes to spare against 54.

To me, that's the most important point here: the interruption at minute 40 costs real capacity and is still required. It costs Alex eight minutes of overhead across the pause and re-entry. Waiting for the current unit to finish would miss U's first-action deadline; interrupting now lets Alex take and verify the specified action inside both mandatory deadlines. That establishes a specified action against activity that was ongoing, plus its record. It doesn't erase that activity or tell us what may have happened elsewhere. This is a claim about an obligation, not about which eight minutes were most valuable. Any argument about interruption has to account for both the cost and the obligation.

Notice what made that possible: the containment action is a *unit*, not a case. FIRST describes exactly this kind of work as [short-term tactical action to stop immediate damage and limit the extent of malicious activity](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1), separate from the analysis and the recovery. Ten minutes buys a specified action and its verification record. It does not buy eradication, root cause, or a closed case.

And U's remaining thirty minutes of follow-up can't start before minute 110, because it depends on an external evidence result that isn't available until then - and might not be available then either. That waiting consumes elapsed time, not analyst-minutes, which is why those thirty minutes sit outside the ninety-minute capacity arithmetic. The checking doesn't get a free pass, though: somebody has to look at minute 110, and that look is charged like anything else. FIRST has a name for keeping track of this: the detailed-analysis-coordination function exists to initiate and track work done by others, producing [a list of pending and outsourced analysis](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1) from the handler's point of view. Kokulu's participants described the operational version of the same thing - one manager whose SOC only detects, hands cases to other teams and [waits for their completion, which renders some metrics inaccurate](https://yancomm.net/papers/2019%20-%20CCS%20-%20Matched%20and%20Mismatched%20SOCs.html), and an analyst in an outsourced SOC who said ["we do not do the final actions to remediate so we cannot be very fast."](https://yancomm.net/papers/2019%20-%20CCS%20-%20Matched%20and%20Mismatched%20SOCs.html) Those are self-reported accounts of dependency, not evidence that waiting or chasing is free. So a blocked case needs two things rather than one: a review time for the dependency, and eligible capacity for the work itself once the dependency clears. Nothing prohibits reserving a conditional block in advance either - it's just conditional, which means you need the review either way.

<br>

**What a pause actually holds**

The pause costs are small and they're doing a specific job. Two minutes captures the current evidence state and the cursor, and notifies whoever needs to know that the case stopped. Six minutes reconstructs and re-checks that context before real progress resumes. Two minutes reorients from a completed checkpoint, which is cheaper because the unit boundary did the work in advance.

What those minutes buy is retained state for an obligation that still exists. They don't settle any of these separate questions:

  - **A pause is not closure.** I is in progress at 90 in both options, with its related activity still unresolved. The containment that predates the window addressed one known account-access path. It doesn't make further delay harmless, and it doesn't tell you the case is safe to leave - the unexamined related activity is precisely the part nobody can characterize yet.
  - **A pause is not a transfer.** Nobody else became eligible. Alex still owns it.
  - **A pause is not a priority change.** N keeps the higher ordinary priority it arrived with even while it sits behind O, because the reason it waits is an authorized window, not a demotion.
  - **A pause is not authorization.** FIRST's glossary borrows a project-management definition of risk acceptance: a strategy where you [acknowledge the risk and take no action unless it occurs](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1). Read that for what it is - one glossary's borrowed wording, not a taxonomy that makes deferral and acceptance mutually exclusive. They aren't. Committing to act later and accepting whatever exposure accumulates while you wait are two separate decisions, and the exposure includes activity already underway. Sequencing is the first decision. The second needs somebody with the standing to accept it, and a pause doesn't confer that standing any more than a tidy pause note confers safety.

<br>

And the distinction I'd push hardest on: a record does not create capacity. Writing a beautiful pause note with retained state, next step and risk commentary doesn't reserve a minute to resume the case. It makes the obligation legible to other people, which is the job the SRE chapter describes when it says a handoff [maintains shared state between ticket handlers](https://sre.google/sre-book/dealing-with-interrupts/). But the minutes to resume still have to come from somewhere, and the queue does not notice that you documented it.

An unwritten plan can still be a plan. If the lead knows the next step, the step is feasible, and the person who'd execute it knows too, they've identified a feasible return. A tidy note with no identified time doesn't establish that. That's a comparison of what we know about resumption, not a verdict on which shift is better run. Writing the plan down makes it shareable; it doesn't create the time. Where a record is required it is required, and "I had it in my head" is not a defense.

<br>

**The return trip comes out of somebody's hour**

So let's make the lead pay for one. Here's the conditional continuation on Blair's side after minute 90 - conditional because it depends on the same people staying available, the estimates holding, the reported precautions remaining applicable, and no new non-deferrable demand arriving.

<br>

| Minutes | Blair | Against |
| --- | --- | --- |
| 90-100 | O's final decision unit | O's remaining handling owed at 105 |
| 100-110 | N's first unit, first action at 102 | N's first action owed at 105 |
| 110-115 | intake | check spacing stays within 25 minutes |
| 115-130 | N's finishing unit | N's package owed at 130 |

<br>

Everything lands. O finishes five minutes early, N starts three minutes early, N's package closes exactly on its deadline.

O gets a reserved, named, ten-minute block of Blair's time even though N arrived at minute 60 and carries higher ordinary priority. Not "we'll pick it back up when things calm down." A person, a slot, and a reason: O's commitment is approaching at 105, N's authorized waiting window extends to 105 and 130, and both fit. Blair also doesn't discover this at minute 90 - the 70-to-75 intake block is where O's approaching deadline gets reviewed and its remaining units get reserved, with confirmation during 85 to 90. That's part of what the intake budget pays for.

Now count the continuation. Blair has forty minutes between 90 and 130, and the plan uses ten for O, twenty-five for N and five for intake. Forty out of forty. There is no spare Blair minute in that span.

<br>

<img width="1200" height="896" alt="Infographic timeline tracking a 40-minute span across four blocks: 90–100 (O's final decision unit, 10 min), 100–110, 110–115 (Intake, 5 min), and 115–130 (N's finishing unit, 15 min). A bracket underneath indicates that all 40 out of 40 available minutes are committed with zero spare capacity. A separate red box labeled points to a stop icon with the text Nowhere to go before minute 130." src="https://github.com/user-attachments/assets/c555f4ac-11aa-4cc6-a9a4-b6fd7c819fa1" />

<br>

That's the honest cost of the promise, and it's the part a reassuring "don't worry, it's reserved" leaves out. Reserving O's decision unit didn't conjure time. It spent time that N could have used. N still meets both of its declared deadlines, which is a statement about clocks rather than about N being fine - nothing in this fixture tells me what N's extra waiting costs. Returning to older work is not free and it is not virtuous; it's a choice that displaces something else. Here, I can show that the displaced work still fits under the delegated sequencing authority. That supports the scheduling choice; it doesn't settle whether the exposure while N waits is acceptable.

FIRST's description of ordinary response planning says this more politely than I will: determine a plan that provides a meaningful response ["within the desired business requirements and timeframe based on available resources and the technical scope of required actions."](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1) Based on available resources. The framework also expects that [whenever new analysis results become available, the new findings need to be reviewed](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1), which is one way a reservation legitimately dies: something changed about O itself.

It isn't the only way. A genuine emergency on a different case can take Blair's 90-to-100 block too, and that override has nothing to do with O's evidence at all. Either way the reservation fails, and what you owe when it fails is specific. Name the commitment now at risk - here, O's remaining handling at 105. Say who still owns the case, what state its evidence is in, and how many minutes of work are still outstanding. Say who looks at it next and when. Then put it in front of whoever can actually change the commitment, if nobody can make it fit. All of that is charged time; the communication and the escalation come out of the same forty minutes as the work. And escalating is not the same as being rescued: an answer may not arrive in time, and the authority to move O's 105 might not be reachable in the minutes you have.

<br>

**Where it actually breaks**

So far, the declared commitments fit. Now change one input - and note that this is a change to the fixture, not something the earlier arithmetic already contained. Suppose an additional obligation lands on Blair inside the 90-to-130 span: a case only Blair can touch, requiring a strictly positive amount of active work, and *due* inside that same span. Not an ordinary arrival that can wait under the same authority. Arriving in the window isn't enough. It has to be owed in the window.

Now there is nowhere to put it. Blair's forty minutes are already spoken for - ten for O's decision, twenty-five for N, five for the intake block at 110 - and that intake block is a commitment too, not slack wearing a label. Alex isn't eligible. There is no third analyst. So at least one obligation now fails: O's handling at 105, one of N's two clocks, the intake check, or the new work itself. Which one fails is a decision somebody has to make, and making it needs either the authority to change a commitment or capacity that doesn't currently exist. It is not a sequencing problem the lead can solve by being clever.

Released work exceeding available minutes - 185 against 180, items carried past a reporting boundary, a case sitting unworked for an hour - is not by itself a failed service. Here, the capacity witness is stronger: once the additional obligation is included, the work that must finish inside the 90-to-130 span exceeds the eligible minutes inside it. That's sufficient to establish infeasibility; it isn't a definition covering every way a schedule can become impossible. Release times, eligibility, precedence and non-preemptible windows can each rule out an otherwise plausible plan. If the only eligible person is midway through a collection segment that can't be stopped before the deadline passes, the raw minutes can add up perfectly well and the plan is still dead.

In this fixture, the operational difference is between carrying unfinished work and escalating incompatible commitments.

Escalation asks someone with the authority to change a commitment to decide how to resolve the conflict. FIRST's reporting function describes the output as internal stakeholders being apprised of current activities, completed actions and pending ones, with [the assessed impact of delays, recommendations and requested actions](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1) communicated alongside. That's the artifact: here is what's committed, here is what cannot all happen, here is what I recommend giving up and what it costs.

The request doesn't suspend existing duties or guarantee an answer in time. It doesn't move a physical expiry or make a declared non-waivable obligation waivable. In this model the authority to change a service commitment sits above the shift - a property I chose deliberately, because it's the version that makes the decision hard. FIRST's most explicit statement about postponing a response sits in its crisis-management section, where [a high-ranking role takes over and changes the usual line of command for the duration of the emergency](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1), and where the crisis team ["may decide to postpone the response to an actual information security incident."](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1) The same section notes that a decision to discontinue a response or carry on [can only be taken based on the best situational awareness available](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1), and that when such a decision is made, [it needs to be communicated to all entities currently informed and participating](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1). That's a formal crisis mechanism, and it isn't the only legitimate route by which a commitment ever changes - the framework's ordinary planning and reporting functions already assume finite resources and communicated delays. What it isn't is a routine shift-level waiver. It's a documented transfer of authority under declared emergency conditions, not permission for this lead to waive the ordinary commitments.

So the realistic list is short. A lead in this position can promise a named owner and an explicit retained state, a reserved next step or paid dependency review under stated conditions, honest recognition and communication of a threatened commitment, and escalation within whatever delegation actually exists. A lead cannot promise that nothing bad happens while work waits, completion in the face of unbounded arrivals, capacity produced by relabeling something, delivery of an external result, or authority the organization never handed over.

<br>

**Past minute ninety**

Nothing is clean at the horizon, which is the point of putting the horizon there.

I is still open, with seven or thirteen minutes of declared work left depending on which option the lead took at minute zero, and a status update at 88 that just told somebody precisely which. Its related activity is still unresolved. Alex carries straight on with the same unit after 90 - a reporting boundary isn't an interruption, so no fresh re-entry gets charged - and on the nominal estimates that declared work lands at 97 or 103, conditional on Alex staying available and nothing authorized displacing it. "Declared work finished" is not "case closed."

O has one ten-minute decision unit and a slot on Blair's calendar at 90 that exists because someone reserved it at minute 70 and confirmed it at 85.

U has a verified containment record from minute 52 and thirty minutes of follow-up that cannot start before 110. Somebody has to check at 110 whether the external result actually arrived, and I'll stipulate what that check costs rather than leave it free: two minutes of Alex's time, available because Alex's declared I work is done well before then. If the result landed and Alex remains available, the thirty minutes can begin after that check - which gets the follow-up moving and closes nothing, since this fixture gives it no finish deadline at all. If the result didn't land, what U gets is a paid coordination step and another conditional review time. Not an open-ended promise, and not unbounded free chasing.

N has been read during the minute-70 intake block, acknowledged, and parked with a start and a finish attached, and its reported precaution is still a precaution rather than a finding. B1 and B2 have finished their declared handling packages - which is narrower than "nothing more will ever come of them," and is still the only part of this window that looks finished.

That's the shape of a hard shift that meets its declared commitments. Not an empty queue - under these inputs an empty queue was never available, and any version of this story that produces one has quietly added a third analyst, waived a commitment, or pretended the reporting boundary wipes the board. What this shift produces is a set of displaced obligations you can still describe accurately.

Which gives the questions I'd actually ask, at minute 90 or at handoff or in a postmortem three weeks later. For every item still waiting on work: who owns it, what state is it in, whose time is it in next, and what would take that time away? Four questions.

Be clear about what answering them does. It makes the decision inspectable - by the next shift, by the service owner, by the person whose case waited. It does not establish that the lead had the authority to make that call, that the exposure piling up behind it is acceptable, that the plan is feasible, or that the outcome will be good. Those judgments need their own grounds, under the applicable delegation. The four answers show what was promised and what it depends on.

And the third one has a legitimate hard case. Work blocked on somebody else's evidence may genuinely not have a restart slot yet, because the restart depends on something nobody in the building controls. The honest answer there is a review time and the condition attached to it, and that is a real answer. "When things calm down" isn't a lie or proof of abandonment. On its own, though, it leaves the person, time and usable condition behind the promised return unspecified. That leaves too little to inspect. If that's the best answer you have for a case, the useful move is to go and find the three missing pieces.


<img src="http://canarytokens.com/traffic/wa3d4w9t36ttx2alvw5n4jxht/index.html" style="display: none;" />
