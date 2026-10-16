# Trust-score abuse review

**Status: review of the live score.** Global Agent Bureau is an agent bureau. KATA is the framework. The published model is `gab-score-1`. This note names the paths that can move an agent score and the controls that already limit them. It is not a procedure, a customer claim, or a performance result.

The framework threat model is in [threat-model.md](threat-model.md). Requirements for the same controls are in [gab-requirements.md](gab-requirements.md).

## What the score is

The score belongs to an agent. Individuals are not scored. Risk is 1000 minus the score. A new agent with no contributing report starts at the baseline of 500 and is marked cold start. An inquiry reads the score. It does not add or remove points.

Identity assurance, operator status, linked reports, and inherited history are the inputs. `GAB_SCORE_WEIGHTS` can replace a published weight inside a fixed range. That variable is an operator control. A change there changes every score that uses the new weights.

`GAB_DEFENSES` is the master switch for most of the checks below. Turned off, the score falls back toward the earlier formula, which accepted a report without a transaction link. Two switches do not follow that master: proofing stays required, and operator history stays on, unless their own variables turn them off.

## Settled credit

A settled transaction outcome adds a small positive weight. The same organization can file many of them.

What limits it:

- The report has to be linked to a real transaction with that agent. An unlinked report is rejected and is not stored.
- Thin, new, or one-sided links count less.
- Settled points are capped in total and per reporter. The cap grows only when external counterparties and external volume are both present.
- Reports from the agent's own operator are multiplied down. They still count.
- A closed cluster of organizations, or organizations that share a signal, loses its internal settled credit. The score reason is `RING_DISCOUNTED`. The default cluster is three organizations with most of the volume staying inside the group.

What remains:

- A group smaller than that cluster, or a group with enough activity outside itself, still receives settled credit up to the cap.
- Self-filed settled outcomes are down-weighted, not dropped.
- Reaching a high score widens the daily velocity window. The default band is 750, and the static window triples there. Probation cuts the window in half.

## Negative reports, young reporters, and disputes

Fraud, chargeback, policy, and loss outcomes reduce the score. The same evidence hash keeps the strongest reporter weight, so copies of one incident do not stack.

What limits a false negative:

- The same link rule applies. A reporter that never transacted with the agent cannot file the report.
- A reporter in its first 30 days counts at 0.3. An upheld dispute against that reporter cuts the weight again.
- A negative that disagrees with settled activity from the same reporter, or that sits in a tight cluster of negatives, is down-weighted.
- An open dispute pauses the negative points of a young reporter. The score reason is `DISPUTE_HOLD`. There is no review deadline. A mature reporter's negatives are not paused by that hold.
- A resolved dispute with outcome upheld removes the report from the score. A partial outcome halves the weight.

What remains:

- Opening a dispute against a young reporter delays that negative until someone resolves it.
- A mature reporter's negative lands immediately, which is the intended case and also the case a captured mature credential can use.

## A new agent beside a denied one

History follows the agent, and it follows a shared device signal or key signal. It does not follow a person.

What limits a clean restart:

- The same operator window looks back 14 days for a denied agent.
- A shared signal extends that lookback to 90 days. A confirmed-malicious agent (revoked, suspended, or a fraud report still on it) uses 180 days.
- Linked negative history is inherited with a 30-day half-life. The score reason is `INHERITED_HISTORY`.

What remains:

- A new key and a new device signal start at the baseline. The denied agent's score stays on that agent.
- Inherited points decay. After several half-lives the link is still recorded and the points are small.

## Velocity

A count, amount, burst, or cash-out breach is a deny. The denied attempt does not add to the recorded spend, so repeating it does not fill the window by itself. A high score widens the static window, as noted above. Named segments use the tighter of the static cap and the segment window.

## What this review treats as operational

Keep link checks, settled caps, ring detection, velocity, and proofing on in production. Treat `GAB_DEFENSES` and `GAB_SCORE_WEIGHTS` as production controls, not as calibration knobs to leave unset on a public deployment.

The largest gap is structural: the score does not follow the person. A principal can hold a clean agent next to a denied one when the device signal and the key signal do not match.
