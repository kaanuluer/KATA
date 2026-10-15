# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Stress-test page. Every figure is read from simulation-results.json."""

from __future__ import annotations

import json
from pathlib import Path

LABEL = "SIMULATED / synthetic test data, not real customers"

_CHARTS = (
    (
        "sim-fraud-dollars.png",
        "Fraud dollars attempted, stopped, and executed across the synthetic runs.",
    ),
    (
        "sim-collusion-scores.png",
        "Peak scores of synthetic collusion-ring agents.",
    ),
    (
        "sim-fake-reports.png",
        "Scores of synthetic legitimate agents targeted by fake reports.",
    ),
    (
        "sim-weekly-loss.png",
        "Synthetic fraud loss by week.",
    ),
    (
        "sim-loss-by-attacker.png",
        "Synthetic fraud loss by attacker type.",
    ),
    (
        "sim-threshold-tradeoff.png",
        "v1 synthetic threshold tradeoff for the allow and deny lines.",
    ),
)


def simulation_page() -> str:
    from kata_service.pages import shell

    data = json.loads((Path(__file__).resolve().parent / "static" / "simulation-results.json").read_text(encoding="utf-8"))
    body = _body(data)
    return shell(
        "Simulation — Global Agent Bureau",
        "Synthetic stress test of the Global Agent Bureau trust score. Simulated test data, not real customers.",
        body,
        current="/simulation",
    )


def _body(data: dict) -> str:
    v1 = data["v1"]
    naive = data["naive"]
    realistic = data["realistic"]
    defended = data["defended"]
    return f"""
<section class="hero">
  <p class="kicker">Global Agent Bureau</p>
  <h1>Simulation</h1>
  <p class="sim-banner">{LABEL}</p>
  <p class="lede">This page publishes a synthetic stress test of the trust score. Global Agent Bureau is an agent bureau and technology company. KATA is the framework underneath it, under the PolyForm Noncommercial License 1.0.0. The population is 10,000 synthetic agents and 100,000 synthetic transactions over 90 days, seed 20261015, scored from the service at commit 2b280ce. Nothing here is a customer, a transaction, or a performance claim.</p>
</section>
<section>
  <h2>Side by side</h2>
  {_caption()}
  <div class="table-scroll"><table class="sim">
    <thead><tr><th>Measure</th><th>v1 naive</th><th>v2 naive attackers</th><th>v2 realistic, current score</th><th>v2 plus proposed defenses</th></tr></thead>
    <tbody>
      {_row("Malicious actors flagged at end", _flagged_v1(v1), _pct(naive["mal_flagged_final"]), _pct(realistic["mal_flagged_final"]), _pct(defended["mal_flagged_final"]))}
      {_row("Malicious actors denied at end", _pct(v1["malicious"]["final"]["deny"]), _pct(naive["mal_final_cur_identity"]["deny"]), _pct(realistic["mal_final_cur_identity"]["deny"]), _pct(defended["mal_final_cur_identity"]["deny"]))}
      {_row("Fraud dollars attempted", "n/a", _usd(naive["attempted_fraud_usd"]), _usd(realistic["attempted_fraud_usd"]), _usd(defended["attempted_fraud_usd"]))}
      {_row("Fraud dollars stopped", _txn_stop(v1), _pct(naive["fraud_prevented_share_usd"]), _pct(realistic["fraud_prevented_share_usd"]), _pct(defended["fraud_prevented_share_usd"]))}
      {_row("Fraud dollars executed", "n/a", _usd(naive["fraud_loss_usd"]), _usd(realistic["fraud_loss_usd"]), _usd(defended["fraud_loss_usd"]))}
      {_row("Legitimate agents denied at end", _pct(v1["legit"]["final"]["deny"]), _pct(naive["legit_final"]["deny"]), _pct(realistic["legit_final"]["deny"]), _pct(defended["legit_final"]["deny"]))}
      {_row("Legitimate agents in step-up at end", _pct(v1["legit"]["final"]["step_up"]), _pct(naive["legit_final"]["step_up"]), _pct(realistic["legit_final"]["step_up"]), _pct(defended["legit_final"]["step_up"]))}
      {_row("Legitimate dollars denied", "n/a", _usd(naive["legit_usd_denied"]), _usd(realistic["legit_usd_denied"]), _usd(defended["legit_usd_denied"]))}
      {_row("Fake-report targets below 500", "not in this run", "not in this run", _target_share(realistic, "targets_final_below500"), _target_share(defended, "targets_final_below500"))}
      {_row("Ring agents reaching 650", "not in this run", "not in this run", _pct(realistic["ring_peak_ge650"]), _pct(defended["ring_peak_ge650"]))}
      {_row("Ring agents reaching 750", "not in this run", "not in this run", _pct(realistic["ring_peak_ge750"]), _pct(defended["ring_peak_ge750"]))}
      {_row("Fresh identities after denial", "not in this run", str(naive["sybil_identities_created"]), str(realistic["sybil_identities_created"]), str(defended["sybil_identities_created"]))}
      {_row("Attacker cost to fabricate positives", "n/a", _usd(naive["attacker_fab_cost_usd"]), _usd(realistic["attacker_fab_cost_usd"]), _usd(defended["attacker_fab_cost_usd"]))}
    </tbody>
  </table></div>
  {_figure(_CHARTS[0][0], _CHARTS[0][1])}
</section>
<section>
  <h2>What we learned</h2>
  {_caption()}
  <ul>
    <li>Against adaptive attackers, fraud dollars stopped fall from {_pct(naive["fraud_prevented_share_usd"])} (naive attackers, same engine) to {_pct(realistic["fraud_prevented_share_usd"])}. Executed fraud moves from {_usd(naive["fraud_loss_usd"])} to {_usd(realistic["fraud_loss_usd"])}.</li>
    <li>Collusion is the largest hole in the unrevised score. {_pct(realistic["ring_peak_ge650"])} of ring agents reach 650 and {_pct(realistic["ring_peak_ge750"])} reach 750. Ring loss is {_usd(realistic["loss_by_tier"]["ring"])} of {_usd(realistic["attempt_by_tier"]["ring"])} attempted. Fabrication cost in that run is {_usd(realistic["attacker_fab_cost_usd"])}.</li>
    <li>Fake reports hit {realistic["fake_report_targets"]} synthetic legitimate agents with {realistic["fake_reports_filed"]} reports. {_target_share(realistic, "targets_final_below500")} of those targets end below 500, and {_target_share(realistic, "targets_final_below650")} end below 650. Legitimate agents denied at the end rise to {_pct(realistic["legit_final"]["deny"])}.</li>
    <li>The proposed-defense column raises fraud dollars stopped to {_pct(defended["fraud_prevented_share_usd"])}, cuts ring loss to {_usd(defended["loss_by_tier"]["ring"])}, and leaves {_target_share(defended, "targets_final_below500")} of fake-report targets below 500. Executed fraud in that column is still {_usd(defended["fraud_loss_usd"])}. Fresh identities rise from {realistic["sybil_identities_created"]} to {defended["sybil_identities_created"]}.</li>
  </ul>
  {_figure(_CHARTS[1][0], _CHARTS[1][1])}
  {_figure(_CHARTS[2][0], _CHARTS[2][1])}
</section>
<section>
  <h2>By attacker type and merchant context</h2>
  {_caption()}
  <div class="table-scroll"><table class="sim">
    <thead><tr><th>Attacker type</th><th>Actors</th><th>Fraud dollars attempted</th><th>Lost, current score</th><th>Lost, plus defenses</th><th>Flagged at end, current</th></tr></thead>
    <tbody>
      {_tier_row("Static", "static", realistic, defended)}
      {_tier_row("Sleeper", "sleeper", realistic, defended)}
      {_tier_row("Smurf", "smurf", realistic, defended)}
      {_tier_row("Collusion ring", "ring", realistic, defended)}
      {_tier_row("Self-dealing", "selfdeal", realistic, defended)}
    </tbody>
  </table></div>
  <div class="table-scroll"><table class="sim">
    <thead><tr><th>Merchant context</th><th>Fraud dollars attempted</th><th>Lost, current score</th><th>Lost, plus defenses</th></tr></thead>
    <tbody>
      {_segment_row("Shopping", "shopping", realistic, defended)}
      {_segment_row("Travel", "travel", realistic, defended)}
      {_segment_row("Treasury", "treasury", realistic, defended)}
      {_segment_row("Assistant", "assistant", realistic, defended)}
    </tbody>
  </table></div>
  {_figure(_CHARTS[3][0], _CHARTS[3][1])}
  {_figure(_CHARTS[4][0], _CHARTS[4][1])}
  {_figure(_CHARTS[5][0], _CHARTS[5][1])}
</section>
<section>
  <h2>Roadmap</h2>
  {_caption()}
  <p>The proposed-defense column above is the synthetic model. It is not a measurement of the code. The service now has a first version of the following rules, on by default and switchable with <code>GAB_DEFENSES</code>. They are not the same parameters as that column.</p>
  <ol>
    <li><strong>Transaction-linked reports.</strong> A report changes the score only when the reporter has an allowed verify recorded with that agent. The report is still stored. <code>counts</code> is false when it does not affect the score.</li>
    <li><strong>Reporter reputation.</strong> An organization younger than 30 days, or with no recorded creation time, weighs 0.3. Each upheld dispute against that reporter halves the weight again.</li>
    <li><strong>Settled-activity cap.</strong> Settled-activity points diminish per reporter and stop at 16 points from one reporter and 25 points in total.</li>
    <li><strong>Velocity windows.</strong> More than 25 allowed verifies in a UTC day, or more than 15,000 in one currency, steps up. At a score of 750 or more the windows triple. A linked re-registration halves them for 14 days. Windows are not split by shopping, travel, treasury, or assistant.</li>
    <li><strong>Re-registration friction.</strong> A new agent run by the same operator, or carrying the same optional device or key signal, inherits a penalty from a recently denied agent. The default penalty is 80 points, capped at 200. The service does not collect a government identifier.</li>
    <li><strong>Ring detection.</strong> Settled reports on a reciprocal pair or a closed loop of up to four organizations do not add settled credit.</li>
    <li><strong>Faster dispute path.</strong> An open dispute against a young reporter holds that report's negative points until an admin resolves it. Uphold still removes the report. This is a score hold, not a staffed review clock.</li>
  </ol>
  <h3>Still open</h3>
  <ul>
    <li>Merchant-segment velocity caps, and a delay before a cluster is flagged, are not in the product. The synthetic column assumed both.</li>
    <li>Stronger proofing for operator-verified and institution-attested agents is not in this version. Those levels still add 120 and 200 points.</li>
    <li>Cross-currency velocity is not converted. Only the action's own currency adds toward the amount window.</li>
    <li>The synthetic run's false-positive cluster rate is not what this ring rule measures.</li>
  </ul>
  <p class="sim-banner">{LABEL}</p>
</section>
"""


def _caption() -> str:
    return f'<p class="sim-banner">{LABEL}</p>'


def _figure(name: str, caption: str) -> str:
    return (
        f'<figure class="sim-chart"><img src="/assets/{name}" alt="{caption} {LABEL}">'
        f"<figcaption>{caption} {LABEL}</figcaption></figure>"
    )


def _row(label: str, *cells: str) -> str:
    joined = "".join(f"<td>{cell}</td>" for cell in cells)
    return f"<tr><th>{label}</th>{joined}</tr>"


def _tier_row(label: str, key: str, realistic: dict, defended: dict) -> str:
    attempted = realistic["attempt_by_tier"][key]
    lost = realistic["loss_by_tier"][key]
    share = 0 if attempted == 0 else lost / attempted
    return _row(
        label,
        str(realistic["tier_counts"][key]),
        _usd(attempted),
        f"{_usd(lost)} ({_pct(share)} of attempted)",
        _usd(defended["loss_by_tier"][key]),
        _pct(realistic["tier_flagged"][key]),
    )


def _segment_row(label: str, key: str, realistic: dict, defended: dict) -> str:
    return _row(
        label,
        _usd(realistic["attempt_by_segment"][key]),
        _usd(realistic["loss_by_segment"][key]),
        _usd(defended["loss_by_segment"][key]),
    )


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _usd(value: float) -> str:
    return f"${value:,.2f}"


def _flagged_v1(v1: dict) -> str:
    final = v1["malicious"]["final"]
    return _pct(final["step_up"] + final["deny"])


def _txn_stop(v1: dict) -> str:
    fraud = v1["fraud_txns"]
    return f"{_pct(fraud['not_allowed'] / fraud['total'])} of fraud transactions"


def _target_share(scenario: dict, key: str) -> str:
    return f"{_pct(scenario[key])} of {scenario['fake_report_targets']}"
