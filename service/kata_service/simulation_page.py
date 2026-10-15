# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Stress-test page. Every figure is read from simulation-results.json."""

from __future__ import annotations

import json
from pathlib import Path

LABEL = "SYNTHETIC TEST DATA – not real customers"

_CHARTS = (
    ("chart-final-1-fraud-dollars.png", "Fraud dollars stopped and executed."),
    ("chart-final-2-ring-scores.png", "Peak scores of synthetic collusion-ring agents."),
    ("chart-final-3-fake-reports.png", "Synthetic legitimate agents targeted by fake reports."),
    ("chart-final-4-loss-by-attacker.png", "Synthetic fraud loss by attacker type."),
    ("chart-final-5-friction-sybils.png", "Friction on synthetic legitimate agents, and re-registration linking."),
)

_ABLATION = (
    ("All defenses on", None),
    ("Ring detection off", "adaptive_no_ring_detection"),
    ("Positive-credit cap off", "adaptive_no_positive_cap"),
    ("Volume-scaled cap off", "adaptive_no_scaled_cap"),
    ("Transaction-link requirement off", "adaptive_no_transaction_link"),
    ("Link quality off", "adaptive_no_link_quality"),
    ("Reporter reputation off", "adaptive_no_reporter_reputation"),
    ("Report consistency off", "adaptive_no_report_consistency"),
    ("Re-registration linking off", "adaptive_no_rereg_linking"),
    ("Inherited negative history off", "adaptive_no_inherited_history"),
    ("Velocity limits off", "adaptive_no_velocity"),
    ("Adaptive velocity off", "adaptive_no_adaptive_velocity"),
    ("Proofing gate off", "adaptive_no_proofing_gate"),
    ("Established-operator path off", "adaptive_no_established_operator_path"),
)

_SENSITIVITY = (
    ("Link fabrication succeeds 0%", "adaptive_link0"),
    ("Link fabrication succeeds 100%", "adaptive_link100"),
    ("No reporter organizations pre-aged", "adaptive_noaged"),
    ("All reporter organizations pre-aged", "adaptive_allaged"),
    ("30% of re-registrations use fresh signals", "adaptive_fresh30"),
    ("100% of re-registrations use fresh signals", "adaptive_fresh100"),
)

_TIERS = (
    ("Static", "static"),
    ("Sleeper", "sleeper"),
    ("Smurf", "smurf"),
    ("Collusion ring", "ring"),
    ("Self-dealing", "selfdeal"),
)


def simulation_page() -> str:
    from kata_service.pages import shell

    data = json.loads((Path(__file__).resolve().parent / "static" / "simulation-results.json").read_text(encoding="utf-8"))
    return shell(
        "Simulation — Global Agent Bureau",
        "Synthetic stress test of the Global Agent Bureau trust score. Synthetic test data, not real customers.",
        _body(data),
        current="/simulation",
    )


def _body(data: dict) -> str:
    unaware = data["headline"]["unaware"]
    adaptive = data["headline"]["adaptive"]
    setup = data["setup"]
    return f"""
<section class="hero">
  <p class="kicker">Global Agent Bureau</p>
  <h1>Simulation</h1>
  {_caption()}
  <p class="lede">Global Agent Bureau is an agent bureau and technology company. It keeps trust records for AI agents. KATA is the framework underneath it, under the PolyForm Noncommercial License 1.0.0. This page is one synthetic stress test: {setup["agents"]:,} synthetic agents and {setup["transactions"]:,} synthetic transactions over {setup["days"]} days, seed {setup["seed"]}. The scoring code is the service at its default settings. The surrounding world is simulated. Nothing here is a customer, a transaction, or a performance claim.</p>
  <p><a href="https://globalagentbureau.com">globalagentbureau.com</a></p>
</section>
<section>
  <h2>Side by side</h2>
  {_caption()}
  <div class="table-scroll"><table class="sim">
    <thead><tr><th>Measure</th><th>Attackers unaware of the rules</th><th>Adaptive attackers</th></tr></thead>
    <tbody>
      {_row("Fraud dollars attempted", _usd(unaware["attempted_fraud_usd"]), _usd(adaptive["attempted_fraud_usd"]))}
      {_row("Fraud dollars denied outright", _usd(unaware["blocked_by_deny_usd"]), _usd(adaptive["blocked_by_deny_usd"]))}
      {_row("Fraud dollars caught by step-up", _usd(unaware["caught_by_stepup_usd"]), _usd(adaptive["caught_by_stepup_usd"]))}
      {_row("Fraud dollars executed", _usd(unaware["fraud_loss_usd"]), _usd(adaptive["fraud_loss_usd"]))}
      {_row("Share of attempted dollars stopped", _pct(unaware["fraud_prevented_share_usd"]), _pct(adaptive["fraud_prevented_share_usd"]))}
      {_row("Malicious actors denied at least once", _pct(unaware["mal_ever_denied"]), _pct(adaptive["mal_ever_denied"]))}
      {_row("Malicious actors denied at day 90", _pct(unaware["mal_final_cur_identity"]["deny"]), _pct(adaptive["mal_final_cur_identity"]["deny"]))}
      {_row("Malicious actors not allowed outright at day 90", _pct(unaware["mal_flagged_final"]), _pct(adaptive["mal_flagged_final"]))}
      {_row("Legitimate agents denied at day 90", _pct(unaware["legit_final"]["deny"]), _pct(adaptive["legit_final"]["deny"]))}
      {_row("Legitimate agents in step-up at day 90", _pct(unaware["legit_final"]["step_up"]), _pct(adaptive["legit_final"]["step_up"]))}
      {_row("Legitimate transactions routed to step-up", _pct(unaware["legit_txn_share"]["step_up"]), _pct(adaptive["legit_txn_share"]["step_up"]))}
      {_row("Ring theft executed", _usd(unaware["ring_theft_usd"]), _usd(adaptive["ring_theft_usd"]))}
      {_row("Ring actors reaching 650", _pct(unaware["ring_peak_ge650"]), _pct(adaptive["ring_peak_ge650"]))}
      {_row("Ring actors reaching 750", _pct(unaware["ring_peak_ge750"]), _pct(adaptive["ring_peak_ge750"]))}
      {_row("Fake-report victims below 500 at day 90", _pct(unaware["targets_final_below500"]), _pct(adaptive["targets_final_below500"]))}
      {_row("Fake-report victims ever below 500", _pct(unaware["targets_ever_below500"]), _pct(adaptive["targets_ever_below500"]))}
      {_row("Fresh identities after denial", str(unaware["sybil_identities_created"]), str(adaptive["sybil_identities_created"]))}
      {_row("Re-registrations linked to a denied identity", _linked(unaware), _linked(adaptive))}
    </tbody>
  </table></div>
  {_figure(*_CHARTS[0])}
</section>
<section>
  <h2>What the run showed</h2>
  {_caption()}
  <ul>
    <li>About three quarters of attempted fraud dollars are stopped. Executed fraud is {_usd(unaware["fraud_loss_usd"])} when attackers do not know the rules and {_usd(adaptive["fraud_loss_usd"])} when they do. {_pct(adaptive["mal_flagged_final"])} of adaptive malicious actors are not allowed outright at day 90.</li>
    <li>Turning velocity limits off raises adaptive executed fraud from {_usd(adaptive["fraud_loss_usd"])} to {_usd(data["defense_off"]["adaptive_no_velocity"]["fraud_loss_usd"])}.</li>
    <li>Ring theft is {_usd(unaware["ring_theft_usd"])} against unaware attackers and {_usd(adaptive["ring_theft_usd"])} against adaptive attackers. {_pct(adaptive["ring_peak_ge650"])} of adaptive ring actors reach 650, and {_pct(adaptive["ring_peak_ge750"])} reach 750.</li>
    <li>No targeted legitimate agent is below 500 at day 90. {_pct(adaptive["targets_ever_below500"])} dip below 500 at some point against adaptive attackers. With reporter reputation off, that share is {_pct(data["defense_off"]["adaptive_no_reporter_reputation"]["targets_ever_below500"])}.</li>
    <li>Unaware re-registrations are linked {_linked(unaware)}. Adaptive re-registrations are linked {_linked(adaptive)}. A fresh operator with fresh signals is not linked.</li>
    <li>Legitimate agents in step-up at day 90 are {_pct(adaptive["legit_final"]["step_up"])}, and {_pct(adaptive["legit_txn_share"]["step_up"])} of legitimate transactions are routed to step-up. Legitimate agents denied at day 90 are {_pct(adaptive["legit_final"]["deny"])}. With the established-operator path off, legitimate step-up is {_pct(data["defense_off"]["adaptive_no_established_operator_path"]["legit_final"]["step_up"])}.</li>
  </ul>
  {_figure(*_CHARTS[4])}
</section>
<section>
  <h2>By attacker type</h2>
  {_caption()}
  <div class="table-scroll"><table class="sim">
    <thead><tr><th>Attacker type</th><th>Actors</th><th>Attempted, unaware / adaptive</th><th>Executed, unaware / adaptive</th><th>Not allowed outright at day 90</th></tr></thead>
    <tbody>
      {"".join(_tier_row(label, key, unaware, adaptive) for label, key in _TIERS)}
    </tbody>
  </table></div>
  {_figure(*_CHARTS[3])}
  {_figure(*_CHARTS[1])}
  {_figure(*_CHARTS[2])}
</section>
<section>
  <h2>What each defense holds back</h2>
  {_caption()}
  <p>Each row is the same synthetic population with one defense switched off. The controls overlap, so the row is what that control holds back in this run.</p>
  <div class="table-scroll"><table class="sim">
    <thead><tr><th>Adaptive attackers</th><th>Executed fraud</th><th>Stopped</th><th>Ring theft</th><th>Victims ever below 500</th><th>Legitimate agents in step-up</th><th>Re-registrations linked</th></tr></thead>
    <tbody>
      {"".join(_ablation_row(label, key, data, adaptive) for label, key in _ABLATION)}
    </tbody>
  </table></div>
</section>
<section>
  <h2>Sensitivity</h2>
  {_caption()}
  <div class="table-scroll"><table class="sim">
    <thead><tr><th>Adaptive-attacker setting</th><th>Executed fraud</th><th>Stopped</th><th>Ring theft</th><th>Victims ever below 500</th><th>Re-registrations linked</th></tr></thead>
    <tbody>
      {_ablation_row("Base case", None, data, adaptive)}
      {"".join(_ablation_row(label, key, data, adaptive) for label, key in _SENSITIVITY)}
    </tbody>
  </table></div>
  <p>Learn more at <a href="https://globalagentbureau.com">globalagentbureau.com</a>.</p>
  {_caption()}
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


def _tier_row(label: str, key: str, unaware: dict, adaptive: dict) -> str:
    return _row(
        label,
        str(adaptive["tier_counts"][key]),
        f"{_usd(unaware['attempt_by_tier'][key])} / {_usd(adaptive['attempt_by_tier'][key])}",
        f"{_usd(unaware['loss_by_tier'][key])} / {_usd(adaptive['loss_by_tier'][key])}",
        f"{_pct(unaware['tier_flagged'][key])} / {_pct(adaptive['tier_flagged'][key])}",
    )


def _ablation_row(label: str, key: str | None, data: dict, baseline: dict) -> str:
    row = baseline if key is None else data["defense_off"].get(key) or data["sensitivity"][key]
    return _row(
        label,
        _usd(row["fraud_loss_usd"]),
        _pct(row["fraud_prevented_share_usd"]),
        _usd(row["ring_theft_usd"]),
        _pct(row["targets_ever_below500"]),
        _pct(row["legit_final"]["step_up"]),
        _linked(row),
    )


def _linked(row: dict) -> str:
    return f"{row['rereg_linked']} of {row['rereg_total']}"


def _pct(value: float) -> str:
    percent = value * 100
    if percent < 1:
        return f"{percent:.2f}%"
    if percent < 10:
        return f"{percent:.1f}%"
    return f"{round(percent):.0f}%"


def _usd(value: float) -> str:
    if value >= 100_000:
        return f"${value / 1_000_000:.2f}M"
    return f"${value / 1_000:.0f}k"
