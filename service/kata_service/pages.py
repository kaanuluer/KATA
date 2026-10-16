# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""HTML shell, repository timeline, and rendered documentation."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

import markdown

GITHUB = "https://github.com/kaanuluer/KATA"
_SCHEMA_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_HREF = re.compile(r"""href=(["'])(.*?)(\1)""")

# Slug, repository file, nav label, index blurb.
DOCUMENTS: tuple[tuple[str, str, str, str], ...] = (
    (
        "gab-requirements",
        "gab-requirements.md",
        "Bureau requirements",
        "Functional and non-functional requirements for the Global Agent Bureau.",
    ),
    (
        "design",
        "intent-agreement.md",
        "Design",
        "The signed intent agreement: decisions, data model, lifecycle, and the action check.",
    ),
    (
        "authorization",
        "delegation-model.md",
        "Authorization",
        "Who authorized the agent: the delegation grant, scope, monitoring, and revocation.",
    ),
    (
        "intent",
        "intent-model.md",
        "Intent",
        "Structured intent, the fields the principal signs, and how that record is confirmed.",
    ),
    (
        "threat-model",
        "threat-model.md",
        "Threat model",
        "Assets, actors, and the threats the framework's layers are meant to see.",
    ),
    (
        "trust-score-abuse",
        "trust-score-abuse.md",
        "Trust-score abuse",
        "How the live agent score can be pushed, and which controls already limit that.",
    ),
    (
        "architecture",
        "architecture.md",
        "Architecture",
        "How the questions and modules sit together.",
    ),
    (
        "risk-model",
        "risk-model.md",
        "Risk model",
        "Signals and decision outcomes around a checked action.",
    ),
    (
        "agent-identity",
        "agent-identity.md",
        "Agent identity",
        "How an agent is named and how that identity is distinct from authorization.",
    ),
    (
        "interoperability",
        "interoperability.md",
        "Interoperability",
        "Field mapping from Verifiable Intent, AP2, TAP, and AGNTCY into KATA objects.",
    ),
)

_FILE_TO_SLUG = {filename: slug for slug, filename, _label, _blurb in DOCUMENTS}
DOCUMENT_SLUGS = tuple(slug for slug, _filename, _label, _blurb in DOCUMENTS)


def repo_root() -> Path:
    """Directory that contains docs/intent-agreement.md and schemas/."""

    here = Path(__file__).resolve()
    candidates = [Path.cwd(), *here.parents]
    for candidate in candidates:
        if (candidate / "docs" / "intent-agreement.md").is_file() and (candidate / "schemas").is_dir():
            return candidate
    raise FileNotFoundError("KATA docs were not found beside this service")


def static_dir() -> Path:
    return Path(__file__).resolve().parent / "static"


def home_page() -> str:
    fragment = (static_dir() / "index.html").read_text(encoding="utf-8")
    fragment = fragment.replace("<!--HISTORY-->", history_section())
    return shell(
        "Global Agent Bureau",
        "Global Agent Bureau registers agents and checks signed intents. Powered by KATA.",
        fragment,
        current="",
        script=True,
    )


def dashboard_page() -> str:
    fragment = (static_dir() / "dashboard.html").read_text(encoding="utf-8")
    return shell(
        "Dashboard — Global Agent Bureau",
        "Organization dashboard for the Global Agent Bureau.",
        fragment,
        current="/dashboard",
        scripts=("dashboard.js",),
    )


def portal_page() -> str:
    fragment = (static_dir() / "portal.html").read_text(encoding="utf-8")
    return shell(
        "Portal — Global Agent Bureau",
        "Individual portal for the Global Agent Bureau.",
        fragment,
        current="/portal",
        scripts=("portal.js",),
    )


def history_page() -> str:
    intro = (
        '<section class="hero"><p class="kicker">Repository</p><h1>History</h1>'
        "<p class=\"lede\">Milestones from the commit history, the changelog, and the GitHub pull requests.</p></section>"
    )
    return shell(
        "History — KATA",
        "Milestones taken from the KATA commit history, changelog, and GitHub pull requests.",
        intro + history_section(),
        current="/history",
    )


def documentation_index() -> str:
    cards = []
    cards.append(
        _card(
            "/docs/design#lifecycle",
            "Intent lifecycle",
            "Proposal, acceptance, acknowledgement, amendment, revocation, and expiry, in the design doc.",
        )
    )
    for slug, _filename, label, blurb in DOCUMENTS:
        cards.append(_card(f"/docs/{slug}", label, blurb))
    cards.append(_card("/docs/schemas", "JSON schemas", "The schema files in schemas/, with each document served as JSON."))
    cards.append(
        _card(
            "/docs/api",
            "API reference",
            "Endpoints on this service, with request and response shapes, plus the generated OpenAPI page.",
        )
    )
    intro = (
        "<p class=\"lede\">These pages render the Markdown in <code>docs/</code> and the JSON in "
        "<code>schemas/</code>. The long-form framework note and the standards survey stay on "
        f"<a href=\"{GITHUB}/blob/main/KATA.md\">GitHub</a> "
        f"(<a href=\"{GITHUB}/blob/main/research/standards.md\">standards survey</a>).</p>"
    )
    body = (
        '<section class="hero"><p class="kicker">KATA</p><h1>Documentation</h1>'
        + intro
        + '</section><div class="doc-grid">'
        + "".join(cards)
        + "</div>"
    )
    return shell("Documentation — KATA", "KATA design, authorization, intent, threat model, schemas, and API.", body, current="/docs")


def render_document(slug: str) -> str | None:
    match = next((item for item in DOCUMENTS if item[0] == slug), None)
    if match is None:
        return None
    _slug, filename, label, _blurb = match
    source = (repo_root() / "docs" / filename).read_text(encoding="utf-8")
    rendered = markdown.markdown(
        source,
        extensions=["tables", "fenced_code", "sane_lists", "toc"],
        extension_configs={"toc": {"toc_depth": 6}},
    )
    rendered = _wrap_tables(_rewrite_links(rendered))
    body = f"<article class=\"doc-body\">{rendered}</article>"
    return shell(f"{label} — KATA", label, body, current="/docs")


def schema_index() -> str:
    root = repo_root() / "schemas"
    cards = []
    for path in sorted(root.glob("*.json")):
        if not _SCHEMA_NAME.match(path.stem):
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            document = {}
        title = str(document.get("title") or path.name)
        description = str(document.get("description") or "JSON schema.")
        cards.append(
            _card(
                f"/docs/schemas/{path.name}",
                title,
                description,
                extra=f"<p class=\"meta\">{html.escape(path.name)}</p>",
            )
        )
    body = (
        '<section class="hero"><p class="kicker">Schemas</p><h1>JSON schemas</h1>'
        "<p class=\"lede\">Each file in <code>schemas/</code> is served unchanged at "
        "<code>/docs/schemas/&lt;name&gt;.json</code>.</p></section>"
        '<div class="doc-grid">' + "".join(cards) + "</div>"
    )
    return shell("JSON schemas — KATA", "KATA JSON schemas.", body, current="/docs")


def schema_bytes(name: str) -> bytes | None:
    """Raw schema file. ``name`` is the basename, including ``.json``."""

    if not name.endswith(".json"):
        return None
    stem = name[: -len(".json")]
    if not _SCHEMA_NAME.match(stem):
        return None
    path = repo_root() / "schemas" / f"{stem}.json"
    if not path.is_file():
        return None
    return path.read_bytes()


def api_reference() -> str:
    blocks = [
        '<section class="hero"><p class="kicker">Service</p><h1>API reference</h1>',
        "<p class=\"lede\">Shapes below are the fields this service returns. "
        f"FastAPI generates the machine-readable description at <a href=\"/docs/openapi\">/docs/openapi</a> "
        "and <a href=\"/openapi.json\">/openapi.json</a>.</p></section>",
    ]
    for item in _ENDPOINTS:
        blocks.append("<section class=\"endpoint\">")
        blocks.append(
            f"<h2><span class=\"method\">{html.escape(item['method'])}</span> "
            f"<code>{html.escape(item['path'])}</code></h2>"
        )
        blocks.append(f"<p>{item['summary']}</p>")
        if item.get("request"):
            blocks.append("<h3>Request</h3>")
            blocks.append(f"<pre><code>{html.escape(item['request'])}</code></pre>")
        blocks.append("<h3>Response</h3>")
        blocks.append(f"<pre><code>{html.escape(item['response'])}</code></pre>")
        if item.get("errors"):
            blocks.append(f"<p class=\"meta\">{html.escape(item['errors'])}</p>")
        blocks.append("</section>")
    return shell("API reference — KATA", "KATA service endpoints.", "".join(blocks), current="/docs")


def history_section() -> str:
    return (
        "<section id=\"history\">"
        "<h2>History</h2>"
        "<p class=\"lede\">Dates and titles below are the git history, "
        "<code>CHANGELOG.md</code>, and the GitHub pull requests. "
        "When a commit date and a GitHub merge time fall on different days, both are stated. "
        f"The repository is <a href=\"{GITHUB}\">{GITHUB}</a>.</p>"
        "<ol class=\"timeline\">"
        + "".join(_MILESTONES)
        + "</ol></section>"
    )


def shell(title: str, description: str, body: str, *, current: str, script: bool = False, scripts: tuple[str, ...] = ()) -> str:
    tags = []
    if script:
        tags.append('<script src="/assets/app.js"></script>')
    for src in scripts:
        tags.append(f'<script src="/assets/{html.escape(src)}"></script>')
    script_tag = "".join(tags)
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <meta name="description" content="{html.escape(description)}">
  <meta name="color-scheme" content="dark light">
  <link rel="icon" href="/assets/gab-icon.svg" type="image/svg+xml">
  <link rel="icon" href="/assets/favicon-32.png" type="image/png" sizes="32x32">
  <link rel="apple-touch-icon" href="/assets/gab-icon-180.png">
  <link rel="stylesheet" href="/assets/app.css">
  <script>
    try {{
      var storedTheme = localStorage.getItem("gab-theme");
      if (storedTheme === "light" || storedTheme === "dark") document.documentElement.setAttribute("data-theme", storedTheme);
    }} catch (err) {{}}
  </script>
</head>
<body>
  <a class="skip" href="#top">Skip to content</a>
  <header class="site">
    <div class="wrap bar">
      <a class="brand" href="/">
        <span class="plate"><img class="logo" src="/assets/gab-logo.svg" alt="GAB_" width="142" height="76"></span>
        <span class="brand-note">Powered by KATA · Know And Trust Agents</span>
      </a>
      <div class="header-tools">
        {_nav(current)}
        <button class="mode" id="theme-toggle" type="button" aria-pressed="true">Light mode</button>
      </div>
    </div>
  </header>
  <div class="wrap">
    <main id="top">
      {_docs_nav(current)}
      {body}
    </main>
    <footer class="site">
      <p>Global Agent Bureau is an agent bureau. Powered by <img class="mark" src="/assets/kata-logo.svg" alt="KATA">. Copyright 2026 Kaan Uluer. PolyForm Noncommercial License. <a href="/simulation">Simulation</a>. <a href="{GITHUB}">GitHub</a>.</p>
      <p><img src="/assets/kata-icon.svg" alt="" width="28" height="28"> The demo seed is public and is not a production signing key. Verdicts here are allow, deny, or step-up. Deny means block the action. It does not revoke the grant.</p>
    </footer>
  </div>
  <script>
    (function () {{
      var root = document.documentElement;
      var button = document.getElementById("theme-toggle");
      function paint() {{
        var theme = root.getAttribute("data-theme") === "light" ? "light" : "dark";
        if (!button) return;
        button.textContent = theme === "dark" ? "Light mode" : "Dark mode";
        button.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
      }}
      if (button) {{
        button.addEventListener("click", function () {{
          var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
          root.setAttribute("data-theme", next);
          try {{ localStorage.setItem("gab-theme", next); }} catch (err) {{}}
          paint();
        }});
      }}
      paint();
    }})();
  </script>
  {script_tag}
</body>
</html>
"""


def _nav(current: str) -> str:
    items = [
        ("/#questions", "Questions", ""),
        ("/#demo", "Demo", ""),
        ("/dashboard", "Dashboard", "/dashboard"),
        ("/portal", "Portal", "/portal"),
        ("/history", "History", "/history"),
        ("/simulation", "Simulation", "/simulation"),
        ("/docs", "Docs", "/docs"),
        ("/#operations", "Live status", ""),
        (GITHUB, "GitHub", "github"),
    ]
    links = []
    for href, label, key in items:
        current_attr = ' aria-current="page"' if key and key == current else ""
        extra = ' rel="noopener noreferrer"' if href.startswith("http") else ""
        links.append(f'<a href="{href}"{current_attr}{extra}>{label}</a>')
    return '<nav class="site" aria-label="Page">' + "".join(links) + "</nav>"


def _docs_nav(current: str) -> str:
    if current != "/docs":
        return ""
    links = ['<a href="/docs">Overview</a>']
    links.append('<a href="/docs/design#lifecycle">Lifecycle</a>')
    for slug, _filename, label, _blurb in DOCUMENTS:
        links.append(f'<a href="/docs/{slug}">{html.escape(label)}</a>')
    links.append('<a href="/docs/schemas">Schemas</a>')
    links.append('<a href="/docs/api">API</a>')
    links.append(f'<a href="{GITHUB}">GitHub</a>')
    return '<nav class="docs" aria-label="Documentation">' + "".join(links) + "</nav>"


def _card(href: str, title: str, blurb: str, extra: str = "") -> str:
    return (
        f'<a class="doc-card" href="{html.escape(href)}">'
        f"<strong>{html.escape(title)}</strong>"
        f"<span>{html.escape(blurb)}</span>"
        f"{extra}</a>"
    )


def _commit(sha: str) -> str:
    return f'<a href="{GITHUB}/commit/{sha}"><code>{sha}</code></a>'


def _pr(number: int, title: str) -> str:
    return f'<a href="{GITHUB}/pull/{number}">#{number} {html.escape(title)}</a>'


def _mile(when: str, title: str, body: str) -> str:
    return (
        "<li>"
        f"<time datetime=\"{html.escape(when)}\">{html.escape(when)}</time>"
        f"<strong>{html.escape(title)}</strong>"
        f"{body}"
        "</li>"
    )


def _rewrite_links(rendered: str) -> str:
    def replace(match: re.Match[str]) -> str:
        quote, target, _end = match.group(1), match.group(2), match.group(3)
        return f"href={quote}{html.escape(_rewrite_target(html.unescape(target)), quote=True)}{quote}"

    return _HREF.sub(replace, rendered)


def _rewrite_target(target: str) -> str:
    if target.startswith(("http://", "https://", "mailto:", "#", "/")):
        return target
    path, fragment = (target.split("#", 1) + [""])[:2]
    suffix = f"#{fragment}" if "#" in target else ""
    basename = path.split("/")[-1]
    if basename.endswith(".json") and "schemas" in path.split("/"):
        return f"/docs/schemas/{basename}{suffix}"
    if basename in _FILE_TO_SLUG:
        return f"/docs/{_FILE_TO_SLUG[basename]}{suffix}"
    cleaned = path
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    if cleaned.startswith("../"):
        cleaned = cleaned[3:]
    elif cleaned and not cleaned.startswith("docs/"):
        cleaned = "docs/" + cleaned
    kind = "tree" if cleaned.endswith("/") or "." not in cleaned.rsplit("/", 1)[-1] else "blob"
    return f"{GITHUB}/{kind}/main/{cleaned}{suffix}"


def _wrap_tables(rendered: str) -> str:
    return rendered.replace("<table>", '<div class="table-scroll"><table>').replace("</table>", "</table></div>")


_PR3 = "Update KATA docs from Sardine's 2026 agentic commerce fraud report"

_MILESTONES = (
    _mile(
        "2026-10-04",
        "Repository starts",
        "<p>"
        f"{_commit('a581f1c')} Initial commit. "
        f"{_commit('c57c16c')} KATA framework initial content: README, docs, schemas, examples, research. "
        f"{_commit('6ffc9f7')} KATA assets: logo. "
        f"{_commit('d9037b3')} Remove corrupted logo upload (retry via web UI). "
        f"{_commit('302ba83')} KATA assets: hero banner and logo."
        "</p>"
        "<p>Five commits that day share the message “KATA framework part 1: README, license, gitignore”: "
        f"{_commit('3d5275a')}, {_commit('29899e1')}, {_commit('1a514d4')}, {_commit('e85217e')}, {_commit('2191ce3')}."
        "</p>",
    ),
    _mile(
        "2026-10-08",
        "Price integrity, and a mapping onto other mandates",
        "<p>"
        f"{_commit('0129d8a')} Record price integrity and the AgentCommerceBench gap (#1). "
        f"GitHub {_pr(1, 'Add price integrity and an AgentCommerceBench mapping')} "
        "was opened 2026-10-09T02:02:58Z and merged 2026-10-09T02:05:23Z."
        "</p>"
        "<p>"
        f"{_commit('2ab98f5')} Map KATA objects to Verifiable Intent and AP2 mandates. (#2). "
        f"GitHub {_pr(2, 'Map KATA to Verifiable Intent, AP2, TAP, and AGNTCY')} "
        "was opened 2026-10-09T02:42:08Z and merged 2026-10-09T02:52:11Z."
        "</p>",
    ),
    _mile(
        "2026-10-12",
        "Related-work notes, then the intent agreement",
        "<p>"
        f"{_commit('37d54b0')} Record a reading of Sardine's agentic-commerce fraud report in the KATA docs. (#3). "
        f"GitHub {_pr(3, _PR3)} "
        "was opened 2026-10-12T05:06:29Z and merged 2026-10-12T05:07:08Z. "
        "CHANGELOG.md for that day records the reading of Sardine's public report "
        "Rethinking Fraud Prevention for Agentic Commerce (2026). The changelog says no schema or example changed, "
        "and that nothing in the update is a measured result."
        "</p>"
        "<p>"
        f"{_commit('d9d5712')} Separate the KATA core from optional profiles and related work. (#4). "
        f"GitHub {_pr(4, 'Keep the KATA core lean: optional profiles and Darwinium as related work')} "
        "was opened 2026-10-12T12:43:56Z and merged 2026-10-12T12:44:19Z. "
        "The changelog says an implementation needs the four questions, the intent and delegation schemas, "
        "and the decision outcomes, and that use-case examples are profiles. "
        "It cites Darwinium's press release of 8 October 2026 as that related-work entry."
        "</p>"
        "<p>"
        f"{_commit('8ca5197')} Add a signed intent agreement and a reference action check. "
        "The changelog points at docs/intent-agreement.md, schemas/intent-mandate.json, schemas/agreement.json, "
        "and the reference library's Ed25519 mandate, action check, and revoke-or-expire path."
        "</p>"
        "<p>"
        f"GitHub {_pr(5, 'Add a signed intent agreement and a reference action check')} "
        "was opened 2026-10-12T22:46:54Z. GitHub lists it as a draft and records no merge time."
        "</p>",
    ),
    _mile(
        "2026-10-13",
        "Decisions, the deployment service, and this page",
        "<p>"
        f"{_commit('32711ab')} Apply Kaan's intent-agreement decisions to the spec and the reference check. "
        "The changelog records the agreement inside the delegation, the spend ledger on the agreement, "
        "several live intents inside one parent set, and the principal's signature as the activation."
        "</p>"
        "<p>"
        f"{_commit('39c6328')} Apply the confirmation, ledger, revocation, FX, institution-key, and ES256 decisions. "
        "The changelog records canonical confirmation text, a hash-chained ledger with a 60-second staleness step-up, "
        "auto-selection of one matching intent, pull plus push plus a transparency log, "
        "a pluggable daily FX ceiling, institution keys at .well-known plus an allowlist, and ES256 beside Ed25519."
        "</p>"
        "<p>"
        f"{_commit('5df8892')} Add a Vercel service for the revocation list, transparency log, and daily FX. "
        f"{_commit('2e36a7d')} Point the Vercel FastAPI entrypoint at the repository-root app.py. "
        f"{_commit('28c0765')} Send a user agent on Frankfurter FX requests and use the v1 host."
        "</p>"
        "<p>"
        f"{_commit('87d97e2')} Add an English KATA page with a sample intent check and live status. "
        f"{_commit('b237da9')} Use the teal seal and KATA wordmark on the web page."
        "</p>"
        "<p>"
        f"GitHub {_pr(6, 'Relicense KATA under PolyForm Noncommercial 1.0.0')} "
        "was opened 2026-10-13T03:45:55Z and merged 2026-10-13T04:16:43Z. "
        "The LICENSE file in this checkout is the PolyForm Noncommercial License 1.0.0. "
        "Versions published before that change were released under Apache-2.0."
        "</p>"
        "<p>CHANGELOG.md for 2026-10-13 also records <code>/history</code> and <code>/docs</code> "
        "(design, authorization, intent, threat model, schemas, and the API reference), "
        "with FastAPI's generated OpenAPI page at <code>/docs/openapi</code>.</p>"
        "<p>This checkout adds the Global Agent Bureau on that service: organizations and hashed API keys, "
        "the agent registry, stored intents and the verify API, incident reports, purpose-coded inquiries, "
        "the rule-based trust score, signed alerts, the individual portal, and disputes. "
        "The requirements are in <a href=\"/docs/gab-requirements\">docs/gab-requirements.md</a>. "
        "The organization dashboard is <a href=\"/dashboard\">/dashboard</a> and the individual portal is "
        "<a href=\"/portal\">/portal</a>.</p>",
    ),
    _mile(
        "2026-10-15",
        "Bureau defenses and one synthetic stress test",
        "<p>The service rejects an unlinked report, denies a velocity breach, and publishes one synthetic "
        "stress test at <a href=\"/simulation\">/simulation</a>. Every figure is labeled "
        "SYNTHETIC TEST DATA – not real customers. Against adaptive attackers, 73% of attempted fraud "
        "dollars are stopped and $0.71M is executed. When attackers do not know the rules, 78% is stopped "
        "and $0.68M is executed. The home page states that same headline.</p>",
    ),
)


_ENDPOINTS: tuple[dict[str, str], ...] = (
    {
        "method": "GET",
        "path": "/v1/revocations",
        "summary": "Pull list of stored principal revocations. The response sets Cache-Control: public, max-age=300.",
        "response": '{\n  "revocations": []\n}',
        "errors": '503 {"error": "DATABASE_URL is not set"} when storage is not configured.',
    },
    {
        "method": "POST",
        "path": "/v1/revocations/push",
        "summary": (
            "Notifier-signed webhook. The body is the object from sign_revocation_push: "
            "at, kata_revocation_push \"1\", revocation, and signature. "
            "signature is a flattened JWS whose protected header typ is kata-revocation-push+jws."
        ),
        "request": (
            '{\n'
            '  "at": "2026-10-04T18:00:00Z",\n'
            '  "kata_revocation_push": "1",\n'
            '  "revocation": {\n'
            '    "agreement_id": "agr_demo",\n'
            '    "at": "2026-10-04T18:00:00Z",\n'
            '    "kata_revocation": "1",\n'
            '    "mandate_hash": "sha256:…",\n'
            '    "reason": "principal revoked",\n'
            '    "signature": {"payload": "…", "protected": "…", "signature": "…"}\n'
            "  },\n"
            '  "signature": {"payload": "…", "protected": "…", "signature": "…"}\n'
            "}"
        ),
        "response": '{\n  "stored": true,\n  "revocation_id": "sha256:…",\n  "sequence": 1\n}',
        "errors": (
            'A repeat of the same revocation returns {"stored": false, "revocation_id": "sha256:…"} and does not append again. '
            '401 {"error": "revocation push did not verify"}. '
            '503 when KATA_PUSH_NOTIFIER_JWK or KATA_LOG_SIGNING_SEED is unset. '
            '400 when the body is not a JSON object.'
        ),
    },
    {
        "method": "POST",
        "path": "/v1/log/entries",
        "summary": "Append an agreement, revocation, registration, or incident and sign a new tree head. Authorization: Bearer <KATA_APPEND_TOKEN>. Bureau registrations, revocations, and incidents are appended by the service itself.",
        "request": '{\n  "kind": "agreement",\n  "body": {}\n}',
        "response": (
            '{\n'
            '  "entry": {\n'
            '    "kind": "agreement",\n'
            '    "sequence": 1,\n'
            '    "body": {},\n'
            '    "entry_hash": "sha256:…"\n'
            "  },\n"
            '  "tree_head": {\n'
            '    "algorithm": "EdDSA",\n'
            '    "at": "2026-10-04T14:02:11Z",\n'
            '    "kata_tree_head": "1",\n'
            '    "root": "sha256:…",\n'
            '    "tree_size": 1,\n'
            '    "signature": {"payload": "…", "protected": "…", "signature": "…"}\n'
            "  }\n"
            "}"
        ),
        "errors": (
            "kind is agreement, revocation, registration, or incident. A later entry also carries prev_entry_hash. "
            "The tree-head JWS typ is kata-tree-head+jws. "
            '401 {"error": "append token does not match"}. '
            '400 {"error": "log append needs kind and a body object"} and 400 when kind is rejected. '
            "503 when KATA_APPEND_TOKEN or KATA_LOG_SIGNING_SEED is unset."
        ),
    },
    {
        "method": "GET",
        "path": "/v1/log/entries/{sequence}",
        "summary": "One hash-chained entry. sequence starts at 1.",
        "response": (
            '{\n'
            '  "entry": {\n'
            '    "kind": "revocation",\n'
            '    "sequence": 1,\n'
            '    "body": {},\n'
            '    "entry_hash": "sha256:…"\n'
            "  }\n"
            "}"
        ),
        "errors": '404 {"error": "log entry was not found"} when the sequence is outside the log.',
    },
    {
        "method": "GET",
        "path": "/v1/log/entries/{sequence}/proof",
        "summary": "Merkle inclusion proof for that entry. index is sequence minus 1. side is left or right.",
        "response": (
            '{\n'
            '  "sequence": 1,\n'
            '  "index": 0,\n'
            '  "leaf": "sha256:…",\n'
            '  "proof": [{"hash": "sha256:…", "side": "right"}],\n'
            '  "root": "sha256:…",\n'
            '  "tree_size": 1\n'
            "}"
        ),
        "errors": "404 when the sequence is outside the tree.",
    },
    {
        "method": "GET",
        "path": "/v1/log/head",
        "summary": "Signed tree head. The same fields are on tree_head from a log append.",
        "response": (
            '{\n'
            '  "algorithm": "EdDSA",\n'
            '  "at": "2026-10-04T14:02:11Z",\n'
            '  "kata_tree_head": "1",\n'
            '  "root": "sha256:…",\n'
            '  "tree_size": 1,\n'
            '  "signature": {"payload": "…", "protected": "…", "signature": "…"}\n'
            "}"
        ),
        "errors": '404 {"error": "the transparency log has no signed tree head"} when nothing has been appended.',
    },
    {
        "method": "GET",
        "path": "/.well-known/kata-keys.json",
        "summary": "Log public key, plus any records in KATA_PUBLISHED_KEYS. An empty key list is a 200 when no seed is set.",
        "response": (
            '{\n'
            '  "keys": [\n'
            '    {"public_key": {"crv": "Ed25519", "kid": "sha256:…", "kty": "OKP", "x": "…"}}\n'
            "  ]\n"
            "}"
        ),
        "errors": "500 when a configured key or seed fails to load.",
    },
    {
        "method": "GET",
        "path": "/v1/fx?currency=CAD&reference=USD&day=YYYY-MM-DD",
        "summary": (
            "Reference-currency units for one unit of currency on that UTC day. "
            "reference_currency is an alias of reference. The default reference is USD. "
            "day defaults to the current UTC date. The rate is a decimal string from the configured source "
            "(default https://api.frankfurter.dev/v1). The same currency returns rate \"1\"."
        ),
        "response": (
            '{\n'
            '  "currency": "CAD",\n'
            '  "reference_currency": "USD",\n'
            '  "day": "2026-10-04",\n'
            '  "rate": "…"\n'
            "}"
        ),
        "errors": (
            '400 when a currency is not three letters or day is not YYYY-MM-DD. '
            '404 {"error": "no USD rate for CAD on YYYY-MM-DD"} when the source has no rate. '
            '502 {"error": "FX source did not answer"}. '
            "503 when DATABASE_URL is not set."
        ),
    },
    {
        "method": "POST",
        "path": "/demo/check",
        "summary": (
            "Signs one sample agreement with the public demo keys and evaluates one payment. "
            "principal is K. Uluer and the agent is shopper-01. demo is true. "
            "verdict is ALLOW, DENY, or STEP_UP. kata_decision is ALLOW, BLOCK, or STEP_UP. DENY maps to BLOCK."
        ),
        "request": (
            '{\n'
            '  "intent": {\n'
            '    "maximum_amount": 1500,\n'
            '    "currency": "CAD",\n'
            '    "purpose": "purchase",\n'
            '    "category": "electronics",\n'
            '    "natural_language": "Find and buy a laptop for me, maximum CAD 1,500.",\n'
            '    "include_expiry": true,\n'
            '    "time_limit": "2026-12-31"\n'
            "  },\n"
            '  "payment": {\n'
            '    "amount": 1300,\n'
            '    "currency": "CAD",\n'
            '    "merchant": "techstore.example",\n'
            '    "item": "Laptop"\n'
            "  }\n"
            "}"
        ),
        "response": (
            '{\n'
            '  "verdict": "ALLOW",\n'
            '  "kata_decision": "ALLOW",\n'
            '  "reasons": [],\n'
            '  "messages": [],\n'
            '  "required_action": "NONE",\n'
            '  "confirmation_text": "…",\n'
            '  "mandate_hash": "sha256:…",\n'
            '  "principal": "K. Uluer",\n'
            '  "principal_fingerprint": "sha256:…",\n'
            '  "agent_id": "shopper-01",\n'
            '  "agreement_id": "agr_demo",\n'
            '  "status": "active",\n'
            '  "demo": true\n'
            "}"
        ),
        "errors": (
            "A payment of 4200 CAD against that ceiling returns verdict DENY, kata_decision BLOCK, "
            "and reasons including AMOUNT_ABOVE_INTENT_CEILING. "
            "include_expiry false returns verdict STEP_UP and reasons including OVER_BROAD_INTENT. "
            "400 when an amount or currency is unusable."
        ),
    },
    {
        "method": "GET",
        "path": "/v1/score-model",
        "summary": "Publishes the agent score weights. No credential is required. risk is 1000 minus the score. Individuals are not scored. GAB_SCORE_WEIGHTS can replace a weight for calibration.",
        "request": "",
        "response": '{\n  "model_version": "gab-score-1",\n  "subjects": "agents",\n  "individuals_scored": false,\n  "risk": "1000 - score",\n  "reports": {"fraud_incident": -120}\n}',
        "errors": "500 when GAB_SCORE_WEIGHTS is not usable JSON or a weight is outside its range.",
    },
    {
        "method": "POST",
        "path": "/v1/admin/consortium/members",
        "summary": "Admin adds an organization to the fingerprint consortium. A second call returns the same membership.",
        "request": '{\n  "org_id": "org_…"\n}',
        "response": '{\n  "member_id": "cmb_…",\n  "org_id": "org_…",\n  "status": "active"\n}',
        "errors": "403 without the admin token. 404 when the organization does not exist.",
    },
    {
        "method": "POST",
        "path": "/v1/consortium/sightings",
        "summary": "A member records a key fingerprint it has seen. The body is the fingerprint only. The same member and fingerprint is stored once.",
        "request": '{\n  "fingerprint": "sha256:…"\n}',
        "response": '{\n  "sighting_id": "sgt_…",\n  "fingerprint": "sha256:…",\n  "seen_at": "2026-10-15T12:00:00Z"\n}',
        "errors": "403 when the caller is not a member. 400 when the fingerprint is not sha256 and 64 hex characters.",
    },
    {
        "method": "POST",
        "path": "/v1/consortium/match",
        "summary": "A member asks whether other members have sighted a fingerprint. The caller is not counted. At or above GAB_CONSORTIUM_MATCH_THRESHOLD (default 2) the response includes other_member_count. Below that threshold the count is omitted. The response does not name the other members.",
        "request": '{\n  "fingerprint": "sha256:…"\n}',
        "response": '{\n  "matched": true,\n  "other_member_count": 2\n}',
        "errors": "403 when the caller is not a member. 400 when the fingerprint is not sha256 and 64 hex characters.",
    },
    {
        "method": "POST",
        "path": "/v1/orgs",
        "summary": "Admin bootstrap. Creates a participant organization. org_type is agent_operator, wallet, bank_issuer, processor_psp, or merchant.",
        "request": '{\n  "name": "Harbor Agents",\n  "org_type": "agent_operator"\n}',
        "response": '{\n  "org_id": "org_…",\n  "name": "Harbor Agents",\n  "org_type": "agent_operator",\n  "status": "active"\n}',
        "errors": "401 without the admin token. 403 for any other credential. 400 for an unknown org_type.",
    },
    {
        "method": "POST",
        "path": "/v1/orgs/{org_id}/keys",
        "summary": "Issues an API key. The raw token is returned once. Stored value is the SHA-256 hash. List responses omit the token.",
        "request": '{\n  "name": "primary"\n}',
        "response": '{\n  "key_id": "key_…",\n  "prefix": "…",\n  "scopes": ["registry:read"],\n  "token": "gab_…"\n}',
        "errors": "404 when another organization asks. 401 when the key is revoked.",
    },
    {
        "method": "POST",
        "path": "/v1/agents",
        "summary": "An agent operator registers an agent. public_key is an Ed25519 or P-256 JWK with no private d. principal_id is a pseudonymous id. Optional principal_email binds that address to the principal. An address already bound to a different principal is rejected. Optional device_signal and key_signal link the agent to a recently denied agent and inherit a penalty. proofing_evidence is sha256 and 64 hex characters. With proofing on, operator_verified adds 120 points only when that hash is present. Without it the score uses key_bound.",
        "request": '{\n  "agent_id": "shopper-01",\n  "principal_id": "prn_demo",\n  "verification_level": "operator_verified",\n  "proofing_evidence": "sha256:…",\n  "public_key": {"kty": "OKP", "crv": "Ed25519", "x": "…"}\n}',
        "response": '{\n  "agent_id": "shopper-01",\n  "status": "active",\n  "verification_level": "operator_verified",\n  "assurance_level": "operator_verified",\n  "fingerprint": "sha256:…",\n  "score": 700,\n  "risk": 300,\n  "model_version": "gab-score-1"\n}',
        "errors": "Other tenants do not receive principal_id. 409 when the agent id or key is already registered, or when principal_email is already bound to another principal. 400 when proofing_evidence is not sha256 and 64 hex characters.",
    },
    {
        "method": "POST",
        "path": "/v1/agents/{agent_id}/proofing",
        "summary": "Files operator_review from the agent's operator, or institution_attestation from a wallet or bank. evidence_hash is sha256 and 64 hex characters. The claim in verification_level stays as set. assurance_level is what the score uses. key_binding is written at registration and is not accepted here. The operator, the admin, and the principal can list the rows. Other tenants see assurance_level only.",
        "request": '{\n  "method": "institution_attestation",\n  "evidence_hash": "sha256:…"\n}',
        "response": '{\n  "agent_id": "shopper-01",\n  "verification_level": "institution_attested",\n  "assurance_level": "institution_attested",\n  "score": 780\n}',
        "errors": "403 when the caller cannot file that method. 400 for an unknown method or a bad hash.",
    },
    {
        "method": "POST",
        "path": "/v1/verify",
        "summary": "Checks a payment action against the agent's active stored agreement. ALLOW records the spend and the caller's organization as a transaction counterparty, unless counterparty_org_id names another organization. A daily count or amount window above the configured cap returns DENY with kata_decision BLOCK and VELOCITY_COUNT or VELOCITY_AMOUNT and does not record the spend. Other DENY results also use kata_decision BLOCK.",
        "request": '{\n  "agent_id": "shopper-01",\n  "action": {"action_id": "act_1", "action_type": "purchase", "amount": 1300, "currency": "CAD", "proposed_at": "2026-10-04T13:55:00Z"}\n}',
        "response": '{\n  "verdict": "ALLOW",\n  "kata_decision": "ALLOW",\n  "reasons": [],\n  "agent_id": "shopper-01",\n  "agreement_id": "agr_demo"\n}',
        "errors": "AGENT_NOT_ACTIVE, NO_ACTIVE_AGREEMENT, and AGREEMENT_NOT_SELECTED are bureau reasons. Library reasons such as AMOUNT_ABOVE_INTENT_CEILING are passed through.",
    },
    {
        "method": "POST",
        "path": "/v1/inquiries",
        "summary": "Purpose-coded inquiry. Returns identity, verification, active authorizations, revocations, incident counts, and the trust score. Contributors also receive recent evidence hashes.",
        "request": '{\n  "agent_id": "shopper-01",\n  "purpose_code": "payment_authorization"\n}',
        "response": '{\n  "inquiry_id": "inq_…",\n  "agent": {"agent_id": "shopper-01", "status": "active", "verification_level": "institution_attested", "assurance_level": "institution_attested"},\n  "trust_score": {"score": 724, "risk": 276, "model_version": "gab-score-1", "cold_start": false, "reasons": [{"code": "CHARGEBACK", "points": -56}]}\n}',
        "errors": "400 when purpose_code is missing. The body does not include an email address or principal_id.",
    },
    {
        "method": "POST",
        "path": "/v1/reports",
        "summary": "Files a transaction outcome, fraud incident, chargeback, or policy violation. evidence_hash is sha256 and 64 hex characters. The same reporter, agent, kind, and hash is a duplicate. The report is accepted only when this organization has an allowed verify with the agent that meets the link minimum. A stored report has counts true.",
        "request": '{\n  "agent_id": "shopper-01",\n  "kind": "chargeback",\n  "evidence_hash": "sha256:…",\n  "summary": "Disputed purchase.",\n  "action_id": "act_1"\n}',
        "response": '{\n  "report_id": "rpt_…",\n  "kind": "chargeback",\n  "counts": true\n}',
        "errors": "400 when no qualifying verify is on file. 409 duplicate report. 429 when the organization exceeds the daily cap.",
    },
    {
        "method": "POST",
        "path": "/v1/subscriptions",
        "summary": "Subscribes the caller to signed webhooks for revocation, a new incident, and a score drop of 50 points or more. The signature typ is kata-bureau-alert+jws and uses the log signing key.",
        "request": '{\n  "agent_id": "shopper-01",\n  "webhook_url": "https://merchant.example/hooks/gab"\n}',
        "response": '{\n  "subscription_id": "sub_…",\n  "agent_id": "shopper-01"\n}',
        "errors": "400 unless the URL is https, or http on localhost.",
    },
    {
        "method": "POST",
        "path": "/v1/portal/magic-link",
        "summary": "Sends a portal sign-in link. The response is always sent true. An email already bound to a principal keeps that principal. A new email creates a new principal id and does not move an existing binding. SMTP is used when the host, user, password, and from address are set. Otherwise the link is not printed unless the development mailbox is on.",
        "request": '{\n  "email": "principal@example.com"\n}',
        "response": '{\n  "sent": true\n}',
        "errors": "POST /v1/sessions exchanges the token. A new email creates a new principal id. Registering principal_email on the agent binds the portal to that principal.",
    },
    {
        "method": "POST",
        "path": "/v1/admin/seed-demo",
        "summary": (
            "Inserts the public demo organizations, shopper-01, and agr_demo into the live repository. "
            "Authorization is the GAB_ADMIN_TOKEN bearer. The route stays closed unless GAB_ALLOW_DEMO_SEED=1. "
            "It does not require GAB_DEMO. A second call returns already_present true and does not insert another copy. "
            "The response omits the admin token."
        ),
        "response": (
            '{\n'
            '  "operator_key": "gab_demo_operator_public",\n'
            '  "wallet_key": "gab_demo_wallet_public",\n'
            '  "merchant_key": "gab_demo_merchant_public",\n'
            '  "agent_id": "shopper-01",\n'
            '  "agreement_id": "agr_demo",\n'
            '  "already_present": "false"\n'
            "}"
        ),
        "errors": "401 without a bearer. 403 for a non-admin key. 403 {\"error\": \"demo seed is disabled\"} when the flag is unset.",
    },
)
