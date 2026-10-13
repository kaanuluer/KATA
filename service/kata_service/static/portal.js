(function () {
  const tokenKey = "gab-portal-token";
  const $ = (id) => document.getElementById(id);

  function setStatus(text) {
    $("portal-status").textContent = text;
  }

  function headers() {
    return {
      Authorization: "Bearer " + sessionStorage.getItem(tokenKey),
      "Content-Type": "application/json",
    };
  }

  async function api(path, options) {
    const response = await fetch(path, options || {});
    const text = await response.text();
    let body = null;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch (error) {
        body = { error: text };
      }
    }
    if (!response.ok) {
      const failure = new Error((body && body.error) || response.statusText);
      failure.status = response.status;
      throw failure;
    }
    return body;
  }

  function line(text) {
    const p = document.createElement("p");
    p.textContent = text;
    return p;
  }

  async function load() {
    $("portal-login").hidden = true;
    $("portal-app").hidden = false;
    $("portal-who").textContent = "Signed in.";
    const agents = await api("/v1/portal/agents", { headers: headers() });
    const agentBox = $("portal-agents");
    agentBox.innerHTML = "";
    if (!agents.length) {
      agentBox.append(line("No agents are bound to this principal."));
    }
    for (const agent of agents) {
      const card = document.createElement("article");
      card.className = "agent-card";
      card.append(line(agent.agent_id + " · " + agent.status + " · " + agent.verification_level));
      const score = document.createElement("p");
      score.className = "score";
      const figure = document.createElement("strong");
      figure.id = "portal-score";
      figure.textContent = String(agent.score);
      score.append(figure, document.createTextNode(" / 1000"));
      card.append(score);
      const reasons = document.createElement("ol");
      reasons.id = "portal-reasons";
      (agent.score_reasons || []).forEach((item) => {
        const row = document.createElement("li");
        row.textContent = item.code + " (" + item.points + ") " + item.detail;
        reasons.append(row);
      });
      card.append(reasons);
      const revoke = document.createElement("button");
      revoke.type = "button";
      revoke.textContent = "Revoke agent";
      revoke.addEventListener("click", async () => {
        await api("/v1/portal/agents/" + encodeURIComponent(agent.agent_id) + "/revoke", {
          method: "POST",
          headers: headers(),
        });
        await load();
      });
      card.append(revoke);
      const authorizations = await api("/v1/portal/agents/" + encodeURIComponent(agent.agent_id) + "/authorizations", {
        headers: headers(),
      });
      authorizations.forEach((item) => {
        const row = document.createElement("p");
        const label = (item.intents || []).map((intent) => intent.intent_id + " " + intent.currency + " " + intent.maximum_amount).join(", ");
        row.textContent = item.agreement_id + " · " + item.status + " · " + label;
        const button = document.createElement("button");
        button.type = "button";
        button.className = "ghost";
        button.textContent = "Revoke intent";
        button.addEventListener("click", async () => {
          await api("/v1/portal/agreements/" + encodeURIComponent(item.agreement_id) + "/revoke", {
            method: "POST",
            headers: headers(),
          });
          await load();
        });
        card.append(row, button);
      });
      const reports = await api("/v1/portal/agents/" + encodeURIComponent(agent.agent_id) + "/reports", {
        headers: headers(),
      });
      reports.forEach((item) => {
        const row = document.createElement("p");
        row.textContent = item.report_id + " · " + item.kind + " · " + (item.summary || "");
        const use = document.createElement("button");
        use.type = "button";
        use.className = "ghost";
        use.textContent = "Dispute this";
        use.addEventListener("click", () => {
          $("dispute-report").value = item.report_id;
        });
        card.append(row, use);
      });
      agentBox.append(card);
    }
    const inquiries = await api("/v1/portal/inquiries", { headers: headers() });
    const inquiryBox = $("portal-inquiries");
    inquiryBox.innerHTML = "";
    if (!inquiries.length) {
      inquiryBox.append(line("No inquiries yet."));
    }
    inquiries.forEach((item) => {
      inquiryBox.append(line(item.at + " · " + item.organization + " · " + item.purpose_code + " · " + item.agent_id));
    });
  }

  $("portal-login").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api("/v1/portal/magic-link", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: $("portal-email").value.trim() }),
      });
      setStatus("If that address can sign in, a link was sent. In the demo, open the development mailbox.");
    } catch (error) {
      setStatus(error.message);
    }
  });

  $("portal-mailbox").addEventListener("click", async () => {
    try {
      const mail = await api("/v1/dev/mailbox");
      const session = await api("/v1/sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: mail.token }),
      });
      sessionStorage.setItem(tokenKey, session.token);
      await load();
      setStatus("");
    } catch (error) {
      setStatus(error.message);
    }
  });

  $("portal-out").addEventListener("click", () => {
    sessionStorage.removeItem(tokenKey);
    $("portal-app").hidden = true;
    $("portal-login").hidden = false;
  });

  $("dispute-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const node = $("dispute-result");
    try {
      const filed = await api("/v1/portal/disputes", {
        method: "POST",
        headers: headers(),
        body: JSON.stringify({
          report_id: $("dispute-report").value.trim(),
          statement: $("dispute-statement").value.trim(),
        }),
      });
      node.hidden = false;
      node.textContent = "Dispute " + filed.dispute_id + " is " + filed.status + ".";
    } catch (error) {
      node.hidden = false;
      node.textContent = error.message;
    }
  });

  const hash = new URLSearchParams(location.hash.replace(/^#/, ""));
  const token = hash.get("token");
  if (token) {
    api("/v1/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: token }),
    }).then((session) => {
      sessionStorage.setItem(tokenKey, session.token);
      return load();
    }).catch((error) => setStatus(error.message));
  } else if (sessionStorage.getItem(tokenKey)) {
    load().catch(() => sessionStorage.removeItem(tokenKey));
  }
})();
