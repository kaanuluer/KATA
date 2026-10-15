(function () {
  const tokenKey = "gab-dashboard-token";
  const $ = (id) => document.getElementById(id);

  function setStatus(text) {
    $("login-status").textContent = text;
  }

  function authHeaders() {
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

  function show(id, value) {
    const node = $(id);
    node.hidden = false;
    node.innerHTML = "";
    node.append(render(value));
  }

  function render(value) {
    if (value && value.trust_score) {
      return inquiryView(value);
    }
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(value, null, 2);
    return pre;
  }

  function inquiryView(report) {
    const wrap = document.createElement("div");
    const score = document.createElement("p");
    score.className = "score";
    const figure = document.createElement("strong");
    figure.id = "trust-score";
    figure.textContent = String(report.trust_score.score);
    score.append(figure, document.createTextNode(" / 1000"));
    if (report.trust_score.cold_start) {
      const note = document.createElement("span");
      note.className = "meta";
      note.textContent = " Cold start";
      score.append(note);
    }
    wrap.append(score);
    const reasons = document.createElement("ol");
    reasons.id = "score-reasons";
    (report.trust_score.reasons || []).forEach((item) => {
      const row = document.createElement("li");
      row.textContent = item.code + " (" + item.points + ") " + item.detail;
      reasons.append(row);
    });
    wrap.append(reasons);
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(report, null, 2);
    wrap.append(pre);
    return wrap;
  }

  async function enter() {
    await api("/v1/alerts", { headers: authHeaders() });
    $("login-form").hidden = true;
    $("workspace").hidden = false;
    $("who").textContent = "Signed in.";
    try {
      const disputes = await api("/v1/admin/disputes", { headers: authHeaders() });
      show("disputes-result", disputes);
    } catch (error) {
      $("disputes-result").hidden = true;
    }
  }

  async function useToken(token) {
    sessionStorage.setItem(tokenKey, token);
    try {
      await enter();
    } catch (error) {
      sessionStorage.removeItem(tokenKey);
      $("login-form").hidden = false;
      $("workspace").hidden = true;
      throw error;
    }
  }

  document.querySelectorAll("[data-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll("[data-tab]").forEach((item) => item.removeAttribute("aria-current"));
      button.setAttribute("aria-current", "true");
      document.querySelectorAll("[id^='tab-']").forEach((panel) => {
        panel.hidden = panel.id !== "tab-" + button.getAttribute("data-tab");
      });
    });
  });

  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await useToken($("api-key").value.trim());
      setStatus("");
    } catch (error) {
      setStatus(error.message);
    }
  });

  document.querySelectorAll("[data-demo-key]").forEach((button) => {
    button.addEventListener("click", async () => {
      $("api-key").value = button.getAttribute("data-demo-key");
      try {
        await useToken($("api-key").value);
        setStatus("Signed in with the public demo credential.");
      } catch (error) {
        setStatus(error.message);
      }
    });
  });

  $("email-link").addEventListener("click", async () => {
    try {
      await api("/v1/dashboard/magic-link", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: $("org-email").value.trim() }),
      });
      setStatus("If that email is registered, a sign-in link was sent.");
    } catch (error) {
      setStatus(error.message);
    }
  });

  $("dev-mailbox").addEventListener("click", async () => {
    try {
      const mail = await api("/v1/dev/mailbox");
      const session = await api("/v1/sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: mail.token }),
      });
      await useToken(session.token);
      setStatus("Signed in from the development mailbox.");
    } catch (error) {
      setStatus(error.message);
    }
  });

  $("sign-out").addEventListener("click", () => {
    sessionStorage.removeItem(tokenKey);
    $("workspace").hidden = true;
    $("login-form").hidden = false;
  });

  $("agent-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const publicKey = JSON.parse($("public-key").value);
      const created = await api("/v1/agents", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          agent_id: $("agent-id").value.trim(),
          principal_id: $("principal-id").value.trim(),
          public_key: publicKey,
          verification_level: $("verification-level").value,
        }),
      });
      show("agent-result", created);
    } catch (error) {
      show("agent-result", { error: error.message });
    }
  });

  $("lookup-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const agent = await api("/v1/agents/" + encodeURIComponent($("lookup-id").value.trim()), {
        headers: authHeaders(),
      });
      show("agent-result", agent);
    } catch (error) {
      show("agent-result", { error: error.message });
    }
  });

  $("inquiry-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const report = await api("/v1/inquiries", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          agent_id: $("inquiry-agent").value.trim(),
          purpose_code: $("purpose-code").value,
        }),
      });
      show("inquiry-result", report);
    } catch (error) {
      show("inquiry-result", { error: error.message });
    }
  });

  $("report-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const filed = await api("/v1/reports", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          agent_id: $("report-agent").value.trim(),
          kind: $("report-kind").value,
          evidence_hash: $("evidence-hash").value.trim(),
          summary: $("report-summary").value.trim(),
        }),
      });
      show("report-result", filed);
    } catch (error) {
      show("report-result", { error: error.message });
    }
  });

  $("subscribe-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const created = await api("/v1/subscriptions", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          agent_id: $("subscribe-agent").value.trim(),
          webhook_url: $("subscribe-url").value.trim(),
        }),
      });
      show("alerts-result", created);
    } catch (error) {
      show("alerts-result", { error: error.message });
    }
  });

  $("refresh-alerts").addEventListener("click", async () => {
    try {
      show("alerts-result", await api("/v1/alerts", { headers: authHeaders() }));
    } catch (error) {
      show("alerts-result", { error: error.message });
    }
  });

  $("key-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const issued = await api("/v1/orgs/" + encodeURIComponent($("key-org").value.trim()) + "/keys", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ name: $("key-name").value.trim() || "key" }),
      });
      show("keys-result", issued);
    } catch (error) {
      show("keys-result", { error: error.message });
    }
  });

  $("refresh-keys").addEventListener("click", async () => {
    try {
      show("keys-result", await api("/v1/orgs/" + encodeURIComponent($("key-org").value.trim()) + "/keys", {
        headers: authHeaders(),
      }));
    } catch (error) {
      show("keys-result", { error: error.message });
    }
  });

  $("refresh-disputes").addEventListener("click", async () => {
    try {
      const disputes = await api("/v1/admin/disputes", { headers: authHeaders() });
      const wrap = document.createElement("div");
      if (!disputes.length) {
        wrap.textContent = "No disputes are open.";
      }
      disputes.forEach((item) => {
        const block = document.createElement("article");
        const title = document.createElement("p");
        title.textContent = item.dispute_id + " · " + item.status + " · " + item.report_id;
        const statement = document.createElement("p");
        statement.textContent = item.statement;
        const review = document.createElement("button");
        review.type = "button";
        review.textContent = "Uphold";
        review.addEventListener("click", async () => {
          const updated = await api("/v1/admin/disputes/" + encodeURIComponent(item.dispute_id), {
            method: "POST",
            headers: authHeaders(),
            body: JSON.stringify({ status: "resolved", outcome: "upheld" }),
          });
          show("disputes-result", updated);
        });
        block.append(title, statement, review);
        wrap.append(block);
      });
      const node = $("disputes-result");
      node.hidden = false;
      node.innerHTML = "";
      node.append(wrap);
    } catch (error) {
      show("disputes-result", { error: error.message });
    }
  });

  const hash = new URLSearchParams(location.hash.replace(/^#/, ""));
  const token = hash.get("token");
  if (token) {
    api("/v1/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: token }),
    }).then((session) => useToken(session.token)).catch((error) => setStatus(error.message));
  } else if (sessionStorage.getItem(tokenKey)) {
    enter().catch(() => sessionStorage.removeItem(tokenKey));
  }
})();
