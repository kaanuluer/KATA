(function () {
  const tokenKey = "gab-portal-token";
  const $ = (id) => document.getElementById(id);
  let installEvent = null;

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

  function bytesToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let raw = "";
    bytes.forEach((item) => {
      raw += String.fromCharCode(item);
    });
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function base64urlToBytes(value) {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
    const raw = atob(padded);
    const bytes = new Uint8Array(raw.length);
    for (let index = 0; index < raw.length; index += 1) bytes[index] = raw.charCodeAt(index);
    return bytes.buffer;
  }

  function publicKeyOptions(options) {
    const next = Object.assign({}, options);
    next.challenge = base64urlToBytes(options.challenge);
    if (options.user) {
      next.user = Object.assign({}, options.user, { id: base64urlToBytes(options.user.id) });
    }
    const list = options.excludeCredentials || options.allowCredentials;
    const key = options.excludeCredentials ? "excludeCredentials" : "allowCredentials";
    if (list) {
      next[key] = list.map((item) => Object.assign({}, item, { id: base64urlToBytes(item.id) }));
    }
    return next;
  }

  function credentialJSON(credential) {
    const response = credential.response;
    const body = {
      id: credential.id,
      rawId: bytesToBase64url(credential.rawId),
      type: credential.type,
      response: { clientDataJSON: bytesToBase64url(response.clientDataJSON) },
    };
    if (response.attestationObject) {
      body.response.attestationObject = bytesToBase64url(response.attestationObject);
    } else {
      body.response.authenticatorData = bytesToBase64url(response.authenticatorData);
      body.response.signature = bytesToBase64url(response.signature);
      if (response.userHandle) body.response.userHandle = bytesToBase64url(response.userHandle);
    }
    return body;
  }

  async function assertion() {
    const options = await api("/v1/portal/passkeys/assert/options", { method: "POST", headers: headers() });
    const credential = await navigator.credentials.get({ publicKey: publicKeyOptions(options) });
    return credentialJSON(credential);
  }

  async function load() {
    $("portal-login").hidden = true;
    $("portal-app").hidden = false;
    $("portal-who").textContent = "Signed in.";
    const devices = await api("/v1/portal/devices", { headers: headers() });
    const deviceBox = $("portal-devices");
    deviceBox.innerHTML = "";
    if (!devices.devices.length) deviceBox.append(line("No device is registered yet."));
    devices.devices.forEach((item) => {
      const row = document.createElement("div");
      row.className = "device";
      row.append(line(item.label + " · " + item.created_at));
      const button = document.createElement("button");
      button.type = "button";
      button.className = "ghost";
      button.textContent = "Remove device";
      button.addEventListener("click", async () => {
        const proof = await assertion();
        await api("/v1/portal/devices/" + encodeURIComponent(item.credential_id) + "/remove", {
          method: "POST",
          headers: headers(),
          body: JSON.stringify({ assertion: proof }),
        });
        await load();
      });
      row.append(button);
      deviceBox.append(row);
    });
    const agents = await api("/v1/portal/agents", { headers: headers() });
    const agentBox = $("portal-agents");
    agentBox.innerHTML = "";
    if (!agents.length) agentBox.append(line("No agents are bound to this principal."));
    for (const agent of agents) {
      const card = document.createElement("article");
      card.className = "agent-card";
      card.append(
        line(agent.agent_id + " · " + agent.status + " · claim " + agent.verification_level + " · assurance " + (agent.assurance_level || ""))
      );
      const revoke = document.createElement("button");
      revoke.type = "button";
      revoke.textContent = "Revoke agent";
      revoke.addEventListener("click", async () => {
        const proof = await assertion();
        await api("/v1/portal/agents/" + encodeURIComponent(agent.agent_id) + "/revoke", {
          method: "POST",
          headers: headers(),
          body: JSON.stringify({ assertion: proof }),
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
          const proof = await assertion();
          await api("/v1/portal/agreements/" + encodeURIComponent(item.agreement_id) + "/revoke", {
            method: "POST",
            headers: headers(),
            body: JSON.stringify({ assertion: proof }),
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
    if (!inquiries.length) inquiryBox.append(line("No inquiries yet."));
    inquiries.forEach((item) => {
      inquiryBox.append(line(item.at + " · " + item.organization + " · " + item.purpose_code + " · " + item.agent_id));
    });
    const disputes = await api("/v1/portal/disputes", { headers: headers() });
    const disputeBox = $("portal-disputes");
    disputeBox.innerHTML = "";
    if (!disputes.length) disputeBox.append(line("No disputes filed."));
    disputes.forEach((item) => {
      const outcome = item.outcome ? " · " + item.outcome : "";
      disputeBox.append(line(item.dispute_id + " · " + item.status + outcome + " · " + item.report_id));
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

  $("portal-passkey").addEventListener("click", async () => {
    try {
      const options = await api("/v1/portal/passkeys/authenticate/options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      const credential = await navigator.credentials.get({ publicKey: publicKeyOptions(options) });
      const session = await api("/v1/portal/passkeys/authenticate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: credentialJSON(credential) }),
      });
      sessionStorage.setItem(tokenKey, session.token);
      await load();
      setStatus("");
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

  $("device-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const options = await api("/v1/portal/passkeys/register/options", { method: "POST", headers: headers() });
      const credential = await navigator.credentials.create({ publicKey: publicKeyOptions(options) });
      await api("/v1/portal/passkeys", {
        method: "POST",
        headers: headers(),
        body: JSON.stringify({ label: $("device-label").value.trim(), credential: credentialJSON(credential) }),
      });
      await load();
    } catch (error) {
      setStatus(error.message);
    }
  });

  $("dispute-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const node = $("dispute-result");
    try {
      const proof = await assertion();
      const filed = await api("/v1/portal/disputes", {
        method: "POST",
        headers: headers(),
        body: JSON.stringify({
          report_id: $("dispute-report").value.trim(),
          statement: $("dispute-statement").value.trim(),
          assertion: proof,
        }),
      });
      node.hidden = false;
      node.textContent = "Dispute " + filed.dispute_id + " is " + filed.status + ".";
      await load();
    } catch (error) {
      node.hidden = false;
      node.textContent = error.message;
    }
  });

  window.addEventListener("beforeinstallprompt", (event) => {
    event.preventDefault();
    installEvent = event;
    $("portal-install").hidden = false;
  });

  $("portal-install").addEventListener("click", async () => {
    if (!installEvent) return;
    installEvent.prompt();
    await installEvent.userChoice;
    installEvent = null;
    $("portal-install").hidden = true;
  });

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }

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
