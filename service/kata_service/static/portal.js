(function () {
  const tokenKey = "gab-portal-token";
  const $ = (id) => document.getElementById(id);
  let installEvent = null;

  function enrollmentOn() {
    const root = document.querySelector(".portal-home");
    return !!(root && root.getAttribute("data-passkey-enrollment") === "on");
  }

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
    if (!enrollmentOn()) {
      const list = options.excludeCredentials || options.allowCredentials;
      const key = options.excludeCredentials ? "excludeCredentials" : "allowCredentials";
      if (list) {
        next[key] = list.map((item) => Object.assign({}, item, { id: base64urlToBytes(item.id) }));
      }
      return next;
    }
    ["excludeCredentials", "allowCredentials"].forEach((key) => {
      const list = options[key];
      if (list && list.length) {
        next[key] = list.map((item) => Object.assign({}, item, { id: base64urlToBytes(item.id) }));
      } else {
        delete next[key];
      }
    });
    return next;
  }

  function passkeyHintsSupported() {
    if (typeof PublicKeyCredential === "undefined") return false;
    if (typeof PublicKeyCredential.parseRequestOptionsFromJSON !== "function") return false;
    try {
      const parsed = PublicKeyCredential.parseRequestOptionsFromJSON({
        challenge: "AA",
        hints: ["client-device"],
      });
      return Array.isArray(parsed.hints) && parsed.hints.indexOf("client-device") !== -1;
    } catch (error) {
      return false;
    }
  }

  function withClientHint(options) {
    const next = Object.assign({}, options);
    delete next.hints;
    if (passkeyHintsSupported()) next.hints = ["client-device"];
    return next;
  }

  function ceremonyOptions(options) {
    return publicKeyOptions(withClientHint(options));
  }

  const PASSKEY_MISS = "No passkey was found for this device. Email me a sign-in link. After you sign in, create a passkey on this device.";

  function showPasskeyMiss() {
    const miss = $("portal-passkey-miss");
    if (miss) miss.hidden = false;
    setStatus(PASSKEY_MISS);
    const email = $("portal-email");
    if (email) email.focus();
  }

  function passkeySignInFailed(error) {
    const name = error && error.name;
    const cancelled = name === "NotAllowedError" || name === "AbortError" || name === "NotSupportedError";
    if (cancelled || (error && error.status === 401)) {
      showPasskeyMiss();
      return;
    }
    setStatus(error && error.status ? error.message : "Sign-in did not finish. Email me a sign-in link. After you sign in, create a passkey on this device.");
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

  let conditionalAbort = null;
  let conditionalTimer = null;

  function stopConditional() {
    if (conditionalTimer) {
      clearTimeout(conditionalTimer);
      conditionalTimer = null;
    }
    if (conditionalAbort) {
      conditionalAbort.abort();
      conditionalAbort = null;
    }
  }

  async function conditionalAvailable() {
    if (!window.PublicKeyCredential || typeof PublicKeyCredential.isConditionalMediationAvailable !== "function") {
      return false;
    }
    try {
      return await PublicKeyCredential.isConditionalMediationAvailable();
    } catch (error) {
      return false;
    }
  }

  async function finishPasskey(credential) {
    const session = await api("/v1/portal/passkeys/authenticate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: credentialJSON(credential) }),
    });
    stopConditional();
    sessionStorage.setItem(tokenKey, session.token);
    await load();
    setStatus("");
  }

  async function startConditional() {
    if (!enrollmentOn()) return;
    if (sessionStorage.getItem(tokenKey)) return;
    stopConditional();
    conditionalAbort = new AbortController();
    const signal = conditionalAbort.signal;
    conditionalTimer = setTimeout(() => {
      if (!sessionStorage.getItem(tokenKey)) startConditional();
    }, 240000);
    if (!(await conditionalAvailable())) {
      if (!signal.aborted) stopConditional();
      return;
    }
    if (signal.aborted || sessionStorage.getItem(tokenKey)) return;
    try {
      const options = await api("/v1/portal/passkeys/authenticate/options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (signal.aborted) return;
      const credential = await navigator.credentials.get({
        mediation: "conditional",
        signal: signal,
        publicKey: ceremonyOptions(options),
      });
      if (!credential || signal.aborted) return;
      await finishPasskey(credential);
    } catch (error) {
      if (signal.aborted || (error && error.name === "AbortError")) return;
    }
  }

  async function load() {
    stopConditional();
    $("portal-login").hidden = true;
    $("portal-app").hidden = false;
    $("portal-who").textContent = "Signed in.";
    const devices = await api("/v1/portal/devices", { headers: headers() });
    const deviceBox = $("portal-devices");
    deviceBox.innerHTML = "";
    const offer = $("portal-passkey-offer");
    if (enrollmentOn()) {
      if (!devices.devices.length) {
        deviceBox.append(line("No passkey is registered yet."));
        if (offer) offer.textContent = "No passkey is registered yet. Create a passkey on this device.";
      } else if (offer) {
        offer.textContent = "Passkeys on this account. Create another on this device, or remove one.";
      }
    } else if (!devices.devices.length) {
      deviceBox.append(line("No device is registered yet."));
    }
    devices.devices.forEach((item) => {
      const row = document.createElement("div");
      row.className = "device";
      const used = item.last_used_at ? " · last used " + item.last_used_at : "";
      row.append(line(enrollmentOn() ? item.label + " · added " + item.created_at + used : item.label + " · " + item.created_at));
      const button = document.createElement("button");
      button.type = "button";
      button.className = "ghost";
      button.textContent = enrollmentOn() ? "Remove passkey" : "Remove device";
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
    const pushBox = $("portal-push");
    pushBox.innerHTML = "";
    devices.push_devices.forEach((item) => {
      const row = document.createElement("div");
      row.className = "device";
      row.append(line("Notices · " + item.endpoint));
      const button = document.createElement("button");
      button.type = "button";
      button.className = "ghost";
      button.textContent = "Remove notices";
      button.addEventListener("click", async () => {
        const proof = await assertion();
        await api("/v1/portal/push/" + encodeURIComponent(item.device_id) + "/remove", {
          method: "POST",
          headers: headers(),
          body: JSON.stringify({ assertion: proof }),
        });
        await load();
      });
      row.append(button);
      pushBox.append(row);
    });
    const approvalBox = $("portal-approvals");
    approvalBox.innerHTML = "";
    try {
      const approvals = await api("/v1/portal/approvals", { headers: headers() });
      if (!approvals.length) approvalBox.append(line("No approval is waiting."));
      approvals.forEach((item) => {
        const card = document.createElement("article");
        card.className = "agent-card";
        card.append(line(item.approval_id + " · " + item.status + " · until " + item.expires_at));
        if (item.action) card.append(line(JSON.stringify(item.action)));
        if (item.status === "pending") {
          ["approve", "reject"].forEach((decision) => {
            const button = document.createElement("button");
            button.type = "button";
            button.className = decision === "reject" ? "ghost" : "";
            button.textContent = decision === "approve" ? "Approve" : "Reject";
            button.addEventListener("click", async () => {
              const proof = await assertion();
              await api("/v1/portal/approvals/" + encodeURIComponent(item.approval_id) + "/" + decision, {
                method: "POST",
                headers: headers(),
                body: JSON.stringify({ assertion: proof }),
              });
              await load();
            });
            card.append(button);
          });
        }
        approvalBox.append(card);
      });
    } catch (error) {
      approvalBox.append(line(error.status === 404 ? "Approval notices are off on this host." : error.message));
    }
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
    if (enrollmentOn() && !devices.devices.length) {
      const create = $("portal-create-passkey");
      const account = $("portal-account");
      if (account && account.scrollIntoView) account.scrollIntoView();
      if (create) create.focus();
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
    if (!enrollmentOn()) {
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
      return;
    }
    stopConditional();
    try {
      if (!window.PublicKeyCredential || !navigator.credentials) {
        showPasskeyMiss();
        return;
      }
      const options = await api("/v1/portal/passkeys/authenticate/options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      const credential = await navigator.credentials.get({ publicKey: ceremonyOptions(options) });
      if (!credential) {
        showPasskeyMiss();
        return;
      }
      await finishPasskey(credential);
    } catch (error) {
      passkeySignInFailed(error);
      if (!sessionStorage.getItem(tokenKey)) startConditional();
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
    startConditional();
  });

  $("device-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const options = await api("/v1/portal/passkeys/register/options", { method: "POST", headers: headers() });
      const prepared = enrollmentOn() ? ceremonyOptions(options) : publicKeyOptions(options);
      const credential = await navigator.credentials.create({ publicKey: prepared });
      if (enrollmentOn() && !credential) {
        setStatus("The passkey was not created.");
        return;
      }
      await api("/v1/portal/passkeys", {
        method: "POST",
        headers: headers(),
        body: JSON.stringify({ label: $("device-label").value.trim(), credential: credentialJSON(credential) }),
      });
      await load();
      if (enrollmentOn()) setStatus("Passkey saved on this account.");
    } catch (error) {
      if (!enrollmentOn()) {
        setStatus(error.message);
        return;
      }
      const name = error && error.name;
      if (name === "NotAllowedError" || name === "AbortError") {
        setStatus("Passkey creation was cancelled. You can create a passkey on this device when you are ready.");
        return;
      }
      setStatus(error && error.status ? error.message : "The passkey was not created.");
    }
  });

  $("push-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!$("push-consent").checked) {
      setStatus("Approval notices stay off until you agree.");
      return;
    }
    try {
      const key = await api("/v1/portal/push/key", { headers: headers() });
      const registration = await navigator.serviceWorker.ready;
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: base64urlToBytes(key.public_key),
      });
      const json = subscription.toJSON();
      await api("/v1/portal/push", {
        method: "POST",
        headers: headers(),
        body: JSON.stringify({
          consent: true,
          endpoint: json.endpoint,
          keys: json.keys,
        }),
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
  } else {
    startConditional();
  }
})();
