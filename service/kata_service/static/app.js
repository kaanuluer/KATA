const form = document.querySelector("#demo-form");
const result = document.querySelector("#demo-result");

function readDemo() {
  const data = new FormData(form);
  return {
    intent: {
      maximum_amount: data.get("maximum_amount"),
      currency: data.get("intent_currency"),
      purpose: data.get("purpose"),
      category: data.get("category"),
      merchant: data.get("allowed_merchant"),
      natural_language: data.get("natural_language"),
      include_expiry: data.get("include_expiry") === "on",
      time_limit: data.get("time_limit"),
    },
    payment: {
      amount: data.get("payment_amount"),
      currency: data.get("payment_currency"),
      merchant: data.get("payment_merchant"),
      item: data.get("item"),
    },
  };
}

function badge(verdict) {
  const span = document.createElement("span");
  span.className = "badge " + verdict;
  span.textContent = verdict;
  return span;
}

function showResult(payload, status) {
  result.replaceChildren();
  result.hidden = false;
  if (!payload || payload.error) {
    result.dataset.verdict = "";
    const p = document.createElement("p");
    p.textContent = (payload && payload.error) || "The check did not complete.";
    result.append(p);
    return;
  }
  result.dataset.verdict = payload.verdict || "";
  const title = document.createElement("p");
  title.append(badge(payload.verdict || "STEP_UP"));
  const decision = document.createElement("span");
  decision.textContent = "  KATA decision " + (payload.kata_decision || "");
  title.append(decision);
  result.append(title);

  const who = document.createElement("p");
  who.textContent = payload.principal + " authorized " + payload.agent_id + ". Agreement " + payload.agreement_id + " is " + payload.status + ".";
  result.append(who);

  if (payload.messages && payload.messages.length) {
    const list = document.createElement("ul");
    payload.messages.forEach((message) => {
      const item = document.createElement("li");
      item.textContent = message;
      list.append(item);
    });
    result.append(list);
  } else if (payload.verdict === "ALLOW") {
    const ok = document.createElement("p");
    ok.textContent = "Identity, authorization, intent, and this payment agree.";
    result.append(ok);
  }

  if (payload.reasons && payload.reasons.length) {
    const reasons = document.createElement("p");
    reasons.className = "meta";
    reasons.textContent = "Reasons: " + payload.reasons.join(", ");
    result.append(reasons);
  }

  const hash = document.createElement("p");
  hash.className = "meta";
  hash.textContent = "Mandate hash " + (payload.mandate_hash || "") + " · principal " + (payload.principal_fingerprint || "");
  result.append(hash);

  const label = document.createElement("p");
  label.className = "meta";
  label.textContent = "Confirmation the principal signed";
  const pre = document.createElement("pre");
  pre.className = "confirm";
  pre.textContent = payload.confirmation_text || "";
  result.append(label, pre);
  result.dataset.status = String(status);
}

async function submitDemo(event) {
  if (event) event.preventDefault();
  result.hidden = false;
  result.dataset.verdict = "";
  result.textContent = "Checking the payment against the signed intent…";
  const response = await fetch("/demo/check", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify(readDemo()),
  });
  let payload = null;
  try {
    payload = await response.json();
  } catch (_err) {
    payload = { error: "The service returned a response that was not JSON." };
  }
  showResult(payload, response.status);
}

const expiry = form.elements.time_limit;
if (!expiry.value) {
  const day = new Date();
  day.setUTCDate(day.getUTCDate() + 30);
  expiry.value = day.toISOString().slice(0, 10);
}

form.addEventListener("submit", submitDemo);

document.querySelectorAll("[data-preset]").forEach((button) => {
  button.addEventListener("click", () => {
    const preset = button.dataset.preset;
    form.elements.maximum_amount.value = "1500";
    form.elements.intent_currency.value = "CAD";
    form.elements.payment_currency.value = "CAD";
    form.elements.purpose.value = "purchase";
    form.elements.category.value = "electronics";
    form.elements.item.value = preset === "deny" ? "MacBook Pro 14-inch" : "Laptop";
    form.elements.payment_amount.value = preset === "deny" ? "4200" : "1300";
    form.elements.include_expiry.checked = preset !== "step";
    submitDemo();
  });
});

function fillList(node, items, empty) {
  node.replaceChildren();
  if (!items.length) {
    const p = document.createElement("p");
    p.textContent = empty;
    node.append(p);
    return;
  }
  const list = document.createElement("ul");
  items.forEach((text) => {
    const item = document.createElement("li");
    item.textContent = text;
    list.append(item);
  });
  node.append(list);
}

async function loadJson(url) {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  const payload = await response.json();
  return { ok: response.ok, status: response.status, payload };
}

function statusText(payload, fallback) {
  const error = payload && payload.error;
  if (error === "DATABASE_URL is not set") {
    return "Nothing is published yet. Connect storage and set DATABASE_URL.";
  }
  return error || fallback;
}

async function refreshOps() {
  const revocations = document.querySelector("#revocation-body");
  const keys = document.querySelector("#keys-body");
  const log = document.querySelector("#log-body");
  try {
    const list = await loadJson("/v1/revocations");
    if (!list.ok) {
      fillList(revocations, [statusText(list.payload, "The revocation list is unavailable.")], "");
    } else {
      const rows = (list.payload.revocations || []).map((item) => {
        const id = item.agreement_id || item.revocation_id || "revocation";
        return item.reason ? id + " · " + item.reason : String(id);
      });
      fillList(revocations, rows, "No revocations are published.");
    }
  } catch (_err) {
    fillList(revocations, ["The revocation list did not answer."], "");
  }

  try {
    const published = await loadJson("/.well-known/kata-keys.json");
    if (!published.ok) {
      fillList(keys, [statusText(published.payload, "Published keys are unavailable.")], "");
    } else {
      const rows = (published.payload.keys || []).map((record) => {
        const key = record.public_key || {};
        return [key.kty, key.crv, key.kid].filter(Boolean).join(" · ") || "public key";
      });
      fillList(keys, rows, "No public keys are configured.");
    }
  } catch (_err) {
    fillList(keys, ["Published keys did not answer."], "");
  }

  try {
    const head = await loadJson("/v1/log/head");
    if (!head.ok) {
      fillList(log, [statusText(head.payload, "The transparency log has no signed tree head yet.")], "");
    } else {
      const size = head.payload.tree_size == null ? "unknown" : String(head.payload.tree_size);
      fillList(log, [
        "Tree size " + size,
        "Root " + (head.payload.root || ""),
        "Signed at " + (head.payload.at || ""),
      ], "");
    }
  } catch (_err) {
    fillList(log, ["The transparency log did not answer."], "");
  }
}

document.querySelector("#refresh-ops").addEventListener("click", refreshOps);
refreshOps();
