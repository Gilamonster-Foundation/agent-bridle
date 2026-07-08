// agent-bridle-gateway console — Presence + Traffic.
//
// Real WebAuthn ceremony (create/get), real WebSocket transport. The mesh leg is
// mocked by the gateway; this script never pretends the assertion is verified —
// the gateway relays it and the work-box gate would re-verify (§8.1/§8.3).
"use strict";

// ── base64url helpers (WebAuthn's wire form) ──────────────────────────────────
const b64u = {
  encode(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  decode(str) {
    const pad = str.length % 4 ? "=".repeat(4 - (str.length % 4)) : "";
    const s = atob(str.replace(/-/g, "+").replace(/_/g, "/") + pad);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  },
};

const hexToBytes = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
};

const $ = (id) => document.getElementById(id);
const setStatus = (el, msg, cls) => {
  el.textContent = msg;
  el.className = "status " + (cls || "info");
};

// ── tabs ──────────────────────────────────────────────────────────────────────
function selectTab(which) {
  for (const t of ["presence", "traffic"]) {
    $("tab-" + t).classList.toggle("active", t === which);
    $("panel-" + t).classList.toggle("active", t === which);
  }
}
$("tab-presence").onclick = () => selectTab("presence");
$("tab-traffic").onclick = () => selectTab("traffic");

// ── state fed by the server ────────────────────────────────────────────────────
let RP_ID = "localhost";
let currentRequest = null; // the outstanding DischargeRequest

// ── WebSocket ──────────────────────────────────────────────────────────────────
let ws;
function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onmessage = (ev) => onServerMsg(JSON.parse(ev.data));
  ws.onclose = () => {
    $("banner").textContent = "disconnected — retrying…";
    setTimeout(connect, 1500);
  };
}

function send(obj) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

function onServerMsg(msg) {
  switch (msg.type) {
    case "hello":
      RP_ID = msg.rp_id;
      $("banner").textContent = msg.notice;
      refreshStatus();
      break;
    case "discharge_request":
      showRequest(msg);
      break;
    case "discharge_result":
      showResult(msg);
      break;
    case "flow":
      addFlow(msg);
      break;
  }
}

// ── status ─────────────────────────────────────────────────────────────────────
async function refreshStatus() {
  try {
    const s = await (await fetch("/api/status")).json();
    $("enrolled-count").textContent = s.enrolled;
  } catch (_) {}
}

// ── enroll (navigator.credentials.create) ──────────────────────────────────────
$("btn-enroll").onclick = async () => {
  const status = $("enroll-status");
  if (!window.PublicKeyCredential) {
    setStatus(status, "WebAuthn is not available in this browser.", "err");
    return;
  }
  try {
    setStatus(status, "requesting authenticator…", "info");
    const opts = await (await fetch("/api/presence/enroll/options")).json();
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: b64u.decode(opts.challenge),
        rp: opts.rp,
        user: {
          id: b64u.decode(opts.user.id),
          name: opts.user.name,
          displayName: opts.user.displayName,
        },
        pubKeyCredParams: opts.pubKeyCredParams,
        authenticatorSelection: opts.authenticatorSelection,
        timeout: opts.timeout,
      },
    });
    const body = {
      raw_id: b64u.encode(cred.rawId),
      client_data_json: b64u.encode(cred.response.clientDataJSON),
      label: $("enroll-label").value || "authenticator",
    };
    const res = await fetch("/api/presence/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const j = await res.json();
    $("enrolled-count").textContent = j.enrolled;
    setStatus(status, "enrolled ✓ — credential pinned in this gateway's registry.", "ok");
  } catch (e) {
    setStatus(status, "enroll failed: " + (e.message || e), "err");
  }
};

// ── simulate a presence request ─────────────────────────────────────────────────
$("btn-simulate").onclick = () => {
  send({
    type: "simulate_request",
    presence: $("req-presence").value,
    action_summary: $("req-summary").value,
  });
};

function showRequest(req) {
  currentRequest = req;
  $("ap-summary").textContent = req.action_summary;
  $("ap-presence").textContent = req.required_presence;
  $("ap-gen").textContent = req.generation;
  $("ap-chal").textContent = req.challenge_hex.slice(0, 16) + "…";
  $("approve-card").classList.remove("hidden");
  setStatus($("approve-status"), "", "info");
  selectTab("presence");
}

// ── approve (navigator.credentials.get) ─────────────────────────────────────────
$("btn-approve").onclick = async () => {
  const status = $("approve-status");
  if (!currentRequest) return;
  try {
    setStatus(status, "touch your authenticator…", "info");
    const challenge = hexToBytes(currentRequest.challenge_hex);
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: RP_ID,
        userVerification: "required",
        timeout: 60000,
      },
    });
    send({
      type: "discharge",
      kind: "assertion",
      id: currentRequest.id,
      raw_id: b64u.encode(assertion.rawId),
      authenticator_data: b64u.encode(assertion.response.authenticatorData),
      client_data_json: b64u.encode(assertion.response.clientDataJSON),
      signature: b64u.encode(assertion.response.signature),
    });
    setStatus(status, "assertion sent — relaying to the (mock) mesh…", "info");
  } catch (e) {
    setStatus(status, "gesture failed: " + (e.message || e), "err");
  }
};

$("btn-deny").onclick = () => {
  if (!currentRequest) return;
  send({ type: "discharge", kind: "refused", id: currentRequest.id });
  setStatus($("approve-status"), "denied.", "info");
};

function showResult(res) {
  const status = $("approve-status");
  setStatus(status, res.detail, res.relayed ? "ok" : "err");
  currentRequest = null;
  refreshStatus();
}

// ── traffic table ───────────────────────────────────────────────────────────────
const MAX_ROWS = 200;
function addFlow(f) {
  const body = $("flow-body");
  const tr = document.createElement("tr");
  const tok = f.usage ? f.usage.prompt + f.usage.completion : "—";
  const cells = [
    f.seq,
    f.provider,
    f.endpoint,
    f.model || "—",
    `<span class="fid-${f.fidelity}">${f.fidelity}</span>`,
    f.bytes_up,
    f.bytes_down,
    tok,
    f.dur_ms,
  ];
  tr.innerHTML = cells
    .map((c, i) => `<td class="${i >= 5 ? "num" : ""}">${c}</td>`)
    .join("");
  body.prepend(tr);
  while (body.children.length > MAX_ROWS) body.removeChild(body.lastChild);
}

// initial history load for the Traffic tab
(async () => {
  try {
    const rows = await (await fetch("/api/traffic")).json();
    for (const r of rows.reverse()) addFlow(r);
  } catch (_) {}
})();

connect();
