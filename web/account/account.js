// account.js — Misconfig Index account page
// Handles auth, org display, API key management, and repo listing.

const AUTH_API = "https://api.misconfig.dev";

const GRADE_COLORS = {
  A: "#22c55e",
  B: "#84cc16",
  C: "#eab308",
  D: "#f97316",
  F: "#ef4444",
};

// ── Auth helpers (mirrors app.js — no shared module needed) ──────────────────

function authGetToken() {
  return localStorage.getItem("misconfig_token");
}

function authClear() {
  localStorage.removeItem("misconfig_token");
  localStorage.removeItem("misconfig_user");
}

async function authFetchMe(token) {
  const res = await fetch(`${AUTH_API}/auth/me`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return null;
  return res.json();
}

// ── API helpers ───────────────────────────────────────────────────────────────

async function apiGet(path, token) {
  const res = await fetch(`${AUTH_API}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function apiPost(path, body, token) {
  const res = await fetch(`${AUTH_API}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

// ── Utility ───────────────────────────────────────────────────────────────────

function esc(str) {
  if (!str && str !== 0) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmtDate(iso) {
  if (!iso) return "never";
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function fmtRelative(iso) {
  if (!iso) return "never";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 2) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return fmtDate(iso);
}

// ── Render: plan & billing ────────────────────────────────────────────────────

function renderBilling(user) {
  const panel = document.getElementById("acct-billing-panel");
  const badgeEl = document.getElementById("billing-plan-badge");
  const detailsEl = document.getElementById("billing-details");
  const actionsEl = document.getElementById("billing-actions");
  if (!panel) return;

  const plan = user.plan || "free";
  const status = user.plan_status || null;
  const isPro = plan === "pro" && status === "active";
  const isPastDue = plan === "pro" && status === "past_due";

  if (isPro) {
    badgeEl.innerHTML = `<span class="plan-badge plan-badge--pro">Pro</span>`;
    detailsEl.innerHTML = `
      <div class="billing-detail-row">
        <span class="billing-detail-label">Plan</span>
        <span class="billing-detail-val">Pro — $19 / month</span>
      </div>
      <div class="billing-detail-row">
        <span class="billing-detail-label">Status</span>
        <span class="billing-detail-val billing-status--active">● Active</span>
      </div>`;
    actionsEl.innerHTML = `
      <button class="btn-billing-portal" onclick="handlePortal(this)">Manage billing →</button>
      <p class="billing-portal-note">Update payment method, download invoices, or cancel anytime.</p>`;
  } else if (isPastDue) {
    badgeEl.innerHTML = `<span class="plan-badge plan-badge--pastdue">Past Due</span>`;
    detailsEl.innerHTML = `
      <div class="billing-detail-row">
        <span class="billing-detail-label">Plan</span>
        <span class="billing-detail-val">Pro — $19 / month</span>
      </div>
      <div class="billing-detail-row">
        <span class="billing-detail-label">Status</span>
        <span class="billing-detail-val billing-status--pastdue">⚠ Payment past due</span>
      </div>`;
    actionsEl.innerHTML = `
      <button class="btn-billing-portal" onclick="handlePortal(this)">Update payment method →</button>`;
  } else {
    badgeEl.innerHTML = `<span class="plan-badge plan-badge--free">Free</span>`;
    detailsEl.innerHTML = `
      <div class="billing-detail-row">
        <span class="billing-detail-label">Plan</span>
        <span class="billing-detail-val">Free</span>
      </div>
      <div class="billing-detail-row">
        <span class="billing-detail-label">Limits</span>
        <span class="billing-detail-val">1 org · 50 API ingests/month · 30-day history</span>
      </div>`;
    actionsEl.innerHTML = `
      <button class="btn-upgrade" onclick="handleUpgrade(this)">Upgrade to Pro — $19/mo →</button>
      <p class="billing-upgrade-note">Unlimited ingests · 1-year history · Slack &amp; email alerts · priority support</p>`;
  }

  panel.hidden = false;
}

async function handleUpgrade(btn) {
  btn.disabled = true;
  btn.textContent = "Redirecting to checkout…";
  const token = authGetToken();
  try {
    const res = await apiPost("/billing/checkout", {}, token);
    window.location.href = res.checkout_url;
  } catch (e) {
    alert("Could not start checkout: " + esc(e.message));
    btn.disabled = false;
    btn.textContent = "Upgrade to Pro — $19/mo →";
  }
}

async function handlePortal(btn) {
  btn.disabled = true;
  btn.textContent = "Opening billing portal…";
  const token = authGetToken();
  try {
    const res = await apiPost("/billing/portal", {}, token);
    window.location.href = res.portal_url;
  } catch (e) {
    alert("Could not open billing portal: " + esc(e.message));
    btn.disabled = false;
    btn.textContent = "Manage billing →";
  }
}

// ── Render: user info ─────────────────────────────────────────────────────────

function renderUserInfo(user) {
  const avatarEl = document.getElementById("acct-avatar");
  if (user.avatar_url) {
    avatarEl.src = user.avatar_url;
    avatarEl.style.display = "block";
  } else {
    avatarEl.style.display = "none";
  }

  document.getElementById("acct-login").textContent = "@" + user.github_login;
  document.getElementById("acct-email").textContent = user.github_email || "";

  if (user.created_at) {
    const since = new Date(user.created_at).toLocaleDateString("en-US", {
      month: "long",
      year: "numeric",
    });
    document.getElementById("acct-member").textContent = "Member since " + since;
  }

  document.getElementById("acct-user-panel").hidden = false;
  document.getElementById("acct-actions-panel").hidden = false;
}

// ── Render: API key rows ──────────────────────────────────────────────────────

function renderKeyRow(key) {
  const lastUsed = key.last_used_at
    ? `Last used ${fmtRelative(key.last_used_at)}`
    : "Never used";

  const fullKeyHtml = key.key
    ? `<div class="key-new-reveal">
        <span class="key-new-warn">⚠ Copy this key now — it won't be shown again</span>
        <div class="key-full-row">
          <code class="key-full-val" id="keyval-${esc(key.id)}">${esc(key.key)}</code>
          <button class="copy-btn-sm" onclick="copyText('keyval-${esc(key.id)}', this)">Copy</button>
        </div>
      </div>`
    : "";

  return `
    <div class="key-row">
      <div class="key-row-main">
        <span class="key-name">${esc(key.name)}</span>
        <code class="key-prefix">${esc(key.key_prefix)}…</code>
        <span class="key-meta">${esc(lastUsed)}</span>
        <span class="key-status key-status--${key.is_active ? "active" : "inactive"}">${key.is_active ? "active" : "revoked"}</span>
      </div>
      ${fullKeyHtml}
    </div>`;
}

// ── Render: orgs + keys ───────────────────────────────────────────────────────

async function renderOrgs(user, token) {
  const panel = document.getElementById("acct-orgs-panel");
  const container = document.getElementById("acct-orgs-list");

  if (!user.orgs || user.orgs.length === 0) {
    container.innerHTML = `
      <p class="acct-empty">
        No organizations linked yet.
        <a href="/">Create one from the dashboard →</a>
      </p>`;
    panel.hidden = false;
    return;
  }

  // Show panel early with a loading state
  container.innerHTML = `<p class="acct-loading-msg">Loading API keys…</p>`;
  panel.hidden = false;

  let html = "";
  for (const org of user.orgs) {
    let keys = [];
    try {
      keys = await apiGet(`/v1/orgs/${org.id}/keys`, token);
    } catch (_) {
      // non-fatal — show empty state
    }

    html += `
      <div class="org-card">
        <div class="org-card-header">
          <span class="org-name">${esc(org.name)}</span>
          <span class="org-slug">/${esc(org.slug)}</span>
          <span class="org-role-badge org-role-${esc(org.role)}">${esc(org.role)}</span>
        </div>

        <div class="org-keys-section">
          <p class="org-keys-label">API Keys</p>
          <div class="org-keys-list">
            ${keys.length === 0
              ? `<p class="acct-empty-sm">No keys yet — create one below.</p>`
              : keys.map(renderKeyRow).join("")}
          </div>

          <div class="create-key-form" id="create-form-${org.id}">
            <input
              type="text"
              class="create-key-input"
              id="key-name-${org.id}"
              placeholder="Key name (e.g. github-actions)"
              maxlength="100"
            >
            <button class="btn-create-key" onclick="handleCreateKey(${org.id})">+ Create key</button>
          </div>
          <div id="create-result-${org.id}"></div>
        </div>
      </div>`;
  }

  container.innerHTML = html;
}

// ── Render: repos ─────────────────────────────────────────────────────────────

async function renderRepos(token) {
  const panel = document.getElementById("acct-repos-panel");
  const container = document.getElementById("acct-repos-list");
  const emptyEl = document.getElementById("acct-repos-empty");

  panel.hidden = false;
  container.innerHTML = `<p class="acct-loading-msg">Loading repos…</p>`;

  let orgRepos = [];
  try {
    orgRepos = await apiGet("/auth/my-repos", token);
  } catch (_) {
    container.innerHTML = `<p class="acct-empty">Could not load repos — try refreshing.</p>`;
    return;
  }

  // Flatten: collect all repos across orgs
  const allRepos = orgRepos.flatMap((group) =>
    group.repos.map((r) => ({ ...r, org_name: group.org_name, org_slug: group.org_slug }))
  );

  if (allRepos.length === 0) {
    container.innerHTML = "";
    emptyEl.hidden = false;
    return;
  }

  // Group by org
  let html = "";
  for (const group of orgRepos) {
    if (group.repos.length === 0) continue;

    html += `<p class="repo-group-label">${esc(group.org_name)} <span class="repo-group-slug">/${esc(group.org_slug)}</span></p>`;
    html += `<div class="repo-table">`;

    for (const repo of group.repos) {
      const color = GRADE_COLORS[repo.latest_grade] || "#64748b";
      const score = repo.latest_score !== null && repo.latest_score !== undefined
        ? repo.latest_score
        : "—";
      const grade = repo.latest_grade || "—";
      const scans = repo.total_scans;
      const last = fmtRelative(repo.last_scanned_at);

      html += `
        <div class="repo-row">
          <span class="repo-identifier" title="${esc(repo.identifier)}">${esc(repo.identifier)}</span>
          <span class="repo-grade-badge" style="color:${color};border-color:${color}22;background:${color}11">${grade}</span>
          <span class="repo-score-val">${score}<span class="repo-score-unit">/100</span></span>
          <span class="repo-scans-count">${scans} scan${scans !== 1 ? "s" : ""}</span>
          <span class="repo-last-scan">${last}</span>
        </div>`;
    }

    html += `</div>`;
  }

  container.innerHTML = html;
}

// ── Create API key ────────────────────────────────────────────────────────────

async function handleCreateKey(orgId) {
  const input = document.getElementById(`key-name-${orgId}`);
  const resultDiv = document.getElementById(`create-result-${orgId}`);
  const name = input.value.trim();

  if (!name) {
    resultDiv.innerHTML = `<p class="key-create-error">Please enter a key name.</p>`;
    return;
  }

  resultDiv.innerHTML = `<p class="acct-loading-msg">Creating…</p>`;

  const token = authGetToken();
  try {
    const key = await apiPost(`/v1/orgs/${orgId}/keys`, { name }, token);
    input.value = "";

    resultDiv.innerHTML = `
      <div class="key-created-box">
        <p class="key-new-warn">⚠ Copy this key now — it won't be shown again</p>
        <div class="key-full-row">
          <code class="key-full-val" id="new-key-${esc(key.id)}">${esc(key.key)}</code>
          <button class="copy-btn-sm" onclick="copyText('new-key-${esc(key.id)}', this)">Copy</button>
        </div>
        <p class="key-created-meta">
          <strong>${esc(key.name)}</strong> · prefix: <code class="key-prefix">${esc(key.key_prefix)}</code>
        </p>
      </div>`;
  } catch (e) {
    resultDiv.innerHTML = `<p class="key-create-error">Failed: ${esc(e.message)}</p>`;
  }
}

// ── Copy helper ───────────────────────────────────────────────────────────────

function copyText(elemId, btn) {
  const el = document.getElementById(elemId);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent.trim()).then(() => {
    const orig = btn.textContent;
    btn.textContent = "Copied!";
    btn.classList.add("copied");
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove("copied");
    }, 1800);
  });
}

// ── Sign out ──────────────────────────────────────────────────────────────────

function setupSignout() {
  const doSignout = (e) => {
    e.preventDefault();
    authClear();
    window.location.href = "/";
  };
  document.getElementById("nav-signout")?.addEventListener("click", doSignout);
  document.getElementById("acct-signout-btn")?.addEventListener("click", doSignout);
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

window.addEventListener("DOMContentLoaded", async () => {
  const token = authGetToken();

  if (!token) {
    // Not logged in — send back to homepage where they can sign in
    window.location.href = "/?need_signin=1";
    return;
  }

  setupSignout();

  const loadingEl = document.getElementById("acct-loading");

  const user = await authFetchMe(token);
  if (!user) {
    // Token expired or invalid
    authClear();
    window.location.href = "/";
    return;
  }

  // Cache updated user
  localStorage.setItem("misconfig_user", JSON.stringify(user));

  // Hide loading spinner
  loadingEl.hidden = true;

  // Upgrade success banner (redirected here from Stripe Checkout)
  if (new URLSearchParams(window.location.search).get("upgrade") === "success") {
    const banner = document.createElement("div");
    banner.className = "upgrade-success-banner";
    banner.innerHTML = `<span>🎉</span><span><strong>You're now on Pro!</strong> Thank you — your plan is active.</span>`;
    document.querySelector("main").insertBefore(banner, document.querySelector(".acct-page-header").nextSibling);
    // Clean the URL without reloading
    history.replaceState(null, "", "/account/");
  }

  // Render sections in parallel where possible
  renderUserInfo(user);
  renderBilling(user);
  await renderOrgs(user, token);
  await renderRepos(token);
});
