// In development the web server runs on port 3000 and the API runs separately
// on port 8000.  In production (Docker) nginx serves everything on port 80
// and proxies /api/* to the FastAPI backend, so we use a relative path.
const IS_DEV = window.location.hostname === "localhost" ||
               window.location.hostname === "127.0.0.1";
const API_BASE = IS_DEV ? "http://127.0.0.1:8000" : "/api";

// Grade → accent color
const GRADE_COLORS = {
  A: "#22c55e",   // green
  B: "#84cc16",   // lime
  C: "#eab308",   // yellow
  D: "#f97316",   // orange
  F: "#ef4444",   // red
};

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#64748b",
};

const RULE_LABELS = {
  TF_OPEN_SG_0_0_0_0:      "Security group open to 0.0.0.0/0",
  TF_OPEN_SG_ALL_TRAFFIC:   "Security group allows all traffic",
  K8S_NO_RESOURCE_LIMITS:   "No CPU/memory resource limits",
  K8S_PRIVILEGED_CONTAINER: "Container running in privileged mode",
  K8S_LATEST_TAG:           "Container image uses :latest tag",
  K8S_IMAGE_LATEST_TAG:     "Container image uses :latest tag",
  K8S_RUN_AS_ROOT:          "Container runs as root (UID 0)",
  K8S_WRITABLE_ROOT_FS:     "Writable root filesystem",
  K8S_HOST_NETWORK:         "hostNetwork or hostPID enabled",
  K8S_NO_LIVENESS_PROBE:                "No liveness probe defined",
  K8S_NO_READINESS_PROBE:               "No readiness probe defined",
  K8S_AUTOMOUNT_SERVICE_ACCOUNT_TOKEN:  "Service account token auto-mounted",
  K8S_PRIVILEGE_ESCALATION_ALLOWED:     "Container allows privilege escalation",
  K8S_SECRET_AS_ENV_VAR:                "Secret referenced as environment variable",
  K8S_NO_POD_SECURITY_CONTEXT:          "No pod security context defined",
  K8S_HOST_PATH_MOUNT:                  "hostPath volume mount detected",
  K8S_INGRESS_NO_TLS:                   "Ingress missing TLS configuration",
  TF_IAM_WILDCARD:          "IAM wildcard resource (*)",
  TF_IAM_WILDCARD_HCL:              "IAM wildcard resource in HCL policy",
  TF_IAM_WILDCARD_RESOURCES_HCL:        "IAM wildcard resource in HCL policy",
  TF_SG_ALL_TRAFFIC:                    "Security group allows all traffic (protocol -1)",
  DOCKER_LATEST_TAG:                    "Dockerfile uses :latest base image",
  DOCKER_ROOT_USER:                     "Dockerfile runs as root user",
  TF_S3_PUBLIC_ACCESS_NOT_BLOCKED:      "S3 bucket public access not blocked",
  TF_S3_VERSIONING_DISABLED:            "S3 bucket versioning disabled",
  TF_S3_ENCRYPTION_DISABLED:            "S3 bucket encryption disabled",
  TF_RDS_PUBLICLY_ACCESSIBLE:           "RDS instance publicly accessible",
  TF_RDS_DELETION_PROTECTION_DISABLED:  "RDS deletion protection disabled",
  TF_RDS_STORAGE_ENCRYPTED_DISABLED:    "RDS storage encryption disabled",
  TF_SG_SSH_OPEN:                       "SSH port 22 open to the internet",
  TF_SG_RDP_OPEN:                       "RDP port 3389 open to the internet",
  TF_EBS_ENCRYPTION_DISABLED:           "EBS volume encryption disabled",
  TF_ECR_IMAGE_SCAN_DISABLED:           "ECR image scanning on push disabled",
  TF_CLOUDTRAIL_DISABLED:               "CloudTrail logging disabled",
  TF_KMS_ROTATION_DISABLED:             "KMS key rotation disabled",
};
function ruleLabel(id) { return RULE_LABELS[id] || id; }

// Benchmark data cached on load — used by percentile calculations
let _benchmarkCache = null;

function calcPercentile(score, dist) {
  const total = (dist.A||0)+(dist.B||0)+(dist.C||0)+(dist.D||0)+(dist.F||0);
  if (total < 5) return null;
  const bands = [[90,101,'A'],[80,90,'B'],[70,80,'C'],[40,70,'D'],[0,40,'F']];
  const [min, max, key] = bands.find(([lo,hi]) => score >= lo && score < hi) || [90,101,'A'];
  const below = {
    F: 0,
    D: (dist.F||0),
    C: (dist.F||0)+(dist.D||0),
    B: (dist.F||0)+(dist.D||0)+(dist.C||0),
    A: (dist.F||0)+(dist.D||0)+(dist.C||0)+(dist.B||0),
  }[key];
  const frac = (score - min) / (max - min);
  return Math.min(100, Math.max(0, Math.round(((below + (dist[key]||0) * frac) / total) * 100)));
}

function renderPercentileEl(score, elId, dist) {
  const el = document.getElementById(elId);
  if (!el) return;
  if (!dist) { el.hidden = true; return; }
  const pct = calcPercentile(score, dist);
  if (pct === null) { el.hidden = true; return; }
  el.hidden = false;
  if (pct >= 100)    el.textContent = "Top score in the community";
  else if (pct <= 0) el.textContent = "Scores lower than all tracked repos";
  else               el.textContent = `Scores better than ${pct}% of tracked repos`;
}

// Valid GitHub repo URL pattern (client-side pre-check before hitting the API)
// Accepts: github.com/owner/repo, https://github.com/owner/repo, owner/repo
const GH_REPO_RE =
  /^(https?:\/\/)?(www\.)?github\.com\/[A-Za-z0-9_.\-]+\/[A-Za-z0-9_.\-]+(\/.*)?$|^[A-Za-z0-9_.\-]+\/[A-Za-z0-9_.\-]+$/;

// ── Score card ───────────────────────────────────────────────────────────────

function renderScore(data) {
  const circleEl = document.getElementById("score-circle");
  const valueEl = document.getElementById("score-value");
  const gradeEl = document.getElementById("score-grade");
  const breakdownEl = document.getElementById("score-breakdown");

  const score = data.score ?? null;
  const grade = data.grade ?? null;
  const color = GRADE_COLORS[grade] || "#64748b";

  if (score === null) {
    valueEl.textContent = "—";
    gradeEl.textContent = "";
    return;
  }

  valueEl.textContent = score;
  gradeEl.textContent = `Grade ${grade}`;
  gradeEl.style.color = color;
  circleEl.style.borderColor = color;
  circleEl.style.boxShadow = `0 0 24px ${color}33`;
  renderPercentileEl(score, "score-percentile", _benchmarkCache?.grade_distribution);

  // Category breakdown bars
  const breakdown = data.score_breakdown || {};
  const entries = Object.entries(breakdown).sort((a, b) => a[1] - b[1]);

  if (entries.length === 0) {
    breakdownEl.innerHTML = "";
    return;
  }

  breakdownEl.innerHTML = entries
    .map(([cat, catScore]) => {
      const barColor = catScore >= 90 ? GRADE_COLORS.A
                     : catScore >= 75 ? GRADE_COLORS.B
                     : catScore >= 60 ? GRADE_COLORS.C
                     : catScore >= 40 ? GRADE_COLORS.D
                     : GRADE_COLORS.F;
      return `
        <div class="breakdown-row">
          <span class="breakdown-cat">${cat}</span>
          <div class="breakdown-bar-wrap">
            <div class="breakdown-bar" style="width:${catScore}%; background:${barColor}"></div>
          </div>
          <span class="breakdown-score">${catScore}</span>
        </div>`;
    })
    .join("");
}

// ── Stats panel ──────────────────────────────────────────────────────────────

function renderStats(data) {
  document.getElementById("total-findings").textContent = data.total_findings ?? 0;

  const filesEl = document.getElementById("files-scanned");
  if (filesEl) filesEl.textContent = data.total_files_scanned ?? "—";

  const topRulesEl = document.getElementById("top-rules");
  topRulesEl.innerHTML = "";
  (data.top_5_rules || []).forEach((item) => {
    const li = document.createElement("li");
    li.innerHTML = `<span class="rule-label">${ruleLabel(item.rule_id)}</span>` +
                   `<span class="rule-meta">${item.rule_id} · ${item.count}</span>`;
    topRulesEl.appendChild(li);
  });

  const severityEl = document.getElementById("severity-counts");
  severityEl.innerHTML = "";
  const severities = data.counts_by_severity || {};
  ["critical", "high", "medium", "low"].forEach((sev) => {
    if (severities[sev] === undefined) return;
    const li = document.createElement("li");
    li.innerHTML = `<span class="sev-dot" style="background:${SEVERITY_COLORS[sev] || '#64748b'}"></span>${sev}: <strong>${severities[sev]}</strong>`;
    severityEl.appendChild(li);
  });
  document.getElementById("severity-stat").style.display =
    severityEl.children.length > 0 ? "" : "none";
}

// ── Trend sparkline ───────────────────────────────────────────────────────────

function renderSparkline(history) {
  const subtitleEl = document.getElementById("chart-subtitle");
  const axisEl = document.getElementById("chart-axis");

  if (!history || history.length === 0) {
    subtitleEl.textContent = "No scan history yet";
    return;
  }

  // Score → y coordinate in 160-unit space (invert: high score = low y)
  const scoreToY = (s) => 160 - (Math.min(100, Math.max(0, s)) / 100) * 160;

  // X spread: leave 30px left padding for grade labels, 10px right
  const LEFT = 30, RIGHT = 790;
  const xRange = RIGHT - LEFT;
  const n = history.length;
  const xOf = (i) => LEFT + (n <= 1 ? xRange / 2 : (i / (n - 1)) * xRange);

  const points = history.map((entry, i) => ({
    x: xOf(i),
    y: scoreToY(entry.score),
    score: entry.score,
    grade: entry.grade,
    date: entry.scanned_at,
  }));

  // Build smooth polyline path
  const pathD = points
    .map((p, i) => (i === 0 ? `M ${p.x} ${p.y}` : `L ${p.x} ${p.y}`))
    .join(" ");

  const lineEl = document.getElementById("trend-line");
  const latestGrade = history[history.length - 1]?.grade || "C";
  const lineColor = GRADE_COLORS[latestGrade] || "#64748b";
  lineEl.setAttribute("d", pathD);
  lineEl.setAttribute("stroke", lineColor);

  // Dots
  const dotsEl = document.getElementById("trend-dots");
  dotsEl.innerHTML = "";
  points.forEach((p, i) => {
    const isLast = i === n - 1;
    const color = GRADE_COLORS[p.grade] || "#64748b";
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", p.x);
    circle.setAttribute("cy", p.y);
    circle.setAttribute("r", isLast ? 5 : 3.5);
    circle.setAttribute("fill", color);
    circle.setAttribute("stroke", "#151922");
    circle.setAttribute("stroke-width", "1.5");
    if (isLast) circle.setAttribute("filter", `drop-shadow(0 0 4px ${color})`);
    dotsEl.appendChild(circle);
  });

  // Score labels on last dot only
  const labelsEl = document.getElementById("trend-labels");
  labelsEl.innerHTML = "";
  const last = points[n - 1];
  const labelText = document.createElementNS("http://www.w3.org/2000/svg", "text");
  labelText.setAttribute("x", last.x + 8);
  labelText.setAttribute("y", last.y + 4);
  labelText.setAttribute("fill", lineColor);
  labelText.setAttribute("font-size", "11");
  labelText.setAttribute("font-weight", "700");
  labelText.setAttribute("font-family", "monospace");
  labelText.textContent = `${last.score} (${last.grade})`;
  labelsEl.appendChild(labelText);

  // Subtitle
  const first = history[0];
  const latest = history[history.length - 1];
  const firstDate = new Date(first.scanned_at).toLocaleDateString("en-US", { month: "short", day: "numeric" });
  const latestDate = new Date(latest.scanned_at).toLocaleDateString("en-US", { month: "short", day: "numeric" });
  const delta = latest.score - first.score;
  const deltaStr = delta >= 0 ? `+${delta}` : `${delta}`;
  const sign = delta >= 0 ? "↑" : "↓";
  subtitleEl.textContent = `${n} scans · ${firstDate} → ${latestDate} · ${sign} ${Math.abs(delta)} pts`;
  subtitleEl.style.color = delta >= 0 ? GRADE_COLORS.A : GRADE_COLORS.F;

  // X-axis date labels
  axisEl.innerHTML = "";
  const step = Math.max(1, Math.floor(n / 6));
  const axisIndices = [];
  for (let i = 0; i < n; i += step) axisIndices.push(i);
  if (axisIndices[axisIndices.length - 1] !== n - 1) axisIndices.push(n - 1);

  axisEl.style.display = "flex";
  axisEl.style.justifyContent = "space-between";
  axisEl.style.padding = "0 0 0 30px";

  const axisPoints = axisIndices.map((idx) => history[idx]);
  axisPoints.forEach((entry) => {
    const span = document.createElement("span");
    span.className = "axis-label";
    span.textContent = new Date(entry.scanned_at).toLocaleDateString("en-US", { month: "short", day: "numeric" });
    axisEl.appendChild(span);
  });
}

// ── Tabs (Get Started panel) ──────────────────────────────────────────────────

function initTabs() {
  const tabBar = document.querySelector(".tab-bar");
  if (!tabBar) return;

  tabBar.addEventListener("click", (e) => {
    const btn = e.target.closest(".tab-btn");
    if (!btn) return;
    const targetId = btn.dataset.tab;

    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));

    btn.classList.add("active");
    document.getElementById(targetId)?.classList.add("active");
  });
}

// ── Copy buttons ──────────────────────────────────────────────────────────────

function initCopyButtons() {
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.dataset.target;
      const el = document.getElementById(targetId);
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
    });
  });
}

// ── Industry Benchmark ────────────────────────────────────────────────────────

function renderBenchmark(data) {
  document.getElementById("bm-repos").textContent = data.total_repos.toLocaleString();
  document.getElementById("bm-scans").textContent = data.total_scans.toLocaleString();
  document.getElementById("bm-avg").textContent   = data.industry_avg_score;

  const dist = data.grade_distribution || {};
  const total = (dist.A || 0) + (dist.B || 0) + (dist.C || 0) + (dist.D || 0) + (dist.F || 0);
  const pct = (g) => total > 0 ? Math.max(0, ((dist[g] || 0) / total) * 100) : 0;

  ["A", "B", "C", "D", "F"].forEach((g) => {
    const el = document.getElementById(`gseg-${g.toLowerCase()}`);
    if (el) el.style.width = `${pct(g)}%`;
  });

  const legendEl = document.getElementById("grade-bar-legend");
  if (legendEl) {
    legendEl.innerHTML = ["A", "B", "C", "D", "F"]
      .filter((g) => (dist[g] || 0) > 0)
      .map((g) => `
        <span class="legend-item legend-item--${g.toLowerCase()}">
          <span class="legend-dot"></span>
          Grade ${g}: ${dist[g]} (${pct(g).toFixed(0)}%)
        </span>`)
      .join("");
  }

  const catEl = document.getElementById("cat-avg-list");
  const catAvgs = data.category_averages || {};
  if (catEl) {
    const entries = Object.entries(catAvgs).sort((a, b) => a[0].localeCompare(b[0]));
    if (entries.length === 0) {
      catEl.innerHTML = "<p class='bm-empty'>No category data yet.</p>";
    } else {
      catEl.innerHTML = entries
        .map(([cat, avg]) => {
          const barColor = avg >= 90 ? GRADE_COLORS.A
                         : avg >= 75 ? GRADE_COLORS.B
                         : avg >= 60 ? GRADE_COLORS.C
                         : avg >= 40 ? GRADE_COLORS.D
                         : GRADE_COLORS.F;
          return `
            <div class="cat-avg-row">
              <span class="cat-avg-name">${cat}</span>
              <div class="cat-avg-bar-wrap">
                <div class="cat-avg-bar" style="width:${avg}%;background:${barColor}"></div>
              </div>
              <span class="cat-avg-score">${avg}</span>
            </div>`;
        })
        .join("");
    }
  }

  const topEl = document.getElementById("top-misconfig-list");
  const topList = data.top_misconfigs || [];
  if (topEl) {
    if (topList.length === 0) {
      topEl.innerHTML = "<li class='bm-empty'>No findings recorded yet.</li>";
    } else {
      const maxCount = topList[0]?.count || 1;
      topEl.innerHTML = topList
        .slice(0, 10)
        .map((item) => {
          const barW = Math.round((item.count / maxCount) * 100);
          return `
            <li class="top-mc-row">
              <span class="top-mc-rule">${ruleLabel(item.rule_id)}</span><span class="top-mc-rule-sub">${item.rule_id}</span>
              <div class="top-mc-bar-wrap">
                <div class="top-mc-bar" style="width:${barW}%"></div>
              </div>
              <span class="top-mc-count">${item.count.toLocaleString()}</span>
            </li>`;
        })
        .join("");
    }
  }
}

// ── Data loading ──────────────────────────────────────────────────────────────

async function loadLatestReport() {
  const fallback = {
    total_findings: 0,
    top_5_rules: [],
    counts_by_severity: {},
    score: null,
    grade: null,
    score_breakdown: null,
    total_files_scanned: null,
  };

  try {
    const res = await fetch(`${API_BASE}/reports/latest`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderScore(data);
    renderStats(data);
  } catch (err) {
    console.warn("Failed to load report, using fallback.", err);
    renderScore(fallback);
    renderStats(fallback);
  }
}

async function loadHistory() {
  try {
    const res = await fetch(`${API_BASE}/reports/history`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderSparkline(data);
  } catch (err) {
    console.warn("Failed to load history.", err);
    const subtitleEl = document.getElementById("chart-subtitle");
    if (subtitleEl) subtitleEl.textContent = "Could not load history";
  }
}

async function loadBenchmark() {
  try {
    const res = await fetch(`${API_BASE}/reports/benchmark`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    _benchmarkCache = data;
    renderBenchmark(data);
  } catch (err) {
    console.warn("Failed to load benchmark data.", err);
    const panel = document.getElementById("benchmark-panel");
    if (panel) {
      panel.querySelector(".benchmark-columns").innerHTML =
        "<p class='bm-empty' style='padding:1rem'>Could not load benchmark data.</p>";
    }
  }
}

// ── Quick Scan ────────────────────────────────────────────────────────────────

function renderQuickScanResult(data) {
  const color = GRADE_COLORS[data.grade] || "#64748b";

  // Score circle
  const circle = document.getElementById("qs-circle");
  document.getElementById("qs-score-val").textContent = data.score;
  circle.style.borderColor = color;
  circle.style.boxShadow = `0 0 20px ${color}33`;

  // Grade + meta
  const gradeEl = document.getElementById("qs-grade");
  gradeEl.textContent = `Grade ${data.grade}`;
  gradeEl.style.color = color;
  renderPercentileEl(data.score, "qs-percentile", _benchmarkCache?.grade_distribution);

  document.getElementById("qs-meta").textContent =
    `${data.total_files_scanned} files · ${data.total_findings} finding${data.total_findings !== 1 ? "s" : ""}`;

  // Show repo name
  const repoEl = document.getElementById("qs-result-repo");
  if (repoEl) repoEl.textContent = data.repo || "";

  // Category breakdown
  const breakdownEl = document.getElementById("qs-breakdown");
  const entries = Object.entries(data.breakdown || {}).sort((a, b) => a[1] - b[1]);
  breakdownEl.innerHTML = entries
    .map(([cat, s]) => {
      const c = s >= 90 ? GRADE_COLORS.A : s >= 75 ? GRADE_COLORS.B
              : s >= 60 ? GRADE_COLORS.C : s >= 40 ? GRADE_COLORS.D : GRADE_COLORS.F;
      return `<div class="qs-br-row">
        <span class="qs-br-cat">${cat}</span>
        <div class="qs-br-bar-wrap"><div class="qs-br-bar" style="width:${s}%;background:${c}"></div></div>
        <span class="qs-br-score">${s}</span>
      </div>`;
    })
    .join("");

  // Top findings list
  const findingsEl = document.getElementById("qs-findings");
  if (!data.findings || data.findings.length === 0) {
    findingsEl.innerHTML = "<li class='qs-finding-empty'>No findings — looks clean!</li>";
  } else {
    findingsEl.innerHTML = data.findings
      .slice(0, 20)
      .map((f) => {
        const loc = f.line_start ? `${f.file}:${f.line_start}` : f.file;
        return `<li class="qs-finding">
          <div class="qs-finding-header">
            <span class="qs-rule-label">${escapeHtml(ruleLabel(f.rule_id))}</span>
            <span class="qs-finding-loc" title="${f.file}">${loc}</span>
          </div>
          <code class="qs-rule-id">${escapeHtml(f.rule_id)}</code>
          ${f.snippet ? `<code class="qs-snippet">${escapeHtml(f.snippet)}</code>` : ""}
          ${f.remediation ? `<p class="qs-remediation">→ ${escapeHtml(f.remediation)}</p>` : ""}
        </li>`;
      })
      .join("");
  }

  // Show result panel, hide findings wrap if clean
  const resultPanel = document.getElementById("qs-result");
  resultPanel.hidden = false;
  document.getElementById("qs-findings-wrap").hidden = data.total_findings === 0;

  // Scroll result into view smoothly
  resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function initQuickScan() {
  const form = document.getElementById("qs-form");
  if (!form) return;

  // "Clear" button hides the result panel
  const clearBtn = document.getElementById("qs-clear-btn");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      const resultPanel = document.getElementById("qs-result");
      if (resultPanel) resultPanel.hidden = true;
      const input = document.getElementById("qs-input");
      if (input) {
        input.value = "";
        input.focus();
      }
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const input = document.getElementById("qs-input");
    const url = input.value.trim();
    const errorEl = document.getElementById("qs-error");
    const loadingEl = document.getElementById("qs-loading");
    const btn = document.getElementById("qs-btn");

    // Always reset error state first
    errorEl.hidden = true;
    errorEl.textContent = "";

    // Guard: empty input — never show loading state
    if (!url) {
      errorEl.textContent = "Please enter a GitHub repository URL.";
      errorEl.hidden = false;
      return;
    }

    // Guard: invalid format — validate before touching loading state
    if (!GH_REPO_RE.test(url)) {
      errorEl.textContent =
        "Please enter a valid GitHub repo URL, e.g. github.com/hashicorp/terraform";
      errorEl.hidden = false;
      return;
    }

    // Only reach here with a valid-looking URL — safe to show loading
    // Hide any stale result panel from a previous scan
    const resultPanel = document.getElementById("qs-result");
    if (resultPanel) resultPanel.hidden = true;

    const loadingMsgEl = document.getElementById("qs-loading-msg");
    if (loadingMsgEl) loadingMsgEl.textContent = "Downloading & scanning…";

    btn.disabled = true;
    loadingEl.hidden = false;

    // Abort after 90 s; show a "still going" message after 15 s
    const controller = new AbortController();
    const abortTimer = setTimeout(() => controller.abort(), 90_000);
    const slowTimer = setTimeout(() => {
      if (loadingMsgEl) loadingMsgEl.textContent = "Still scanning (large repo)…";
    }, 15_000);

    try {
      const res = await fetch(`${API_BASE}/reports/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
        signal: controller.signal,
      });

      clearTimeout(abortTimer);
      clearTimeout(slowTimer);
      loadingEl.hidden = true;

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const msg = body.detail || `HTTP ${res.status}`;
        errorEl.textContent = `Scan failed: ${msg}`;
        errorEl.hidden = false;
        return;
      }

      const data = await res.json();
      renderQuickScanResult(data);
    } catch (err) {
      clearTimeout(abortTimer);
      clearTimeout(slowTimer);
      loadingEl.hidden = true;
      if (err.name === "AbortError") {
        errorEl.textContent = "Scan timed out — the repo may be too large. Try the CLI: pip install misconfig-index";
      } else {
        errorEl.textContent = `Network error: ${err.message}`;
      }
      errorEl.hidden = false;
    } finally {
      btn.disabled = false;
    }
  });
}


// ── User repos panel (dashboard personalisation) ──────────────────────────────

async function loadUserRepos(token) {
  const panel = document.getElementById("user-repos-panel");
  const listEl = document.getElementById("ur-list");
  const subtitleEl = document.getElementById("ur-subtitle");
  if (!panel) return;

  try {
    const orgRepos = await fetch(`${AUTH_API}/auth/my-repos`, {
      headers: { Authorization: `Bearer ${token}` },
    }).then((r) => (r.ok ? r.json() : []));

    // Flatten repos across orgs
    const allRepos = orgRepos.flatMap((g) =>
      g.repos.map((r) => ({ ...r, org_name: g.org_name, org_slug: g.org_slug }))
    );

    if (allRepos.length === 0) {
      // User is logged in but has no repos tracked yet
      subtitleEl.textContent = "No repos tracked yet";
      listEl.innerHTML = `
        <p style="color:#9aa5b8;font-size:14px;margin:8px 0 0">
          Set up <a href="/docs/" style="color:#6366f1">the CI integration</a> or use the CLI to start tracking your IaC.
        </p>`;
      panel.hidden = false;
      return;
    }

    // Show the panel
    panel.hidden = false;
    const totalScans = allRepos.reduce((s, r) => s + r.total_scans, 0);
    subtitleEl.textContent = `${allRepos.length} repo${allRepos.length !== 1 ? "s" : ""} · ${totalScans} scan${totalScans !== 1 ? "s" : ""}`;

    listEl.innerHTML = allRepos
      .map((repo) => {
        const color = GRADE_COLORS[repo.latest_grade] || "#64748b";
        const grade = repo.latest_grade || "—";
        const score = repo.latest_score !== null && repo.latest_score !== undefined
          ? repo.latest_score
          : "—";
        const lastScan = repo.last_scanned_at
          ? new Date(repo.last_scanned_at).toLocaleDateString("en-US", {
              month: "short",
              day: "numeric",
            })
          : "never";

        return `
          <div class="ur-repo-row">
            <span class="ur-identifier">${escapeHtml(repo.identifier)}</span>
            <span class="ur-grade" style="color:${color};border-color:${color}22;background:${color}11">${grade}</span>
            <span class="ur-score">${score}<span class="ur-score-unit">/100</span></span>
            <span class="ur-meta">${repo.total_scans} scan${repo.total_scans !== 1 ? "s" : ""}</span>
            <span class="ur-meta ur-last">${lastScan}</span>
          </div>`;
      })
      .join("");

  } catch (err) {
    console.warn("Failed to load user repos", err);
  }
}


// ── Auth (GitHub OAuth + JWT) ─────────────────────────────────────────────────

const AUTH_API = "https://api.misconfig.dev";

function authGetToken() {
  return localStorage.getItem("misconfig_token");
}

function authSetToken(token) {
  localStorage.setItem("misconfig_token", token);
}

function authClear() {
  localStorage.removeItem("misconfig_token");
  localStorage.removeItem("misconfig_user");
}

function authGetUser() {
  const raw = localStorage.getItem("misconfig_user");
  return raw ? JSON.parse(raw) : null;
}

async function authFetchMe(token) {
  const res = await fetch(`${AUTH_API}/auth/me`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return null;
  return res.json();
}

function authRenderNav(user) {
  const signinBtn = document.getElementById("nav-signin");
  const authBlock = document.getElementById("nav-auth");
  const avatar    = document.getElementById("nav-avatar");
  const loginSpan = document.getElementById("nav-login");
  const signout   = document.getElementById("nav-signout");

  if (!signinBtn) return;

  if (user) {
    signinBtn.style.display = "none";
    authBlock.style.display = "inline-flex";
    authBlock.style.alignItems = "center";
    avatar.src = user.avatar_url || "";
    avatar.style.display = user.avatar_url ? "inline" : "none";
    loginSpan.textContent = user.github_login;
    signout.addEventListener("click", (e) => {
      e.preventDefault();
      authClear();
      window.location.reload();
    });
  } else {
    signinBtn.style.display = "";
    authBlock.style.display = "none";
  }
}

async function initAuth() {
  // Pick up token from URL after GitHub OAuth callback redirect
  const params = new URLSearchParams(window.location.search);
  const urlToken = params.get("token");
  if (urlToken) {
    authSetToken(urlToken);
    // Clean token from URL without triggering a reload
    const clean = window.location.pathname;
    window.history.replaceState({}, "", clean);
  }

  const token = authGetToken();
  if (!token) { authRenderNav(null); return; }

  // Use cached user if fresh enough, otherwise re-fetch
  let user = authGetUser();
  if (!user) {
    user = await authFetchMe(token);
    if (user) {
      localStorage.setItem("misconfig_user", JSON.stringify(user));
    } else {
      authClear(); // token expired / invalid
    }
  }
  authRenderNav(user);

  // Load personalised repos panel when logged in
  if (user && token) {
    loadUserRepos(token);
  }
}


// ── Bootstrap ─────────────────────────────────────────────────────────────────

window.addEventListener("DOMContentLoaded", () => {
  loadLatestReport();
  loadHistory();
  loadBenchmark();
  initTabs();
  initCopyButtons();
  initQuickScan();
  initAuth();
});
