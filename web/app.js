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
    li.textContent = `${item.rule_id}: ${item.count}`;
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
}

// ── Trend sparkline ───────────────────────────────────────────────────────────

/**
 * Renders an SVG trend line onto #trend-chart.
 * viewBox is 800×160 where y=0 → score 100, y=160 → score 0.
 *
 * Grade bands (matching SVG rect elements):
 *   A ≥ 90  → y: 0–16
 *   B ≥ 75  → y: 16–40
 *   C ≥ 60  → y: 40–64
 *   D ≥ 40  → y: 64–96
 *   F < 40  → y: 96–160
 */
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
  // Show up to 6 evenly-spaced dates
  const step = Math.max(1, Math.floor(n / 6));
  const axisIndices = [];
  for (let i = 0; i < n; i += step) axisIndices.push(i);
  if (axisIndices[axisIndices.length - 1] !== n - 1) axisIndices.push(n - 1);

  axisEl.style.display = "flex";
  axisEl.style.justifyContent = "space-between";
  axisEl.style.padding = "0 0 0 30px";

  // Build axis with positioned spans
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

    // Deactivate all
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));

    // Activate selected
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

/**
 * Renders the public benchmark panel from /reports/benchmark.
 * @param {Object} data  PublicBenchmarkStats (or OrgBenchmarkStats)
 */
function renderBenchmark(data) {
  // Header stats
  document.getElementById("bm-repos").textContent = data.total_repos.toLocaleString();
  document.getElementById("bm-scans").textContent = data.total_scans.toLocaleString();
  document.getElementById("bm-avg").textContent   = data.industry_avg_score;

  // Grade distribution stacked bar
  const dist = data.grade_distribution || {};
  const total = (dist.A || 0) + (dist.B || 0) + (dist.C || 0) + (dist.D || 0) + (dist.F || 0);

  const pct = (g) => total > 0 ? Math.max(0, ((dist[g] || 0) / total) * 100) : 0;

  ["A", "B", "C", "D", "F"].forEach((g) => {
    const el = document.getElementById(`gseg-${g.toLowerCase()}`);
    if (el) el.style.width = `${pct(g)}%`;
  });

  // Legend
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

  // Category averages
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

  // Top misconfigs
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
              <span class="top-mc-rule" title="${item.rule_id}">${item.rule_id}</span>
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

  document.getElementById("qs-meta").textContent =
    `${data.total_files_scanned} files · ${data.total_findings} finding${data.total_findings !== 1 ? "s" : ""}`;

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
            <code class="qs-rule-id">${f.rule_id}</code>
            <span class="qs-finding-loc" title="${f.file}">${loc}</span>
          </div>
          ${f.snippet ? `<code class="qs-snippet">${escapeHtml(f.snippet)}</code>` : ""}
          ${f.remediation ? `<p class="qs-remediation">→ ${escapeHtml(f.remediation)}</p>` : ""}
        </li>`;
      })
      .join("");
  }

  // Show result, hide anything else
  document.getElementById("qs-result").hidden = false;
  document.getElementById("qs-findings-wrap").hidden = data.total_findings === 0;
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

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = document.getElementById("qs-input");
    const url = input.value.trim();
    if (!url) return;

    const btn = document.getElementById("qs-btn");
    const loadingEl = document.getElementById("qs-loading");
    const errorEl = document.getElementById("qs-error");
    const resultEl = document.getElementById("qs-result");

    // Reset state
    btn.disabled = true;
    resultEl.hidden = true;
    errorEl.hidden = true;
    loadingEl.hidden = false;

    try {
      const res = await fetch(`${API_BASE}/reports/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

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
      loadingEl.hidden = true;
      errorEl.textContent = `Network error: ${err.message}`;
      errorEl.hidden = false;
    } finally {
      btn.disabled = false;
    }
  });
}


// ── Bootstrap ─────────────────────────────────────────────────────────────────

window.addEventListener("DOMContentLoaded", () => {
  loadLatestReport();
  loadHistory();
  loadBenchmark();
  initTabs();
  initCopyButtons();
  initQuickScan();
});
