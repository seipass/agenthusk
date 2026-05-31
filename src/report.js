const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEVERITY_LABELS = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info"
};
const GUARANTEE = "Matched content values are excluded from content-derived report fields. Paths are anonymized by default; review metadata before sharing.";
const RAW_PATH_WARNING = "Unsafe path mode is active. Raw source paths are included for private local review and can contain sensitive text. Do not share this report.";
const HIDDEN_VALUE = "<hidden>";

const VALUE_PATTERNS = [
  [/https:\/\/(?:discord|discordapp)\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/gi, HIDDEN_VALUE],
  [/\bgh[pousr]_[A-Za-z0-9_]{30,}\b/g, HIDDEN_VALUE],
  [/\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, HIDDEN_VALUE],
  [/\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b/g, HIDDEN_VALUE],
  [/\bAIza[A-Za-z0-9_-]{30,}\b/g, HIDDEN_VALUE],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, HIDDEN_VALUE],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, HIDDEN_VALUE],
  [/\b(Bearer\s+)[A-Za-z0-9._~+/=-]{16,}/gi, `$1${HIDDEN_VALUE}`],
  [
    /\b((?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|webhook[_-]?url)\b\s*[:=]\s*["']?)[A-Za-z0-9_./+:=@-]{8,}/gi,
    `$1${HIDDEN_VALUE}`
  ]
];

function clamp(value, minimum, maximum) {
  return Math.min(Math.max(value, minimum), maximum);
}

function finiteNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function integer(value, fallback = 0) {
  return Math.max(0, Math.round(finiteNumber(value, fallback)));
}

function redactValues(value, fallback = "") {
  let text = value == null ? fallback : String(value);
  for (const [pattern, replacement] of VALUE_PATTERNS) {
    pattern.lastIndex = 0;
    text = text.replace(pattern, replacement);
  }
  return text;
}

function escapeHtml(value) {
  return redactValues(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeJson(value) {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function safeColor(value) {
  const color = String(value ?? "");
  return /^#[0-9a-f]{6}$/i.test(color) ? color : "#e27650";
}

function safeFingerprint(value) {
  const fingerprint = String(value ?? "");
  return /^[a-f0-9]{6,64}$/i.test(fingerprint) ? fingerprint : "unavailable";
}

function safeSeverity(value) {
  return SEVERITIES.includes(value) ? value : "info";
}

function riskFromScore(score) {
  if (score >= 75) return "critical";
  if (score >= 45) return "high";
  if (score >= 20) return "guarded";
  return "low";
}

function normalizeStats(stats = {}) {
  return {
    filesVisited: integer(stats.filesVisited),
    directoriesVisited: integer(stats.directoriesVisited),
    entriesVisited: integer(stats.entriesVisited),
    bytesVisited: integer(stats.bytesVisited),
    bytesRead: integer(stats.bytesRead),
    textFilesInspected: integer(stats.textFilesInspected),
    binaryFilesSkipped: integer(stats.binaryFilesSkipped),
    filesSkippedBySize: integer(stats.filesSkippedBySize),
    symlinksSkipped: integer(stats.symlinksSkipped),
    rootsMissing: integer(stats.rootsMissing),
    rootsSkippedUnsafe: integer(stats.rootsSkippedUnsafe),
    depthCapped: integer(stats.depthCapped),
    findingsDropped: integer(stats.findingsDropped),
    secretOccurrencesDropped: integer(stats.secretOccurrencesDropped),
    coverageIncomplete: Boolean(stats.coverageIncomplete),
    noFollowSupported: Boolean(stats.noFollowSupported),
    permissionsSupported: Boolean(stats.permissionsSupported),
    capped: Boolean(stats.capped)
  };
}

function normalizeFinding(finding = {}, index) {
  return {
    id: redactValues(finding.id, `finding-${index + 1}`),
    severity: safeSeverity(finding.severity),
    category: redactValues(finding.category, "scan"),
    title: redactValues(finding.title, "Untitled finding"),
    detail: redactValues(finding.detail, "No additional detail was recorded."),
    path: redactValues(finding.path, "unknown path"),
    agent: redactValues(finding.agent, "unknown"),
    agentLabel: redactValues(finding.agentLabel, "Unknown agent")
  };
}

function normalizeReport(input = {}) {
  const findings = Array.isArray(input.findings)
    ? input.findings.map(normalizeFinding)
    : [];
  const severityCounts = Object.fromEntries(
    SEVERITIES.map(severity => [
      severity,
      findings.filter(finding => finding.severity === severity).length
    ])
  );
  const score = clamp(Math.round(finiteNumber(input.score)), 0, 100);
  const pathsRedacted = input.pathsRedacted !== false;

  return {
    schemaVersion: integer(input.schemaVersion, 1),
    generatedAt: redactValues(input.generatedAt, new Date().toISOString()),
    home: redactValues(input.home, "~"),
    pathsRedacted,
    guarantee: pathsRedacted ? GUARANTEE : RAW_PATH_WARNING,
    score,
    risk: riskFromScore(score),
    stats: normalizeStats(input.stats),
    severityCounts,
    agents: Array.isArray(input.agents)
      ? input.agents.map((agent, index) => ({
          id: redactValues(agent.id, `agent-${index + 1}`),
          label: redactValues(agent.label, `Agent ${index + 1}`),
          color: safeColor(agent.color),
          path: redactValues(agent.path, "unknown path")
        }))
      : [],
    findings,
    secretOccurrences: Array.isArray(input.secretOccurrences)
      ? input.secretOccurrences.map(occurrence => ({
          agent: redactValues(occurrence.agent, "unknown"),
          agentLabel: redactValues(occurrence.agentLabel, "Unknown agent"),
          type: redactValues(occurrence.type, "Secret"),
          fingerprint: safeFingerprint(occurrence.fingerprint),
          path: redactValues(occurrence.path, "unknown path"),
          line: integer(occurrence.line)
        }))
      : [],
    duplicateSecrets: Array.isArray(input.duplicateSecrets)
      ? input.duplicateSecrets.map(duplicate => ({
          fingerprint: safeFingerprint(duplicate.fingerprint),
          type: redactValues(duplicate.type, "Secret"),
          files: Array.isArray(duplicate.files)
            ? duplicate.files.map(file => redactValues(file, "unknown path"))
            : [],
          agents: Array.isArray(duplicate.agents)
            ? duplicate.agents.map(agent => redactValues(agent, "Unknown agent"))
            : []
        }))
      : []
  };
}

function formatNumber(value) {
  return integer(value).toLocaleString("en-US");
}

function formatBytes(value) {
  const bytes = integer(value);
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = bytes / 1024;
  let unit = units[0];
  for (let index = 1; size >= 1024 && index < units.length; index += 1) {
    size /= 1024;
    unit = units[index];
  }
  return `${size >= 10 ? size.toFixed(0) : size.toFixed(1)} ${unit}`;
}

function formatTimestamp(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown time";
  return date.toISOString().replace("T", " ").replace(".000Z", " UTC");
}

function severityCards(report) {
  return SEVERITIES.map((severity, index) => `
    <article class="severity-card severity-card--${severity}" style="--delay:${index * 70}ms">
      <span class="severity-card__label">${SEVERITY_LABELS[severity]}</span>
      <strong>${formatNumber(report.severityCounts[severity])}</strong>
      <span class="severity-card__rule"></span>
    </article>`).join("");
}

function exposureAgents(report) {
  const agents = new Map(report.agents.map(agent => [agent.id, agent]));
  for (const finding of report.findings) {
    if (!agents.has(finding.agent)) {
      agents.set(finding.agent, {
        id: finding.agent,
        label: finding.agentLabel,
        color: "#e27650",
        path: "unlisted root"
      });
    }
  }
  return [...agents.values()];
}

function exposureMap(report) {
  const agents = exposureAgents(report);
  const exposure = agents.map(agent => {
    const findings = report.findings.filter(finding => finding.agent === agent.id);
    const fingerprints = report.secretOccurrences.filter(occurrence => occurrence.agent === agent.id);
    return { ...agent, findings: findings.length, fingerprints: fingerprints.length };
  });
  const maximum = Math.max(1, ...exposure.map(agent => agent.findings + agent.fingerprints * 2));

  if (exposure.length === 0) {
    return `<div class="map-empty">No agent roots were discovered during this scan.</div>`;
  }

  return exposure.map((agent, index) => {
    const signal = agent.findings + agent.fingerprints * 2;
    const width = signal === 0 ? 6 : clamp(Math.round((signal / maximum) * 100), 12, 100);
    return `
      <article class="agent-row" style="--agent:${agent.color};--delay:${index * 85}ms">
        <div class="agent-row__head">
          <span class="agent-row__node"></span>
          <div>
            <strong>${escapeHtml(agent.label)}</strong>
            <small>${escapeHtml(agent.path)}</small>
          </div>
          <span class="agent-row__total">${formatNumber(agent.findings)}</span>
        </div>
        <div class="agent-row__track"><i style="width:${width}%"></i></div>
        <div class="agent-row__meta">
          <span>${formatNumber(agent.findings)} findings</span>
          <span>${formatNumber(agent.fingerprints)} fingerprints</span>
        </div>
      </article>`;
  }).join("");
}

function duplicateCards(report) {
  if (report.duplicateSecrets.length === 0) {
    return `
      <div class="empty-state">
        <strong>No duplicate fingerprints.</strong>
        <span>No redacted fingerprint appeared across multiple files.</span>
      </div>`;
  }

  return report.duplicateSecrets.map(duplicate => `
    <article class="duplicate-card">
      <div class="duplicate-card__top">
        <span>${escapeHtml(duplicate.type)}</span>
        <code>${escapeHtml(duplicate.fingerprint)}</code>
      </div>
      <div class="duplicate-card__route">
        ${duplicate.agents.map(agent => `<b>${escapeHtml(agent)}</b>`).join("<i>to</i>")}
      </div>
      <p>${formatNumber(duplicate.files.length)} files carry this value-hidden fingerprint.</p>
      <ul>${duplicate.files.map(file => `<li>${escapeHtml(file)}</li>`).join("")}</ul>
    </article>`).join("");
}

function findingRows(report) {
  if (report.findings.length === 0) return "";

  return report.findings.map(finding => {
    const searchText = [
      finding.severity,
      finding.category,
      finding.title,
      finding.detail,
      finding.path,
      finding.agentLabel
    ].join(" ").toLowerCase();
    return `
      <tr data-finding-row data-severity="${escapeHtml(finding.severity)}" data-category="${escapeHtml(finding.category)}" data-search="${escapeHtml(searchText)}">
        <td><span class="severity-dot severity-dot--${finding.severity}"></span><b>${escapeHtml(SEVERITY_LABELS[finding.severity])}</b></td>
        <td><span class="category-tag">${escapeHtml(finding.category)}</span></td>
        <td>
          <strong>${escapeHtml(finding.title)}</strong>
          <p>${escapeHtml(finding.detail)}</p>
        </td>
        <td>
          <span class="agent-inline">${escapeHtml(finding.agentLabel)}</span>
          <code>${escapeHtml(finding.path)}</code>
        </td>
      </tr>`;
  }).join("");
}

function categoryOptions(report) {
  const categories = [...new Set(report.findings.map(finding => finding.category))].sort();
  return categories
    .map(category => `<option value="${escapeHtml(category)}">${escapeHtml(category)}</option>`)
    .join("");
}

function stat(label, value, note = "") {
  return `
    <div class="scan-stat">
      <span>${escapeHtml(label)}</span>
      <b>${escapeHtml(value)}</b>
      ${note ? `<small>${escapeHtml(note)}</small>` : ""}
    </div>`;
}

/**
 * Create a portable HTML report. Only the scanner's redacted report fields are
 * retained, so unknown caller-supplied properties cannot leak into the file.
 */
export function renderHtmlReport(input) {
  const report = normalizeReport(input);
  const categories = categoryOptions(report);
  const timestamp = formatTimestamp(report.generatedAt);
  const hiddenValues = report.secretOccurrences.length;
  const scoreRotation = report.score * 3.6;

  return `<!doctype html>
<html lang="en" data-schema-version="${report.schemaVersion}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>AgentHusk // value-hidden forensic report</title>
  <style>
    :root {
      color-scheme: light;
      --paper: #f3ead8;
      --paper-deep: #e8d8bd;
      --paper-light: #fff9ed;
      --ink: #171713;
      --muted: #776f61;
      --faint: rgba(23, 23, 19, .12);
      --coral: #ed6a4d;
      --coral-deep: #bd4a35;
      --amber: #f3b63f;
      --olive: #798149;
      --sky: #6097a6;
      --shadow: 0 18px 48px rgba(70, 45, 24, .14);
      font-family: Georgia, "Times New Roman", serif;
      background: var(--paper);
      color: var(--ink);
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      min-width: 320px;
      margin: 0;
      background:
        linear-gradient(90deg, rgba(237, 106, 77, .08), transparent 24%, transparent 76%, rgba(243, 182, 63, .1)),
        radial-gradient(circle at 15% 4%, rgba(255, 249, 237, .96), transparent 23rem),
        var(--paper);
    }
    body::before {
      position: fixed;
      inset: 0;
      z-index: -2;
      content: "";
      background-image:
        linear-gradient(rgba(23, 23, 19, .045) 1px, transparent 1px),
        linear-gradient(90deg, rgba(23, 23, 19, .045) 1px, transparent 1px);
      background-size: 32px 32px;
      mask-image: linear-gradient(to bottom, rgba(0,0,0,.7), rgba(0,0,0,.12));
    }
    .paper-noise {
      position: fixed;
      inset: 0;
      z-index: -1;
      width: 100%;
      height: 100%;
      opacity: .2;
      pointer-events: none;
      mix-blend-mode: multiply;
    }
    .shell { width: min(1420px, calc(100% - 40px)); margin: 0 auto; }
    .mono, code, button, select, input, .eyebrow, .privacy-stamp, .brand small, .scan-stat span, .scan-stat small,
    .severity-card__label, .agent-row__meta, .section-kicker, th, .result-count, .footer-note {
      font-family: "Courier New", Courier, monospace;
    }
    .masthead {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
      padding: 24px 0 18px;
      border-bottom: 2px solid var(--ink);
    }
    .brand { display: flex; align-items: baseline; gap: 13px; letter-spacing: -.06em; }
    .brand b { font-size: clamp(2rem, 4vw, 3.55rem); line-height: .8; }
    .brand b::first-letter { color: var(--coral); }
    .brand small { color: var(--muted); font-size: .62rem; font-weight: 700; letter-spacing: .16em; }
    .privacy-stamp {
      padding: 8px 11px 7px;
      border: 1px solid var(--coral-deep);
      color: var(--coral-deep);
      font-size: .62rem;
      font-weight: 700;
      letter-spacing: .14em;
      text-transform: uppercase;
      transform: rotate(-1deg);
    }
    .hero {
      display: grid;
      grid-template-columns: 1.34fr .66fr;
      gap: 28px;
      padding: 72px 0 34px;
    }
    .eyebrow, .section-kicker {
      display: flex;
      align-items: center;
      gap: 9px;
      color: var(--coral-deep);
      font-size: .67rem;
      font-weight: 700;
      letter-spacing: .16em;
      text-transform: uppercase;
    }
    .eyebrow::before, .section-kicker::before { width: 35px; height: 2px; content: ""; background: currentColor; }
    h1 {
      max-width: 860px;
      margin: 14px 0 18px;
      font-size: clamp(4.8rem, 11vw, 10rem);
      font-weight: 700;
      letter-spacing: -.105em;
      line-height: .8;
    }
    h1 em { color: var(--coral); font-style: italic; font-weight: 400; }
    .hero-copy {
      max-width: 760px;
      margin: 0;
      color: #514b41;
      font-size: clamp(1rem, 1.8vw, 1.35rem);
      line-height: 1.5;
    }
    .guarantee {
      display: flex;
      gap: 12px;
      max-width: 760px;
      margin-top: 28px;
      padding: 15px 17px;
      border: 1px solid var(--ink);
      background: rgba(255, 249, 237, .62);
      box-shadow: 6px 6px 0 var(--amber);
      font-size: .88rem;
      line-height: 1.45;
    }
    .guarantee b { flex: none; color: var(--coral-deep); font-family: "Courier New", Courier, monospace; font-size: .68rem; letter-spacing: .1em; text-transform: uppercase; }
    .score-card {
      position: relative;
      align-self: end;
      min-height: 335px;
      overflow: hidden;
      padding: 24px;
      border: 2px solid var(--ink);
      background: var(--ink);
      color: var(--paper-light);
      box-shadow: 11px 11px 0 var(--coral);
    }
    .score-card::after {
      position: absolute;
      right: -68px;
      bottom: -94px;
      width: 230px;
      height: 230px;
      border: 1px solid rgba(243, 182, 63, .25);
      border-radius: 50%;
      content: "";
      box-shadow: 0 0 0 28px rgba(243, 182, 63, .06), 0 0 0 55px rgba(243, 182, 63, .035);
    }
    .score-head { display: flex; justify-content: space-between; gap: 12px; color: var(--amber); font-family: "Courier New", Courier, monospace; font-size: .67rem; font-weight: 700; letter-spacing: .13em; text-transform: uppercase; }
    .score-ring {
      display: grid;
      width: 196px;
      height: 196px;
      margin: 20px auto 8px;
      border-radius: 50%;
      background: conic-gradient(var(--coral) ${scoreRotation}deg, rgba(255,255,255,.12) 0);
      place-items: center;
    }
    .score-ring::before { width: 152px; height: 152px; border: 1px solid rgba(255,255,255,.15); border-radius: inherit; background: var(--ink); content: ""; grid-area: 1 / 1; }
    .score-value { z-index: 1; grid-area: 1 / 1; font-size: 5.1rem; font-weight: 700; letter-spacing: -.11em; line-height: 1; transform: translateX(-.08em); }
    .score-foot { position: relative; z-index: 1; display: flex; justify-content: space-between; border-top: 1px solid rgba(255,255,255,.22); padding-top: 12px; font-family: "Courier New", Courier, monospace; font-size: .68rem; letter-spacing: .1em; text-transform: uppercase; }
    .score-foot b { color: var(--coral); }
    .stat-strip {
      display: grid;
      grid-template-columns: repeat(7, 1fr);
      margin: 18px 0 52px;
      border-block: 1px solid var(--ink);
    }
    .scan-stat { min-width: 0; padding: 15px 14px 13px; border-right: 1px solid var(--faint); }
    .scan-stat:last-child { border-right: 0; }
    .scan-stat span, .scan-stat small { display: block; overflow: hidden; color: var(--muted); font-size: .61rem; letter-spacing: .08em; text-overflow: ellipsis; text-transform: uppercase; white-space: nowrap; }
    .scan-stat b { display: block; margin: 7px 0 5px; font-size: 1.8rem; letter-spacing: -.07em; }
    .section { padding: 28px 0 52px; }
    .section-head { display: flex; align-items: end; justify-content: space-between; gap: 20px; margin-bottom: 22px; }
    h2 { max-width: 800px; margin: 7px 0 0; font-size: clamp(2.25rem, 5vw, 4.45rem); letter-spacing: -.075em; line-height: .96; }
    .section-note { max-width: 390px; margin: 0; color: var(--muted); font-size: .88rem; line-height: 1.45; }
    .severity-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; }
    .severity-card {
      position: relative;
      min-height: 166px;
      padding: 15px;
      border: 1px solid var(--ink);
      background: rgba(255, 249, 237, .72);
      box-shadow: 4px 4px 0 rgba(23, 23, 19, .14);
      animation: lift .55s both;
      animation-delay: var(--delay);
    }
    .severity-card::before { position: absolute; inset: 0 0 auto; height: 5px; content: ""; background: var(--tone); }
    .severity-card--critical { --tone: var(--coral-deep); }
    .severity-card--high { --tone: var(--coral); }
    .severity-card--medium { --tone: var(--amber); }
    .severity-card--low { --tone: var(--olive); }
    .severity-card--info { --tone: var(--sky); }
    .severity-card__label { color: var(--muted); font-size: .65rem; font-weight: 700; letter-spacing: .13em; text-transform: uppercase; }
    .severity-card strong { display: block; margin-top: 17px; font-size: 4.7rem; letter-spacing: -.12em; line-height: .9; }
    .severity-card__rule { position: absolute; right: 15px; bottom: 15px; left: 15px; height: 8px; background: repeating-linear-gradient(90deg, var(--tone), var(--tone) 6px, transparent 6px, transparent 11px); opacity: .8; }
    .map-layout { display: grid; grid-template-columns: .74fr 1.26fr; overflow: hidden; border: 2px solid var(--ink); background: rgba(255, 249, 237, .7); box-shadow: var(--shadow); }
    .map-intro { display: flex; min-height: 420px; flex-direction: column; justify-content: space-between; padding: 25px; background: var(--ink); color: var(--paper-light); }
    .map-intro h3 { max-width: 390px; margin: 20px 0; color: var(--amber); font-size: clamp(2.5rem, 5vw, 4.55rem); letter-spacing: -.09em; line-height: .9; }
    .map-intro p { max-width: 430px; margin: 0; color: #cfc4b0; font-size: .88rem; line-height: 1.55; }
    .map-legend { display: flex; gap: 19px; padding-top: 18px; border-top: 1px solid rgba(255,255,255,.2); color: #cfc4b0; font-family: "Courier New", Courier, monospace; font-size: .62rem; letter-spacing: .08em; text-transform: uppercase; }
    .map-board { display: grid; gap: 1px; padding: 15px; background-image: radial-gradient(rgba(23,23,19,.16) 1px, transparent 1px); background-size: 12px 12px; }
    .agent-row { padding: 13px 15px; border: 1px solid rgba(23,23,19,.18); background: rgba(255, 249, 237, .9); animation: lift .55s both; animation-delay: var(--delay); }
    .agent-row__head { display: grid; grid-template-columns: 15px 1fr auto; align-items: center; gap: 10px; }
    .agent-row__node { width: 12px; height: 12px; border-radius: 50%; background: var(--agent); box-shadow: 0 0 0 4px color-mix(in srgb, var(--agent), transparent 75%); }
    .agent-row strong, .agent-row small { display: block; }
    .agent-row strong { font-size: 1.02rem; }
    .agent-row small { overflow: hidden; max-width: 330px; color: var(--muted); font-family: "Courier New", Courier, monospace; font-size: .62rem; text-overflow: ellipsis; white-space: nowrap; }
    .agent-row__total { font-size: 2rem; font-weight: 700; letter-spacing: -.08em; }
    .agent-row__track { height: 8px; margin: 10px 0 8px; overflow: hidden; background: rgba(23,23,19,.1); }
    .agent-row__track i { display: block; height: 100%; background: var(--agent); }
    .agent-row__meta { display: flex; gap: 16px; color: var(--muted); font-size: .6rem; letter-spacing: .06em; text-transform: uppercase; }
    .map-empty { display: grid; min-height: 280px; padding: 30px; color: var(--muted); font-style: italic; place-items: center; }
    .duplicate-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
    .duplicate-card, .empty-state { padding: 18px; border: 1px solid var(--ink); background: rgba(255, 249, 237, .76); box-shadow: 5px 5px 0 var(--amber); }
    .duplicate-card__top { display: flex; align-items: center; justify-content: space-between; gap: 14px; color: var(--coral-deep); font-size: 1.1rem; font-weight: 700; }
    code { font-size: .69rem; }
    .duplicate-card code { padding: 4px 7px; border: 1px solid var(--ink); background: var(--ink); color: var(--amber); }
    .duplicate-card__route { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 23px 0 14px; }
    .duplicate-card__route b { padding: 5px 8px; border: 1px solid var(--coral-deep); color: var(--coral-deep); font-family: "Courier New", Courier, monospace; font-size: .63rem; letter-spacing: .06em; text-transform: uppercase; }
    .duplicate-card__route i { color: var(--muted); font-size: .72rem; }
    .duplicate-card p, .duplicate-card li, .empty-state span { color: var(--muted); font-size: .82rem; line-height: 1.45; }
    .duplicate-card ul { margin: 12px 0 0; padding-left: 17px; }
    .empty-state { display: flex; min-height: 130px; flex-direction: column; gap: 8px; justify-content: center; }
    .findings-section { margin-top: 26px; padding: 28px 0 68px; border-top: 2px solid var(--ink); }
    .filter-bar {
      display: grid;
      grid-template-columns: auto minmax(180px, 1fr) 170px auto;
      gap: 9px;
      align-items: center;
      margin: 20px 0 12px;
    }
    .filter-buttons { display: flex; flex-wrap: wrap; gap: 5px; }
    button, select, input {
      min-height: 38px;
      border: 1px solid var(--ink);
      border-radius: 0;
      background: rgba(255,249,237,.78);
      color: var(--ink);
      font-size: .68rem;
    }
    button { padding: 0 10px; cursor: pointer; letter-spacing: .04em; text-transform: uppercase; }
    button:hover, button.is-active { background: var(--ink); color: var(--paper-light); }
    select, input { width: 100%; padding: 0 10px; }
    .result-count { color: var(--muted); font-size: .63rem; letter-spacing: .04em; text-align: right; text-transform: uppercase; white-space: nowrap; }
    .table-wrap { overflow-x: auto; border: 1px solid var(--ink); box-shadow: var(--shadow); }
    table { width: 100%; min-width: 920px; border-collapse: collapse; background: rgba(255, 249, 237, .82); }
    th { padding: 11px 12px; border-bottom: 2px solid var(--ink); background: var(--ink); color: var(--paper-light); font-size: .62rem; letter-spacing: .1em; text-align: left; text-transform: uppercase; }
    td { padding: 13px 12px; border-bottom: 1px solid var(--faint); font-size: .82rem; vertical-align: top; }
    tr:last-child td { border-bottom: 0; }
    td:first-child { white-space: nowrap; }
    td p { max-width: 620px; margin: 4px 0 0; color: var(--muted); font-size: .78rem; line-height: 1.45; }
    td code { display: block; max-width: 350px; margin-top: 5px; overflow-wrap: anywhere; color: var(--muted); }
    .severity-dot { display: inline-block; width: 9px; height: 9px; margin-right: 7px; border-radius: 50%; background: var(--tone); }
    .severity-dot--critical { --tone: var(--coral-deep); }
    .severity-dot--high { --tone: var(--coral); }
    .severity-dot--medium { --tone: var(--amber); }
    .severity-dot--low { --tone: var(--olive); }
    .severity-dot--info { --tone: var(--sky); }
    .category-tag, .agent-inline { display: inline-block; font-family: "Courier New", Courier, monospace; font-size: .61rem; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; }
    .category-tag { padding: 3px 6px; border: 1px solid rgba(23,23,19,.3); }
    .agent-inline { color: var(--coral-deep); }
    .table-empty { padding: 32px; border: 1px solid var(--ink); color: var(--muted); background: rgba(255, 249, 237, .78); font-style: italic; text-align: center; }
    footer { display: flex; justify-content: space-between; gap: 20px; padding: 19px 0 25px; border-top: 2px solid var(--ink); }
    .footer-note { color: var(--muted); font-size: .61rem; letter-spacing: .07em; line-height: 1.5; text-transform: uppercase; }
    .footer-note strong { color: var(--coral-deep); }
    @keyframes lift {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @media (prefers-reduced-motion: reduce) {
      html { scroll-behavior: auto; }
      .severity-card, .agent-row { animation: none; }
    }
    @media (max-width: 900px) {
      .hero { grid-template-columns: 1fr; padding-top: 50px; }
      .score-card { width: min(100%, 420px); }
      .stat-strip { grid-template-columns: repeat(3, 1fr); }
      .severity-grid { grid-template-columns: repeat(3, 1fr); }
      .map-layout { grid-template-columns: 1fr; }
      .map-intro { min-height: 270px; }
      .filter-bar { grid-template-columns: 1fr 1fr; }
      .filter-buttons { grid-column: 1 / -1; }
      .result-count { text-align: left; }
    }
    @media (max-width: 600px) {
      .shell { width: min(100% - 24px, 1420px); }
      .masthead { align-items: start; flex-direction: column; }
      .brand b { font-size: 2.65rem; }
      .brand small { display: none; }
      h1 { font-size: clamp(4.2rem, 22vw, 7.2rem); }
      .guarantee { align-items: start; flex-direction: column; }
      .stat-strip { grid-template-columns: repeat(2, 1fr); }
      .severity-grid { grid-template-columns: repeat(2, 1fr); }
      .severity-card:last-child { grid-column: 1 / -1; }
      .section-head { align-items: start; flex-direction: column; }
      .duplicate-grid { grid-template-columns: 1fr; }
      .filter-bar { grid-template-columns: 1fr; }
      footer { flex-direction: column; }
    }
  </style>
</head>
<body>
  <svg class="paper-noise" aria-hidden="true">
    <filter id="paper-grain">
      <feTurbulence baseFrequency=".78" numOctaves="3" seed="17" stitchTiles="stitch"></feTurbulence>
      <feColorMatrix type="saturate" values="0"></feColorMatrix>
    </filter>
    <rect width="100%" height="100%" filter="url(#paper-grain)"></rect>
  </svg>

  <header class="shell masthead">
    <div class="brand"><b>agenthusk</b><small>LOCAL-FIRST AGENT FORENSICS</small></div>
    <div class="privacy-stamp">${report.pathsRedacted ? "paths anonymized" : "unsafe raw paths"} / no external calls</div>
  </header>

  <main class="shell">
    <section class="hero">
      <div>
        <div class="eyebrow">Forensic residue report // ${escapeHtml(timestamp)}</div>
        <h1>Residue leaves an <em>agent husk.</em></h1>
        <p class="hero-copy">${formatNumber(report.findings.length)} local findings form the review queue. Coverage cap: <b>${report.stats.capped ? "reached" : "not hit"}</b> after ${formatNumber(report.stats.filesVisited)} files visited and ${formatNumber(report.stats.textFilesInspected)} text files inspected. The risk signal supports triage; it is not proof of compromise.</p>
        <div class="guarantee">
          <b>${report.pathsRedacted ? "Default disclosure boundary" : "Private report warning"}</b>
          <span>${escapeHtml(report.guarantee)}</span>
        </div>
      </div>
      <aside class="score-card">
        <div class="score-head"><span>Risk signal</span><span>triage / 100</span></div>
        <div class="score-ring"><span class="score-value">${report.score}</span></div>
        <div class="score-foot"><span>Signal, not proof</span><b>${escapeHtml(report.risk)} band</b></div>
      </aside>
    </section>

    <section class="stat-strip" aria-label="Scan statistics">
      ${stat("Finding evidence", formatNumber(report.findings.length), "local signals")}
      ${stat("Coverage cap", report.stats.capped ? "REACHED" : "NOT HIT", `${formatNumber(report.stats.filesVisited)} files visited`)}
      ${stat("Files visited", formatNumber(report.stats.filesVisited))}
      ${stat("Text inspected", formatNumber(report.stats.textFilesInspected))}
      ${stat("Data traversed", formatBytes(report.stats.bytesVisited))}
      ${stat("Agent roots", formatNumber(report.agents.length), `${report.stats.rootsMissing} absent / ${report.stats.rootsSkippedUnsafe} unsafe`)}
      ${stat("Hidden fingerprints", formatNumber(hiddenValues))}
    </section>

    <section class="section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Severity ledger</span>
          <h2>Signals, weighted by urgency.</h2>
        </div>
        <p class="section-note">Counts summarize redacted metadata only. Findings identify where to inspect locally without copying credential values into this report.</p>
      </div>
      <div class="severity-grid">${severityCards(report)}</div>
    </section>

    <section class="section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Agent exposure map</span>
          <h2>Residue clusters around tools.</h2>
        </div>
        <p class="section-note">Each lane combines local findings with value-hidden fingerprints. Longer bars indicate a denser review queue.</p>
      </div>
      <div class="map-layout">
        <div class="map-intro">
          <span class="section-kicker">Local surface</span>
          <h3>${formatNumber(report.agents.length)} roots.<br>${formatNumber(report.findings.length)} signals.</h3>
          <p>Agent storage can preserve transcripts, copied environment files, shell history, and server configuration long after a task ends.</p>
          <div class="map-legend"><span>dot / agent</span><span>bar / exposure</span></div>
        </div>
        <div class="map-board">${exposureMap(report)}</div>
      </div>
    </section>

    <section class="section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Duplicate fingerprints</span>
          <h2>One trace. Multiple surfaces.</h2>
        </div>
        <p class="section-note">A duplicate means the same HMAC fingerprint appeared in more than one file. The underlying secret value remains excluded.</p>
      </div>
      <div class="duplicate-grid">${duplicateCards(report)}</div>
    </section>

    <section class="findings-section">
      <div class="section-head">
        <div>
          <span class="section-kicker">Finding index</span>
          <h2>Review the local trail.</h2>
        </div>
        <p class="section-note">Filter in place. The controls operate only on rows embedded in this HTML file and never transmit data.</p>
      </div>
      <div class="filter-bar">
        <div class="filter-buttons" role="group" aria-label="Filter findings by severity">
          <button class="is-active" type="button" data-severity-filter="all">All</button>
          ${SEVERITIES.map(severity => `<button type="button" data-severity-filter="${severity}">${SEVERITY_LABELS[severity]} ${report.severityCounts[severity]}</button>`).join("")}
        </div>
        <input type="search" data-search-input placeholder="Search title, path, agent..." aria-label="Search findings">
        <select data-category-filter aria-label="Filter findings by category">
          <option value="all">All categories</option>
          ${categories}
        </select>
        <span class="result-count" data-result-count>${formatNumber(report.findings.length)} / ${formatNumber(report.findings.length)} findings</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Severity</th><th>Category</th><th>Signal</th><th>Local surface</th></tr></thead>
          <tbody>${findingRows(report)}</tbody>
        </table>
      </div>
      <div class="table-empty" data-filter-empty ${report.findings.length === 0 ? "" : "hidden"}>No findings match the current local filter.</div>
    </section>
  </main>

  <footer class="shell">
    <span class="footer-note"><strong>${report.pathsRedacted ? "Default disclosure boundary" : "Private report warning"}:</strong> ${escapeHtml(report.guarantee)}</span>
    <span class="footer-note">AgentHusk schema ${report.schemaVersion} // generated ${escapeHtml(timestamp)} // portable offline artifact</span>
  </footer>

  <script id="agenthusk-report-data" type="application/json">${safeJson(report)}</script>
  <script>
    (() => {
      const embeddedReport = JSON.parse(document.getElementById("agenthusk-report-data").textContent);
      const rows = [...document.querySelectorAll("[data-finding-row]")];
      const buttons = [...document.querySelectorAll("[data-severity-filter]")];
      const search = document.querySelector("[data-search-input]");
      const category = document.querySelector("[data-category-filter]");
      const count = document.querySelector("[data-result-count]");
      const empty = document.querySelector("[data-filter-empty]");
      let severity = "all";

      document.documentElement.dataset.schemaVersion = embeddedReport.schemaVersion;

      function applyFilters() {
        const needle = search.value.trim().toLowerCase();
        let visible = 0;
        for (const row of rows) {
          const include = (severity === "all" || row.dataset.severity === severity)
            && (category.value === "all" || row.dataset.category === category.value)
            && (!needle || row.dataset.search.includes(needle));
          row.hidden = !include;
          if (include) visible += 1;
        }
        count.textContent = visible + " / " + rows.length + " findings";
        empty.hidden = visible !== 0;
      }

      for (const button of buttons) {
        button.addEventListener("click", () => {
          severity = button.dataset.severityFilter;
          for (const candidate of buttons) candidate.classList.toggle("is-active", candidate === button);
          applyFilters();
        });
      }
      search.addEventListener("input", applyFilters);
      category.addEventListener("change", applyFilters);
    })();
  </script>
</body>
</html>`;
}

function svgAgentNodes(report) {
  const agents = exposureAgents(report).slice(0, 5);
  if (agents.length === 0) {
    return `<text x="74" y="504" class="map-empty">NO AGENT ROOTS DISCOVERED</text>`;
  }

  return agents.map((agent, index) => {
    const x = 76 + index * 148;
    const findings = report.findings.filter(finding => finding.agent === agent.id).length;
    const radius = clamp(15 + findings * 3, 15, 34);
    return `
      <circle cx="${x}" cy="473" r="${radius + 8}" fill="none" stroke="${agent.color}" stroke-opacity=".25"/>
      <circle cx="${x}" cy="473" r="${radius}" fill="${agent.color}"/>
      <text x="${x}" y="536" class="node-label" text-anchor="middle">${escapeHtml(agent.label)}</text>
      <text x="${x}" y="557" class="node-count" text-anchor="middle">${formatNumber(findings)} SIGNALS</text>`;
  }).join("");
}

/**
 * Create an SVG social card with aggregate metadata only. No paths, findings,
 * or matched secret values are exposed in the shareable image.
 */
export function renderShareCard(input) {
  const report = normalizeReport(input);
  const timestamp = formatTimestamp(report.generatedAt).slice(0, 10);
  const critical = report.severityCounts.critical;
  const high = report.severityCounts.high;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" role="img" aria-labelledby="title desc">
  <title id="title">AgentHusk local-first agent forensic report</title>
  <desc id="desc">A value-hidden scan summary with ${report.findings.length} local findings and a risk signal of ${report.score}. The signal is not proof.</desc>
  <defs>
    <pattern id="grid" width="24" height="24" patternUnits="userSpaceOnUse">
      <path d="M24 0H0V24" fill="none" stroke="#171713" stroke-opacity=".09"/>
    </pattern>
    <filter id="noise">
      <feTurbulence baseFrequency=".8" numOctaves="3" seed="17" stitchTiles="stitch"/>
      <feColorMatrix type="saturate" values="0"/>
      <feComponentTransfer><feFuncA type="table" tableValues="0 .12"/></feComponentTransfer>
    </filter>
    <style>
      .serif { font-family: Georgia, "Times New Roman", serif; }
      .mono { font-family: "Courier New", Courier, monospace; }
      .label { font: 700 12px "Courier New", Courier, monospace; letter-spacing: 2px; fill: #bd4a35; }
      .metric { font: 700 48px Georgia, "Times New Roman", serif; letter-spacing: -4px; fill: #fff9ed; }
      .metric-label { font: 700 10px "Courier New", Courier, monospace; letter-spacing: 1.3px; fill: #776f61; }
      .node-label { font: 700 12px Georgia, "Times New Roman", serif; fill: #171713; }
      .node-count, .map-empty { font: 700 9px "Courier New", Courier, monospace; letter-spacing: 1px; fill: #776f61; }
    </style>
  </defs>
  <rect width="1200" height="630" fill="#f3ead8"/>
  <rect width="1200" height="630" fill="url(#grid)"/>
  <rect width="1200" height="630" filter="url(#noise)" opacity=".65"/>
  <rect x="0" y="0" width="26" height="630" fill="#ed6a4d"/>
  <rect x="1072" y="0" width="128" height="630" fill="#171713"/>
  <rect x="1101" y="0" width="1" height="630" fill="#f3b63f" fill-opacity=".4"/>

  <text x="72" y="79" class="serif" font-size="58" font-weight="700" letter-spacing="-5" fill="#171713">agenthusk</text>
  <text x="76" y="108" class="label">LOCAL-FIRST AGENT FORENSICS // ${escapeHtml(timestamp)}</text>
  <text x="74" y="208" class="serif" font-size="94" font-weight="700" letter-spacing="-8" fill="#171713">Residue leaves</text>
  <text x="74" y="292" class="serif" font-size="94" font-style="italic" letter-spacing="-8" fill="#ed6a4d">an agent husk.</text>
  <text x="76" y="353" class="mono" font-size="15" fill="#514b41">LOCAL SCAN / ${formatNumber(report.findings.length)} FINDINGS / COVERAGE CAP: ${report.stats.capped ? "REACHED" : "NOT HIT"}</text>
  <text x="76" y="378" class="mono" font-size="12" letter-spacing="1" fill="#776f61">${formatNumber(report.stats.filesVisited)} FILES VISITED / ${formatNumber(report.stats.textFilesInspected)} TEXT FILES INSPECTED / VALUE-HIDDEN</text>

  <path d="M74 413H813" stroke="#171713" stroke-width="2"/>
  <text x="74" y="444" class="label">AGENT EXPOSURE MAP / EVIDENCE DENSITY</text>
  ${svgAgentNodes(report)}

  <rect x="840" y="56" width="285" height="518" fill="#171713"/>
  <text x="875" y="100" class="mono" font-size="12" font-weight="700" letter-spacing="2" fill="#f3b63f">RISK SIGNAL / 100</text>
  <text x="875" y="123" class="mono" font-size="10" font-weight="700" letter-spacing="1.4" fill="#cfc4b0">SIGNAL, NOT PROOF</text>
  <circle cx="985" cy="252" r="92" fill="none" stroke="#ffffff" stroke-opacity=".14" stroke-width="18"/>
  <circle cx="985" cy="252" r="92" fill="none" stroke="#ed6a4d" stroke-width="18" pathLength="100" stroke-dasharray="${report.score} 100" transform="rotate(-90 985 252)"/>
  <text x="985" y="279" class="serif" font-size="102" font-weight="700" letter-spacing="-10" text-anchor="middle" fill="#fff9ed">${report.score}</text>
  <text x="985" y="334" class="mono" font-size="12" font-weight="700" letter-spacing="2" text-anchor="middle" fill="#ed6a4d">${escapeHtml(report.risk.toUpperCase())} TRIAGE BAND</text>

  <path d="M874 376H1091" stroke="#ffffff" stroke-opacity=".2"/>
  <text x="875" y="423" class="metric" fill="#fff9ed">${report.findings.length}</text>
  <text x="875" y="446" class="metric-label" fill="#cfc4b0">FINDINGS</text>
  <text x="958" y="423" class="metric" fill="#fff9ed">${critical}</text>
  <text x="958" y="446" class="metric-label" fill="#cfc4b0">CRITICAL</text>
  <text x="1033" y="423" class="metric" fill="#fff9ed">${high}</text>
  <text x="1033" y="446" class="metric-label" fill="#cfc4b0">HIGH</text>
  <rect x="874" y="485" width="218" height="51" fill="#f3b63f"/>
  <text x="983" y="507" class="mono" font-size="10" font-weight="700" letter-spacing="1.4" text-anchor="middle" fill="#171713">VALUE-HIDDEN GUARANTEE</text>
  <text x="983" y="524" class="mono" font-size="9" font-weight="700" letter-spacing=".7" text-anchor="middle" fill="#171713">MATCHED VALUES STAY HIDDEN</text>
</svg>`;
}
