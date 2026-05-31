import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { AGENT_CATALOG, knownRoots } from "./catalog.js";

const SENSITIVE_FILE_PATTERN = /(?:^|[/_.-])(?:\.?env|credentials?|secrets?|tokens?|auth|session|history|logs?|config)(?:$|[/_.-])/i;
const ENV_COPY_PATTERN = /(?:^|[/_.-])\.?env(?:$|[/_.-])/i;
const HISTORY_PATTERN = /(?:bash|zsh|fish|shell)[_.-]?history/i;
const SESSION_PATTERN = /(?:^|[/_.-])(?:sessions?|conversations?|chats?|rollouts?|transcripts?)(?:$|[/_.-])/i;
const MCP_PATTERN = /["']?mcpServers?["']?\s*[:=]/i;
const PLACEHOLDER_PATTERNS = [
  /^(?:example|placeholder|replace[_-]?me|changeme|dummy|redacted)$/i,
  /^your[_-][a-z0-9_-]+$/i,
  /^x{4,}$/i,
  /^<[^>]+>$/,
  /^\$\{[^}]+\}$/
];
const SKIP_DIRECTORIES = new Set([".git", "node_modules", "coverage"]);
const DEFAULT_MAX_FILES = 20_000;
const DEFAULT_MAX_DEPTH = 14;
const DEFAULT_MAX_CONTENT_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_DIRECTORIES = 5_000;
const DEFAULT_MAX_ENTRIES = 100_000;
const DEFAULT_MAX_FINDINGS = 5_000;
const DEFAULT_MAX_OCCURRENCES = 5_000;
const DEFAULT_MAX_OCCURRENCES_PER_FILE = 200;
const FINGERPRINT_LENGTH = 32;

export class ScanUsageError extends Error {}

const SECRET_PATTERNS = [
  {
    type: "Discord webhook",
    regex: /https:\/\/(?:discord|discordapp)\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g
  },
  { type: "GitHub token", regex: /\bgh[pousr]_[A-Za-z0-9_]{30,}\b/g },
  { type: "Anthropic API key", regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { type: "OpenAI-style API key", regex: /\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b/g },
  { type: "Google API key", regex: /\bAIza[A-Za-z0-9_-]{30,}\b/g },
  { type: "AWS access key ID", regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { type: "Slack token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  {
    type: "Bearer token",
    regex: /\bBearer\s+([A-Za-z0-9._~+/=-]{16,})/gi,
    capture: 1
  },
  {
    type: "Assigned secret",
    regex: /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|webhook[_-]?url)\b\s*[:=]\s*["']?([A-Za-z0-9_./+:=@-]{8,})/gi,
    capture: 1
  }
];

function createFingerprinter() {
  const key = crypto.randomBytes(32);
  return value => crypto
    .createHmac("sha256", key)
    .update(value)
    .digest("hex")
    .slice(0, FINGERPRINT_LENGTH);
}

function positiveIntegerOption(value, fallback, label) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected <= 0) {
    throw new ScanUsageError(`${label} must be a positive integer.`);
  }
  return selected;
}

function nonNegativeIntegerOption(value, fallback, label) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 0) {
    throw new ScanUsageError(`${label} must be a non-negative integer.`);
  }
  return selected;
}

function normalizeRelativePath(value) {
  return value.split(path.sep).join("/");
}

function isPlaceholder(value) {
  return PLACEHOLDER_PATTERNS.some(pattern => pattern.test(value));
}

function createNewlineOffsets(content) {
  const offsets = [];
  for (let index = 0; index < content.length; index += 1) {
    if (content.charCodeAt(index) === 10) offsets.push(index);
  }
  return offsets;
}

function lineNumber(newlineOffsets, matchIndex) {
  let left = 0;
  let right = newlineOffsets.length;
  while (left < right) {
    const middle = Math.floor((left + right) / 2);
    if (newlineOffsets[middle] < matchIndex) left = middle + 1;
    else right = middle;
  }
  return left + 1;
}

function redactKnownSecrets(value) {
  let redacted = value;
  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    redacted = redacted.replace(pattern.regex, "<redacted>");
  }
  return redacted;
}

function displayPath(filePath, homeDir, rootPath, redactPaths, pathFingerprint) {
  if (redactPaths) return `<redacted-path:${pathFingerprint(filePath)}>`;
  if (filePath === homeDir) return "~";
  if (filePath.startsWith(`${homeDir}${path.sep}`)) {
    return redactKnownSecrets(`~${path.sep}${path.relative(homeDir, filePath)}`);
  }
  const rootLabel = `<external-root:${pathFingerprint(rootPath ?? filePath).slice(0, 16)}>`;
  if (!rootPath || filePath === rootPath) return rootLabel;
  return redactKnownSecrets(path.join(rootLabel, path.relative(rootPath, filePath)));
}

function detectSecrets(content, filePath, homeDir, agent, fingerprint, display, limit) {
  const occurrences = [];
  const dedupe = new Set();
  const newlineOffsets = createNewlineOffsets(content);
  const publishedPath = display(filePath, homeDir, agent.path);
  let dropped = 0;

  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    for (const match of content.matchAll(pattern.regex)) {
      const value = pattern.capture ? match[pattern.capture] : match[0];
      if (!value || isPlaceholder(value)) continue;
      const secretFingerprint = fingerprint(value);
      const line = lineNumber(newlineOffsets, match.index);
      const key = `${secretFingerprint}:${line}`;
      if (dedupe.has(key)) continue;
      dedupe.add(key);
      if (occurrences.length >= limit) {
        dropped += 1;
        continue;
      }
      occurrences.push({
        agent: agent.id,
        agentLabel: agent.label,
        type: pattern.type,
        fingerprint: secretFingerprint,
        path: publishedPath,
        line
      });
    }
  }

  return { occurrences, dropped };
}

function createFinding({ severity, category, title, detail, filePath, homeDir, agent, display }) {
  return {
    id: crypto.randomUUID(),
    severity,
    category,
    title,
    detail,
    path: display(filePath, homeDir, agent.path),
    agent: agent.id,
    agentLabel: agent.label
  };
}

function severityScore(severity) {
  return { critical: 25, high: 14, medium: 7, low: 3, info: 0 }[severity] ?? 0;
}

function riskScore(findings) {
  const categoryCaps = { secret: 100, permissions: 30, residue: 20, mcp: 10 };
  const categoryScores = new Map();
  for (const finding of findings) {
    const cap = categoryCaps[finding.category] ?? 0;
    if (cap === 0) continue;
    const current = categoryScores.get(finding.category) ?? 0;
    categoryScores.set(finding.category, Math.min(cap, current + severityScore(finding.severity)));
  }
  return Math.min(100, [...categoryScores.values()].reduce((sum, value) => sum + value, 0));
}

function riskLabel(score) {
  if (score >= 75) return "critical";
  if (score >= 45) return "high";
  if (score >= 20) return "guarded";
  return "low";
}

function isProbablyText(buffer) {
  return !buffer.includes(0);
}

function isWithinRoot(candidatePath, rootPath) {
  const relative = path.relative(rootPath, candidatePath);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function hasSymbolicLinkComponent(filePath, anchorPath) {
  const absolutePath = path.resolve(filePath);
  const absoluteAnchor = path.resolve(anchorPath);
  if (!isWithinRoot(absolutePath, absoluteAnchor)) return false;

  const relativeParts = path.relative(absoluteAnchor, absolutePath).split(path.sep).filter(Boolean);
  let currentPath = absoluteAnchor;

  for (const part of relativeParts) {
    currentPath = path.join(currentPath, part);
    try {
      if (fs.lstatSync(currentPath).isSymbolicLink()) return true;
    } catch {
      return false;
    }
  }
  return false;
}

function descriptorPath(fileDescriptor) {
  for (const basePath of ["/proc/self/fd", "/dev/fd"]) {
    const alias = path.join(basePath, String(fileDescriptor));
    try {
      return { alias, realPath: fs.realpathSync.native(alias) };
    } catch {
      // Descriptor aliases are platform-specific. The pre-open check remains as a fallback.
    }
  }
  return null;
}

function readTextSample(filePath, rootRealPath, maxContentBytes, remainingBytes) {
  if (remainingBytes <= 0) return { content: null, bytesRead: 0, reason: "total-bytes" };
  const realPath = fs.realpathSync.native(filePath);
  if (!isWithinRoot(realPath, rootRealPath)) {
    return { content: null, bytesRead: 0, reason: "outside-root" };
  }

  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  const fileDescriptor = fs.openSync(filePath, flags);
  try {
    const openedDescriptor = descriptorPath(fileDescriptor);
    if (openedDescriptor && !isWithinRoot(openedDescriptor.realPath, rootRealPath)) {
      return { content: null, bytesRead: 0, reason: "outside-root" };
    }
    const stat = fs.fstatSync(fileDescriptor);
    if (!stat.isFile()) return { content: null, bytesRead: 0, reason: "not-file" };
    if (stat.size > maxContentBytes) return { content: null, bytesRead: 0, reason: "file-size" };
    if (stat.size > remainingBytes) return { content: null, bytesRead: 0, reason: "total-bytes" };

    const buffer = Buffer.alloc(stat.size);
    let bytesRead = 0;
    while (bytesRead < buffer.length) {
      const count = fs.readSync(fileDescriptor, buffer, bytesRead, buffer.length - bytesRead, bytesRead);
      if (count === 0) break;
      bytesRead += count;
    }
    const sample = buffer.subarray(0, bytesRead);
    return {
      content: isProbablyText(sample) ? sample.toString("utf8") : null,
      bytesRead,
      reason: isProbablyText(sample) ? null : "binary"
    };
  } finally {
    fs.closeSync(fileDescriptor);
  }
}

function mergeRootDescriptors(homeDir, roots) {
  if (!roots?.length) return knownRoots(homeDir);
  return roots.map((rootPath, index) => {
    const absolutePath = path.resolve(rootPath);
    if (absolutePath === path.parse(absolutePath).root) {
      throw new ScanUsageError("Refusing to scan a filesystem root. Select a narrower agent storage directory.");
    }
    const knownAgent = AGENT_CATALOG.find(agent =>
      agent.paths.some(candidate => absolutePath.endsWith(candidate))
    );
    return {
      id: knownAgent?.id ?? `custom-${index + 1}`,
      label: knownAgent?.label ?? `Custom root ${index + 1}`,
      color: knownAgent?.color ?? "#a9b3bd",
      path: absolutePath
    };
  });
}

export function scan(options = {}) {
  const homeDir = path.resolve(options.homeDir ?? os.homedir());
  const maxFiles = positiveIntegerOption(options.maxFiles, DEFAULT_MAX_FILES, "maxFiles");
  const maxDepth = nonNegativeIntegerOption(options.maxDepth, DEFAULT_MAX_DEPTH, "maxDepth");
  const maxContentBytes = positiveIntegerOption(options.maxContentBytes, DEFAULT_MAX_CONTENT_BYTES, "maxContentBytes");
  const maxTotalBytes = positiveIntegerOption(options.maxTotalBytes, DEFAULT_MAX_TOTAL_BYTES, "maxTotalBytes");
  const maxDirectories = positiveIntegerOption(options.maxDirectories, DEFAULT_MAX_DIRECTORIES, "maxDirectories");
  const maxEntries = positiveIntegerOption(options.maxEntries, DEFAULT_MAX_ENTRIES, "maxEntries");
  const maxFindings = positiveIntegerOption(options.maxFindings, DEFAULT_MAX_FINDINGS, "maxFindings");
  const maxOccurrences = positiveIntegerOption(options.maxOccurrences, DEFAULT_MAX_OCCURRENCES, "maxOccurrences");
  const maxOccurrencesPerFile = positiveIntegerOption(
    options.maxOccurrencesPerFile,
    DEFAULT_MAX_OCCURRENCES_PER_FILE,
    "maxOccurrencesPerFile"
  );
  const redactPaths = options.showPaths !== true;
  const explicitRoots = Boolean(options.roots?.length);
  const roots = mergeRootDescriptors(homeDir, options.roots);
  const fingerprint = createFingerprinter();
  const pathFingerprint = createFingerprinter();
  const display = (filePath, baseHomeDir, rootPath) =>
    displayPath(filePath, baseHomeDir, rootPath, redactPaths, pathFingerprint);
  const findings = [];
  const secretOccurrences = [];
  const agents = [];
  const coverageKeys = new Set();
  let stopTraversal = false;
  const stats = {
    filesVisited: 0,
    directoriesVisited: 0,
    entriesVisited: 0,
    bytesVisited: 0,
    bytesRead: 0,
    textFilesInspected: 0,
    binaryFilesSkipped: 0,
    filesSkippedBySize: 0,
    symlinksSkipped: 0,
    rootsMissing: 0,
    rootsSkippedUnsafe: 0,
    depthCapped: 0,
    findingsDropped: 0,
    secretOccurrencesDropped: 0,
    coverageIncomplete: false,
    noFollowSupported: typeof fs.constants.O_NOFOLLOW === "number",
    permissionsSupported: process.platform !== "win32",
    capped: false
  };

  function addFinding(finding) {
    if (findings.length >= maxFindings) {
      stats.findingsDropped += 1;
      stats.coverageIncomplete = true;
      stats.capped = true;
      return;
    }
    findings.push(finding);
  }

  function addCoverageFinding(key, finding) {
    stats.coverageIncomplete = true;
    stats.capped = true;
    if (coverageKeys.has(key)) return;
    coverageKeys.add(key);
    addFinding(finding);
  }

  function finding(details) {
    return createFinding({ ...details, homeDir, display });
  }

  function addPermissionFinding(filePath, agent, mode, sensitiveName, hasSecrets = false) {
    if (!stats.permissionsSupported || (mode & 0o077) === 0 || (!sensitiveName && !hasSecrets)) return;
    addFinding(finding({
      severity: "high",
      category: "permissions",
      title: "Sensitive residue grants access outside its owner account",
      detail: `Mode ${mode.toString(8).padStart(3, "0")} grants group or other permission bits on an agent-related file.`,
      filePath,
      agent
    }));
  }

  function inspectFile(filePath, initialStat, agent, rootRealPath) {
    if (stats.filesVisited >= maxFiles) {
      stopTraversal = true;
      addCoverageFinding("max-files", finding({
        severity: "medium",
        category: "coverage",
        title: "File traversal limit reached",
        detail: `AgentHusk stopped after ${maxFiles} files. Raise --max-files or scan a narrower root.`,
        filePath,
        agent
      }));
      return;
    }
    stats.filesVisited += 1;
    stats.bytesVisited += initialStat.size;

    const relativePath = normalizeRelativePath(path.relative(agent.path, filePath));
    const mode = initialStat.mode & 0o777;
    const sensitiveName = SENSITIVE_FILE_PATTERN.test(relativePath);
    addPermissionFinding(filePath, agent, mode, sensitiveName);

    if (ENV_COPY_PATTERN.test(relativePath)) {
      addFinding(finding({
        severity: "high",
        category: "residue",
        title: "Environment file residue found inside agent storage",
        detail: "Review whether this environment snapshot is still needed. It may contain credentials copied from a workspace.",
        filePath,
        agent
      }));
    } else if (HISTORY_PATTERN.test(relativePath)) {
      addFinding(finding({
        severity: "high",
        category: "residue",
        title: "Shell history residue found inside agent storage",
        detail: "Shell history often contains commands, URLs, tokens, and operational details.",
        filePath,
        agent
      }));
    } else if (SESSION_PATTERN.test(relativePath) && /\.(?:json|jsonl|log|txt)$/i.test(filePath)) {
      addFinding(finding({
        severity: "low",
        category: "residue",
        title: "Agent session transcript stored locally",
        detail: "Session transcripts are expected but should be retained intentionally and protected with owner-only permissions.",
        filePath,
        agent
      }));
    }

    let sample;
    try {
      sample = readTextSample(filePath, rootRealPath, maxContentBytes, maxTotalBytes - stats.bytesRead);
    } catch {
      addCoverageFinding(`read:${filePath}`, finding({
        severity: "info",
        category: "scan",
        title: "File could not be inspected",
        detail: "AgentHusk continued without reading this file. The coverage signal is incomplete.",
        filePath,
        agent
      }));
      return;
    }
    stats.bytesRead += sample.bytesRead;

    if (sample.reason === "file-size") {
      stats.filesSkippedBySize += 1;
      addCoverageFinding(`large:${filePath}`, finding({
        severity: sensitiveName ? "medium" : "info",
        category: "coverage",
        title: "Large file was not content-scanned",
        detail: `File size exceeds the ${(maxContentBytes / 1024 / 1024).toFixed(1)} MiB inspection limit. Increase --max-bytes if this residue needs a deeper scan.`,
        filePath,
        agent
      }));
      return;
    }
    if (sample.reason === "total-bytes") {
      stopTraversal = true;
      addCoverageFinding("max-total-bytes", finding({
        severity: "medium",
        category: "coverage",
        title: "Total content-reading limit reached",
        detail: "AgentHusk stopped content traversal at its bounded total-read limit. Scan a narrower root for deeper coverage.",
        filePath,
        agent
      }));
      return;
    }
    if (sample.reason === "outside-root") {
      addCoverageFinding(`outside-root:${filePath}`, finding({
        severity: "medium",
        category: "coverage",
        title: "Path escaped the selected root and was skipped",
        detail: "AgentHusk refused to follow a path whose resolved target was outside the selected root.",
        filePath,
        agent
      }));
      return;
    }
    if (sample.reason === "binary") {
      stats.binaryFilesSkipped += 1;
      return;
    }
    if (sample.content === null) return;
    stats.textFilesInspected += 1;

    const availableOccurrences = Math.max(0, maxOccurrences - secretOccurrences.length);
    const limit = Math.min(maxOccurrencesPerFile, availableOccurrences);
    const detected = detectSecrets(sample.content, filePath, homeDir, agent, fingerprint, display, limit);
    secretOccurrences.push(...detected.occurrences);
    stats.secretOccurrencesDropped += detected.dropped;
    if (detected.dropped > 0) {
      addCoverageFinding(`occurrences:${filePath}`, finding({
        severity: "medium",
        category: "coverage",
        title: "Secret occurrence reporting limit reached",
        detail: "Additional secret-shaped matches were omitted to keep the local report bounded. Scan a narrower root for complete triage.",
        filePath,
        agent
      }));
    }

    if (!sensitiveName) {
      addPermissionFinding(filePath, agent, mode, sensitiveName, detected.occurrences.length > 0);
    }
    for (const occurrence of detected.occurrences) {
      addFinding(finding({
        severity: "critical",
        category: "secret",
        title: `${occurrence.type} fingerprint found in agent storage`,
        detail: `Matched value hidden. Fingerprint ${occurrence.fingerprint} at line ${occurrence.line}. Rotate the credential if this residue was not expected.`,
        filePath,
        agent
      }));
    }

    if (MCP_PATTERN.test(sample.content)) {
      addFinding(finding({
        severity: "medium",
        category: "mcp",
        title: "MCP server configuration discovered",
        detail: "Review command paths, environment variable references, and trust boundaries before enabling local MCP servers.",
        filePath,
        agent
      }));
    }
  }

  function inspectDirectory(directoryPath, stat, agent) {
    if (!stats.permissionsSupported) return;
    const relativePath = normalizeRelativePath(path.relative(agent.path, directoryPath));
    const mode = stat.mode & 0o777;
    if ((directoryPath === agent.path || SENSITIVE_FILE_PATTERN.test(relativePath)) && (mode & 0o077) !== 0) {
      addFinding(finding({
        severity: "medium",
        category: "permissions",
        title: "Agent storage directory grants access outside its owner account",
        detail: `Mode ${mode.toString(8).padStart(3, "0")} grants group or other permission bits on a residue directory.`,
        filePath: directoryPath,
        agent
      }));
    }
  }

  function walk(directoryPath, depth, agent, rootRealPath) {
    if (stopTraversal) return;
    if (depth > maxDepth) {
      stats.depthCapped += 1;
      addCoverageFinding(`depth:${directoryPath}`, finding({
        severity: "medium",
        category: "coverage",
        title: "Directory depth limit reached",
        detail: `AgentHusk did not descend beyond depth ${maxDepth}. Scan this subtree directly for deeper coverage.`,
        filePath: directoryPath,
        agent
      }));
      return;
    }
    if (stats.directoriesVisited >= maxDirectories) {
      stopTraversal = true;
      addCoverageFinding("max-directories", finding({
        severity: "medium",
        category: "coverage",
        title: "Directory traversal limit reached",
        detail: "AgentHusk stopped at its bounded directory limit. Scan a narrower root for deeper coverage.",
        filePath: directoryPath,
        agent
      }));
      return;
    }

    let directoryDescriptor;
    let directory;
    let directoryFileDescriptor;
    function closeDirectoryHandles() {
      try {
        directory?.closeSync();
      } catch {
        // The directory handle may already be closed after an iteration failure.
      }
      directory = undefined;
      if (directoryFileDescriptor !== undefined) {
        try {
          fs.closeSync(directoryFileDescriptor);
        } catch {
          // The descriptor may already be closed after an open failure.
        }
      }
      directoryFileDescriptor = undefined;
    }
    try {
      const resolvedDirectory = fs.realpathSync.native(directoryPath);
      if (!isWithinRoot(resolvedDirectory, rootRealPath)) {
        addCoverageFinding(`outside-root:${directoryPath}`, finding({
          severity: "medium",
          category: "coverage",
          title: "Directory escaped the selected root and was skipped",
          detail: "AgentHusk refused to traverse a directory whose resolved target was outside the selected root.",
          filePath: directoryPath,
          agent
        }));
        return;
      }
      if (typeof fs.constants.O_DIRECTORY === "number" && typeof fs.constants.O_NOFOLLOW === "number") {
        const flags = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW;
        directoryFileDescriptor = fs.openSync(directoryPath, flags);
        directoryDescriptor = descriptorPath(directoryFileDescriptor);
        if (directoryDescriptor && !isWithinRoot(directoryDescriptor.realPath, rootRealPath)) {
          addCoverageFinding(`outside-root:${directoryPath}`, finding({
            severity: "medium",
            category: "coverage",
            title: "Directory escaped the selected root and was skipped",
            detail: "AgentHusk refused to traverse a directory whose opened descriptor resolved outside the selected root.",
            filePath: directoryPath,
            agent
          }));
          closeDirectoryHandles();
          return;
        }
      }
      directory = fs.opendirSync(directoryDescriptor?.alias ?? directoryPath);
      stats.directoriesVisited += 1;
    } catch {
      closeDirectoryHandles();
      addCoverageFinding(`directory:${directoryPath}`, finding({
        severity: "info",
        category: "scan",
        title: "Directory could not be inspected",
        detail: "AgentHusk continued without reading this directory. The coverage signal is incomplete.",
        filePath: directoryPath,
        agent
      }));
      return;
    }

    try {
      let entry;
      while (!stopTraversal && (entry = directory.readSync()) !== null) {
        stats.entriesVisited += 1;
        if (stats.entriesVisited > maxEntries) {
          stopTraversal = true;
          addCoverageFinding("max-entries", finding({
            severity: "medium",
            category: "coverage",
            title: "Directory entry limit reached",
            detail: "AgentHusk stopped at its bounded directory-entry limit. Scan a narrower root for deeper coverage.",
            filePath: directoryPath,
            agent
          }));
          return;
        }
        const entryPath = path.join(directoryPath, entry.name);
        let stat;
        try {
          stat = fs.lstatSync(entryPath);
        } catch {
          addCoverageFinding(`stat:${entryPath}`, finding({
            severity: "info",
            category: "scan",
            title: "Directory entry metadata could not be inspected",
            detail: "AgentHusk continued without inspecting this entry. The coverage signal is incomplete.",
            filePath: entryPath,
            agent
          }));
          continue;
        }
        if (stat.isSymbolicLink()) {
          stats.symlinksSkipped += 1;
        } else if (stat.isDirectory()) {
          if (SKIP_DIRECTORIES.has(entry.name)) continue;
          inspectDirectory(entryPath, stat, agent);
          walk(entryPath, depth + 1, agent, rootRealPath);
        } else if (stat.isFile()) {
          inspectFile(entryPath, stat, agent, rootRealPath);
        }
      }
    } finally {
      closeDirectoryHandles();
    }
  }

  for (const agent of roots) {
    if (stopTraversal) break;
    let stat;
    let rootRealPath;
    try {
      stat = fs.lstatSync(agent.path);
      if (!stat.isDirectory()) {
        stats.rootsMissing += 1;
        if (explicitRoots) {
          stats.coverageIncomplete = true;
          stats.capped = true;
        }
        continue;
      }
      if (stat.isSymbolicLink() || hasSymbolicLinkComponent(agent.path, homeDir)) {
        stats.rootsSkippedUnsafe += 1;
        stats.coverageIncomplete = true;
        stats.capped = true;
        continue;
      }
      rootRealPath = fs.realpathSync.native(agent.path);
    } catch (error) {
      stats.rootsMissing += 1;
      if (explicitRoots || error?.code !== "ENOENT") {
        stats.coverageIncomplete = true;
        stats.capped = true;
      }
      continue;
    }
    agents.push({
      id: agent.id,
      label: agent.label,
      color: agent.color,
      path: display(agent.path, homeDir, agent.path)
    });
    inspectDirectory(agent.path, stat, agent);
    walk(agent.path, 0, agent, rootRealPath);
  }

  if (explicitRoots && agents.length === 0) {
    throw new ScanUsageError("No explicit scan root could be inspected. Check --root paths and permissions.");
  }

  const duplicateSecrets = [];
  const fingerprintGroups = new Map();
  for (const occurrence of secretOccurrences) {
    const group = fingerprintGroups.get(occurrence.fingerprint) ?? [];
    group.push(occurrence);
    fingerprintGroups.set(occurrence.fingerprint, group);
  }
  for (const [secretFingerprint, occurrences] of fingerprintGroups) {
    const uniqueFiles = [...new Set(occurrences.map(occurrence => occurrence.path))];
    if (uniqueFiles.length < 2) continue;
    duplicateSecrets.push({
      fingerprint: secretFingerprint,
      type: occurrences[0].type,
      files: uniqueFiles,
      agents: [...new Set(occurrences.map(occurrence => occurrence.agentLabel))]
    });
  }

  findings.sort((left, right) => severityScore(right.severity) - severityScore(left.severity));
  const severityCounts = Object.fromEntries(
    ["critical", "high", "medium", "low", "info"].map(severity => [
      severity,
      findings.filter(finding => finding.severity === severity).length
    ])
  );
  const score = riskScore(findings);

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    home: "~",
    pathsRedacted: redactPaths,
    guarantee: "Matched content values are excluded from content-derived report fields. Paths are anonymized by default; review metadata before sharing.",
    score,
    risk: riskLabel(score),
    stats,
    severityCounts,
    agents,
    findings,
    secretOccurrences,
    duplicateSecrets
  };
}
