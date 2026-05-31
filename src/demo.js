export function createDemoReport() {
  const findings = [
    {
      id: "demo-1",
      severity: "critical",
      category: "secret",
      title: "Discord webhook fingerprint found in agent storage",
      detail: "Value hidden. Fingerprint a18f09b4d1 at line 482. Rotate the credential if this residue was not expected.",
      path: "~/.gemini/tmp/chats/session-late-night.json",
      agent: "gemini",
      agentLabel: "Gemini"
    },
    {
      id: "demo-2",
      severity: "critical",
      category: "secret",
      title: "GitHub token fingerprint found in agent storage",
      detail: "Value hidden. Fingerprint 77cf2e0aa4 at line 91. Rotate the credential if this residue was not expected.",
      path: "~/.openclaw/agents/main/sessions/launch.jsonl",
      agent: "openclaw",
      agentLabel: "OpenClaw"
    },
    {
      id: "demo-3",
      severity: "high",
      category: "residue",
      title: "Environment file residue found inside agent storage",
      detail: "Review whether this environment snapshot is still needed. It may contain credentials copied from a workspace.",
      path: "~/.gemini/code_tracker/active/no_repo/7f92_.env",
      agent: "gemini",
      agentLabel: "Gemini"
    },
    {
      id: "demo-4",
      severity: "high",
      category: "permissions",
      title: "Sensitive residue is readable by other local users",
      detail: "Mode 644 exposes an agent-related file outside its owner account.",
      path: "~/.gemini/code_tracker/active/no_repo/7f92_.env",
      agent: "gemini",
      agentLabel: "Gemini"
    },
    {
      id: "demo-5",
      severity: "high",
      category: "residue",
      title: "Shell history residue found inside agent storage",
      detail: "Shell history often contains commands, URLs, tokens, and operational details.",
      path: "~/.openclaw/migration/backups/.bash_history",
      agent: "openclaw",
      agentLabel: "OpenClaw"
    },
    {
      id: "demo-6",
      severity: "medium",
      category: "mcp",
      title: "MCP server configuration discovered",
      detail: "Review command paths, environment variable references, and trust boundaries before enabling local MCP servers.",
      path: "~/.claude/settings.json",
      agent: "claude",
      agentLabel: "Claude Code"
    },
    {
      id: "demo-7",
      severity: "low",
      category: "residue",
      title: "Agent session transcript stored locally",
      detail: "Session transcripts are expected but should be retained intentionally and protected with owner-only permissions.",
      path: "~/.codex/sessions/2026/06/01/rollout.jsonl",
      agent: "codex",
      agentLabel: "Codex"
    }
  ];

  return {
    schemaVersion: 1,
    generatedAt: "2026-06-01T00:00:00.000Z",
    home: "~",
    pathsRedacted: true,
    guarantee: "Matched content values are excluded from content-derived report fields. Paths are anonymized by default; review metadata before sharing.",
    score: 92,
    risk: "critical",
    stats: {
      filesVisited: 1842,
      directoriesVisited: 311,
      bytesVisited: 23840019,
      textFilesInspected: 906,
      filesSkippedBySize: 8,
      symlinksSkipped: 3,
      rootsMissing: 2,
      rootsSkippedUnsafe: 0,
      capped: false
    },
    severityCounts: { critical: 2, high: 3, medium: 1, low: 1, info: 0 },
    agents: [
      { id: "codex", label: "Codex", color: "#f3b63f", path: "~/.codex" },
      { id: "claude", label: "Claude Code", color: "#e27650", path: "~/.claude" },
      { id: "gemini", label: "Gemini", color: "#6fb5ff", path: "~/.gemini" },
      { id: "openclaw", label: "OpenClaw", color: "#e96666", path: "~/.openclaw" }
    ],
    findings,
    secretOccurrences: [
      { agent: "gemini", agentLabel: "Gemini", type: "Discord webhook", fingerprint: "a18f09b4d1", path: "~/.gemini/tmp/chats/session-late-night.json", line: 482 },
      { agent: "openclaw", agentLabel: "OpenClaw", type: "Discord webhook", fingerprint: "a18f09b4d1", path: "~/.openclaw/agents/main/sessions/launch.jsonl", line: 122 },
      { agent: "openclaw", agentLabel: "OpenClaw", type: "GitHub token", fingerprint: "77cf2e0aa4", path: "~/.openclaw/agents/main/sessions/launch.jsonl", line: 91 }
    ],
    duplicateSecrets: [
      {
        fingerprint: "a18f09b4d1",
        type: "Discord webhook",
        files: [
          "~/.gemini/tmp/chats/session-late-night.json",
          "~/.openclaw/agents/main/sessions/launch.jsonl"
        ],
        agents: ["Gemini", "OpenClaw"]
      }
    ]
  };
}
