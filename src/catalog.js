import path from "node:path";

export const AGENT_CATALOG = [
  { id: "codex", label: "Codex", color: "#f3b63f", paths: [".codex"] },
  { id: "claude", label: "Claude Code", color: "#e27650", paths: [".claude"] },
  { id: "gemini", label: "Gemini", color: "#6fb5ff", paths: [".gemini"] },
  { id: "openclaw", label: "OpenClaw", color: "#e96666", paths: [".openclaw"] },
  { id: "hermes", label: "Hermes", color: "#dc8fff", paths: [".hermes"] },
  { id: "cursor", label: "Cursor", color: "#a78bfa", paths: [".cursor"] },
  { id: "windsurf", label: "Windsurf", color: "#4fc3b3", paths: [".windsurf"] },
  {
    id: "opencode",
    label: "OpenCode",
    color: "#5bd2a6",
    paths: [path.join(".config", "opencode")]
  },
  { id: "continue", label: "Continue", color: "#8ad56b", paths: [".continue"] },
  { id: "cline", label: "Cline", color: "#ff8c73", paths: [".cline"] }
];

export function knownRoots(homeDir) {
  return AGENT_CATALOG.flatMap(agent =>
    agent.paths.map(relativePath => ({
      ...agent,
      path: path.join(homeDir, relativePath)
    }))
  );
}
