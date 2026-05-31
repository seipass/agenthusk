import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { scan } from "../src/scanner.js";

function createFixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "agenthusk-scanner-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

test("scan stores fingerprints instead of secret values and finds duplicate residue", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");
  const sessions = path.join(root, "sessions");
  const githubToken = `ghp_${"A".repeat(36)}`;
  const assignedSecret = "correct-horse-battery-staple";

  fs.mkdirSync(sessions, { recursive: true });
  fs.writeFileSync(path.join(sessions, "first.json"), `{"token":"${githubToken}"}`);
  fs.writeFileSync(path.join(sessions, "second.log"), `Bearer ${githubToken}\n`);
  fs.writeFileSync(path.join(root, ".env"), `password=${assignedSecret}\n`, { mode: 0o600 });
  fs.chmodSync(path.join(root, ".env"), 0o644);
  fs.symlinkSync(path.join(sessions, "first.json"), path.join(sessions, "linked.json"));

  const report = scan({ homeDir, roots: [root] });
  const serialized = JSON.stringify(report);
  const githubOccurrences = report.secretOccurrences.filter(
    occurrence => occurrence.type === "GitHub token"
  );

  assert.equal(serialized.includes(githubToken), false);
  assert.equal(serialized.includes(assignedSecret), false);
  assert.equal(githubOccurrences.length, 2);
  assert.match(githubOccurrences[0].fingerprint, /^[a-f0-9]{16,64}$/);
  assert.equal(githubOccurrences[0].fingerprint, githubOccurrences[1].fingerprint);
  assert.deepEqual(report.duplicateSecrets, [{
    fingerprint: githubOccurrences[0].fingerprint,
    type: "GitHub token",
    files: githubOccurrences.map(occurrence => occurrence.path),
    agents: ["Codex"]
  }]);
  assert.equal(report.stats.symlinksSkipped, 1);
  assert.ok(report.findings.some(finding =>
    finding.category === "permissions"
    && finding.detail.startsWith("Mode 644 ")
  ));
});

test("scan anonymizes all published paths by default", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");
  const privateFileName = "customer-project-credentials.txt";

  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, privateFileName), `sk-${"P".repeat(30)}\n`);

  const report = scan({ homeDir, roots: [root] });
  const serialized = JSON.stringify(report);

  assert.equal(report.pathsRedacted, true);
  assert.equal(serialized.includes(privateFileName), false);
  assert.ok(report.agents.every(agent => /^<redacted-path:[a-f0-9]{16,64}>$/.test(agent.path)));
  assert.ok(report.findings.every(finding => /^<redacted-path:[a-f0-9]{16,64}>$/.test(finding.path)));
  assert.ok(report.secretOccurrences.every(occurrence =>
    /^<redacted-path:[a-f0-9]{16,64}>$/.test(occurrence.path)
  ));
});

test("scan publishes local paths only when showPaths is explicitly enabled", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");
  const privateFileName = "customer-project-credentials.txt";

  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, privateFileName), `sk-${"P".repeat(30)}\n`);

  const report = scan({ homeDir, roots: [root], showPaths: true });

  assert.equal(report.pathsRedacted, false);
  assert.equal(report.agents[0].path, "~/.codex");
  assert.ok(report.findings.some(finding => finding.path === `~/.codex/${privateFileName}`));
  assert.equal(report.secretOccurrences[0].path, `~/.codex/${privateFileName}`);
});

test("scan does not reveal the absolute path of an external root when paths are shown", t => {
  const directory = createFixture(t);
  const homeDir = path.join(directory, "home");
  const externalRoot = path.join(directory, "external-root-do-not-publish");

  fs.mkdirSync(homeDir);
  fs.mkdirSync(externalRoot);
  fs.writeFileSync(path.join(externalRoot, "credentials.txt"), `sk-${"Z".repeat(30)}\n`);

  const report = scan({ homeDir, roots: [externalRoot], showPaths: true });
  const serialized = JSON.stringify(report);

  assert.equal(serialized.includes(externalRoot), false);
  assert.match(report.agents[0].path, /^<external-root:[a-f0-9]{16,64}>$/);
  assert.match(report.secretOccurrences[0].path, /^<external-root:[a-f0-9]{16,64}>[/\\]credentials\.txt$/);
});

test("the same value receives unrelated fingerprints in separate scans", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");
  const secret = `sk-${"F".repeat(30)}`;

  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, "credentials.txt"), `${secret}\n`);

  const firstFingerprint = scan({ homeDir, roots: [root] }).secretOccurrences[0].fingerprint;
  const secondFingerprint = scan({ homeDir, roots: [root] }).secretOccurrences[0].fingerprint;

  assert.notEqual(firstFingerprint, secondFingerprint);
});

test("default path IDs hide secret-shaped file names and change across scans", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");
  const secret = `sk-${"K".repeat(30)}`;
  const fileName = `session-${secret}.txt`;

  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, fileName), "local transcript metadata\n");

  const firstReport = scan({ homeDir, roots: [root] });
  const secondReport = scan({ homeDir, roots: [root] });

  assert.equal(JSON.stringify(firstReport).includes(secret), false);
  assert.equal(JSON.stringify(secondReport).includes(secret), false);
  assert.notEqual(firstReport.findings[0].path, secondReport.findings[0].path);
});

test("scan inspects common source extensions such as .js", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");
  const secret = `sk-${"J".repeat(30)}`;

  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, "residue.js"), `export const leaked = "${secret}";\n`);

  const report = scan({ homeDir, roots: [root] });

  assert.ok(report.secretOccurrences.some(occurrence => occurrence.type === "OpenAI-style API key"));
});

test("scan does not discard a valid token merely because it contains a placeholder substring", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");
  const secret = `sk-${"A".repeat(12)}example${"B".repeat(20)}`;

  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, "credentials.txt"), `${secret}\n`);

  const report = scan({ homeDir, roots: [root] });

  assert.equal(report.secretOccurrences.length, 1);
  assert.equal(report.secretOccurrences[0].type, "OpenAI-style API key");
});

test("scan records a coverage finding when maxDepth prevents traversal", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");
  const hiddenDirectory = path.join(root, "one", "two");
  const secret = `sk-${"D".repeat(30)}`;

  fs.mkdirSync(hiddenDirectory, { recursive: true });
  fs.writeFileSync(path.join(hiddenDirectory, "credentials.txt"), `${secret}\n`);

  const report = scan({ homeDir, roots: [root], maxDepth: 0 });

  assert.equal(report.secretOccurrences.length, 0);
  assert.ok(report.findings.some(finding =>
    finding.category === "coverage"
    && /depth/i.test(`${finding.title} ${finding.detail}`)
  ));
});

test("scan reports risky permissions after finding a secret in an ordinary file name", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");

  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, "notes.txt"), `sk-${"N".repeat(30)}\n`, { mode: 0o644 });
  fs.chmodSync(path.join(root, "notes.txt"), 0o644);

  const report = scan({ homeDir, roots: [root] });

  assert.ok(report.findings.some(finding =>
    finding.category === "permissions"
    && finding.detail.startsWith("Mode 644 ")
  ));
});

test("scan does not duplicate a permission finding after inspecting a sensitive file", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");

  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, ".env"), `password=${"S".repeat(30)}\n`, { mode: 0o644 });
  fs.chmodSync(path.join(root, ".env"), 0o644);

  const report = scan({ homeDir, roots: [root], showPaths: true });

  assert.equal(report.findings.filter(finding =>
    finding.category === "permissions"
    && finding.path === "~/.codex/.env"
  ).length, 1);
});

test("default known roots may be absent without reporting a coverage gap", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");

  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, "notes.txt"), "bounded content\n");

  const report = scan({ homeDir });

  assert.equal(report.agents.length, 1);
  assert.equal(report.stats.rootsMissing, 9);
  assert.equal(report.stats.coverageIncomplete, false);
  assert.equal(report.stats.capped, false);
});

test("scan rejects explicit roots when none can be inspected", t => {
  const homeDir = createFixture(t);

  assert.throws(
    () => scan({ homeDir, roots: [path.join(homeDir, "missing")] }),
    /no explicit scan root could be inspected/i
  );
});

test("scan records a coverage gap for a root with a symlinked ancestor", t => {
  const homeDir = createFixture(t);
  const actualRoot = path.join(homeDir, "actual", "agent");
  const linkedParent = path.join(homeDir, "linked");
  const linkedRoot = path.join(linkedParent, "agent");

  fs.mkdirSync(actualRoot, { recursive: true });
  fs.symlinkSync(path.dirname(actualRoot), linkedParent);

  assert.throws(
    () => scan({ homeDir, roots: [linkedRoot] }),
    /no explicit scan root could be inspected/i
  );
});

test("default scan reports a known root skipped for a symlinked ancestor", t => {
  const homeDir = createFixture(t);
  const actualConfig = path.join(homeDir, "actual-config");

  fs.mkdirSync(path.join(actualConfig, "opencode"), { recursive: true });
  fs.symlinkSync(actualConfig, path.join(homeDir, ".config"));

  const report = scan({ homeDir });

  assert.equal(report.agents.length, 0);
  assert.equal(report.stats.rootsSkippedUnsafe, 1);
  assert.equal(report.stats.coverageIncomplete, true);
  assert.equal(report.stats.capped, true);
});

test("scan records a coverage finding when its total content-read cap is reached", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");

  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, "notes.txt"), "bounded content\n");

  const report = scan({ homeDir, roots: [root], maxTotalBytes: 1 });

  assert.equal(report.stats.bytesRead, 0);
  assert.equal(report.stats.coverageIncomplete, true);
  assert.equal(report.stats.capped, true);
  assert.ok(report.findings.some(finding =>
    finding.category === "coverage"
    && /total content-reading limit/i.test(finding.title)
  ));
});

test("scan does not classify unrelated chatsworth files as session transcripts", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");

  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, "chatsworth.txt"), "not a transcript\n");

  const report = scan({ homeDir, roots: [root] });

  assert.equal(report.findings.some(finding =>
    finding.title === "Agent session transcript stored locally"
  ), false);
});

test("scan refuses a filesystem root as an explicit custom root", () => {
  assert.throws(
    () => scan({ roots: [path.parse(process.cwd()).root] }),
    /refusing to scan a filesystem root/i
  );
});

test("scan rejects invalid API limits", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");

  fs.mkdirSync(root);

  for (const option of [
    "maxFiles",
    "maxContentBytes",
    "maxTotalBytes",
    "maxDirectories",
    "maxEntries",
    "maxFindings",
    "maxOccurrences",
    "maxOccurrencesPerFile"
  ]) {
    for (const value of [0, -1, Number.NaN, 1.5]) {
      assert.throws(
        () => scan({ homeDir, roots: [root], [option]: value }),
        /positive integer/i,
        `${option} should reject ${String(value)}`
      );
    }
  }
});
