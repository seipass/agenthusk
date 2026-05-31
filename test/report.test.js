import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { parseArguments, VERSION } from "../src/cli.js";
import { createDemoReport } from "../src/demo.js";
import { renderHtmlReport, renderShareCard } from "../src/report.js";
import { scan } from "../src/scanner.js";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = path.join(projectRoot, "src", "cli.js");

function createFixture(t, prefix = "agenthusk-report-") {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

test("HTML and SVG renders do not reveal scanned secret values", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");
  const privateFileName = "credentials.txt";
  const secret = `sk-${"S".repeat(30)}`;

  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, privateFileName), `${secret}\n`);

  const report = scan({ homeDir, roots: [root] });
  const fingerprint = report.secretOccurrences[0].fingerprint;
  const json = JSON.stringify(report);
  const html = renderHtmlReport(report);
  const svg = renderShareCard(report);

  assert.equal(json.includes(secret), false);
  assert.equal(html.includes(secret), false);
  assert.equal(svg.includes(secret), false);
  assert.ok(json.includes(fingerprint));
  assert.ok(html.includes(fingerprint));
  assert.equal(svg.includes(privateFileName), false);
  assert.equal(svg.includes(fingerprint), false);
});

test("demo report renders as HTML and an SVG share card", () => {
  const report = createDemoReport();
  const html = renderHtmlReport(report);
  const svg = renderShareCard(report);

  assert.match(html, /AgentHusk/i);
  assert.ok(html.includes("a18f09b4d1"));
  assert.match(svg, /^<svg\b/);
  assert.match(svg, /AgentHusk/i);
});

test("HTML render neutralizes script injection in report fields", () => {
  const report = createDemoReport();
  const injection = `</script><script>alert("agenthusk-xss")</script>`;
  report.findings[0].title = injection;

  const html = renderHtmlReport(report);

  assert.equal(html.includes(injection), false);
  assert.equal(html.includes(`<script>alert("agenthusk-xss")</script>`), false);
  assert.ok(html.includes("&lt;/script&gt;&lt;script&gt;alert(&quot;agenthusk-xss&quot;)&lt;/script&gt;"));
  assert.ok(html.includes("\\u003c/script\\u003e\\u003cscript\\u003ealert"));
});

test("HTML render warns when a private report includes raw paths", t => {
  const homeDir = createFixture(t);
  const root = path.join(homeDir, ".codex");

  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, "credentials.txt"), `sk-${"W".repeat(30)}\n`);
  const report = scan({ homeDir, roots: [root], showPaths: true });
  const html = renderHtmlReport(report);

  assert.equal(report.pathsRedacted, false);
  assert.match(html, /unsafe raw paths/i);
  assert.match(html, /private report warning/i);
  assert.match(html, /do not share this report/i);
});

test("CLI parser accepts repeated roots and scan output controls", () => {
  assert.deepEqual(
    parseArguments([
      "scan",
      "--home", "/tmp/home",
      "--root", "/tmp/first",
      "--root", "/tmp/second",
      "--out", "/tmp/report.html",
      "--json", "/tmp/report.json",
      "--card", "/tmp/card.svg",
      "--max-files", "42",
      "--max-bytes", "1048576",
      "--show-paths",
      "--no-html"
    ]),
    {
      command: "scan",
      homeDir: "/tmp/home",
      roots: ["/tmp/first", "/tmp/second"],
      htmlPath: "/tmp/report.html",
      jsonPath: "/tmp/report.json",
      cardPath: "/tmp/card.svg",
      maxFiles: 42,
      maxBytes: 1048576,
      showPaths: true,
      html: false
    }
  );
});

test("CLI demo atomically replaces JSON, HTML, and SVG artifacts without logging values", t => {
  const directory = createFixture(t, "agenthusk-cli-");
  const hiddenArgument = "do-not-log-this-value";
  const outputDirectory = path.join(directory, hiddenArgument);
  const htmlPath = path.join(outputDirectory, "demo.html");
  const jsonPath = path.join(outputDirectory, "demo.json");
  const cardPath = path.join(outputDirectory, "demo.svg");

  fs.mkdirSync(outputDirectory);
  for (const filePath of [htmlPath, jsonPath, cardPath]) {
    fs.writeFileSync(filePath, "stale", { mode: 0o644 });
    fs.chmodSync(filePath, 0o644);
  }

  const result = spawnSync(process.execPath, [
    cliPath,
    "demo",
    "--out", htmlPath,
    "--json", jsonPath,
    "--card", cardPath
  ], {
    cwd: projectRoot,
    encoding: "utf8"
  });

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "AgentHusk report generated. 4 roots scanned, 7 findings, no cap hit.\n");
  assert.equal(result.stderr, "");
  assert.equal(result.stdout.includes(hiddenArgument), false);
  assert.equal(result.stderr.includes(hiddenArgument), false);
  assert.deepEqual(JSON.parse(fs.readFileSync(jsonPath, "utf8")), createDemoReport());
  assert.match(fs.readFileSync(htmlPath, "utf8"), /AgentHusk/i);
  assert.match(fs.readFileSync(cardPath, "utf8"), /^<svg\b/);
  assert.deepEqual(
    fs.readdirSync(outputDirectory).sort(),
    ["demo.html", "demo.json", "demo.svg"]
  );
  for (const filePath of [htmlPath, jsonPath, cardPath]) {
    assert.equal(fs.statSync(filePath).mode & 0o777, 0o600);
  }
});

test("CLI runs when invoked through an npm-style symlink", t => {
  const directory = createFixture(t, "agenthusk-cli-link-");
  const linkedCliPath = path.join(directory, "agenthusk");
  const jsonPath = path.join(directory, "demo.json");

  fs.symlinkSync(cliPath, linkedCliPath);
  const result = spawnSync(linkedCliPath, [
    "demo",
    "--json", jsonPath,
    "--no-html"
  ], {
    cwd: projectRoot,
    encoding: "utf8"
  });

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "AgentHusk report generated. 4 roots scanned, 7 findings, no cap hit.\n");
  assert.deepEqual(JSON.parse(fs.readFileSync(jsonPath, "utf8")), createDemoReport());
});

test("CLI prints its package version", () => {
  const result = spawnSync(process.execPath, [cliPath, "--version"], {
    cwd: projectRoot,
    encoding: "utf8"
  });

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${VERSION}\n`);
  assert.equal(result.stderr, "");
});

test("CLI returns a useful error when no explicit scan root can be inspected", t => {
  const directory = createFixture(t, "agenthusk-cli-missing-root-");
  const missingRoot = path.join(directory, "missing");

  const result = spawnSync(process.execPath, [
    cliPath,
    "scan",
    "--root", missingRoot,
    "--no-html"
  ], {
    cwd: projectRoot,
    encoding: "utf8"
  });

  assert.equal(result.status, 2);
  assert.match(result.stderr, /no explicit scan root could be inspected/i);
  assert.equal(result.stderr.includes(missingRoot), false);
});

test("CLI scan anonymizes paths by default for shareable JSON output", t => {
  const directory = createFixture(t, "agenthusk-cli-redacted-");
  const root = path.join(directory, "private-agent-root");
  const jsonPath = path.join(directory, "redacted.json");
  const privateFileName = "customer-project-credentials.txt";

  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, privateFileName), `sk-${"R".repeat(30)}\n`);

  const result = spawnSync(process.execPath, [
    cliPath,
    "scan",
    "--root", root,
    "--json", jsonPath,
    "--no-html"
  ], {
    cwd: projectRoot,
    encoding: "utf8"
  });

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.includes(root), false);
  assert.equal(result.stderr.includes(root), false);

  const report = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
  const serialized = JSON.stringify(report);

  assert.equal(report.pathsRedacted, true);
  assert.equal(serialized.includes(privateFileName), false);
  assert.ok(report.findings.every(finding => /^<redacted-path:[a-f0-9]{16,64}>$/.test(finding.path)));
  assert.ok(report.secretOccurrences.every(occurrence =>
    /^<redacted-path:[a-f0-9]{16,64}>$/.test(occurrence.path)
  ));
});
