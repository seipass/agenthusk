import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "agenthusk-pack-smoke-"));
const consumerRoot = path.join(temporaryRoot, "consumer");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? packageRoot,
    encoding: "utf8",
    stdio: options.stdio ?? "pipe"
  });
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    throw new Error(`${command} ${args.join(" ")} failed with status ${result.status}.`);
  }
  return result;
}

try {
  const pack = run(npm, ["pack", "--pack-destination", temporaryRoot]);
  const tarballName = pack.stdout.trim().split(/\r?\n/).at(-1);
  const tarballPath = path.join(temporaryRoot, tarballName);
  fs.mkdirSync(consumerRoot);

  run(npm, ["init", "-y"], { cwd: consumerRoot });
  run(npm, ["install", "--ignore-scripts", tarballPath], { cwd: consumerRoot });

  const binPath = path.join(
    consumerRoot,
    "node_modules",
    ".bin",
    process.platform === "win32" ? "agenthusk.cmd" : "agenthusk"
  );
  const htmlPath = path.join(temporaryRoot, "demo.html");
  const jsonPath = path.join(temporaryRoot, "demo.json");
  const cardPath = path.join(temporaryRoot, "card.svg");
  run(binPath, ["demo", "--out", htmlPath, "--json", jsonPath, "--card", cardPath], {
    cwd: consumerRoot
  });

  const installedRoot = path.join(consumerRoot, "node_modules", "agenthusk");
  const previewPath = path.join(installedRoot, "docs", "assets", "agenthusk-social.svg");
  const html = fs.readFileSync(htmlPath, "utf8");
  const card = fs.readFileSync(cardPath, "utf8");
  const modes = [htmlPath, jsonPath, cardPath].map(filePath => fs.statSync(filePath).mode & 0o777);

  if (!fs.existsSync(previewPath)) throw new Error("The packaged README preview SVG is missing.");
  if (!html.includes("AgentHusk")) throw new Error("The packaged CLI did not render the HTML report.");
  if (!card.includes("MATCHED VALUES STAY HIDDEN")) {
    throw new Error("The packaged CLI did not render the expected SVG share card.");
  }
  if (process.platform !== "win32" && modes.some(mode => mode !== 0o600)) {
    throw new Error(`Expected owner-only report modes, received ${modes.join(",")}.`);
  }

  process.stdout.write("AgentHusk packaged CLI smoke test passed.\n");
} finally {
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
}
