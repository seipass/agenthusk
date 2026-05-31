#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createDemoReport } from "./demo.js";
import { renderHtmlReport, renderShareCard } from "./report.js";
import { ScanUsageError, scan } from "./scanner.js";

const DEFAULT_HTML_PATH = "agenthusk-report.html";
const DEFAULT_JSON_PATH = "agenthusk-report.json";
export const VERSION = JSON.parse(
  fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")
).version;

export const USAGE = `Usage:
  agenthusk scan [options]
  agenthusk demo [options]
  agenthusk help
  agenthusk --version

Options:
  --home <directory>    Override the home directory used by scan
  --root <directory>    Scan a specific root; may be repeated
  --out <file>          Write the HTML report to this file
  --json <file>         Write the JSON report to this file
  --card <file>         Write an SVG share card to this file
  --max-files <count>   Stop scanning after this many files
  --max-bytes <count>   Skip content inspection for files larger than this
  --show-paths          Unsafe: include relative paths in a private report
  --no-html             Do not write an HTML report
  --version             Show the AgentHusk version
  --help                Show this help
`;

class CliUsageError extends Error {}

function takeValue(args, option) {
  const value = args.shift();
  if (!value || value.startsWith("--")) {
    throw new CliUsageError(`Missing value for ${option}.`);
  }
  return value;
}

export function parseArguments(argv) {
  const args = [...argv];
  const command = args.shift() ?? "help";
  const options = {
    command,
    homeDir: undefined,
    roots: [],
    htmlPath: DEFAULT_HTML_PATH,
    jsonPath: DEFAULT_JSON_PATH,
    cardPath: undefined,
    maxFiles: undefined,
    maxBytes: undefined,
    showPaths: false,
    html: true
  };

  if (command === "--help" || command === "-h") {
    return { ...options, command: "help" };
  }
  if (command === "--version" || command === "-v") {
    return { ...options, command: "version" };
  }
  if (!["scan", "demo", "help", "version"].includes(command)) {
    throw new CliUsageError("Unknown command.");
  }

  while (args.length > 0) {
    const option = args.shift();
    switch (option) {
      case "--home":
        options.homeDir = takeValue(args, option);
        break;
      case "--root":
        options.roots.push(takeValue(args, option));
        break;
      case "--out":
        options.htmlPath = takeValue(args, option);
        break;
      case "--json":
        options.jsonPath = takeValue(args, option);
        break;
      case "--card":
        options.cardPath = takeValue(args, option);
        break;
      case "--max-files": {
        const maxFiles = Number(takeValue(args, option));
        if (!Number.isSafeInteger(maxFiles) || maxFiles <= 0) {
          throw new CliUsageError("--max-files must be a positive integer.");
        }
        options.maxFiles = maxFiles;
        break;
      }
      case "--max-bytes": {
        const maxBytes = Number(takeValue(args, option));
        if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
          throw new CliUsageError("--max-bytes must be a positive integer.");
        }
        options.maxBytes = maxBytes;
        break;
      }
      case "--no-html":
        options.html = false;
        break;
      case "--show-paths":
        options.showPaths = true;
        break;
      case "--help":
      case "-h":
        options.command = "help";
        break;
      case "--version":
      case "-v":
        options.command = "version";
        break;
      default:
        throw new CliUsageError("Unknown option.");
    }
  }

  return options;
}

export function atomicWrite(filePath, contents) {
  const destination = path.resolve(filePath);
  const directory = path.dirname(destination);
  const temporaryPath = path.join(
    directory,
    `.${path.basename(destination)}.${process.pid}.${crypto.randomUUID()}.tmp`
  );

  fs.mkdirSync(directory, { recursive: true });
  try {
    fs.writeFileSync(temporaryPath, contents, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600
    });
    fs.renameSync(temporaryPath, destination);
  } finally {
    try {
      fs.unlinkSync(temporaryPath);
    } catch {
      // The rename succeeded or the temporary file was never created.
    }
  }
}

function createReport(options) {
  if (options.command === "demo") return createDemoReport();
  return scan({
    homeDir: options.homeDir,
    roots: options.roots.length > 0 ? options.roots : undefined,
    maxFiles: options.maxFiles,
    maxContentBytes: options.maxBytes,
    showPaths: options.showPaths
  });
}

export function runCli(
  argv = process.argv.slice(2),
  streams = { stdout: process.stdout, stderr: process.stderr }
) {
  try {
    const options = parseArguments(argv);
    if (options.command === "help") {
      streams.stdout.write(USAGE);
      return 0;
    }
    if (options.command === "version") {
      streams.stdout.write(`${VERSION}\n`);
      return 0;
    }

    const report = createReport(options);
    const artifacts = [
      [options.jsonPath, `${JSON.stringify(report, null, 2)}\n`]
    ];
    if (options.html) artifacts.push([options.htmlPath, renderHtmlReport(report)]);
    if (options.cardPath) artifacts.push([options.cardPath, renderShareCard(report)]);

    for (const [filePath, contents] of artifacts) atomicWrite(filePath, contents);
    const coverage = report.stats.coverageIncomplete ? "coverage gaps reported" : "no cap hit";
    streams.stdout.write(
      `AgentHusk report generated. ${report.agents.length} roots scanned, ${report.findings.length} findings, ${coverage}.\n`
    );
    return 0;
  } catch (error) {
    if (error instanceof CliUsageError || error instanceof ScanUsageError) {
      streams.stderr.write(`agenthusk: ${error.message}\n\n${USAGE}`);
      return 2;
    }
    streams.stderr.write("agenthusk: unable to generate report.\n");
    return 1;
  }
}

function resolveEntryPoint(filePath) {
  try {
    return fs.realpathSync.native(filePath);
  } catch {
    return path.resolve(filePath);
  }
}

const isEntryPoint = process.argv[1]
  && resolveEntryPoint(process.argv[1]) === fileURLToPath(import.meta.url);

if (isEntryPoint) process.exitCode = runCli();
