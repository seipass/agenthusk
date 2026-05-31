# AgentHusk Architecture

AgentHusk is intentionally narrow: a local-first, report-only scanner for residue left in AI coding-agent storage.

## Data flow

```text
known roots or explicit roots
  -> bounded directory traversal
  -> bounded text sampling
  -> residue and secret-shaped match rules
  -> report-scoped HMAC fingerprints
  -> normalized report model
  -> local JSON, portable HTML, optional aggregate-only SVG
```

## Safety boundaries

- Scanned source artifacts are not intentionally modified.
- The scanning path has no external API call, upload, telemetry, discovered-command execution, or MCP-server execution.
- Paths are anonymized by default. The explicit `--show-paths` option is unsafe for artifacts that may be shared.
- Matched content values are not copied into content-derived report fields.
- Secret and path fingerprints use per-run random HMAC keys and are intentionally unstable across runs.
- Traversal skips discovered symlinks, symlinked final roots, roots under the selected home with symlinked descendant components, and filesystem roots. It uses bounded reads and records coverage gaps when caps are reached.
- Live writable trees, FUSE mounts, network mounts, attacker-controlled filesystems, and elevated execution remain outside the supported isolation boundary.

## Modules

| Module | Responsibility |
| --- | --- |
| `src/catalog.js` | Known agent roots and display metadata |
| `src/scanner.js` | Bounded traversal, detection, report model |
| `src/report.js` | Defensive normalization, portable HTML, aggregate SVG |
| `src/demo.js` | Synthetic report for screenshots and safe evaluation |
| `src/cli.js` | Argument parsing and owner-only atomic artifact writes |

## Adding a rule

1. Keep the rule narrow enough to explain.
2. Add synthetic positive and nearby negative cases.
3. Verify JSON, HTML, SVG, and normal CLI output do not reveal the matched value.
4. Describe likely false positives and false negatives.

## Adding an exporter

Treat an exporter as a new disclosure boundary. Normalize allowed fields, redact matched content values, default to anonymized paths, and add regression tests before shipping it.
