# AgentHusk Roadmap

AgentHusk is pre-1.0. This roadmap describes intended direction, not a delivery promise. The priority is to keep scanning local and bounded, without intentionally modifying source artifacts.

## Current foundation

- Known-root scanning for common AI coding agents.
- Secret-shaped value detection with report-safe, per-run fingerprints.
- Duplicate-secret grouping within a scan.
- Residue, local-permission, MCP-configuration, and coverage-gap findings.
- Local demo and scan workflows.
- Default path anonymization with an explicit unsafe option for raw-path local investigation.
- Redaction regressions for JSON, HTML, SVG, normal CLI output, and npm-style symlink execution.

## Next

### Broader redaction regression CI

Keep expanding the regression suite whenever a report format, console path, error path, or exporter is added. Any new output must fail closed when a matched synthetic secret could appear.

### MCP receipts

Capture a local, reviewable MCP receipt: where a server declaration was discovered, which execution boundary it implies, and what configuration metadata deserves inspection. Receipts must redact values and must not execute, contact, or validate the configured server.

### Plugin adapters

Introduce small adapters for agent- and plugin-specific storage layouts. Adapters should declare roots and parsing rules without expanding the scanner into an agent runtime or allowing unbounded traversal.

## Later

### RuleMesh-style rule overlap analysis

Surface when independent rules converge on the same residue or when overlapping rules create redundant findings. The goal is explainable confidence and lower noise, not an opaque score or a claim of complete detection.

### Report schema hardening

Version and document the local report schema, add compatibility fixtures, and define exporter safety requirements.

### Coverage visibility

Make skipped files, traversal caps, unsupported layouts, and parser limitations easier to audit from a report.

### Snapshot workflow guidance

Document and test practical snapshot or copied-tree workflows for ordinary-user scans. Treat live writable trees, FUSE mounts, network mounts, adversarial filesystems, and elevated execution as unsafe operating conditions rather than supported isolation boundaries.

### Windows compatibility harness

Add a Windows-specific filesystem fixture suite before adding Windows CI. Symlink privileges and POSIX permission bits differ from the Ubuntu and macOS security checks.

## Non-goals

- Uploading reports or source files to a hosted service.
- Calling external APIs during a scan.
- Sending telemetry.
- Automatically deleting residue or rotating credentials.
- Claiming that a clean scan proves a machine is safe.
- Treating the aggregate risk signal as a security grade.

## Release gates

Before a stable release:

- Redaction regression CI covers every report output.
- Traversal bounds and symlink behavior have regression tests.
- Security reporting instructions point to an active private contact path.
- Public docs distinguish detected residue from confirmed exposure.
