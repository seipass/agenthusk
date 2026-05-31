# Security Policy

AgentHusk scans security-sensitive local files. Treat bugs that expose source content or weaken redaction as security issues.

## Supported versions

AgentHusk is pre-1.0 software. Security fixes are applied to the latest release line only.

| Version | Supported |
| --- | --- |
| Latest `0.x` release | Yes |
| Older releases | No |

## Reporting a vulnerability

Do not open a public issue for a vulnerability or include real secrets, tokens, report files, or sensitive paths in public discussion.

Use the repository's [private vulnerability-reporting form](https://github.com/seipass/agenthusk/security/advisories/new) when it is available. If it is not available, contact a maintainer privately through the channel listed on the repository profile. If no private channel is listed, open a minimal issue asking for a private contact method without disclosing vulnerability details.

Include:

- The affected AgentHusk version or commit.
- The operating system and Node.js version.
- A minimal reproduction using synthetic placeholders only.
- The expected and actual behavior.
- Whether a generated report, console output, or file path may reveal sensitive content.

## Security invariants

Changes should preserve these properties:

- Scanned source artifacts are not intentionally modified. Requested local report artifacts are written.
- No external API calls, uploads, or telemetry are introduced into the scanning path.
- Default anonymized reports and normal CLI output do not contain matched content values.
- Source paths are anonymized by default. Raw source paths appear only when the user explicitly passes the unsafe `--show-paths` option.
- Secret fingerprints use a per-run random key and are not stable cross-run identifiers.
- Discovered symlinks are not followed during traversal. Symlinked final roots and roots under the selected home with symlinked descendant components are skipped.
- Test fixtures contain synthetic values only.

## Report handling

AgentHusk default anonymized reports omit matched content values, but they are not automatically safe public artifacts. Reports can still include line numbers, permission modes, agent names, and forensic findings. Reports generated with the unsafe `--show-paths` option also include raw source paths, which can themselves contain sensitive text or a value also present in file content. Review reports before sharing them outside the machine where they were generated.

## Safe scanning environment

Prefer scanning a snapshot or copied tree as an ordinary user. Avoid scanning a live writable tree, FUSE or network mount, or attacker-controlled filesystem. Do not run AgentHusk with elevated privileges unless you have a specific reason and understand the expanded exposure. Symlink skipping is not a complete defense against a filesystem that changes concurrently during traversal.

## Response expectations

Maintainers will validate the report, determine severity, prepare a fix, and coordinate disclosure when appropriate. Response timing depends on maintainer availability; no fixed service-level agreement is promised.
