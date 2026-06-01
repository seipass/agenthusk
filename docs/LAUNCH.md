# AgentHusk Launch Materials

Use these as editable drafts. Keep claims tied to shipped behavior and avoid implying complete detection, remediation, or breach prevention.

## Core positioning

AgentHusk is a local-first forensic scanner for secrets and risky residue left in AI coding-agent storage.

- Scans known local agent directories without intentionally modifying source artifacts; writes requested local report artifacts.
- Matched content values stay out of default anonymized reports; reports use short per-run fingerprints.
- Source paths are anonymized by default; raw paths require the unsafe `--show-paths` option.
- No external API, upload, or telemetry.
- Findings and the aggregate risk signal are review leads, not proof of compromise or a security grade.

Preview image: [`docs/assets/agenthusk-social.svg`](assets/agenthusk-social.svg). Use [`docs/assets/agenthusk-social.png`](assets/agenthusk-social.png) for GitHub social preview upload.

## X

### Short post

AI coding agents retain local state. Sometimes that state deserves a second look.

AgentHusk is an OSS, local-first forensic scanner for secret-shaped values and risky residue in known agent directories.

Does not intentionally change source artifacts. No upload. No telemetry. Default reports hide matched values and anonymize paths.

### Thread

1. AI coding agents can leave useful local history behind. That same local state can also retain `.env` copies, shell history, session transcripts, MCP configuration, or secret-shaped values.
2. AgentHusk scans known agent directories locally without intentionally changing source artifacts. Its default anonymized reports keep matched content values out.
3. Reports use short, per-run fingerprints to group repeated matches and anonymize source paths by default. They still contain forensic metadata, so review before sharing.
4. AgentHusk is narrow by design: no external API, upload, telemetry, automatic deletion, or claim that a clean scan proves a machine is safe.
5. Try the synthetic demo first: `npx agenthusk demo`. Then scan locally with `npx agenthusk scan`.

## Hacker News

### Title

Show HN: AgentHusk - a local-first scanner for residue left by AI coding agents

### Submission text

AgentHusk is an OSS forensic scanner for local AI coding-agent storage. It scans known agent directories without intentionally modifying source artifacts and writes local reports for secret-shaped values, duplicate fingerprints, environment-file copies, shell-history residue, retained transcripts, permissive local file modes, and MCP server declarations.

The main design constraint is that the scanner should not create a more dangerous report than necessary. Default anonymized reports omit matched content values; a short fingerprint derived with a per-run random key is used to group repeats inside one report. The scan path has no external API calls, uploads, or telemetry.

This is deliberately a narrow tool. Pattern matching can miss secrets or produce false positives, and a clean result does not prove a machine is safe. Reports anonymize source paths by default but still contain forensic metadata and should be reviewed before sharing.

The safe starting point is the synthetic demo:

```sh
npx agenthusk demo
```

Feedback on redaction edge cases, bounded traversal, agent storage layouts, and useful low-noise rules would be helpful.

For real data, prefer scanning a snapshot or copied tree as an ordinary user. Avoid live writable trees, FUSE or network mounts, and elevated execution.

## Product Hunt

### Name

AgentHusk

### Tagline

Scan local AI-agent residue with safer default reports

### Description

AgentHusk is an open-source, local-first forensic scanner for known AI coding-agent directories. It flags secret-shaped values, repeated fingerprints, risky residue, permissive local access, and MCP server declarations. It does not intentionally modify scanned source artifacts, and the scan path uses no external API, upload, or telemetry. Default reports omit matched content values, anonymize paths, and should still be reviewed before sharing because they include forensic metadata.

### First comment

AgentHusk started from a simple concern: local AI coding-agent state is useful, but it can outlive the task that created it.

The tool is intentionally constrained. It scans known local directories without intentionally modifying source artifacts, writes default anonymized reports without copying matched content values, and avoids network calls and telemetry. It does not delete files, rotate credentials, or claim that a clean scan proves safety.

Start with `npx agenthusk demo` for a synthetic report. If you run `npx agenthusk scan`, keep the generated report local until you have reviewed its metadata.

## FAQ

### Does AgentHusk upload files or reports?

No. The scanner is local-first and has no upload path.

### Does a clean scan mean there are no secrets on the machine?

No. AgentHusk scans known roots with bounded, pattern-based rules. It can miss residue and does not replace secret management or incident response.

### Are reports safe to publish?

Not automatically. Matched content values are omitted and source paths are anonymized by default, but reports can still contain line numbers, permission modes, agent names, and finding details. Reports created with the unsafe `--show-paths` option include raw source paths, which can themselves contain sensitive text. Review before sharing.

### Does AgentHusk delete residue or rotate keys?

No. Scanned source artifacts are not intentionally modified. AgentHusk writes requested local report artifacts, and remediation remains an explicit user action.

## Launch checklist

- Run `npx agenthusk demo` and inspect the synthetic report.
- Run `npx agenthusk scan` as an ordinary user against a snapshot or copied tree and inspect report metadata locally.
- Avoid scanning live writable trees, FUSE or network mounts, or running with elevated privileges.
- Confirm that the preview image renders from `docs/assets/agenthusk-social.svg`.
- Upload `docs/assets/agenthusk-social.png` as the GitHub social preview.
- Verify the private vulnerability-reporting path referenced by `SECURITY.md`.
- Replace draft repository links only after the public repository URL is final.
- Avoid benchmark, coverage, or prevention claims unless they are documented and reproducible.
