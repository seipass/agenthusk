# AgentHusk Release Checklist

Use this checklist for the first public release. Do not publish from an elevated shell.

## 1. Verify the release candidate

```sh
npm test
npm run check
npm run demo
npm run smoke:pack
npm publish --dry-run
```

Open `demo/agenthusk-demo.html` locally and inspect the synthetic report.

## 2. Create the public repository

Set your Git identity if the machine does not already have one:

```sh
git config user.name "<your-name>"
git config user.email "<your-email>"
git add .
git commit -m "Initial release: AgentHusk 0.1.0"
```

Create a public GitHub repository named `agenthusk`, then push `main`. If GitHub CLI is installed and authenticated:

```sh
gh repo create agenthusk --public --source=. --remote=origin --push
```

If not, create the repository in the GitHub web UI and follow the displayed push instructions.

## 3. Finish repository settings

- Upload `docs/assets/agenthusk-social.png` as the GitHub social preview.
- Enable GitHub private vulnerability reporting under **Settings > Security > Private vulnerability reporting**.
- Confirm that the `package.json` repository URL resolves to the public repository.
- Re-run the verification commands after changing package metadata.

## 4. Publish npm

The package name should still be checked immediately before release:

```sh
npm view agenthusk name version
npm login
npm publish
```

An `E404` from `npm view agenthusk` means the unscoped package name is not currently published. Confirm the expected npm account before running `npm publish`.

## 5. Launch

Use the editable drafts in [`LAUNCH.md`](LAUNCH.md). Start with the synthetic demo in public posts; do not attach a real report without reviewing its metadata.
