# Repository guidance

## Scope

This repository currently contains only the Church App desktop foundation. Keep changes limited to the Tauri shell, its narrow health command, tests, validation, and documentation. Do not represent future parish workflows as implemented.

## Trust boundary

React is presentation and interaction only. Privileged operations belong in Rust. React must not directly access a future database, filesystem, encryption keys, secrets, or privileged services.

## Change safety

- Inspect root-level `PLANS.md` when an active substantial implementation initiative exists.
- Inspect `git status --short`, `git diff --stat`, and relevant files before editing.
- Preserve unrelated modified and untracked work. Never reset, clean, stash, stage, commit, or push unless explicitly requested.
- Obtain approval before adding or changing packages beyond the dependencies required by the current task.
- Do not add databases, schemas, migrations, database bindings, authentication, Supabase, or future subsystem abstractions without an explicitly scoped task.
- Never place secrets, credentials, environment values, real parish data, or personal data in source, tests, logs, or documentation. Tests use synthetic, non-person data only.
- Keep logs local, minimal, structured, and redaction-first. Never log command payloads or raw error chains.

## Narrow validation

Run the relevant subset, and report exact commands and results:

```powershell
npm run format:check
npm run lint
npm run typecheck
npm test
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo clippy --manifest-path src-tauri/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml --locked
git diff --check
```

Report files changed, dependencies changed, skipped or failed checks, environment limits, remaining manual checks, and final Git status. Never claim runtime behavior that was not manually observed.
