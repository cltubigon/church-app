# Repository guidance

## Scope

This repository currently contains only the Church App desktop foundation. Keep changes limited to the Tauri shell, its narrow health command, tests, validation, and documentation. Do not represent future parish workflows as implemented.

## Trust boundary

React is presentation and interaction only. Privileged operations belong in Rust. React must not directly access a future database, filesystem, encryption keys, secrets, or privileged services.

## Change safety

- Inspect root-level `PLANS.md` when an active substantial implementation initiative exists.
- Inspect `git status --short`, `git diff --stat`, and relevant files before editing.
- Preserve unrelated modified and untracked work. Never reset, clean, or stash unless explicitly requested. Stage and commit only under the approved task workflow below or when an explicit prompt requests them. Push only after Carlo explicitly instructs or approves it.
- Obtain approval before adding or changing packages beyond the dependencies required by the current task.
- Do not add databases, schemas, migrations, database bindings, authentication, Supabase, or future subsystem abstractions without an explicitly scoped task.
- Never place secrets, credentials, environment values, real parish data, or personal data in source, tests, logs, or documentation. Tests use synthetic, non-person data only.
- Keep logs local, minimal, structured, and redaction-first. Never log command payloads or raw error chains.

## Default Codex task workflow

Routine narrowly scoped Codex tasks should normally complete the edit, task-specific validation, exact allowed-file review, staging of only approved files, complete staged-diff inspection, `git diff --cached --check`, and one ordinary local commit, then stop. Push is not automatic and occurs only after Carlo explicitly instructs or approves pushing the relevant local commit or commits. Multiple approved local commits may remain stacked ahead of `origin/main` until Carlo chooses to push them. An explicit task prompt may instead require implementation only with no commit, a read-only audit, review before commit, documentation-only work, commit-only work, an explicitly authorized push, or other narrower behavior; the explicit prompt wins.

Stop before staging or committing and return the work for Carlo/Project-Manager review if the prompt requires review first; unexpected or unauthorized files changed; the working tree materially differs from the approved baseline; a material product or architecture conflict appears; a locked decision cannot be preserved; scope expansion is required; a security- or ownership-sensitive ambiguity remains; a required security- or correctness-relevant check fails or materially contradicts the implementation claim; a prohibited dependency, database, migration, infrastructure, secret, environment, or deployment change would be required; or the staged diff cannot be proven to match the approved scope exactly. Preserve the working tree, do not silently fix unrelated work, and do not stage, commit, or push in those cases.

Routine tasks must preserve unrelated changes; stage explicit approved paths only; never use `git add .` or `git add -A` for scoped work; inspect the complete staged patch; and do not amend, rebase, reset, restore, stash, or force-push unless separately authorized. After the local commit, verify a clean working tree, an empty index, and no untracked files, and report the commit hash, exact subject, direct parent, exact committed files, current divergence from `origin/main`, whether a normal fast-forward push appears available, and that push is pending Carlo's instruction. When Carlo authorizes a push, refresh the remote first, use only a normal fast-forward push unless explicitly authorized otherwise, and stop if remote advancement prevents it. After an approved push, verify and report final upstream equality, divergence, worktree cleanliness, index state, and untracked-file state. Neither the routine commit workflow nor an authorized push broadens validation authority: run only the narrowest task-relevant approved checks, never expensive, destructive, deployment-affecting, or broad commands merely because delivery includes a commit or push.

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
