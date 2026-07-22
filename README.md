# Church App

This repository contains the initial Windows-first desktop foundation for a future Roman Catholic parish application. It is an unfinished application shell, not an implemented parish product. Do not enter real parish or personal data.

The current scaffold uses Tauri 2, Rust, React, TypeScript, Vite, and npm. Rust is the trusted desktop boundary; React provides presentation and interaction only. The permanent production identifier is `io.github.cltubigon.churchapp`; it is fixed for production storage-path purposes.

## Prerequisites

- Windows 10 or Windows 11 (intended targets; neither is certified by automated checks)
- Node.js 24.18.0 with its bundled npm 11.16.0
- Rust 1.97.1 through `rustup` (the repository toolchain file selects it)
- Microsoft C++ Build Tools with **Desktop development with C++**
- Microsoft Edge WebView2 Runtime

## Setup and development

```powershell
npm ci
npm run tauri:dev
```

`npm run dev` starts only the browser-hosted Vite frontend. It is useful for presentation work, but the health command requires the Tauri desktop runtime.

## Validation

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

See `docs/verification.md` for scope, environment-dependent checks, and manual verification.

## Current limitations

The four visible staff areas are unavailable placeholders. There is no production database, authentication, parish workflow, central service, backup, PDF, updater, release signing, telemetry, or production storage implementation. The development health check returns only the application name, bootstrap status, and package version. No real parish or personal data should be entered.

The production display name is `Church App`, the permanent application identifier is `io.github.cltubigon.churchapp`, and the version remains `0.1.0`. The repository is still only an unfinished foundation and is not production-ready.

If Git reports dubious ownership, do not change global or repository Git configuration without approval. A one-command inspection can use a temporary override such as:

```powershell
git -c safe.directory=D:/Tauri/church-app status --short
```
