# Verification

Run from the repository root with Node.js 24.18.0, npm 11.16.0, and the pinned Rust toolchain.

## Frontend checks

```powershell
npm ci
npm run format:check
npm run lint
npm run typecheck
npm test
```

Tests mock Tauri and verify the shell, routes, keyboard semantics, typed health success, and safe rendering when the command boundary returns an unsafe malformed payload.

## Rust and repository checks

```powershell
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_state::tests
cargo test --manifest-path src-tauri/Cargo.toml --locked storage_foundation::tests
cargo test --manifest-path src-tauri/Cargo.toml --locked sqlcipher_windows_temporary_encryption_feasibility -- --nocapture
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo clippy --manifest-path src-tauri/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml --locked
git diff --check
```

The focused installation-state tests supply only synthetic evidence to pure Rust decisions. They verify that ordinary startup cannot authorize setup, explicit authorization permits only a future setup step, initialized-but-missing and inconsistent states fail closed, present storage indicates only future open eligibility, the authorization boundary has no boolean, string, path, frontend, or Tauri argument, and no directory or file is created. Installation evidence protection and persistence remain deferred.

The focused storage-foundation tests use synthetic roots for path construction and do not create directories or files. They verify fixed production naming, typed production/development/test/restore separation, unique safe automated-test path identities, and narrow database-format and parish-identifier representations. Production path resolution itself remains behind Rust's Tauri application-handle boundary and is not invoked during normal startup.

The focused SQLCipher command is a Windows-only feasibility test. It creates an encrypted database under the operating system temporary directory, verifies independent correct-key and wrong-key connections, reports non-sensitive native identity and cipher configuration, scans the database and retained journal sidecar for the synthetic plaintext sentinel, and removes its test directory. It does not select or exercise a production data location. The absence of the sentinel is supporting evidence, not complete proof of cryptographic correctness.

For the owner-SID warning, use a command-scoped override such as `git -c safe.directory=D:/Tauri/church-app status --short`; do not modify Git configuration.

## Environment-dependent and manual checks

`npm run tauri:dev` needs Microsoft C++ Build Tools and WebView2. It opens the real window. Local structured health events appear in its terminal; no log file or upload exists.

To inspect the unknown route, use webview devtools when available and run `window.history.pushState({}, "", "/not-a-route"); window.dispatchEvent(new PopStateEvent("popstate"));`. Health failure is safely covered by `npm test`, which mocks an invalid command response containing raw backend detail. There is no production crash trigger; manual visual inspection requires an uncommitted, disposable equivalent mock.

On Windows 11, manually inspect startup, one-window behavior, keyboard use, focus, resizing, scaling, health success, and logs. Repeat startup on Windows 10 where available. Neither target is verified until observed.

A temporary Windows-only SQLCipher feasibility database check is included, but it is not production database validation and automation does not prove production storage security; no production build, installer, signing, release, deployment, browser or desktop E2E automation, coverage threshold, or service check is included. CI omits `tauri build`; Clippy and Rust tests provide narrow compile coverage without generating an installer. Automation does not prove runtime startup, Windows 10 support, WebView2 availability, real-webview accessibility, low-memory support, security, or parish workflows.
