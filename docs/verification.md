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
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo clippy --manifest-path src-tauri/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml --locked
git diff --check
```

For the owner-SID warning, use a command-scoped override such as `git -c safe.directory=D:/Tauri/church-app status --short`; do not modify Git configuration.

## Environment-dependent and manual checks

`npm run tauri:dev` needs Microsoft C++ Build Tools and WebView2. It opens the real window. Local structured health events appear in its terminal; no log file or upload exists.

To inspect the unknown route, use webview devtools when available and run `window.history.pushState({}, "", "/not-a-route"); window.dispatchEvent(new PopStateEvent("popstate"));`. Health failure is safely covered by `npm test`, which mocks an invalid command response containing raw backend detail. There is no production crash trigger; manual visual inspection requires an uncommitted, disposable equivalent mock.

On Windows 11, manually inspect startup, one-window behavior, keyboard use, focus, resizing, scaling, health success, and logs. Repeat startup on Windows 10 where available. Neither target is verified until observed.

No production build, installer, signing, release, deployment, browser or desktop E2E automation, coverage threshold, database, or service check is included. CI omits `tauri build`; Clippy and Rust tests provide narrow compile coverage without generating an installer. Automation does not prove runtime startup, Windows 10 support, WebView2 availability, real-webview accessibility, low-memory support, security, or parish workflows.
