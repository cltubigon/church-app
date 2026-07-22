# Architecture

Vite serves and bundles the TypeScript React presentation. React Router supplies four explicit placeholder routes and an unknown-route fallback. The Tauri command bridge exposes one `health_check` operation. Rust constructs its typed, non-sensitive response and owns the desktop runtime.

React may render UI, navigate placeholders, and request health. Privileged operations belong in Rust. React must never directly access a future database, filesystem, encryption key, or privileged service.

The current structure is deliberately small: `src/` contains shell code and frontend tests; `src-tauri/` contains Tauri configuration, one capability, Rust entry points, the command, Rust-owned storage foundations, and Rust tests; `docs/` contains constraints; and `.github/workflows/ci.yml` contains Windows-only validation.

Rust owns production path resolution. Tauri's Rust-side local application-data resolver supplies the application-owned per-user directory associated with `io.github.cltubigon.churchapp`; Rust appends the single fixed filename `parish-data.db`. Production, development, automated-test, and restore-staging paths have distinct wrapper types and separate resolvers. Development uses an explicitly non-production identity, automated tests require a unique safe test identifier beneath an injected temporary root, and restore staging cannot be used as an active production path.

No Tauri command accepts or returns a database or filesystem path. React cannot select, override, supply, or receive the production location. Path construction performs no filesystem operations, and normal startup does not resolve, inspect, create, or open production storage in this stage.

Rust also owns a narrow initialization decision boundary. `InstallationEvidence` distinguishes never initialized, initialized with expected storage present or missing, inconsistent evidence, and unavailable evidence. Ordinary startup supplies no setup authorization: never-initialized remains setup-required, initialized-and-present indicates only future open eligibility, and initialized-but-missing, inconsistent, or unavailable evidence fails closed.

First-time setup authorization is a separate in-memory Rust transition with a private-field authorization type. It can be produced only after the dedicated transition accepts never-initialized evidence; raw frontend values cannot construct it. Installation evidence, setup authorization, and future storage opening remain separate. This stage does not inspect the real filesystem, persist evidence, perform setup, resolve a production path during startup, or create or open storage. No frontend or Tauri IPC operation has setup authority.

Future encrypted local parish data is intended to be authoritative, while central services are non-authoritative. The future public web application and canonical contracts are separate repositories. No interfaces, ports, adapters, schemas, clients, or placeholders for those systems exist here.

Installation-evidence protection and persistence, setup orchestration, database creation and opening, encryption implementation, schema and migrations, authentication, synchronization, public intake, activation, backup and recovery, reporting, PDFs, printing, updates, release distribution, and product workflows are deferred. Production path hardening for ACLs, reparse points and junctions, removable or network storage, and runtime replacement detection is also deferred.
