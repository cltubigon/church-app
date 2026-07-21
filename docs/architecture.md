# Architecture

Vite serves and bundles the TypeScript React presentation. React Router supplies four explicit placeholder routes and an unknown-route fallback. The Tauri command bridge exposes one `health_check` operation. Rust constructs its typed, non-sensitive response and owns the desktop runtime.

React may render UI, navigate placeholders, and request health. Privileged operations belong in Rust. React must never directly access a future database, filesystem, encryption key, or privileged service.

The current structure is deliberately small: `src/` contains shell code and frontend tests; `src-tauri/` contains Tauri configuration, one capability, Rust entry points, the command, and Rust tests; `docs/` contains constraints; and `.github/workflows/ci.yml` contains Windows-only validation.

Future encrypted local parish data is intended to be authoritative, while central services are non-authoritative. The future public web application and canonical contracts are separate repositories. No interfaces, ports, adapters, schemas, clients, or placeholders for those systems exist here.

Database, encryption implementation, authentication, synchronization, public intake, activation, backup and recovery, reporting, PDFs, printing, updates, release distribution, and product workflows are deferred.
