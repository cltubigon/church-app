# Product decisions

## Implemented foundation facts

- **Implemented stack:** Tauri 2, Rust, React, TypeScript, Vite, and npm.
- **Trust boundary:** Rust is trusted; React is presentation and interaction only.
- **Scope:** application shell, placeholder routing, a non-sensitive health command, Rust-only storage-path and storage-identity foundations, and pure Rust installation-state decisions.
- **Permanent identity:** production display name `Church App`, application identifier `io.github.cltubigon.churchapp`, version `0.1.0`.
- **Storage-path boundary:** the production database path is resolved only in Rust beneath Tauri's per-user local application-data directory and uses the fixed filename `parish-data.db`.
- **Current storage limitation:** no production directory or database is created, opened, migrated, or connected.
- **Initialization boundary:** ordinary startup leaves a never-initialized installation setup-required and cannot authorize creation. A distinct Rust-only in-memory authorization transition can indicate that a future setup step is permitted, but performs no setup or storage operation.
- **Missing-storage behavior:** an initialized installation whose expected storage is missing fails closed and is not treated as a new installation. Inconsistent or unavailable evidence also fails closed.

## Locked future direction (not implemented)

- Desktop-first and offline-capable; Windows 10 and Windows 11 are intended targets.
- Normal Church App operation will use one dedicated standard Windows account and require no elevation.
- Production data will operate only from the application-owned per-user local application-data directory.
- Production database creation may occur only through a future explicit first-time setup flow; ordinary startup does not authorize setup and must never silently create a missing database.
- Each future parish database will contain an immutable randomly generated opaque parish identifier. Representation and validation boundaries exist, but generation and persistence do not.
- SQLCipher remains a production-storage candidate, not the selected final engine.
- Local parish data will be authoritative; future central Supabase services will be non-authoritative.
- The public Next.js application and canonical contracts belong in separate repositories.
- The first release direction is English only.
- Schedule timezone: `Asia/Manila`; dates: `MM/DD/YYYY`; times: 12-hour with AM/PM.
- Future primary request statuses are Pending, Scheduled, Completed, and Cancelled.
- The prior visible **Cancellation requested** primary-status indicator rule is superseded: no such primary-status indicator is to be shown.

The implemented initialization work is decision logic only. These directions do not authorize setup orchestration, installation-evidence persistence, database creation or opening, setup UI, schemas, migrations, authentication, recovery, backup, or product workflows in this repository.
