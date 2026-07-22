# First-Time Setup Gate and Missing-Storage State Model

## 1. Initiative and status

Active multi-stage initiative. The permanent application identity and Rust-only storage-path foundation are complete. The active stage is a Rust-only, side-effect-free first-time setup gate and missing-storage state model. SQLCipher remains a candidate, not the selected production database.

## 2. Authority and objective

Carlo approved the permanent identifier `io.github.cltubigon.churchapp`, production display name `Church App`, a dedicated standard Windows account, per-user local application-data storage, application-owned-directory-only production operation, future explicit setup-only database creation, no silent startup creation, and a future immutable random parish identifier. Carlo previously authorized a temporary Windows SQLCipher Community Edition feasibility proof and the documented future verified-restore condition. None of this authorizes production database creation or opening.

## 3. Locked operational decisions relevant to the initiative

- Future local parish data is authoritative and offline-capable; future central services are non-authoritative.
- Privileged data operations and encryption material belong in Rust, never React.
- Production paths are Rust-owned and fixed beneath the application-owned per-user local data directory; React cannot supply or receive them.
- Normal operation targets one dedicated standard Windows account without elevation.
- The approved recovery condition above is a product decision only; its design and implementation remain deferred.

## 4. Current repository baseline

The repository is a Tauri 2 foundation with four unavailable React areas, one non-sensitive Rust health command, typed Rust storage-path and identity foundations, and pure installation-state decisions. It has no production database, schema, authentication, recovery, backup, or parish workflow.

## 5. Candidate technical direction

Keep installation evidence, explicit in-memory setup authorization, and future storage opening as separate Rust-owned boundaries. Ordinary startup cannot authorize creation; initialized-but-missing storage fails closed instead of becoming first-time setup. Preserve the completed path foundation and `rusqlite` 0.39.0 SQLCipher feasibility evidence; SQLCipher remains only a candidate.

## 6. Active stage

First-time setup gate and missing-storage state model.

## 7. Allowed scope

Pure Rust installation evidence, structurally constrained in-memory setup authorization, missing-storage decisions, safe high-level categories, focused side-effect-free tests, and task-relevant documentation.

## 8. Prohibited scope

No filesystem inspection, installation-evidence persistence, production directory or database creation or opening, SQLCipher production connection, schema, migrations, authentication, password hashing, key management, recovery, backup, sessions, roles, drafts, UI, setup or database IPC command, installer, signing, release, or product workflow.

## 9. Dependency approvals

No new dependency is approved or required for this stage. The existing Windows-only dev dependency on exact `rusqlite` 0.39.0 with its exact bundled SQLCipher/vendored OpenSSL feature remains confined to the completed feasibility test.

## 10. Milestones

- [x] Record authority and narrow stage.
- [x] Select and lock one Windows candidate configuration.
- [x] Complete runtime encryption, wrong-key, native identity, artifact, and cleanup validation on the observed Windows 11 host.
- [x] Finalize the permanent application identifier and production display name.
- [x] Add Rust-only typed storage-path and storage-identity foundations without storage side effects.
- [x] Complete static validation for the production identity and storage-path foundation.
- [x] Add the Rust-only first-time setup authorization gate and fail-closed missing-storage decisions without side effects.
- [x] Complete static validation for the first-time setup gate and missing-storage state model.
- [ ] Complete manual Windows regression verification.
- [ ] Obtain senior Project Manager and Carlo approval before any production selection.

## 11. Discoveries

The selected feasibility crate embeds SQLCipher 4.10.0 Community based on SQLite 3.50.4 and locks vendored OpenSSL 3.6.3. Native source compilation materially increases clean-build time. Tauri's Rust-side local app-data resolver can model the canonical production location without creating or inspecting it. Pure evidence supplied by future Rust orchestration is sufficient to distinguish first use from initialized-but-missing storage without resolving a path.

## 12. Decisions and authority classifications

- Carlo-approved: permanent identifier and display name; dedicated standard Windows account; per-user application-data direction; application-owned-directory-only operation; explicit setup-only creation; no silent startup creation; immutable random parish identifier direction; temporary Windows SQLCipher feasibility; future verified restore condition.
- Implemented foundation: fixed Rust-owned path categories and filename, non-persisted identity representations, and pure initialization decisions. Explicit setup authorization is structurally represented in memory but performs no setup; ordinary startup cannot produce it.
- Technical experiment: exact bundled `rusqlite` configuration and test mechanics.
- Pending approval: production database engine and creation/opening flow, cryptography/key design, authentication, recovery and backup formats, distribution.

## 13. Validation status

Installation-state and storage-foundation focused tests, completed SQLCipher feasibility runtime, formatting, Clippy, full locked Rust tests, targeted searches, and repository diff checks pass on the observed Windows 11 host. Exact results belong in the task report. Manual Windows regression remains pending.

## 14. Manual testing status

Automated execution is limited to the observed Windows host. Windows 10 and independent manual desktop regression remain pending unless separately observed.

## 15. Completed work

SQLCipher feasibility history remains complete: repository baseline inspection, official-source review, configuration selection, dependency lock update, isolated test/documentation implementation, Windows 11 runtime proof, native artifact inspection, and focused/full Rust validation. The permanent identity and storage-path stage remains complete. The current stage adds only pure Rust initialization evidence, explicit in-memory setup authorization, fail-closed missing-storage behavior, and safe state categories.

## 16. Remaining risks

Installation-evidence protection and persistence, production setup orchestration, production engine suitability, creation/opening behavior, ACL and path hardening, key design, long-term patch cadence, clean-build cost, redistribution notices, legal review, other Windows architectures, Windows 10, macOS/Linux runtime behavior, and every production data/security design remain unresolved.

## 17. Next smallest safe step

After manual regression verification, define the smallest protected installation-evidence source and persistence contract for review, without creating the marker, registry entry, directory, or database and without adding setup or storage IPC.

## 18. Links

- [Project overview](docs/project-overview.md)
- [Architecture](docs/architecture.md)
- [Security and data](docs/security-and-data.md)
- [Product decisions](docs/product-decisions.md)
- [Verification](docs/verification.md)
- [SQLCipher Windows feasibility findings](docs/sqlcipher-windows-feasibility.md)
