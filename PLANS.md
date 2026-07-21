# Local Data, Encryption, Authentication, and Recovery Foundation

## 1. Initiative and status

Active multi-stage initiative. SQLCipher is a candidate under feasibility evaluation, not the selected production database.

## 2. Authority and objective

Carlo authorized a temporary Windows SQLCipher Community Edition and `rusqlite` feasibility proof of concept. Carlo also decided that, in a future verified cross-device restore, a valid unused recovery code plus its matching recovery file may establish a new primary-administrator password without the forgotten password. Neither authority approves production implementation.

## 3. Locked operational decisions relevant to the initiative

- Future local parish data is authoritative and offline-capable; future central services are non-authoritative.
- Privileged data operations and encryption material belong in Rust, never React.
- The approved recovery condition above is a product decision only; its design and implementation remain deferred.

## 4. Current repository baseline

The repository is a Tauri 2 foundation with four unavailable React areas and one non-sensitive Rust health command. It has no production database, schema, authentication, recovery, backup, or parish workflow.

## 5. Candidate technical direction

Evaluate `rusqlite` 0.39.0 with `bundled-sqlcipher-vendored-openssl` on pinned Rust 1.97.1 for x64 Windows MSVC. SQLCipher remains only a candidate.

## 6. Active stage

Windows feasibility and temporary encryption proof of concept.

## 7. Allowed scope

Exact dependency locking, a Windows-only temporary Rust test, native and license inspection, focused validation, and initiative/findings documentation.

## 8. Prohibited scope

No production database path, schema, migrations, authentication, password hashing, key management, recovery, backup, sessions, roles, drafts, UI, IPC database command, installer, signing, release, or product workflow.

## 9. Dependency approvals

Only SQLCipher Community Edition through exact `rusqlite` 0.39.0 with its exact bundled SQLCipher/vendored OpenSSL feature is approved for this temporary stage. No other future security or storage dependency is approved.

## 10. Milestones

- [x] Record authority and narrow stage.
- [x] Select and lock one Windows candidate configuration.
- [x] Complete runtime encryption, wrong-key, native identity, artifact, and cleanup validation on the observed Windows 11 host.
- [ ] Obtain senior Project Manager and Carlo approval before any production selection.

## 11. Discoveries

The selected crate embeds SQLCipher 4.10.0 Community based on SQLite 3.50.4 and locks vendored OpenSSL 3.6.3. Native source compilation materially increases clean-build time.

## 12. Decisions and authority classifications

- Carlo-approved: temporary Windows SQLCipher feasibility; future verified restore condition.
- Technical experiment: exact bundled `rusqlite` configuration and test mechanics.
- Pending approval: production database, cryptography/key design, authentication, recovery and backup formats, distribution.

## 13. Validation status

Focused runtime, formatting, Clippy, and full locked Rust tests pass on the observed Windows 11 host. See `docs/sqlcipher-windows-feasibility.md` and the task report for exact evidence and the vendored OpenSSL linker warning.

## 14. Manual testing status

Automated execution is limited to the observed Windows host. Windows 10 and independent manual desktop regression remain pending unless separately observed.

## 15. Completed work

Repository baseline inspection, official-source review, configuration selection, dependency lock update, isolated test/documentation implementation, Windows 11 runtime proof, native artifact inspection, and focused/full Rust validation.

## 16. Remaining risks

Production suitability, long-term patch cadence, clean-build cost, redistribution notices, legal review, other Windows architectures, Windows 10, macOS/Linux runtime behavior, and every production data/security design remain unresolved.

## 17. Next smallest safe step

Review the Windows evidence and obtain a new scoped decision before any production storage design; Windows 10 repetition is the smallest outstanding feasibility check.

## 18. Links

- [Project overview](docs/project-overview.md)
- [Architecture](docs/architecture.md)
- [Security and data](docs/security-and-data.md)
- [Product decisions](docs/product-decisions.md)
- [Verification](docs/verification.md)
- [SQLCipher Windows feasibility findings](docs/sqlcipher-windows-feasibility.md)
