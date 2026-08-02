# Approved Production Database Foundation: Documentation and Sequenced Implementation

## 1. Initiative and status

Active multi-stage initiative. Carlo has explicitly approved the bounded production database and evidence-correspondence architecture package, including the corrected `ApplicationDatabaseFormatIdentity` exactly-16-byte SQLite `BLOB` encoding. The Windows production SQLCipher dependency promotion and private raw-key application primitive are implemented and accepted. They are a narrow production-capable foundation only: no operational production database-opening, validation, startup, setup, schema, migration, backup, restore, recovery, replacement, or frontend flow exists. The accepted installation-evidence, local-volume, device-property, and controlled-host evidence remains unchanged.

## 2. Authority and objective

The active objective is to preserve the approved typed trust-chain sequence while recording the accepted Windows production dependency and raw-key primitive gate. The next implementation must remain separately scoped to the production database-open trust chain and must not introduce schema, migration, setup/startup integration, backup/restore, recovery, replacement, or frontend behavior.

## 3. Locked operational decisions relevant to the initiative

- Future local parish data is authoritative and offline-capable; future central services are non-authoritative.
- Privileged data operations and encryption material belong in Rust, never React.
- Production paths are Rust-owned and fixed beneath the application-owned per-user local data directory; React cannot supply or receive them.
- Ordinary Church App use may run under the current Windows account, and the process should run in a non-elevated session. Administrator-group membership need not be established for the accepted current-account evidence. A dedicated standard Windows account is optional and recommended for a parish-owned shared workstation, not an ordinary-use prerequisite. Elevation refusal is not yet implemented; this direction does not approve privileged or elevated ordinary operation.
- The approved recovery condition above is a product decision only; its design and implementation remain deferred.

## 4. Current repository baseline

The repository is a Tauri 2 foundation with four unavailable React areas, one non-sensitive Rust health command, typed Rust storage, evidence, key, metadata, correspondence, and freshness foundations, a Windows production SQLCipher dependency, and a private Windows-only raw-key application primitive. It has no operational production database-opening flow, schema, authentication, recovery, backup, or parish workflow.

## 5. Approved technical direction

Keep database-key ownership, metadata contracts, metadata decoding, correspondence, freshness, operating-system randomness, DPAPI protection, path validation, database inspection, key application, integrity, migrations, setup/startup decisions, recovery, and destructive authority as separate typed transitions. No earlier stage grants later authority. SQLCipher Community Edition is the approved production engine. The earlier feasibility module remains historical Windows test-only evidence; the accepted production dependency and private primitive are separate current implementation.

## 6. Active stage

The exact Windows production dependency promotion and private raw-key application primitive are complete and accepted. The larger production database-opening flow remains incomplete. The active next implementation stage must be a separately scoped database-open trust-chain task that composes an already-open production handle, trusted key recovery, the accepted key-application primitive, and later validation boundaries without adding schema or operational startup/setup authority.

## 7. Allowed scope

Documentation-only reconciliation of the accepted dependency and primitive state in `PLANS.md`, `docs/architecture.md`, `docs/product-decisions.md`, `docs/security-and-data.md`, and `docs/verification.md`. Existing installation-evidence decisions and repository safeguards remain unchanged.

## 8. Prohibited scope

This documentation reconciliation authorizes no code, dependency, SQL, schema or migration, database opening or VFS/path adapter, setup/startup/recovery integration, backup/restore, Tauri command, frontend change, generated inventory, application runtime, database creation, or destructive operation. The accepted dependency and primitive are recorded facts, not changes made by this documentation task.

## 9. Dependency approvals

The accepted Windows production dependency is exactly `rusqlite = { version = "=0.39.0", default-features = false, features = ["bundled-sqlcipher-vendored-openssl"] }` under `[target.'cfg(windows)'.dependencies]`. There is no Windows `rusqlite` development dependency and no direct `libsqlite3-sys` dependency. Metadata schema creation, migrations, remaining database-open orchestration, key and recovery persistence, freshness-anchor operational integration, backup/restore, setup/startup/recovery authority, replacement, retention, and cleanup each require separately scoped approval.

## 10. Milestones

- [x] Record authority and narrow stage.
- [x] Select and lock one Windows candidate configuration.
- [x] Complete runtime encryption, wrong-key, native identity, artifact, and cleanup validation on the observed Windows 11 host.
- [x] Finalize the permanent application identifier and production display name.
- [x] Add Rust-only typed storage-path and storage-identity foundations without storage side effects.
- [x] Complete static validation for the production identity and storage-path foundation.
- [x] Add the Rust-only first-time setup authorization gate and fail-closed missing-storage decisions without side effects.
- [x] Complete static validation for the first-time setup gate and missing-storage state model.
- [x] Add the platform-neutral logical installation-evidence contract and pure structural validation.
- [x] Complete static validation for installation-evidence contract types.
- [x] Reconcile and approve the corrected 152-byte payload and 164-byte total encoding layout.
- [x] Add deterministic version-1 encoding and a synthetic golden fixture without a dependency.
- [x] Add strict version-1 parsing into a distinct parsed-but-untrusted type with dedicated parse errors and a separate structural-validation transition.
- [x] Add dependency-free deterministic malformed-input hardening across all 164 byte positions, field boundaries, wrong lengths, representative patterns, and two-byte framing mutations.
- [x] Evaluate fuzzing architecture and defer execution because the approved Windows tooling is not available in the current foundation.
- [x] Add strict dependency-free parsing for the fixed 226-byte version-1 authenticated-envelope framing into a parsed-but-untrusted type only.
- [x] Add the Rust-owned 32-byte evidence-authentication-key type with redacted debug and manual drop zeroization.
- [x] Add full HMAC-SHA-256 construction over exact bytes `0..194` and verification through the HMAC crate API.
- [x] Add the cryptographically authenticated envelope boundary and authenticated-only release to the existing plaintext parser.
- [x] Add deterministic mutation coverage for all 226 envelope positions with framing-versus-authentication classification.
- [x] Add deterministic wrong-key, wrong-length, representative-pattern, boundary, and two-byte mutation corpora.
- [x] Add correctly retagged malformed-plaintext cases and an alternate canonical authenticated-plaintext path through structural validation.
- [x] Preserve production protocol bytes and APIs without change; no concrete defect was found.
- [x] Add independent operating-system-backed generation of one 32-byte owned key and one nonzero 16-byte key-generation identifier.
- [x] Fail closed on randomness errors and after three all-zero identifier fill attempts, without deterministic fallback.
- [x] Preserve best-effort authentication-key zeroization and keep generation separate from envelopes, DPAPI, persistence, setup, startup, IPC, and frontend state.
- [x] Add deterministic generation and failure tests plus a real operating-system randomness smoke test.
- [x] Add separate in-memory current-user DPAPI protection for authentication material and authenticated evidence.
- [x] Add the exact 14-byte wrapper and exact 49-byte key payload with strict parsing and coarse errors.
- [x] Clear native unprotected output before `LocalFree` and confine unsafe code to one Windows adapter.
- [x] Require authenticated generation matching before plaintext release.
- [x] Add deterministic codec/orchestration tests and same-user Windows DPAPI smoke tests.
- [x] Complete the accepted manual Windows application regression for the preceding DPAPI stage.
- [x] Add exhaustive 14-byte wrapper-header mutation plus bounded length, truncation, trailing-data, pattern, boundary, and opaque-blob corpora.
- [x] Add exhaustive 49-byte protected-key payload mutation plus wrong-length, pattern, boundary, clearing, and outcome-classification corpora.
- [x] Add fake-protector malformed-output, wrong-kind, key-first ordering, redaction, and authenticated-malformed-plaintext coverage.
- [x] Add first, midpoint, and final-byte real DPAPI corruption coverage for both protected objects through the complete recovery chain.
- [x] Preserve production formats, APIs, DPAPI behavior, and dependencies; no concrete production defect was found.
- [x] Complete manual review and Windows application regression for the DPAPI malformed-input hardening stage.
- [x] Add the pure persistence foundation: canonical fixed names, synthetic typed paths, bounded reader, typed presence classifier, publication state machines, and deterministic tests.
- [x] Add the Windows-only filesystem binding compile preflight without invoking a native API or touching the filesystem.
- [x] Add the Windows-only single authentication-key-wrapper temporary publication proof with create-new staging, flush, independent bounded reload and canonical validation, no-replace initial publication, active reload, sentinel preservation, and exact test-root teardown.
- [x] Add the Windows-only existing-file replacement proof with independent old-active and new-stage validation, all ordinary handles closed before the locked null-backup/zero-flag `ReplaceFileW` call, fresh exact-name inspection after every return, file-identity continuity, sentinel preservation, one-shot sharing failures, and pure special-code simulation.
- [x] Accept the existing-file replacement proof without changing its locked publication behavior.
- [x] Add the Windows-test-only normal-tree handle and path hardening proof with component opens, retained directory handles, reject-all reparse policy, full `FILE_ID_INFO`, normalized volume-GUID component comparison, wrapper-only single-link enforcement, same-volume checks, and before/after bounded-read revalidation.
- [x] Add the Windows-test-only real hard-link fixture for both authentication-key wrapper names, including shared full identity and bytes, distinct final paths, exact-name and single-link rejection, pre-read/pre-mutation ordering, alias-only restoration, sentinel preservation, and exact teardown.
- [x] Add one Windows-test-only exact evidence-directory substitution proof: retain the target handle to block rename; close the target and descendant handles; keep temporary/root/intermediate handles; move the original to `evidence-displaced.synthetic`; move `substitute-candidate.synthetic` into exact `installation-evidence`; prove byte-identical canonical wrappers cannot override full directory-identity discontinuity; and reject before any continuation, publication, replacement, or wrapper mutation.
- [x] Add one Windows-test-only retained evidence-directory replacement compatibility case: close every active/stage leaf handle, retain only the exact evidence-directory handle with the approved access and sharing, revalidate that same handle before and immediately after the unchanged one-shot replacement and again after fresh child inspection, and reuse the existing child-state classifier.
- [x] Accept the evidence-directory retention replacement compatibility proof.
- [x] Add one private Windows-test-only local-volume classifier and one unique temporary-root runtime observation using strict retained-handle volume-GUID evidence, an exact derived root, one `GetDriveTypeW` call, and fail-closed coarse facts.
- [x] Add one private Windows-test-only device-property classifier and controlled-host runtime observation using the retained-root-derived volume device, one bounded two-call storage-property query, strict raw descriptor parsing, and non-authoritative `DevicePropertyCandidate`.
- [x] Add the private Windows-test-only current-account baseline and manually rooted USB-flash controlled-host harness for exactly two cases, with redacted evidence, exact fixture scope, and no discovery.
- [x] Complete the current Windows 11 non-elevated baseline observation. Two manually rooted USB runtime attempts later ran: the first failed broadly during hardened child-directory validation before its first drive-type query, and the accepted diagnostic rerun identified `DirectoryAttributeInfoUnavailable` with disposition `Unavailable`. Neither attempt produced a local-volume or device-property classification.
- [x] Add a private controlled-host-only first-failed-stage diagnostic after the supplied USB observation failed during hardened child-directory validation before drive-type classification. The accepted shared hardening helper and classifiers remain unchanged.
- [x] Record the accepted diagnostic USB observation: prerequisite present; zero drive-type, volume-open, property-IOCTL, and hot-plug calls; sentinel verification not reached; exact-root cleanup attempted and succeeded; every authority field false; and the manual leftover-folder check found no entries. The USB row remains failed and incomplete.
- [x] Record Carlo's explicit approval of the bounded production database and evidence-correspondence architecture package.
- [x] Implement the separately approved pure database-key secret-owner and metadata contract types.
- [x] Add the separately approved pure metadata decoding and validation tests.
- [x] Add the separately approved pure correspondence and freshness models.
- [x] Promote exact pinned `rusqlite` 0.39.0 with only `bundled-sqlcipher-vendored-openssl` into Windows production dependencies, with no Windows `rusqlite` development dependency or direct `libsqlite3-sys` dependency.
- [x] Add and accept the private Windows-only raw-key application primitive over `&GenerationBoundDatabaseKey`, with exact fixed encoding, one `sqlite3_key` call, `SQLITE_OK`-only success, and coarse failure.
- [ ] Separately scope and implement the production database-open trust chain without schema or startup/setup integration.

## 11. Discoveries

The accepted plaintext remains exactly 164 bytes. The envelope layout is a 30-byte header, unchanged plaintext at `30..194`, and the full 32-byte HMAC-SHA-256 tag at `194..226`. The exact authentication-input region is `0..194`; the tag is excluded from its own computation. Version 1 has no nonce, salt, padding, reserved bytes, extension area, negotiation, fallback, or trailing data.

Zeroization is best effort for the type's owned 32-byte buffer. It does not remove prior caller copies, compiler-created temporaries, register or stack spills, HMAC-state copies, swap, hibernation, crash dumps, debugger snapshots, or microarchitectural leakage.

The key and generation identifier use separate `getrandom::fill` calls. An all-zero identifier is rejected through the existing identifier constructor and retried up to three total identifier fill attempts. General randomness errors are not retried and expose no provider or operating-system detail.

The protected wrapper is exactly 14 header bytes plus an opaque DPAPI blob: `CHDPAPI\0`, version 1, object kind, and a big-endian `u32` blob length capped at 65,536. The key plaintext is exactly 49 bytes: version 1, the nonzero 16-byte key-generation identifier, and the 32-byte key. DPAPI uses current-user scope, `CRYPTPROTECT_UI_FORBIDDEN`, no optional entropy, and no description. Unprotected native output is best-effort cleared before its single `LocalFree`; this is not a perfect-erasure claim.

The installed `windows-sys 0.61.2` bindings expose the approved filesystem surface through `Win32_Storage_FileSystem`; the existing cryptography feature supplies the parent security gate required by `CreateFileW`. The accepted compile preflight and initial-publication proof remain intact. The replacement proof exercises one synthetic authentication-key wrapper only. A nonzero return is accepted only with fresh canonical replacement bytes at the active name, stage absence, exact final path, stage-to-result file-ID continuity, old/result identity distinction, and sentinel preservation. Simulated special failure families validate orchestration/classification only and do not prove that Windows produces those states on the host.

On the observed Windows host, the exact evidence-directory target required a test-only read-access handle without delete sharing to make `std::fs::rename` refuse while the handle remained live. After all target, descendant, and duplicate handles closed, the two approved renames succeeded while temporary/root/intermediate handles remained retained. The displaced directory preserved the saved original full identity; the exact path reopened with the saved candidate identity and byte-identical canonical wrapper; the identity mismatch was decisive and the injected continuation count remained zero.

On the observed Windows host, the exact evidence-directory handle using `GENERIC_READ`, `FILE_SHARE_READ | FILE_SHARE_WRITE`, no delete sharing, backup semantics, and open-reparse-point semantics remained compatible with the accepted child `ReplaceFileW` call. Full leaf closure preceded the call. The same retained handle preserved its full directory identity, normalized volume-GUID path, directory/disk/reparse facts, and saved-parent volume relationship before the call, immediately after it, and after fresh child inspection; the existing classifier reported active-new/stage-absent with the accepted leaf identity checks.

On the observed Windows host, a retained validated handle to one unique temporary test root produced a strict normalized volume-GUID final path. The exact volume root derived from that path was queried once through `GetDriveTypeW`; the private documented numeric mapping reported the fixed category, and the classifier produced only non-authoritative `LocalFixedCandidate`. Remote, removable, unsupported, malformed, inconsistent, unknown, no-root, and unavailable cases fail closed. This adds no Cargo feature and no removable-media, hot-plug, device-topology, production, setup, startup, persistence, publication, replacement, database, DPAPI, IPC, or frontend authority.

On the observed Windows host, the accepted `LocalFixedCandidate` prerequisite and retained root handle yielded the exact volume-GUID device name. One access-zero, read/write-shared volume open succeeded, followed by exactly one descriptor-header and one bounded full-descriptor `IOCTL_STORAGE_QUERY_PROPERTY` call. The installed binding layout version matched, the descriptor was non-removable, its bus was in the approved candidate family, and the private classifier reported only `DevicePropertyCandidate`. No hot-plug query ran. This observation does not prove device non-removability, internal placement, physical locality, virtual or remote backing absence, durability, production suitability, or any application authority.

## 12. Decisions and authority classifications

- Carlo-approved: permanent identifier and display name; current-account, non-elevated ordinary-use direction with a dedicated standard Windows account optional and recommended for a parish-owned shared workstation; per-user application-data direction; application-owned-directory-only operation; explicit setup-only creation; no silent startup creation; immutable random parish identifier direction; temporary Windows SQLCipher feasibility; future verified restore condition; and the bounded SQLCipher Community Edition production database, independent database-key, metadata, correspondence, freshness, opening, integrity, path/sidecar, journal/durability, migration, support, redaction, and authority-separation package.
- Implemented foundation: all previously accepted foundations plus operating-system-backed authentication-material generation, HMAC-SHA-256 envelope authentication, current-user in-memory DPAPI protection for separate key and evidence objects, strict wrapper and key-payload codecs, native clear-before-free handling, and a typed generation-match transition before plaintext release. Protection remains separate from persistence, structural validation, database cross-checking, setup, startup, and operational evidence.
- Historical technical experiment: `sqlcipher_windows_feasibility` and its former development-dependency state remain Windows test-only evidence of the earlier candidate evaluation.
- Implemented and accepted production foundation: the exact Windows production `rusqlite` configuration and the private raw-key application primitive. The primitive accepts only a generation-bound database key and an already-open caller-supplied handle; it does not provide an operational database-opening workflow.
- Approved but not fully implemented: the larger bounded architecture package. Deferred implementation includes database-open orchestration and validation, metadata schema creation, portable recovery, operational freshness integration, migrations, backup/restore, setup/startup/recovery authority, replacement, destructive retention or cleanup, and release automation.
- Separate approval/scoping still required: the production database-open trust chain; metadata schema creation; portable recovery envelope; migrations; backup/restore; setup/startup/recovery authority; database or anchor replacement; and destructive retention or cleanup.

## 13. Validation status

The accepted earlier proofs remain recorded in history. The Windows dependency promotion and raw-key primitive passed clean CI at commit `58e903bf7f1ac186a5172a8be96a5d5cf66d8b58`. Accepted local validation covers the exact manifest and private-module contract, fixed raw-key encoding and redaction, owned-buffer zeroization, one-call success and failure classification, null-handle refusal, full Rust regressions, source exclusions, and repository checks. This evidence does not include manual operational database opening or runtime database behavior. The accepted controlled-host evidence remains unchanged; the USB row remains failed and incomplete.

## 14. Manual testing status

The DPAPI hardening manual Windows application regression remains accepted. The current baseline observation used exactly: `Current Windows account, non-elevated session; administrator-group membership not established.` It is not evidence of dedicated-standard-account execution or administrator-group membership. Windows 10 and a successful manually selected USB flash observation remain pending. Two manually rooted USB attempts have run; the accepted diagnostic rerun stopped at unavailable directory attribute/tag information before classification, cleaned its exact root successfully, and left no entry in the manual leftover-folder check.

## 15. Completed work

All prior completed history remains accepted. The current production SQLCipher foundation now includes the exact Windows production `rusqlite` promotion and the private `sqlcipher_database_key_application` module. Its 67-byte owner encodes a 32-byte generation-bound key as lowercase `x'<64 hex characters>'`, invokes `sqlite3_key` exactly once for a non-null caller-supplied already-open handle, accepts only `SQLITE_OK`, clears its owned encoded buffer best-effort, and otherwise returns only `DatabaseKeyApplicationError::Failed`. It has no active caller, Tauri command, frontend, IPC, database-open, query, inspection, mutation, rekey, close, startup, or setup behavior.

## 16. Remaining risks

The accepted raw-key primitive does not establish handle provenance, key correctness, database readability, encryption, metadata validity, integrity, correspondence, freshness, startup authorization, or operational authority. No production database is selected or opened; the key is not applied through startup or setup; SQLite metadata reads, SQLCipher integrity checks, first-time creation, schema, migrations, backup, restore, recovery, replacement, and frontend/Tauri exposure remain absent. The existing controlled-host risks also remain: no successful USB observation exists, no filesystem-format or hardware cause is established, and the deferred host/storage matrix and production integration remain separate stages. Test-root teardown is not production cleanup.

## 17. Next smallest safe step

After Carlo reviews this reconciliation, separately scope the production database-open trust-chain task. It should compose the already implemented production-file inspection and trusted key-recovery boundaries with one controlled database connection open, the accepted raw-key primitive, and later SQLite/SQLCipher validation boundaries. It must remain distinct from schema creation, migrations, first-time database creation, operational setup/startup authorization, backup/restore, recovery, replacement, Tauri commands, and frontend exposure.

## 18. Links

- [Project overview](docs/project-overview.md)
- [Architecture](docs/architecture.md)
- [Security and data](docs/security-and-data.md)
- [Product decisions](docs/product-decisions.md)
- [Verification](docs/verification.md)
- [SQLCipher Windows feasibility findings](docs/sqlcipher-windows-feasibility.md)
