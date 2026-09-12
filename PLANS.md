# Approved Production Database Foundation: Documentation and Sequenced Implementation

## 1. Initiative and status

Active multi-stage initiative. Carlo has explicitly approved the bounded production database and evidence-correspondence architecture package, including the corrected `ApplicationDatabaseFormatIdentity` exactly-16-byte SQLite `BLOB` encoding. The Windows production SQLCipher dependency, private raw-key primitive, metadata-only production database-file inspection, guarded read-only SQLCipher connection handoff, consuming validation and authorization chain, Rust-owned application-startup lifecycle, explicit first-time setup lifecycle, minimal production V1 metadata/bootstrap schema, and private unwired full-integrity validation boundary are implemented and accepted through the current repository state. The repository still has no migration, backup, restore, recovery, replacement, authentication, parish workflow, parish/business schema, or general writable database-operation interface. This accepted foundation does not make the full product launch-ready. The accepted installation-evidence, local-volume, device-property, and controlled-host evidence remains otherwise unchanged.

## 2. Authority and objective

The active documentation objective is to lock the product-level maintenance authorization trigger policy and initial operation taxonomy. The local human operator physically using Church App under the dedicated Church App production Windows account is the maintenance-authorizing actor, but authority exists only after an explicit interactive maintenance confirmation initiated from the application. This is an authorization and consent boundary, not application-level identity authentication. Production database migration is the sole initial maintenance authorization identity; no generic maintenance-operation enum or broad generic maintenance-authorization capability is approved. The policy is documentation only: maintenance execution, authentication, backup/restore, writable database access, migration, schema V2, parish/business schema, IPC, UI design, and the Rust capability design remain separate and unimplemented.

## 3. Locked operational decisions relevant to the initiative

- Future local parish data is authoritative and offline-capable; future central services are non-authoritative.
- Privileged data operations and encryption material belong in Rust, never React.
- Production paths are Rust-owned and fixed beneath the application-owned per-user local data directory; React cannot supply or receive them.
- Production normal operation uses one dedicated standard Windows account for Church App, and the process should run in a non-elevated session. Historical current-account test evidence does not establish dedicated-account execution or administrator-group membership. Elevation refusal is not yet implemented; this direction does not approve privileged or elevated ordinary operation.
- The approved recovery condition above is a product decision only; its design and implementation remain deferred.

## 4. Current repository baseline

The repository is a Tauri 2 foundation with four unavailable React areas, one non-sensitive Rust health command, read-only coarse `startup_status`, one narrow argument-free `request_first_time_setup` command, typed Rust storage and trust-chain foundations, and accepted Rust-owned startup, setup, and orderly-shutdown lifecycles. The application window appears immediately in a non-ready state. `Ready` is installed only in a fresh process after the normal startup trust chain authorizes and activates a real `OperationalProductionDatabase`; successful setup instead reports restart-required. React remains non-authoritative. The implemented database schema is only the minimal production V1 metadata/bootstrap contract, not a parish/business schema. Authentication, migration, recovery, backup/restore, replacement, parish workflows, and general writable database operations remain absent.

## 5. Approved technical direction

Keep database-key ownership, metadata contracts, metadata decoding, correspondence, freshness, operating-system randomness, DPAPI protection, path validation, database inspection, key application, integrity, migrations, setup/startup decisions, recovery, and destructive authority as separate typed transitions. No earlier stage grants later authority. SQLCipher Community Edition is the approved production engine. The earlier feasibility module remains historical Windows test-only evidence; the accepted production dependency and private primitive are separate current implementation.

## 6. Active stage

The guarded read-only SQLCipher startup chain, operational activation, explicit first-time setup, encrypted database creation, minimal V1 metadata/bootstrap initialization, and private unwired full-integrity validation boundary are implemented and accepted. Migration is the next genuinely unimplemented gated storage stage, but this documentation reconciliation does not approve its implementation. Future parish/business schema work, recovery, replacement, backup/restore, authentication, parish workflows, release validation, and any broader database-operation interface also remain unimplemented. Startup has no setup, migration, full-integrity, repair, recovery, or reset fallthrough.

## 7. Allowed scope

Documentation-only recording of the approved maintenance authorization trigger policy, initial operation taxonomy, and the directly related dedicated-account correction, limited to `PLANS.md`, `docs/architecture.md`, `docs/product-decisions.md`, `docs/security-and-data.md`, and `docs/verification.md`. Code and repository safeguards remain unchanged.

## 8. Prohibited scope

This documentation work authorizes no code, test, dependency, configuration, workflow, maintenance execution, authentication, new schema or migration, SQL or PRAGMA change, writable database access, freshness redesign, recovery integration, backup/restore, replacement, new Tauri command or IPC, frontend change, generated inventory, application runtime change, header mutation, or destructive operation. It does not define a Rust representation for the migration-specific authority, a generic maintenance-operation enum, a broad generic maintenance-authorization capability, migration source/target versions, schema V2, IPC shape, UI wording or dialog design, authentication roles, backup implementation, writable maintenance owner, or migration execution.

## 9. Dependency approvals

The accepted Windows production dependency is exactly `rusqlite = { version = "=0.39.0", default-features = false, features = ["bundled-sqlcipher-vendored-openssl"] }` under `[target.'cfg(windows)'.dependencies]`. There is no Windows `rusqlite` development dependency and no direct `libsqlite3-sys` dependency. The minimal V1 metadata/bootstrap schema and first-time setup are implemented. Migration, parish/business schema, recovery authority, backup/restore, replacement, retention, cleanup, and broader operational database APIs each require separately scoped approval.

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
- [x] Implement and accept the guarded read-only SQLCipher connection handoff without validation, schema, or startup/setup integration.
- [x] Implement and accept the database readability-and-integrity validation transition over the opaque keyed-but-unvalidated owner using only `PRAGMA cipher_integrity_check` followed by `PRAGMA main.quick_check(1)`.
- [x] Approve and canonically document, without implementing, the next live metadata and SQLite-header observation architecture.
- [x] Implement and accept the live metadata and SQLite-header validation transition over the opaque readability-and-integrity-validated owner.
- [x] Approve and canonically document the identity-only database/evidence correspondence adapter.
- [x] Implement and accept the identity-only database/evidence correspondence transition over the live metadata/header owner and trusted current-installation assessment.
- [x] Approve and canonically document the preloaded normalized database-freshness composition boundary.
- [x] Implement and verify the preloaded normalized database-freshness composition boundary.
- [x] Implement and verify the internal startup-authorization boundary after freshness.
- [x] Implement, manually exercise, stage-review, and accept the Rust-owned operational application-startup lifecycle and orderly-shutdown integration.
- [x] Implement the minimal production V1 metadata/bootstrap schema and encrypted `parish-data.db` creation path.
- [x] Implement and wire the explicit first-time setup lifecycle through the narrow `request_first_time_setup` Tauri command.
- [x] Validate setup through final active artifacts and require a fresh-process restart before operational startup can reach `Ready`.
- [x] Complete the accepted Windows debug end-to-end setup/startup observation from marker-only isolated root through `Unavailable`, explicit setup, restart-required, and fresh-process `ready_installed`.
- [x] Implement and accept the private, consuming, currently unwired full-integrity transition from `ReadabilityAndIntegrityValidatedProductionDatabaseConnection` to `FullIntegrityValidatedProductionDatabaseConnection`.
- [x] Document and lock the product-level maintenance authorization trigger policy and initial migration-specific taxonomy without implementing them.
- [ ] Separately approve the migration prerequisites and exact migration design; no migration implementation is authorized by this plan state.

## Implemented first-time setup and minimal V1 bootstrap

Explicit first-time setup is implemented as a Rust-owned authority and lifecycle distinct from ordinary startup. The narrow argument-free `request_first_time_setup` command may begin setup only when the canonical installation observation follows the accepted `NeverInitialized` path. Setup creates the encrypted production `parish-data.db`, initializes only the minimal production V1 metadata/header bootstrap contract, validates the database, prepares and publishes the protected installation artifacts under the existing evidence/freshness/key rules, performs final active verification, and completes as restart-required.

Setup completion never installs `Ready` and never turns the setup process into an operational startup process. A fresh process must run the ordinary read-only startup trust chain, including its currently implemented startup integrity checks, before `Ready` may be installed. The V1 bootstrap is not a parish/business schema: there are no parish workflow tables, and broad product “schema creation” remains incomplete.

Migration is the next unimplemented gated storage stage. It is not approved for immediate implementation and cannot inherit authority from setup or startup. Before any migration implementation is separately approved, planning must resolve at least:

- the exact approved target schema and version;
- explicit maintenance authorization;
- a verified recoverable encrypted backup;
- approved composition and completed use of the implemented full-integrity validation capability at the migration boundary;
- a separately approved writable maintenance connection and owner;
- forward-only version-transition rules and downgrade refusal;
- interruption and restart classification;
- exact ordering for metadata, `user_version`, evidence, freshness, and lineage updates;
- migration concurrency and exclusivity;
- close-failure ownership; and
- proof that migration cannot become a startup or setup fallback.

The reusable full-integrity transition now exists, but its composition with the other migration prerequisites remains unresolved and unimplemented. The boundary alone grants no migration or maintenance authorization, verified recoverable backup, writable maintenance ownership, migration exclusivity, target schema/version, interruption/restart policy, or update ordering. It does not decide whether future maintenance must repeat cipher-integrity validation before mutation. This plan records prerequisite categories only. It does not define schema V2, parish/business tables, migration SQL, or the detailed designs and policies needed to satisfy those gates.

## 11. Implemented readability-and-integrity boundary

The implemented transition consumes `ProductionReadOnlyDatabaseConnection` and performs exactly this sequence on its same privately owned connection: run `PRAGMA cipher_integrity_check`; require normal end-of-stream with zero rows; run `PRAGMA main.quick_check(1)`; require exactly one SQLite `TEXT` row whose complete value is exactly `ok`; require normal end-of-stream after that row; and return a new opaque readability-and-integrity-validated production connection owner. No separate readability query exists. This stage does not read `sqlite_master`, metadata tables, `application_id`, `user_version`, product tables, or arbitrary content, and it exposes no unrestricted SQL.

Success is represented only by possession of the new opaque validated owner. The consuming transition retains the same `rusqlite::Connection`, `ConnectionLifetimeWriteGuard`, and `InspectedProductionDatabaseFile` lifetime unit. The validated owner exposes only consuming explicit close and later separately approved fixed consuming transitions. It establishes no metadata table existence, metadata row validity, SQLite `application_id`, SQLite `user_version`, schema-contract validity, database/evidence correspondence, freshness, startup/setup authority, migration authority, recovery authority, backup/restore authority, or operational database use.

The canonical coarse validation categories are `EncryptedDatabaseAuthenticationOrCipherIntegrityFailed`, `SQLiteReadabilityOrIntegrityFailed`, `ValidationUnavailable`, and `ValidationInterruptedOrIncomplete`. The first returned cipher diagnostic row establishes failure; its text is not decoded, copied, formatted, retained, or logged, and later diagnostic rows need not be consumed. The row stream must be dropped or reset before close. Cipher success requires normal zero-row completion. Quick-check success requires exactly the one complete text value `ok` and normal completion; zero rows, multiple rows, non-text output, non-`ok` output, stepping errors, interruption, malformed shape, or premature termination fail closed. `quick_check` is not full `integrity_check` and proves only its limited SQLite invariants.

No active cancellation API or rusqlite hooks feature is part of this stage. No validation succeeds without its complete required terminal result; interruption, statement failure, malformed result shape, or premature termination maps to a coarse fail-closed result. Both operations run sequentially on the same connection while the existing guard and inspection proof remain retained and query-only, defensive mode, and read-only opening remain active. No explicit SQLite transaction is added, and no stronger snapshot guarantee is claimed beyond that guarded same-connection lifetime.

On validation failure, explicit close is attempted after the row stream and statement are released. Close success returns the primary coarse validation category. Close failure preserves that already determined category together with an opaque close-retry owner containing the complete connection, guard, and inspection-proof lifetime unit. Neither validation nor close outcomes retain or expose SQL or PRAGMA text, result diagnostics, paths, keys, identifiers or identities, SQLite/native codes, raw handles, or rusqlite errors or chains.

Carlo accepts that `cipher_integrity_check` may synchronously scan the whole file with work proportional to database pages. This stage introduces no production database-size ceiling and makes no bounded-latency or active-cancellation claim. The accepted lifecycle runs it on the blocking startup worker rather than the UI/event loop; this does not bound worker duration or eliminate shutdown drain time.

The succeeding live metadata/header, correspondence, preloaded normalized freshness, startup-authorization, operational-activation, and lifecycle transitions are implemented as described below. The separate setup path now creates and validates the minimal V1 metadata/bootstrap database. Migration, parish/business schema, recovery, replacement, backup/restore, authentication, parish workflows, broader frontend/database IPC, and final release approval remain separately scoped work.

The separately implemented private full-integrity transition consumes `ReadabilityAndIntegrityValidatedProductionDatabaseConnection`, retains its existing guarded connection lifetime, runs only fixed `PRAGMA main.integrity_check`, and returns `FullIntegrityValidatedProductionDatabaseConnection` only after exactly one SQLite `TEXT` row exactly equal to `ok` followed by normal completion. Malformed, unavailable, interrupted, incomplete, zero-row, extra-row, non-`TEXT`, and non-`ok` outcomes fail closed. Explicit close and ownership-bearing close retry are preserved, and no connection, arbitrary SQL, path, key, metadata, diagnostic text, raw handle, or backend error is exposed. The transition has no production caller and is not wired into startup, setup, application lifecycle, migration, backup, restore, recovery, IPC, or frontend. Ordinary startup remains the cipher-integrity plus `quick_check(1)` sequence above; setup remains unchanged.

## 12. Implemented live metadata and SQLite-header validation boundary

The implemented consuming transition starts from `ReadabilityAndIntegrityValidatedProductionDatabaseConnection` and performs only this first-failed-stage sequence: prepare and fully observe `PRAGMA main.application_id`; require one result column, exactly one row, SQLite `INTEGER`, signed-32-bit representability, and normal terminal completion; compare with `0x43484150` and fail immediately with `WrongApplicationId` on mismatch; then apply the same strict shape policy to `PRAGMA main.user_version` and retain that value temporarily. It next prepares and executes exactly this fixed query:

```sql
SELECT
    singleton_id,
    metadata_contract_version,
    database_schema_version,
    permanent_application_identifier,
    database_format_identity,
    parish_identifier,
    installation_identifier,
    installation_generation,
    recovery_replacement_generation,
    database_key_generation_identifier,
    setup_publication_identifier,
    database_created_at
FROM main.church_app_database_metadata
LIMIT 2
```

The statement must expose exactly 12 result columns. Normal zero-row completion is `MetadataRowMissing`. The first row's values are copied into a private owned raw observation before stepping again. A second row is `DuplicateMetadataRows`; normal completion after the first proves exactly one row; a step failure is `MetadataObservationInterruptedOrIncomplete`. `LIMIT 2` is approved because it distinguishes zero, exactly one, and more than one row without unbounded enumeration. The query never filters on `singleton_id = 1`, because that could hide additional noncanonical rows.

The live adapter preserves exact storage classes only: `INTEGER` becomes `Integer(i64)`; `TEXT` undergoes strict UTF-8 validation before `Text(&str)`; `BLOB` becomes `Blob(&[u8])`; `NULL` becomes `Null`; and `REAL` is `MalformedMetadata`. It constructs one `RawDatabaseMetadataRow`, invokes `parse()` exactly once, invokes `validate_structure()` exactly once, then compares the validated metadata `database_schema_version` with the observed `user_version`. Equality returns the opaque `LiveMetadataAndHeaderValidatedProductionDatabaseConnection`. No other query, PRAGMA, schema introspection, dynamic SQL, cast, `typeof()`, or arbitrary content access is implemented or approved.

The canonical primary categories are `HeaderObservationUnavailable`, `WrongApplicationId`, `MetadataObservationUnavailable`, `MetadataObservationInterruptedOrIncomplete`, `MetadataRowMissing`, `DuplicateMetadataRows`, `MalformedMetadata`, `UnsupportedMetadataContractVersion`, `UnsupportedDatabaseSchemaVersion`, and `UserVersionMismatch`. `CloseFailed` is an ownership-bearing result, not a primary category. Correctly represented metadata contract or schema versions other than 1 map to their respective unsupported category; wrong storage class or parse range is malformed; a wrong fixed application ID has its dedicated category; and supported validated metadata that disagrees with `user_version` is `UserVersionMismatch`. Unsupported versions precede the user-version comparison. There is no automatic repair, assignment, normalization, or fallback.

The exact precedence is: application-ID observation unavailable; wrong application ID; user-version observation unavailable; metadata preparation/query-startup unavailable; metadata stepping interruption or incomplete terminal state; missing row; duplicate rows; malformed storage class, UTF-8, parse, or non-version structural state; unsupported metadata contract version; unsupported database schema version; remaining structural invalidity as malformed; then user-version mismatch. Observation stops at the first failure and never collects or exposes multiple defects.

The success owner privately retains the unchanged `ConnectionLifetimeOwner` and one owned `DatabaseMetadataContractV1`; it does not retain `application_id` or `user_version` separately. It exposes only consuming explicit close and later separately approved fixed consuming transitions. The implementation resides in a sealed private child module beneath `production_database_connection_handoff`; it does not widen the visibility of the lifetime owner, connection, guard, inspection proof, or close helpers and introduces no generic connection callback or crate-root sibling bridge.

Every primary failure releases `Rows` and `Statement`, discards temporary header values, raw observations, parsed metadata, and partially validated metadata, then explicitly closes. Close success returns the primary category. Close failure retains that same category plus the full connection/guard/inspection lifetime unit across consuming retries. Explicit close of the successful live-metadata owner first discards its retained metadata contract; close failure then retains only the full connection/guard/inspection lifetime unit.

Production reads only the already-existing named relation. Accepted tests create synthetic schemas, rows, and header values before the guarded read-only transition, but no production schema creation, header mutation, migration, repair, normalization, or mutation is authorized. Absence fails closed. This stage validates neither physical DDL, constraints, indexes, triggers, object kind, the wider product schema, correspondence, freshness, startup authorization or operational activation, setup completion, migration status, recovery, backup/restore suitability, replacement authority, nor business data.

## 13. Discoveries

The accepted plaintext remains exactly 164 bytes. The envelope layout is a 30-byte header, unchanged plaintext at `30..194`, and the full 32-byte HMAC-SHA-256 tag at `194..226`. The exact authentication-input region is `0..194`; the tag is excluded from its own computation. Version 1 has no nonce, salt, padding, reserved bytes, extension area, negotiation, fallback, or trailing data.

Zeroization is best effort for the type's owned 32-byte buffer. It does not remove prior caller copies, compiler-created temporaries, register or stack spills, HMAC-state copies, swap, hibernation, crash dumps, debugger snapshots, or microarchitectural leakage.

The key and generation identifier use separate `getrandom::fill` calls. An all-zero identifier is rejected through the existing identifier constructor and retried up to three total identifier fill attempts. General randomness errors are not retried and expose no provider or operating-system detail.

The protected wrapper is exactly 14 header bytes plus an opaque DPAPI blob: `CHDPAPI\0`, version 1, object kind, and a big-endian `u32` blob length capped at 65,536. The key plaintext is exactly 49 bytes: version 1, the nonzero 16-byte key-generation identifier, and the 32-byte key. DPAPI uses current-user scope, `CRYPTPROTECT_UI_FORBIDDEN`, no optional entropy, and no description. Unprotected native output is best-effort cleared before its single `LocalFree`; this is not a perfect-erasure claim.

The installed `windows-sys 0.61.2` bindings expose the approved filesystem surface through `Win32_Storage_FileSystem`; the existing cryptography feature supplies the parent security gate required by `CreateFileW`. The accepted compile preflight and initial-publication proof remain intact. The replacement proof exercises one synthetic authentication-key wrapper only. A nonzero return is accepted only with fresh canonical replacement bytes at the active name, stage absence, exact final path, stage-to-result file-ID continuity, old/result identity distinction, and sentinel preservation. Simulated special failure families validate orchestration/classification only and do not prove that Windows produces those states on the host.

On the observed Windows host, the exact evidence-directory target required a test-only read-access handle without delete sharing to make `std::fs::rename` refuse while the handle remained live. After all target, descendant, and duplicate handles closed, the two approved renames succeeded while temporary/root/intermediate handles remained retained. The displaced directory preserved the saved original full identity; the exact path reopened with the saved candidate identity and byte-identical canonical wrapper; the identity mismatch was decisive and the injected continuation count remained zero.

On the observed Windows host, the exact evidence-directory handle using `GENERIC_READ`, `FILE_SHARE_READ | FILE_SHARE_WRITE`, no delete sharing, backup semantics, and open-reparse-point semantics remained compatible with the accepted child `ReplaceFileW` call. Full leaf closure preceded the call. The same retained handle preserved its full directory identity, normalized volume-GUID path, directory/disk/reparse facts, and saved-parent volume relationship before the call, immediately after it, and after fresh child inspection; the existing classifier reported active-new/stage-absent with the accepted leaf identity checks.

On the observed Windows host, a retained validated handle to one unique temporary test root produced a strict normalized volume-GUID final path. The exact volume root derived from that path was queried once through `GetDriveTypeW`; the private documented numeric mapping reported the fixed category, and the classifier produced only non-authoritative `LocalFixedCandidate`. Remote, removable, unsupported, malformed, inconsistent, unknown, no-root, and unavailable cases fail closed. This adds no Cargo feature and no removable-media, hot-plug, device-topology, production, setup, startup, persistence, publication, replacement, database, DPAPI, IPC, or frontend authority.

On the observed Windows host, the accepted `LocalFixedCandidate` prerequisite and retained root handle yielded the exact volume-GUID device name. One access-zero, read/write-shared volume open succeeded, followed by exactly one descriptor-header and one bounded full-descriptor `IOCTL_STORAGE_QUERY_PROPERTY` call. The installed binding layout version matched, the descriptor was non-removable, its bus was in the approved candidate family, and the private classifier reported only `DevicePropertyCandidate`. No hot-plug query ran. This observation does not prove device non-removability, internal placement, physical locality, virtual or remote backing absence, durability, production suitability, or any application authority.

## 14. Decisions and authority classifications

- Carlo-approved: permanent identifier and display name; dedicated standard Windows account and non-elevated production-operation direction, with historical current-account observations retained only as test evidence; per-user application-data direction; application-owned-directory-only operation; explicit setup-only creation; no silent startup creation; immutable random parish identifier direction; temporary Windows SQLCipher feasibility; future verified restore condition; and the bounded SQLCipher Community Edition production database, independent database-key, metadata, correspondence, freshness, opening, integrity, path/sidecar, journal/durability, migration, support, redaction, and authority-separation package.
- Implemented foundation: all previously accepted foundations plus operating-system-backed authentication-material generation, HMAC-SHA-256 envelope authentication, current-user in-memory DPAPI protection for separate key and evidence objects, strict wrapper and key-payload codecs, native clear-before-free handling, and a typed generation-match transition before plaintext release. Protection remains separate from persistence, structural validation, database cross-checking, setup, startup, and operational evidence.
- Historical technical experiment: `sqlcipher_windows_feasibility` and its former development-dependency state remain Windows test-only evidence of the earlier candidate evaluation.
- Implemented production foundation: the exact Windows production `rusqlite` configuration, private raw-key application primitive, metadata-only production database-file inspection, guarded read-only connection handoff, consuming validation and startup-authorization transitions, operational activation, lifecycle ownership, explicit first-time setup, encrypted database creation, minimal V1 metadata/bootstrap schema, and private unwired full-integrity validation transition. The repository retains distinct setup and startup authority; activation consumes `StartupAuthorizedProductionDatabaseConnection` into `OperationalProductionDatabase` without granting arbitrary SQL or product-workflow authority. The full-integrity transition is not part of that startup chain and grants no migration authority.
- Approved but not fully implemented: the larger bounded architecture package. Deferred implementation includes migration, parish/business schema, portable recovery, backup/restore, recovery authority, replacement, destructive retention or cleanup, authentication, parish workflows, broader database operations, and release automation.
- The implemented startup-authorization boundary retains the exact signature, taxonomy, ownership, disposal, close/retry, redaction, and private placement recorded in section 21. The accepted lifecycle supplies the independently observed final installation evidence to that boundary, then consumes the authorized owner through operational activation.

## 15. Validation status

The freshness and internal startup-authorization validation history remains accepted as previously recorded. The later operational lifecycle implementation at commit `44d2770786d4534ef37fb58b383e5b74ab73d04c` was accepted after focused and full automated validation in its implementation review and after manual scenarios A-E. The unwired full-integrity boundary at commit `3d7e71551b8ec23af7ec47a227b6c37ac190b546` was accepted with 8 focused `full_integrity` tests, `cargo fmt --check`, Clippy with warnings denied, and `git diff --check` passing; pre-existing OpenSSL missing-PDB linker warnings were non-fatal. No broad Rust suite, frontend suite, or manual runtime test was run for that unwired Rust-only slice. No implementation suites are rerun by this documentation-only reconciliation.

## 16. Manual testing status

The DPAPI hardening manual Windows application regression remains accepted. The current baseline observation used exactly: `Current Windows account, non-elevated session; administrator-group membership not established.` It is not evidence of dedicated-standard-account execution or administrator-group membership. Windows 10 and a successful manually selected USB flash observation remain pending. Two manually rooted USB attempts have run; the accepted diagnostic rerun stopped at unavailable directory attribute/tag information before classification, cleaned its exact root successfully, and left no entry in the manual leftover-folder check.

The accepted startup-lifecycle manual scenarios are: A, a valid complete fixture reached `Ready`; B, active evidence with the database missing became `Unavailable`; C, recognized staging at launch became `Unavailable`; D, a state change before the final canonical observation was rejected by that final observation and did not reach `Ready`; and E, close while `Starting` entered shutdown pending/drain and did not fall through to `Ready`. Scenario D verifies the implemented second-observation veto in the exercised fixture; it is not proof against every possible TOCTOU or race condition. Separately, Windows debug manual validation demonstrated marker-only isolated root -> `Unavailable` -> explicit first-time setup -> restart-required -> fresh-process `ready_installed`. This is accepted end-to-end debug evidence, not release or full-product readiness. Manual fixture export is Windows test-only and ignored. Manual startup/setup root and diagnostic support remain debug/test-only and are not frontend authority beyond the narrow setup request.

## 17. Completed work

All prior completed history remains accepted. The production foundation includes the guarded read-only connection handoff and its consuming validation chain, the explicit first-time setup lifecycle, encrypted database creation, and the minimal V1 metadata/bootstrap schema. The Rust-owned startup worker is the operational caller of the fixed startup chain; the narrow setup command invokes the distinct setup path. Neither exposes arbitrary SQL, a general writable database surface, or frontend-supplied paths or evidence.

The readability-and-integrity-validated owner can be consumed through the fixed live metadata/header and identity-only correspondence transitions. The correspondence owner is then consumed with one `NormalizedFreshnessAnchorObservation` by the implemented freshness transition, which advances only on `Fresh` to `DatabaseFreshnessValidatedProductionDatabaseConnection`. That intermediate owner retains the unchanged connection/guard/inspection lifetime unit, one owned `DatabaseMetadataContractV1`, and one owned trusted assessment before final installation observation, startup authorization, and operational activation. Its failures and consuming close paths preserve the accepted explicit-close ownership discipline and redaction boundary.

## 18. Remaining risks

The keyed handoff alone does not establish key correctness, readability, or integrity. Each succeeding owner establishes only its named transition. The synchronous cipher operation may scan the whole file without a production size ceiling, bounded-latency guarantee, or active cancellation; the accepted lifecycle keeps this work off the UI/event loop by running the complete production trust chain in one blocking Rust worker, but it does not bound worker duration or eliminate shutdown drain time. Read-only/no-create applies to ordinary startup; explicit first-time setup is the distinct creation authority. Migration, parish/business schema, backup, restore, recovery, replacement, authentication, parish workflows, and a frontend database-operation surface remain absent. The existing controlled-host and race risks also remain.

The correspondence-validated owner adds only the six-field identity match and retention of the validated metadata and trusted assessment. Correspondence success does not establish equal lineage, freshness, rollback resistance, startup authorization, operational database opening, setup completion, migration status, physical DDL, relation object kind, wider product-schema correctness, recovery fitness, backup/restore suitability, replacement authority, or business-data correctness.

## 19. Implemented identity-only database/evidence correspondence boundary

The implemented consuming transition is:

```text
LiveMetadataAndHeaderValidatedProductionDatabaseConnection
+ TrustedCurrentInstallationEvidenceAssessment
-> DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection
```

Its function is `validate_production_database_evidence_correspondence(database, evidence) -> DatabaseEvidenceCorrespondenceValidationOutcome`; both inputs are consumed, no weaker evidence input is accepted, and the transition does not load evidence internally. It invokes `classify_database_metadata_correspondence(&metadata_contract, trusted_assessment.evidence())` exactly once and leaves that pure classifier as the sole authority for exact equality of the permanent application identifier, application database-format identity, parish identifier, installation identifier, database-key generation identifier, and setup-publication identifier. One or many mismatches map only to the unit-like coarse `DatabaseEvidenceCorrespondenceMismatch`; comparison order and field-level precedence are intentionally unobservable, and no field, count, index, set, or diagnostic escapes.

Success is possession of opaque `DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection`, which privately retains exactly the unchanged `ConnectionLifetimeOwner`, one owned `DatabaseMetadataContractV1`, and one owned `TrustedCurrentInstallationEvidenceAssessment`. It retains no separate `DatabaseMetadataCorrespondence::Corresponds` proof. The trusted assessment preserves trusted loading and authentication provenance, its structurally validated evidence, and `TrustedCurrentInstallationIdentity` without retaining paths, wrapper bytes, keys, envelope bytes, native errors, or loader state. The approved next implementation boundary consumes the whole correspondence owner with exactly one preloaded `NormalizedFreshnessAnchorObservation`; the correspondence owner remains the possession proof used to construct one ephemeral `DatabaseMetadataCorrespondence::Corresponds` only for the pure freshness-classifier call.

Correspondence ignores installation generation, recovery/replacement generation, evidence-format identity and version, database creation timestamp, and evidence creation timestamp. It establishes no equal lineage, freshness, or rollback resistance. The implemented freshness boundary performs the later three-way classification without allowing any timestamp to influence freshness.

Implementation resides in `production_database_connection_handoff/live_metadata_and_header_validation/database_evidence_correspondence_validation.rs`, declared as a private nested child beneath `live_metadata_and_header_validation.rs`. The nested child destructures the live owner and retains the ancestor-private lifetime owner without visibility widening. It exposes no `Connection`, arbitrary-SQL callback, or detachable proof and leaves `database_metadata_correspondence` pure and independent.

On mismatch, temporary borrows end, metadata and the trusted assessment are discarded, and only then is the unchanged lifetime owner explicitly closed. Close success returns `DatabaseEvidenceCorrespondenceMismatch`; close failure retains that same category plus the complete lifetime owner in `DatabaseEvidenceCorrespondenceValidationCloseFailure`. A consuming retry attempts only close, repeated failure preserves both, and eventual success returns the original mismatch. Metadata and evidence never survive in this close-failure owner. Closing the successful owner likewise discards metadata and the trusted assessment before SQLite close; close failure reuses the existing capability-free `ProductionDatabaseConnectionCloseFailure` and retains only the lifetime owner. The implemented result family is `DatabaseEvidenceCorrespondenceValidationOutcome`, `DatabaseEvidenceCorrespondenceValidationCloseFailure`, and `DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome`.

Manual coarse `Debug` is implemented for every correspondence owner and outcome. Formatting and ordinary logs expose no mismatch detail, identifiers, generations, timestamps, metadata or evidence values, evidence-format fields, paths, wrapper or DPAPI/HMAC state, SQL/PRAGMA text, SQLite/native errors or codes, handles, or connection details. Success proves only that preceding stages remain satisfied, the six approved identity fields correspond, the same guarded lifetime remains owned, the trusted assessment remains retained, and both generations remain internally available for later freshness. It proves no lineage equality, freshness, rollback resistance, startup or operational authority, setup completion, migration state, physical DDL or object kind, wider schema correctness, recovery fitness, backup/restore suitability, replacement authority, or business-data correctness.

Test construction uses the narrow `#[cfg(test)] pub(crate)` function named `trusted_current_installation_evidence_assessment_for_test` in `installation_evidence_protection/trusted_current_installation_evidence_assessment.rs`. It accepts owned `StructurallyValidatedInstallationEvidence`, derives `TrustedCurrentInstallationIdentity` internally through the existing pure derivation, accepts no independently supplied identity, performs no filesystem, DPAPI, HMAC, loading, or parsing, is absent from production compilation, and grants no production authority.

The accepted correspondence adapter introduced no lineage classification, detailed mismatch variant, detachable proof, internal evidence loading, weaker evidence input, widened production visibility, `Connection` or arbitrary SQL exposure, pure-classifier change, dependency, Cargo feature, FFI, unsafe block, filesystem/DPAPI/HMAC/SQL operation, schema, migration, public API, separate application caller, or non-narrow production test seam, and it does not combine correspondence with freshness. The later lifecycle composes it only through the fixed trust chain.

## 20. Implemented and accepted preloaded normalized database-freshness composition boundary

The implemented consuming transition is:

```text
DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection
+ NormalizedFreshnessAnchorObservation
-> DatabaseFreshnessValidatedProductionDatabaseConnection
   or coarse non-Fresh outcome
```

Its exact signature is `validate_production_database_freshness(database: DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection, anchor_observation: NormalizedFreshnessAnchorObservation) -> ProductionDatabaseFreshnessValidationOutcome`; both inputs are consumed. `NormalizedFreshnessAnchorObservation` is the only accepted anchor input, including `Present(AssuredFreshnessAnchor)`, `Missing`, `Unavailable`, and `Invalid`. No path or earlier anchor type is accepted. The complete presence, loading, DPAPI, HMAC, parsing, authentication, generation-match, installation-binding, assurance, and normalization chain finishes before this transition receives its input.

The sealed nested adapter constructs `DatabaseMetadataCorrespondence::Corresponds` ephemerally because possession of the correspondence owner is the proof. It neither reruns correspondence nor retains, returns, or exposes that enum. It invokes exactly once `classify_database_freshness(DatabaseMetadataCorrespondence::Corresponds, &metadata_contract, trusted_assessment.evidence(), &anchor_observation)`. The existing pure classifier remains unchanged and solely owns generation comparisons, three-way anchor-identity checks, lineage combination, precedence, and timestamp exclusion. The adapter performs no SQL, PRAGMA, database read, filesystem or path operation, presence inspection, loading, DPAPI, HMAC, parsing, authentication, binding, assurance, or normalization.

Only `DatabaseFreshnessClassification::Fresh` advances ownership. `StaleEvidence`, `StaleDatabase`, `RollbackSuspicion`, `IdentityMismatch`, `AnchorMissing`, `AnchorUnavailable`, `AnchorInvalid`, and `Ambiguous` are non-success. The live stage reuses `DatabaseFreshnessClassification` directly: `Fresh` returns `DatabaseFreshnessValidatedProductionDatabaseConnection`; non-Fresh plus successful close returns `Failed(classification)`; non-Fresh plus failed close returns ownership-bearing `CloseFailed`. `Fresh` can never appear in failure or retry forms. Close behavior does not change classifier precedence.

The opaque success owner privately retains exactly the unchanged `ConnectionLifetimeOwner`, one `DatabaseMetadataContractV1`, and one `TrustedCurrentInstallationEvidenceAssessment`. It retains no classification, correspondence enum, normalized observation, assured/authenticated/bound anchor, anchor contract or fields, paths, wrappers, loader state, or protection errors. The observation and any contained assured anchor are discarded after classification, including on success; possession of the owner proves the classifier returned `Fresh`.

For non-Fresh results, all classifier borrows end; the copyable classification is preserved; metadata, trusted assessment, normalized observation, and any assured anchor are discarded; and only then is the lifetime owner explicitly closed. Close success returns the original classification. `ProductionDatabaseFreshnessValidationCloseFailure` retains exactly that classification plus the complete lifetime owner; consuming retry performs only close, preserves both on repeated failure, and returns the original classification on eventual success. No metadata, assessment, trusted identity, observation, or anchor survives close failure. Closing the successful owner first discards metadata and the assessment, then reuses `ProductionDatabaseConnectionCloseFailure`, retaining only lifetime ownership on failure.

The implemented type family is `ProductionDatabaseFreshnessValidationOutcome`, `ProductionDatabaseFreshnessValidationCloseFailure`, `ProductionDatabaseFreshnessValidationCloseRetryOutcome`, and `DatabaseFreshnessValidatedProductionDatabaseConnection`. Manual coarse `Debug` may reveal only a payload-free non-Fresh classification name; owners and ownership-bearing failures are redacted. No identifiers, generations, timestamps, metadata, evidence, trusted identity, anchor values, protection state, paths, SQL/PRAGMA text, SQLite/native detail, handles, connection detail, or raw chain may escape, and no ordinary logging is required.

Implementation resides in `production_database_connection_handoff/live_metadata_and_header_validation/database_evidence_correspondence_validation/database_freshness_validation.rs`, declared and narrowly reexported by the correspondence module. This placement permits private destructuring without production visibility widening and adds no crate-root bridge or arbitrary `Connection` callback. An implementation review removed production-compiled injected connection callbacks before commit; the accepted implementation closes only through canonical lifetime-owner paths, and all injected close callbacks are `cfg(test)`-only.

Success proves only that preceding stages remain represented, correspondence had already succeeded, the pure classifier was called once with ephemeral `Corresponds`, the supplied observation was `Present` with an assured anchor, its three-way identity checks passed, both lineages were `Current`, the result was `Fresh`, and the same guarded lifetime remains owned. It does not prove cryptographic monotonic rollback prevention, absolute newest state, detection of coordinated rollback, startup authorization, operational activation, setup completion, migration state, DDL/object-kind/wider schema correctness, recovery/replacement authority, backup/restore suitability, business-data correctness, or continued validity after external changes.

The accepted anchor loader proves bounded, stable selection and validation of the current active wrapper pair. It does not guarantee detection of every transient historical disappearance or recreation when that history is indistinguishable through existing observations. The corrected Windows test `second_file_disappearance_is_rejected_and_replacement_never_returns_stale_pair` requires disappearance without replacement to return `Err`; replacement may return `Err` or may succeed only with the fully validated current recreated pair; stale or mixed-pair success is forbidden. Production loader bytes did not change, and this is not a weakening of production security.

## 21. Implemented internal startup-authorization boundary

The implemented internal database trust-chain transition is exactly:

```rust
pub(crate) fn authorize_production_database_startup(
    database: DatabaseFreshnessValidatedProductionDatabaseConnection,
    installation_evidence: InstallationEvidence,
) -> ProductionDatabaseStartupAuthorizationOutcome
```

The second input is exactly one preloaded `installation_state::InstallationEvidence`. The boundary performs one fixed policy decision over that supplied observation. It performs no installation-state loading and no filesystem, path, sidecar, anchor, database, environment, current-account, administrator-group, standard-user, or elevation observation. Freshness and every earlier database trust stage have already succeeded and are not rerun.

Only `InstallationEvidence::Initialized(ExpectedStorageEvidence::Present)` advances. Success returns opaque `StartupAuthorizedProductionDatabaseConnection`, privately retaining exactly `ConnectionLifetimeOwner`, `DatabaseMetadataContractV1`, and `TrustedCurrentInstallationEvidenceAssessment`. Possession of the owner is the startup-authorization proof. It retains no installation evidence, storage or setup decision, authorization Boolean or enum, freshness classification, correspondence value, normalized or assured/authenticated/bound anchor, path, or sidecar observation. It is not operational: it exposes no connection, SQL/query operation, arbitrary callback, path, metadata, trusted-assessment, or evidence accessor.

The exact primary taxonomy and mapping are:

- `Initialized(Present)` -> `Authorized`;
- `NeverInitialized` -> `ProductionDatabaseStartupAuthorizationError::NeverInitialized`;
- `Initialized(Missing)` -> `ProductionDatabaseStartupAuthorizationError::ExpectedStorageMissing`;
- `Initialized(Unavailable)` -> `ProductionDatabaseStartupAuthorizationError::InstallationStateUnavailable`;
- `Inconsistent` -> `ProductionDatabaseStartupAuthorizationError::InstallationStateInconsistent`;
- `Unavailable` -> `ProductionDatabaseStartupAuthorizationError::InstallationStateUnavailable`.

Both unavailable observations intentionally collapse. `NeverInitialized` fails this boundary and closes the database owner; it does not grant `FirstTimeSetupAuthorization`, become `SetupPermitted`, or branch into setup. `FutureOpenPermitted`, `StorageDecision`, and `SetupAuthorizationState` are not startup authority. Existing installation-state meanings and the separate explicit first-time-setup boundary remain unchanged.

The implemented family is `StartupAuthorizedProductionDatabaseConnection`, `ProductionDatabaseStartupAuthorizationError`, `ProductionDatabaseStartupAuthorizationOutcome`, `ProductionDatabaseStartupAuthorizationCloseFailure`, and `ProductionDatabaseStartupAuthorizationCloseRetryOutcome`. The initial outcome distinguishes `Authorized(success owner)`, `Failed(primary category after successful close)`, and ownership-bearing `CloseFailed`; `CloseFailed` is not a primary authorization category.

On success, policy evaluation completes, requires `Initialized(Present)`, discards the installation-state observation, and moves the unchanged lifetime owner, metadata contract, and trusted assessment into the startup-authorized owner. On failure, the adapter preserves the primary category, discards `InstallationEvidence`, `DatabaseMetadataContractV1`, and `TrustedCurrentInstallationEvidenceAssessment`, then explicitly closes `ConnectionLifetimeOwner`. Successful close returns the original category. Failed close returns `ProductionDatabaseStartupAuthorizationCloseFailure`, retaining exactly the original category and complete lifetime owner. Its consuming retry performs only close; repeated failure preserves both, and eventual success returns the original category. No authorization, observation, loading, database access, recovery, or setup work occurs during retry.

Closing a successful `StartupAuthorizedProductionDatabaseConnection` first discards the metadata contract and trusted assessment, then explicitly closes the lifetime owner. It reuses `ProductionDatabaseConnectionCloseOutcome` and `ProductionDatabaseConnectionCloseFailure`; a failed successful-owner close retains only lifetime ownership.

The implementation resides privately at `production_database_connection_handoff/live_metadata_and_header_validation/database_evidence_correspondence_validation/database_freshness_validation/startup_authorization.rs`, with `database_freshness_validation.rs` declaring the private child. This permits private destructuring without visibility widening. No crate-root bridge, generic or arbitrary `Connection` callback, production success constructor, unsafe/FFI, dependency, Cargo feature, frontend, IPC, or Tauri surface was added.

Manual coarse `Debug` may reveal only the payload-free primary names `NeverInitialized`, `ExpectedStorageMissing`, `InstallationStateInconsistent`, and `InstallationStateUnavailable`. Owners and ownership-bearing failures remain redacted, and formatting must not delegate to metadata, trusted assessment, installation evidence, lifetime ownership, rusqlite, or native errors. No identifier, generation, timestamp, metadata/evidence value, trusted identity, path, sidecar, handle, SQL or PRAGMA text, native code, connection detail, or raw error chain may escape. No ordinary success or failure logging is required.

This owner proves only that all preceding database trust stages remain represented, freshness already succeeded, the supplied installation evidence was `Initialized(Present)`, fixed startup policy accepted it, the same guarded connection lifetime remains owned, and metadata plus trusted assessment remain internally available to the consuming operational-activation transition. Authorization itself is not activation and grants no SQL or broader capability.

## 22. Implemented application-startup lifecycle

The accepted Tauri lifecycle presents the window immediately with frontend status `Starting`. Rust owns orchestration and runs the synchronous production trust chain in one `spawn_blocking` worker, off the UI/event loop. React only polls the read-only `startup_status` command and treats unknown or failed command responses as `Unavailable`; the only intended lifecycle IPC addition is `startup_status` alongside `health_check`.

Startup observes `installation_state::InstallationEvidence` early and requires `Initialized(Present)` without constructing or substituting that value. It then loads and validates the existing evidence, anchor, key, database, metadata, correspondence, and freshness chain. Immediately before final startup authorization, it re-observes canonical installation evidence and passes the actual second observation into `authorize_production_database_startup`. Startup never manufactures `Initialized(Present)`. No setup, migration, repair, recovery, reset, or retry fallthrough exists. After successful authorization, `activate_production_database_for_operational_use` is the operational activation transition, not another authorization decision. Only the resulting real `OperationalProductionDatabase` may be installed as `Ready`.

Frontend-visible states are `Starting`, `Ready`, `Unavailable`, `SetupInProgress`, `SetupRestartRequired`, `Stopping`, and `ShutdownIncomplete`. Internal states remain richer, including retained `CloseRetryRequired`; terminal startup failure collapses to `Unavailable`. Shutdown during startup records stopping intent, waits for the startup worker to drain, checks that intent throughout the chain, and prevents any later `Ready` installation. A late owner is closed on a blocking worker. Close failure retains ownership internally as `CloseRetryRequired` and exposes only `ShutdownIncomplete`. This implementation has no close-retry UI, IPC command, or user action.

Lifecycle logs are local, fixed, and coarse. They must not expose paths, keys, identifiers, metadata, native errors, or raw backend chains. Windows debug-assertion-only manual root/pause support is an isolated manual verification aid and is not frontend or IPC authority. The synthetic fixture exporter is Windows test-only, ignored, and not production behavior.

## 23. Locked maintenance authorization trigger and taxonomy policy

The maintenance-authorizing actor is the local human operator physically using Church App under the dedicated standard Windows account used for Church App production operation. Merely being that Windows user does not create maintenance authorization. The application must require an explicit interactive maintenance confirmation initiated from Church App. That confirmation records the operator's authorization and consent for one maintenance action; it is deliberately not proof of application-level user identity. Application-level authentication may strengthen this boundary later, but the first-generation maintenance architecture does not depend on authentication existing.

Any future maintenance authority must be explicit, interactive, single-use, process-local, non-persistent, non-renewing, and scoped to exactly one approved maintenance operation. It must never be inferred automatically, granted during startup or setup completion, granted merely because migration is required, survive application restart, be serialized or persisted, be reconstructed from frontend-supplied Boolean, string, path, or version values, or authorize a different maintenance operation. Automatic maintenance authorization and automatic maintenance execution are prohibited in the initial design.

Application start, `Ready`, first-time setup authority, startup authorization, possession of `OperationalProductionDatabase` or `FullIntegrityValidatedProductionDatabaseConnection`, backup existence or verified-backup proof, writable database ownership, migration eligibility, version compatibility, and concurrency or exclusivity do not create or substitute for maintenance authorization. Safety prerequisites remain separate composed gates: a verified recoverable encrypted backup, full-integrity validation, valid source and target versions, writable maintenance ownership, concurrency and exclusivity, and installation, evidence, and freshness state. Satisfying any or all of them does not record operator consent.

The initial authorization identity is specifically production database migration because migration is the only concrete next maintenance operation. No generic `MaintenanceOperation` enum and no broad generic `MaintenanceAuthorization` capability are approved at this stage. The future migration-specific capability may conceptually be named `ProductionDatabaseMigrationAuthorization`, but this decision neither finalizes nor implements its Rust representation. Source and target schema versions are separate migration-plan and eligibility prerequisites, not fields of that authorization identity. Verified recoverable backup proof is likewise a separate safety prerequisite: its presence does not create consent and it is not embedded in migration authorization. Possession of migration authorization alone must never imply that migration is eligible or executable.

Restore, recovery, rekey or database-key replacement, anchor replacement, database replacement, and destructive cleanup remain separately authorized future authority domains and must not be collapsed into migration authority. Recovery and restore remain distinct from one another; rekey remains distinct from database replacement; and destructive cleanup remains distinct from reset, repair, recovery, replacement, and migration. Setup and startup are not maintenance operations. Backup verification or acceptance and full-integrity validation are safety or proof capabilities, not maintenance-operation identities. Explicit diagnostics, including full-integrity diagnostics, are not approved operation variants; backup creation is not approved as a distinct operator-authorized operation identity; and the catch-all identity “installation/evidence replacement” is too broad and must not be introduced.

React may eventually request or present the interactive confirmation, but it remains non-authoritative. Rust must ultimately construct and own any future maintenance authority. Before `ProductionDatabaseMigrationAuthorization` can be implemented even as a private token, the project must separately approve a Rust-owned construction boundary that represents the already-locked interactive operator confirmation. This task does not design that IPC, UI, or construction flow. A ceremonial constructor whose only input is a Boolean, enum, version, path, startup state, `Ready` state, backup proof, integrity proof, or existing database owner is prohibited. Full-integrity proof, writable maintenance ownership, exclusivity, installation/evidence/freshness state, version eligibility, and backup proof remain separately composed prerequisites. This policy does not approve migration implementation, schema V2, migration SQL, authentication roles, backup implementation, writable maintenance ownership, or exclusivity design.

## 24. Links

- [Project overview](docs/project-overview.md)
- [Architecture](docs/architecture.md)
- [Security and data](docs/security-and-data.md)
- [Product decisions](docs/product-decisions.md)
- [Verification](docs/verification.md)
- [SQLCipher Windows feasibility findings](docs/sqlcipher-windows-feasibility.md)
