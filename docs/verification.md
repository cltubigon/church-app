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
cargo check --manifest-path src-tauri/Cargo.toml
cargo test --manifest-path src-tauri/Cargo.toml --locked sqlcipher_database_key_application::tests
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_persistence::windows_filesystem::tests
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_persistence::windows_filesystem::tests::directory_substitution_fixture -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked normal_tree_handle_path_hardening -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked hard_link_fixture -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_persistence::windows_filesystem::tests::successful_stage_flush_reload_validate_publish_and_active_reload_flow
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_persistence::windows_filesystem::tests::exact_minimum_normal_and_maximum_canonical_wrappers_publish
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_persistence::windows_filesystem::tests::successful_existing_file_replacement_reinspects_and_preserves_identity
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_persistence::windows_filesystem::tests::retained_active_handle_blocks_once_then_fresh_state_is_inspected
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_persistence::windows_filesystem::tests::retained_stage_handle_blocks_once_then_fresh_state_is_inspected
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_persistence::windows_filesystem::tests::special_failure_families_are_classified_only_from_injected_observations
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_persistence::windows_filesystem::tests::reported_failure_completed_state_and_unavailable_state_remain_distinct
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_protection::protected_blob_wrapper::tests
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_protection::protected_key_payload::tests
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_protection::protected_blob_wrapper::tests::malformed_input_hardening
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_protection::protected_key_payload::tests::malformed_input_hardening
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_protection::tests::fake_protector_malformed_input_hardening
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_protection::tests::authenticated_malformed_plaintext_reaches_only_later_logical_failures
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_protection::tests::corrupted_dpapi_blobs_cannot_produce_generation_matched_authenticated_evidence
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_authenticated_envelope::tests::trusted_and_verified_results_retain_generation_until_explicit_matching
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_authenticated_envelope::tests::generation_mismatch_is_coarse_and_plaintext_release_belongs_only_to_matched_type
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_protection::tests -- --skip windows_full_wrapper_dpapi_round_trip_is_same_user_and_in_memory
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_protection::windows_current_user_dpapi::tests
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_protection::tests::windows_full_wrapper_dpapi_round_trip_is_same_user_and_in_memory
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_authentication_key_generation::tests -- --skip operating_system_generation_smoke_test
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_authentication_key_generation::tests::operating_system_generation_smoke_test
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_authentication_key::tests
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_authenticated_envelope::tests::malformed_input_hardening
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_authenticated_envelope::tests
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_authenticated_envelope::tests::rfc_4231_hmac_sha256_vectors
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_contract::tests::version_1_encoding
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_contract::tests::strict_parser
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_contract::tests::malformed_input_hardening
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_contract::tests
cargo test --manifest-path src-tauri/Cargo.toml --locked storage_foundation::tests
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_persistence::tests
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_state::tests
cargo test --manifest-path src-tauri/Cargo.toml --locked sqlcipher_windows_temporary_encryption_feasibility -- --nocapture
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo clippy --manifest-path src-tauri/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml --locked
git diff --check
```

The focused Windows filesystem adapter command retains the accepted signature, type, ownership, policy, and initial-publication assertions and adds the test-owned existing-file replacement proof. It covers fixed names; 15-byte, representative, and 65,550-byte canonical authentication-key wrappers; create-new stage discipline; independent old-active and new-stage validation; exact normalized directory and volume; closure of ordinary handles; the one-shot null-backup/zero-flag `ReplaceFileW` call; fresh exact-name inspection on every return; canonical active replacement bytes; stage absence; stage/result file-ID continuity; old/result identity distinction; sentinel preservation; pre-call refusals; and redacted errors. It adds no production replacement, mutex, IOCTL, DPAPI, database, resolver, setup/startup, IPC, frontend, or broad cleanup.

The focused `normal_tree_handle_path_hardening` command runs with one test thread. It covers the ordinary root/intermediate/evidence chain, independent opens and retained directory handles, disk/directory checks, reject-all reparse facts, full 128-bit `FILE_ID_INFO`, exact normalized volume-GUID component comparison, narrowly bounded GUID-hex case folding, exact fixed spelling, wrapper-only one-link policy, same-volume facts, stable wrapper and directory identity across the existing bounded reader, canonical kind-1 parsing, deterministic changed/unavailable observation failures, minimum/representative/maximum wrappers, sentinel preservation, redacted errors, compiler-boundary source checks, and mutation-call exclusions. It creates no reparse, hard-link, cross-volume, or substitution fixture and changes no publication API.

The focused `hard_link_fixture` command also runs with one test thread. Separate unique roots cover the active and staged authentication-key wrapper names with exactly one canonical wrapper each. Each case observes link count `1`, creates only `wrapper-hard-link-alias.synthetic` through `std::fs::hard_link`, observes link count `2`, compares the full volume serial and 128-bit file ID, canonical kind-1 bytes, and distinct normalized final paths, rejects the alias exact name, and receives `HardLinkRejected` from the existing hardening path before injected mutation or bounded-reader counters advance. It then removes only the alias and verifies link count `1`, unchanged full identity and bytes, the unrelated sentinel, and exact root-only teardown. Failure to create the required local hard link is a coarse test failure, not a skip. The fixture invokes no publication or replacement function.

The focused `directory_substitution_fixture` command runs with one test thread and fails rather than skips if its Windows filesystem prerequisite is unavailable. It creates one exact ordinary target and one prebuilt candidate with independently bounded, canonical, byte-identical authentication-key wrappers. A retained read-access target handle without delete sharing must make the first `std::fs::rename` fail; fresh observations then require unchanged target and candidate full identities and exact normalized paths, unchanged wrapper snapshots, stable retained ancestors, and sentinel preservation. After all target, descendant, and duplicate handles close, exactly two successful renames displace the original and place the candidate at exact `installation-evidence`. Fresh observations require displaced-original identity continuity, candidate identity at the exact path, candidate/original identity inequality, exact normalized paths, equal canonical bytes, the substitution classification, and zero continuation/publication/replacement/wrapper-mutation calls. Source assertions require test-only placement, the existing bounded reader, three total rename expressions (one blocked attempt and two intended successful calls), no unsafe block, and no fixture call to native rename, `MoveFileExW`, `ReplaceFileW`, hard-link, reparse, DPAPI, database, publication, or replacement operations.

The two retained-handle commands each keep exactly one deliberate restrictive leaf handle, verify one failed replacement call, close the blocker, freshly inspect both exact names, preserve the sentinel, and perform no retry. The special-family commands inject only private outcomes and exact-name observations to cover the three documented partial-failure families, other failure, reported failure with completed replacement state, and unexpected or unavailable inspection. These simulations validate orchestration and classification only; they do not prove Windows produces those rare states on the host.

Every Windows runtime case creates a unique test-owned root beneath the operating-system temporary directory and removes only that root after successful assertions. A drop guard attempts best-effort removal of that same root if a test unwinds, without hiding the assertion failure. After the focused commands, `Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory -Filter 'church-app-wrapper-proof-*'`, `Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory -Filter 'church-app-normal-tree-proof-*'`, `Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory -Filter 'church-app-hard-link-proof-*'`, `Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory -Filter 'church-app-directory-substitution-proof-*'`, and `Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory -Filter '*replacement-proof*'` should return no entries. This is exact test-root teardown, not production stale-stage cleanup, repair, or winner selection.

Run the retained evidence-directory replacement compatibility proof with exactly one test thread:

```powershell
cargo test --manifest-path src-tauri/Cargo.toml --locked retained_directory_replacement_compatibility -- --test-threads=1
```

The focused filter must run four tests and fail rather than skip if the Windows filesystem behavior or inspection is unavailable. It proves the exact retained access/share flags, complete leaf closure, one locked replacement call, three same-handle directory observations, fresh active/stage inspection through the existing classifier, leaf identity continuity, sentinel preservation, redacted failures, source exclusions, and exact-root teardown. Re-run the successful replacement, retained active/stage blockers, special and reported-failure classifiers, substitution, hard-link, normal-tree, one successful initial-publication, canonical protected-wrapper, pure persistence, storage-foundation, and installation-state filters. Confirm no `church-app-retained-directory-replacement-proof-*` root or any previously accepted proof-root pattern remains beneath the operating-system temporary directory.

Run the private local-volume candidate classifier and runtime observation with exactly one test thread:

```powershell
cargo test --manifest-path src-tauri/Cargo.toml --locked local_volume_policy -- --test-threads=1
```

The focused filter must execute exactly eight tests. On Windows it fails rather than skips when the unique test root cannot be created or opened, a strict handle-derived normalized volume-GUID path or exact 49-unit root is unavailable, the drive fact is unknown/no-root/unavailable, the host is not classified fixed, the sentinel changes, or exact-root cleanup fails. The runtime calls `GetDriveTypeW` once. The pure cases cover the documented private numeric mapping, fixed-only candidacy, remote/removable/unsupported rejection, unavailable facts, UNC and malformed input, inconsistent facts, redaction, non-authority, and source exclusions.

Run the private device-property classifier and controlled-host runtime observation with exactly one test thread:

```powershell
cargo test --manifest-path src-tauri/Cargo.toml --locked device_property_policy -- --test-threads=1
```

The focused filter must execute exactly ten tests and fail rather than skip if the prerequisite, exact root transformation, access-zero/read-write-shared volume open, header query, bounded full query, strict parsing, candidate policy, sentinel preservation, or exact-root teardown is unavailable. The successful runtime case retains the root handle and reports exactly one volume open, two storage-property IOCTL calls, and zero hot-plug IOCTL calls. Pure cases cover binding sizes and features; root malformation; header, version, size, truncation, changed-response, offset, removable-byte, bus, unavailable, inconsistent, redaction, non-authority, and source-exclusion policy.

Run only the named regressions for this stage:

```powershell
cargo test --manifest-path src-tauri/Cargo.toml --locked retained_directory_replacement_compatibility -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked directory_substitution_fixture -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked hard_link_fixture -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked normal_tree_handle_path_hardening -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked successful_stage_flush_reload_validate_publish_and_active_reload_flow -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked successful_existing_file_replacement_reinspects_and_preserves_identity -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked retained_active_handle_blocks_once_then_fresh_state_is_inspected -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked retained_stage_handle_blocks_once_then_fresh_state_is_inspected -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked protected_blob_wrapper -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_contract -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_evidence_persistence::tests -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked storage_foundation -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked installation_state -- --test-threads=1
```

Confirm both classifier implementations are wholly after the Windows `#[cfg(test)]` boundary, reuse the existing strict helpers, and have no authority conversion. The device-property implementation must contain one exact volume open, exactly two `IOCTL_STORAGE_QUERY_PROPERTY` call sites, the 65,536-byte cap, and no hot-plug, physical-drive, disk-extent, interface-enumeration, production resolver, publication/replacement, DPAPI, database, setup/startup, IPC, frontend, subprocess, or shell surface. Confirm no `church-app-device-property-proof-*`, `church-app-local-volume-proof-*`, or previously accepted proof roots remain under the operating-system temporary directory.

For final integrated validation, use this self-contained hash baseline:

1. Immediately before final validation, capture SHA-256 hashes for `src-tauri/Cargo.toml`, `src-tauri/Cargo.lock`, and every protected installation-evidence source.
2. Run only the separately approved final validation commands in the repository's concise validation process.
3. Recompute the same hashes afterward.
4. Require no source or Cargo change caused by validation, exact before-and-after hash matches, and every pre-existing intended working-tree difference to remain unchanged.
5. Treat historical stage hashes as evidence, not as an implicit baseline for future commands.

The protection codec commands use deterministic synthetic bytes to verify the exact 14-byte wrapper, exact 49-byte key payload, every fixed position, bounded wrong-length, truncation, trailing-data, pattern, boundary, and selected multi-byte corpora, the 65,536-byte blob cap, redacted debug output, and zeroizing owned plaintext containers. Fake-protector tests exercise empty, maximum, oversized, malformed key/evidence outputs, wrong kinds, key-first ordering, coarse failures, HMAC authentication, generation matching, and delayed plaintext and structural validation without filesystem, registry, database, environment, network, Tauri, IPC, or frontend operations. Windows-only tests exercise current-user non-interactive round trips and first, midpoint, and final-byte corruption of protected key and evidence blobs through the complete chain. Native rejection and later strict application rejection are both safe outcomes; no corrupted case may return generation-matched authenticated evidence. These tests do not cover wrong-user, profile-reset, password-reset, cross-machine, persistence, setup, startup, or database scenarios.

The focused deterministic authentication-material command supplies synthetic bytes through a private closure only. It verifies separate exact 32-byte and 16-byte fills, direct key ownership transfer, reuse of the existing nonzero identifier constructor, three total identifier attempts, coarse fail-closed randomness errors, normal key drop on partial failure, exact redaction, no retained provider handle, and source exclusions for deterministic fallback or derived entropy. The separately named smoke test calls the production `getrandom::fill` wrapper on the observed Windows host and asserts only success and redacted accepted material; it does not compare random outputs or print generated bytes.

The focused authentication-key ownership tests use only a synthetic caller-owned 32-byte pattern. They verify ownership transfer, crate-private closure-based read-only use, exact debug redaction, the shared live-buffer zeroization path called by `Drop`, and the absence of command, serialization, randomness, cryptographic, filesystem, environment, network, Windows, and database APIs from the module. They use no unsafe code and do not inspect freed memory.

The focused authenticated-envelope hardening command uses only deterministic synthetic bytes. It mutates all 226 positions; classifies framing failures separately from authentication failures; checks every framing-preserving prefix mutation and every tag mutation; covers wrong-key, wrong-length, pattern, boundary, and selected two-byte corpora; authenticates deliberately retagged malformed plaintext before later parse or validation failure; and completes the nonoperational chain with an alternate valid plaintext and byte-identical re-encoding. The full authenticated-envelope test module preserves exact construction, verification, authenticated-only release, redacted debug behavior, and the separately named unchanged RFC 4231 cases 1 and 2.

The focused installation-evidence tests use only synthetic in-memory values. Encoding tests verify the exact 164-byte layout, fixed offsets, big-endian integers, golden fixture, determinism, and redacted output. Strict-parser tests verify exact total length and framing, application-identifier length and UTF-8, fixed-offset decoding, distinct parse and structural-validation errors, parsed-value redaction, the raw-bytes → parsed-but-untrusted → structural-validation API, and byte-exact canonical round-trip. Malformed-input hardening tests use a dependency-free deterministic corpus covering all 164 single-byte positions, wrong lengths, representative patterns, explicit field boundaries, selected two-byte framing mutations, redacted outcomes, and byte-identical re-encoding for every structurally valid accepted input. Contract tests retain current logical identity, canonical parish, nonzero identifier and generation, debug-redaction, and operational-boundary checks. They perform no persistence, filesystem or registry access, database work, environment mutation, clock reading, randomness, cryptography, DPAPI, or Tauri IPC.

The focused installation-state tests supply only synthetic evidence to pure Rust decisions. They verify that ordinary startup cannot authorize setup, explicit authorization permits only a future setup step, initialized-but-missing and inconsistent states fail closed, present storage indicates only future open eligibility, the authorization boundary has no boolean, string, path, frontend, or Tauri argument, and no directory or file is created. The new persistence classifier has no conversion to this operational model.

The focused storage-foundation tests use Windows-like and portable synthetic roots for path construction and do not create directories or files. They verify all seven exact active/stage names, continued canonical ownership of `parish-data.db`, typed active/evidence/publication-stage paths, evidence-directory nesting, direct-root database staging, restore-versus-publication staging separation, redacted debug output, existing production/development/test/restore separation, unique safe automated-test identities, and narrow database-format and parish-identifier representations. Production path resolution itself remains behind Rust's Tauri application-handle boundary and is not invoked by the new constructor.

The focused installation-evidence-persistence tests are deterministic and pure. They cover the reported lengths 0, 1, 14, 15, 65,549, 65,550, and 65,551; exact minimum and maximum reads; rejection before an oversized read or allocation; one-byte and multi-byte short reads; interrupted reads followed by success; ordinary failure; trailing data and simulated growth; error/value redaction; and source exclusions for unbounded reads, memory mapping, and filesystem operations. Classifier tests cover all 64 active/stage presence combinations, absent and empty evidence directories, every asymmetry, stage, unavailable fact, and unexpected entry type with exact precedence. Publication tests cover all valid and out-of-order events, every interruption and failure boundary, refused baselines, and evidence-last success for all three operation kinds.

The pure persistence stage remains side-effect free. The separately gated Windows adapter proof performs filesystem operations only beneath its unique test-owned roots and uses the existing bounded reader. It does not resolve or touch production evidence paths and performs no DPAPI, database, setup/startup, recovery, rollback, IPC, or frontend behavior.

The focused SQLCipher command is a Windows-only feasibility test. It creates an encrypted database under the operating system temporary directory, verifies independent correct-key and wrong-key connections, reports non-sensitive native identity and cipher configuration, scans the database and retained journal sidecar for the synthetic plaintext sentinel, and removes its test directory. It does not select or exercise a production data location. The absence of the sentinel is supporting evidence, not complete proof of cryptographic correctness.

The focused `sqlcipher_database_key_application::tests` command verifies the accepted production dependency and primitive boundary without opening a database. It checks the one exact Windows production `rusqlite` declaration, absence of a Windows `rusqlite` development dependency and direct `libsqlite3-sys`, private module registration, exact fixed 67-byte lowercase raw-key encoding, nibble and boundary mapping, redacted formatting, best-effort clearing of the owned encoding buffer, exactly one injected native call for success and non-`SQLITE_OK` failure, `SQLITE_OK`-only success, coarse `DatabaseKeyApplicationError::Failed`, null-handle refusal before invocation, and source exclusions for opening, querying, mutation, rekey, integrity, logging, Tauri, IPC, and frontend surfaces. The injected handle token never reaches SQLite, so these tests do not establish runtime database behavior.

For the owner-SID warning, use a command-scoped override such as `git -c safe.directory=D:/Tauri/church-app status --short`; do not modify Git configuration.

## Current-account baseline and USB-flash controlled host harness

Run the focused harness diagnostic tests and the current-account baseline serially:

```powershell
cargo test --manifest-path src-tauri/Cargo.toml --locked controlled_storage_host_matrix_pure -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked controlled_storage_host_matrix_baseline_runtime -- --test-threads=1
```

The accepted manually rooted diagnostic USB rerun produced this redacted manual evidence:

- diagnostic stage: `DirectoryAttributeInfoUnavailable`;
- disposition: `Unavailable`;
- prerequisite: present;
- local-volume classification: unavailable/not reached;
- device-property classification: not reached;
- drive-type calls: 0;
- volume opens: 0;
- property IOCTL calls: 0;
- hot-plug calls: 0;
- sentinel verification: `NotReached`;
- exact-root cleanup attempted: true;
- exact-root cleanup succeeded: true;
- all authority fields: false;
- manual leftover-folder check: no entries.

This USB row remains failed and incomplete, not passed. Do not rerun this same USB merely to seek a different result, and do not reformat it for the test. A different controlled USB device would be a separate future matrix observation requiring separate approval. No filesystem type, hardware cause, removable/fixed classification, bus classification, or general USB-media incompatibility was established.

Run the accepted policy regressions. The shared hardening helper is unchanged, so no hardening-proof runtime filter is required for this correction:

```powershell
cargo test --manifest-path src-tauri/Cargo.toml --locked device_property_policy -- --test-threads=1
cargo test --manifest-path src-tauri/Cargo.toml --locked local_volume_policy -- --test-threads=1
```

The focused harness tests verify every fixed unavailable/rejected hardened-directory stage, first-failure precedence, the accepted operation order, zero pre-drive call counts, sentinel `NotReached` for early failure, distinct unavailable/changed/preserved sentinel results, exact-root-only removal, one cleanup attempt, combined primary-plus-cleanup preservation, redaction, native-call counts when reached, zero hot-plug calls, and no authority conversion. Child-creation and sentinel-write failures remain general fixture failures but are excluded as explanations for the recorded USB attempts because fixture construction completed and cleanup later succeeded. The accepted diagnostic observation identifies unavailable directory attribute/tag information only; it does not establish why those facts were unavailable. Missing USB input is a visible `PrerequisiteAbsent` result, not a pass. A manually confirmed USB flash drive yielding `DevicePropertyCandidate` remains a defect/unresolved false-confidence result and fails the USB case.

## Accepted guarded read-only SQLCipher connection-handoff evidence

The exact Windows production dependency, private raw-key primitive, metadata-only production database-file inspection, and guarded read-only connection handoff are implemented and accepted. Clean CI passed at commit `ae284b05b4169a609eca753bcc3f466c0e40d06f` with subject `feat(database): add guarded read-only SQLCipher handoff`.

Accepted focused evidence covers:

- the exact one application-level path-based `Connection::open_with_flags_and_vfs(..., "win32")` call;
- inclusion of `SQLITE_OPEN_READ_ONLY`, `SQLITE_OPEN_FULL_MUTEX`, `SQLITE_OPEN_PRIVATE_CACHE`, and `SQLITE_OPEN_NOFOLLOW`, and exclusion of read-write, create, shared-cache, no-mutex, memory, and URI flags;
- no main database creation when the database is missing, no application retry loop, and no writable fallback;
- guard acquisition with `FILE_READ_ATTRIBUTES | FILE_READ_DATA`, `FILE_SHARE_READ`, `OPEN_EXISTING`, and `FILE_FLAG_OPEN_REPARSE_POINT`;
- guard/proof identity matching before SQLite open and SQLite/proof identity matching through the borrowed `SQLITE_FCNTL_WIN32_GET_HANDLE` main-database handle;
- detection of database-file substitution between inspection, guard acquisition, and SQLite-handle verification;
- denial of ordinary incompatible write, delete, rename, and replacement opens while the verified guard lives under normal Windows sharing semantics;
- five-second busy timeout, extension loading disabled, defensive mode enabled, trusted schema disabled, no-checkpoint-on-close enabled, attach-create and attach-write disabled, and main-database read-only state confirmed;
- exactly one key call after pre-key policy and only then query-only enablement and verification;
- opaque keyed-but-unvalidated ownership with no exposed guard, file, path, identity, content-read API, raw handle, or database-content capability;
- full `Connection`/guard/proof ownership retained after construction-time or normal close failure, with consuming close and close-retry behavior; and
- redacted coarse failure behavior and absence of an operational caller, frontend, IPC, or Tauri command.

All 40 focused tests across `production_database_connection_handoff`, `production_database_file`, and `sqlcipher_database_key_application` passed. The accepted workflow also passed frontend formatting, frontend lint, frontend type-check, frontend tests, Rust formatting, Rust Clippy with warnings denied, and the locked Rust test suite. Rust totals were 616 passed, 0 failed, and 1 ignored.

No production runtime caller, live metadata read, or operational database use was manually tested for this earlier handoff commit. Its accepted evidence establishes the guarded keyed-but-unvalidated handoff; the succeeding readability-and-integrity evidence is recorded separately below.

## Accepted database readability-and-integrity validation evidence

The consuming readability-and-integrity transition is implemented and accepted at commit `547527a6ff7332ce3256eeb28704bbdf76913f93` with subject `feat(database): validate SQLCipher readability and integrity`. The `Bootstrap validation` workflow run `30768297789` completed successfully, and its job conclusion was success. Frontend formatting, lint, type-check, and tests passed; Rust formatting and Clippy with warnings denied passed; and the locked Rust suite reported 630 passed, 0 failed, and 1 ignored. All new tests passed, with no new test ignored or filtered out. The single ignored test remains the unrelated pre-existing manually rooted USB controlled-host test.

Focused accepted database totals were:

- `production_database_connection_handoff`: 29 passed;
- `production_database_file`: 18 passed;
- `sqlcipher_database_key_application`: 7 passed;
- total focused database tests: 54 passed.

Accepted real-engine and injected evidence covers:

- consumption of `ProductionReadOnlyDatabaseConnection` and the exact private order `PRAGMA cipher_integrity_check`, normal zero-row completion, `PRAGMA main.quick_check(1)`, exactly one complete SQLite `TEXT` value `ok`, normal end-of-stream, and return of `ReadabilityAndIntegrityValidatedProductionDatabaseConnection`;
- a valid correct-key SQLCipher database, wrong key, controlled ciphertext/HMAC corruption, and a minimal encrypted database without product schema or metadata;
- first-cipher-row failure without decoding, copying, formatting, retaining, or logging diagnostic text;
- exact quick-check success and zero-row, multiple-row, non-text, non-`ok`, malformed, interrupted, stepping-error, and incomplete result shapes;
- phase-aware classification at statement preparation, query startup, and row stepping into exactly `EncryptedDatabaseAuthenticationOrCipherIntegrityFailed`, `SQLiteReadabilityOrIntegrityFailed`, `ValidationUnavailable`, or `ValidationInterruptedOrIncomplete`;
- release of row streams and statements before failure close; primary-category preservation on close failure; consuming repeated close retry; validated-owner close failure; and retention of the same connection, write guard, and inspection proof; and
- redaction and authority-boundary source checks excluding raw rusqlite errors, native codes, paths, keys, identifiers or identities, SQL/PRAGMA text, result diagnostics, raw handles, unrestricted SQL, connection exposure, operational callers, frontend, IPC, and Tauri commands.

No separate readability query, `sqlite_master` query, metadata-table read, `application_id` or `user_version` observation, product-content query, explicit SQLite transaction, active cancellation API, or rusqlite hooks feature was added. The accepted synchronous `cipher_integrity_check` workload is proportional to database pages, with no production database-size ceiling or bounded-latency claim, and remains acceptable only while there is no operational caller.

This automated evidence does not constitute manual application or production runtime validation. No operational flow invokes the owner, so no manual application/runtime flow applies to this boundary. The validated owner proves only the fixed readability-and-integrity contract; it does not establish metadata table existence, metadata row validity, SQLite `application_id`, SQLite `user_version`, schema-contract validity, database/evidence correspondence, freshness, startup authorization, setup authority, migration authority, recovery authority, backup/restore authority, or operational database use.

## Accepted live metadata and SQLite-header validation evidence

The consuming live metadata and SQLite-header validation transition is implemented and accepted at commit `aa2317eddeca73d7709f84136f12067d80e0a881` with subject `feat(database): validate live metadata and headers`. The `Bootstrap validation` workflow run `30778837736` completed successfully, and its workflow and job conclusions were both success. Frontend formatting, lint, type-check, and tests passed; Rust formatting and Clippy with warnings denied passed; and the locked Rust suite reported 645 passed, 0 failed, and 1 ignored. All 15 new live metadata/header tests passed, with no new test ignored or filtered out. The single ignored test remains the unrelated pre-existing manually rooted USB controlled-host test.

The accepted transition consumes `ReadabilityAndIntegrityValidatedProductionDatabaseConnection`, retains the same connection/guard/inspection lifetime unit, and returns only `LiveMetadataAndHeaderValidatedProductionDatabaseConnection` with one owned `DatabaseMetadataContractV1`. It has no operational caller. This automated evidence is not manual application or production runtime validation, and no manual application/runtime flow applies while no operational flow invokes the owner.

### Accepted live metadata and header validation matrix

Accepted real encrypted SQLCipher fixtures enter through the same guarded readability-and-integrity-validated ownership chain and cover:

- correct `application_id`, matching `user_version`, exactly one canonical metadata row, successful `LiveMetadataAndHeaderValidatedProductionDatabaseConnection`, consuming explicit close, and exact temporary-root cleanup;
- wrong `application_id` and immediate first-failed-stage precedence;
- wrong `user_version` against supported validated metadata;
- absent named relation;
- present but empty relation;
- duplicate rows, including a valid first row;
- `NULL` representatives across integer, text, 16-byte BLOB, and 8-byte generation field families;
- wrong storage classes across integer, text, 16-byte BLOB, and 8-byte generation field families;
- short and long 16-byte BLOB values;
- short and long 8-byte generation BLOB values;
- invalid UTF-8 SQLite `TEXT`;
- correctly represented unsupported metadata contract version;
- correctly represented unsupported database schema version;
- wrong canonical application identifier;
- wrong database-format identity;
- zero values for every identifier family;
- zero installation and recovery/replacement generations;
- negative creation timestamp;
- supported schema metadata with a mismatching `user_version`;
- missing required column or another non-preparable fixed-query state; and
- source/behavior evidence that the adapter executes only the two fixed PRAGMAs and explicit 12-column `LIMIT 2` query, never filters by `singleton_id`, copies the first row before the second step, invokes `parse()` and `validate_structure()` exactly once each, and retains no separate header value on success.

Accepted private injected seams cover states that the fixed valid statements cannot reliably produce:

- header statement wrong column count;
- metadata statement wrong column count;
- header zero rows and extra rows;
- metadata step failure before the first row;
- metadata step failure during the second-step terminal check;
- unavailable expected-column access;
- successful explicit close after every canonical primary category;
- close failure after every canonical primary category;
- repeated consuming close-retry failure and eventual success; and
- explicit close failure from the successful live-metadata owner after its metadata contract is discarded.

The tests assert the canonical taxonomy and exact first-failed-stage precedence: application-ID observation unavailable; wrong application ID; user-version observation unavailable; metadata preparation/query-startup unavailable; metadata stepping interruption or incomplete terminal state; missing row; duplicate rows; malformed storage class, UTF-8, parse, or non-version structural state; unsupported metadata contract version; unsupported database schema version; remaining structural invalidity as malformed; then user-version mismatch. They prove that defects are not collected, `CloseFailed` is ownership-bearing rather than primary, temporary observations are discarded before close, close failures retain the original category plus the full connection/guard/inspection unit, and outward formatting reveals none of the prohibited live values or diagnostics.

Fixture creation used synthetic encrypted schemas, rows, and header assignments before the guarded read-only transition. That test-only preparation grants no production schema creation, header mutation, migration, repair, normalization, or other mutation authority. The live stage fails closed on absence and makes no claim of physical DDL, constraints, indexes, triggers, object kind, wider product-schema correctness, correspondence, freshness, startup/setup authority, recovery, backup/restore, replacement, business-data correctness, or operational opening.

## Accepted identity-only database/evidence correspondence evidence

The consuming identity-only correspondence transition is implemented and accepted at commit `8b880621e9d7cf9dcff30eaab31f84958926d024` with subject `feat(database): validate evidence correspondence`. The `Bootstrap validation` workflow run `30786193482` (run number 17) completed successfully, and its workflow and job conclusions were both success. Frontend formatting, lint, type-check, and all 5 frontend tests passed; Rust formatting and Clippy with warnings denied passed; and the locked Rust suite reported 655 passed, 0 failed, and 1 ignored. All 10 new correspondence tests passed, with no correspondence test ignored or filtered out. The sole ignored test remains the unrelated pre-existing manually rooted USB controlled-host test.

The implemented transition consumes `LiveMetadataAndHeaderValidatedProductionDatabaseConnection` and exactly `TrustedCurrentInstallationEvidenceAssessment`, invokes the existing pure classifier exactly once, and returns opaque `DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection` on success. Both inputs are consumed. There is no operational caller, so this automated evidence is not manual application or production runtime validation and no manual application/runtime flow applies.

Accepted pure correspondence evidence covers:

- an exact full match corresponds;
- parish mismatch is the aggregate mismatch;
- installation mismatch is the aggregate mismatch;
- database-key generation mismatch is the aggregate mismatch;
- setup-publication mismatch is the aggregate mismatch;
- canonical permanent application identifier and database-format comparisons remain present;
- installation and recovery/replacement generations are ignored;
- database and evidence creation timestamps are ignored;
- evidence-format identity and version are incapable of affecting correspondence; and
- one or multiple mismatches remain the same coarse result.

If the validated version-1 constructors make noncanonical permanent-application or database-format fixtures unreachable, source-boundary evidence may supplement those cases; validators must not be weakened to create impossible fixtures.

Accepted live composition and ownership evidence covers:

- a real accepted live metadata/header owner plus matching synthetic trusted assessment succeeds;
- the success owner is opaque, manually redacted, consumes normally, closes normally, and performs exact temporary-root cleanup;
- every constructible identity mismatch yields only `DatabaseEvidenceCorrespondenceMismatch`;
- simultaneous mismatches still yield that same category;
- differing generations and timestamps do not fail correspondence;
- metadata and trusted assessment are dropped before mismatch close;
- successful mismatch close returns the primary category;
- mismatch close failure retains the category plus the complete lifetime owner;
- repeated consuming close failure preserves both, and eventual retry success returns the original mismatch;
- successful-owner close drops metadata and trusted assessment before close;
- successful-owner close failure reuses the existing capability-free close failure and retains only lifetime ownership;
- manual `Debug` for the success owner, mismatch, initial outcome, close-failure owner, and retry outcome is exactly coarse and does not delegate to retained values; and
- no operational caller, Tauri command, IPC, or frontend surface exists.

Real SQLCipher predecessor fixtures cover matching composition, normal consuming close, exact temporary-root cleanup, parish mismatch, installation mismatch, database-key-generation mismatch, setup-publication mismatch, simultaneous mismatches, differing installation generation, differing recovery/replacement generation, differing evidence timestamp, and combined generation/timestamp differences.

Accepted deterministic injected-ownership evidence covers metadata and trusted-assessment destruction before mismatch close; successful mismatch close; failed mismatch close with complete lifetime ownership retention; repeated close failure; eventual successful retry returning the original mismatch; successful-owner metadata and assessment destruction before close; and successful-owner close failure retaining only lifetime ownership.

Accepted source-boundary checks prove that the production correspondence adapter:

- invokes `classify_database_metadata_correspondence` exactly once;
- contains no SQL or `PRAGMA`;
- contains no rusqlite prepare, query, or row-reading call;
- exposes no `Connection` accessor or arbitrary-SQL callback;
- performs no filesystem operation or path resolution;
- performs no DPAPI, HMAC, envelope parsing, plaintext parsing, or evidence loading;
- performs no generation or timestamp comparison;
- performs no schema mutation;
- adds no Tauri command, IPC, frontend surface, unsafe block, or FFI; and
- requires no dependency or Cargo feature change.

Test construction uses only this `cfg(test)` seam in `installation_evidence_protection/trusted_current_installation_evidence_assessment.rs`:

```rust
#[cfg(test)]
pub(crate) fn trusted_current_installation_evidence_assessment_for_test(
    evidence: StructurallyValidatedInstallationEvidence,
) -> TrustedCurrentInstallationEvidenceAssessment
```

The helper derives `TrustedCurrentInstallationIdentity` internally through the existing pure derivation, accepts no independently supplied identity, remains absent from production compilation, performs no filesystem access, DPAPI, HMAC, loading, or parsing, and confers no production authority.

The implemented outcome family is `DatabaseEvidenceCorrespondenceMismatch`, `DatabaseEvidenceCorrespondenceValidationOutcome`, `DatabaseEvidenceCorrespondenceValidationCloseFailure`, `DatabaseEvidenceCorrespondenceValidationCloseRetryOutcome`, and `DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection`. Tests prove that the first outcome distinguishes success ownership, mismatch after successful close, and mismatch with retained close-failure ownership; `CloseFailed` is not a primary category.

The accepted source-boundary evidence also confirms private nested placement beneath `live_metadata_and_header_validation`; no `Connection` exposure, arbitrary SQL callback, detachable proof, crate-root bridge, unsafe code, FFI, dependency, Cargo feature, schema work, migration, public API, operational caller, frontend, IPC, or Tauri command was introduced. Correspondence success establishes none of equal lineage, freshness, rollback resistance, startup authorization, operational database opening, setup completion, migration status, physical DDL, relation object kind, wider product-schema correctness, recovery fitness, backup/restore suitability, replacement authority, or business-data correctness.

## Approved future preloaded normalized freshness verification requirements

The architecture is approved but unimplemented. No test result, CI run, manual application observation, production runtime behavior, or passing live freshness evidence is claimed here. The future transition consumes `DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection` and exactly `NormalizedFreshnessAnchorObservation`; all four normalized states are accepted, and no real anchor filesystem or DPAPI test is required for this preloaded adapter because loading, authentication, binding, assurance, and normalization remain upstream.

### Pure regression requirements

The existing unchanged pure suite must continue proving:

- `Fresh`, `StaleEvidence`, `StaleDatabase`, `RollbackSuspicion`, `IdentityMismatch`, `AnchorMissing`, `AnchorUnavailable`, `AnchorInvalid`, and `Ambiguous`;
- correspondence mismatch has precedence before every anchor state;
- exact three-way installation, database-key-generation, and setup-publication identity checks;
- all weak orderings for installation lineage and recovery/replacement lineage;
- the complete lineage-state cross-product;
- gap magnitude, maximum, and above-anchor boundary behavior; and
- the coordinated-rollback limitation, under which mutually consistent older database, evidence, and anchor snapshots may still classify `Fresh`.

The live work must not modify the pure classifier or precedence absent a separately demonstrated defect.

### Live real-chain requirements

Future live tests must obtain genuine `DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection` values through the existing real SQLCipher predecessor chain and supply synthetic preloaded normalized observations. They must cover:

- `Fresh` success, consuming normal close, and exact temporary-root cleanup;
- `AnchorMissing`, `AnchorUnavailable`, and `AnchorInvalid`;
- present-anchor mismatch for installation identifier, database-key-generation identifier, and setup-publication identifier;
- `StaleEvidence`, `StaleDatabase`, `RollbackSuspicion`, and `Ambiguous`; and
- exact cleanup for every case whose close succeeds.

No path, presence inspection, wrapper loading, DPAPI, HMAC, parsing, binding, assurance, or normalization should run inside the adapter tests. Synthetic present observations may use the existing contract, installation-bound-anchor, and production assurance transitions; non-present variants are directly constructible.

### Ownership, destruction, retry, and redaction requirements

Injected close and destruction-order evidence must prove:

- every non-Fresh classification is preserved after successful close;
- `Fresh` never enters failure handling or appears in a failure/retry form;
- classification finishes before close begins;
- metadata, trusted assessment, normalized observation, and any assured anchor are destroyed before non-success close;
- close failure retains exactly the classification and complete lifetime owner;
- consuming repeated retry failure preserves both, and eventual success returns the original classification;
- retry performs no classification, loading, or other work;
- successful-owner metadata and assessment are destroyed before close;
- successful-owner close failure reuses `ProductionDatabaseConnectionCloseFailure` and retains only lifetime ownership; and
- manual `Debug` is exactly coarse: only payload-free non-Fresh names may appear, while owners and ownership-bearing failures remain redacted.

Only narrow `cfg(test)` close-injection and destruction-order seams inside the new nested module are approved. Tests must not require a production constructor, production visibility widening, arbitrary `Connection` callback, forgeable freshness-success constructor, or classifier bypass.

### Source-boundary requirements

Source assertions must prove:

- `classify_database_freshness` is invoked exactly once with `DatabaseMetadataCorrespondence::Corresponds`, `&metadata_contract`, `trusted_assessment.evidence()`, and `&anchor_observation`;
- ephemeral `Corresponds` translation is confined to the sealed adapter, with no retained, returned, or detachable proof and no correspondence-classifier call;
- no duplicated generation comparison, anchor-identity comparison, lineage combination, precedence, or timestamp accessor exists;
- no SQL, PRAGMA, prepare, query, row read, database-content operation, or `Connection` exposure exists;
- no filesystem, path, presence inspection, loading, DPAPI, HMAC, wrapper/envelope/plaintext/contract parsing, authentication, generation matching, binding, assurance, or normalization exists;
- no schema, migration, unsafe code, FFI, dependency, feature, public API, Tauri command, IPC, frontend, or operational caller is added;
- `DatabaseFreshnessValidatedProductionDatabaseConnection` contains exactly `ConnectionLifetimeOwner`, `DatabaseMetadataContractV1`, and `TrustedCurrentInstallationEvidenceAssessment`;
- `ProductionDatabaseFreshnessValidationCloseFailure` contains exactly `DatabaseFreshnessClassification` and `ConnectionLifetimeOwner`; and
- `Fresh` is impossible in `Failed`, close-failure ownership, and close-retry outcomes.

The approved nested source location is `production_database_connection_handoff/live_metadata_and_header_validation/database_evidence_correspondence_validation/database_freshness_validation.rs`, declared and narrowly reexported by the correspondence module without visibility widening or a crate-root bridge.

## Remaining production database verification gates

- Preloaded normalized freshness composition is the next approved but unimplemented verification gate. It consumes `DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection` plus exactly one `NormalizedFreshnessAnchorObservation`, invokes the unchanged pure classifier once with ephemeral `DatabaseMetadataCorrespondence::Corresponds`, advances only on `Fresh`, and otherwise explicitly closes. The complete verification requirements are recorded above. No passing live freshness evidence or operational caller exists.
- Schema-creation tests must prove only the separately approved version-1 schema, singleton metadata row, `application_id = 0x43484150`, mirrored `user_version`, and fail-closed header/metadata disagreement. They remain separate from live read-only validation and correspondence.
- Path/link/sidecar tests must cover the exact application-owned NTFS path and filename, reparse/symlink/junction/mount traversal, cloud placeholder, hard link, network/removable storage, stable final path and identity, race revalidation, unexpected sidecars, and initial WAL/SHM prohibition. Startup must be proven unable to delete or repair sidecars.
- Transaction-policy tests must cover rollback-journal `DELETE`, `synchronous=FULL`, explicit transactions, `secure_delete=ON`, `auto_vacuum=NONE`, no automatic journal switch, no automatic VACUUM, and no WAL checkpoint behavior.
- Interrupted setup, migration, rekey, anchor replacement, database replacement, and controlled journal recovery tests must prove fail-closed restart classification and absence of generic repair. Migration tests additionally require explicit maintenance authorization, verified recoverable backup, prior full integrity success, forward-only behavior, and no automatic downgrade.
- Backup and staged-restore tests must prove SQLCipher-only encrypted artifacts, separate recovery-key envelopes, full integrity at acceptance, exact correspondence and lineage policy, explicit recovery authority, and no production plaintext database or fallback.
- Authority tests must prove that persisted presence, evidence validation, path validation, key recovery, read-only opening, metadata decoding, integrity, correspondence, freshness, installation-state classification, startup authorization, operational opening, setup, migration, recovery, replacement, and destructive cleanup cannot substitute for one another.
- Clean-machine release verification must run separately on supported Windows 10 x64 and Windows 11 x64 local-NTFS standard-user hosts. It must record pinned `rusqlite`, SQLCipher, OpenSSL, and lockfile identity; prove no system SQLCipher/OpenSSL dependency; and reject every unsupported platform/storage category. Release automation details remain deferred.

The existing `sqlcipher_windows_temporary_encryption_feasibility` test remains historical Windows test-only experiment evidence.

Carlo must manually review the approval record; the metadata-only inspector versus the separate lifetime guard; the inspected proof, guard, SQLite handle, and owner identity/lifetime chain; the exact one-open flags and `win32` VFS; pre-key policy, one key application, and post-key query-only ordering; the distinct keyed-but-unvalidated, readability-and-integrity-validated, live-metadata-and-header-validated, and correspondence-validated results; the exact cipher-then-quick-check and live-observation boundaries; the implemented consuming correspondence transition; accepted workflow run `30786193482` (run number 17) and its 655/0/1 Rust result with all 10 new correspondence tests passing; the unrelated pre-existing ignored USB test; the approved but still-unimplemented freshness boundary; the still-absent startup-authority and operational-opening boundaries; and confirmation that this documentation change contains no code, passing freshness evidence, or runtime claim.

For correspondence Carlo must manually confirm the exact two consumed input types; prohibition on weaker or internally loaded evidence; exactly-once reuse of the six-field pure classifier; the single coarse mismatch category and unobservable field precedence; private retention of only lifetime owner, validated metadata, and trusted assessment; strict exclusion of generations, timestamps, and evidence-format fields from correspondence; later whole-owner freshness composition; private nested module placement without visibility widening; metadata/evidence disposal before mismatch or successful-owner close; mismatch close-failure and retry ownership; reuse of the existing general successful-owner close failure; strict redaction; the narrow production-absent `cfg(test)` trusted-assessment seam; the accepted real SQLCipher, ownership, and source-boundary evidence; the absence of new dependencies, features, FFI, unsafe, filesystem, DPAPI, HMAC, SQL, schema, migration, public API, and operational caller; and the locked limitations on lineage, freshness, rollback resistance, startup, operational opening, setup, migration, DDL/object kind, wider schema, recovery, backup/restore, replacement, and business data.

For freshness Carlo must manually confirm the two consumed inputs and all four normalized observation states; prohibition on paths and weaker or earlier anchor forms; completion of loading, DPAPI, HMAC, parsing, binding, assurance, and normalization before the adapter; one ephemeral `Corresponds` argument and exactly one unchanged pure-classifier call; Fresh-only advancement and direct reuse of the pure taxonomy; disposal of the normalized observation and any assured anchor even on success; exact three-field success ownership; classification plus lifetime-only close-failure ownership; destruction before close, consuming retry, and reuse of the general successful-owner close failure; nested placement without visibility widening or callbacks; redaction; the pure, real-chain, ownership, and source-boundary requirements above; the coordinated-rollback limitation; absence of new dependencies, features, FFI, unsafe, filesystem/path, DPAPI, HMAC, parsing, SQL, database read, schema, migration, public API, operational caller, frontend, IPC, or Tauri work; and continued separation from startup authorization and operational opening.

## Environment-dependent and manual checks

`npm run tauri:dev` needs Microsoft C++ Build Tools and WebView2. It opens the real window. Local structured health events appear in its terminal; no log file or upload exists.

To inspect the unknown route, use webview devtools when available and run `window.history.pushState({}, "", "/not-a-route"); window.dispatchEvent(new PopStateEvent("popstate"));`. Health failure is safely covered by `npm test`, which mocks an invalid command response containing raw backend detail. There is no production crash trigger; manual visual inspection requires an uncommitted, disposable equivalent mock.

On Windows 11, manually inspect startup, one-window behavior, keyboard use, focus, resizing, scaling, health success, and logs. Repeat startup on Windows 10 where available. Neither target is verified until observed.

A temporary Windows-only SQLCipher feasibility database check is included, but it is not production database validation and automation does not prove production storage security; no production build, installer, signing, release, deployment, browser or desktop E2E automation, coverage threshold, or service check is included. CI omits `tauri build`; Clippy and Rust tests provide narrow compile coverage without generating an installer. Automation does not prove runtime startup, Windows 10 support, WebView2 availability, real-webview accessibility, low-memory support, security, or parish workflows.
