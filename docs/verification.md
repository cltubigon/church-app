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

The focused installation-state tests supply only synthetic evidence to pure Rust decisions. They verify that ordinary startup cannot authorize setup, the pure authorization transition permits only the distinct setup path, initialized-but-missing and inconsistent states fail closed, present storage indicates only future open eligibility, the authorization boundary has no boolean, string, path, frontend, or Tauri argument, and that pure boundary creates no directory or file. The implemented setup lifecycle consumes this authority separately; the persistence classifier has no direct conversion to the operational model.

The focused storage-foundation tests use Windows-like and portable synthetic roots for path construction and do not create directories or files. They verify all seven exact active/stage names, continued canonical ownership of `parish-data.db`, typed active/evidence/publication-stage paths, evidence-directory nesting, direct-root database staging, restore-versus-publication staging separation, redacted debug output, existing production/development/test/restore separation, unique safe automated-test identities, and narrow database-format and parish-identifier representations. Production path resolution itself remains behind Rust's Tauri application-handle boundary and is not invoked by the new constructor.

The focused installation-evidence-persistence tests are deterministic and pure. They cover the reported lengths 0, 1, 14, 15, 65,549, 65,550, and 65,551; exact minimum and maximum reads; rejection before an oversized read or allocation; one-byte and multi-byte short reads; interrupted reads followed by success; ordinary failure; trailing data and simulated growth; error/value redaction; and source exclusions for unbounded reads, memory mapping, and filesystem operations. Classifier tests cover all 64 active/stage presence combinations, absent and empty evidence directories, every asymmetry, stage, unavailable fact, and unexpected entry type with exact precedence. Publication tests cover all valid and out-of-order events, every interruption and failure boundary, refused baselines, and evidence-last success for all three operation kinds.

The pure persistence stage remains side-effect free. The separately gated Windows adapter proof performs filesystem operations only beneath its unique test-owned roots and uses the existing bounded reader. It does not resolve or touch production evidence paths and performs no DPAPI, database, setup/startup, recovery, rollback, IPC, or frontend behavior.

The focused SQLCipher command is a Windows-only feasibility test. It creates an encrypted database under the operating system temporary directory, verifies independent correct-key and wrong-key connections, reports non-sensitive native identity and cipher configuration, scans the database and retained journal sidecar for the synthetic plaintext sentinel, and removes its test directory. It does not select or exercise a production data location. The absence of the sentinel is supporting evidence, not complete proof of cryptographic correctness.

The focused `sqlcipher_database_key_application::tests` command verifies the accepted production dependency and primitive boundary without opening a database. It checks the one exact Windows production `rusqlite` declaration, absence of a Windows `rusqlite` development dependency and direct `libsqlite3-sys`, private module registration, exact fixed 67-byte lowercase raw-key encoding, nibble and boundary mapping, redacted formatting, best-effort clearing of the owned encoding buffer, exactly one injected native call for success and non-`SQLITE_OK` failure, `SQLITE_OK`-only success, coarse `DatabaseKeyApplicationError::Failed`, null-handle refusal before invocation, and source exclusions for opening, querying, mutation, rekey, integrity, logging, Tauri, IPC, and frontend surfaces. The injected handle token never reaches SQLite, so these tests do not establish runtime database behavior.

For the owner-SID warning, use a command-scoped override such as `git -c safe.directory=D:/Tauri/church-app status --short`; do not modify Git configuration.

## Repository task delivery workflow

Routine narrowly scoped Codex work normally combines the approved edit, task-specific validation, exact allowed-file review, explicit-path staging, complete staged-patch inspection, `git diff --cached --check`, and one ordinary local commit, then stops. Push is not automatic and occurs only after Carlo explicitly instructs or approves pushing the relevant local commit or commits. Multiple approved local commits may remain stacked ahead of `origin/main` until Carlo chooses to push them. An explicit prompt may narrow or override this workflow with implementation-only and no commit, a read-only audit, review before commit, documentation-only work, commit-only work, an explicitly authorized push, or other behavior.

Before staging or commit, stop for Carlo/Project-Manager review if the prompt requires it; the baseline materially differs; unexpected or unauthorized files changed; a product/architecture conflict or unpreservable locked decision appears; scope must expand; security or ownership ambiguity remains; required security/correctness validation fails or contradicts the claim; prohibited dependency, database, migration, infrastructure, secret, environment, or deployment work would be required; or exact staged-scope correspondence cannot be proved. Leave the working tree intact, do not repair unrelated work, and do not stage, commit, or push.

For routine delivery, preserve unrelated changes, stage only named approved paths, never use `git add .` or `git add -A`, inspect the entire staged diff, and prohibit amend, rebase, reset, restore, stash, and force-push unless separately authorized. After the local commit, prove a clean working tree, an empty index, and no untracked files, and report the commit hash, exact subject, direct parent, exact committed files, current divergence from `origin/main`, whether a normal fast-forward push appears available, and that push is pending Carlo's instruction. When Carlo authorizes a push, refresh the remote first, use only a normal fast-forward push unless explicitly authorized otherwise, and stop if remote advancement prevents it. After an approved push, prove final upstream equality, divergence, worktree cleanliness, index state, and untracked-file state. Neither the routine commit workflow nor an authorized push broadens validation authority: use only the narrowest task-relevant approved checks and do not add expensive, destructive, deployment-affecting, or broad validation merely because delivery includes a commit or push.

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
- redacted coarse failure behavior and absence of a direct frontend, IPC, Tauri-command, or separate application caller in that boundary; the later lifecycle composes it through the fixed chain.

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
- redaction and authority-boundary source checks excluding raw rusqlite errors, native codes, paths, keys, identifiers or identities, SQL/PRAGMA text, result diagnostics, raw handles, unrestricted SQL, connection exposure, direct frontend/IPC callers, and Tauri commands.

No separate readability query, `sqlite_master` query, metadata-table read, `application_id` or `user_version` observation, product-content query, explicit SQLite transaction, active cancellation API, or rusqlite hooks feature was added. The accepted synchronous `cipher_integrity_check` workload is proportional to database pages, with no production database-size ceiling or bounded-latency claim. The later lifecycle runs it on the blocking startup worker rather than the UI/event loop.

This boundary's automated evidence did not by itself constitute manual application or production runtime validation. The later accepted lifecycle and manual scenarios exercise it only as part of the whole startup chain. The validated owner still proves only the fixed readability-and-integrity contract.

## Accepted private full-integrity validation evidence

The private consuming full-integrity transition is implemented and accepted at commit `3d7e71551b8ec23af7ec47a227b6c37ac190b546` with subject `feat(database): add full integrity validation boundary`. It consumes `ReadabilityAndIntegrityValidatedProductionDatabaseConnection`, retains the guarded connection lifetime, runs only fixed `PRAGMA main.integrity_check`, and returns `FullIntegrityValidatedProductionDatabaseConnection` only for exactly one SQLite `TEXT` row exactly equal to `ok` followed by normal completion. Malformed, unavailable, interrupted, incomplete, zero-row, extra-row, non-`TEXT`, and non-`ok` outcomes fail closed. Accepted evidence also covers explicit close, ownership-bearing close retry, and exclusion of connection access, arbitrary SQL, paths, keys, metadata, diagnostic text, raw handles, and backend errors.

Focused `full_integrity` tests reported 8 passed. `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, and `git diff --check` passed. Pre-existing OpenSSL missing-PDB linker warnings were non-fatal. No broad Rust suite or frontend suite was run for this unwired Rust-only slice, and no manual runtime test was warranted.

At the time of its isolated acceptance this boundary had no production caller. Later implementation composes it into the exact migration source consumed by the verified encrypted backup stage, while ordinary startup still performs only `PRAGMA cipher_integrity_check` followed by `PRAGMA main.quick_check(1)` and setup remains unchanged. Full integrity alone establishes no migration authorization, portable recoverability, writable maintenance ownership, schema-version-2 implementation, interruption/restart policy, or update ordering.

## Accepted live metadata and SQLite-header validation evidence

The consuming live metadata and SQLite-header validation transition is implemented and accepted at commit `aa2317eddeca73d7709f84136f12067d80e0a881` with subject `feat(database): validate live metadata and headers`. The `Bootstrap validation` workflow run `30778837736` completed successfully, and its workflow and job conclusions were both success. Frontend formatting, lint, type-check, and tests passed; Rust formatting and Clippy with warnings denied passed; and the locked Rust suite reported 645 passed, 0 failed, and 1 ignored. All 15 new live metadata/header tests passed, with no new test ignored or filtered out. The single ignored test remains the unrelated pre-existing manually rooted USB controlled-host test.

The accepted transition consumes `ReadabilityAndIntegrityValidatedProductionDatabaseConnection`, retains the same connection/guard/inspection lifetime unit, and returns only `LiveMetadataAndHeaderValidatedProductionDatabaseConnection` with one owned `DatabaseMetadataContractV1`. Its focused automated evidence remains distinct from the later whole-lifecycle manual evidence.

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

Fixture creation used synthetic encrypted schemas, rows, and header assignments before the guarded read-only transition. That test-only preparation grants no production schema creation, header mutation, migration, repair, normalization, or other mutation authority. The live stage fails closed on absence and makes no claim of physical DDL, constraints, indexes, triggers, object kind, wider product-schema correctness, correspondence, freshness, startup/setup authority, operational activation, recovery, backup/restore, replacement, or business-data correctness.

## Accepted identity-only database/evidence correspondence evidence

The consuming identity-only correspondence transition is implemented and accepted at commit `8b880621e9d7cf9dcff30eaab31f84958926d024` with subject `feat(database): validate evidence correspondence`. The `Bootstrap validation` workflow run `30786193482` (run number 17) completed successfully, and its workflow and job conclusions were both success. Frontend formatting, lint, type-check, and all 5 frontend tests passed; Rust formatting and Clippy with warnings denied passed; and the locked Rust suite reported 655 passed, 0 failed, and 1 ignored. All 10 new correspondence tests passed, with no correspondence test ignored or filtered out. The sole ignored test remains the unrelated pre-existing manually rooted USB controlled-host test.

The implemented transition consumes `LiveMetadataAndHeaderValidatedProductionDatabaseConnection` and exactly `TrustedCurrentInstallationEvidenceAssessment`, invokes the existing pure classifier exactly once, and returns opaque `DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection` on success. Both inputs are consumed. Its focused automated evidence remains distinct from the later whole-lifecycle manual evidence.

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
- the adapter itself adds no Tauri command, IPC, or frontend surface; the later Rust-owned lifecycle is its only application-level composition.

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

## Accepted preloaded normalized freshness implementation evidence

The freshness transition was implemented in commit `8770ca7fa99adc3c8554f1d51ad310d2084d5cf0` (`feat(database): validate preloaded freshness`). `Bootstrap validation` run `30802303048` (run number 20), head SHA `8770ca7fa99adc3c8554f1d51ad310d2084d5cf0`, failed because a pre-existing environment-sensitive loader test imposed an over-strong historical-continuity expectation. That historical run remains a failure. Commit `da91011c1553cd22f8a14da7bc2db6fede9e784c` (`test: align anchor loader replacement expectation`) changed only the test expectation to match the existing production loader contract. `Bootstrap validation` run `31724049978` (run number 21), head SHA `da91011c1553cd22f8a14da7bc2db6fede9e784c`, completed successfully.

The accepted final evidence for this stage is: frontend 5 passed; Rust 665 passed, 0 failed, 1 ignored; freshness adapter 10/10; pure freshness 14/14; correspondence-related 20/20; loader Windows module 11/11; full loader module 17/17; Clippy passed with warnings denied; and formatting passed. The single ignored test is the unrelated pre-existing manually rooted USB controlled-host test. Later whole-lifecycle manual results are recorded separately below.

The implemented transition consumes `DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection` and exactly `NormalizedFreshnessAnchorObservation`; all four normalized states are accepted, and no real anchor filesystem or DPAPI operation occurs in this preloaded adapter because loading, authentication, binding, assurance, and normalization remain upstream.

### Accepted pure regression evidence

The unchanged pure suite proves:

- `Fresh`, `StaleEvidence`, `StaleDatabase`, `RollbackSuspicion`, `IdentityMismatch`, `AnchorMissing`, `AnchorUnavailable`, `AnchorInvalid`, and `Ambiguous`;
- correspondence mismatch has precedence before every anchor state;
- exact three-way installation, database-key-generation, and setup-publication identity checks;
- all weak orderings for installation lineage and recovery/replacement lineage;
- the complete lineage-state cross-product;
- gap magnitude, maximum, and above-anchor boundary behavior; and
- the coordinated-rollback limitation, under which mutually consistent older database, evidence, and anchor snapshots may still classify `Fresh`.

The implementation did not modify the pure classifier or precedence.

### Accepted live real-chain evidence

Accepted live tests obtain genuine `DatabaseEvidenceCorrespondenceValidatedProductionDatabaseConnection` values through the existing real SQLCipher predecessor chain and supply synthetic preloaded normalized observations. They cover:

- `Fresh` success, consuming normal close, and exact temporary-root cleanup;
- `AnchorMissing`, `AnchorUnavailable`, and `AnchorInvalid`;
- present-anchor mismatch for installation identifier, database-key-generation identifier, and setup-publication identifier;
- `StaleEvidence`, `StaleDatabase`, `RollbackSuspicion`, and `Ambiguous`; and
- exact cleanup for every case whose close succeeds.

No path, presence inspection, wrapper loading, DPAPI, HMAC, parsing, binding, assurance, or normalization should run inside the adapter tests. Synthetic present observations may use the existing contract, installation-bound-anchor, and production assurance transitions; non-present variants are directly constructible.

### Accepted ownership, destruction, retry, and redaction evidence

Injected close and destruction-order evidence proves:

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

Only narrow `cfg(test)` close-injection and destruction-order seams exist inside the nested module. An implementation review caught private production-compiled injected `Connection` callbacks in the initial uncommitted draft; they were removed before commit. Accepted production code uses canonical `close_lifetime_owner` paths, and source checks prohibit a production constructor, production visibility widening, arbitrary production `Connection` callback, forgeable freshness-success constructor, or classifier bypass.

### Accepted source-boundary evidence

Source assertions prove:

- `classify_database_freshness` is invoked exactly once with `DatabaseMetadataCorrespondence::Corresponds`, `&metadata_contract`, `trusted_assessment.evidence()`, and `&anchor_observation`;
- ephemeral `Corresponds` translation is confined to the sealed adapter, with no retained, returned, or detachable proof and no correspondence-classifier call;
- no duplicated generation comparison, anchor-identity comparison, lineage combination, precedence, or timestamp accessor exists;
- no SQL, PRAGMA, prepare, query, row read, database-content operation, or `Connection` exposure exists;
- no filesystem, path, presence inspection, loading, DPAPI, HMAC, wrapper/envelope/plaintext/contract parsing, authentication, generation matching, binding, assurance, or normalization exists;
- the freshness adapter adds no schema, migration, unsafe code, FFI, dependency, feature, public API, Tauri command, IPC, frontend, or separate application caller; the later lifecycle composes it through the fixed chain;
- `DatabaseFreshnessValidatedProductionDatabaseConnection` contains exactly `ConnectionLifetimeOwner`, `DatabaseMetadataContractV1`, and `TrustedCurrentInstallationEvidenceAssessment`;
- `ProductionDatabaseFreshnessValidationCloseFailure` contains exactly `DatabaseFreshnessClassification` and `ConnectionLifetimeOwner`; and
- `Fresh` is impossible in `Failed`, close-failure ownership, and close-retry outcomes.

The implemented nested source location is `production_database_connection_handoff/live_metadata_and_header_validation/database_evidence_correspondence_validation/database_freshness_validation.rs`, declared and narrowly reexported by the correspondence module without visibility widening or a crate-root bridge.

Accepted source and behavior evidence additionally proves one real-SQLCipher predecessor-chain `Fresh` success; Fresh-only advancement; all eight non-Fresh outcomes; destruction before close; close-failure retention of exactly classification and lifetime; repeated retry and eventual success returning the original classification; successful-owner close; exactly one pure-classifier call; exactly one ephemeral `Corresponds`; and prohibited-capability assertions covering filesystem/path/presence, loading, DPAPI, HMAC, parsing, authentication, generation matching, installation binding, assurance, normalization, SQL, PRAGMA, and database reads.

The corrected loader test is `second_file_disappearance_is_rejected_and_replacement_never_returns_stale_pair`. It requires disappearance without replacement to return `Err`; replacement may return `Err`, or may succeed only with the fully validated current recreated pair; stale or mixed-pair success is forbidden. The loader contract is stable current-pair selection and validation, not absolute historical continuity. The production-loader prefix was unchanged across the test-only correction, and production loader bytes did not change.

## Accepted internal startup-authorization implementation evidence

The internal startup-authorization boundary after freshness is implemented at `d839686c53365711f2674c29033bc1602d4774c1`. Repository-grounded focused/local implementation verification reports passed. At that historical boundary-only commit, the real desktop startup did not yet invoke it. The exact target commit did not have clean CI: an intermittent active-evidence loader test failed, and the subsequent diagnostic investigation did not establish a startup-authorization implementation defect. The later accepted lifecycle commit now invokes the boundary and is recorded separately below.

Focused/local implementation verification covers:

- a genuine SQLCipher predecessor chain reaching `DatabaseFreshnessValidatedProductionDatabaseConnection`, combined with preloaded `InstallationEvidence::Initialized(ExpectedStorageEvidence::Present)`, succeeds with opaque `StartupAuthorizedProductionDatabaseConnection`;
- all five non-success installation-evidence observations fail closed: `NeverInitialized`, `Initialized(Missing)`, `Initialized(Unavailable)`, `Inconsistent`, and `Unavailable`;
- `NeverInitialized` maps to `ProductionDatabaseStartupAuthorizationError::NeverInitialized`, `Initialized(Missing)` maps to `ExpectedStorageMissing`, `Inconsistent` maps to `InstallationStateInconsistent`, and both unavailable observations map to `InstallationStateUnavailable`;
- installation-state evaluation completes before close begins, and there is no earlier-stage precedence inside the adapter;
- `InstallationEvidence` is not retained on success, primary failure, or close failure;
- metadata and trusted assessment are destroyed before a failed-authorization close attempt;
- a successful failed-authorization close returns the original primary category;
- failed close retains exactly the original category plus the complete `ConnectionLifetimeOwner`;
- repeated consuming close retry preserves both category and complete lifetime ownership, and eventual retry success returns the original category;
- retry performs only close and performs no authorization, observation, loading, database access, recovery, or setup work;
- successful-owner close destroys metadata and trusted assessment before close;
- successful-owner close failure reuses `ProductionDatabaseConnectionCloseFailure` and retains only lifetime ownership;
- manual coarse `Debug` is exact: the four payload-free primary names may be visible, owners and ownership-bearing failures are redacted, and formatting never delegates to retained or native values; and
- `StartupAuthorizedProductionDatabaseConnection` exposes no operational `Connection`, SQL/query interface, arbitrary callback, path, metadata, trusted-assessment, or evidence accessor.

Source-boundary checks cover that the implementation introduces no hidden installation-state loading; filesystem, path, file-identity, or sidecar access; SQL or PRAGMA; database access; freshness, correspondence, metadata/header, readability/integrity, or database-file-inspection rerun; anchor loading or normalization; schema or migration work; setup helper use; storage creation; recovery or repair; Tauri command, IPC, or frontend surface; arbitrary `Connection` callback; production success constructor; visibility widening or crate-root bridge; unsafe/FFI; dependency; or Cargo feature. Deterministic close injection is `cfg(test)`-only.

The implementation resides privately at `production_database_connection_handoff/live_metadata_and_header_validation/database_evidence_correspondence_validation/database_freshness_validation/startup_authorization.rs`, declared as a private child by `database_freshness_validation.rs`. The later lifecycle supplies the independently re-observed installation evidence and consumes success through operational activation. Account/elevation enforcement and stronger path/sidecar reinspection policy remain separate decisions.

Separate cleanup remains for stale historical source comments in `database_freshness_classification.rs` and `database_metadata_contract.rs` that reportedly state there is no production caller. This documentation task does not verify or modify those comments.

## Accepted application-startup lifecycle evidence

The Rust-owned lifecycle and operational activation are implemented and accepted at `44d2770786d4534ef37fb58b383e5b74ab73d04c` (`feat(app): orchestrate secure startup lifecycle`), with the later explicit setup integration accepted in the current repository state. The window begins in non-ready `Starting`; one blocking Rust worker runs the synchronous startup chain; `Ready` requires installation of a real `OperationalProductionDatabase`; and the lifecycle IPC surface now includes read-only `startup_status` plus the narrow argument-free `request_first_time_setup` command alongside `health_check`.

Accepted implementation verification establishes:

- canonical installation evidence is observed early and independently re-observed immediately before final startup authorization;
- the actual second observed `InstallationEvidence` value is passed into authorization, and startup does not construct `Initialized(Present)`;
- operational activation is the consuming post-authorization transition, not another authorization decision;
- no setup, migration, repair, recovery, reset, or retry fallthrough exists in ordinary startup; explicit setup is separately requested and authorized;
- frontend-visible states include `Starting`, `Ready`, `Unavailable`, `SetupInProgress`, `SetupRestartRequired`, `Stopping`, and `ShutdownIncomplete`, while internal `CloseRetryRequired` ownership remains Rust-only;
- shutdown during startup requests drain and prevents any later `Ready` installation;
- close failure retains ownership internally and exposes `ShutdownIncomplete`, with no retry UI, IPC command, or user action;
- manual root/pause support is Windows plus `debug_assertions` only and not frontend/IPC authority; the fixture exporter is Windows test-only and ignored; and
- lifecycle logs and errors remain coarse and disclose no path, key, identifier, metadata, native error, or raw backend chain.

Focused and full automated validation were accepted during the lifecycle implementation review. They were not rerun during the later staging/commit tasks and are not rerun by this documentation-only reconciliation.

The following manual scenarios were completed and accepted:

| Scenario | Result | Establishes |
| --- | --- | --- |
| A: valid complete fixture | `Ready` — PASS | The exercised complete synthetic fixture can traverse the real startup chain and install the operational owner. |
| B: active evidence, database missing | `Unavailable` — PASS | Missing expected database storage fails closed without setup or creation fallthrough. |
| C: recognized staging at launch | `Unavailable` — PASS | Recognized staging evidence prevents readiness. |
| D: state changed before final canonical observation | final observation vetoed `Ready` — PASS | The implemented second observation governs final authorization in this exercised mutation scenario. It is not proof against every possible TOCTOU or race condition. |
| E: close while `Starting` | shutdown pending/drain, no `Ready` fallthrough — PASS | Shutdown intent remains responsive at the UI/event-loop level, drains the worker, and prevents late readiness. |

These scenarios use debug/test-only support for controlled observation. They do not turn that support into production product behavior and do not establish full-product launch readiness.

## Accepted first-time setup and fresh-process startup evidence

The implemented first-time setup lifecycle begins only from the accepted `NeverInitialized` path reached through the narrow setup request. It creates encrypted `parish-data.db`, initializes the minimal V1 metadata/header bootstrap contract, validates the database, prepares and publishes protected installation artifacts, performs final active verification, and finishes at `SetupRestartRequired`. This verification scope establishes no parish/business schema, workflow tables, migration, backup/restore, recovery, authentication, or general writable database API.

Accepted Windows debug manual validation demonstrated this exact end-to-end sequence:

```text
marker-only isolated root
-> Unavailable
-> explicit first-time setup
-> restart-required
-> fresh-process ready_installed
```

The observation confirms the exercised debug setup/startup lifecycle, including the prohibition on same-process `Ready` after setup. It is not clean-machine release validation, installer validation, production readiness, or parish-workflow readiness. The old zero-byte setup failure did not reproduce and is not tracked here as an active defect. The existing Windows-debug setup terminal-failure phase diagnostic seam remains intentional.

## Approved first business-schema verification contract

The final product and physical design is documented but STILL UNIMPLEMENTED. Documentation review must prove the exact three-entity/table boundary: `ServiceRequest`/`service_requests`, `RequestScheduleOccurrence`/`request_schedule_occurrences`, and `RequestCancellationReview`/`request_cancellation_reviews`. It must reject a fourth entity; service/status/disposition/kind or location lookup tables; person/parishioner and permanent/sacramental records; generic workflow, audit/history/event-sourcing, soft-delete, or schedule-history structures; executable SQL; migration SQL; and any claim that version assignment creates migration eligibility or authorization.

Version-decision review must prove that the implemented metadata/bootstrap source is `database_schema_version = 1`; the exact approved three-table target is `database_schema_version = 2`; target `metadata_contract_version = 1`; target SQLite `user_version = 2`; `application_id = 0x43484150`; and the existing `ApplicationDatabaseFormatIdentity` is unchanged. It must prove compatibility is 1 -> 2 only, reject a generic `unsupported -> 2` rule, treat versions newer than 2 as unsupported and downgrade-refused, and verify no current source constants or validators were changed. Schema version 2 remains unimplemented.

Physical-design review must verify `STRICT` for only the three business tables, `id INTEGER PRIMARY KEY`, no `WITHOUT ROWID`, internal-ID non-authority, exact lowercase ASCII persisted code sets, required status/disposition with no SQLite `DEFAULT`, explicit Rust binding of `pending`, exact column nullability, approved Unicode-character limits, non-negative UTC Unix-millisecond timestamps, resolved-time/disposition nullability, shape-only database date validation, ranged `HH:MM`, child foreign keys with both actions `RESTRICT`, `UNIQUE(service_request_id, occurrence_kind)`, and the pending-review partial unique index.

Index review must find only `service_requests(status, created_at, id)`, occurrence exact-slot lookup by date/time/id, review parent chronology by parent/requested time/id, pending-review priority by requested time/id, and pending-review uniqueness by parent. It must find no unique schedule-slot constraint, trigger, or speculative index. Future writable-connection verification must separately prove foreign-key enforcement is enabled and verified; declarations alone do not suffice and current startup connection policy is unchanged.

Future Rust behavior tests must cover all four forward-only status transitions with compare-and-set and exactly-one-row success; draft pending occurrences; occupancy by scheduled parents only; historical occurrence retention after completion/cancellation; exact-slot conflict across the shared parish schedule independent of location; pending-review non-release; and atomic in-place rescheduling. They must exclude durations, end time, intervals, resource/capacity domains, and history tables.

Cardinality/compatibility tests must require exactly one primary occurrence before scheduling Baptism, Confirmation, Wedding/Marriage, and First Communion; require at least one of Funeral or Burial for Burial/Funeral; accept either alone or both; reject neither; enforce at most one kind per parent; reject Burial/Funeral primary and non-Burial/Funeral funeral/burial. Location tests must allow null while pending, require non-empty location for Wedding/Marriage and First Communion before and during scheduled status, keep other locations optional, and permit different Funeral/Burial locations.

Validation tests must cover 200/32/254/256 Unicode-character limits; trimming and non-empty required text; `NULL` for absent optional data; rejection of empty optional text, NUL, and disallowed controls; no aggressive case-folding or destructive normalization; actual Gregorian validity in Rust; minute precision; `Asia/Manila`; presentation-only `MM/DD/YYYY` and AM/PM; and no repeated timezone column.

Cancellation transaction tests must prove approval atomically requires a pending review and a `pending` or `scheduled` parent, changes exactly one parent to `cancelled`, changes exactly one review to `approved`, and sets `resolved_at`, otherwise rolling back. Rejection must change exactly one pending review to `rejected`, set `resolved_at`, and leave parent status unchanged. Resolved reviews remain retained and rejection permits a later pending review.

This C2b custody-lifecycle documentation reconciliation changes none of those runtime behaviors. Its validation is limited to complete documentation diff review, allowed-file review, baseline/final Git-state review, and `git diff --check`. No npm, Cargo, Tauri, application/runtime, SQL/database, migration, key-generation, envelope, or custody command is appropriate because there is no executable change.

## Accepted migration recovery-envelope implementation evidence

The implemented evidence begins with `VerifiedEncryptedProductionDatabaseMigrationBackupStage`: exact full-integrity source and same database key, independent cipher and full SQLite integrity, exact metadata/header equality, ciphertext at rest, unchanged retained source, retained source-bound migration authorization, and retained parent/leaf identity continuity. Later implemented work publishes and freshly verifies both sets' database and envelope payloads and manifest-last manifests, independently verifies each complete recovery set, and composes them into final keyless aggregate Layer D proof. The aggregate transition repeats no custody, AEAD, recovered-key, or SQLCipher operation. Lifecycle composition reaches first-manifest publication; operational ceremony reachability, lifecycle recovery-key re-entry and later stages, restore, retention, and migration execution remain unimplemented.

The pure Migration Recovery Envelope Format Version 1 tests prove exact magic/domain `CHMRECV\0`, version `1`, algorithm ID `1`, XChaCha20-Poly1305 identity, exact 182-byte envelope, exact 96-byte payload, exact 44-byte AAD, 24-byte nonce, and detached 16-byte tag. Version 1 rejects plain ChaCha20, 96-bit-nonce ChaCha20-Poly1305, AES-CBC/CTR, unauthenticated or HMAC-only protection, DPAPI framing as the portable envelope, SQLCipher payload misuse, unknown versions, unknown algorithms, negotiation, and fallback. A RustCrypto-compatible known-answer XChaCha20-Poly1305 vector is present.

Key-generation tests prove a separately generated uniformly random 256-bit migration recovery key from the approved OS source; a dedicated non-`Clone`, non-`Copy`, non-serializable, redacted, best-effort-zeroizing owner; process-local plaintext lifetime; one independent nonzero 128-bit recovery-key-generation identifier; and one independent nonzero opaque 128-bit backup-set identifier. The identifiers are public and not key material, and the backup-set identifier never reuses setup-publication, installation, database-key-generation, or recovery/replacement generation. Randomness failure fails closed. The approved and implemented dependency is exactly `chacha20poly1305 = { version = "=0.11.0", default-features = false, features = ["zeroize"] }`.

Nonce tests prove one independently OS-random 192-bit nonce per envelope, encoded as non-secret framing, with no counter, global persisted allocator, or deterministic derivation from identifiers, digest, timestamp, path, metadata, or key material. Reuse under the same recovery key is prohibited.

Payload tests prove the plaintext contains exactly the 256-bit production database key, 128-bit database-key-generation identifier, 128-bit backup-set identifier, and 256-bit SHA-256 digest of the exact encrypted backup-stage database bytes. Hashing occurs only after successful writer close and current verified-stage proof. The format excludes parish, installation, installation-generation, recovery/replacement-generation, setup-publication, `application_id`, `user_version`, schema-version, database-format-identity, evidence/freshness keys, active DPAPI wrapper, path, and timestamp data.

AAD/domain tests prove the fixed Church App migration-recovery-envelope separator, format version, algorithm identifier, recovery-key-generation identifier, and externally framed backup-set identifier are authenticated. Evidence-envelope and freshness-envelope domains cannot verify as this domain.

Parsing and opening tests prove authentication-before-release: framing, exact version, exact algorithm, structurally valid required identifiers, ciphertext length, and AEAD authentication all precede release of any production database-key plaintext. A wrong recovery key or authentication failure releases no candidate, and no unauthenticated plaintext inspection is possible. After opening, tests require payload/envelope backup-set equality, database-key-generation correspondence to recovered database metadata, and fresh exact-stage SHA-256 equality.

The version-1 rejection matrix includes: wrong recovery key; altered format/domain identity; unsupported version; unsupported algorithm; zero or invalid generation identifier; altered nonce; altered ciphertext; altered tag; truncation; trailing bytes; altered authenticated backup-set association; altered authenticated digest/binding; and association with a different encrypted backup database. Each outcome fails closed and exposes no key candidate.

Independent recovery verification evidence exercises this exact order: consume `VerifiedEncryptedProductionDatabaseMigrationBackupStage`; generate key, generation identifier, set identifier, and nonce; hash the exact retained stage; independently reload/recover/exactly bind the active protected wrapper for construction; seal; destroy/drop that wrapper-derived `GenerationBoundDatabaseKey`; independently parse/authenticate/decrypt without reloading the wrapper; reconstruct a fresh generation-bound candidate through the existing trusted installation assessment; hash and match the exact stage a second time; and reopen it using only that candidate. The verifier opens with `READ_ONLY`, `FULL_MUTEX`, `PRIVATE_CACHE`, `NOFOLLOW`, fixed win32 VFS, no `CREATE`, canonical pre-key hardening, one key application, and enabled/verified `query_only`; reruns only canonical cipher integrity and fixed metadata/header observation with exact source equality; explicitly closes; and performs final stage-identity continuity before returning `VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup`. Cross-process migration exclusivity is not owned by this private transition; the lifecycle preparation worker now owns that separate gate around the composed chain.

Full SQLite integrity is deliberately not repeated during this verifier because the prior encrypted stage passed canonical full integrity, authenticated SHA-256 equality proves exact stage-byte identity, recovered-key cipher integrity succeeds, and exact metadata/header equality is re-established. If byte equality cannot be established, verification fails; it does not substitute a weaker check. Tests also prove the transition never mutates the staged database. This is not a general integrity skip.

Envelope construction preserves recovery/replacement generation. Authority and ownership tests prove the recovery key and envelope grant no migration/startup authorization, database write, restore, evidence/freshness, or mutation authority; success retains exact migration authorization/source/stage, recovery-key material, and envelope proof; authorization is destroyed before outward failure; primary failure explicitly closes the source; source-close and verifier-close-only retry ownership remain canonical; outward failures retain stage/envelope artifacts without recovery-key material; and no automatic destructive cleanup occurs. A future DPAPI local convenience key copy is not the portable envelope and cannot constitute sufficient portable custody.

The envelope-stage verified type is exactly `VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup`, never `VerifiedRecoverableProductionDatabaseBackup`. Verification keeps encrypted stage, envelope, C1 custody foundation, C2a private adapter, C2b lifecycle dispatch, publication, restore, and retention/deletion layers separate. C2b runtime/manual ceremony validation, final root/filenames, publication atomicity/durability and complete-set verification, rotation, supersession, retention, destructive deletion, and restore tests remain deferred.

Observed focused validation for the pure primitive recorded 19 passed tests, the RustCrypto-compatible known-answer vector, `cargo fmt --check` passed, and Clippy with `-D warnings` passed. Final recovery-envelope backup-integration evidence recorded:

- `production_database_connection_handoff`: 375 passed, 0 failed, 1 ignored;
- `production_database_migration_backup_stage::recovery_envelope`: 9 passed, 0 failed;
- `production_database_migration_backup_stage`: 17 passed, 0 failed;
- `production_database_migration_recovery_envelope`: 19 passed, 0 failed;
- `cargo fmt --check`: passed;
- `cargo clippy --locked --all-targets -- -D warnings`: passed; and
- `git diff --check`: passed.

Two source-structure tests exposed verified pre-existing brittle extraction defects and were narrowly corrected without production behavior changes; those old failures are not active defects. The final integration slice did not run the full Rust suite. The vendored OpenSSL `LNK4099` missing-PDB warning remains non-fatal historical validation noise, not an active application defect.

## Accepted migration recovery-key custody foundation evidence

Migration Recovery Key Custody Format Version 1 tests establish the exact golden format and checksum: prefix `CHURCH-MIGRATION-RECOVERY-KEY-V1`; alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`; MSB-first unpadded Base32; uppercase canonical output; ASCII case-insensitive input; no Unicode normalization or ambiguous aliases; and rejection of `I`, `L`, `O`, and `U` in encoded positions. The canonical form is exactly five LF-separated lines, 196 bytes, no terminal newline, with line lengths 32/36/36/68/20. `GEN-`, `SET-`, `KEY-`, and `CHK-` have exact symbol counts 26/26/52/13 and groupings `4-4-4-4-4-4-2`, `4-4-4-4-4-4-2`, thirteen groups of four, and `4-4-4-1`.

Field tests prove that only format/version, recovery-key-generation ID, migration-backup-set ID, 256-bit recovery key, and checksum exist. The exact 105-byte checksum input is `ASCII("CHURCH-MIGRATION-RECOVERY-KEY-CHECKSUM") || 0x00 || U16_BE(1) || generation-id[16] || backup-set-id[16] || recovery-key[32]`; only the first eight SHA-256 digest bytes are encoded. Verification treats this as typo/error detection, not authentication, a MAC, password verification, provenance, or restore authority; recovery-envelope AEAD remains the authentication boundary.

Codec evidence covers strict parsing/canonicalization, CRLF acceptance only as a whole-record alternate line ending, mixed-line-ending rejection, truncation and trailing-data cases, grouping and alphabet matrices, zero generation/set ID rejection, and separation of checksum validity from expected envelope/key association. Ownership evidence covers redacted formatting, fixed `[u8; 196]` ownership, zeroization of encoded/parsed/checksum-validated secret material, non-`Copy`/non-`Clone`/non-serde behavior, and absence of a broad production text/string/raw-key API.

Private state evidence covers whole-owner preparation from only `VerifiedRecoveryEnvelopedProductionDatabaseMigrationBackup`; association derived from the already verified envelope and retained generated key; no independent key/arbitrary identifier inputs; and source isolation from `generate_migration_recovery_key_material`, `generate_migration_backup_set_identifier`, and `seal_migration_recovery_envelope_v1`. It proves pre-exposure whole-owner preservation without regeneration, irreversible disclosure, terminal post-exposure ownership and destruction, close-only retry, exactly two successful complete readbacks, no completion after only the first readback, and keyless continuation retaining exact encrypted stage, independently verified envelope, and `VerifiedMigrationRecoveryKeyCustody` only.

For that C1 slice, forbidden-surface/dependency evidence confirmed no React/Tauri IPC secret path, clipboard, ordinary file export, print-spooler, QR, secret-sharing, password/KDF, DPAPI custody-copy, native Windows UI, lifecycle wiring, or new dependency was added. The locked policy remains one plaintext bearer record, exactly two independently re-entered complete paper copies of that same record, redundancy rather than secret sharing, no satisfaction of the later two-complete-recovery-set publication requirement, and no applicability of historical ten recovery codes.

Initial custody implementation validation recorded:

- `cargo test --locked custody`: 11 passed initially;
- `production_database_migration_recovery_envelope`: 26 passed initially; and
- `production_database_migration_backup_stage::recovery_envelope`: 13 passed initially.

The final focused evidence expansion recorded:

- `production_database_migration_recovery_envelope::custody`: 24 passed, 0 failed;
- `production_database_migration_backup_stage::recovery_envelope::custody`: 15 passed, 0 failed;
- `custody`: 39 passed, 0 failed;
- `production_database_migration_recovery_envelope`: 43 passed, 0 failed;
- `production_database_migration_backup_stage::recovery_envelope`: 24 passed, 0 failed;
- `cargo fmt --check`: passed;
- `cargo clippy --locked --all-targets -- -D warnings`: passed; and
- `git diff --check`: passed.

The vendored OpenSSL `LNK4099` missing-PDB warnings remained non-fatal. The full Rust suite was not run for that C1 custody implementation slice, and npm/frontend validation was not run. No Tauri runtime or manual custody ceremony ran, no production app-data was accessed, and no manual ceremony test was appropriate at that stage because native custody UI was not then implemented.

## Accepted private Windows native custody-adapter evidence

C2a is implemented privately at `src-tauri/src/production_database_migration_backup_stage/recovery_envelope/custody/native_windows.rs` and is registered under `cfg(windows)` from the existing custody state module. Source-structure evidence confirms that it accepts an already-supplied `HWND`, uses `DialogBoxIndirectParamW` with only `STATIC`, `EDIT`, and `BUTTON`, and remains absent from `ApplicationLifecycle`, Tauri commands, production migration orchestration, filesystem access, logging, clipboard APIs, capture-exclusion APIs, and React/Tauri IPC. It neither obtains the real Tauri main-window handle nor dispatches to the main thread.

Focused tests establish one conceptual owner-modal progression, Intro -> Reveal 1 -> Readback 1 -> Reveal 2 -> Readback 2 -> Success; deterministic control/tab creation order; default/cancel semantics; and explicit focus transitions. This is implementation evidence only. No real owner modality, keyboard runtime, screen reader, high-DPI behavior, complete accessibility, UI-automation resistance, or interactive dialog behavior was observed.

Display evidence covers the narrow crate-private closure-scoped seam over fixed `[u8; 196]`, absence of `as_bytes`, `as_str`, `String`, `Vec`, a general slice getter, `Clone`, `Copy`, and serialization, and exact zeroizing `[u16; 201]` conversion: 196 canonical ASCII bytes, exactly four LF-to-CRLF insertions, 200 text code units, and explicit NUL. Secret display is a non-selectable `STATIC`.

Readback evidence covers visible multiline `EDIT` controls, exact `EM_SETLIMITTEXT` limit 200, `GetWindowTextLengthW`, fixed `[u16; 201]`, returned-length consistency, ASCII-only rejection, fixed zeroizing `[u8; 200]`, and exact handoff to existing strict custody validation. No trimming, Unicode normalization, aliases, case rewriting, or grouping rewriting occurs.

Suppression evidence covers `WM_PASTE`, `WM_COPY`, `WM_CUT`, `WM_CONTEXTMENU`, Ctrl+V, Ctrl+C, Ctrl+X, and Shift+Insert where applicable. No clipboard API is called. No `SetWindowDisplayAffinity` or `WDA_EXCLUDEFROMCAPTURE` support was added. Tests do not establish resistance to same-user message injection, accessibility tooling, UI automation, debuggers, malware, screen capture, or photography.

Ownership tests lock the order Prepared -> consume `disclose()` -> Disclosed -> borrow -> convert -> `SetWindowTextW`, and prove that Prepared cannot reach the display seam. Intro cancellation is retryable before exposure. All native failure/cancellation after disclosure is terminal. First success produces only `FirstCopyVerifiedMigrationRecoveryKeyCustody`; first failure is terminal. Second reveal continues from that owner without reconstructing Prepared, regenerating key/set material, or resealing. Second success returns `RecoveryKeyCustodyVerifiedProductionDatabaseMigrationBackup`; second failure is terminal. `NativeCeremonyFailedAfterCustodyExposure` follows the existing cleanup path for encoded text, recovery-key material, migration authorization, backup context, explicit source close, and canonical close-only retry ownership.

Callback tests establish unwind containment at all native callback ABI boundaries, independently contained recovery, and fail-stop abort as the final fallback if terminal recovery itself panics. Native outcomes are redacted `Verified`, `InterruptedBeforeExposure`, `UnavailableBeforeExposure`, and `FailedAfterExposure`; no native payload or log surface is retained.

Observed focused C2a validation recorded:

- `native_windows`: 9 passed;
- `production_database_migration_backup_stage::recovery_envelope::custody`: 26 passed;
- `production_database_migration_recovery_envelope::custody`: 25 passed;
- `custody`: 51 passed;
- `cargo fmt --check`: passed;
- `cargo clippy --locked --all-targets -- -D warnings`: passed; and
- `git diff --check`: passed.

The existing vendored OpenSSL missing-static-PDB warnings were non-fatal. This C2a slice did not run the full Rust suite, npm/frontend checks, the Tauri runtime, production app-data access, a real interactive dialog, or a manual paper-copy ceremony. Manual testing was not required before commit because C2a remained unwired and unreachable. No real Tauri `HWND` integration, main-thread dispatch, runtime shutdown behavior, or lifecycle ownership/exit-retention policy was validated.

The existing `windows-sys = "=0.61.2"` dependency remains pinned with default features disabled and the UI features `Win32_UI_Controls`, `Win32_UI_Input_KeyboardAndMouse`, and `Win32_UI_WindowsAndMessaging` available. No new crate was added, and compile/test availability of these bindings does not make the ceremony operational.

Current recovery-layer status is: A implemented; B implemented; C1 implemented; C2a implemented; C2b lifecycle/main-thread/real-main-window dispatch implemented and committed but normally unreachable and manually unvalidated; D independently complete-set-verified first and second digital recovery sets plus final aggregate proof implemented, with lifecycle composition through first-manifest publication; E restore unimplemented; and F retention/deletion unimplemented. C2a/C2b themselves add no migration execution, publication, restore, filesystem export, printing, QR, DPAPI custody, password/KDF, secret sharing, recovery-key regeneration, backup-set regeneration, or envelope resealing, and grant none of the authorities prohibited by the custody contract.

## Accepted lifecycle migration-preparation orchestration evidence

The committed implementation composes authorized/revalidated migration through migration exclusivity, operational-owner retirement, exact authorization consumption, canonical full integrity, verified encrypted backup staging, independent recovery-envelope verification, and C1 custody preparation. It runs on the existing dedicated `production-database-migration` OS thread and stops at worker-retained `PreparedUndisclosedMigrationRecoveryKeyCustody`. Lifecycle stores only coarse `CustodyPrepared`; it does not own the Prepared owner, plaintext custody data, or exclusivity. The worker blocks on `control.recv()` rather than busy-spinning.

Source-order evidence confirms exclusivity acquisition precedes operational close, operational close precedes authorization consumption, and authorization consumption precedes the preparation chain. The operational owner is removed from `Ready` and explicitly closed first. Operational close failure remains worker-owned with exclusivity retained. Authorization still comes only from successful existing revalidation and is consumed once; no new `Pending` opportunity or renewal path was added.

The canonical stage-path test confirms exact fixed leaf `production-database-migration-backup.stage` directly below the Rust/Tauri-resolved application-local-data root, represented by redacted `ProductionDatabaseMigrationBackupStagePath`. The production preparation boundary accepts the Tauri `AppHandle`, resolves no caller/frontend/environment path, and derives backup context only through canonical database-key persistence paths.

Prepared ownership keeps `migration_work_resolved` false until it is resolved. The same is true during active preparation and migration close-only retry ownership. `may_exit` independently requires resolved startup, ordinary close, setup, and migration work; ordinary failed/stopped lifecycle state; and resolved migration-confirmation ownership. Tests specifically establish that confirmation `Consumed` does not permit exit while worker-held migration ownership remains.

The implemented `abort_before_exposure_for_shutdown` test proves no disclosure; destruction of encoded custody text, recovery-key material, and migration authorization; backup-context drop; explicit source close; retention of keyless encrypted-stage/envelope proof; and canonical close-only retry on close failure. Source exclusions prove the transition cannot disclose, invoke the native ceremony, retry custody, publish, or execute migration.

Shutdown-race tests cover the exact claim variants `NoWork`, `Ready(OperationalProductionDatabase)`, and `ShutdownWon(AuthorizedProductionDatabaseMigrationHandoff)`. The `ShutdownWon` path consumes exact authorization once, performs none of full integrity/staging/envelope/custody, closes the exact authorized source, and retains worker-local close-only retry plus exclusivity on failure. The ordinary operational owner already extracted by shutdown remains in the ordinary close path, proving no double-close.

Recorded initial migration-preparation validation was:

- migration exclusivity tests: 9 passed;
- migration confirmation ownership tests: 17 passed;
- migration backup-stage tests: 8 passed;
- recovery-envelope tests: 28 passed;
- custody tests: 43 passed;
- initial migration lifecycle tests: 16 passed;
- canonical stage-path test: 1 passed;
- `cargo check --locked --all-targets`: passed;
- `cargo fmt --check`: passed;
- `cargo clippy --locked --all-targets -- -D warnings`: passed; and
- `git diff --check`: passed.

The shutdown-race correction recorded final `application_lifecycle::tests::migration_` results of 20 passed and 0 failed, with the transient discovery timing case independently rerun once and passed. `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, and `git diff --check` passed. Commit-staging validation recorded `git diff --cached --check` passed. Existing vendored OpenSSL missing-PDB warnings were non-fatal, and existing SQLCipher `VirtualLock` warnings appeared in custody tests.

For this historical preparation-only implementation slice, the full Rust suite, npm/frontend validation, Tauri runtime, production app-data, native custody dialog, manual custody ceremony, and integrated migration runtime test were not run. No result for those checks is implied. At that time, operational reachability remained incomplete because production migration-discovery invocation, migration confirmation/cancellation commands, frontend migration UI, and C2b native ceremony dispatch were absent. The later C2b section records the superseding current state: C2b dispatch is implemented, while the normal product trigger, confirmation/cancellation commands, and frontend migration UI remain absent. No manual integrated migration ceremony, publication, or migration execution occurred.

## Accepted native recovery custody lifecycle dispatch evidence

The committed C2b implementation extends the preceding preparation slice without changing its security-significant preparation order. The migration worker retains cross-process exclusivity and the ownership-bearing `PreparedUndisclosedMigrationRecoveryKeyCustody` off lifecycle-visible state until dispatch. `LifecycleInner` remains coarse. Source/static evidence establishes `AppHandle::run_on_main_thread`, real-window resolution through `get_webview_window("main")`, `window.hwnd()`, no retained or logged `HWND`, C2a invocation with that real parent handle, no lifecycle/escrow mutex held while C2a executes, and ownership-bearing result return through `std::sync::mpsc`.

Ownership-race tests establish one explicit shutdown/main-thread synchronization boundary. If shutdown intent wins before the main-thread take, Prepared remains unexposed and is recovered for terminal pre-exposure shutdown handling. If the main-thread take wins, shutdown cannot reconstruct or reclaim Prepared and waits for the ownership-bearing C2a outcome. The worker retains migration exclusivity until exact ownership resolution. Source-close failures retain only the appropriate close-only retry owner; completion-send failure and impossible ownership states fail-stop rather than silently dropping authority.

Verified custody remains keyless and advances only to `CustodyVerifiedAwaitingPublication`. `migration_work_resolved` stays false while privileged migration work remains unresolved, so `may_exit` remains blocked. Verified custody has an explicit terminal shutdown path through `abort_for_shutdown()`. Tests and source exclusions establish that C2b performs no migration execution or publication.

Latest accepted focused C2b validation recorded:

- `application_lifecycle` migration-focused tests: 35 passed, 0 failed;
- `cargo fmt --check`: passed;
- `cargo clippy --locked --all-targets -- -D warnings`: passed; and
- `git diff --check`: passed.

Earlier accepted C2b/C2a-focused validation recorded `native_windows`: 9 passed and `custody`: 28 passed. The existing Windows OpenSSL missing `ossl_static.pdb` linker/debug-information warning remained non-fatal.

The full Rust suite, npm/frontend validation, Tauri runtime, real dialog, production app-data, and product-level manual ceremony were intentionally not performed for C2b. No normal trigger currently reaches the integrated path: production migration discovery invocation, migration confirmation and cancellation Tauri commands, and frontend migration confirmation/cancellation UI are absent. Therefore no claim is made for real main-window parenting, dialog modality against the running Church App, WebView interaction blocking, Tauri/event-loop behavior during the real dialog, keyboard traversal, Alt+F4/X behavior, shutdown during the actual dialog, high-DPI layout, screen-reader behavior, parent restoration, or the real two-paper-copy ceremony.

## Approved Layer D verification contract (partially implemented)

Focused first-database-publication tests now lock the canonical non-parameterized `parish-data.db` name; private source/destination-only composition; `CREATE_NEW` and no cleanup surface; 64 KiB bounded streaming; checked byte counting; source observation and continuity reuse; partial-write handling through `write_all`; flush and explicit close before fresh reopen; independent exact-length and SHA-256 verification to EOF; stable full file identity and normalized final path; non-directory/non-reparse/non-delete-pending facts; parent/root/device continuity; opaque source-preserving success and phase-bearing partial failure; redacted fixed errors; and absence of envelope, manifest, set-2, serde, Tauri, frontend, path, handle, and digest getters. The Windows runtime fixture uses one unique OS-temporary test-owned directory and a deterministic payload larger than one chunk to exercise create-new, bounded write, flush, explicit close, independent reopen, length/digest/identity/path stability, conflict on a second create-new attempt, and exact teardown. It is test evidence only and establishes no production recovery-device authority.

Focused first-envelope-publication tests lock the canonical non-parameterized `migration-recovery-envelope-v1.bin` name; consumption only of the first-database success owner; closure-scoped borrowing of the exact retained verified `[u8; 182]`; no resealing, key generation, identifier generation, decryption, caller bytes, manifest, set-2 publication, cleanup, serde, Tauri, or frontend surface; prerequisite source/destination/database revalidation; `CREATE_NEW`; exact partial-write handling; flush and explicit close; independent read-only reopen; exact length, byte equality, and clean EOF; stable identity/path facts; directory/reparse/delete-pending rejection; parent/root/device continuity; opaque prior-preserving success and phase-bearing partial failure; fixed redacted errors; and source-only non-mutating failure/success abandonment. Focused first-manifest tests lock exact database-plus-envelope predecessor ownership, source-derived canonical bytes, manifest-last create-new/write/flush/single-close/fresh-reopen verification, terminal fail-stop on ambiguous close, and source-only non-mutating failure/success abandonment. Focused lifecycle source-contract tests lock exact-owner entry, canonical facade reuse, shutdown guarding before manifest invocation, custody-only ordinary failure, exact manifest-published success ownership and verification-awaiting state, retained exclusivity/unresolved migration work, and canonical shutdown close chaining without custody re-entry, complete-set, set-2, frontend, or IPC work. Windows runtime fixtures prove canonical manifest behavior and unchanged database/envelope/manifest bytes across abandonment. Source-text assertions establish structure only; the canonical Windows fixtures do not establish integrated lifecycle runtime behavior, production recovery-device authority, or set completion.

Layer D verification must eventually begin only from the existing keyless custody-verified backup owner and must prove exactly two complete digital recovery sets on two physically distinct, physically disconnectable external devices, both distinct from production storage. The implemented private Windows eligibility prerequisite consumes the retained single-physical-device topology proof and accepts only a strictly parsed same-volume `StorageDeviceProperty` observation reporting `BusTypeUsb` plus a strictly parsed same-volume `IOCTL_STORAGE_GET_HOTPLUG_INFO` observation reporting `DeviceHotplug != 0`. Revalidation repeats all three checks. The production database inspection owner now projects its retained file through the same topology primitive, and private consuming comparisons revalidate both sides before producing opaque production/recovery and two-recovery-device separation proofs. The second-device transition revalidates production, first recovery, and second recovery observations and rejects a match with either retained device. Focused pure tests cover USB/hotplug acceptance, both removable-media values, every named non-USB bus plus unknown values, descriptor and hot-plug truncation/malformed sizes, both unavailable queries, revalidation success/change, same/different disk outcomes, every comparison-input failure, redaction, and source/authority exclusions. The exact OS-temporary-directory runtime tests observe only their retained backing volume, including an internal same-device comparison of two retained handles; no external USB device or second physical disk is required.

The retained destination-root prerequisite is also implemented and focused-tested. Its opaque production boundary accepts only the private result of the implemented Rust-native selector; the production constructor accepts only the validated fixed 49-unit canonical volume-GUID-root representation, while the arbitrary `PathBuf` constructor remains `cfg(test)`. The opened directory uses backup semantics and open-reparse-point behavior, requests no mutation access, and allows no delete sharing. Deterministic tests cover exact `\\?\Volume{GUID}\` acceptance; child, UNC/network, and malformed rejection; directory, reparse, and delete-pending facts; changed full `FILE_ID_INFO`; changed normalized root; NTFS acceptance; exFAT, FAT32, ReFS, and unknown rejection; unavailable filesystem observation; eligibility failure/change; redaction; absent path/handle/filesystem/topology/device getters; absent serde/Tauri/frontend surface; reuse of topology and eligibility; and absence of creation/publication APIs. The one OS-temporary-directory runtime test proves its non-root child directory is rejected without weakening the production exact-root rule and uses no USB device or volume enumeration.

The private Windows-native picker is implemented beneath the retained-root subtree. Focused deterministic and source-contract tests cover the exact selected/cancelled/unavailable taxonomy; fixed redacted formatting; the approved four `IFileOpenDialog` options with no multi-select; explicit STA/OLE1DDE-disabled COM initialization; successful `S_OK` and `S_FALSE` balancing through `CoUninitialize`; fail-closed `RPC_E_CHANGED_MODE`; standard cancellation-only classification; `SIGDN_FILESYSPATH`; task-allocator cleanup; direct exact-path mount-root recognition without ancestor walking; reuse of the canonical volume-GUID-root parser; and absence of NTFS, USB, hotplug, separation, capacity, lifecycle, publication, Tauri, IPC, or frontend work. The picker is not wired into lifecycle composition or normal product interaction, and no interactive dialog automation is attempted.

The capacity prerequisite is implemented as a private, non-mutating transition over the complete two-root separation owner. Focused deterministic tests cover checked `database + canonical 182-byte envelope + canonical 98-byte manifest` arithmetic, overflow, equality, one-byte insufficiency, first- and second-root failure, unavailable observation, pre- and post-observation revalidation failure, both-root success and ordering, opaque/redacted owners and errors, absent size/path/handle/GUID/device getters, trusted manifest/source-fact composition, and absence of serde, Tauri, frontend, fixed-child, directory-creation, or publication surfaces. Production calls `GetDiskFreeSpaceExW` only with each retained handle-derived exact volume-GUID root and reads only bytes available to the caller. No capacity runtime smoke test is required; deterministic injection avoids a real large-disk or USB fixture. Success is explicitly not reservation, durability, publication, or completion proof.

The fixed-child boundary is implemented privately beneath the retained-root subtree. Focused deterministic/source tests cover the exact non-parameterized `church-app-recovery-set` name; root-only path derivation; unavailable inspection; exact, ASCII-case-conflicting, file, directory, and reparse conflicts; first-before-second create ordering; first failure preventing a second attempt; set-2 failure retaining set-1 ownership; no rollback or cleanup API; disk-directory, non-delete-pending, non-reparse, full-identity, exact normalized parent/child path, volume-serial, and volume-root checks; root/separation and child continuity; opaque success and partial-failure ownership; coarse redacted errors; and absent getter, serde, Tauri, frontend, artifact, write, publication, and lifecycle surfaces. Focused Windows runtime tests use only unique temporary test-owned directories to exercise native namespace inspection, one-shot `CreateDirectoryW`, immediate hardened child opening, exact/case/file/reparse conflicts, and exact test-root teardown; those tests observed the test-owned directories as empty immediately after creation. Production success proves only that each target was absent and conflict-free under the implemented inspection, `CreateDirectoryW` created it, and the new child was immediately opened, hardened, continuity-validated, and retained as authority for that exact directory. It does not continuously enumerate child contents or prove that no unrelated process can subsequently add an entry, and it does not establish artifact publication, durability, independent final reopen verification, complete recovery sets, or Layer D completion.

The implemented comparisons reject two logical locations on one physical device and fail closed when any participating topology or eligibility revalidation is unavailable, changed, inconsistent, malformed, unsupported, or no longer eligible. Database, envelope, and manifest-last publication, recovered-key verification, exact three-entry layout verification, independent complete-set verification for both sets, final aggregate proof, and the private native picker are implemented. The final transition revalidates the retained source, both artifact chains, both destinations, both production/recovery separations, recovery/recovery separation, roots, and children. Layer D lifecycle integration, normal product reachability, restore, and migration execution remain unimplemented. Test-only local-volume and device-property candidate classifiers remain test-only.

For each set, the accepted complete-set tests prove the fixed final layout contains exactly `parish-data.db`, `migration-recovery-envelope-v1.bin`, and `recovery-set-v1.manifest`; the names are fixed constants, not input or encoded fields, and file presence alone is insufficient. The accepted committed Recovery Set Manifest V1 pure-codec tests prove exact length 98; magic `CHLDRSM\0`; big-endian `u16` version `00 01`; raw identifier, big-endian database length, raw database digest, and raw envelope digest at `0..8`, `8..10`, `10..26`, `26..34`, `34..66`, and `66..98`; and rejection of truncation, trailing data, wrong magic, and unsupported version under exactly `WrongTotalLength`, `WrongMagic`, and `UnsupportedVersion`.

The accepted structural-validation tests prove all-zero identifier rejection, inclusive acceptance at database lengths 512 and `281_474_976_579_584`, rejection immediately outside those bounds, deterministic identifier-before-length validation, and exactly `InvalidBackupSetIdentifier` and `InvalidDatabaseByteLength`. They prove arbitrary digest patterns are structurally accepted; only validated state encodes; canonical output is exactly 98 bytes; and accepted valid manifests round-trip byte-identically as `encode(validate(parse(bytes))) == bytes`. Source-boundary tests also prove the pure codec has no hashing, digest comparison, I/O, envelope parsing, database operation, or authority construction.

The committed construction-observation boundary adds the narrow crate-private trusted constructor and the private borrowed `prepare_recovery_set_manifest_v1(&self)` operation on the keyless custody-verified owner. Accepted source and focused tests establish canonical identifier derivation through the retained envelope parser/accessor; fresh stage length and SHA-256 observation using the existing 64 KiB buffer, checked `u64` counting, identity checks, before/after metadata, and agreement with streamed count; reuse of that observation primitive by the existing stage-digest path; fresh SHA-256 over the exact retained 182-byte envelope; owner preservation across success and failure; and the exact redacted errors `SourceObservationUnavailable`, `StageIdentityUnavailableOrChanged`, and `ManifestConstructionRejected`. The trusted constructor retains the locked database-length bounds and does not alter the 98-byte codec contract.

Accepted focused tests now traverse both complete-set proofs and the final aggregate transition. The second transition accepts only `FirstCompleteRecoverySetAndSecondRecoverySetArtifactsPublished` plus a fresh owned custody record, reuses the fixed three-slot exact-name classifier for two native directory observations, freshly reopens and retained-identity-binds the exact 98-byte manifest, exact 182-byte envelope, and second database, authenticates the actual fresh envelope, and sends only the fresh second database to the canonical recovered-key SQLCipher verifier. The final transition accepts only `SecondCompleteRecoverySetVerified`, repeats no custody, AEAD, recovered-key, or SQLCipher operation, and revalidates current source, artifact, root, child, layout, and device-separation continuity. The genuine synthetic Windows fixture proves unchanged first- and second-set artifacts, exactly three canonical entries in both directories, retained source-stage presence, and final keyless success. An extra entry fails closed while preserving the retry owner and performing no cleanup. Lifecycle source-contract tests establish worker-only canonical first-database, first-envelope, and first-manifest invocation, ownership parking, failure abandonment, shutdown ordering, unresolved migration work, and retained exclusivity; they do not establish runtime lifecycle execution. Separate Windows synthetic publication tests establish create-new write/flush/single-close/fresh-reopen behavior and filesystem-inert manifest failure/success abandonment. Lifecycle recovery-key re-entry and later stages remain future work.

The accepted implementation report recorded 5 focused final-transition tests passed and 0 failed, plus 9 second-complete regressions passed and 0 failed. A genuine Windows synthetic final-two-set fixture passed. Rust formatting passed. Clippy with `-D warnings` passed using an isolated repository-local target because the normal target lock was inaccessible. Both unstaged and cached diff checks passed. Full Rust, frontend, Tauri, real-USB, production, migration, and restore validation were not run for that implementation slice.

Future Layer E tests may use the manifest only for candidate recognition and inventory behind a trusted selection boundary. They must prove fixed-name location, parsing/validation, identifier extraction, size/digest verification, and manifest/envelope identity comparison cannot authorize restore or database replacement. The implemented topology, publication, both individual complete-set proofs, final aggregate proof, and private exact-root native picker remain non-authorizing beyond their named facts. Arbitrary folders do not qualify. Lifecycle composition and normal product reachability, operational recovery, restore, retention/deletion, and migration execution remain unimplemented.

Manual native-picker validation remains required and has not run. The future plan must cover the real Church App parent window and owner modality; Cancel, X, and Alt+F4; internal production root; a valid external NTFS USB root; child-folder rejection; mounted-folder volume-root behavior; unsupported or non-filesystem items; device detach before retained-root validation; shutdown before the main-thread take and while the dialog is visible; second recovery-device selection; selecting the same physical device twice; keyboard-only use; Windows 10; Windows 11; and repeated open/cancel/select cycles.

Two-set tests must prove identical backup bytes, identical envelope bytes, one backup-set identifier, and independent publication of set 2 from the retained source rather than copying set 1. They must exclude generation of another recovery key, backup-set identifier, envelope, or encrypted backup. Paper-entry tests may use either valid bearer record for either set but must record no paper identity or paper/device pairing. Manual validation must separately confirm the required physical separation of both paper copies from both devices and from each other, without claiming later software-provable separation.

Publication tests must prove create-new/no-replace behavior, refusal of merge/overwrite/repair/delete/resume, fail-closed handling of incomplete or conflicting destinations, and a new independently selected destination for retry. Focused first-database tests additionally prove one native writer-close attempt; fail-stop classification for an injected ambiguous result; no raw-handle reownership, close retry, recoverable close failure, or post-failure fresh verification; ordinary flush failure retention; consuming abandonment to the exact source; RAII release of represented file/destination handles; unchanged partial bytes and directories; no mutation/reopen/republish surface; fresh-destination source typing; and the existing `abort_for_shutdown()` then `retry_source_close()` chain. Failure, cancellation, and shutdown tests must cover zero complete sets, first-set publication, one complete set, second-set publication/partial, and two verified complete sets; preserve a completed first set; leave partial artifacts untouched; prevent new work during shutdown; destroy secrets and close handles; retain close-only ownership when required; and emit success only after both sets complete. Restart tests must require full revalidation before adopting existing disk artifacts.

Durability validation must separately demonstrate supported writes, file-buffer flushes, closes, final-name publication, the strongest technically available supported namespace/directory durability operation, and fresh reopen/verification. It must not claim absolute survival of power loss, defective media, controller/firmware failure, unsafe removal, or long-term degradation. Source-retention tests must prove the application-local encrypted stage remains after zero, one, and two complete sets and that Layer D performs no deletion. Authority tests must continue to prove the implemented final aggregate Layer D proof grants no migration execution, writable ownership, schema mutation, restore, replacement, retention, deletion, or cleanup.

## Remaining production database verification gates

- The minimal version-1 metadata/bootstrap schema and its setup creation path are implemented. The first business-schema product and physical design are approved as target schema version 2 only in documentation and remain distinct from that bootstrap contract. No schema-version-2 physical business table, executable DDL, migration, or parish workflow implementation is approved here.
- Path/link/sidecar tests must cover the exact application-owned NTFS path and filename, reparse/symlink/junction/mount traversal, cloud placeholder, hard link, network/removable storage, stable final path and identity, race revalidation, unexpected sidecars, and initial WAL/SHM prohibition. Startup must be proven unable to delete or repair sidecars.
- Transaction-policy tests must cover rollback-journal `DELETE`, `synchronous=FULL`, explicit transactions, `secure_delete=ON`, `auto_vacuum=NONE`, no automatic journal switch, no automatic VACUUM, and no WAL checkpoint behavior.
- Future migration verification now starts from implemented opportunity/revalidation, source-bound authorization, full-integrity source, dedicated exclusivity, verified encrypted SQLCipher backup-stage, recovery-envelope verification, C1, C2a, private C2b lifecycle dispatch, the private Recovery Set Manifest V1 codec, trusted construction, custody-owner fact observation, the private exact-root native picker, independently complete-set-verified first and second digital recovery sets, and the final aggregate keyless Layer D proof. The strongest supported namespace/directory durability proof, Layer D lifecycle composition, and runtime/manual validation remain prerequisites. Migration also remains gated on normal product reachability and manual ceremony validation, a separate writable maintenance connection/owner, interruption/restart classification, exact metadata/`user_version`/evidence/freshness/lineage update ordering, later execution-chain close-failure composition, and proof that migration cannot become startup/setup fallback. Observing schema 1, possessing `ProductionDatabaseMigrationAuthorization`, constructing, parsing, validating, publishing, or freshly verifying a manifest, or holding the final aggregate Layer D proof must never by itself imply eligibility or execution.
- Implemented migration-opportunity and confirmation verification proves that Rust alone establishes the exact process-local `Pending` opportunity after revalidation; React cannot create or identify it; no bare IPC call can manufacture it; and the migration-specific substate is owned beneath `ApplicationLifecycle`, separate from `StartupStatus` and any generic maintenance state machine.
- Focused state-transition tests cover `NotOffered -> Pending -> Authorized -> Consumed` and `Pending -> Revoked`, atomic mutex-serialized confirmation/shutdown invalidation, duplicate refusal, same-process no-renewal, fresh-owner restart semantics, and shutdown invalidation before the existing lifecycle shutdown transition.
- Future command tests must treat `confirm_production_database_migration` and `cancel_production_database_migration_confirmation` as migration-specific and argument-free. Confirmation must allow only the first valid atomic consumption; repeated, concurrent, replayed, stale, and non-pending calls must create nothing. Cancellation must be non-authorizing, terminally revoke `Pending`, and prevent later confirmation in that process. UI abandonment must eventually invoke cancellation or equivalent Rust-owned revocation.
- Neither future command may accept a Boolean, operation name, version, path, ID, nonce, authorization object, backup proof, integrity proof, database owner, or arbitrary frontend value. Any result must remain coarse (`accepted`, `notPending`, or `unavailable`); `accepted` means only internal Rust retention, and authorization must never be serialized or cross IPC.
- No `ConfirmedMigrationIntent` abstraction exists. Confirmation directly constructs and internally retains private, non-`Copy`, non-`Clone`, non-serializable, non-persistent, redacted, exactly-once-consumable `ProductionDatabaseMigrationAuthorization`.
- Threat-model verification must not claim protection from a compromised renderer: it could invoke the future argument-free command during legitimate Rust-owned `Pending`. The boundary represents consent in that exact context, not authenticated identity. Stronger assurance requires separately approved authentication, trusted UI, or another mechanism, while React still cannot establish `Pending` or authority.
- The state machine, production opportunity/revalidation path, exclusivity, full-integrity source, and encrypted backup stage are implemented before migration execution. Confirmation/cancellation IPC and UI remain absent, and migration eligibility must still be revalidated when execution is composed.
- Future authority-composition verification must prove that application start, `Ready`, setup authority, startup authorization, `OperationalProductionDatabase`, `FullIntegrityValidatedProductionDatabaseConnection`, backup existence or verified-backup proof, writable ownership, migration eligibility, version compatibility, and concurrency or exclusivity cannot substitute for migration authorization. Source/target versions, backup proof, full-integrity proof, writable ownership, exclusivity, and installation/evidence/freshness state remain separate prerequisites; backup proof does not create consent and is not embedded in authorization.
- Future taxonomy verification must preserve restore, recovery, rekey or database-key replacement, anchor replacement, database replacement, and destructive cleanup as distinct authority domains outside migration. Recovery must remain distinct from restore, rekey from database replacement, and destructive cleanup from reset, repair, recovery, replacement, and migration. Setup and startup are not maintenance operations. Backup verification/acceptance and full-integrity validation are safety/proof capabilities, not operation identities. Diagnostics, including full-integrity diagnostics, backup creation, and the catch-all “installation/evidence replacement” are not approved operation variants.
- The migration foundation includes the private Rust authorization/state representation, production opportunity/revalidation, exclusivity, full-integrity-bound source, encrypted backup stage, recovery-envelope verification, C1 custody foundation, C2a adapter, C2b lifecycle/main-thread/real-main-window dispatch, independently complete-set-verified first and second digital recovery sets, and final aggregate Layer D proof. The separately documented first-business-schema physical contract supplies target schema version 2 and the 1-to-2 compatibility direction, but there is no migration SQL, production confirmation IPC/UI, authentication role, normal product reachability, Layer D lifecycle composition, writable maintenance owner, migration execution, or detailed fixtures for those future designs.
- Future C2b runtime/manual, publication, and staged-restore tests must preserve the verified encrypted stage, implemented XChaCha20-Poly1305 recovery envelope, C1 state/ownership contracts, C2a disclosure/failure contracts, and C2b ownership boundary; validate real main-window/main-thread behavior, actual human custody, and publication in later contracts; retain exact correspondence and lineage policy; require explicit recovery authority; and permit no production plaintext database or fallback.
- Authority tests must prove that persisted presence, evidence validation, path validation, key recovery, read-only opening, metadata decoding, integrity, correspondence, freshness, installation-state classification, startup authorization, operational activation, setup, migration, recovery, replacement, and destructive cleanup cannot substitute for one another.
- Clean-machine release verification must run separately on supported Windows 10 x64 and Windows 11 x64 local-NTFS standard-user hosts. It must record pinned `rusqlite`, SQLCipher, OpenSSL, and lockfile identity; prove no system SQLCipher/OpenSSL dependency; and reject every unsupported platform/storage category. Release automation details remain deferred.

The existing `sqlcipher_windows_temporary_encryption_feasibility` test remains historical Windows test-only experiment evidence.

The accepted review now includes the complete owner chain through startup authorization and operational activation; lifecycle commit `44d2770786d4534ef37fb58b383e5b74ab73d04c`; independently observed early and final installation evidence; actual second-value authorization; worker/off-UI-thread sequencing; coarse frontend status; shutdown drain and late-owner prevention; retained close-failure ownership; debug/test-only manual support; manual scenarios A-E and Scenario D's limited race claim; the historical validation evidence above; remaining coordinated-rollback and path-race limitations; and confirmation that this reconciliation changes documentation only.

For correspondence the accepted review covers the exact consumed inputs, exactly-once classifier reuse, coarse mismatch taxonomy, private ownership, disposal and close behavior, redaction, the narrow production-absent `cfg(test)` seam, absence of new dependencies or direct frontend authority in the adapter, later fixed-chain lifecycle composition, and the locked limitations on lineage, freshness, rollback resistance, startup authorization, operational activation, setup, migration, wider schema, recovery, backup/restore, replacement, and business data.

For freshness the accepted review covers the two consumed inputs and all four normalized states, prohibition on paths and earlier anchor forms, completion of loading and normalization upstream, exactly-once pure classification, Fresh-only advancement, disposal and close ownership, redaction, the coordinated-rollback limitation, absence of direct frontend authority in the adapter, later fixed-chain lifecycle composition, and continued separation from startup authorization and operational activation.

## Environment-dependent and manual checks

`npm run tauri:dev` needs Microsoft C++ Build Tools and WebView2. It opens the real window. Local structured health and lifecycle events appear in its terminal; no log file or upload exists. Those events remain coarse and redacted.

To inspect the unknown route, use webview devtools when available and run `window.history.pushState({}, "", "/not-a-route"); window.dispatchEvent(new PopStateEvent("popstate"));`. Health failure is safely covered by `npm test`, which mocks an invalid command response containing raw backend detail. There is no production crash trigger; manual visual inspection requires an uncommitted, disposable equivalent mock.

On Windows 11, manually inspect startup, one-window behavior, keyboard use, focus, resizing, scaling, health success, and logs. Repeat startup on Windows 10 where available. Neither target is verified until observed.

A temporary Windows-only SQLCipher feasibility database check is included, but it is not production database validation and automation does not prove production storage security; no production build, installer, signing, release, deployment, browser or desktop E2E automation, coverage threshold, or service check is included. CI omits `tauri build`; Clippy and Rust tests provide narrow compile coverage without generating an installer. Automation does not prove runtime startup, Windows 10 support, WebView2 availability, real-webview accessibility, low-memory support, security, or parish workflows.

## Recovery-volume lifecycle evidence

Focused deterministic lifecycle tests and source-contract checks cover both picker dispatches through `run_on_main_thread`, real `main` window/`HWND` resolution, reuse of `select_native_recovery_volume_root`, one-shot shutdown/main-thread arbitration, lock release before native work, worker-held source/root/exclusivity ownership, retryable `Cancelled` and `Unavailable` parking, and explicit private retry without automatic redisplay. First-root coverage proves canonical production topology, retained-root, and production-separation reuse. Second-root coverage proves canonical retained-root validation followed by the consuming canonical two-root transition, both-root revalidation, first-root preservation only before consumption, custody-only reset on every consuming-transition failure, exact source-plus-two-root success ownership, and unchanged unresolved exit accounting. Capacity-composition coverage proves the exact canonical borrowed required-byte observation, absence of lifecycle byte arithmetic, the narrow canonical capacity facade, pre-consumption source-observation failure preserving both roots, consuming failure retaining neither root, and shutdown-before-work suppression. Directory-composition coverage proves entry only from exact capacity-validated ownership, immediate worker continuation through the canonical facade, lifecycle absence of child-name or conflict policy, source-plus-canonical-directory success ownership, unpublished coarse state, unresolved migration work, retained exclusivity, custody-only reset after consuming failure, no automatic retry, and directory/root drop before canonical source shutdown. Canonical fixed-child regressions cover exact naming; exact, ASCII-case, file, reparse, and unavailable-observation conflicts; first-before-second ordering; first failure blocking second; second or verification failure preserving created state without rollback; hardened immediate reopen; root/child and destination continuity; redacted ownership; and absence of cleanup APIs. The deterministic picker seam displays no UI and uses no Tauri runtime, USB, or browser automation.

Source exclusions cover lifecycle/IPC path exposure, fake production selection, lifecycle-derived child naming, artifact publication, custody re-entry, complete-set verification, migration execution, and recovery-device cleanup. No manual directory-creation run is claimed for this unreachable isolated slice. Future integrated real-device validation must cover successful creation on two selected NTFS external devices; exact, case-conflicting, file, and reparse conflicts; failure on device 2 after device 1 creation; shutdown after one or two child creations; and confirmation that every partial child remains untouched. Capacity validation, picker parenting/modality, Cancel/X/Alt+F4, retry after cancellation/unavailability, valid distinct and same-device cases, detach races, Windows 10/11, and keyboard-only behavior also remain for integrated validation.
