# SQLCipher Windows feasibility findings

## Scope and selection

This report covers only the temporary Windows proof of concept. SQLCipher is a candidate under evaluation, not the final production database. No production path, schema, migration, authentication, recovery, backup, session, UI, or Tauri command is introduced.

The selected exact direct dependency is `rusqlite` 0.39.0 with default features disabled and only `bundled-sqlcipher-vendored-openssl` enabled as a Windows development dependency. Cargo locks `libsqlite3-sys` 0.37.0, `openssl-sys` 0.9.117, and `openssl-src` 300.6.1+3.6.3. Inspection of the locked amalgamation identifies SQLCipher 4.10.0 Community and SQLite 3.50.4.

## Configurations considered

- System-linked SQLCipher (`sqlcipher`): rejected for this experiment because it requires a separately provisioned architecture-compatible SQLCipher library and does not establish one reproducible native package.
- Bundled SQLCipher (`bundled-sqlcipher`): rejected because it still searches for a system crypto library.
- Bundled SQLCipher with vendored OpenSSL (`bundled-sqlcipher-vendored-openssl`): selected because Cargo compiles the pinned SQLCipher amalgamation and OpenSSL source without an external SQLCipher or OpenSSL runtime package.

No fallback configuration was installed or tested.

## Native build and artifacts

On `x86_64-pc-windows-msvc`, `libsqlite3-sys` compiles the SQLCipher C amalgamation and links it statically. `openssl-src` builds OpenSSL 3.6.3 with MSVC/`nmake`; `openssl-sys` links its static libraries. Observed ignored intermediates were `sqlcipher.lib`/`libsqlcipher.a` (5,142,426 bytes), `libcrypto.lib` (55,126,954 bytes), and `libssl.lib` (10,246,704 bytes). The debug test executable was 7,108,608 bytes. `dumpbin /dependents` showed Windows system/UCRT and `VCRUNTIME140.dll` imports, with no SQLCipher or OpenSSL DLL import. The selected integration therefore does not require shipping a separate SQLCipher or OpenSSL DLL. Existing Rust/Tauri and Windows runtime dependencies are unchanged.

This source build requires Cargo/Rust, the MSVC C/C++ toolchain, Perl, and native make tooling. The observed host is 64-bit Windows using Rust 1.97.1 and the MSVC target. x86 and ARM64 are not validated. A clean vendored native build is slower and larger than the previous Rust-only dependency graph; final release-binary size was not measured because release builds are prohibited.

The feature exists cross-platform and source compilation should preserve a technical path for macOS/Linux, but this test and dependency declaration are Windows-gated. No macOS or Linux compile or runtime result is claimed.

## Runtime proof

The focused test creates a uniquely named directory only below `std::env::temp_dir()`, opens `feasibility.db`, applies a synthetic 32-byte test-only raw key, selects SQLCipher compatibility 4, disables SQLCipher native logging, and stores one unmistakably synthetic sentinel through a bound SQL parameter. It closes and independently reopens with the correct key, then independently attempts a schema read with a different test-only key. It reports only non-sensitive status, SQLCipher/provider identity, and cipher configuration; it never prints either key, the sentinel, SQL payloads, paths, or raw errors.

Journal mode `PERSIST` intentionally retains a test-owned rollback-journal sidecar long enough for the test to scan it. The test scans every regular file in its temporary directory for the sentinel bytes, then removes the entire directory and asserts cleanup. This byte scan is supporting evidence only and is not complete proof of cryptographic correctness.

Run from the repository root:

```powershell
cargo test --manifest-path src-tauri/Cargo.toml --locked sqlcipher_windows_temporary_encryption_feasibility -- --nocapture
```

The temporary directory naming mechanism is `%TEMP%\church-app-sqlcipher-feasibility-<process-id>-<sequence>`. The test does not print the resolved path. Normal and unwinding cleanup use the test-directory guard; the successful path additionally asserts the directory no longer exists. A process termination can bypass Rust destructors and leave only synthetic artifacts in the operating-system temporary location, never in the repository or a future application-data location.

## Licenses, notices, and support

- SQLCipher Community Edition: BSD-style license. Zetetic requires its copyright, complete license conditions, disclaimer, and dependency notices in a user-accessible application or distribution location.
- `rusqlite` and `libsqlite3-sys`: MIT license; retain the copyright and permission notice with substantial copies.
- SQLite base: public domain, with SQLite project acknowledgement identified by Zetetic.
- OpenSSL 3.6.3: Apache License 2.0; distributions must satisfy its notice and license conditions. OpenSSL is the selected cryptographic provider and is not represented as a FIPS-validated configuration.

Primary sources:

- [SQLCipher Community Edition and attribution guidance](https://www.zetetic.net/sqlcipher/community/)
- [SQLCipher license and dependency notices](https://www.zetetic.net/sqlcipher/license/)
- [SQLCipher API and cipher inspection pragmas](https://www.zetetic.net/sqlcipher/sqlcipher-api/)
- [`rusqlite` features, bundled build behavior, and license](https://github.com/rusqlite/rusqlite/tree/v0.39.0)
- [`rusqlite` 0.39.0 manifest](https://github.com/rusqlite/rusqlite/blob/v0.39.0/Cargo.toml)
- [`libsqlite3-sys` 0.37.0 manifest](https://github.com/rusqlite/rusqlite/blob/v0.39.0/libsqlite3-sys/Cargo.toml)
- [Vendored OpenSSL build behavior](https://docs.rs/openssl/latest/openssl/#vendored)
- [OpenSSL license](https://openssl-library.org/source/license/)
- [Rust 1.97.1 release notes](https://doc.rust-lang.org/stable/releases.html#version-1971-2026-07-16)

This is a technical inventory, not legal approval. Separate legal/license review remains advisable before distribution, including the exact placement and completeness of third-party notices and any export/import obligations.

## Limitations and maintenance

Community Edition has community support rather than Zetetic private support. The project would own monitoring and updating `rusqlite`, the bundled SQLCipher amalgamation, OpenSSL, and transitive native build dependencies; rebuilding and repeating encryption/interoperability tests would be required for patches. The pinned versions will not receive fixes automatically. Production key derivation and storage, memory handling, authenticated recovery/backup design, performance, corruption behavior, migration, concurrency, durability, installer redistribution, and long-term format compatibility are deliberately unevaluated.

The focused and full Rust tests passed on the observed 64-bit Windows 11 Professional host. The vendored OpenSSL archive emitted MSVC `LNK4099` warnings because `ossl_static.pdb` was not present; code generation and execution succeeded, and the exact Clippy command with warnings denied also passed. Windows 10 remains pending until directly observed.
