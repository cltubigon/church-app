# Bootstrap review checklist

- [ ] Changes stay in allowed bootstrap scope and preserve unrelated work.
- [ ] Dependencies are necessary, exact, locked, approved, and reported.
- [ ] React remains presentation-only; privileged work remains in Rust.
- [ ] No secrets, sensitive data, raw errors, payloads, or production configuration exist.
- [ ] No unapproved production database implementation, authentication, Supabase, backup, PDF, updater, activation, telemetry, or speculative abstraction exists.
- [ ] Any production database dependency is separately approved, exact, locked, uses the approved bundled SQLCipher/vendored OpenSSL feature, and has no system-library or plaintext fallback.
- [ ] Any metadata-schema change exactly preserves the approved singleton fields, storage classes, lengths, `ApplicationDatabaseFormatIdentity` 16-byte BLOB decoding, header values, and fail-closed validation.
- [ ] Database-key ownership, CurrentUser-DPAPI live-key protection, separate recovery-key custody, zeroization limits, and redacted formatting follow the approved lifecycle without sharing the evidence HMAC key.
- [ ] Ordinary database inspection is proven read-only and no-create, and setup, startup, operational opening, migration, recovery, replacement, and destructive cleanup remain separate authorities.
- [ ] Database errors and logs expose no path, SQL/PRAGMA text, key, identifier, generation, metadata, DPAPI data, native status, raw chain, username, or profile directory.
- [ ] Only the four approved unavailable top-level areas appear.
- [ ] Landmarks, headings, labels, keyboard access, focus, resizing, and scaling were reviewed.
- [ ] Health success is non-sensitive and typed on both sides; failures are calm and safe.
- [ ] Exact validation evidence, failures, skipped checks, and environment limits are reported.
- [ ] Manual Windows 11, intended Windows 10, navigation, health, accessibility/scaling, logging, and exclusion tests are recorded.
- [ ] No file was staged, committed, or pushed and no Git configuration changed.
