# Security and data

- Never place secrets, tokens, credentials, or production environment configuration in the frontend or repository.
- Never place sensitive parish or personal data in logs, tests, examples, or screenshots. Tests use synthetic bootstrap strings only.
- Privileged operations belong in Rust. React must not directly access files, a future database, encryption material, or privileged services.
- Production database paths cannot be supplied by frontend values, command arguments, environment variables, command-line values, or user-selected strings. No Tauri command returns the production directory, database filename, database path, Windows username, or filesystem metadata.
- Production setup authorization is an in-memory Rust type with a private field, created only by a dedicated transition from never-initialized evidence. Raw booleans, React or IPC values, CLI arguments, environment variables, paths, and arbitrary strings cannot construct it. No setup Tauri command exists.
- Ordinary startup has no setup authorization. Initialized-but-missing storage, inconsistent installation evidence, and unavailable evidence fail closed and cannot fall back to first-time setup or authorize creation.
- The fixed production path is modeled beneath the application-owned per-user local application-data directory for `io.github.cltubigon.churchapp`. This stage performs no directory or database creation, opening, migration, or connection.
- Normal operation assumes one dedicated standard Windows account and no elevation. Future local parish storage must be encrypted and authoritative, but the final database technology, algorithms, keys, schemas, and migrations are deferred; SQLCipher remains only a candidate.
- Future central privileged credentials must remain server-side. Supabase is not configured here.
- Current logs are local development terminal output, limited to event name, outcome, and safe code. They contain no payload, raw error, environment value, machine identifier, path, user information, or parish data, and nothing is uploaded.

Automated checks do not prove security, accessibility, desktop runtime behavior, storage safety, or complete user flows. Protection and persistence for future installation evidence remain deferred, as do ACL enforcement, reparse-point and junction defenses, removable-drive and network-share detection, runtime file-replacement detection, database creation, authentication, backup, recovery, activation, and update security.
