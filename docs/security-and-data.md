# Security and data

- Never place secrets, tokens, credentials, or production environment configuration in the frontend or repository.
- Never place sensitive parish or personal data in logs, tests, examples, or screenshots. Tests use synthetic bootstrap strings only.
- Privileged operations belong in Rust. React must not directly access files, a future database, encryption material, or privileged services.
- Future local parish storage must be encrypted and authoritative, but database technology, algorithms, keys, schemas, and migrations are deferred.
- Future central privileged credentials must remain server-side. Supabase is not configured here.
- Current logs are local development terminal output, limited to event name, outcome, and safe code. They contain no payload, raw error, environment value, machine identifier, path, user information, or parish data, and nothing is uploaded.

Automated checks do not prove security, accessibility, desktop runtime behavior, storage safety, or complete user flows. Database, authentication, backup, recovery, activation, and update security remain deferred.
