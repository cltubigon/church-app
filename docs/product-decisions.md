# Product decisions

## Current bootstrap authority

- **Implemented stack:** Tauri 2, Rust, React, TypeScript, Vite, and npm.
- **Trust boundary:** Rust is trusted; React is presentation and interaction only.
- **Scope:** application shell, placeholder routing, and a non-sensitive health command only.
- **Non-production identity:** `Church App Foundation`, `org.churchapp.foundation`, version `0.1.0`; review before release.

## Locked future direction (not implemented)

- Desktop-first and offline-capable; Windows 10 and Windows 11 are intended targets.
- Local parish data will be authoritative; future central Supabase services will be non-authoritative.
- The public Next.js application and canonical contracts belong in separate repositories.
- The first release direction is English only.
- Schedule timezone: `Asia/Manila`; dates: `MM/DD/YYYY`; times: 12-hour with AM/PM.
- Future primary request statuses are Pending, Scheduled, Completed, and Cancelled.
- The prior visible **Cancellation requested** primary-status indicator rule is superseded: no such primary-status indicator is to be shown.

These constraints do not authorize related UI, utilities, services, or storage in this repository.
