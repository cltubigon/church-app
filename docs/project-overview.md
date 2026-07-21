# Project overview

Church App is intended to support a Roman Catholic parish through a Windows-first, desktop-first application that must operate offline. Future encrypted local parish data will be authoritative; central Supabase infrastructure is planned to be non-authoritative. The public Next.js surface and canonical contracts are intended for separate repositories and neither exists here.

This repository currently provides only a Tauri 2 foundation: an accessible React shell, four unavailable placeholder areas, a typed Rust health command, focused tests, and narrow validation. It is not a usable parish application and must not receive real parish data.

The five approved future service types, as documentation constraints only, are Baptism, Confirmation, Wedding or Marriage, Burial/Funeral, and First Communion. No forms, workflows, records, schedules, or domain models for them are implemented here.

The bootstrap excludes databases and encryption implementations, authentication, Supabase integration, public intake, synchronization, activation, backup and recovery, PDFs and printing, updates, telemetry, reports, certificates, and all real workflows. The first release direction is English only, but localization behavior is not implemented.
