# Walkthrough: Aligned Hybrid Static-Dynamic APK Security Console

We have successfully refined the **Session 1** user interface for **APK Sentinel** to align perfectly with the provided Hackathon Report. All generic PCI-DSS and OWASP terms have been replaced by technical analysis parameters centered on **apkman** (static analysis core) and **aparoid** (dynamic sandbox tracer).

---

## 1. Summary of Changes

### Removal of Out-of-Scope Standards
- Purged all occurrences of `PCI-DSS` and `OWASP` from headings, badges, chat logs, terminal simulator strings, tables, and tab structures.

### Header & Hero Section Alignments
- Updated the header badge to `HYBRID APK THREAT ANALYSER`.
- Changed the hero title to `Automated Reverse Engineering & Risk Scoring for Mobile Applications`.
- Replaced the hero subtitle to emphasize browser-side extraction via **apkman** and sandbox runtime tracing via **aparoid**.

### Specifications Tab Overhaul
- The specification sub-tabs at the bottom of the landing page now showcase the core technologies:
  1. **apkman (Static)**: Highlights manifest parsing, DEX decompiler capabilities, and cryptographic signer checks.
  2. **aparoid (Dynamic)**: Details network beacon tracking, overlay window intercepting, and Accessibility service auditing.
  3. **NVIDIA NIM (AI)**: Explains how LLM models translate raw signal data into readable threat narratives.

### Interactive Audit Tab & Checklist
- Renamed the dashboard's detailed checklist tab to **Dynamic Traces (aparoid)**.
- Replaced the old regulatory requirements (PCI-M1 to PCI-M5) with technical tracer codes:
  * **AP-D1 (Network Beacon Tracer)**: Outbound socket telemetry and C2 detections.
  * **AP-D2 (UI Overlay Injection)**: Hijacking detection of login forms via overlay drawing.
  * **AP-D3 (Filesystem Sandbox Integrity)**: Cryptographic audits of local app files.
  * **AP-D4 (Accessibility Service Abuse)**: Keystroke and input logging checks.
  * **AP-D5 (Dynamic Executable Tracer)**: Sandbox reflection and classloader audits.

### Job History Ledger & PDF Export
- Replaced the ledger standard checked column with **Analysis Scope** and labeled items as `apkman + aparoid (Hybrid)`.
- Adjusted default chat prompt placeholders to invite inquiries about static/dynamic traces.

---

## 2. Verification

- **Dev Compilation**: Next.js compiled successfully with zero type or build errors.
- **Dynamic Tracing**: Clicking on the history ledger or cards launches scans that correctly map verification status against the new `AP-D1` through `AP-D5` indicators.
- **Verdict Mapping**: Verified that verdicts map cleanly across all four official classifications (`BENIGN`, `SUSPICIOUS`, `FRAUDULENT`, `MALICIOUS`).
