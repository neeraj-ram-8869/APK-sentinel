# Implementation Plan: Generative AI for Automated APK Reverse Engineering, Static-Dynamic Analysis & Risk Scoring

This master plan aligns the **APK Sentinel** hackathon project with the [Hackathon Report Document](file:///c:/Users/ACER/Downloads/document.md). The system is built around **apkman** (browser-based static reverse engineering) and **aparoid** (sandbox dynamic tracing), with a generative AI layer powered by NVIDIA NIM (Llama-3.1-70B) for analyst-ready threat narratives.

---

## System Architecture (from document)

The document specifies a **six-layer architecture**:

| Layer | Purpose | Technology |
|-------|---------|------------|
| 1. APK Ingestion | Upload and unpack APK files | apkman (browser-based, client-side) |
| 2. Static Extraction | Permissions, components, strings, classes, signatures, resources | apkman manifest parser, DEX decompiler |
| 3. Feature Normalization | Convert extracted artifacts to JSON/tabular format | Custom normalizer |
| 4. Generative AI Interpretation | Summarize code, explain suspicious logic, produce analyst reports | NVIDIA NIM (Llama-3.1-70B) |
| 5. Dynamic Analysis Module | Runtime traces, network behavior, execution indicators | aparoid (emulator sandbox) |
| 6. Risk Scoring Engine | Fuse static + dynamic features into final threat score | Rule-based + ML hybrid |

### Verdict Classifications
APKs are classified into four categories: **BENIGN**, **SUSPICIOUS**, **FRAUDULENT**, **MALICIOUS**.

### Hackathon MVP Requirements (from document)
- APK upload and analysis through apkman
- Manifest and code extraction
- AI-generated reverse-engineering summary
- Static risk score with reasons
- Basic comparison against known benign or suspicious APKs
- A simple dashboard showing verdict, confidence, and key indicators

---

## Session Breakdown

### Session 1: Foundation & UI Shell ✅ COMPLETE

**Scope:** Project setup, design system, upload interface, mock analysis dashboard.

#### Delivered
- Next.js 16 project with dependencies (jszip, jspdf, html2canvas)
- Full design system CSS (light corporate theme, glassmorphic cards)
- 4 mock APK profiles: BankBot (MALICIOUS), Adware (SUSPICIOUS), CryptoWallet (FRAUDULENT), Calculator (BENIGN)
- Interactive canvas DNA fingerprint visualization
- Simulated terminal decompile logger
- Tab system: Executive Summary, Dynamic Traces (aparoid), Permissions Matrix, Static Code & APIs, AndroidManifest.xml, AI Threat Narrative
- NVIDIA NIM chatbot panel
- Client-side jsPDF threat report exporter
- All PCI-DSS / OWASP references removed and replaced with apkman / aparoid terminology

#### Files
- `frontend/src/app/globals.css` — Design system
- `frontend/src/app/layout.tsx` — Root layout with SEO metadata
- `frontend/src/app/page.tsx` — Full dashboard with state machine
- `frontend/src/components/ApkUploader.tsx` — Upload component
- `frontend/.env.local` — Environment variables

---

### Session 2: APK Parser Engine COMPLETE

**Scope:** Real APK file parsing — extract manifest, DEX class tables, and certificate info from uploaded `.apk` files using JSZip.

#### Files to Create
- `lib/apk-parser/index.ts` — JSZip extraction orchestrator
- `lib/apk-parser/manifest-decoder.ts` — Binary AXML → readable XML decoder
- `lib/apk-parser/dex-parser.ts` — DEX string table + class name extractor
- `lib/apk-parser/signature.ts` — META-INF certificate parser
- `hooks/useAnalysis.ts` — Orchestration hook with progress events

#### Files to Modify
- `page.tsx` — Wire uploader → parser → console output

#### Verification
- Drop a real `.apk` file → console shows parsed permissions, class names, strings

---

### Session 3: Analysis Engine COMPLETE

**Scope:** Parser output feeds into analyzers → structured threat findings with severity levels.

#### Files to Create
- `lib/analysis/permissions.ts` — Permission database + danger mapping + dangerous combos
- `lib/analysis/repackaging.ts` — Known app database + signature mismatch detection
- `lib/analysis/sdk-detector.ts` — SDK identification by class name patterns
- `lib/analysis/strings.ts` — URL/IP extraction from DEX string tables

#### Files to Modify
- `hooks/useAnalysis.ts` — Chain: parse → analyze → findings

#### Verification
- Drop APK → console shows categorized findings with severity levels

---

### Session 4: AI Integration (NVIDIA NIM) ⬜

**Scope:** NVIDIA NIM Llama-3.1-70B generates threat narratives and app summaries from the structured findings.

#### Files to Create
- `app/api/analyze/route.ts` — Next.js API route proxying NVIDIA NIM calls
- `lib/ai/nvidia-client.ts` — Client-side API caller with streaming support
- `lib/ai/prompts.ts` — Prompt templates (app summary, threat narrative, risk explanation)
- `components/ThreatNarrative.tsx` — Streaming AI text display component
- `components/AiSummaryCard.tsx` — Summary card with loading state

#### Files to Modify
- `hooks/useAnalysis.ts` — Wire AI layer into analysis pipeline

#### Verification
- Drop APK → AI streams a plain-language threat narrative on screen

---

### Session 5: Risk Scoring + DNA Fingerprint + Timeline ⬜

**Scope:** Calculate interpretable risk scores, render visual DNA fingerprint, animate analysis timeline.

#### Files to Create
- `lib/scoring/engine.ts` — Rule-based scorer with explainability
- `lib/dna/fingerprint.ts` — Fingerprint data generator from analysis features
- `components/RiskGauge.tsx` — Animated SVG circular gauge
- `components/DnaFingerprint.tsx` — Canvas concentric ring visualization
- `components/AnalysisTimeline.tsx` — Animated vertical timeline
- `components/ScoreBreakdown.tsx` — Expandable score explanation cards

#### Key Design (from document)
> "The final score should be interpretable, so the system can explain *why* an APK was marked high risk rather than only returning a label."

Static indicators: dangerous permissions, exported components, obfuscation, weak signatures, embedded URLs, suspicious API usage.
Dynamic indicators: network beacons, stealth behavior, sensitive data access.

#### Verification
- Drop APK → see animated score, DNA rings drawing, timeline populating

---

### Session 6: Full Dashboard Assembly ⬜

**Scope:** Compose all components into the final single-page dashboard with responsive layouts and scroll-reveal animations.

#### Files to Create
- `components/PermissionGrid.tsx` — Color-coded permission heatmap
- `components/ManifestViewer.tsx` — Interactive manifest tree viewer
- `components/CodeViewer.tsx` — Suspicious code snippets display
- `components/RepackagingBadge.tsx` — Clone/repackaging detection indicator

#### Files to Modify
- `page.tsx` — Full layout with all sections integrated
- `globals.css` — Responsive grid layout + scroll reveal animations

#### Verification
- Full end-to-end: upload → parse → analyze → AI → score → all panels populated

---

### Session 7: PDF Report + Polish + Demo Prep ⬜

**Scope:** PDF export with all analysis sections, final animations, demo-ready state.

#### Files to Create/Modify
- `lib/pdf/report-generator.ts` — jsPDF multi-section report builder
- `components/PdfReport.tsx` — Download button with generation progress

#### Verification
- Complete demo rehearsal with 3+ sample APKs
- PDF downloads successfully with all sections (profile, cert, static indicators, dynamic traces, threat narrative, risk score)

---

## Key Technical References

| Tool | Role | Source |
|------|------|--------|
| **apkman** | Browser-based APK reverse engineering (static) | https://github.com/jiusanzhou/apkman |
| **aparoid** | Dynamic sandbox analysis | https://github.com/stefan2200/aparoid |
| **ReverseAPK** | Reference reverse engineering tool | https://github.com/1N3/ReverseAPK |
| **NVIDIA NIM** | Llama-3.1-70B threat narrative generation | NVIDIA API |

