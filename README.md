# APK Sentinel

APK Sentinel is a hybrid threat analyzer that allows you to scan APK files for potential security risks, generate AI-powered threat reports, and perform dynamic and static analysis.

## Features

- **Static Analysis**: Extract AndroidManifest.xml, parse DEX bytecode, check certificates.
- **Dynamic Analysis**: Upload to VirusTotal, scan with hybrid engines.
- **AI Narrative**: Uses NVIDIA NIM to generate threat reports.
- **Dashboard**: Track history and risk scores for uploaded APKs.

## Prerequisites

- Node.js (v18+)
- npm or yarn

## Setup

1. Navigate to the `frontend` directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Environment Variables:
   Copy `.env.example` to `.env.local` and fill in your API keys:
   ```bash
   cp .env.example .env.local
   ```
   You will need:
   - `NVIDIA_API_KEY`: For AI Threat Narratives
   - `VIRUSTOTAL_API_KEY`: For VirusTotal Intel integration

4. Run the development server:
   ```bash
   npm run dev
   ```

5. Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

## Structure

- `frontend/`: Contains the Next.js application, UI components, and API routes.
- `frontend/src/components/`: Reusable React components.
- `frontend/src/app/`: Next.js app router pages and API routes.
- `frontend/src/lib/`: Utility functions for AI, scoring, and PDF generation.

## License

This project is licensed under the MIT License.
