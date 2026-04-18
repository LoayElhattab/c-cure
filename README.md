# C-Cure: LLM-Based C/C++ Vulnerability Scanner

[![Rust Backend](https://img.shields.io/badge/Backend-Rust-orange.svg)](https://www.rust-lang.org/)
[![Tauri Framework](https://img.shields.io/badge/Framework-Tauri_v2-blue.svg)](https://tauri.app/)
[![Svelte Frontend](https://img.shields.io/badge/Frontend-Svelte_5-ff3e00.svg)](https://svelte.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

**C-Cure** is a desktop application designed to streamline the identification of security vulnerabilities in C and C++ source code. By combining native system-level parsing with intelligent inference, C-Cure enables developers, security researchers, and students to detect critical flaws such as buffer overflows and memory leaks before they reach production.

Built on the **Tauri v2** framework with a high-performance **Rust backend**, C-Cure provides a lightweight, responsive, and cross-platform experience with zero external runtime dependencies.

---

## Table of Contents

- [Key Features](#key-features)
- [Application Architecture](#application-architecture)
- [Project Structure](#project-structure)
- [Methodology & Workflow](#methodology--workflow)
- [Vulnerability Coverage](#vulnerability-coverage)
- [Prerequisites](#prerequisites)
- [Installation & Usage](#installation--usage)
- [Unit Testing](#unit-testing)
- [Contact](#contact)

---

## Key Features

### Smart Static Analysis
C-Cure uses specialized AST (Abstract Syntax Tree) parsing to break down C++ files into logical functions. This allows for granular security analysis of code blocks, improving accuracy and reducing noise compared to traditional line-by-line scanners.

### Interactive Security Dashboard
Monitor your project's security posture in real-time. The built-in dashboard provides visual metrics on total analyses, vulnerability counts, and severity distributions, helping you prioritize your remediation efforts.

### Continuous Folder Monitoring
Register your project directories to track changes automatically. C-Cure uses baseline hashing to detect modified files, allowing you to re-analyze only what has changed, saving time and resources.

### Professional PDF Reporting
Export detailed vulnerability assessment reports with a single click. Every report includes project metadata, function-level breakdowns, CWE identifications, and severity ratings, formatted for professional distribution.

### Premium User Experience
Enjoy a modern, responsive interface built with Svelte 5 and Tailwind CSS. The app features optimized navigation, syntax-highlighted code views, and a unified dark-mode aesthetic for comfortable development.

---

## Application Architecture

| Layer | Component | Description |
|-------|-----------|-------------|
| **Frontend** | Svelte 5 + Tailwind | A reactive, modern UI managing user interactions and data visualization. |
| **Logic Engine** | Rust (Tauri Core) | High-performance backend handling AST parsing, file system I/O, and secure state management. |
| **Parser** | Tree-sitter (C++) | Industrial-grade parser for accurate C++ function extraction and syntax analysis. |
| **Inference Layer** | Remote API | A modular "blackbox" inference step that classifies extracted code snippets via external ML models. |
| **Persistence** | SQLite (Rusqlite) | Secure, in-process storage for historical project data and analysis logs. |

---

## Project Structure

```text
.
├── src/                # Frontend Application (SvelteKit)
│   ├── lib/            # Shared logic, stores, and UI utilities
│   └── routes/         # Application pages (Analyze, Statistics, Monitor, Reports)
├── src-tauri/          # Native Backend (Rust)
│   ├── src/
│   │   ├── parser.rs   # AST extraction logic
│   │   ├── db.rs       # Database & Result persistence
│   │   ├── ml_api.rs   # External inference bridge
│   │   ├── monitor.rs  # File change detection
│   │   └── report.rs   # Native PDF generation
│   └── Cargo.toml      # Backend dependency manifest
├── test_project/       # Demo analysis target project
└── README.md
```

---

## Methodology & Workflow

1.  **Scanning**: The user selects a file or folder for analysis.
2.  **Extraction**: The Rust backend uses `tree-sitter` to identify every C++ function definition, effectively "slicing" the code for analysis.
3.  **Inference**: Normalized function snippets are sent to a remote inference service (via the endpoint configured in Settings). This stage classifies each block as **Safe** or **Vulnerable**.
4.  **Reporting**: Analysis results are merged with CWE metadata, stored in the local database, and made available for dashboard viewing or PDF export.

---

## Vulnerability Coverage

C-Cure maps code vulnerabilities to standard **Common Weakness Enumerations (CWE)**:

| ID | Description | Default Severity |
|----|-------------|------------------|
| **CWE-125** | Out-of-bounds Read | High |
| **CWE-787** | Out-of-bounds Write | Critical |
| **CWE-190** | Integer Overflow | High |
| **CWE-369** | Divide By Zero | Medium |
| **CWE-415** | Double Free | High |
| **CWE-476** | NULL Pointer Dereference | High |

---

## Prerequisites

- **Node.js**: Version 20+
- **Rust**: Stable toolchain (via `rustup`)
- **C++ Build Tools**: MSVC (Windows) or GCC/Clang (Linux/macOS) for native parser bindings.
- **Inference Endpoint**: A valid Kaggle/NGROK URL configured in the app's settings.

---

## Installation & Usage

1.  **Clone & Install**
    ```bash
    git clone https://github.com/LoayElHattab/C-Cure.git
    cd C-Cure
    npm install
    ```

2.  **Run Development Environment**
    ```bash
    npm run tauri dev
    ```

3.  **Setup Inference**
    Open the application, go to **Settings**, and enter your remote Inference API URL.


---

## Contact

For questions or collaboration inquiries, please open an issue in the project repository.
