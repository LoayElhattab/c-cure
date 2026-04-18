# C-Cure — CLAUDE.md

## ⚠️ CRITICAL: Token Constraints
You are running via a **limited-token OpenRouter free-tier API**.
- **DO NOT** use glob patterns to read entire directories.
- **DO NOT** read multiple large files in a single turn.
- **Ask before reading any file over 200 lines.**
- Keep all responses, code generation, and explanations **extremely concise** to avoid HTTP 402 errors.
- Prefer targeted, surgical edits over full-file rewrites.

---

## Architecture

```
C-Cure/
├── src/            # SvelteKit frontend (routes, components, lib)
├── src-tauri/      # Tauri v2 config, Rust shell
├── backend/        # Python backend (called via Tauri shell plugin)
│   ├── main.py     # CLI entrypoint — dispatches all commands
│   ├── parser.py   # tree-sitter AST extraction
│   ├── inference.py# Kaggle API ML calls
│   ├── database.py # SQLite3 CRUD
│   └── reports_generator.py # reportlab PDF generation
└── static/
```

**Data flow:** SvelteKit UI → Tauri `shell` plugin → `python main.py <command>` → JSON stdout → UI.

---

## Tech Stack

| Layer | Stack |
|---|---|
| Desktop shell | Tauri v2 |
| Frontend | SvelteKit (Svelte 5), Tailwind CSS v3, Lucide-Svelte, Chart.js |
| Backend | Python 3, tree-sitter + tree-sitter-cpp, SQLite3, requests, reportlab |

---

## Code Conventions

### Frontend (SvelteKit / Svelte 5)
- Use **Svelte 5 Runes** (`$state`, `$derived`, `$effect`) — not legacy `let`/`$:` reactivity.
- ES modules only (`import`/`export`), no CommonJS.
- Style with **Tailwind utility classes**; avoid inline `style=` unless dynamic values require it.
- Routes live in `src/routes/`; shared logic/types in `src/lib/`.

### Backend (Python)
- **PEP 8** formatting; use **type hints** on all function signatures.
- All SQLite queries must use **parameterized placeholders** (`?`) — no f-string SQL.
- `main.py` is the only CLI entrypoint; all new features must be registered as a `command` branch there.
- Backend returns **only JSON** to stdout; errors as `{"error": "..."}`.

---

## Common Commands

```bash
# Start Tauri dev (frontend + desktop)
npm run tauri dev

# Frontend only (browser)
npm run dev

# Type-check frontend
npm run check

# Build production app
npm run tauri build

# Run Python backend manually
python backend/main.py <command> [args]
# e.g.:
python backend/main.py analyze path/to/file.cpp
python backend/main.py analyze_folder path/to/project/
python backend/main.py history
python backend/main.py statistics
python backend/main.py generate_pdf <analysis_id>
python backend/main.py get_settings
python backend/main.py save_settings <kaggle_url>
```

---

## Key Constraints
- ML inference requires a **live Kaggle notebook URL** set via Settings (`backend/config.json`).
- The Tauri `shell` plugin bridges frontend ↔ Python; sidecar is bundled under `bundle.resources`.
- Python deps: `tree-sitter tree-sitter-cpp requests reportlab`
