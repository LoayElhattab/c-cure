# Architectural Refactoring Plan: C-Cure

This plan outlines the strategy to refactor the C-Cure project into a highly modular, professional, and performant cross-platform application. The goal is to prepare the foundation for complex future features by decoupling the frontend presentation from business logic, breaking down monolithic Rust backend modules, and implementing high-concurrency patterns.

## User Decisions & Constraints
- **Connection Pool**: We will use `deadpool-sqlite` (or `r2d2_sqlite` with `tokio::task::spawn_blocking`) to manage a connection pool. This is the best modern approach for async Rust (Tokio) and Tauri, preventing database locks during high-concurrency inference tasks.
- **Component Library**: We will integrate **Bits UI** (a headless component library for Svelte). This provides robust, accessible primitives (dialogs, tooltips, select menus) while allowing us to completely control the markup and CSS to maintain C-Cure's premium dark aesthetic.
- **Inference Architecture**: An `InferenceProvider` trait is mandated. This will decouple the ML logic and allow hot-swapping between:
  1. The current remote Kaggle API.
  2. Local ONNX models (for fully offline scanning).
  3. Future commercial LLM endpoints (e.g., OpenAI, Anthropic).
- **Error Handling**: 
  - `thiserror` will be used in the core libraries and repository layers to define precise, strictly-typed domain errors.
  - `anyhow` will be used at the service and binary edges for easy error propagation and context wrapping.
  - **Tauri IPC Serialization**: All errors crossing the boundary will be mapped into a standardized `AppError` struct that implements `serde::Serialize`, returning user-friendly strings to the Svelte frontend.

## Proposed Changes

### Frontend (SvelteKit / Svelte 5)
Refactor to enforce strict separation of concerns, utilizing Svelte 5 runes for state and dedicated UI components.

#### [NEW] `src/lib/types/bindings.ts`
- Consolidate all TypeScript interfaces mirroring Rust structs (e.g., `AnalysisSummary`, `Report`, `FunctionData`, `DashboardStats`). This ensures type safety across the IPC boundary.

#### [NEW] `src/lib/components/ui/`
- Build reusable UI components wrapping **Bits UI** primitives where applicable: `Button.svelte`, `Card.svelte`, `ProgressBar.svelte`, `StatDisplay.svelte`, `AnimatedStep.svelte`.
- Replace hardcoded Tailwind markup in routes with these modular components to DRY up the codebase and enforce consistency.

#### [NEW] `src/lib/stores/`
- Migrate business logic out of isolated `logic.ts` route files into global/contextual Svelte 5 rune stores (e.g., `analysis.svelte.ts`, `monitor.svelte.ts`).

#### [MODIFY] `src/routes/`
- Strip complex imperative logic from `+page.svelte` files.
- Pages should act as pure views that orchestrate layout, bind store states, and pass data to UI components.

---

### Backend (Rust / Tauri)
Deconstruct monoliths, enforce a service layer, and maximize concurrency.

#### [DELETE] `src-tauri/src/db.rs`
- This 600+ line monolith will be deprecated and broken down into a modular `repository` pattern.

#### [NEW] `src-tauri/src/db/mod.rs`
- Core connection management using `deadpool-sqlite`. Handles connection pool initialization and schema migrations.

#### [NEW] `src-tauri/src/db/analysis_repo.rs`
- Database interactions specific to `analyses`, `files`, and `functions`. Uses `thiserror` for precise database error variants.

#### [NEW] `src-tauri/src/db/stats_repo.rs`
- Database interactions for KPIs, CWE distributions, and trend data.

#### [NEW] `src-tauri/src/db/projects_repo.rs`
- Database interactions for watched projects and directory file hashes.

#### [NEW] `src-tauri/src/services/`
- Introduce a service layer (e.g., `analysis_service.rs`, `monitor_service.rs`) to orchestrate DB calls, parser invocations, and ML API interactions. 
- Uses `anyhow` for context-rich error propagation.
- `commands.rs` will simply parse Tauri inputs, call services, map `anyhow::Error` to the serialized `AppError`, and return mapped IPC results.

#### [MODIFY] `src-tauri/src/ml_api.rs` -> `src-tauri/src/inference/`
- Move ML logic into an `inference` module.
- Define the `InferenceProvider` trait.
- Implement `KaggleProvider` and `MockProvider` matching the trait.
- Implement high-concurrency execution using `tokio::task::JoinSet` and `tokio::sync::Semaphore` to dispatch multiple AST slices to the active `InferenceProvider` simultaneously while respecting rate limits.

#### [MODIFY] `src-tauri/src/error.rs`
- Define the unified `AppError` enum that implements `Serialize` for Tauri IPC.
- Implement `From<anyhow::Error>` for `AppError` to gracefully convert edge failures into frontend-consumable messages.

## Verification Plan

### Automated Tests
- Run `cargo test` across backend repositories and services to ensure database queries and ML mocking remain intact.
- Run `npm run check` to verify strict TypeScript adherence and Svelte 5 rune reactivity across the new frontend architecture.

### Manual Verification
- Run a full C++ project scan through the refactored architecture to verify the concurrent inference pipeline drastically reduces scan times.
- Validate that PDF reports, dashboard graphs, and the history view reflect accurate data using the refactored database repositories.
- Confirm the premium UI aesthetic is perfectly preserved while utilizing the new Bits UI-backed component system.
