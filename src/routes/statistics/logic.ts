import { invoke } from "@tauri-apps/api/core";
import { writable } from "svelte/store";

/* ═══════════════════════════════════════════════════════
   CORE STATE REGISTRY
   ═══════════════════════════════════════════════════════ */

/** Aggregate dashboard statistics from Tauri backend */
export const stats = writable<any>(null);

/** Temporal vulnerability trend dataset */
export const trendData = writable<any[]>([]);

/** Global loading semaphore */
export const loading = writable(true);

/** Error propagation channel */
export const error = writable("");

/** Available analysis instances for drill-down */
export const allAnalyses = writable<{ id: number; label: string }[]>([]);

/** File-level vulnerability ratios (safe vs. vulnerable) */
export const selectedFileRatios = writable<any[]>([]);

/** Animated KPI display values (interpolated during count-up) */
export const displayKpis = writable({
  total_analyses: 0,
  total_functions: 0,
  total_vulnerable: 0,
  total_safe: 0,
});

type FileRatio = {
  label: string;
  safe: number;
  vuln: number;
};

type AnalysisFileRatios = {
  analysis_id: number;
  file_ratios: FileRatio[];
};

const fileRatioCache = new Map<number, FileRatio[]>();
let latestFileRatioRequest = 0;

function topFileRatios(fileRatios: FileRatio[]): FileRatio[] {
  return [...fileRatios].sort((a, b) => b.vuln - a.vuln).slice(0, 10);
}

function normalizeSelection(selection: "all" | number | string): "all" | number {
  if (selection === "all") {
    return "all";
  }

  return Number(selection);
}

/* ═══════════════════════════════════════════════════════
   DESIGN SYSTEM CONSTANTS
   ═══════════════════════════════════════════════════════ */

/** Severity-to-color mapping for consistent visualization */
export const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#ef4444",  // Red-500
  High: "#f97316",      // Orange-500
  Medium: "#eab308",     // Yellow-500
  Low: "#3b82f6",        // Blue-500
};

/* ═══════════════════════════════════════════════════════
   ANIMATION ENGINE
   ═══════════════════════════════════════════════════════ */

/**
 * Eased count-up animation for KPI values.
 * Uses quartic ease-out for cinematic deceleration.
 */
export function animateCountUp(targets: any, duration = 1200) {
  const start = performance.now();
  const keys = Object.keys(targets) as (
    | "total_analyses"
    | "total_functions"
    | "total_vulnerable"
    | "total_safe"
  )[];

  function frame(now: number) {
    const t = Math.min((now - start) / duration, 1);
    // Quartic ease-out: smooth deceleration
    const ease = 1 - Math.pow(1 - t, 4);

    displayKpis.update((current) => {
      const next = { ...current };
      keys.forEach((k) => {
        (next as any)[k] = Math.round((targets[k] ?? 0) * ease);
      });
      return next;
    });

    if (t < 1) requestAnimationFrame(frame);
  }

  requestAnimationFrame(frame);
}

/* ═══════════════════════════════════════════════════════
   DATA FETCHING LAYER
   ═══════════════════════════════════════════════════════ */

/**
 * Fetches comprehensive statistics from the Tauri backend.
 * Hydrates all dashboard stores with aggregated data.
 */
export async function loadStatistics() {
  loading.set(true);
  error.set("");

  try {
    const data = await invoke<any>("get_statistics");

    if (data.error) {
      error.set(data.error);
      loading.set(false);
      return;
    }

    stats.set(data.dashboard);
    trendData.set(data.trend ?? []);
    selectedFileRatios.set(topFileRatios(data.dashboard.file_ratios ?? []));

    for (const analysis of data.dashboard.analysis_file_ratios ?? []) {
      const item = analysis as AnalysisFileRatios;
      fileRatioCache.set(item.analysis_id, topFileRatios(item.file_ratios));
    }

    // Build analysis selector options from recent analyses
    allAnalyses.set(
      (data.dashboard.recent_analyses ?? []).map((a: any) => ({
        id: a.id,
        label: `${a.project_name} (${a.timestamp})`,
      }))
    );

    loading.set(false);
  } catch (err) {
    error.set(`Failed to load statistics: ${err}`);
    loading.set(false);
  }
}

/* ═══════════════════════════════════════════════════════
   INTERACTIVE DRILL-DOWN HANDLER
   ═══════════════════════════════════════════════════════ */

/**
 * Handles analysis selection changes for the attack surface view.
 * Supports "all" (aggregated) or specific analysis ID drill-down.
 */
export async function handleSelectionChange(
  selection: "all" | number | string,
  currentStats: any
) {
  if (!currentStats) return;

  const normalizedSelection = normalizeSelection(selection);

  if (normalizedSelection === "all") {
    latestFileRatioRequest++;
    // Aggregate view: top 10 most vulnerable files across all analyses
    selectedFileRatios.set(topFileRatios(currentStats.file_ratios ?? []));
  } else {
    const cachedRatios = fileRatioCache.get(normalizedSelection);
    if (cachedRatios !== undefined) {
      selectedFileRatios.set(cachedRatios);
      return;
    }

    const requestId = ++latestFileRatioRequest;

    try {
      const ratios = await invoke<any[]>("get_analysis_file_ratios", {
        analysisId: normalizedSelection,
      });

      const sortedRatios = topFileRatios(ratios);
      fileRatioCache.set(normalizedSelection, sortedRatios);

      if (requestId === latestFileRatioRequest) {
        selectedFileRatios.set(sortedRatios);
      }
    } catch (e) {
      console.error("Failed to load file ratios for selection", e);
      if (requestId === latestFileRatioRequest) {
        selectedFileRatios.set([]);
      }
    }
  }
}
