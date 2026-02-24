<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";
  import { Chart, registerables } from "chart.js";
  import { theme } from "$lib/theme";

  Chart.register(...registerables);

  let stats: any = null;
  let trendData: any[] = [];
  let loading = true;
  let error = "";

  // ── Count-up ──────────────────────────────────────────
  let displayKpis = {
    total_analyses: 0,
    total_functions: 0,
    total_vulnerable: 0,
    total_safe: 0,
  };

  function animateCountUp(targets: any, duration = 1200) {
    const start = performance.now();
    const keys = Object.keys(targets);
    function frame(now: number) {
      const t = Math.min((now - start) / duration, 1);
      const ease = 1 - Math.pow(1 - t, 4);
      keys.forEach((k) => {
        displayKpis[k] = Math.round((targets[k] ?? 0) * ease);
      });
      displayKpis = displayKpis;
      if (t < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  // ── Chart instances (must destroy before recreating) ──
  let cweChart: Chart | null = null;
  let severityChart: Chart | null = null;
  let fileChart: Chart | null = null;
  let trendChart: Chart | null = null;

  let cweCanvas: HTMLCanvasElement;
  let severityCanvas: HTMLCanvasElement;
  let fileCanvas: HTMLCanvasElement;
  let trendCanvas: HTMLCanvasElement;

  const SEVERITY_COLORS: Record<string, string> = {
    Critical: "#ef4444",
    High: "#f97316",
    Medium: "#eab308",
    Low: "#3b82f6",
  };

  // ── File chart dropdown ───────────────────────────────
  let allAnalyses: { id: number; label: string }[] = [];
  let selectedAnalysis: "all" | number = "all";
  let selectedFileRatios: any[] = [];

  // Guard: only fires after stats is loaded
  $: if (stats && !loading) handleSelectionChange(selectedAnalysis);

  async function handleSelectionChange(selection: "all" | number) {
    if (!stats) return;
    if (selection === "all") {
      selectedFileRatios = [...stats.file_ratios]
        .sort((a, b) => b.vuln - a.vuln)
        .slice(0, 10);
    } else {
      try {
        const raw = await invoke<string>("get_report", {
          analysisId: selection,
        });
        const report = JSON.parse(raw);
        selectedFileRatios = (report.files ?? [])
          .map((f: any) => {
            const vuln = f.functions.filter(
              (fn: any) => fn.verdict === "vulnerable",
            ).length;
            const safe = f.functions.length - vuln;
            return {
              label: f.file_path.replace(/\\/g, "/").split("/").pop(),
              safe,
              vuln,
            };
          })
          .sort((a: any, b: any) => b.vuln - a.vuln)
          .slice(0, 10);
      } catch (e) {
        console.error("Failed to load file ratios for selection", e);
        selectedFileRatios = [];
      }
    }
    drawFiles(); // safe — guard ensures stats exists
  }

  onMount(async () => {
    try {
      // ONE spawn instead of two — get_statistics returns dashboard + trend together
      const raw = await invoke<string>("get_statistics");
      const data = JSON.parse(raw);

      if (data.error) {
        error = data.error;
        loading = false;
        return;
      }

      stats = data.dashboard;
      trendData = data.trend ?? [];

      // Populate dropdown from recent_analyses (no extra invoke needed)
      allAnalyses = (stats.recent_analyses ?? []).map((a: any) => ({
        id: a.id,
        label: `${a.project_name} (${a.timestamp})`,
      }));

      selectedFileRatios = [...stats.file_ratios]
        .sort((a: any, b: any) => b.vuln - a.vuln)
        .slice(0, 10);

      loading = false;
      setTimeout(() => {
        drawCharts();
        animateCountUp(stats.kpis);
      }, 50);
    } catch (err) {
      error = `Failed to load statistics: ${err}`;
      loading = false;
    }
  });

  function tc(dark: string, light: string) {
    return $theme === "dark" ? dark : light;
  }

  function drawCharts() {
    drawCWE();
    drawSeverity();
    drawFiles();
    drawTrend();
  }

  function drawCWE() {
    if (!cweCanvas || !stats?.cwe_counts?.length) return;
    if (cweChart) {
      cweChart.destroy();
      cweChart = null;
    }
    cweChart = new Chart(cweCanvas, {
      type: "bar",
      data: {
        labels: stats.cwe_counts.map((c: any) => `${c.cwe} — ${c.cwe_name}`),
        datasets: [
          {
            label: "Occurrences",
            data: stats.cwe_counts.map((c: any) => c.count),
            backgroundColor: stats.cwe_counts.map(
              (c: any) => SEVERITY_COLORS[c.severity] ?? "#6b7280",
            ),
            borderRadius: 4,
          },
        ],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: {
            ticks: { color: tc("#9ca3af", "#6b7280") },
            grid: { color: tc("#1f2937", "#e5e7eb") },
          },
          y: {
            ticks: { color: tc("#d1d5db", "#374151") },
            grid: { display: false },
          },
        },
      },
    });
  }

  function drawSeverity() {
    if (!severityCanvas || !stats?.severity_counts?.length) return;
    if (severityChart) {
      severityChart.destroy();
      severityChart = null;
    }
    const labels = stats.severity_counts.map((s: any) => s.severity);
    const data = stats.severity_counts.map((s: any) => s.count);
    severityChart = new Chart(severityCanvas, {
      type: "doughnut",
      data: {
        labels,
        datasets: [
          {
            data,
            backgroundColor: labels.map(
              (l: string) => SEVERITY_COLORS[l] ?? "#6b7280",
            ),
            borderWidth: 0,
          },
        ],
      },
      options: {
        responsive: true,
        cutout: "70%",
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: tc("#9ca3af", "#6b7280"), padding: 16 },
          },
        },
      },
    });
  }

  function drawFiles() {
    if (!fileCanvas) return;
    // CRITICAL: always destroy before recreating
    if (fileChart) {
      fileChart.destroy();
      fileChart = null;
    }
    if (!selectedFileRatios.length) return;
    fileChart = new Chart(fileCanvas, {
      type: "bar",
      data: {
        labels: selectedFileRatios.map((f: any) => f.label),
        datasets: [
          {
            label: "Safe",
            data: selectedFileRatios.map((f: any) => f.safe),
            backgroundColor: "#22c55e",
            borderRadius: 4,
          },
          {
            label: "Vulnerable",
            data: selectedFileRatios.map((f: any) => f.vuln),
            backgroundColor: "#ef4444",
            borderRadius: 4,
          },
        ],
      },
      options: {
        responsive: true,
        scales: {
          x: {
            stacked: true,
            ticks: { color: tc("#9ca3af", "#6b7280") },
            grid: { display: false },
          },
          y: {
            stacked: true,
            ticks: { color: tc("#9ca3af", "#6b7280") },
            grid: { color: tc("#1f2937", "#e5e7eb") },
          },
        },
        plugins: { legend: { labels: { color: tc("#9ca3af", "#6b7280") } } },
      },
    });
  }

  function drawTrend() {
    if (!trendCanvas || !trendData.length) return;
    if (trendChart) {
      trendChart.destroy();
      trendChart = null;
    }
    trendChart = new Chart(trendCanvas, {
      type: "line",
      data: {
        labels: trendData.map(
          (d: any) => d.timestamp.split(" ")[0] || d.timestamp,
        ),
        datasets: [
          {
            label: "Vulnerable Functions",
            data: trendData.map((d: any) => d.vuln_count),
            borderColor: "#ff9f8a",
            backgroundColor: "rgba(255,159,138,0.15)",
            fill: true,
            tension: 0.3,
            borderWidth: 2,
            pointBackgroundColor: "#ff839b",
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: { label: (ctx: any) => `${ctx.raw} vulnerable` },
          },
        },
        scales: {
          x: {
            ticks: { color: tc("#9ca3af", "#6b7280") },
            grid: { display: false },
          },
          y: {
            ticks: { color: tc("#d1d5db", "#374151") },
            grid: { color: tc("#1f2937", "#e5e7eb") },
            beginAtZero: true,
          },
        },
      },
    });
  }
</script>

<div
  class="min-h-screen px-6 py-8"
  style="background:var(--bg);color:var(--text)"
>
  <div class="max-w-7xl mx-auto">
    <div class="mb-6">
      <h1 class="text-lg font-semibold">Statistics</h1>
      <p class="text-xs mt-0.5" style="color:var(--muted)">
        Aggregate stats across all analyses
      </p>
    </div>

    {#if loading}
      <div class="grid grid-cols-4 gap-3 mb-4">
        {#each Array(4) as _}
          <div class="card p-5">
            <div class="skeleton h-3 w-24 mb-3"></div>
            <div class="skeleton h-8 w-16"></div>
          </div>
        {/each}
      </div>
      <div class="grid grid-cols-3 gap-3 mb-3">
        <div class="card col-span-2 p-5">
          <div class="skeleton h-3 w-40 mb-4"></div>
          <div class="skeleton h-48"></div>
        </div>
        <div class="card p-5">
          <div class="skeleton h-3 w-32 mb-4"></div>
          <div class="skeleton h-48 rounded-full mx-auto w-48"></div>
        </div>
      </div>
      <div class="grid grid-cols-2 gap-3 mb-3">
        <div class="card p-5">
          <div class="skeleton h-3 w-40 mb-4"></div>
          <div class="skeleton h-48"></div>
        </div>
        <div class="card p-5">
          <div class="skeleton h-3 w-40 mb-4"></div>
          <div class="skeleton h-48"></div>
        </div>
      </div>
    {:else if error}
      <p class="text-sm" style="color:var(--danger)">{error}</p>
    {:else}
      <!-- KPI Row -->
      <div class="grid grid-cols-4 gap-3 mb-4">
        {#each [{ label: "Analyses Run", value: displayKpis.total_analyses, color: "var(--accent)" }, { label: "Functions Scanned", value: displayKpis.total_functions, color: "#818cf8" }, { label: "Vulnerable", value: displayKpis.total_vulnerable, color: "var(--danger)" }, { label: "Clean", value: displayKpis.total_safe, color: "var(--success)" }] as kpi}
          <div class="card p-5">
            <p
              class="text-xs uppercase tracking-wider mb-2"
              style="color:var(--muted)"
            >
              {kpi.label}
            </p>
            <p
              class="text-3xl font-bold tabular-nums"
              style="color:{kpi.color}"
            >
              {kpi.value}
            </p>
          </div>
        {/each}
      </div>

      <!-- CWE + Severity -->
      <div class="grid grid-cols-3 gap-3 mb-3">
        <div class="card col-span-2 p-5">
          <p class="text-xs font-semibold mb-4" style="color:var(--text)">
            Vulnerability Breakdown by CWE
          </p>
          {#if stats.cwe_counts.length}
            <canvas bind:this={cweCanvas}></canvas>
          {:else}
            <p class="text-xs text-center py-8" style="color:var(--muted)">
              No vulnerable functions yet.
            </p>
          {/if}
        </div>
        <div class="card p-5 flex flex-col">
          <p class="text-xs font-semibold mb-4" style="color:var(--text)">
            Severity Distribution
          </p>
          {#if stats.severity_counts.length}
            <div class="relative flex-1 flex items-center justify-center">
              <canvas bind:this={severityCanvas}></canvas>
              <div
                class="absolute inset-0 flex items-center justify-center pointer-events-none"
              >
                <div class="text-center">
                  <p class="text-2xl font-bold">
                    {stats.kpis.total_vulnerable ?? 0}
                  </p>
                  <p class="text-xs" style="color:var(--muted)">vulnerable</p>
                </div>
              </div>
            </div>
          {:else}
            <p class="text-xs text-center py-8" style="color:var(--muted)">
              No data yet.
            </p>
          {/if}
        </div>
      </div>

      <!-- Files + Trend -->
      <div class="grid grid-cols-2 gap-3 mb-3">
        <div class="card p-5">
          <div class="flex items-center justify-between mb-4">
            <p class="text-xs font-semibold" style="color:var(--text)">
              Vulnerable vs Safe per File
            </p>
            <select
              bind:value={selectedAnalysis}
              class="text-xs rounded-lg px-2 py-1.5 outline-none cursor-pointer"
              style="background:var(--surface-2);border:1px solid var(--border);color:var(--text)"
            >
              <option value="all">All Analyses</option>
              {#each allAnalyses as a}
                <option value={a.id}>{a.label}</option>
              {/each}
            </select>
          </div>
          {#if selectedFileRatios.length}
            <canvas bind:this={fileCanvas}></canvas>
          {:else}
            <p class="text-xs text-center py-8" style="color:var(--muted)">
              No files scanned yet.
            </p>
          {/if}
        </div>

        <div class="card p-5">
          <p class="text-xs font-semibold mb-1" style="color:var(--text)">
            Vulnerability Trend Over Time
          </p>
          <p class="text-xs mb-4" style="color:var(--muted)">
            Vulnerable functions per analysis
          </p>
          {#if trendData.length > 0}
            <div class="h-64 relative">
              <canvas bind:this={trendCanvas} class="w-full h-full"></canvas>
            </div>
          {:else}
            <p class="text-xs text-center py-8" style="color:var(--muted)">
              Not enough analyses yet.
            </p>
          {/if}
        </div>
      </div>

      <!-- Recent Analyses -->
      <div class="card overflow-hidden mb-3">
        <div class="px-5 py-3.5" style="border-bottom:1px solid var(--border)">
          <p class="text-xs font-semibold" style="color:var(--text)">
            Recent Analyses
          </p>
        </div>
        <table class="w-full">
          <thead>
            <tr style="border-bottom:1px solid var(--border)">
              {#each ["Project", "Date", "Functions", "Vulnerable", ""] as h}
                <th
                  class="text-left px-5 py-2.5 text-xs uppercase tracking-wider"
                  style="color:var(--muted)">{h}</th
                >
              {/each}
            </tr>
          </thead>
          <tbody>
            {#each stats.recent_analyses as item}
              <tr
                class="transition-colors"
                style="border-bottom:1px solid var(--border)"
                onmouseenter={(e) =>
                  (e.currentTarget.style.background = "var(--surface-2)")}
                onmouseleave={(e) =>
                  (e.currentTarget.style.background = "transparent")}
              >
                <td class="px-5 py-3 text-xs mono">{item.project_name}</td>
                <td class="px-5 py-3 text-xs" style="color:var(--muted)"
                  >{item.timestamp}</td
                >
                <td class="px-5 py-3 text-xs" style="color:var(--muted)"
                  >{item.total_functions ?? 0}</td
                >
                <td class="px-5 py-3">
                  <span
                    class="text-xs font-semibold"
                    style="color:{(item.vuln_count ?? 0) > 0
                      ? 'var(--danger)'
                      : 'var(--success)'}"
                  >
                    {(item.vuln_count ?? 0) > 0
                      ? `${item.vuln_count} found`
                      : "Clean"}
                  </span>
                </td>
                <td class="px-5 py-3 text-right">
                  <a
                    href="/report/{item.id}"
                    class="text-xs"
                    style="color:var(--accent)">View →</a
                  >
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
</div>
