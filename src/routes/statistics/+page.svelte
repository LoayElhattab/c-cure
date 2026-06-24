<script lang="ts">
  import { onMount, tick } from "svelte";
  import { Chart, registerables } from "chart.js";
  import { theme } from "$lib/types/theme";
  import {
    stats,
    trendData,
    loading,
    error,
    displayKpis,
    allAnalyses,
    selectedFileRatios,
    SEVERITY_COLORS,
    animateCountUp,
    loadStatistics,
    handleSelectionChange,
  } from "./logic";

  Chart.register(...registerables);

  /* ═══════════════════════════════════════════
     CHART REGISTRY & CANVAS BINDINGS
     ═══════════════════════════════════════════ */
  let cweChart: Chart | null = null;
  let severityChart: Chart | null = null;
  let trendChart: Chart | null = null;
  let radarChart: Chart | null = null;

  let cweCanvas: HTMLCanvasElement;
  let severityCanvas: HTMLCanvasElement;
  let trendCanvas: HTMLCanvasElement;
  let radarCanvas: HTMLCanvasElement;

  /* ═══════════════════════════════════════════
     INTERACTIVE STATE MACHINES
     ═══════════════════════════════════════════ */
  let selectedAnalysis: "all" | number = "all";
  let hoveredInsight: number | null = null;
  let activeKpiIndex: number = 0;
  let pageVisible = false;
  let chartsReady = false;
  let lastHandledSelection: "all" | number | null = null;

  /* ═══════════════════════════════════════════
     DERIVED THREAT INTELLIGENCE
     ═══════════════════════════════════════════ */
  $: severityMap = Object.fromEntries(
    ($stats?.severity_counts ?? []).map((s: any) => [s.severity, s.count])
  );

  $: criticalCount = severityMap["Critical"] ?? 0;
  $: highCount = severityMap["High"] ?? 0;
  $: mediumCount = severityMap["Medium"] ?? 0;
  $: lowCount = severityMap["Low"] ?? 0;

  $: totalFunctions = $stats?.kpis?.total_functions ?? 0;
  $: totalSafe = $stats?.kpis?.total_safe ?? 0;
  $: totalVulnerable = $stats?.kpis?.total_vulnerable ?? 0;

  /* ── Composite Risk Scoring Engine ── */
  $: rawRisk = criticalCount * 10 + highCount * 6 + mediumCount * 3 + lowCount;
  $: riskScore = totalFunctions > 0
    ? Math.min(100, Math.round((rawRisk / totalFunctions) * 100))
    : 0;

  $: securityHealth = totalFunctions > 0
    ? ((totalSafe / totalFunctions) * 100).toFixed(1)
    : "0.0";

  $: vulnerabilityDensity = totalFunctions > 0
    ? ((totalVulnerable / totalFunctions) * 100).toFixed(1)
    : "0.0";

  $: riskLabel = riskScore >= 75 ? "CRITICAL"
    : riskScore >= 50 ? "HIGH"
    : riskScore >= 25 ? "ELEVATED"
    : "LOW";

  $: riskColor = riskScore >= 75 ? "#ef4444"
    : riskScore >= 50 ? "#f97316"
    : riskScore >= 25 ? "#eab308"
    : "#22c55e";

  $: riskGradient = riskScore >= 75
    ? "from-red-500/20 via-red-600/10 to-transparent"
    : riskScore >= 50
      ? "from-orange-500/20 via-orange-600/10 to-transparent"
      : riskScore >= 25
        ? "from-yellow-500/20 via-yellow-600/10 to-transparent"
        : "from-emerald-500/20 via-emerald-600/10 to-transparent";

  /* ── Threat Topology Analysis ── */
  $: topCwe = $stats?.cwe_counts?.[0];
  $: topCwePercentage = topCwe && totalVulnerable > 0
    ? Math.round((topCwe.count / totalVulnerable) * 100)
    : 0;

  $: mostAffectedFile = [...($selectedFileRatios ?? [])]
    .sort((a, b) => b.vuln - a.vuln)[0];

  $: topFilesContribution = totalVulnerable > 0
    ? Math.round(
        ($selectedFileRatios
          .slice(0, 3)
          .reduce((sum, file) => sum + file.vuln, 0) / totalVulnerable) * 100
      )
    : 0;

  $: dominantSeverity = [...($stats?.severity_counts ?? [])]
    .sort((a, b) => b.count - a.count)[0]?.severity ?? null;

  /* ── Auto-Generated Threat Intelligence ── */
  $: insights = (() => {
    const generated: Array<{ text: string; severity: "info" | "warning" | "critical"; icon: string }> = [];
    
    if (topCwe) {
      generated.push({
        text: `${topCwe.cwe} dominates the threat landscape, accounting for ${topCwePercentage}% of all detected vulnerabilities.`,
        severity: topCwePercentage > 40 ? "critical" : "warning",
        icon: "◈"
      });
    }

    if (dominantSeverity) {
      generated.push({
        text: `${dominantSeverity}-severity findings represent the primary attack vector in the current codebase assessment.`,
        severity: ["Critical", "High"].includes(dominantSeverity) ? "critical" : "warning",
        icon: "▲"
      });
    }

    if (mostAffectedFile?.vuln > 0) {
      generated.push({
        text: `${mostAffectedFile.label} is the primary attack surface with ${mostAffectedFile.vuln} confirmed vulnerabilities.`,
        severity: mostAffectedFile.vuln > 5 ? "critical" : "warning",
        icon: "◎"
      });
    }

    if (topFilesContribution > 0) {
      generated.push({
        text: `The top 3 affected files concentrate ${topFilesContribution}% of total vulnerabilities — prioritize remediation.`,
        severity: topFilesContribution > 60 ? "critical" : "info",
        icon: "◉"
      });
    }

    const healthNum = +securityHealth;
    if (healthNum >= 95) {
      generated.push({
        text: "Aggregate security posture is exemplary. Maintain current defensive standards.",
        severity: "info",
        icon: "✓"
      });
    } else if (healthNum >= 85) {
      generated.push({
        text: "Security posture is stable with isolated remediation opportunities identified.",
        severity: "info",
        icon: "◐"
      });
    } else if (healthNum >= 70) {
      generated.push({
        text: "Moderate risk concentration detected. Targeted intervention recommended.",
        severity: "warning",
        icon: "◑"
      });
    } else {
      generated.push({
        text: "Critical vulnerability density requires immediate comprehensive security review.",
        severity: "critical",
        icon: "◈"
      });
    }

    return generated;
  })();

  /* ── Temporal Vulnerability Analysis ── */
  $: riskTrendData = $trendData.map((d: any) => ({
    ...d,
    vulnerabilityRate: d.total_functions > 0
      ? Number(((d.vuln_count / d.total_functions) * 100).toFixed(2))
      : 0,
    securityHealth: d.total_functions > 0
      ? Number((((d.total_functions - d.vuln_count) / d.total_functions) * 100).toFixed(2))
      : 0,
  }));

  $: affectedFiles = [...($selectedFileRatios ?? [])]
    .sort((a, b) => b.vuln - a.vuln)
    .slice(0, 10);

  $: maxFileVulns = Math.max(...affectedFiles.map((f) => f.vuln), 1);

  /* ── Radar Chart Data: Security Dimensions ── */
  $: radarData = $stats ? {
    labels: ["Input Validation", "Memory Safety", "Auth/Session", "Crypto", "Error Handling", "Logging"],
    datasets: [{
      label: "Current Posture",
      data: [
        Math.max(20, 100 - (severityMap["Critical"] * 15)),
        Math.max(20, 100 - (criticalCount * 10)),
        Math.max(20, 100 - (highCount * 8)),
        Math.max(20, 100 - (mediumCount * 5)),
        Math.max(20, 100 - (lowCount * 2)),
        +securityHealth * 0.9,
      ],
      backgroundColor: "rgba(239, 68, 68, 0.15)",
      borderColor: riskColor,
      pointBackgroundColor: riskColor,
      pointBorderColor: "#fff",
      pointHoverBackgroundColor: "#fff",
      pointHoverBorderColor: riskColor,
    }]
  } : null;

  /* ═══════════════════════════════════════════
     THEME ADAPTER
     ═══════════════════════════════════════════ */
  function tc(dark: string, light: string) {
    return $theme === "dark" ? dark : light;
  }

  function parseAnalysisSelection(value: string): "all" | number {
    return value === "all" ? "all" : Number(value);
  }

  function handleAnalysisSelect(event: Event) {
    if (!(event.currentTarget instanceof HTMLSelectElement)) {
      return;
    }

    selectedAnalysis = parseAnalysisSelection(event.currentTarget.value);
  }

  /* ═══════════════════════════════════════════
     LIFECYCLE & ANIMATION ORCHESTRATION
     ═══════════════════════════════════════════ */
  onMount(async () => {
    await loadStatistics();
    if (!$error) {
      pageVisible = true;
      await tick();
      setTimeout(() => {
        chartsReady = true;
        drawCharts();
        if ($stats?.kpis) animateCountUp($stats.kpis);
      }, 150);
    }
  });

  /* ═══════════════════════════════════════════
     CHART RENDERING ENGINE
     ═══════════════════════════════════════════ */
  function drawCharts() {
    drawCWE();
    drawSeverity();
    drawTrend();
    drawRadar();
  }

  function drawCWE() {
    if (!cweCanvas || !$stats?.cwe_counts?.length) return;
    if (cweChart) { cweChart.destroy(); cweChart = null; }

    cweChart = new Chart(cweCanvas, {
      type: "bar",
      data: {
        labels: $stats.cwe_counts.map((c: any) => `${c.cwe}`),
        datasets: [{
          label: "Occurrences",
          data: $stats.cwe_counts.map((c: any) => c.count),
          backgroundColor: $stats.cwe_counts.map(
            (c: any) => SEVERITY_COLORS[c.severity] ?? "#6b7280"
          ),
          borderRadius: 4,
          borderSkipped: false,
          barThickness: 22,
        }],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 1000, easing: "easeOutQuart" },
        layout: { padding: { top: 4, right: 8, bottom: 0, left: 0 } },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: tc("rgba(17,24,39,0.95)", "rgba(255,255,255,0.95)"),
            titleColor: tc("#e5e7eb", "#1f2937"),
            bodyColor: tc("#d1d5db", "#4b5563"),
            borderColor: tc("#374151", "#e5e7eb"),
            borderWidth: 1,
            padding: 12,
            callbacks: {
              title: (items: any) => {
                const idx = items[0].dataIndex;
                const cwe = $stats.cwe_counts[idx];
                return `${cwe.cwe} — ${cwe.cwe_name}`;
              },
              label: (ctx: any) => ` ${ctx.raw} occurrences`
            }
          }
        },
        scales: {
          x: {
            ticks: { color: tc("#9ca3af", "#6b7280"), font: { family: "monospace", size: 11 } },
            grid: { color: tc("rgba(31,41,55,0.5)", "rgba(229,231,235,0.5)") },
            border: { display: false },
          },
          y: {
            ticks: { 
              color: tc("#d1d5db", "#374151"), 
              font: { family: "monospace", size: 11, weight: "bold" } 
            },
            grid: { display: false },
            border: { display: false },
          },
        },
      },
    });
  }

  function drawSeverity() {
    if (!severityCanvas || !$stats?.severity_counts?.length) return;
    if (severityChart) { severityChart.destroy(); severityChart = null; }

    const labels = $stats.severity_counts.map((s: any) => s.severity);
    const data = $stats.severity_counts.map((s: any) => s.count);

    severityChart = new Chart(severityCanvas, {
      type: "doughnut",
      data: {
        labels,
        datasets: [{
          data,
          backgroundColor: labels.map((l: string) => SEVERITY_COLORS[l] ?? "#6b7280"),
          borderColor: tc("#111217", "#ffffff"),
          borderWidth: 3,
          borderRadius: 5,
          spacing: 2,
          hoverOffset: 10,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        animation: { animateScale: true, animateRotate: true, duration: 1200 },
        plugins: {
          legend: {
            display: false,
          },
          tooltip: {
            backgroundColor: tc("rgba(17,24,39,0.95)", "rgba(255,255,255,0.95)"),
            callbacks: {
              label: (ctx: any) => ` ${ctx.label}: ${ctx.raw} (${((ctx.raw / totalVulnerable) * 100).toFixed(1)}%)`
            }
          }
        },
      },
    });
  }

  function drawTrend() {
    if (!trendCanvas || !$trendData.length) return;
    if (trendChart) { trendChart.destroy(); trendChart = null; }

    trendChart = new Chart(trendCanvas, {
      type: "line",
      data: {
        labels: $trendData.map((d: any) => d.timestamp.split(" ")[0] || d.timestamp),
        datasets: [
          {
            label: "Vulnerability Rate (%)",
            data: riskTrendData.map((d: any) => d.vulnerabilityRate),
            borderColor: "#FF8C7A",
            backgroundColor: (ctx: any) => {
              const canvas = ctx.chart.ctx;
              const gradient = canvas.createLinearGradient(0, 0, 0, 300);
              gradient.addColorStop(0, "rgba(255,140,122,0.25)");
              gradient.addColorStop(1, "rgba(255,140,122,0.0)");
              return gradient;
            },
            fill: true,
            tension: 0.4,
            borderWidth: 2.5,
            pointBackgroundColor: "#FF849C",
            pointBorderColor: tc("#111827", "#ffffff"),
            pointBorderWidth: 2,
            pointRadius: 4,
            pointHoverRadius: 7,
          },
          {
            label: "Security Health (%)",
            data: riskTrendData.map((d: any) => d.securityHealth),
            borderColor: "#22c55e",
            backgroundColor: "transparent",
            borderDash: [5, 5],
            tension: 0.4,
            borderWidth: 1.5,
            pointRadius: 0,
            pointHoverRadius: 5,
          }
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        layout: { padding: { top: 2, right: 10, bottom: 0, left: 0 } },
        plugins: {
          legend: { 
            display: true,
            position: "top",
            align: "end",
            labels: {
              color: tc("#9ca3af", "#6b7280"),
              font: { family: "monospace", size: 10 },
              boxWidth: 10,
              boxHeight: 6,
              padding: 8,
            }
          },
          tooltip: {
            backgroundColor: tc("rgba(17,24,39,0.95)", "rgba(255,255,255,0.95)"),
            titleColor: tc("#e5e7eb", "#1f2937"),
            bodyColor: tc("#d1d5db", "#4b5563"),
            borderColor: tc("#374151", "#e5e7eb"),
            borderWidth: 1,
            padding: 12,
          },
        },
        scales: {
          x: {
            ticks: { color: tc("#9ca3af", "#6b7280"), font: { family: "monospace", size: 10 } },
            grid: { display: false },
            border: { display: false },
          },
          y: {
            ticks: { color: tc("#9ca3af", "#6b7280"), font: { family: "monospace", size: 10 } },
            grid: { color: tc("rgba(31,41,55,0.3)", "rgba(229,231,235,0.3)") },
            border: { display: false },
            beginAtZero: true,
            max: 100,
          },
        },
      },
    });
  }

  function drawRadar() {
    if (!radarCanvas || !radarData) return;
    if (radarChart) { radarChart.destroy(); radarChart = null; }

    radarChart = new Chart(radarCanvas, {
      type: "radar",
      data: radarData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            angleLines: { color: tc("rgba(75,85,99,0.3)", "rgba(156,163,175,0.3)") },
            grid: { color: tc("rgba(75,85,99,0.2)", "rgba(156,163,175,0.2)") },
            pointLabels: { 
              color: tc("#d1d5db", "#4b5563"), 
              font: { family: "monospace", size: 10 } 
            },
            ticks: { display: false, backdropColor: "transparent" },
            suggestedMin: 0,
            suggestedMax: 100,
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: tc("rgba(17,24,39,0.95)", "rgba(255,255,255,0.95)"),
            callbacks: {
              label: (ctx: any) => ` ${ctx.label}: ${ctx.raw.toFixed(1)}% strength`
            }
          }
        },
      },
    });
  }

  /* ── Attack Surface Selection Updates ── */
  $: if ($stats && !$loading && chartsReady && selectedAnalysis !== lastHandledSelection) {
    lastHandledSelection = selectedAnalysis;
    handleSelectionChange(selectedAnalysis, $stats);
  }

  /* ── KPI Carousel Auto-Rotation ── */
  let kpiInterval: ReturnType<typeof setInterval>;
  onMount(() => {
    kpiInterval = setInterval(() => {
      activeKpiIndex = (activeKpiIndex + 1) % 5;
    }, 4000);
    return () => clearInterval(kpiInterval);
  });

  /* ═══════════════════════════════════════════
     UTILITY FUNCTIONS
     ═══════════════════════════════════════════ */
  function getInsightBorderColor(severity: string) {
    if (severity === "critical") return "var(--danger)";
    if (severity === "warning") return "var(--warning, #f59e0b)";
    return "var(--success)";
  }

  function getInsightGlow(severity: string) {
    if (severity === "critical") return "0 0 20px rgba(239,68,68,0.15)";
    if (severity === "warning") return "0 0 20px rgba(245,158,11,0.1)";
    return "0 0 20px rgba(34,197,94,0.1)";
  }
</script>

<!-- ═══════════════════════════════════════════════════════
     CINEMATIC STATISTICS DASHBOARD — C-CURE v2.0
     ═══════════════════════════════════════════════════════ -->

<div
  class="min-h-screen relative overflow-hidden"
  style="background: var(--bg); color: var(--text);"
  class:opacity-0={!pageVisible}
  class:opacity-100={pageVisible}
  style:transition="opacity 0.8s cubic-bezier(0.4, 0, 0.2, 1)"
>
  <div class="relative z-10 max-w-[1360px] mx-auto px-4 py-5 font-mono">
    
    <!-- ═══════════════════════════════════════════
         HEADER: THREAT INTELLIGENCE BANNER
         ═══════════════════════════════════════════ -->
    <header class="mb-4 flex items-end justify-between border-b pb-3" style="border-color: var(--border);">
      <div>
        <div class="flex items-center gap-2 mb-1.5">
          <div 
            class="w-2 h-2 rounded-full animate-pulse"
            style="background: {riskColor}; box-shadow: 0 0 10px {riskColor};"
          />
          <h1 class="text-xl font-bold uppercase tracking-[0.2em]" style="color: var(--text);">
            Aggregate Threat Analysis Dashboard
          </h1>
        </div>
        <p class="text-[11px] uppercase tracking-widest" style="color: var(--muted);">
          {new Date().toLocaleDateString("en-US", { weekday: "long", year: "numeric", month: "long", day: "numeric" })}
        </p>
      </div>
      
      
    </header>

    {#if $loading}
      <!-- ═══════════════════════════════════════════
           SKELETON LOADING STATE
           ═══════════════════════════════════════════ -->
      <div class="space-y-3 animate-pulse">
        <div class="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
          {#each Array(5) as _, i}
            <div class="card p-4 h-24" style="background: var(--surface); border: 1px solid var(--border);">
              <div class="skeleton h-3 w-20 mb-3 rounded" style="background: var(--surface-2);" />
              <div class="skeleton h-8 w-16 rounded" style="background: var(--surface-2);" />
            </div>
          {/each}
        </div>
        <div class="grid grid-cols-3 gap-3">
          <div class="card col-span-2 p-4 h-64" style="background: var(--surface); border: 1px solid var(--border);" />
          <div class="card p-4 h-64" style="background: var(--surface); border: 1px solid var(--border);" />
        </div>
      </div>

    {:else if $error}
      <div 
        class="card p-4 text-center"
        style="background: rgba(239,68,68,0.05); border: 1px solid rgba(239,68,68,0.2);"
      >
        <p class="text-sm font-bold mb-2" style="color: var(--danger);">SYSTEM ERROR</p>
        <p class="text-xs" style="color: var(--muted);">{$error}</p>
      </div>

    {:else}
      <!-- ═══════════════════════════════════════════
           SECTION 1: EXECUTIVE THREAT METRICS
           ═══════════════════════════════════════════ -->
      <section class="mb-4">
        <div class="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
          
          <!-- Risk Score: Hero Metric -->
          <div 
            class="card relative overflow-hidden group p-4 min-h-[112px]"
            style="
              background: var(--surface);
              border: 1px solid var(--border);
              transition: all 0.3s ease;
            "
            onmouseenter={(e) => e.currentTarget.style.borderColor = riskColor + '60'}
            onmouseleave={(e) => e.currentTarget.style.borderColor = 'var(--border)'}
          >
            <p class="text-[10px] uppercase tracking-[0.15em] mb-2 font-semibold" style="color: var(--muted);">
              Composite Risk Score
            </p>
            <div class="flex items-baseline gap-2 relative z-10">
              <span 
                class="text-4xl font-bold tabular-nums tracking-tight"
                style="color: {riskColor}; text-shadow: 0 0 30px {riskColor}30;"
              >
                {riskScore}
              </span>
              <span 
                class="text-[10px] font-bold px-2 py-1 uppercase tracking-wider"
                style="color: {riskColor}; border: 1px solid {riskColor}50;"
              >
                {riskLabel}
              </span>
            </div>
            <div class="mt-2 h-1 w-full rounded-full overflow-hidden" style="background: var(--surface-2);">
              <div 
                class="h-full rounded-full transition-all duration-1000 ease-out"
                style="width: {riskScore}%; background: {riskColor}; box-shadow: 0 0 10px {riskColor}50;"
              />
            </div>
          </div>

          <!-- Security Health -->
          <div 
            class="card p-4 relative overflow-hidden group min-h-[112px]"
            style="background: var(--surface); border: 1px solid var(--border);"
          >
            <p class="text-[10px] uppercase tracking-[0.15em] mb-2 font-semibold" style="color: var(--muted);">
              Security Health
            </p>
            <div class="flex items-baseline gap-2 relative z-10">
              <span class="text-4xl font-bold tabular-nums tracking-tight" style="color: #22c55e;">
                {securityHealth}
              </span>
              <span class="text-lg" style="color: #22c55e; opacity: 0.6;">%</span>
            </div>
            <p class="text-[10px] mt-1.5" style="color: var(--muted);">
              {totalSafe.toLocaleString()} safe / {totalFunctions.toLocaleString()} total
            </p>
          </div>

          <!-- Vulnerability Density -->
          <div 
            class="card p-4 relative overflow-hidden group min-h-[112px]"
            style="background: var(--surface); border: 1px solid var(--border);"
          >
            <p class="text-[10px] uppercase tracking-[0.15em] mb-2 font-semibold" style="color: var(--muted);">
              Vuln. Density
            </p>
            <div class="flex items-baseline gap-2 relative z-10">
              <span class="text-4xl font-bold tabular-nums tracking-tight" style="color: var(--danger);">
                {vulnerabilityDensity}
              </span>
              <span class="text-lg" style="color: var(--danger); opacity: 0.6;">%</span>
            </div>
            <p class="text-[10px] mt-1.5" style="color: var(--muted);">
              {totalVulnerable.toLocaleString()} vulnerable functions
            </p>
          </div>

          <!-- Analyses Run -->
          <div 
            class="card p-4 relative overflow-hidden group min-h-[112px]"
            style="background: var(--surface); border: 1px solid var(--border);"
          >
            <p class="text-[10px] uppercase tracking-[0.15em] mb-2 font-semibold" style="color: var(--muted);">
              Analyses Executed
            </p>
            <div class="flex items-baseline gap-2">
              <span class="text-4xl font-bold tabular-nums tracking-tight" style="color: var(--accent);">
                {$displayKpis.total_analyses.toLocaleString()}
              </span>
            </div>
            <p class="text-[10px] mt-1.5" style="color: var(--muted);">
              Total scan operations
            </p>
          </div>

          <!-- Functions Scanned -->
          <div 
            class="card p-4 relative overflow-hidden group min-h-[112px]"
            style="background: var(--surface); border: 1px solid var(--border);"
          >
            <p class="text-[10px] uppercase tracking-[0.15em] mb-2 font-semibold" style="color: var(--muted);">
              Functions Scanned
            </p>
            <div class="flex items-baseline gap-2">
              <span class="text-4xl font-bold tabular-nums tracking-tight" style="color: #818cf8;">
                {$displayKpis.total_functions.toLocaleString()}
              </span>
            </div>
            <p class="text-[10px] mt-1.5" style="color: var(--muted);">
              Lines of code analyzed
            </p>
          </div>
        </div>
      </section>

      <!-- ═══════════════════════════════════════════
           SECTION 2: THREAT INTELLIGENCE FEED
           ═══════════════════════════════════════════ -->
      <section class="mb-4">
        <div 
          class="card p-4 relative overflow-hidden"
          style="
            background: var(--surface);
            border: 1px solid var(--border);
            background-image: linear-gradient(90deg, {riskColor}05 0%, transparent 50%);
          "
        >
          <div class="flex items-center justify-between mb-3">
            <div class="flex items-center gap-2">
              <div 
                class="w-7 h-7 flex items-center justify-center rounded"
                style="background: {riskColor}15; border: 1px solid {riskColor}30;"
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={riskColor} stroke-width="2">
                  <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
                </svg>
              </div>
              <div>
                <p class="text-xs font-bold uppercase tracking-wider" style="color: var(--text);">
                  Automated Threat Intelligence
                </p>
                <p class="text-[10px]" style="color: var(--muted);">
                  LLM-Generated Security Assessment • {insights.length} findings
                </p>
              </div>
            </div>
            <span 
              class="text-[10px] px-2 py-1 font-bold uppercase tracking-wider"
              style="background: var(--surface-2); border: 1px solid var(--border); color: var(--muted);"
            >
              Live Analysis
            </span>
          </div>

          <div class="grid grid-cols-1 {insights.length >= 4 ? 'md:grid-cols-2' : ''} gap-2">
            {#each insights as insight, i}
              <div
                class="group relative p-3 cursor-default transition-all duration-300"
                style="
                  background: var(--surface-2);
                  border-left: 3px solid {getInsightBorderColor(insight.severity)};
                  box-shadow: {hoveredInsight === i ? getInsightGlow(insight.severity) : 'none'};
                  transform: {hoveredInsight === i ? 'translateX(4px)' : 'translateX(0)'};
                "
                onmouseenter={() => hoveredInsight = i}
                onmouseleave={() => hoveredInsight = null}
                role="listitem"
              >
                <div class="flex items-start gap-2">
                  <span 
                    class="text-lg font-bold leading-none mt-0.5"
                    style="color: {getInsightBorderColor(insight.severity)};"
                  >
                    {insight.icon}
                  </span>
                  <p class="text-xs leading-snug" style="color: var(--text);">
                    {insight.text}
                  </p>
                </div>
                <div 
                  class="absolute bottom-0 left-0 h-[1px] transition-all duration-500"
                  style="
                    width: {hoveredInsight === i ? '100%' : '0%'};
                    background: {getInsightBorderColor(insight.severity)};
                  "
                />
              </div>
            {/each}
          </div>
        </div>
      </section>

      <!-- ═══════════════════════════════════════════
           SECTION 3: VULNERABILITY TOPOLOGY
           ═══════════════════════════════════════════ -->
      <section class="mb-4">
        <div class="grid grid-cols-12 gap-3">
          
          <!-- CWE Breakdown -->
          <div class="col-span-12 lg:col-span-7 card p-4 flex min-h-[30rem] flex-col" style="background: var(--surface); border: 1px solid var(--border);">
            <div class="flex items-center justify-between mb-3">
              <div>
                <p class="text-xs font-bold uppercase tracking-wider" style="color: var(--text);">
                  CWE Vulnerability Topology
                </p>
              </div>
              <div class="flex gap-2">
                {#each Object.entries(SEVERITY_COLORS) as [sev, color]}
                  <div class="flex items-center gap-1.5">
                    <div class="w-2 h-2 rounded-full" style="background: {color};"></div>
                    <span class="text-[10px]" style="color: var(--muted);">{sev}</span>
                  </div>
                {/each}
              </div>
            </div>
            {#if $stats.cwe_counts.length}
              <div class="min-h-[24rem] flex-1">
                <canvas bind:this={cweCanvas} class="w-full h-full"></canvas>
              </div>
            {:else}
              <div class="min-h-[24rem] flex flex-1 items-center justify-center">
                <p class="text-xs text-center" style="color: var(--muted);">
                  No vulnerability patterns detected.<br/>Run an analysis to populate CWE data.
                </p>
              </div>
            {/if}
          </div>

          <!-- Severity Distribution + Radar -->
          <div class="col-span-12 lg:col-span-5 space-y-3">
            <!-- Doughnut -->
            <div class="card p-4" style="background: var(--surface); border: 1px solid var(--border);">
              <p class="text-xs font-bold uppercase tracking-wider mb-2" style="color: var(--text);">
                Severity Distribution
              </p>
              {#if $stats.severity_counts.length}
                <div class="relative h-44">
                  <canvas bind:this={severityCanvas} class="w-full h-full drop-shadow-[0_0_18px_rgba(249,115,22,0.12)]"></canvas>
                  <div class="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                    <span class="text-3xl font-bold leading-none tabular-nums" style="color: var(--text);">
                      {totalVulnerable}
                    </span>
                    <span class="mt-1 text-[10px] uppercase tracking-wider" style="color: var(--muted);">
                      Vulnerable
                    </span>
                  </div>
                </div>
                <div class="mt-2 grid grid-cols-2 gap-1.5">
                  {#each $stats.severity_counts as item}
                    <div class="flex items-center justify-between gap-2 px-2 py-1" style="background: var(--surface-2); border: 1px solid var(--border);">
                      <div class="flex items-center gap-1.5 min-w-0">
                        <div class="w-2 h-2 shrink-0 rounded-full" style="background: {SEVERITY_COLORS[item.severity] ?? '#6b7280'};"></div>
                        <span class="truncate text-[10px] font-bold" style="color: var(--muted);">{item.severity}</span>
                      </div>
                      <span class="text-[10px] font-bold tabular-nums" style="color: var(--text);">{item.count}</span>
                    </div>
                  {/each}
                </div>
              {:else}
                <div class="h-48 flex items-center justify-center">
                  <p class="text-xs" style="color: var(--muted);">Awaiting scan data...</p>
                </div>
              {/if}
            </div>

            <!-- Security Posture Radar -->
            <div class="card p-4" style="background: var(--surface); border: 1px solid var(--border);">
              <p class="text-xs font-bold uppercase tracking-wider mb-1" style="color: var(--text);">
                Security Dimension Analysis
              </p>
              <p class="text-[10px] mb-2" style="color: var(--muted);">
                Multi-vector defensive posture assessment
              </p>
              <div class="h-40">
                <canvas bind:this={radarCanvas} class="w-full h-full"></canvas>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- ═══════════════════════════════════════════
           SECTION 4: ATTACK SURFACE & TEMPORAL ANALYSIS
           ═══════════════════════════════════════════ -->
      <section class="mb-4">
        <div class="grid grid-cols-12 gap-3">
          
          <!-- Most Affected Files -->
          <div class="col-span-12 lg:col-span-5 card p-4" style="background: var(--surface); border: 1px solid var(--border);">
            <div class="flex items-center justify-between mb-3">
              <p class="text-xs font-bold uppercase tracking-wider" style="color: var(--text);">
                Attack Surface Ranking
              </p>
              <select
                value={selectedAnalysis === "all" ? "all" : String(selectedAnalysis)}
                onchange={handleAnalysisSelect}
                class="text-[11px] rounded-none px-2 py-1 outline-none cursor-pointer font-mono"
                style="background: var(--surface-2); border: 1px solid var(--border); color: var(--text);"
              >
                <option value="all">All Analyses</option>
                {#each $allAnalyses as a}
                  <option value={String(a.id)}>{a.label}</option>
                {/each}
              </select>
            </div>

            {#if affectedFiles.length}
              <div class="space-y-1">
                {#each affectedFiles.slice(0, 8) as file, index}
                  <div
                    class="group flex items-center gap-2 py-1.5 px-2 transition-colors"
                    style="
                      border-bottom: 1px solid var(--border);
                      background: {index === 0 ? 'rgba(239,68,68,0.03)' : 'transparent'};
                    "
                  >
                    <!-- Rank Badge -->
                    <div 
                      class="w-6 h-6 flex items-center justify-center text-[10px] font-bold shrink-0"
                      style="
                        background: {index < 3 ? riskColor + '20' : 'var(--surface-2)'};
                        color: {index < 3 ? riskColor : 'var(--muted)'};
                        border: 1px solid {index < 3 ? riskColor + '40' : 'var(--border)'};
                      "
                    >
                      {index + 1}
                    </div>

                    <!-- Filename -->
                    <div class="flex-1 min-w-0">
                      <p class="text-xs truncate font-medium" style="color: var(--text);">
                        {file.label}
                      </p>
                      <p class="text-[10px]" style="color: var(--muted);">
                        {file.safe} safe / {file.vuln} vulnerable
                      </p>
                    </div>

                    <!-- Visual Bar -->
                    <div class="w-24 h-1.5 shrink-0 rounded-full overflow-hidden" style="background: var(--surface-2);">
                      <div 
                        class="h-full rounded-full transition-all duration-700"
                        style="
                          width: {(file.vuln / maxFileVulns) * 100}%;
                          background: {index === 0 ? riskColor : 'var(--danger)'};
                          opacity: {0.4 + ((file.vuln / maxFileVulns) * 0.6)};
                        "
                      ></div>
                    </div>

                    <!-- Count -->
                    <div 
                      class="w-8 text-right text-xs font-bold shrink-0"
                      style="color: {index === 0 ? riskColor : 'var(--danger)'};"
                    >
                      {file.vuln}
                    </div>
                  </div>
                {/each}
              </div>
            {:else}
              <div class="py-8 text-center">
                <p class="text-xs" style="color: var(--muted);">
                  No attack surface data available.<br/>Select an analysis or run a scan.
                </p>
              </div>
            {/if}
          </div>

          <!-- Temporal Vulnerability Trend -->
          <div class="col-span-12 lg:col-span-7 card p-4 flex min-h-[30rem] flex-col" style="background: var(--surface); border: 1px solid var(--border);">
            <div class="mb-3">
              <p class="text-xs font-bold uppercase tracking-wider" style="color: var(--text);">
                Temporal Vulnerability Forensics
              </p>
              <p class="text-[10px] mt-1" style="color: var(--muted);">
                Vulnerability rate vs. security health over time
              </p>
            </div>
            {#if $trendData.length > 1}
              <div class="min-h-[24rem] flex-1">
                <canvas bind:this={trendCanvas} class="w-full h-full"></canvas>
              </div>
            {:else}
              <div class="min-h-[24rem] flex flex-1 flex-col items-center justify-center">
                <div 
                  class="w-12 h-12 rounded-full mb-3 flex items-center justify-center"
                  style="background: var(--surface-2); border: 1px solid var(--border);"
                >
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" stroke-width="1.5">
                    <path d="M3 3v18h18"/>
                    <path d="M18.7 8l-5.1 5.2-2.8-2.7L7 14.3"/>
                  </svg>
                </div>
                <p class="text-xs text-center" style="color: var(--muted);">
                  Insufficient temporal data.<br/>Complete 2+ analyses to generate trend visualization.
                </p>
              </div>
            {/if}
          </div>
        </div>
      </section>

      <!-- ═══════════════════════════════════════════
           SECTION 5: RECENT ANALYSES TABLE
           ═══════════════════════════════════════════ -->
      <section class="mb-4">
        <div class="card overflow-hidden" style="background: var(--surface); border: 1px solid var(--border);">
          <div class="px-4 py-3 flex items-center justify-between" style="border-bottom: 1px solid var(--border);">
            <p class="text-xs font-bold uppercase tracking-wider" style="color: var(--text);">
              Recent Analysis Operations
            </p>
            <span 
              class="text-[10px] px-2 py-1 font-mono"
              style="background: var(--surface-2); color: var(--muted); border: 1px solid var(--border);"
            >
              {$stats.recent_analyses?.length ?? 0} records
            </span>
          </div>
          
          <div class="overflow-x-auto">
            <table class="w-full">
              <thead>
                <tr style="border-bottom: 1px solid var(--border);">
                  {#each ["Project", "Timestamp", "Functions", "Vulnerable", "Status", ""] as h}
                    <th
                      class="text-left px-4 py-2 text-[10px] uppercase tracking-wider font-bold"
                      style="color: var(--muted);"
                    >
                      {h}
                    </th>
                  {/each}
                </tr>
              </thead>
              <tbody>
                {#each $stats.recent_analyses as item}
                  <tr
                    class="transition-all duration-200 cursor-pointer"
                    style="border-bottom: 1px solid var(--border);"
                    onmouseenter={(e) => {
                      e.currentTarget.style.background = "var(--surface-2)";
                      e.currentTarget.style.transform = "scale(1.002)";
                    }}
                    onmouseleave={(e) => {
                      e.currentTarget.style.background = "transparent";
                      e.currentTarget.style.transform = "scale(1)";
                    }}
                  >
                    <td class="px-4 py-2">
                      <div class="flex items-center gap-2">
                        <div 
                          class="w-1.5 h-1.5 rounded-full"
                          style="background: {(item.vuln_count ?? 0) > 0 ? 'var(--danger)' : '#22c55e'};"
                        />
                        <span class="text-xs font-medium" style="color: var(--text);">
                          {item.project_name}
                        </span>
                      </div>
                    </td>
                    <td class="px-4 py-2 text-xs font-mono" style="color: var(--muted);">
                      {item.timestamp}
                    </td>
                    <td class="px-4 py-2 text-xs" style="color: var(--muted);">
                      {(item.total_functions ?? 0).toLocaleString()}
                    </td>
                    <td class="px-4 py-2">
                      <span
                        class="text-xs font-bold"
                        style="color: {(item.vuln_count ?? 0) > 0 ? 'var(--danger)' : '#22c55e'};"
                      >
                        {(item.vuln_count ?? 0) > 0 ? `${item.vuln_count} detected` : "Clean"}
                      </span>
                    </td>
                    <td class="px-4 py-2">
                      <span 
                        class="text-[10px] px-2 py-0.5 font-bold uppercase tracking-wider"
                        style="
                          background: {(item.vuln_count ?? 0) > 0 ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)'};
                          color: {(item.vuln_count ?? 0) > 0 ? 'var(--danger)' : '#22c55e'};
                          border: 1px solid {(item.vuln_count ?? 0) > 0 ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.3)'};
                        "
                      >
                        {(item.vuln_count ?? 0) > 0 ? "Threats Found" : "Secure"}
                      </span>
                    </td>
                    <td class="px-4 py-2 text-right">
                      <a
                        href="/report/{item.id}"
                        class="inline-flex items-center gap-1 text-[11px] font-bold uppercase tracking-wider transition-colors hover:opacity-80"
                        style="color: var(--accent);"
                      >
                        Inspect
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                          <path d="M5 12h14M12 5l7 7-7 7"/>
                        </svg>
                      </a>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      

    {/if}
  </div>
</div>

<style>
  .card {
    backdrop-filter: blur(8px);
    transition: transform 0.2s ease, box-shadow 0.2s ease;
  }
  .card:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 20px rgba(0,0,0,0.1);
  }
  
  /* Custom scrollbar */
  ::-webkit-scrollbar {
    width: 6px;
    height: 6px;
  }
  ::-webkit-scrollbar-track {
    background: transparent;
  }
  ::-webkit-scrollbar-thumb {
    background: var(--border);
    border-radius: 3px;
  }
  ::-webkit-scrollbar-thumb:hover {
    background: var(--muted);
  }

  /* Smooth number transitions */
  .tabular-nums {
    font-variant-numeric: tabular-nums;
  }

  /* Entrance animation */
  @keyframes slideUp {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
  }
  
  section {
    animation: slideUp 0.6s cubic-bezier(0.4, 0, 0.2, 1) forwards;
  }
  section:nth-child(1) { animation-delay: 0.1s; }
  section:nth-child(2) { animation-delay: 0.2s; }
  section:nth-child(3) { animation-delay: 0.3s; }
  section:nth-child(4) { animation-delay: 0.4s; }
  section:nth-child(5) { animation-delay: 0.5s; }
</style>
