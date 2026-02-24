<script lang="ts">
  import { page } from "$app/stores";
  import { onMount } from "svelte";
  import { Download, ArrowRight, History } from "lucide-svelte";
  import { fetchReport, flattenFunctions, exportPDF } from "./logic";
  import {
    getSeverityBorderColor,
    getSeverityGlow,
    getCVSSColor,
  } from "$lib/cwe_db";

  let report: any = null;
  let error = "";
  let loading = true;
  let allFunctions: any[] = [];
  let mounted = false;

  $: vulnFns = allFunctions.filter((f) => f.verdict === "vulnerable");
  $: safeFns = allFunctions.filter((f) => f.verdict !== "vulnerable");
  $: vulnPct =
    allFunctions.length > 0
      ? Math.round((vulnFns.length / allFunctions.length) * 100)
      : 0;
  $: isFolder = (report?.files?.length ?? 0) > 1;
  $: filesAffectedCount = [...new Set(vulnFns.map((f) => f.file_path))].length;

  $: severityCounts = {
    Critical: vulnFns.filter((f) => f.severity === "Critical").length,
    High: vulnFns.filter((f) => f.severity === "High").length,
    Medium: vulnFns.filter((f) => f.severity === "Medium").length,
    Low: vulnFns.filter((f) => f.severity === "Low").length,
  };
  $: maxSevCount = Math.max(...Object.values(severityCounts), 1);

  $: cweFrequency = (() => {
    const counts: Record<
      string,
      { cwe: string; cwe_name: string; severity: string; count: number }
    > = {};
    vulnFns.forEach((f) => {
      if (!f.cwe) return;
      if (!counts[f.cwe])
        counts[f.cwe] = {
          cwe: f.cwe,
          cwe_name: f.cwe_name ?? "",
          severity: f.severity ?? "",
          count: 0,
        };
      counts[f.cwe].count++;
    });
    return Object.values(counts)
      .sort((a, b) => b.count - a.count)
      .slice(0, 3);
  })();

  const severityOrder: Record<string, number> = {
    Critical: 0,
    High: 1,
    Medium: 2,
    Low: 3,
  };
  const SEVERITY_COLORS: Record<string, string> = {
    Critical: "#ef4444",
    High: "#f97316",
    Medium: "#eab308",
    Low: "#3b82f6",
  };

  $: topFindings = [...vulnFns]
    .sort(
      (a, b) =>
        (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4),
    )
    .slice(0, 6);

  const RING_R = 56;
  const RING_C = 2 * Math.PI * RING_R;
  $: ringColor =
    vulnPct === 0
      ? "var(--success)"
      : vulnPct < 25
        ? "#eab308"
        : vulnPct < 60
          ? "#f97316"
          : "var(--danger)";
  $: ringOffset = mounted ? RING_C * (1 - vulnPct / 100) : RING_C;

  onMount(async () => {
    try {
      const data = await fetchReport($page.params.id ?? "0");
      report = data;
      allFunctions = flattenFunctions(data);
    } catch (e: any) {
      error = e.message;
    }
    loading = false;
    setTimeout(() => (mounted = true), 80);
  });
</script>

{#if loading}
  <div class="min-h-screen" style="background:var(--bg);color:var(--text)">
    <!-- Header skeleton -->
    <header
      class="h-14 flex items-center justify-between px-6 sticky top-0 z-10"
      style="background:var(--surface);border-bottom:1px solid var(--border)"
    >
      <div class="flex items-center gap-3">
        <div class="skeleton h-6 w-16 rounded-lg"></div>
        <div class="skeleton h-3 w-1 rounded"></div>
        <div class="skeleton h-4 w-36 rounded"></div>
        <div class="skeleton h-3 w-28 rounded hidden sm:block"></div>
      </div>
      <div class="flex items-center gap-2">
        <div class="skeleton h-7 w-24 rounded-lg"></div>
        <div class="skeleton h-7 w-28 rounded-lg"></div>
      </div>
    </header>

    <div class="max-w-6xl mx-auto px-6 py-8 space-y-5">
      <!-- Hero: ring + 4 KPI cards -->
      <div class="flex items-center gap-8">
        <!-- Ring -->
        <div
          class="skeleton rounded-full shrink-0"
          style="width:132px;height:132px"
        ></div>
        <!-- KPI cards -->
        <div class="flex-1 grid grid-cols-4 gap-3">
          {#each Array(4) as _}
            <div class="card p-4">
              <div class="skeleton h-3 w-24 mb-3 rounded"></div>
              <div class="skeleton h-8 w-10 rounded"></div>
            </div>
          {/each}
        </div>
      </div>

      <!-- Severity breakdown + Top vulnerabilities -->
      <div class="grid grid-cols-2 gap-4">
        <!-- Severity bars -->
        <div class="card p-5">
          <div class="skeleton h-3 w-36 mb-5 rounded"></div>
          <div class="space-y-4">
            {#each [80, 100, 50, 20] as w}
              <div class="flex items-center gap-3">
                <div class="skeleton h-3 w-14 rounded shrink-0"></div>
                <div
                  class="flex-1 h-1.5 rounded-full overflow-hidden"
                  style="background:var(--border)"
                >
                  <div
                    class="h-full rounded-full skeleton"
                    style="width:{w}%"
                  ></div>
                </div>
                <div class="skeleton h-3 w-4 rounded"></div>
              </div>
            {/each}
          </div>
        </div>
        <!-- Top CWEs -->
        <div class="card p-5">
          <div class="skeleton h-3 w-32 mb-5 rounded"></div>
          <div class="space-y-5">
            {#each Array(3) as _, i}
              <div class="flex items-start gap-3">
                <div class="skeleton w-5 h-5 rounded-lg shrink-0"></div>
                <div class="flex-1">
                  <div class="flex items-center gap-2 mb-1.5">
                    <div class="skeleton h-3 w-16 rounded"></div>
                    <div class="skeleton h-4 w-14 rounded"></div>
                  </div>
                  <div class="skeleton h-2.5 w-32 rounded"></div>
                </div>
                <div class="skeleton h-4 w-12 rounded shrink-0"></div>
              </div>
            {/each}
          </div>
        </div>
      </div>

      <!-- Most critical findings -->
      <div class="card overflow-hidden">
        <div class="px-5 py-3" style="border-bottom:1px solid var(--border)">
          <div class="skeleton h-3 w-40 rounded"></div>
        </div>
        {#each Array(4) as _, i}
          <div
            class="flex items-center gap-4 px-5 py-3.5"
            style="border-bottom:{i < 3 ? '1px solid var(--border)' : 'none'}"
          >
            <div
              class="skeleton w-1.5 rounded-full shrink-0"
              style="height:36px"
            ></div>
            <div class="flex-1">
              <div class="skeleton h-3 w-28 mb-2 rounded"></div>
              <div class="skeleton h-2.5 w-44 rounded"></div>
            </div>
            <div class="flex items-center gap-2 shrink-0">
              <div class="skeleton h-3 w-16 rounded"></div>
              <div class="skeleton h-5 w-14 rounded"></div>
            </div>
            <div class="skeleton h-3 w-10 rounded shrink-0"></div>
          </div>
        {/each}
      </div>

      <!-- CTA button area -->
      <div class="flex flex-col items-center gap-3 pb-4">
        <div class="skeleton h-10 w-44 rounded-xl"></div>
        <div class="skeleton h-2.5 w-56 rounded"></div>
      </div>
    </div>
  </div>
{:else if error}
  <div
    class="min-h-screen flex items-center justify-center"
    style="background:var(--bg)"
  >
    <div class="text-center">
      <p class="text-xs mb-4" style="color:var(--danger)">{error}</p>
      <a href="/" class="text-xs" style="color:var(--accent)"
        >← Back to Upload</a
      >
    </div>
  </div>
{:else}
  <div class="min-h-screen" style="background:var(--bg);color:var(--text)">
    <header
      class="h-14 flex items-center justify-between px-6 sticky top-0 z-10"
      style="background:var(--surface);border-bottom:1px solid var(--border)"
    >
      <div class="flex items-center gap-3 min-w-0">
        <a href="/history" class="btn-ghost shrink-0"
          ><History size={12} />History</a
        >
        <span style="color:var(--border)">·</span>
        <h1
          class="text-sm font-semibold mono truncate"
          style="color:var(--accent)"
        >
          {report.project_name}
        </h1>
        <span
          class="text-xs shrink-0 hidden sm:block"
          style="color:var(--muted)">{report.timestamp}</span
        >
      </div>
      <div class="flex items-center gap-2 shrink-0">
        <button
          onclick={() => exportPDF($page.params.id ?? "0")}
          class="btn-ghost"
        >
          <Download size={12} />Export PDF
        </button>
        <a href="/report/{$page.params.id}/detail" class="btn-primary">
          Full Report <ArrowRight size={12} />
        </a>
      </div>
    </header>

    <div class="max-w-6xl mx-auto px-6 py-8 space-y-5">
      <!-- Hero: Ring + KPIs -->
      <div class="flex items-center gap-8 animate-fade-up">
        <div class="relative flex items-center justify-center shrink-0">
          <svg
            width={RING_R * 2 + 20}
            height={RING_R * 2 + 20}
            viewBox="0 0 {RING_R * 2 + 20} {RING_R * 2 + 20}"
          >
            <circle
              cx={RING_R + 10}
              cy={RING_R + 10}
              r={RING_R}
              fill="none"
              stroke="var(--border)"
              stroke-width="6"
            />
            {#if vulnPct > 0 && vulnPct < 100}
              <circle
                cx={RING_R + 10}
                cy={RING_R + 10}
                r={RING_R}
                fill="none"
                stroke="var(--success)"
                stroke-width="6"
                stroke-dasharray={RING_C}
                stroke-dashoffset="0"
                transform="rotate(-90 {RING_R + 10} {RING_R + 10})"
                opacity="0.12"
              />
            {/if}
            <circle
              cx={RING_R + 10}
              cy={RING_R + 10}
              r={RING_R}
              fill="none"
              stroke={ringColor}
              stroke-width="6"
              stroke-linecap="round"
              stroke-dasharray={RING_C}
              stroke-dashoffset={ringOffset}
              transform="rotate(-90 {RING_R + 10} {RING_R + 10})"
              style="transition:stroke-dashoffset 1.4s cubic-bezier(0.4,0,0.2,1)"
            />
          </svg>
          <div class="absolute flex flex-col items-center">
            <p
              class="font-bold tabular-nums"
              style="color:{ringColor};font-size:30px;line-height:1"
            >
              {vulnPct}%
            </p>
            <p class="text-xs mt-1" style="color:var(--muted)">vulnerable</p>
          </div>
        </div>

        <div class="flex-1 grid grid-cols-4 gap-3">
          {#each [{ label: "Functions Scanned", value: allFunctions.length, color: "var(--text)" }, { label: "Vulnerable", value: vulnFns.length, color: "var(--danger)" }, { label: "Clean", value: safeFns.length, color: "var(--success)" }, { label: isFolder ? "Files Affected" : "Vulnerability Rate", value: isFolder ? `${filesAffectedCount} / ${report.files.length}` : `${vulnPct}%`, color: vulnPct > 50 ? "var(--danger)" : vulnPct > 0 ? "#f97316" : "var(--success)" }] as kpi, i}
            <div class="card p-4 animate-fade-up stagger-{i + 1}">
              <p
                class="text-xs uppercase tracking-wider mb-1.5"
                style="color:var(--muted)"
              >
                {kpi.label}
              </p>
              <p
                class="text-2xl font-bold tabular-nums"
                style="color:{kpi.color}"
              >
                {kpi.value}
              </p>
            </div>
          {/each}
        </div>
      </div>

      <!-- Severity + Top CWEs -->
      <div class="grid grid-cols-2 gap-4 animate-fade-up stagger-2">
        <div class="card p-5">
          <p
            class="text-xs font-semibold uppercase tracking-wider mb-4"
            style="color:var(--muted)"
          >
            Severity Breakdown
          </p>
          {#if vulnFns.length === 0}
            <div
              class="flex items-center gap-2 py-6"
              style="color:var(--success)"
            >
              <span>✓</span><span class="text-sm font-medium"
                >No vulnerabilities found</span
              >
            </div>
          {:else}
            <div class="space-y-3.5">
              {#each [["Critical", "#ef4444"], ["High", "#f97316"], ["Medium", "#eab308"], ["Low", "#3b82f6"]] as [sev, col]}
                {@const count =
                  severityCounts[sev as keyof typeof severityCounts]}
                {@const delayMap: Record<string,string> = { Critical:"0ms", High:"80ms", Medium:"160ms", Low:"240ms" }}
                <div class="flex items-center gap-3">
                  <span
                    class="text-xs w-14 shrink-0 font-medium"
                    style="color:{col}">{sev}</span
                  >
                  <div
                    class="flex-1 h-1.5 rounded-full overflow-hidden"
                    style="background:var(--border)"
                  >
                    <div
                      class="h-full rounded-full"
                      style="width:{mounted
                        ? Math.round((count / maxSevCount) * 100)
                        : 0}%;
                           background:{col};
                           transition:width 1s ease-out;
                           transition-delay:{delayMap[sev]}"
                    ></div>
                  </div>
                  <span
                    class="text-xs w-4 text-right tabular-nums font-semibold"
                    style="color:{count > 0 ? col : 'var(--subtle)'}"
                    >{count}</span
                  >
                </div>
              {/each}
            </div>
          {/if}
        </div>

        <div class="card p-5">
          <p
            class="text-xs font-semibold uppercase tracking-wider mb-4"
            style="color:var(--muted)"
          >
            Top Vulnerabilities
          </p>
          {#if cweFrequency.length === 0}
            <p class="text-xs py-6" style="color:var(--muted)">
              No vulnerable functions detected.
            </p>
          {:else}
            <div class="space-y-4">
              {#each cweFrequency as item, i}
                {@const color =
                  SEVERITY_COLORS[item.severity] ?? "var(--muted)"}
                <div class="flex items-start gap-3">
                  <div
                    class="w-5 h-5 rounded-lg flex items-center justify-center shrink-0 font-bold tabular-nums"
                    style="background:{color}18;color:{color};font-size:10px"
                  >
                    {i + 1}
                  </div>
                  <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-2 mb-0.5">
                      <span class="text-xs font-bold mono" style="color:{color}"
                        >{item.cwe}</span
                      >
                      <span
                        class="px-1.5 py-0.5 rounded font-semibold"
                        style="background:{color}18;color:{color};font-size:10px"
                        >{item.severity}</span
                      >
                    </div>
                    <p class="text-xs truncate" style="color:var(--muted)">
                      {item.cwe_name}
                    </p>
                  </div>
                  <div class="shrink-0 flex items-center gap-1">
                    <span
                      class="text-sm font-bold tabular-nums"
                      style="color:{color}">{item.count}</span
                    >
                    <span class="text-xs" style="color:var(--muted)"
                      >hit{item.count !== 1 ? "s" : ""}</span
                    >
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      </div>

      <!-- Most critical findings -->
      {#if topFindings.length > 0}
        <div class="card overflow-hidden animate-fade-up stagger-3">
          <div class="px-5 py-3" style="border-bottom:1px solid var(--border)">
            <p
              class="text-xs font-semibold uppercase tracking-wider"
              style="color:var(--muted)"
            >
              Most Critical Findings
            </p>
          </div>
          {#each topFindings as fn, i}
            {@const color = SEVERITY_COLORS[fn.severity] ?? "var(--muted)"}
            {@const fileName =
              (fn.file_path ?? "").replace(/\\/g, "/").split("/").pop() ??
              fn.file_path}
            <div
              class="finding-item flex items-center gap-4 px-5 py-3.5 transition-colors"
              style="border-bottom:{i < topFindings.length - 1
                ? '1px solid var(--border)'
                : 'none'}"
            >
              <div
                class="w-1.5 h-9 rounded-full shrink-0"
                style="background:{color}"
              ></div>
              <div class="flex-1 min-w-0">
                <p class="text-xs font-semibold mono">{fn.function_name}</p>
                <p
                  class="text-xs mono truncate mt-0.5"
                  style="color:var(--muted)"
                >
                  {fileName} · lines {fn.start_line}–{fn.end_line}
                </p>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <span class="text-xs font-bold mono" style="color:{color}"
                  >{fn.cwe}</span
                >
                <span
                  class="px-1.5 py-0.5 rounded text-xs font-semibold"
                  style="background:{color}20;color:{color};font-size:10px"
                  >{fn.severity}</span
                >
              </div>
              <a
                href="/report/{$page.params.id}/detail"
                class="text-xs shrink-0 transition-colors"
                style="color:var(--accent)">View →</a
              >
            </div>
          {/each}
        </div>
      {/if}

      <!-- CTA -->
      <div class="text-center pb-4 animate-fade-up stagger-4">
        <a
          href="/report/{$page.params.id}/detail"
          class="btn-primary inline-flex gap-2 rounded-xl"
          style="padding:10px 24px;font-size:13px;height:auto;box-shadow:0 0 24px var(--accent-glow)"
        >
          View Full Report
          <ArrowRight size={14} />
        </a>
      </div>
    </div>
  </div>
{/if}

<style>
  .finding-item:hover {
    background: var(--surface-2);
  }
</style>
