<script lang="ts">
    import { page } from "$app/stores";
    import { theme } from "$lib/types/theme";
    import { onMount } from "svelte";
    import { invoke } from "@tauri-apps/api/core";
    import {
        Copy,
        Check,
        ChevronDown,
        ChevronLeft,
        ChevronRight,
        Search,
        X,
        LayoutList,
        FolderOpen,
        ArrowLeft,
        Download,
    } from "lucide-svelte";
    import ExportReportModal from "$lib/components/ExportReportModal.svelte";
    import {
        highlightCode,
        copyToClipboard,
    } from "../logic";
    import {
        getCWEData,
        getCVSSColor,
        getSeverityBorderColor,
        getSeverityGlow,
    } from "$lib/data/cwe-reference";

    // ── Types ────────────────────────────────────────────────────────────────
    interface FunctionRow {
        id: number | null;
        function_name: string;
        code: string;
        verdict: string;
        cwe: string | null;
        cwe_name: string | null;
        asvs_id: string | null;
        severity: string | null;
        confidence: number | null;
        start_line: number | null;
        end_line: number | null;
        file_path: string;
    }

    interface PagedFunctions {
        total: number;
        limit: number;
        offset: number;
        functions: FunctionRow[];
    }

    // ── State ────────────────────────────────────────────────────────────────
    let error = $state("");
    let loading = $state(true);
    let isLoading = $state(false);
    let exportModalOpen = $state(false);

    // Pagination
    let currentPage = $state(1);
    let pageSize = $state(50);
    let totalCount = $state(0);
    let totalPages = $derived(Math.max(1, Math.ceil(totalCount / pageSize)));
    let pageStart = $derived(
        totalCount === 0 ? 0 : (currentPage - 1) * pageSize + 1,
    );
    let pageEnd = $derived(Math.min(currentPage * pageSize, totalCount));

    // Data (current page slice)
    let pagedFunctions = $state<FunctionRow[]>([]);

    // UI state
    let expandedIds = $state(new Set<number>());
    let expandedFiles = $state(new Set<string>());
    let copiedId = $state<number | null>(null);
    let searchTerm = $state("");
    let filterVerdict = $state<"all" | "vulnerable" | "safe">("all");
    let sortBy = $state<"severity" | "name" | "line">("severity");
    let viewMode = $state<"function" | "file">("function");

    // ── Derived ──────────────────────────────────────────────────────────────
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

    let groupedByFile = $derived.by(() => {
        const g: Record<string, FunctionRow[]> = {};
        for (const fn of pagedFunctions) {
            if (!g[fn.file_path]) g[fn.file_path] = [];
            g[fn.file_path].push(fn);
        }
        return g;
    });

    // Whether the page looks like a multi-file (folder) analysis.
    let isFolder = $derived(Object.keys(groupedByFile).length > 1);

    let codeBg = $derived($theme === "dark" ? "#1a1b26" : "#f8f8f8");

    // ── Data fetching ────────────────────────────────────────────────────────
    async function loadPage(pageNumber: number) {
        isLoading = true;
        expandedIds = new Set(); // collapse all on page turn
        try {
            const analysisId = parseInt($page.params.id ?? "0");
            const result = await invoke<PagedFunctions>("search_functions", {
                analysisId,
                searchTerm: searchTerm || null,
                verdictFilter: filterVerdict,
                sortBy: sortBy,
                limit: pageSize,
                offset: (pageNumber - 1) * pageSize,
            });
            pagedFunctions = result.functions;
            totalCount = result.total;
            currentPage = pageNumber;
            window.scrollTo({ top: 0, behavior: "smooth" });
        } catch (e: any) {
            console.error("Failed to load report functions page", e);
            error = e.message ?? String(e);
        } finally {
            isLoading = false;
        }
    }

    async function goToPage(pg: number) {
        if (isLoading || pg < 1 || pg > totalPages || pg === currentPage)
            return;
        await loadPage(pg);
    }

    // ── UI helpers ───────────────────────────────────────────────────────────
    function toggleExpand(id: number | null) {
        if (id == null) return;
        const n = new Set(expandedIds);
        n.has(id) ? n.delete(id) : n.add(id);
        expandedIds = n;
    }

    function toggleFile(path: string) {
        const n = new Set(expandedFiles);
        n.has(path) ? n.delete(path) : n.add(path);
        expandedFiles = n;
    }

    async function handleCopy(fn: FunctionRow) {
        await copyToClipboard(fn.code ?? "");
        copiedId = fn.id;
        setTimeout(() => (copiedId = null), 2000);
    }

    function complianceBadges(fn: FunctionRow) {
        return [
            { label: "ASVS", value: fn.asvs_id },
        ].filter((item): item is { label: string; value: string } =>
            Boolean(item.value),
        );
    }

    let debounceTimer: any = null;

    $effect(() => {
        let currentSearch = searchTerm;
        let currentVerdict = filterVerdict;
        let currentSort = sortBy;
        if (!loading) {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                loadPage(1);
            }, 300);
        }
    });

    // ── Lifecycle ────────────────────────────────────────────────────────────
    onMount(async () => {
        try {
            await loadPage(1);
        } catch (e: any) {
            console.error("Failed to load report details", e);
            error = e.message ?? String(e);
        } finally {
            loading = false;
        }
    });
</script>

<svelte:head>
    {#if $theme === "dark"}
        <link
            rel="stylesheet"
            href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.min.css"
        />
    {:else}
        <link
            rel="stylesheet"
            href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-light.min.css"
        />
    {/if}
</svelte:head>

{#if loading}
    <div class="min-h-screen" style="background:var(--bg)">
        <div
            class="h-14 flex items-center gap-3 px-4"
            style="background:var(--surface);border-bottom:1px solid var(--border)"
        >
            <div class="skeleton h-7 w-24 rounded-lg"></div>
            <div class="flex-1 skeleton h-8 rounded-xl"></div>
            <div class="skeleton h-7 w-48 rounded-lg"></div>
        </div>
        <div class="max-w-6xl mx-auto px-6 py-4 space-y-2">
            {#each Array(6) as _}
                <div class="card p-4">
                    <div class="skeleton h-4 w-48 mb-2"></div>
                    <div class="skeleton h-3 w-72"></div>
                </div>
            {/each}
        </div>
    </div>
{:else if error}
    <div
        class="min-h-screen flex items-center justify-center"
        style="background:var(--bg)"
    >
        <p class="text-xs" style="color:var(--danger)">{error}</p>
    </div>
{:else}
    <div
        class="min-h-screen flex flex-col"
        style="background:var(--bg);color:var(--text)"
    >
        <!-- Sticky toolbar -->
        <div
            class="sticky top-0 z-10 px-4 py-2.5 flex items-center gap-2 flex-wrap"
            style="background:var(--surface);border-bottom:1px solid var(--border)"
        >
            <a href="/report/{$page.params.id}" class="btn-ghost shrink-0">
                <ArrowLeft size={12} />Summary
            </a>

            <div
                class="w-px h-5 shrink-0"
                style="background:var(--border)"
            ></div>

            <!-- Search -->
            <div
                class="flex items-center gap-2 flex-1 min-w-[180px] rounded-xl px-3 py-1.5"
                style="background:var(--surface-2);border:1px solid var(--border)"
            >
                <Search size={12} color="var(--muted)" />
                <input
                    type="text"
                    bind:value={searchTerm}
                    placeholder="Search functions, CWEs, files..."
                    class="flex-1 bg-transparent text-xs outline-none"
                    style="color:var(--text)"
                />
                {#if searchTerm}
                    <button
                        onclick={() => (searchTerm = "")}
                        style="color:var(--muted)"
                    >
                        <X size={11} />
                    </button>
                {/if}
            </div>

            <!-- Verdict filter -->
            <div
                class="flex rounded-lg overflow-hidden shrink-0"
                style="border:1px solid var(--border)"
            >
                {#each [["all", "All"], ["vulnerable", "Vuln"], ["safe", "Safe"]] as [v, label]}
                    <button
                        class="px-3 py-1.5 text-xs transition-colors"
                        style={filterVerdict === v
                            ? "background:var(--accent);color:#fff"
                            : "background:var(--surface-2);color:var(--muted)"}
                        onclick={() =>
                            (filterVerdict = v as typeof filterVerdict)}
                    >
                        {label}
                    </button>
                {/each}
            </div>

            <!-- Sort -->
            <select
                bind:value={sortBy}
                class="text-xs rounded-lg px-2 py-1.5 outline-none shrink-0 cursor-pointer"
                style="background:var(--surface-2);border:1px solid var(--border);color:var(--text)"
            >
                <option value="severity">Severity</option>
                <option value="name">Name A–Z</option>
                <option value="line">Line #</option>
            </select>

            <!-- View mode toggle — only folders -->
            {#if isFolder}
                <div
                    class="flex rounded-lg overflow-hidden shrink-0"
                    style="border:1px solid var(--border)"
                >
                    <button
                        class="px-2.5 py-1.5 transition-colors"
                        style={viewMode === "function"
                            ? "background:var(--accent-dim);color:var(--accent)"
                            : "background:var(--surface-2);color:var(--muted)"}
                        onclick={() => (viewMode = "function")}
                        title="By Function"
                    >
                        <LayoutList size={13} />
                    </button>
                    <button
                        class="px-2.5 py-1.5 transition-colors"
                        style={viewMode === "file"
                            ? "background:var(--accent-dim);color:var(--accent)"
                            : "background:var(--surface-2);color:var(--muted)"}
                        onclick={() => (viewMode = "file")}
                        title="By File"
                    >
                        <FolderOpen size={13} />
                    </button>
                </div>
            {/if}

            <button
                type="button"
                onclick={() => (exportModalOpen = true)}
                class="btn-primary shrink-0"
            >
                <Download size={12} />Export Report
            </button>

            <span
                class="text-xs shrink-0 tabular-nums"
                style="color:var(--muted)"
            >
                {pagedFunctions.length} on page / {totalCount} total
            </span>
        </div>

        <!-- Content -->
        <div class="flex-1 overflow-y-auto">
            <div id="fn-list-top" class="max-w-6xl mx-auto px-6 py-4">
                {#if isLoading}
                    <div class="space-y-2">
                        {#each Array(6) as _}
                            <div
                                class="card p-4 overflow-hidden"
                                style="border-left:3px solid var(--border)"
                            >
                                <div class="flex items-center gap-3">
                                    <div
                                        class="skeleton h-2.5 w-2.5 rounded-full shrink-0"
                                    ></div>
                                    <div class="flex-1 min-w-0">
                                        <div
                                            class="skeleton h-4 w-56 max-w-full mb-2"
                                        ></div>
                                        <div
                                            class="skeleton h-3 w-80 max-w-full"
                                        ></div>
                                    </div>
                                    <div class="skeleton h-7 w-20 rounded-lg"></div>
                                </div>
                            </div>
                        {/each}
                    </div>
                {:else if pagedFunctions.length === 0}
                    <div class="text-center mt-20">
                        <p class="text-sm mb-2" style="color:var(--muted)">
                            No functions match.
                        </p>
                        <button
                            onclick={() => {
                                searchTerm = "";
                                filterVerdict = "all";
                            }}
                            class="text-xs"
                            style="color:var(--accent)">Clear filters</button
                        >
                    </div>

                    <!-- ── By Function (flat list) ── -->
                {:else if viewMode === "function" || !isFolder}
                    <div class="space-y-2">
                        {#each pagedFunctions as fn (fn.id)}
                            {@const isExp =
                                fn.id != null && expandedIds.has(fn.id)}
                            {@const color =
                                fn.verdict === "vulnerable"
                                    ? (SEVERITY_COLORS[fn.severity ?? ""] ??
                                      "#ef4444")
                                    : "var(--success)"}

                            <div
                                class="card overflow-hidden"
                                style="border-left:3px solid {color}"
                            >
                                <!-- Card header -->
                                <button
                                    class="w-full text-left px-4 py-3.5 flex items-center gap-3 transition-colors"
                                    style={isExp
                                        ? "background:var(--surface-2)"
                                        : ""}
                                    onclick={() => toggleExpand(fn.id)}
                                    onmouseenter={(e) => {
                                        if (!isExp)
                                            e.currentTarget.style.background =
                                                "var(--surface-2)";
                                    }}
                                    onmouseleave={(e) => {
                                        if (!isExp)
                                            e.currentTarget.style.background =
                                                "transparent";
                                    }}
                                >
                                    <div
                                        class="{fn.verdict === 'vulnerable'
                                            ? 'dot-danger'
                                            : 'dot-success'} shrink-0"
                                    ></div>

                                    <div class="flex-1 min-w-0">
                                        <div
                                            class="flex items-center gap-2 flex-wrap"
                                        >
                                            <span
                                                class="text-sm font-semibold mono"
                                                style="color:var(--text)"
                                                >{fn.function_name}</span
                                            >
                                            {#if fn.verdict === "vulnerable" && fn.cwe}
                                                <span
                                                    class="text-xs font-bold mono"
                                                    style="color:{color}"
                                                    >{fn.cwe}</span
                                                >
                                                <span
                                                    class="px-1.5 py-0.5 rounded font-semibold"
                                                    style="background:{color}20;color:{color};font-size:10px"
                                                    >{fn.severity}</span
                                                >
                                                {#each complianceBadges(fn) as standard}
                                                    <span
                                                        class="px-1.5 py-0.5 rounded font-semibold"
                                                        title="{standard.label}: {standard.value}"
                                                        style="background:var(--surface-2);border:1px solid var(--border);color:var(--muted);font-size:10px"
                                                        >{standard.value}</span
                                                    >
                                                {/each}
                                            {:else}
                                                <span
                                                    class="px-1.5 py-0.5 rounded font-semibold"
                                                    style="background:var(--success-dim);color:var(--success);font-size:10px"
                                                    >Clean</span
                                                >
                                            {/if}
                                        </div>
                                        <p
                                            class="text-xs mt-0.5 mono truncate"
                                            style="color:var(--muted)"
                                        >
                                            {(fn.file_path ?? "")
                                                .replace(/\\/g, "/")
                                                .split("/")
                                                .pop()}
                                            · lines {fn.start_line}–{fn.end_line}
                                            {#if isFolder}<span
                                                    style="color:var(--subtle)"
                                                >
                                                    · {fn.file_path}</span
                                                >{/if}
                                        </p>
                                    </div>

                                    <div
                                        style="color:var(--muted);transform:{isExp
                                            ? 'rotate(180deg)'
                                            : 'rotate(0)'};transition:transform 0.2s"
                                    >
                                        <ChevronDown size={14} />
                                    </div>
                                </button>

                                <!-- Expanded -->
                                {#if isExp}
                                    {@const fnLines = (fn.code ?? "").split(
                                        "\n",
                                    )}
                                    <div
                                        style="border-top:1px solid var(--border)"
                                        class="animate-fade-in"
                                    >
                                        <!-- Code viewer -->
                                        <div
                                            style="border-bottom:1px solid var(--border)"
                                        >
                                            <div
                                                class="flex items-center justify-between px-4 py-2"
                                                style="background:var(--surface-2)"
                                            >
                                                <span
                                                    class="text-xs mono"
                                                    style="color:var(--muted)"
                                                    >C++</span
                                                >
                                                <button
                                                    onclick={() =>
                                                        handleCopy(fn)}
                                                    class="flex items-center gap-1.5 text-xs transition-colors"
                                                    style="color:var(--muted)"
                                                >
                                                    {#if copiedId === fn.id}
                                                        <Check
                                                            size={11}
                                                            color="var(--success)"
                                                        />
                                                        <span
                                                            style="color:var(--success)"
                                                            >Copied!</span
                                                        >
                                                    {:else}
                                                        <Copy size={11} />Copy
                                                    {/if}
                                                </button>
                                            </div>
                                            <div
                                                class="flex overflow-x-auto text-xs mono"
                                                style="background:{codeBg};max-height:320px"
                                            >
                                                <div
                                                    class="select-none text-right px-3 py-4 leading-6 shrink-0"
                                                    style="color:var(--subtle);border-right:1px solid var(--border);min-width:2.5rem"
                                                >
                                                    {#each fnLines as _, i}<div>
                                                            {(fn.start_line ??
                                                                0) + i}
                                                        </div>{/each}
                                                </div>
                                                <pre
                                                    class="flex-1 py-4 px-4 leading-6 overflow-x-auto m-0"><code
                                                        >{@html highlightCode(
                                                            fn.code ?? "",
                                                        )}</code
                                                    ></pre>
                                            </div>
                                        </div>

                                        <!-- CWE panel -->
                                        {#if fn.cwe}
                                            {@const cweList =
                                                typeof fn.cwe === "string" &&
                                                fn.cwe.startsWith("[")
                                                    ? JSON.parse(fn.cwe)
                                                    : fn.cwe
                                                      ? [fn.cwe]
                                                      : []}

                                            <div class="p-4 space-y-6">
                                                {#each cweList as cweCode}
                                                    {@const data =
                                                        getCWEData(cweCode)}
                                                    {#if data}
                                                        {@const cvssCol =
                                                            getCVSSColor(
                                                                data.cvss_score,
                                                            )}
                                                        {@const sevCol =
                                                            getSeverityBorderColor(
                                                                data.cvss_severity,
                                                            )}
                                                        <!-- now uses per-CWE severity -->

                                                        <div
                                                            class="rounded-xl overflow-hidden"
                                                            style="border:1px solid {sevCol}44"
                                                        >
                                                            <div
                                                                class="px-4 py-3 flex items-start gap-3"
                                                                style="background:{getSeverityGlow(
                                                                    data.cvss_severity,
                                                                )};border-bottom:1px solid {sevCol}33"
                                                            >
                                                                <div
                                                                    class="flex-1"
                                                                >
                                                                    <div
                                                                        class="flex items-center gap-2 mb-0.5"
                                                                    >
                                                                        <span
                                                                            class="text-xs font-bold mono"
                                                                            style="color:{sevCol}"
                                                                            >{cweCode}</span
                                                                        >
                                                                    <span
                                                                        class="px-1.5 py-0.5 rounded font-semibold"
                                                                        style="background:{sevCol}22;color:{sevCol};font-size:10px"
                                                                    >
                                                                        {data.cvss_severity}
                                                                    </span>
                                                                    {#each complianceBadges(fn) as standard}
                                                                        <span
                                                                            class="px-1.5 py-0.5 rounded font-semibold"
                                                                            title="{standard.label}: {standard.value}"
                                                                            style="background:var(--surface-2);border:1px solid var(--border);color:var(--muted);font-size:10px"
                                                                            >{standard.value}</span
                                                                        >
                                                                    {/each}
                                                                </div>
                                                                    <p
                                                                        class="text-xs font-semibold"
                                                                        style="color:var(--text)"
                                                                    >
                                                                        {data.name}
                                                                    </p>
                                                                    <p
                                                                        class="text-xs mt-0.5 leading-relaxed"
                                                                        style="color:var(--muted)"
                                                                    >
                                                                        {data.description}
                                                                    </p>
                                                                </div>
                                                                <div
                                                                    class="w-11 h-11 rounded-xl flex flex-col items-center justify-center shrink-0"
                                                                    style="background:{cvssCol}18;border:1px solid {cvssCol}44"
                                                                >
                                                                    <p
                                                                        class="font-bold tabular-nums"
                                                                        style="color:{cvssCol};font-size:13px;line-height:1.1"
                                                                    >
                                                                        {data.cvss_score}
                                                                    </p>
                                                                    <p
                                                                        style="color:{cvssCol};font-size:7px;font-weight:600"
                                                                    >
                                                                        {data.cvss_severity}
                                                                    </p>
                                                                </div>
                                                            </div>
                                                            <div
                                                                class="px-4 py-3"
                                                                style="background:var(--surface)"
                                                            >
                                                                <p
                                                                    class="text-xs font-semibold uppercase tracking-wider mb-2"
                                                                    style="color:var(--muted)"
                                                                >
                                                                    Attack
                                                                    Scenario
                                                                </p>
                                                                <p
                                                                    class="text-xs leading-relaxed mb-3"
                                                                    style="color:var(--text)"
                                                                >
                                                                    {data.scenario}
                                                                </p>
                                                                <p
                                                                    class="text-xs font-semibold uppercase tracking-wider mb-2"
                                                                    style="color:var(--muted)"
                                                                >
                                                                    Mitigations
                                                                </p>
                                                                <div
                                                                    class="space-y-1.5"
                                                                >
                                                                    {#each data.mitigations as m}
                                                                        <div
                                                                            class="flex items-start gap-2"
                                                                        >
                                                                            <span
                                                                                style="color:var(--success);font-size:10px;flex-shrink:0;margin-top:1px"
                                                                                >✓</span
                                                                            >
                                                                            <p
                                                                                class="text-xs leading-relaxed"
                                                                                style="color:var(--text)"
                                                                            >
                                                                                {m}
                                                                            </p>
                                                                        </div>
                                                                    {/each}
                                                                </div>
                                                            </div>
                                                        </div>
                                                    {/if}
                                                {/each}
                                            </div>
                                        {/if}
                                    </div>
                                {/if}
                            </div>
                        {/each}
                    </div>

                    <!-- ── By File (folder accordion) ── -->
                {:else}
                    <div class="space-y-3">
                        {#each Object.entries(groupedByFile) as [filePath, fns]}
                            {@const fileVulns = fns.filter(
                                (f) => f.verdict === "vulnerable",
                            ).length}
                            {@const isFileExp = expandedFiles.has(filePath)}
                            {@const fileName =
                                filePath.replace(/\\/g, "/").split("/").pop() ??
                                filePath}

                            <div class="card overflow-hidden">
                                <!-- File header -->
                                <button
                                    class="w-full flex items-center gap-3 px-4 py-3 transition-colors"
                                    style={isFileExp
                                        ? "background:var(--surface-2);border-bottom:1px solid var(--border)"
                                        : ""}
                                    onclick={() => toggleFile(filePath)}
                                    onmouseenter={(e) =>
                                        (e.currentTarget.style.background =
                                            "var(--surface-2)")}
                                    onmouseleave={(e) => {
                                        if (!isFileExp)
                                            e.currentTarget.style.background =
                                                "transparent";
                                    }}
                                >
                                    <FolderOpen
                                        size={14}
                                        color="var(--muted)"
                                    />

                                    <div class="flex-1 min-w-0 text-left">
                                        <p class="text-xs font-semibold">
                                            {fileName}
                                        </p>
                                        <p
                                            class="text-xs mono truncate mt-0.5"
                                            style="color:var(--subtle)"
                                        >
                                            {filePath}
                                        </p>
                                    </div>

                                    <div
                                        class="flex items-center gap-2 shrink-0"
                                    >
                                        <span
                                            class="text-xs tabular-nums"
                                            style="color:var(--muted)"
                                            >{fns.length} fn</span
                                        >
                                        {#if fileVulns > 0}
                                            <span
                                                class="px-2 py-0.5 rounded-full text-xs font-semibold"
                                                style="background:var(--danger-dim);color:var(--danger)"
                                                >{fileVulns} vuln</span
                                            >
                                        {:else}
                                            <span
                                                class="px-2 py-0.5 rounded-full text-xs font-semibold"
                                                style="background:var(--success-dim);color:var(--success)"
                                                >Clean</span
                                            >
                                        {/if}
                                        <div
                                            style="color:var(--muted);transform:{isFileExp
                                                ? 'rotate(180deg)'
                                                : 'none'};transition:transform 0.2s"
                                        >
                                            <ChevronDown size={13} />
                                        </div>
                                    </div>
                                </button>

                                <!-- Functions in file -->
                                {#if isFileExp}
                                    <div
                                        class="divide-y"
                                        style="border-color:var(--border)"
                                    >
                                        {#each fns as fn (fn.id)}
                                            {@const isExp =
                                                fn.id != null &&
                                                expandedIds.has(fn.id)}
                                            {@const color =
                                                fn.verdict === "vulnerable"
                                                    ? (SEVERITY_COLORS[
                                                          fn.severity ?? ""
                                                      ] ?? "#ef4444")
                                                    : "var(--success)"}

                                            <div
                                                style="border-top:1px solid var(--border);border-left:3px solid {color}"
                                            >
                                                <button
                                                    class="w-full text-left px-4 py-3 flex items-center gap-3 transition-colors"
                                                    onclick={() =>
                                                        toggleExpand(fn.id)}
                                                    onmouseenter={(e) =>
                                                        (e.currentTarget.style.background =
                                                            "var(--surface-2)")}
                                                    onmouseleave={(e) => {
                                                        if (!isExp)
                                                            e.currentTarget.style.background =
                                                                "transparent";
                                                    }}
                                                >
                                                    <div
                                                        class="{fn.verdict ===
                                                        'vulnerable'
                                                            ? 'dot-danger'
                                                            : 'dot-success'} shrink-0"
                                                    ></div>

                                                    <div class="flex-1 min-w-0">
                                                        <div
                                                            class="flex items-center gap-2 flex-wrap"
                                                        >
                                                            <span
                                                                class="text-xs font-semibold mono"
                                                                style="color:var(--text)"
                                                                >{fn.function_name}</span
                                                            >
                                                            {#if fn.verdict === "vulnerable" && fn.cwe}
                                                                <span
                                                                    class="text-xs font-bold mono"
                                                                    style="color:{color}"
                                                                    >{fn.cwe}</span
                                                                >
                                                                <span
                                                                    class="px-1.5 py-0.5 rounded font-semibold"
                                                                    style="background:{color}20;color:{color};font-size:10px"
                                                                    >{fn.severity}</span
                                                                >
                                                                {#each complianceBadges(fn) as standard}
                                                                    <span
                                                                        class="px-1.5 py-0.5 rounded font-semibold"
                                                                        title="{standard.label}: {standard.value}"
                                                                        style="background:var(--surface-2);border:1px solid var(--border);color:var(--muted);font-size:10px"
                                                                        >{standard.value}</span
                                                                    >
                                                                {/each}
                                                            {:else}
                                                                <span
                                                                    class="px-1.5 py-0.5 rounded font-semibold"
                                                                    style="background:var(--success-dim);color:var(--success);font-size:10px"
                                                                    >Clean</span
                                                                >
                                                            {/if}
                                                        </div>
                                                        <p
                                                            class="text-xs mt-0.5 mono"
                                                            style="color:var(--muted)"
                                                        >
                                                            lines {fn.start_line}–{fn.end_line}
                                                        </p>
                                                    </div>

                                                    <div
                                                        style="color:var(--muted);transform:{isExp
                                                            ? 'rotate(180deg)'
                                                            : 'none'};transition:transform 0.2s"
                                                    >
                                                        <ChevronDown
                                                            size={13}
                                                        />
                                                    </div>
                                                </button>

                                                <!-- Expanded -->
                                                {#if isExp}
                                                    {@const fnLines = (
                                                        fn.code ?? ""
                                                    ).split("\n")}
                                                    <div
                                                        style="border-top:1px solid var(--border)"
                                                        class="animate-fade-in"
                                                    >
                                                        <div
                                                            style="border-bottom:1px solid var(--border)"
                                                        >
                                                            <div
                                                                class="flex items-center justify-between px-4 py-2"
                                                                style="background:var(--surface-2)"
                                                            >
                                                                <span
                                                                    class="text-xs mono"
                                                                    style="color:var(--muted)"
                                                                    >C++</span
                                                                >
                                                                <button
                                                                    onclick={() =>
                                                                        handleCopy(
                                                                            fn,
                                                                        )}
                                                                    class="flex items-center gap-1.5 text-xs"
                                                                    style="color:var(--muted)"
                                                                >
                                                                    {#if copiedId === fn.id}
                                                                        <Check
                                                                            size={11}
                                                                            color="var(--success)"
                                                                        />
                                                                        <span
                                                                            style="color:var(--success)"
                                                                            >Copied!</span
                                                                        >
                                                                    {:else}
                                                                        <Copy
                                                                            size={11}
                                                                        />Copy
                                                                    {/if}
                                                                </button>
                                                            </div>
                                                            <div
                                                                class="flex overflow-x-auto text-xs mono"
                                                                style="background:{codeBg};max-height:280px"
                                                            >
                                                                <div
                                                                    class="select-none text-right px-3 py-4 leading-6 shrink-0"
                                                                    style="color:var(--subtle);border-right:1px solid var(--border);min-width:2.5rem"
                                                                >
                                                                    {#each fnLines as _, i}<div
                                                                        >
                                                                            {(fn.start_line ??
                                                                                0) +
                                                                                i}
                                                                        </div>{/each}
                                                                </div>
                                                                <pre
                                                                    class="flex-1 py-4 px-4 leading-6 overflow-x-auto m-0"><code
                                                                        >{@html highlightCode(
                                                                            fn.code ??
                                                                                "",
                                                                        )}</code
                                                                    ></pre>
                                                            </div>
                                                        </div>

                                                        {#if fn.cwe}
                                                            {@const cweData =
                                                                getCWEData(
                                                                    fn.cwe,
                                                                )}
                                                            {#if cweData}
                                                                {@const cvssCol =
                                                                    getCVSSColor(
                                                                        cweData.cvss_score,
                                                                    )}
                                                                {@const sevCol =
                                                                    getSeverityBorderColor(
                                                                        fn.severity,
                                                                    )}
                                                                <div
                                                                    class="p-4"
                                                                >
                                                                    <div
                                                                        class="rounded-xl overflow-hidden"
                                                                        style="border:1px solid {sevCol}44"
                                                                    >
                                                                        <div
                                                                            class="px-4 py-3 flex items-start gap-3"
                                                                            style="background:{getSeverityGlow(
                                                                                fn.severity,
                                                                            )};border-bottom:1px solid {sevCol}33"
                                                                        >
                                                                            <div
                                                                                class="flex-1"
                                                                            >
                                                                                <div
                                                                                    class="flex items-center gap-2 mb-0.5"
                                                                                >
                                                                                    <span
                                                                                        class="text-xs font-bold mono"
                                                                                        style="color:{sevCol}"
                                                                                        >{fn.cwe}</span
                                                                                    >
                                                                                    <span
                                                                                        class="px-1.5 py-0.5 rounded font-semibold"
                                                                                        style="background:{sevCol}22;color:{sevCol};font-size:10px"
                                                                                        >{fn.severity}</span
                                                                                    >
                                                                                    {#each complianceBadges(fn) as standard}
                                                                                        <span
                                                                                            class="px-1.5 py-0.5 rounded font-semibold"
                                                                                            title="{standard.label}: {standard.value}"
                                                                                            style="background:var(--surface-2);border:1px solid var(--border);color:var(--muted);font-size:10px"
                                                                                            >{standard.value}</span
                                                                                        >
                                                                                    {/each}
                                                                                </div>
                                                                                <p
                                                                                    class="text-xs font-semibold"
                                                                                    style="color:var(--text)"
                                                                                >
                                                                                    {cweData.name}
                                                                                </p>
                                                                            </div>
                                                                            <div
                                                                                class="w-11 h-11 rounded-xl flex flex-col items-center justify-center shrink-0"
                                                                                style="background:{cvssCol}18;border:1px solid {cvssCol}44"
                                                                            >
                                                                                <p
                                                                                    class="font-bold tabular-nums"
                                                                                    style="color:{cvssCol};font-size:13px;line-height:1.1"
                                                                                >
                                                                                    {cweData.cvss_score}
                                                                                </p>
                                                                                <p
                                                                                    style="color:{cvssCol};font-size:7px;font-weight:600"
                                                                                >
                                                                                    {cweData.cvss_severity}
                                                                                </p>
                                                                            </div>
                                                                        </div>
                                                                        <div
                                                                            class="px-4 py-3"
                                                                            style="background:var(--surface)"
                                                                        >
                                                                            <div
                                                                                class="space-y-1 mb-3"
                                                                            >
                                                                                {#each cweData.mitigations as m}
                                                                                    <div
                                                                                        class="flex items-start gap-2"
                                                                                    >
                                                                                        <span
                                                                                            style="color:var(--success);font-size:10px;flex-shrink:0;margin-top:1px"
                                                                                            >✓</span
                                                                                        >
                                                                                        <p
                                                                                            class="text-xs leading-relaxed"
                                                                                            style="color:var(--text)"
                                                                                        >
                                                                                            {m}
                                                                                        </p>
                                                                                    </div>
                                                                                {/each}
                                                                            </div>
                                                                            <div
                                                                                class="flex items-center gap-2 rounded-lg px-3 py-2"
                                                                                style="background:var(--surface-2);border:1px solid var(--border)"
                                                                            >
                                                                                <span
                                                                                    class="text-xs"
                                                                                    style="color:var(--muted)"
                                                                                    >Vector:</span
                                                                                >
                                                                                <span
                                                                                    class="text-xs mono flex-1 truncate"
                                                                                    style="color:var(--subtle)"
                                                                                    >{cweData.cvss_vector}</span
                                                                                >
                                                                                <a
                                                                                    href="https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector={cweData.cvss_vector}"
                                                                                    target="_blank"
                                                                                    rel="noopener"
                                                                                    class="text-xs shrink-0"
                                                                                    style="color:var(--accent)"
                                                                                    >NIST
                                                                                    ↗</a
                                                                                >
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            {/if}
                                                        {/if}
                                                    </div>
                                                {/if}
                                            </div>
                                        {/each}
                                    </div>
                                {/if}
                            </div>
                        {/each}
                    </div>
                {/if}

                {#if totalCount > 0}
                    <div
                        class="mt-6 mb-4 flex flex-col sm:flex-row items-center justify-between gap-3 rounded-xl px-4 py-3"
                        style="background:var(--surface);border:1px solid var(--border)"
                    >
                        <p
                            class="text-xs tabular-nums text-center sm:text-left"
                            style="color:var(--muted)"
                        >
                            Showing {pageStart}-{pageEnd} of {totalCount} functions
                        </p>

                        <div class="flex items-center gap-2">
                            <button
                                onclick={() => goToPage(currentPage - 1)}
                                disabled={currentPage === 1 || isLoading}
                                class="inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-all hover:brightness-110 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-45 disabled:hover:brightness-100 disabled:active:scale-100"
                                style="background:var(--surface-2);border-color:var(--border);color:var(--text)"
                            >
                                <ChevronLeft size={13} />
                                Previous
                            </button>

                            <span
                                class="min-w-28 rounded-lg px-3 py-1.5 text-center text-xs tabular-nums"
                                style="background:var(--bg);border:1px solid var(--border);color:var(--muted)"
                            >
                                Page {currentPage} of {totalPages}
                            </span>

                            <button
                                onclick={() => goToPage(currentPage + 1)}
                                disabled={currentPage * pageSize >= totalCount ||
                                    isLoading}
                                class="inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-all hover:brightness-110 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-45 disabled:hover:brightness-100 disabled:active:scale-100"
                                style="background:var(--surface-2);border-color:var(--border);color:var(--text)"
                            >
                                Next
                                <ChevronRight size={13} />
                            </button>
                        </div>
                    </div>
                {/if}
            </div>
        </div>

        <ExportReportModal
            analysisId={$page.params.id ?? "0"}
            open={exportModalOpen}
            onClose={() => (exportModalOpen = false)}
        />
    </div>
{/if}
