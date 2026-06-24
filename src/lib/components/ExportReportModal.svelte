<script lang="ts">
    import { invoke } from "@tauri-apps/api/core";
    import { listen } from "@tauri-apps/api/event";
    import { fade, scale, slide } from "svelte/transition";
    import {
        CheckCircle2,
        ChevronDown,
        FileJson,
        FileText,
        FolderOpen,
        Loader2,
        Table,
        X,
    } from "lucide-svelte";
    import { success, error as errorToast } from "$lib/utils/toast";

    type ExportFormat = "pdf_technical" | "pdf_executive" | "sarif" | "csv";

    interface ExportOption {
        value: ExportFormat;
        label: string;
        description: string;
        extension: "pdf" | "sarif" | "csv";
        icon: typeof FileText;
    }

    interface Props {
        analysisId: string;
        open: boolean;
        onClose: () => void;
    }

    let { analysisId, open, onClose }: Props = $props();

    const exportOptions: ExportOption[] = [
        {
            value: "pdf_technical",
            label: "PDF (Technical)",
            description: "Detailed findings with code-level context.",
            extension: "pdf",
            icon: FileText,
        },
        {
            value: "pdf_executive",
            label: "PDF (Executive)",
            description: "Summary metrics for stakeholder review.",
            extension: "pdf",
            icon: FileText,
        },
        {
            value: "sarif",
            label: "SARIF",
            description: "Security tooling integration format.",
            extension: "sarif",
            icon: FileJson,
        },
        {
            value: "csv",
            label: "CSV",
            description: "Spreadsheet-ready vulnerability table.",
            extension: "csv",
            icon: Table,
        },
    ];

    let selectedFormat = $state<ExportFormat>("pdf_technical");
    let selectedPath = $state("");
    let isExporting = $state(false);
    let errorMessage = $state("");
    let previousFormat = $state<ExportFormat>("pdf_technical");
    let exportProgress = $state("Preparing export...");
    let pdfSettingsOpen = $state(true);
    let maxFindings = $state(100);
    let includeSourceCode = $state(true);

    let selectedOption = $derived(
        exportOptions.find((option) => option.value === selectedFormat) ??
            exportOptions[0],
    );

    $effect(() => {
        if (selectedFormat !== previousFormat) {
            selectedPath = "";
            errorMessage = "";
            previousFormat = selectedFormat;
        }
    });

    function defaultFileName(option: ExportOption) {
        const tier =
            option.value === "pdf_executive"
                ? "executive"
                : option.value === "pdf_technical"
                  ? "technical"
                  : option.value;
        return `c-cure-${tier}-report-${analysisId}.${option.extension}`;
    }

    function withExpectedExtension(path: string, extension: string) {
        const normalized = path.toLowerCase();
        return normalized.endsWith(`.${extension}`)
            ? path
            : `${path}.${extension}`;
    }

    async function choosePath() {
        if (isExporting) return;

        errorMessage = "";
        try {
            const { save } = await import("@tauri-apps/plugin-dialog");
            const filePath = await save({
                defaultPath: defaultFileName(selectedOption),
                filters: [
                    {
                        name: selectedOption.label,
                        extensions: [selectedOption.extension],
                    },
                ],
            });

            if (filePath) {
                selectedPath = withExpectedExtension(
                    filePath,
                    selectedOption.extension,
                );
            }
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            errorMessage = `Could not choose export destination: ${message}`;
            console.error("Failed to choose export destination", err);
            errorToast(errorMessage);
        }
    }

    async function runExport() {
        if (isExporting) return;

        errorMessage = "";
        let targetPath = selectedPath;
        let unlistenProgress: (() => void) | undefined;

        try {
            if (!targetPath) {
                await choosePath();
                targetPath = selectedPath;
            }

            if (!targetPath) return;

            isExporting = true;
            exportProgress = "Starting export...";

            unlistenProgress = await listen<string>("export-progress", (event) => {
                exportProgress = event.payload;
            });

            await invoke("export_report", {
                analysisId: parseInt(analysisId),
                format: selectedFormat,
                filePath: targetPath,
                executiveSummaryOnly: selectedFormat === "pdf_executive",
                maxFindings:
                    selectedFormat === "pdf_technical" ? maxFindings : null,
                includeSourceCode:
                    selectedFormat === "pdf_technical"
                        ? includeSourceCode
                        : null,
            });

            success(`${selectedOption.label} exported successfully.`);
            selectedPath = "";
            onClose();
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            errorMessage = `Export failed: ${message}`;
            console.error("Failed to export report", err);
            errorToast(errorMessage);
        } finally {
            unlistenProgress?.();
            isExporting = false;
            exportProgress = "Preparing export...";
        }
    }

    function close() {
        if (!isExporting) {
            errorMessage = "";
            onClose();
        }
    }
</script>

{#if open}
    <div class="fixed inset-0 z-[70] flex items-center justify-center px-4">
        <button
            type="button"
            class="absolute inset-0 cursor-default bg-black/65 backdrop-blur-sm"
            aria-label="Close export dialog"
            disabled={isExporting}
            onclick={close}
            transition:fade={{ duration: 150 }}
        ></button>

        <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="export-dialog-title"
            class="relative w-full max-w-lg overflow-hidden rounded-2xl shadow-2xl"
            style="background:var(--surface);border:1px solid var(--border);color:var(--text)"
            transition:scale={{ duration: 180, start: 0.96 }}
        >
            {#if isExporting}
                <div
                    class="absolute left-0 right-0 top-0 z-10 flex items-center gap-2 px-5 py-2 text-xs font-medium"
                    style="background:var(--accent-dim);color:var(--accent);border-bottom:1px solid var(--border)"
                >
                    <Loader2 size={14} class="export-spinner" />
                    {exportProgress}
                </div>
            {/if}

            <div class="flex items-start justify-between gap-4 px-5 py-4 {isExporting ? 'pt-12' : ''}">
                <div>
                    <h2 id="export-dialog-title" class="text-base font-semibold">
                        Export Report
                    </h2>
                    <p class="mt-1 text-xs" style="color:var(--muted)">
                        Choose a format and destination for this analysis.
                    </p>
                </div>
                
            </div>

            <div class="px-5 pb-5">
                <fieldset class="space-y-2" disabled={isExporting}>
                    <legend
                        class="mb-2 text-xs font-semibold uppercase"
                        style="color:var(--muted)"
                    >
                        Format
                    </legend>

                    {#each exportOptions as option (option.value)}
                        {@const Icon = option.icon}
                        <label
                            class="flex cursor-pointer items-start gap-3 rounded-xl p-3 transition-colors"
                            class:cursor-not-allowed={isExporting}
                            style={selectedFormat === option.value
                                ? "background:var(--accent-dim);border:1px solid var(--accent)"
                                : "background:var(--surface-2);border:1px solid var(--border)"}
                        >
                            <input
                                class="mt-1 accent-[var(--accent)]"
                                type="radio"
                                name="export-format"
                                value={option.value}
                                bind:group={selectedFormat}
                                disabled={isExporting}
                            />
                            <Icon
                                size={16}
                                color={selectedFormat === option.value
                                    ? "var(--accent)"
                                    : "var(--muted)"}
                            />
                            <span class="min-w-0 flex-1">
                                <span class="block text-sm font-semibold">
                                    {option.label}
                                </span>
                                <span
                                    class="mt-0.5 block text-xs"
                                    style="color:var(--muted)"
                                >
                                    {option.description}
                                </span>
                            </span>
                            {#if selectedFormat === option.value}
                                <CheckCircle2 size={15} color="var(--accent)" />
                            {/if}
                        </label>
                    {/each}
                </fieldset>

                {#if selectedFormat === "pdf_technical"}
                    <div
                        class="mt-3 overflow-hidden rounded-xl"
                        style="border:1px solid var(--border);background:var(--surface-2)"
                        transition:slide={{ duration: 200 }}
                    >
                        <button
                            type="button"
                            class="flex w-full items-center justify-between gap-2 px-3 py-2.5 text-left text-xs font-semibold uppercase"
                            style="color:var(--muted)"
                            disabled={isExporting}
                            onclick={() => (pdfSettingsOpen = !pdfSettingsOpen)}
                        >
                            Technical PDF Options
                            <ChevronDown
                                size={14}
                                class="transition-transform duration-200 {pdfSettingsOpen
                                    ? 'rotate-180'
                                    : ''}"
                            />
                        </button>

                        {#if pdfSettingsOpen}
                            <div
                                class="space-y-3 border-t px-3 py-3"
                                style="border-color:var(--border)"
                                transition:slide={{ duration: 180 }}
                            >
                                <div class="space-y-1.5">
                                    <label
                                        for="max-findings"
                                        class="text-xs font-medium"
                                    >
                                        Max Findings
                                    </label>
                                    <input
                                        id="max-findings"
                                        type="number"
                                        min="1"
                                        max="1000"
                                        class="w-full rounded-lg px-3 py-2 text-sm outline-none"
                                        style="background:var(--surface);border:1px solid var(--border);color:var(--text)"
                                        bind:value={maxFindings}
                                        disabled={isExporting}
                                    />
                                    <p class="text-xs" style="color:var(--muted)">
                                        Highest-severity findings included (1–1000).
                                    </p>
                                </div>

                                <label
                                    class="flex cursor-pointer items-center gap-2 text-sm"
                                    class:cursor-not-allowed={isExporting}
                                >
                                    <input
                                        type="checkbox"
                                        class="accent-[var(--accent)]"
                                        bind:checked={includeSourceCode}
                                        disabled={isExporting}
                                    />
                                    Include Source Code Snippets
                                </label>
                            </div>
                        {/if}
                    </div>
                {/if}

                <div class="mt-4 space-y-2">
                    <label
                        for="export-path"
                        class="text-xs font-semibold uppercase"
                        style="color:var(--muted)"
                    >
                        Destination
                    </label>
                    <div class="flex gap-2">
                        <input
                            id="export-path"
                            class="min-w-0 flex-1 rounded-lg px-3 py-2 text-xs outline-none"
                            style="background:var(--surface-2);border:1px solid var(--border);color:var(--text)"
                            value={selectedPath || "No destination selected"}
                            readonly
                            disabled={isExporting}
                        />
                        <button
                            type="button"
                            class="btn-ghost shrink-0"
                            disabled={isExporting}
                            onclick={choosePath}
                        >
                            <FolderOpen size={13} />
                            Browse
                        </button>
                    </div>
                </div>

                {#if errorMessage}
                    <p
                        class="mt-3 rounded-lg px-3 py-2 text-xs"
                        style="background:var(--danger-dim);border:1px solid rgba(239,68,68,0.35);color:#fca5a5"
                    >
                        {errorMessage}
                    </p>
                {/if}

                <div class="mt-5 flex items-center justify-end gap-2">
                    <button
                        type="button"
                        class="btn-ghost"
                        disabled={isExporting}
                        onclick={close}
                    >
                        Cancel
                    </button>
                    <button
                        type="button"
                        class="btn-primary"
                        disabled={isExporting}
                        onclick={runExport}
                    >
                        {#if isExporting}
                            <Loader2 size={14} class="export-spinner" />
                            Exporting
                        {:else}
                            Export
                        {/if}
                    </button>
                </div>
            </div>
        </div>
    </div>
{/if}

<style>
    :global(.export-spinner) {
        animation: spin 0.8s linear infinite;
    }
</style>
