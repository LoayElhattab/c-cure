import { goto } from "$app/navigation";
import { invoke } from "@tauri-apps/api/core";
import { pendingAnalysis } from "$lib/store";
import { get } from "svelte/store";

export const STEPS = [
    { label: "Reading source file", detail: "Locating and opening target" },
    { label: "Extracting functions", detail: "tree-sitter C++ parser" },
    { label: "Connecting to inference API", detail: "Checking Kaggle endpoint" },
    { label: "Running triage + classification", detail: "UniXcoder · GraphCodeBERT · SecureBERT · CodeT5" },
    { label: "Generating report", detail: "Saving results to database" },
];

export function tick() {
    return new Promise(resolve => setTimeout(resolve, 350));
}

export async function runAnalysis(
    onStep: (i: number) => void,
    onSummary: (data: any) => void,
    onError: (msg: string) => void,
    onDone: (id: number) => void,
) {
    const pending = get(pendingAnalysis);
    if (!pending) { goto("/"); return; }

    try {
        onStep(0); await tick();

        // Step 1: extract functions — only valid for single files
        // For folders we skip the pre-check; the orchestrator handles extraction internally
        onStep(1);
        if (pending.type === "file") {
            const extractRaw = await invoke<string>("extract_functions", { filePath: pending.path });
            const extracted = JSON.parse(extractRaw);
            if (extracted.error) { onError(extracted.error); return; }
            if (extracted.count === 0) { onError("No functions found in file. Is it a valid C++ file?"); return; }
        }
        await tick();

        // Step 2: check API reachability
        onStep(2);
        const apiRaw = await invoke<string>("check_api");
        const apiStatus = JSON.parse(apiRaw);
        if (!apiStatus.reachable) {
            onError("Kaggle API is unreachable. Make sure the notebook is running and the URL is set in Settings.");
            return;
        }
        await tick();

        // Step 3: run the full analysis
        onStep(3);
        let raw: string;
        if (pending.type === "file") {
            raw = await invoke<string>("analyze_file", { filePath: pending.path });
        } else {
            raw = await invoke<string>("analyze_folder", { folderPath: pending.path });
        }
        const result = JSON.parse(raw);
        if (result.error) { onError(result.error); return; }

        // Step 4: done
        onStep(4); await tick();
        pendingAnalysis.set(null);
        onSummary(result);
        setTimeout(() => onDone(result.analysis_id), 2500);

    } catch (err) {
        onError(`Unexpected error: ${err}`);
    }
}