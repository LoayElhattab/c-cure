import { invoke } from "@tauri-apps/api/core";
import { goto } from "$app/navigation";
import type { AnalysisResult, CheckApiResponse, ExtractFunctionsResponse } from "$lib/types/bindings";

export const STEPS = [
    { label: "Reading source file", detail: "Locating and opening target" },
    { label: "Extracting functions", detail: "tree-sitter C++ parser" },
    { label: "Connecting to inference API", detail: "Checking Kaggle endpoint" },
    { label: "Running triage + classification", detail: "UniXcoder · GraphCodeBERT · SecureBERT · CodeT5" },
    { label: "Generating report", detail: "Saving results to database" },
];

function tick() {
    return new Promise(resolve => setTimeout(resolve, 350));
}

class AnalysisStore {
    status = $state<'idle' | 'running' | 'done' | 'error'>('idle');
    currentStep = $state(0);
    error = $state<string | null>(null);
    result = $state<AnalysisResult | null>(null);
    pending = $state<{ type: 'file' | 'folder'; path: string } | null>(null);

    async runAnalysis(type: 'file' | 'folder', path: string) {
        this.pending = { type, path };
        this.status = 'running';
        this.currentStep = 0;
        this.error = null;
        this.result = null;

        try {
            await tick();

            // Step 1: extract functions (pre-check for files)
            this.currentStep = 1;
            if (type === 'file') {
                const extracted = await invoke<ExtractFunctionsResponse>("extract_functions", { filePath: path });
                if (extracted.count === 0) {
                    this.fail("No functions found in file. Is it a valid C++ file?");
                    return;
                }
            }
            await tick();

            // Step 2: check API reachability
            this.currentStep = 2;
            const apiStatus = await invoke<CheckApiResponse>("check_api");
            if (!apiStatus.reachable) {
                this.fail("Kaggle API is unreachable. Check notebook status and URL in Settings.");
                return;
            }
            await tick();

            // Step 3: run full analysis
            this.currentStep = 3;
            let res: AnalysisResult;
            if (type === 'file') {
                res = await invoke<AnalysisResult>("analyze_file", { filePath: path });
            } else {
                res = await invoke<AnalysisResult>("analyze_folder", { folderPath: path });
            }
            this.result = res;

            // Step 4: done
            this.currentStep = 4;
            await tick();
            this.status = 'done';
            
            setTimeout(() => {
                if (this.result) {
                    goto(`/report/${this.result.analysisId}`);
                }
            }, 2500);

        } catch (err) {
            this.fail(`Unexpected error: ${err}`);
        }
    }

    private fail(msg: string) {
        this.error = msg;
        this.status = 'error';
    }

    reset() {
        this.status = 'idle';
        this.currentStep = 0;
        this.error = null;
        this.result = null;
        this.pending = null;
    }
}

export const analysisStore = new AnalysisStore();
