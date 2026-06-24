import { invoke } from "@tauri-apps/api/core";
import hljs from "highlight.js/lib/core";
import cpp from "highlight.js/lib/languages/cpp";

hljs.registerLanguage("cpp", cpp);

export const CIRCUMFERENCE = 2 * Math.PI * 20;

export async function fetchAnalysisSummary(id: string): Promise<any> {
    try {
        return await invoke<any>("get_analysis_summary", { analysisId: parseInt(id) });
    } catch (err) {
        throw new Error(err as string);
    }
}

export function flattenFunctions(data: any): any[] {
    const fns: any[] = [];
    for (const file of data.files)
        for (const fn of file.functions)
            fns.push({ ...fn, file_path: file.file_path });
    return fns;
}

export function highlightCode(code: string): string {
    return hljs.highlight(code, { language: "cpp" }).value;
}

export async function copyToClipboard(code: string): Promise<void> {
    await navigator.clipboard.writeText(code);
}
