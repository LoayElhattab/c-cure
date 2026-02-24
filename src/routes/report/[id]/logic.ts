import { invoke } from "@tauri-apps/api/core";
import { success, error as errorToast } from "$lib/toast";
import hljs from "highlight.js/lib/core";
import cpp from "highlight.js/lib/languages/cpp";

hljs.registerLanguage("cpp", cpp);

export const CIRCUMFERENCE = 2 * Math.PI * 20;

export async function fetchReport(id: string): Promise<any> {
    const raw = await invoke<string>("get_report", { analysisId: parseInt(id) });
    const data = JSON.parse(raw);
    if (data.error) throw new Error(data.error);
    return data;
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

export async function exportPDF(id: string): Promise<void> {
    try {
        const raw = await invoke<string>("generate_pdf", { analysisId: parseInt(id) });
        const result = JSON.parse(raw);
        if (result.error) throw new Error(result.error);
        await invoke("open_path", { path: result.path });
        success("Report exported successfully");
    } catch (err) { errorToast("Failed to export PDF: " + err); }
}