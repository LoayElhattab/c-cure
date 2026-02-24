import { invoke } from "@tauri-apps/api/core";
import { success, error as errorToast } from "$lib/toast";

export async function loadHistory(): Promise<any[]> {
    const raw = await invoke<string>("get_history");
    const data = JSON.parse(raw);
    if (data.error) { errorToast(data.error); return []; }
    return data;
}

export async function deleteAnalysis(id: number): Promise<boolean> {
    try {
        await invoke("delete_analysis", { analysisId: id });
        success("Analysis deleted.");
        return true;
    } catch (err) {
        errorToast(`Failed to delete: ${err}`);
        return false;
    }
}