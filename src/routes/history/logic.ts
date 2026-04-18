import { invoke } from "@tauri-apps/api/core";
import { success, error as errorToast } from "$lib/toast";

export async function loadHistory(): Promise<any[]> {
    try {
        return await invoke<any[]>("get_history");
    } catch (err) {
        errorToast(err as string);
        return [];
    }
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