import { invoke } from "@tauri-apps/api/core";
import { success, error as errorToast } from "$lib/toast";

export async function loadSettings(): Promise<{ kaggle_url: string }> {
    return await invoke<any>("get_settings");
}

export async function saveSettings(kaggleUrl: string): Promise<void> {
    try {
        await invoke("save_settings", { kaggleUrl });
        success("Settings saved successfully.");
    } catch (err) { errorToast(`Failed to save settings: ${err}`); }
}