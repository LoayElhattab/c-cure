import { goto } from "$app/navigation";
import { pendingAnalysis } from "$lib/store";

export let selectedPath: string | null = null;
export let selectedName: string = "";
export let selectionType: "file" | "folder" | null = null;
export let errorMessage: string = "";

export async function handleFilePick(
    onResult: (path: string, name: string) => void,
    onError: (msg: string) => void
) {
    try {
        const { open } = await import("@tauri-apps/plugin-dialog");
        const result = await open({
            multiple: false, directory: false,
            filters: [{ name: "C/C++ Files", extensions: ["cpp", "c", "h", "cc", "cxx"] }],
        });
        if (!result) return;
        const path = result as string;
        const name = path.replace(/\\/g, "/").split("/").pop() ?? path;
        onResult(path, name);
    } catch (err) { onError(`Could not open file picker: ${err}`); }
}

export async function handleFolderPick(
    onResult: (path: string, name: string) => void,
    onError: (msg: string) => void
) {
    try {
        const { open } = await import("@tauri-apps/plugin-dialog");
        const result = await open({ multiple: false, directory: true });
        if (!result) return;
        const path = result as string;
        const name = path.replace(/\\/g, "/").split("/").pop() ?? path;
        onResult(path, name);
    } catch (err) { onError(`Could not open folder picker: ${err}`); }
}

export function handleAnalyze(
    path: string,
    type: "file" | "folder"
) {
    pendingAnalysis.set({ type, path });
    goto("/analyzing");
}