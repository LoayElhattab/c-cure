<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { open } from "@tauri-apps/plugin-dialog";
  import { onMount } from "svelte";
  import { FolderOpen, Radio, Square, XCircle } from "lucide-svelte";
  import {
    success as toastSuccess,
    error as toastError,
    info as toastInfo,
  } from "$lib/utils/toast";

  type MonitoredFolder = {
    id: number;
    name: string;
    path: string;
    registeredAt: string;
    active: boolean;
  };

  let monitoredFolders = $state<MonitoredFolder[]>([]);
  let loading = $state(true);
  let actionPath = $state<string | null>(null);
  let error = $state("");

  const hasMonitoredPaths = $derived(monitoredFolders.length > 0);

  onMount(() => {
    void loadMonitoredPaths();

    // Listen to background monitor scan events
    const unlistenStart = listen<{ path: string }>(
      "monitor-scan-start",
      (event) => {
        toastInfo(
          `File change detected: Scanning ${folderName(event.payload.path)}...`,
        );
      },
    );
    const unlistenSuccess = listen<{
      path: string;
      vuln_count: number;
      total_functions: number;
    }>("monitor-scan-success", (event) => {
      if (event.payload.vuln_count > 0) {
        toastError(
          `Scan complete: Found ${event.payload.vuln_count} vulnerabilities in ${folderName(event.payload.path)}.`,
        );
      } else {
        toastSuccess(
          `Scan complete: No vulnerabilities found in ${folderName(event.payload.path)}.`,
        );
      }
    });
    const unlistenError = listen<{ path: string; error: string }>(
      "monitor-scan-error",
      (event) => {
        toastError(
          `Scan failed for ${folderName(event.payload.path)}: ${event.payload.error}`,
        );
      },
    );

    return () => {
      unlistenStart.then((fn) => fn());
      unlistenSuccess.then((fn) => fn());
      unlistenError.then((fn) => fn());
    };
  });

  function folderName(path: string): string {
    const normalizedPath = path.replace(/\\/g, "/");
    const parts = normalizedPath.split("/").filter(Boolean);
    return parts.at(-1) ?? path;
  }

  function formatPath(path: string): string {
    return path.replace(/\\/g, "/");
  }

  function errorMessage(err: unknown): string {
    if (err instanceof Error) {
      return err.message;
    }

    return String(err);
  }

  async function loadMonitoredPaths(): Promise<void> {
    loading = true;
    error = "";

    try {
      const dbProjects = await invoke<
        {
          id: number;
          name: string;
          folder_path: string;
          registered_at: string;
        }[]
      >("monitor_list");
      const activePaths = await invoke<string[]>("get_monitored_paths");

      const activeSet = new Set(
        activePaths.map((p) => formatPath(p).toLowerCase()),
      );

      monitoredFolders = dbProjects.map((project) => ({
        id: project.id,
        name: project.name,
        path: project.folder_path,
        registeredAt: project.registered_at,
        active: activeSet.has(formatPath(project.folder_path).toLowerCase()),
      }));
    } catch (err) {
      error = `Failed to load monitored folders: ${errorMessage(err)}`;
    } finally {
      loading = false;
    }
  }

  async function handleAddFolder(): Promise<void> {
    error = "";

    try {
      const folder = await open({ directory: true, multiple: false });

      if (typeof folder !== "string") {
        return;
      }

      actionPath = folder;
      await invoke("start_monitoring", { path: folder });
      await loadMonitoredPaths();
    } catch (err) {
      error = `Failed to start monitoring: ${errorMessage(err)}`;
    } finally {
      actionPath = null;
    }
  }

  async function handleStop(path: string): Promise<void> {
    error = "";
    actionPath = path;

    try {
      await invoke("stop_monitoring", { path });
      await loadMonitoredPaths();
    } catch (err) {
      error = `Failed to stop monitoring: ${errorMessage(err)}`;
    } finally {
      actionPath = null;
    }
  }
</script>

<div
  class="min-h-screen px-6 py-8"
  style="background:var(--bg);color:var(--text)"
>
  <div class="mx-auto max-w-6xl">
    <div
      class="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
    >
      <div>
        <h1 class="text-lg font-semibold">Automated File Monitoring</h1>
        <p class="mt-0.5 text-xs" style="color:var(--muted)">
          Background scanning for registered C/C++ project folders.
        </p>
      </div>

      <button
        onclick={handleAddFolder}
        disabled={actionPath !== null}
        class="btn-primary"
      >
        <FolderOpen size={14} />
        Add Folder to Watch
      </button>
    </div>

    {#if error}
      <div
        class="mb-4 flex items-center gap-2 rounded-lg px-4 py-3 text-xs"
        style="background:var(--danger-dim);border:1px solid rgba(239,68,68,0.24);color:var(--danger)"
      >
        <XCircle size={14} />
        {error}
      </div>
    {/if}

    {#if loading}
      <div class="grid gap-3 md:grid-cols-2">
        {#each Array(4) as _}
          <div class="card p-5">
            <div class="skeleton mb-3 h-4 w-36"></div>
            <div class="skeleton h-3 w-full max-w-72"></div>
          </div>
        {/each}
      </div>
    {:else if !hasMonitoredPaths}
      <div class="mt-24 text-center">
        <div
          class="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full"
          style="background:var(--surface-2);border:1px solid var(--border);color:var(--muted)"
        >
          <Radio size={20} />
        </div>
        <p class="text-sm" style="color:var(--muted)">
          No folders are being watched.
        </p>
        <p class="mt-1 text-xs" style="color:var(--subtle)">
          Add a project folder to enable automatic re-scans on save.
        </p>
      </div>
    {:else}
      <div class="grid gap-3 md:grid-cols-2">
        {#each monitoredFolders as folder (folder.id)}
          <div class="card p-5">
            <div class="mb-4 flex items-start justify-between gap-4">
              <div class="min-w-0">
                <div class="mb-2 flex items-center gap-2">
                  {#if folder.active}
                    <span class="relative flex h-3 w-3">
                      <span
                        class="absolute inline-flex h-full w-full animate-ping rounded-full opacity-75"
                        style="background:#22c55e"
                      ></span>
                      <span
                        class="relative inline-flex h-3 w-3 rounded-full"
                        style="background:#22c55e"
                      ></span>
                    </span>
                  {:else}
                    <span class="relative flex h-3 w-3">
                      <span
                        class="relative inline-flex h-3 w-3 rounded-full"
                        style="background:var(--border)"
                      ></span>
                    </span>
                  {/if}
                  <p class="text-sm font-medium">{folder.name}</p>
                </div>
                <p class="mono break-all text-xs" style="color:var(--muted)">
                  {formatPath(folder.path)}
                </p>
              </div>

              <button
                onclick={() => handleStop(folder.path)}
                disabled={actionPath === folder.path}
                class="flex h-8 shrink-0 items-center gap-1.5 rounded-lg px-3 text-xs transition-colors disabled:opacity-50"
                style="border:1px solid var(--border);color:var(--muted)"
              >
                <Square size={11} />
                {actionPath === folder.path ? "Stopping..." : "Stop"}
              </button>
            </div>

            {#if folder.active}
              <div
                class="flex items-center justify-between rounded-lg px-3 py-2 text-xs"
                style="background:var(--success-dim);border:1px solid rgba(34,197,94,0.18);color:var(--success)"
              >
                <span>Watching...</span>
                <span style="color:var(--muted)">.c .cpp .h .hpp .cc .cxx</span>
              </div>
            {:else}
              <div
                class="flex items-center justify-between rounded-lg px-3 py-2 text-xs"
                style="background:var(--danger-dim);border:1px solid rgba(239,68,68,0.18);color:var(--danger)"
              >
                <span>Offline / Directory Missing</span>
                <span style="color:var(--muted)">Not Monitored</span>
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>
