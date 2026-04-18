<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";
  import {
    FolderOpen,
    RefreshCw,
    Trash2,
    AlertTriangle,
    CheckCircle,
  } from "lucide-svelte";

  let projects: any[] = [];
  let loading = true;
  let error = "";
  let checkResults: Record<number, any> = {};
  let checking: Record<number, boolean> = {};
  let refreshing: Record<number, boolean> = {};

  onMount(async () => {
    await loadProjects();
  });

  async function loadProjects() {
    loading = true;
    try {
      projects = await invoke<any[]>("monitor_list");
    } catch (err) {
      error = `Failed to load projects: ${err}`;
    }
    loading = false;
  }

  async function handleRegister() {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const folder = await open({ directory: true, multiple: false });
      if (!folder) return;
      const result = await invoke<any>("monitor_register", {
        folderPath: folder as string,
      });
      if (result.error) {
        error = result.error;
        return;
      }
      await loadProjects();
    } catch (err) {
      error = `Failed to register project: ${err}`;
    }
  }

  async function handleCheck(projectId: number) {
    checking[projectId] = true;
    checking = checking;
    try {
      checkResults[projectId] = await invoke<any>("monitor_check", { projectId });
      checkResults = checkResults;
    } catch (err) {
      error = `Failed to check changes: ${err}`;
    }
    checking[projectId] = false;
    checking = checking;
  }

  async function handleRefresh(projectId: number) {
    refreshing[projectId] = true;
    refreshing = refreshing;
    try {
      await invoke<any>("monitor_refresh", { projectId });
      delete checkResults[projectId];
      checkResults = checkResults;
    } catch (err) {
      error = `Failed to refresh: ${err}`;
    }
    refreshing[projectId] = false;
    refreshing = refreshing;
  }

  async function handleRemove(projectId: number) {
    try {
      await invoke<any>("monitor_remove", { projectId });
      delete checkResults[projectId];
      await loadProjects();
    } catch (err) {
      error = `Failed to remove: ${err}`;
    }
  }
</script>

<div
  class="min-h-screen px-6 py-8"
  style="background:var(--bg);color:var(--text)"
>
  <div class="max-w-4xl mx-auto">
    <div class="flex items-center justify-between mb-6">
      <div>
        <h1 class="text-lg font-semibold">File Monitor</h1>
        <p class="text-xs mt-0.5" style="color:var(--muted)">
          Hash-based change detection for C++ projects
        </p>
      </div>
      <button
        on:click={handleRegister}
        class="flex items-center gap-2 px-3 h-8 rounded-lg text-xs font-medium gradient-bg"
        style="color:#fff"
      >
        <FolderOpen size={13} />
        Watch Folder
      </button>
    </div>

    {#if error}
      <p class="text-xs mb-4" style="color:var(--danger)">{error}</p>
    {/if}

    {#if loading}
      <div class="space-y-3">
        {#each Array(2) as _}
          <div class="card p-5">
            <div class="skeleton h-4 w-32 mb-2"></div>
            <div class="skeleton h-3 w-64"></div>
          </div>
        {/each}
      </div>
    {:else if projects.length === 0}
      <div class="text-center mt-24">
        <p class="text-3xl mb-3">👁</p>
        <p class="text-sm" style="color:var(--muted)">
          No folders being watched yet.
        </p>
        <p class="text-xs mt-1" style="color:var(--subtle)">
          Click "Watch Folder" to start monitoring.
        </p>
      </div>
    {:else}
      <div class="space-y-3">
        {#each projects as project}
          <div class="card p-5">
            <div class="flex items-start justify-between mb-4">
              <div>
                <p class="text-sm font-medium">{project.name}</p>
                <p class="text-xs mt-0.5 mono" style="color:var(--muted)">
                  {project.folder_path}
                </p>
                <p class="text-xs mt-0.5" style="color:var(--subtle)">
                  Registered: {project.registered_at}
                </p>
              </div>
              <div class="flex items-center gap-2">
                <button
                  on:click={() => handleCheck(project.id)}
                  disabled={checking[project.id]}
                  class="flex items-center gap-1.5 px-3 h-7 rounded-lg text-xs transition-colors disabled:opacity-50"
                  style="border:1px solid var(--border);color:var(--muted)"
                >
                  <AlertTriangle size={11} />
                  {checking[project.id] ? "Checking..." : "Check Changes"}
                </button>
                <button
                  on:click={() => handleRefresh(project.id)}
                  disabled={refreshing[project.id]}
                  class="flex items-center gap-1.5 px-3 h-7 rounded-lg text-xs transition-colors disabled:opacity-50"
                  style="border:1px solid var(--border);color:var(--muted)"
                >
                  <RefreshCw size={11} />
                  {refreshing[project.id] ? "Updating..." : "Update Baseline"}
                </button>
                <button
                  on:click={() => handleRemove(project.id)}
                  class="flex items-center gap-1.5 px-3 h-7 rounded-lg text-xs transition-colors"
                  style="border:1px solid var(--border);color:var(--subtle)"
                >
                  <Trash2 size={11} />
                </button>
              </div>
            </div>

            {#if checkResults[project.id]}
              {@const result = checkResults[project.id]}
              {#if result.total_changes === 0 && result.deleted.length === 0}
                <div
                  class="flex items-center gap-2 rounded-xl px-4 py-3 text-xs"
                  style="background:var(--success-dim);border:1px solid rgba(34,197,94,0.2);color:var(--success)"
                >
                  <CheckCircle size={13} />
                  No changes detected since last baseline.
                </div>
              {:else}
                <div class="space-y-3">
                  {#if result.changed.length > 0}
                    <div>
                      <p
                        class="text-xs font-semibold uppercase tracking-wider mb-2"
                        style="color:#f97316"
                      >
                        Modified ({result.changed.length})
                      </p>
                      {#each result.changed as file}
                        <div
                          class="flex items-center justify-between px-3 py-2 rounded-lg mb-1 text-xs mono"
                          style="background:rgba(249,115,22,0.08);border:1px solid rgba(249,115,22,0.2);color:#fed7aa"
                        >
                          <span
                            >{file.replace(/\\/g, "/").split("/").pop()}</span
                          >
                          <a
                            href="/analyzing"
                            class="text-xs"
                            style="color:var(--accent)"
                            on:click|preventDefault={async () => {
                              const { pendingAnalysis } = await import(
                                "$lib/store"
                              );
                              pendingAnalysis.set({ type: "file", path: file });
                              window.location.href = "/analyzing";
                            }}>Re-analyze →</a
                          >
                        </div>
                      {/each}
                    </div>
                  {/if}
                  {#if result.added.length > 0}
                    <div>
                      <p
                        class="text-xs font-semibold uppercase tracking-wider mb-2"
                        style="color:var(--accent)"
                      >
                        New ({result.added.length})
                      </p>
                      {#each result.added as file}
                        <div
                          class="px-3 py-2 rounded-lg mb-1 text-xs mono"
                          style="background:var(--surface-2);border:1px solid var(--border);color:var(--muted)"
                        >
                          {file.replace(/\\/g, "/").split("/").pop()}
                        </div>
                      {/each}
                    </div>
                  {/if}
                  {#if result.deleted.length > 0}
                    <div>
                      <p
                        class="text-xs font-semibold uppercase tracking-wider mb-2"
                        style="color:var(--danger)"
                      >
                        Deleted ({result.deleted.length})
                      </p>
                      {#each result.deleted as file}
                        <div
                          class="px-3 py-2 rounded-lg mb-1 text-xs mono"
                          style="background:var(--danger-dim);border:1px solid rgba(239,68,68,0.2);color:#fca5a5"
                        >
                          {file.replace(/\\/g, "/").split("/").pop()}
                        </div>
                      {/each}
                    </div>
                  {/if}
                </div>
              {/if}
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>
