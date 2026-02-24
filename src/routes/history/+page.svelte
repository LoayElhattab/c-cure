<script lang="ts">
  import { onMount } from "svelte";
  import { Trash2, Search, X, Plus } from "lucide-svelte";
  import { loadHistory, deleteAnalysis } from "./logic";

  let history: any[] = [];
  let loading = true;
  let deleting: Record<number, boolean> = {};
  let confirmId: number | null = null; // which row is showing inline confirm
  let searchTerm = "";

  $: filteredHistory = history.filter((item) =>
    item.project_name.toLowerCase().includes(searchTerm.toLowerCase()),
  );

  onMount(async () => {
    history = await loadHistory();
    loading = false;
  });

  function requestDelete(id: number) {
    confirmId = id; // show inline confirm for this row
  }

  function cancelDelete() {
    confirmId = null;
  }

  async function confirmDelete(id: number) {
    deleting[id] = true;
    deleting = deleting;
    confirmId = null;
    const deleted = await deleteAnalysis(id);
    if (deleted) history = history.filter((h) => h.id !== id);
    deleting[id] = false;
    deleting = deleting;
  }
</script>

<div
  class="min-h-screen px-6 py-8 animate-fade-up"
  style="background:var(--bg);color:var(--text)"
>
  <div class="max-w-6xl mx-auto">
    <div class="flex items-center justify-between mb-6">
      <div>
        <h1 class="text-lg font-semibold">Analysis History</h1>
        <p class="text-xs mt-0.5" style="color:var(--muted)">
          All past scans stored locally
        </p>
      </div>
      <a href="/" class="btn-primary"><Plus size={12} />New Analysis</a>
    </div>

    {#if !loading && history.length > 0}
      <div
        class="flex items-center gap-3 rounded-xl px-4 py-2.5 mb-4"
        style="background:var(--surface);border:1px solid var(--border)"
      >
        <Search size={13} color="var(--muted)" />
        <input
          type="text"
          bind:value={searchTerm}
          placeholder="Search analyses..."
          class="flex-1 bg-transparent text-xs outline-none"
          style="color:var(--text)"
        />
        {#if searchTerm}
          <button
            onclick={() => (searchTerm = "")}
            class="transition-colors"
            style="color:var(--muted)"
          >
            <X size={13} />
          </button>
        {/if}
      </div>
    {/if}

    {#if loading}
      <div class="card overflow-hidden">
        <table class="w-full">
          <thead>
            <tr style="border-bottom:1px solid var(--border)">
              {#each ["Project", "Date", "Functions", "Vulnerable", ""] as h}
                <th
                  class="text-left px-5 py-3 text-xs uppercase tracking-wider"
                  style="color:var(--muted)">{h}</th
                >
              {/each}
            </tr>
          </thead>
          <tbody>
            {#each Array(4) as _, i}
              <tr
                style="border-bottom:1px solid var(--border)"
                class="animate-fade-up stagger-{i + 1}"
              >
                <td class="px-5 py-3.5"
                  ><div class="skeleton h-3 w-32"></div></td
                >
                <td class="px-5 py-3.5"
                  ><div class="skeleton h-3 w-24"></div></td
                >
                <td class="px-5 py-3.5"><div class="skeleton h-3 w-8"></div></td
                >
                <td class="px-5 py-3.5"
                  ><div class="skeleton h-3 w-16"></div></td
                >
                <td class="px-5 py-3.5"
                  ><div class="skeleton h-3 w-12 ml-auto"></div></td
                >
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else if history.length === 0}
      <div class="text-center mt-24 animate-fade-up">
        <p class="text-3xl mb-3">📭</p>
        <p class="text-sm" style="color:var(--muted)">No analyses yet.</p>
        <a
          href="/"
          class="text-xs mt-3 inline-block"
          style="color:var(--accent)">← Go to Upload</a
        >
      </div>
    {:else if filteredHistory.length === 0}
      <div class="text-center mt-24 animate-fade-up">
        <p class="text-sm" style="color:var(--muted)">
          No results for "{searchTerm}"
        </p>
        <button
          onclick={() => (searchTerm = "")}
          class="text-xs mt-2 block mx-auto"
          style="color:var(--accent)"
        >
          Clear search
        </button>
      </div>
    {:else}
      <div class="card overflow-hidden animate-fade-up">
        <table class="w-full">
          <thead>
            <tr style="border-bottom:1px solid var(--border)">
              {#each ["Project", "Date", "Functions", "Vulnerable", ""] as h}
                <th
                  class="text-left px-5 py-3 text-xs uppercase tracking-wider"
                  style="color:var(--muted)">{h}</th
                >
              {/each}
            </tr>
          </thead>
          <tbody>
            {#each filteredHistory as item}
              <tr style="border-bottom:1px solid var(--border)">
                {#if confirmId === item.id}
                  <!-- Inline confirmation row -->
                  <td colspan="5" class="px-5 py-3">
                    <div class="flex items-center justify-between">
                      <p class="text-xs" style="color:var(--text)">
                        Delete
                        <span class="font-semibold mono"
                          >{item.project_name}</span
                        >? This cannot be undone.
                      </p>
                      <div class="flex items-center gap-2">
                        <button
                          onclick={() => cancelDelete()}
                          class="text-xs px-3 py-1.5 rounded-lg transition-colors"
                          style="color:var(--muted);border:1px solid var(--border)"
                        >
                          Cancel
                        </button>
                        <button
                          onclick={() => confirmDelete(item.id)}
                          class="text-xs px-3 py-1.5 rounded-lg font-semibold transition-colors"
                          style="background:var(--danger);color:#fff;border:1px solid var(--danger)"
                          disabled={deleting[item.id]}
                        >
                          {deleting[item.id] ? "Deleting…" : "Delete"}
                        </button>
                      </div>
                    </div>
                  </td>
                {:else}
                  <!-- Normal row -->
                  <td class="px-5 py-3.5 text-xs font-medium mono"
                    >{item.project_name}</td
                  >
                  <td class="px-5 py-3.5 text-xs" style="color:var(--muted)"
                    >{item.timestamp}</td
                  >
                  <td class="px-5 py-3.5 text-xs" style="color:var(--muted)"
                    >{item.total_functions ?? 0}</td
                  >
                  <td class="px-5 py-3.5">
                    <span
                      class="text-xs font-semibold"
                      style="color:{(item.vuln_count ?? 0) > 0
                        ? 'var(--danger)'
                        : 'var(--success)'}"
                    >
                      {(item.vuln_count ?? 0) > 0
                        ? `${item.vuln_count} found`
                        : "Clean"}
                    </span>
                  </td>
                  <td class="px-5 py-3.5">
                    <div class="flex items-center justify-end gap-3">
                      <a
                        href="/report/{item.id}"
                        class="text-xs transition-colors"
                        style="color:var(--accent)"
                        onmouseenter={(e) =>
                          ((e.currentTarget as HTMLElement).style.opacity =
                            "0.7")}
                        onmouseleave={(e) =>
                          ((e.currentTarget as HTMLElement).style.opacity =
                            "1")}
                      >
                        View →
                      </a>
                      <button
                        onclick={() => requestDelete(item.id)}
                        disabled={deleting[item.id]}
                        class="transition-colors disabled:opacity-40"
                        style="color:var(--subtle)"
                        onmouseenter={(e) =>
                          ((e.currentTarget as HTMLElement).style.color =
                            "var(--danger)")}
                        onmouseleave={(e) =>
                          ((e.currentTarget as HTMLElement).style.color =
                            "var(--subtle)")}
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </td>
                {/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
</div>
