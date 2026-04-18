<script lang="ts">
    import { onMount } from "svelte";
    import { theme } from "$lib/theme";
    import { Sun, Moon, Wifi } from "lucide-svelte";
    import { loadSettings, saveSettings } from "./logic";

    let kaggleUrl = "";
    let saving = false;
    let loading = true;

    onMount(async () => {
        const s = await loadSettings();
        kaggleUrl = s.kaggle_url ?? "";
        loading = false;
    });

    async function handleSave() {
        saving = true;
        await saveSettings(kaggleUrl);
        saving = false;
    }

    function toggleTheme() {
        theme.update((t) => (t === "dark" ? "light" : "dark"));
    }
</script>

<div
    class="min-h-screen px-6 py-8 animate-fade-up"
    style="background:var(--bg);color:var(--text)"
>
    <div class="max-w-xl mx-auto">
        <div class="mb-6">
            <h1 class="text-lg font-semibold">Settings</h1>
            <p class="text-xs mt-0.5" style="color:var(--muted)">
                Configure C-Cure preferences
            </p>
        </div>

        {#if loading}
            <div class="space-y-3">
                <div class="card p-5">
                    <div class="skeleton h-3 w-24 mb-3"></div>
                    <div class="skeleton h-9 w-44 rounded-xl"></div>
                </div>
                <div class="card p-5">
                    <div class="skeleton h-3 w-24 mb-3"></div>
                    <div class="skeleton h-9 w-full rounded-xl"></div>
                </div>
            </div>
        {:else}
            <!-- Appearance -->
            <div class="card p-5 mb-3">
                <p
                    class="text-xs font-semibold uppercase tracking-wider mb-1"
                    style="color:var(--muted)"
                >
                    Appearance
                </p>
                <p class="text-xs mb-4" style="color:var(--subtle)">
                    Toggle between dark and light mode.
                </p>
                <button on:click={toggleTheme} class="btn-ghost gap-3 w-auto">
                    {#if $theme === "dark"}
                        <Moon size={14} />Dark Mode
                        <span class="ml-2 text-xs" style="color:var(--subtle)"
                            >Switch to Light →</span
                        >
                    {:else}
                        <Sun size={14} />Light Mode
                        <span class="ml-2 text-xs" style="color:var(--subtle)"
                            >Switch to Dark →</span
                        >
                    {/if}
                </button>
            </div>

            <!-- Kaggle API -->
            <div class="card p-5 mb-3">
                <p
                    class="text-xs font-semibold uppercase tracking-wider mb-1"
                    style="color:var(--muted)"
                >
                    Kaggle API
                </p>
                <p class="text-xs mb-4" style="color:var(--subtle)">
                    Paste your ngrok URL from the running Kaggle notebook.
                </p>
                <div class="flex gap-2">
                    <div
                        class="flex-1 flex items-center gap-2 rounded-xl px-3"
                        style="background:var(--surface-2);border:1px solid var(--border)"
                    >
                        <Wifi size={12} color="var(--muted)" />
                        <input
                            type="text"
                            bind:value={kaggleUrl}
                            placeholder="https://xxxx.ngrok-free.app"
                            class="flex-1 bg-transparent py-2.5 text-xs outline-none mono"
                            style="color:var(--text)"
                        />
                    </div>
                    <button
                        on:click={handleSave}
                        disabled={saving}
                        class="btn-primary disabled:opacity-50"
                    >
                        {saving ? "Saving..." : "Save"}
                    </button>
                </div>
            </div>

            <!-- About -->
            <div class="card p-5">
                <p
                    class="text-xs font-semibold uppercase tracking-wider mb-1"
                    style="color:var(--muted)"
                >
                    About
                </p>
                <p class="text-xs" style="color:var(--subtle)">
                    C-Cure · v1.0.0 · Demo · FCIS Graduation Project 2026
                    <br />
                    Under supervision of Dr. Alshaimaa Abo-Alian & T.A. Alaa Prince
                </p>
            </div>
        {/if}
    </div>
</div>
