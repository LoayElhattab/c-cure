<script lang="ts">
  import { theme } from "$lib/theme";
  import { FolderOpen, FileCode } from "lucide-svelte";
  import { handleFilePick, handleFolderPick, handleAnalyze } from "./logic";

  let selectedPath: string | null = null;
  let selectedName = "";
  let selectionType: "file" | "folder" | null = null;
  let errorMessage = "";

  function onFilePicked(path: string, name: string) {
    selectedPath = path;
    selectedName = name;
    selectionType = "file";
    errorMessage = "";
  }
  function onFolderPicked(path: string, name: string) {
    selectedPath = path;
    selectedName = name;
    selectionType = "folder";
    errorMessage = "";
  }
  function onError(msg: string) {
    errorMessage = msg;
  }

  function hoverIn(e: MouseEvent, type: "file" | "folder") {
    if (selectionType === type) return;
    const el = e.currentTarget as HTMLElement;
    el.style.background =
      "linear-gradient(135deg, var(--accent-start), var(--accent-end))";
    el.style.borderColor = "transparent";
    el.style.color = "#fff";
    el.style.boxShadow = "0 0 18px var(--accent-glow)";
    const sub = el.querySelector(".sub-text") as HTMLElement;
    if (sub) sub.style.color = "rgba(255,255,255,0.7)";
  }
  function hoverOut(e: MouseEvent, type: "file" | "folder") {
    if (selectionType === type) return;
    const el = e.currentTarget as HTMLElement;
    el.style.background = "transparent";
    el.style.borderColor = "var(--border)";
    el.style.color = "var(--muted)";
    el.style.boxShadow = "none";
    const sub = el.querySelector(".sub-text") as HTMLElement;
    if (sub) sub.style.color = "var(--subtle)";
  }
</script>

<div
  class="min-h-screen flex flex-col items-center justify-center px-6 relative overflow-hidden"
  style="background:var(--bg)"
>
  <!-- Aurora background -->
  <div class="aurora-bg"></div>

  <div class="relative z-10 w-full max-w-md animate-fade-up">
    <!-- Big centered logo -->
    <img
      src={$theme === "dark" ? "/logo-white.png" : "/logo-black.png"}
      alt="C-Cure"
      class="h-30 w-auto mb-12 mx-auto"
    />

    <!-- Card -->
    <div class="card p-6">
      <p
        class="text-xs font-semibold uppercase tracking-wider mb-4"
        style="color:var(--muted)"
      >
        Select Target
      </p>

      <div class="grid grid-cols-2 gap-3 mb-4">
        <button
          onclick={() => handleFilePick(onFilePicked, onError)}
          onmouseenter={(e) => hoverIn(e, "file")}
          onmouseleave={(e) => hoverOut(e, "file")}
          class="flex flex-col items-center justify-center gap-2.5 p-5 rounded-xl border-2 transition-all duration-200 cursor-pointer focus:outline-none"
          style={selectionType === "file"
            ? "background:linear-gradient(135deg,var(--accent-start),var(--accent-end));border-color:transparent;color:#fff;box-shadow:0 0 18px var(--accent-glow)"
            : "border-color:var(--border);color:var(--muted)"}
        >
          <FileCode size={26} />
          <div class="text-center">
            <p class="text-xs font-semibold">Single File</p>
            <p
              class="sub-text text-xs mt-0.5"
              style={selectionType === "file"
                ? "color:rgba(255,255,255,0.7)"
                : "color:var(--subtle)"}
            >
              .cpp / .c / .h
            </p>
          </div>
        </button>

        <button
          onclick={() => handleFolderPick(onFolderPicked, onError)}
          onmouseenter={(e) => hoverIn(e, "folder")}
          onmouseleave={(e) => hoverOut(e, "folder")}
          class="flex flex-col items-center justify-center gap-2.5 p-5 rounded-xl border-2 transition-all duration-200 cursor-pointer focus:outline-none"
          style={selectionType === "folder"
            ? "background:linear-gradient(135deg,var(--accent-start),var(--accent-end));border-color:transparent;color:#fff;box-shadow:0 0 18px var(--accent-glow)"
            : "border-color:var(--border);color:var(--muted)"}
        >
          <FolderOpen size={26} />
          <div class="text-center">
            <p class="text-xs font-semibold">Project Folder</p>
            <p
              class="sub-text text-xs mt-0.5"
              style={selectionType === "folder"
                ? "color:rgba(255,255,255,0.7)"
                : "color:var(--subtle)"}
            >
              Scans recursively
            </p>
          </div>
        </button>
      </div>

      {#if selectedName}
        <div
          class="flex items-center gap-3 rounded-xl px-4 py-3 mb-4 animate-fade-in"
          style="background:var(--surface-2);border:1px solid var(--border)"
        >
          <div class="dot-success"></div>
          <div class="flex-1 min-w-0">
            <p
              class="text-xs font-medium truncate mono"
              style="color:var(--accent)"
            >
              {selectedName}
            </p>
            <p class="text-xs truncate mt-0.5 mono" style="color:var(--muted)">
              {selectedPath}
            </p>
          </div>
        </div>
      {/if}

      {#if errorMessage}
        <p class="text-xs mb-4 animate-fade-in" style="color:var(--danger)">
          {errorMessage}
        </p>
      {/if}

      <!-- EXACT UIVerse button from your screenshots -->
      <button
        disabled={!selectedPath}
        onclick={() =>
          selectedPath &&
          selectionType &&
          handleAnalyze(selectedPath, selectionType)}
        class="animated-button w-full"
      >
        <svg
          viewBox="0 0 24 24"
          class="arr-2"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M16.1716 10.9999L10.8076 5.63589L12.2218 4.22168L20 11.9999L12.2218 19.778L10.8076 18.3638L16.1716 12.9999H4V10.9999H16.1716Z"
          ></path>
        </svg>
        <span class="text">Run Analysis</span>
        <span class="circle"></span>
        <svg
          viewBox="0 0 24 24"
          class="arr-1"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M16.1716 10.9999L10.8076 5.63589L12.2218 4.22168L20 11.9999L12.2218 19.778L10.8076 18.3638L16.1716 12.9999H4V10.9999H16.1716Z"
          ></path>
        </svg>
      </button>
    </div>

    <p class="text-center mt-5 text-xs">
      <a
        href="/history"
        class="transition-colors font-medium"
        style="color: var(--text)"
        onmouseenter={(e) => (e.currentTarget.style.color = "var(--bg)")}
        onmouseleave={(e) => (e.currentTarget.style.color = "var(--text)")}
      >
        View past analyses →
      </a>
    </p>
  </div>
</div>
