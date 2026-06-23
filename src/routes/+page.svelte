<script lang="ts">
  import { theme } from "$lib/types/theme";
  import {
    FolderOpen,
    FileCode,
    ShieldAlert,
    Cpu,
    Terminal,
  } from "lucide-svelte";
  import { handleFilePick, handleFolderPick, handleAnalyze } from "./logic";

  // Import our native Svelte 5 WebGL terminal background
  import FaultyTerminal from "$lib/components/ui/FaultyTerminal.svelte";

  let selectedPath = $state<string | null>(null);
  let selectedName = $state<string>("");
  let selectionType = $state<"file" | "folder" | null>(null);
  let errorMessage = $state<string>("");

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
</script>

<div
  class="min-h-screen flex flex-col font-mono relative overflow-hidden transition-colors duration-300 selection:bg-[#FF8C7A] selection:text-[#0A0B10]
    {$theme === 'dark'
    ? 'bg-[#0A0B10] text-[#EAEAEA]'
    : 'bg-[#FAFAFA] text-[#18181B]'}"
>
  <!-- 
    Interactive WebGL Matrix Background (Layered under the content)
    - Set to pointer-events-none so it doesn't block card/button clicks.
    - Uses global mouse tracking so it still reacts to movements over the whole page.
    - Dynamically changes tint and brightness based on active theme state.
  -->
  <div
    class="absolute inset-0 z-0 pointer-events-none transition-opacity duration-500
    {$theme === 'dark' ? 'opacity-80' : 'opacity-40 saturation-200'}"
  >
    <FaultyTerminal
      scale={4}
      gridMul={[2, 1]}
      digitSize={1.4}
      timeScale={0.4}
      pause={false}
      scanlineIntensity={0}
      glitchAmount={1.1}
      flickerAmount={1}
      noiseAmp={0.8}
      chromaticAberration={0}
      dither={0.1}
      curvature={0.15}
      mouseReact={true}
      mouseStrength={0.5}
      pageLoadAnimation={true}
      brightness={$theme === "dark" ? 1.0 : 1.4}
    />
  </div>

  <!-- Grid overlay for HUD visual detail (Sits on top of the WebGL canvas) -->
  <div
    class="absolute inset-0 pointer-events-none opacity-40 transition-all duration-300 z-10
      {$theme === 'dark'
      ? 'bg-[linear-gradient(to_right,rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.02)_1px,transparent_1px)]'
      : 'bg-[linear-gradient(to_right,rgba(0,0,0,0.02)_1px,transparent_1px),linear-gradient(to_bottom,rgba(0,0,0,0.02)_1px,transparent_1px)]'} bg-[size:4rem_4rem]"
  ></div>

  <!-- Ambient Radial Glow behind the main card (Sits on top of the WebGL canvas) -->
  <div
    class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full pointer-events-none blur-[120px] transition-all duration-500 z-10
      {$theme === 'dark'
      ? 'bg-gradient-to-r from-[#FF8C7A]/5 to-[#FF849C]/5 opacity-80'
      : 'bg-gradient-to-r from-zinc-200/45 to-zinc-300/30 opacity-60'}"
  ></div>

  <!-- Main HUD Layout (Assigned z-20 to sit above background layers and capture pointer clicks) -->
  <main class="flex-1 relative z-20 flex items-center justify-center p-6">
    <div class="w-full max-w-2xl flex flex-col gap-6">
      <!-- Top Logo Container -->
      <div class="text-center flex flex-col items-center">
        <img
          src={$theme === "dark" ? "/logo-white.png" : "/logo-black.png"}
          alt="C-Cure"
          class="h-20 w-auto opacity-90 transition-all duration-300 filter drop-shadow-[0_0_15px_rgba(255,140,122,0.1)]"
        />
      </div>

      <!-- Main Config HUD Card -->
      <div
        class="border shadow-2xl relative overflow-hidden transition-all duration-300
          {$theme === 'dark'
          ? 'bg-[#111218]/90 border-white/5 shadow-black/50 backdrop-blur-md'
          : 'bg-white/95 border-zinc-200 shadow-zinc-200/50 backdrop-blur-md'}"
      >
        <!-- Top tech corner accents -->
        <div
          class="absolute top-0 left-0 w-3 h-3 border-t-2 border-l-2 border-[#FF8C7A]"
        ></div>
        <div
          class="absolute top-0 right-0 w-3 h-3 border-t-2 border-r-2 border-[#D6B492]"
        ></div>
        <div
          class="absolute bottom-0 left-0 w-3 h-3 border-b-2 border-l-2 border-[#FF849C]"
        ></div>
        <div
          class="absolute bottom-0 right-0 w-3 h-3 border-b-2 border-r-2 border-[#FF8C7A]"
        ></div>

        <div class="p-8 flex flex-col gap-6">
          <div
            class="flex items-center justify-between border-b pb-4
              {$theme === 'dark' ? 'border-white/5' : 'border-zinc-100'}"
          >
            <div class="flex items-center gap-2">
              <Terminal size={16} class="text-[#FF8C7A]" />
              <span
                class="text-xs font-bold uppercase tracking-widest {$theme ===
                'dark'
                  ? 'text-[#EAEAEA]/80'
                  : 'text-zinc-700'}"
              >
                Input Selection
              </span>
            </div>
            <span class="text-[10px] text-[#D6B492] uppercase font-semibold"
              >C / C++ SOURCE COMPATIBLE</span
            >
          </div>

          <!-- Selector Grid -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <!-- File Selector Button -->
            <button
              onclick={() => handleFilePick(onFilePicked, onError)}
              class="relative flex flex-col items-start gap-4 p-6 border transition-all duration-300 text-left group/btn cursor-pointer
                {selectionType === 'file'
                ? 'scale-[1.02]'
                : 'hover:scale-[1.01] active:scale-[0.99]'}
                {$theme === 'dark' ? 'bg-[#0A0B10]/80' : 'bg-[#FAFAFA]/90'}"
              style="
                border-color: {selectionType === 'file'
                ? '#FF8C7A'
                : $theme === 'dark'
                  ? 'rgba(255,255,255,0.05)'
                  : 'rgba(0,0,0,0.08)'}; 
                box-shadow: {selectionType === 'file'
                ? $theme === 'dark'
                  ? '0 0 25px rgba(255,140,122,0.15)'
                  : '0 4px 20px rgba(255,140,122,0.25)'
                : 'none'};
              "
            >
              <div class="flex items-center justify-between w-full">
                <div
                  class="p-2.5 border transition-colors
                    {$theme === 'dark'
                    ? 'bg-[#111218] border-white/5 text-[#FF8C7A] group-hover/btn:text-white'
                    : 'bg-white border-zinc-200 text-[#FF8C7A] group-hover/btn:text-zinc-900'}"
                >
                  <FileCode size={20} />
                </div>
                {#if selectionType === "file"}
                  <span
                    class="text-[9px] px-2 py-0.5 border uppercase tracking-widest font-bold
                      {$theme === 'dark'
                      ? 'bg-[#FF8C7A]/10 text-[#FF8C7A] border-[#FF8C7A]/20'
                      : 'bg-[#FF8C7A]/15 text-[#E05D4A] border-[#FF8C7A]/30'}"
                  >
                    ACTIVE
                  </span>
                {/if}
              </div>
              <div>
                <h3
                  class="text-xs font-bold uppercase tracking-wider mb-1 {$theme ===
                  'dark'
                    ? 'text-[#EAEAEA]'
                    : 'text-zinc-800'}"
                >
                  Single File Scan
                </h3>
                <p
                  class="text-[11px] leading-relaxed {$theme === 'dark'
                    ? 'text-[#EAEAEA]/50'
                    : 'text-zinc-500'}"
                >
                  Analyze a standalone source or header file (.cpp, .c, .h, .cc,
                  .cxx) for localized security issues.
                </p>
              </div>
            </button>

            <!-- Folder Selector Button -->
            <button
              onclick={() => handleFolderPick(onFolderPicked, onError)}
              class="relative flex flex-col items-start gap-4 p-6 border transition-all duration-300 text-left group/btn cursor-pointer
                {selectionType === 'folder'
                ? 'scale-[1.02]'
                : 'hover:scale-[1.01] active:scale-[0.99]'}
                {$theme === 'dark' ? 'bg-[#0A0B10]/80' : 'bg-[#FAFAFA]/90'}"
              style="
                border-color: {selectionType === 'folder'
                ? '#D6B492'
                : $theme === 'dark'
                  ? 'rgba(255,255,255,0.05)'
                  : 'rgba(0,0,0,0.08)'}; 
                box-shadow: {selectionType === 'folder'
                ? $theme === 'dark'
                  ? '0 0 25px rgba(214,180,146,0.15)'
                  : '0 4px 20px rgba(214,180,146,0.25)'
                : 'none'};
              "
            >
              <div class="flex items-center justify-between w-full">
                <div
                  class="p-2.5 border transition-colors
                    {$theme === 'dark'
                    ? 'bg-[#111218] border-white/5 text-[#D6B492] group-hover/btn:text-white'
                    : 'bg-white border-zinc-200 text-[#D6B492] group-hover/btn:text-zinc-900'}"
                >
                  <FolderOpen size={20} />
                </div>
                {#if selectionType === "folder"}
                  <span
                    class="text-[9px] px-2 py-0.5 border uppercase tracking-widest font-bold
                      {$theme === 'dark'
                      ? 'bg-[#D6B492]/10 text-[#D6B492] border-[#D6B492]/20'
                      : 'bg-[#D6B492]/15 text-[#9E7A53] border-[#D6B492]/30'}"
                  >
                    ACTIVE
                  </span>
                {/if}
              </div>
              <div>
                <h3
                  class="text-xs font-bold uppercase tracking-wider mb-1 {$theme ===
                  'dark'
                    ? 'text-[#EAEAEA]'
                    : 'text-zinc-800'}"
                >
                  Project Folder Scan
                </h3>
                <p
                  class="text-[11px] leading-relaxed {$theme === 'dark'
                    ? 'text-[#EAEAEA]/50'
                    : 'text-zinc-500'}"
                >
                  Recursively scan all C/C++ files inside a directory to detect
                  project-wide vulnerabilities.
                </p>
              </div>
            </button>
          </div>

          <!-- Selected Path Status HUD -->
          {#if selectedName}
            <div
              class="border p-4 flex items-center justify-between gap-4 transition-colors duration-300
                {$theme === 'dark'
                ? 'bg-[#0A0B10] border-white/5'
                : 'bg-[#F4F4F5] border-zinc-200'}"
            >
              <div class="flex items-center gap-3 min-w-0">
                <div
                  class="w-1.5 h-1.5 rounded-full bg-[#FF849C] animate-ping shrink-0"
                ></div>
                <div class="min-w-0">
                  <div
                    class="text-[10px] uppercase font-semibold mb-0.5 {$theme ===
                    'dark'
                      ? 'text-[#EAEAEA]/40'
                      : 'text-zinc-500'}"
                  >
                    SELECTED TARGET
                  </div>
                  <div
                    class="text-xs font-bold truncate font-mono {$theme ===
                    'dark'
                      ? 'text-[#EAEAEA]/80'
                      : 'text-zinc-800'}"
                  >
                    {selectedName}
                  </div>
                  <div
                    class="text-[10px] truncate font-mono {$theme === 'dark'
                      ? 'text-[#EAEAEA]/50'
                      : 'text-zinc-400'}"
                  >
                    {selectedPath}
                  </div>
                </div>
              </div>
              <button
                onclick={() => {
                  selectedPath = null;
                  selectedName = "";
                  selectionType = null;
                }}
                class="text-[10px] uppercase tracking-wider cursor-pointer font-bold transition-colors
                  {$theme === 'dark'
                  ? 'text-[#FF849C]/80 hover:text-[#FF849C]'
                  : 'text-[#D04361] hover:text-[#B02844]'}"
              >
                Clear
              </button>
            </div>
          {/if}

          <!-- Error Log display -->
          {#if errorMessage}
            <div
              class="border p-4 flex gap-3 text-xs transition-colors duration-300
                {$theme === 'dark'
                ? 'bg-[#FF849C]/5 border-[#FF849C]/20 text-[#FF849C]'
                : 'bg-[#FF849C]/10 border-[#FF849C]/30 text-[#D04361]'}"
            >
              <ShieldAlert size={16} class="shrink-0 mt-0.5" />
              <div>
                <span class="font-bold uppercase tracking-wide"
                  >SYSTEM ERROR:</span
                >
                {errorMessage}
              </div>
            </div>
          {/if}

          <!-- Action Button Section (Full Width Button) -->
          <div
            class="pt-4 border-t {$theme === 'dark'
              ? 'border-white/5'
              : 'border-zinc-100'}"
          >
            <button
              disabled={!selectedPath}
              onclick={() =>
                selectedPath &&
                selectionType &&
                handleAnalyze(selectedPath, selectionType)}
              class="w-full py-4 bg-gradient-to-r from-[#FF8C7A] via-[#D6B492] to-[#FF849C] text-[#0A0B10] font-black uppercase tracking-widest text-xs hover:opacity-90 active:scale-[0.99] disabled:opacity-30 disabled:pointer-events-none transition-all relative overflow-hidden group/run cursor-pointer"
            >
              <div
                class="absolute inset-0 bg-white/20 translate-y-full group-hover/run:translate-y-0 transition-transform duration-300"
              ></div>
              <span
                class="relative z-10 flex items-center justify-center gap-2"
              >
                Initiate Code Scan
                <svg
                  viewBox="0 0 24 24"
                  class="w-4 h-4 fill-[#0A0B10]"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M16.1716 10.9999L10.8076 5.63589L12.2218 4.22168L20 11.9999L12.2218 19.778L10.8076 18.3638L16.1716 12.9999H4V10.9999H16.1716Z"
                  />
                </svg>
              </span>
            </button>
          </div>
        </div>
      </div>

      <!-- Footer navigation -->
      <footer class="text-center mt-2 relative z-10">
        <a
          href="/history"
          class="inline-flex items-center gap-2 text-xs uppercase tracking-wider transition-all duration-300 border px-4 py-2 cursor-pointer
            {$theme === 'dark'
            ? 'text-[#D6B492]/70 hover:text-[#D6B492] border-white/5 bg-[#111218] hover:border-[#D6B492]/20'
            : 'text-[#9E7A53] hover:text-[#7A5A35] border-zinc-200 bg-white hover:border-[#D6B492]/50 shadow-[0_2px_10px_rgba(0,0,0,0.02)]'}"
        >
          View System Scan Log History →
        </a>
      </footer>
    </div>
  </main>
</div>
