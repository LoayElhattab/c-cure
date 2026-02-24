<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { ShieldAlert } from "lucide-svelte";
  import { STEPS, runAnalysis } from "./logic";

  let currentStep = 0;
  let progress = 0;
  let errorMessage = "";
  let showSummary = false;
  let summaryData: any = null;

  function setStep(i: number) {
    currentStep = i;
    progress = Math.round((i / (STEPS.length - 1)) * 100);
  }

  onMount(() => {
    runAnalysis(
      setStep,
      (data) => {
        summaryData = data;
        showSummary = true;
      },
      (msg) => {
        errorMessage = msg;
      },
      (id) => goto(`/report/${id}`),
    );
  });
</script>

<div
  class="min-h-screen flex flex-col items-center justify-center px-6 relative overflow-hidden"
  style="background:var(--bg)"
>
  <div class="absolute inset-0 pointer-events-none bg-grid"></div>
  <div
    class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] rounded-full pointer-events-none"
    style="background:radial-gradient(circle,var(--accent-glow) 0%,transparent 60%)"
  ></div>

  {#if showSummary && summaryData}
    <!-- Summary splash -->
    <div class="relative z-10 w-full max-w-sm animate-fade-up text-center">
      <div
        class="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-5 gradient-bg"
        style="box-shadow:0 0 30px rgba(255,195,157,0.3)"
      >
        <ShieldAlert size={28} color="#fff" />
      </div>
      <h2 class="text-lg font-bold mb-1" style="color:var(--text)">
        Analysis Complete
      </h2>
      <p class="text-xs mb-7" style="color:var(--muted)">
        {summaryData.project_name}
      </p>

      <div class="grid grid-cols-3 gap-3 mb-6">
        {#each [{ label: "Functions", value: summaryData.total_functions ?? 0, color: "var(--accent)" }, { label: "Vulnerable", value: summaryData.vuln_count ?? 0, color: "var(--danger)" }, { label: "Clean", value: (summaryData.total_functions ?? 0) - (summaryData.vuln_count ?? 0), color: "var(--success)" }] as stat, i}
          <div class="card p-4 animate-fade-up stagger-{i + 1}">
            <p class="text-2xl font-bold" style="color:{stat.color}">
              {stat.value}
            </p>
            <p class="text-xs mt-1" style="color:var(--muted)">{stat.label}</p>
          </div>
        {/each}
      </div>

      <p class="text-xs mb-2" style="color:var(--subtle)">Opening report...</p>
      <div
        class="h-0.5 rounded-full overflow-hidden"
        style="background:var(--border)"
      >
        <div
          class="h-full rounded-full"
          style="background:linear-gradient(90deg,var(--accent-start),var(--accent-end));animation:progress-fill 2.5s linear forwards"
        ></div>
      </div>
    </div>
  {:else}
    <!-- Steps -->
    <div class="relative z-10 w-full max-w-sm">
      <div class="text-center mb-10">
        <h1 class="text-lg font-bold mb-1" style="color:var(--text)">
          Analyzing
        </h1>
        <p class="text-xs" style="color:var(--muted)">
          Please wait while C-Cure scans your code
        </p>
      </div>

      <!-- Progress bar -->
      <div
        class="h-px rounded-full mb-8 overflow-hidden"
        style="background:var(--border)"
      >
        <div
          class="h-full rounded-full transition-all duration-500"
          style="width:{progress}%;background:linear-gradient(90deg,var(--accent-start),var(--accent-end));box-shadow:0 0 8px var(--accent-glow)"
        ></div>
      </div>

      <div class="space-y-5">
        {#each STEPS as step, i}
          {@const done = i < currentStep}
          {@const active = i === currentStep}
          <div
            class="flex items-start gap-4 transition-all duration-300"
            style="opacity:{i > currentStep ? 0.3 : 1}"
          >
            <div
              class="w-5 h-5 rounded-full flex items-center justify-center shrink-0 mt-0.5 transition-all duration-300"
              style={done
                ? "background:var(--success-dim);border:1px solid var(--success)"
                : active
                  ? "background:var(--accent-dim);border:1px solid var(--accent)"
                  : "background:var(--surface-2);border:1px solid var(--border)"}
            >
              {#if done}
                <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
                  <path
                    d="M2 5l2.5 2.5L8 3"
                    stroke="var(--success)"
                    stroke-width="1.5"
                    stroke-linecap="round"
                  />
                </svg>
              {:else if active}
                <div
                  class="w-1.5 h-1.5 rounded-full"
                  style="background:var(--accent);animation:pulse-red 1s infinite"
                ></div>
              {/if}
            </div>

            <div>
              <p
                class="text-xs font-medium"
                style="color:{done
                  ? 'var(--success)'
                  : active
                    ? 'var(--text)'
                    : 'var(--muted)'}"
              >
                {step.label}
              </p>
              {#if active}
                <p
                  class="text-xs mt-0.5 animate-fade-in"
                  style="color:var(--muted)"
                >
                  {step.detail}
                </p>
              {/if}
            </div>
          </div>
        {/each}
      </div>

      {#if errorMessage}
        <div
          class="mt-8 rounded-xl p-4 animate-fade-up"
          style="background:var(--danger-dim);border:1px solid rgba(239,68,68,0.25)"
        >
          <p class="text-xs font-semibold mb-1" style="color:var(--danger)">
            Analysis failed
          </p>
          <p class="text-xs leading-relaxed" style="color:#fca5a5">
            {errorMessage}
          </p>
          <a
            href="/"
            class="text-xs mt-3 inline-block transition-colors"
            style="color:var(--accent)">← Try again</a
          >
        </div>
      {/if}
    </div>
  {/if}
</div>
