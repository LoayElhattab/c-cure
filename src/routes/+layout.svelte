<script>
  import "../app.css";
  import { page } from "$app/stores";
  import { Upload, BarChart3, Clock, Settings } from "lucide-svelte";
  import { toasts } from "$lib/toast";
  import { theme } from "$lib/theme";

  const navLinks = [
    { href: "/", label: "Upload", icon: Upload },
    { href: "/statistics", label: "Statistics", icon: BarChart3 },
    { href: "/history", label: "History", icon: Clock },
  ];
</script>

<div
  class="min-h-screen flex flex-col"
  style="background:var(--bg);color:var(--text)"
>
  <nav
    class="h-14 px-5 flex items-center gap-1 sticky top-0 z-50"
    style="background:var(--surface);border-bottom:1px solid var(--border);backdrop-filter:blur(8px)"
  >
    <a href="/" class="flex items-center mr-4 shrink-0 group">
      <img
        src={$theme === "dark" ? "/logo-white.png" : "/logo-black.png"}
        alt="C-Cure"
        class="h-5 w-auto transition-transform duration-200 group-hover:scale-110"
      />
    </a>

    <div class="w-px h-4 mx-2 shrink-0" style="background:var(--border)"></div>

    {#each navLinks as link (link.href)}
      <a
        href={link.href}
        class="nav-link {$page.url.pathname === link.href ||
        ($page.url.pathname.startsWith(link.href) && link.href !== '/')
          ? 'active'
          : ''}"
      >
        <svelte:component this={link.icon} size={13} />
        {link.label}
      </a>
    {/each}

    <div class="flex-1"></div>

    <a
      href="/settings"
      class="nav-link {$page.url.pathname === '/settings' ? 'active' : ''}"
    >
      <Settings size={13} />
      Settings
    </a>
  </nav>

  <main class="flex-1"><slot /></main>

  <!-- Toasts -->
  <div
    class="fixed bottom-5 right-5 z-50 flex flex-col gap-2 pointer-events-none"
  >
    {#each $toasts as t (t.id)}
      <div
        class="pointer-events-auto px-4 py-3 rounded-xl text-xs font-medium shadow-2xl
        flex items-center gap-3 min-w-[240px] max-w-xs animate-fade-up"
        style={t.type === "success"
          ? "background:#0a2318;border:1px solid #166534;color:#86efac"
          : t.type === "error"
            ? "background:#2a0a0a;border:1px solid #991b1b;color:#fca5a5"
            : "background:var(--surface-2);border:1px solid var(--border);color:var(--muted)"}
      >
        <span
          >{t.type === "success" ? "✓" : t.type === "error" ? "✕" : "ℹ"}</span
        >
        {t.message}
      </div>
    {/each}
  </div>
</div>
