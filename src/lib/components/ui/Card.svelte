<script lang="ts">
	import { cn } from "$lib/utils";
	import { type HTMLAttributes } from "svelte/elements";

	let {
		class: className,
		children,
		title,
		description,
		footer,
		...rest
	}: {
		class?: string;
		children?: import("svelte").Snippet;
		title?: string;
		description?: string;
		footer?: import("svelte").Snippet;
	} & HTMLAttributes<HTMLDivElement> = $props();
</script>

<div
	class={cn(
		"rounded-none border border-zinc-850 bg-zinc-950/45 backdrop-blur-md text-zinc-100 shadow-2xl overflow-hidden transition-all duration-300 relative",
		className
	)}
	{...rest}
>
	<!-- HUD Top Accent Line -->
	<div class="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-zinc-800/20 via-zinc-700/40 to-zinc-800/20"></div>

	{#if title || description}
		<div class="px-5 py-4 border-b border-zinc-900/60 bg-zinc-950/20">
			{#if title}
				<h3 class="text-xs font-mono font-bold uppercase tracking-widest text-zinc-200">
					{title}
				</h3>
			{/if}
			{#if description}
				<p class="text-[11px] font-mono uppercase tracking-wider text-zinc-500 mt-1">
					{description}
				</p>
			{/if}
		</div>
	{/if}

	<div class="p-5">
		{@render children?.()}
	</div>

	{#if footer}
		<div class="px-5 py-4 border-t border-zinc-900/40 bg-zinc-950/10 flex items-center">
			{@render footer()}
		</div>
	{/if}
</div>