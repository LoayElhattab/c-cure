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
		title?: string | import("svelte").Snippet;
		description?: string;
		footer?: import("svelte").Snippet;
	} & HTMLAttributes<HTMLDivElement> = $props();
</script>

<div
	class={cn(
		"rounded-lg border border-zinc-800 bg-zinc-900/50 backdrop-blur-sm text-zinc-100 shadow-xl overflow-hidden transition-all duration-300",
		className
	)}
	{...rest}
>
	{#if title || description}
		<div class="p-6 border-b border-zinc-800/50">
			{#if typeof title === "string"}
				<h3 class="text-lg font-semibold leading-none tracking-tight text-zinc-100">
					{title}
				</h3>
			{:else if title}
				{@render title()}
			{/if}
			{#if description}
				<p class="text-sm text-zinc-400 mt-1.5">
					{description}
				</p>
			{/if}
		</div>
	{/if}

	<div class="p-6 pt-0 mt-6">
		{@render children?.()}
	</div>

	{#if footer}
		<div class="p-6 pt-0 flex items-center">
			{@render footer()}
		</div>
	{/if}
</div>
