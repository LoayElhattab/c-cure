<script lang="ts">
	import { Progress as ProgressPrimitive } from "bits-ui";
	import { cn } from "$lib/utils";

	let {
		value = 0,
		max = 100,
		class: className,
		indicatorClass,
		...rest
	}: {
		value?: number;
		max?: number;
		class?: string;
		indicatorClass?: string;
	} = $props();
</script>

<ProgressPrimitive.Root
	class={cn("relative h-3 w-full overflow-hidden rounded-none border border-zinc-850 bg-zinc-950 p-[1px]", className)}
	{value}
	{max}
	{...rest}
>
	<div
		class={cn(
			"h-full w-full flex-1 bg-gradient-to-r from-accent/70 to-accent transition-all duration-500 ease-in-out shadow-[0_0_8px_var(--accent-glow)]",
			indicatorClass
		)}
		style="transform: translateX(-{100 - (100 * (value ?? 0)) / (max ?? 100)}%)"
	></div>

	<!-- HUD Repeating Mask to build High-Fidelity Segmented LED Style -->
	<div class="absolute inset-0 pointer-events-none bg-[linear-gradient(to_right,transparent_90%,var(--bg)_90%)] bg-[size:12px_100%]"></div>
</ProgressPrimitive.Root>