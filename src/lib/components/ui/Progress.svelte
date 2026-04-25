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
	class={cn("relative h-2 w-full overflow-hidden rounded-full bg-zinc-800", className)}
	{value}
	{max}
	{...rest}
>
	<div
		class={cn(
			"h-full w-full flex-1 bg-cyan-600 transition-all duration-500 ease-in-out shadow-[0_0_10px_rgba(8,145,178,0.5)]",
			indicatorClass
		)}
		style="transform: translateX(-{100 - (100 * (value ?? 0)) / (max ?? 100)}%)"
	></div>
</ProgressPrimitive.Root>
