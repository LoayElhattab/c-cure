<script lang="ts">
	import { cn } from "$lib/utils";
	import { type HTMLAttributes } from "svelte/elements";

	let {
		class: className,
		variant = "default",
		children,
		...rest
	}: {
		variant?: "default" | "safe" | "vulnerable" | "severity-low" | "severity-medium" | "severity-high" | "outline";
		children?: import("svelte").Snippet;
	} & HTMLAttributes<HTMLSpanElement> = $props();

	const variants = {
		default: "bg-zinc-950 text-zinc-300 border-zinc-800",
		safe: "bg-emerald-950/15 text-emerald-400 border-emerald-500/25",
		vulnerable: "bg-rose-950/15 text-rose-400 border-rose-500/25 shadow-[0_0_10px_rgba(244,63,94,0.06)]",
		"severity-low": "bg-blue-950/15 text-blue-400 border-blue-500/25",
		"severity-medium": "bg-amber-950/15 text-amber-400 border-amber-500/25",
		"severity-high": "bg-orange-950/15 text-orange-500 border-orange-500/25",
		outline: "border-zinc-800 text-zinc-500 bg-transparent"
	};
</script>

<span
	class={cn(
		"inline-flex items-center rounded-none border px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider font-semibold transition-colors focus:outline-none",
		variants[variant],
		className
	)}
	{...rest}
>
	{@render children?.()}
</span>