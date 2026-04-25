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
		default: "bg-zinc-800 text-zinc-100 border-zinc-700",
		safe: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
		vulnerable: "bg-rose-500/10 text-rose-400 border-rose-500/20 shadow-[0_0_10px_rgba(244,63,94,0.1)]",
		"severity-low": "bg-blue-500/10 text-blue-400 border-blue-500/20",
		"severity-medium": "bg-amber-500/10 text-amber-400 border-amber-500/20",
		"severity-high": "bg-orange-600/10 text-orange-500 border-orange-600/20",
		outline: "border-zinc-700 text-zinc-400"
	};
</script>

<span
	class={cn(
		"inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-zinc-400 focus:ring-offset-2",
		variants[variant],
		className
	)}
	{...rest}
>
	{@render children?.()}
</span>
