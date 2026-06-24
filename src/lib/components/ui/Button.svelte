<script lang="ts">
	import { Button as ButtonPrimitive } from "bits-ui";
	import { type HTMLButtonAttributes } from "svelte/elements";
	import { cn } from "$lib/utils";

	let {
		class: className,
		variant = "primary",
		size = "md",
		children,
		...rest
	}: {
		variant?: "primary" | "outline" | "ghost";
		size?: "sm" | "md" | "lg";
		children?: import("svelte").Snippet;
	} & HTMLButtonAttributes = $props();

	const variants = {
		primary: "bg-transparent text-[#ff9f8a] border-[#ff9f8a] hover:bg-[#ff9f8a]/10 hover:shadow-[0_0_15px_rgba(255,159,138,0.2)] active:bg-[#ff9f8a]/15 active:scale-[0.98]",
		outline: "border border-zinc-800 text-zinc-400 hover:bg-zinc-900/60 hover:text-white hover:border-zinc-750 active:scale-[0.98]",
		ghost: "text-zinc-500 hover:bg-zinc-950/50 hover:text-zinc-300 border-transparent"
	};

	const sizes = {
		sm: "px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider",
		md: "px-4 py-2 text-xs font-mono uppercase tracking-wider",
		lg: "px-6 py-3 text-sm font-mono uppercase tracking-widest"
	};
</script>

<ButtonPrimitive.Root
	class={cn(
		"inline-flex items-center justify-center rounded-none font-semibold transition-all duration-150 disabled:opacity-30 disabled:pointer-events-none border",
		variants[variant],
		sizes[size],
		className
	)}
	{...rest}
>
	{@render children?.()}
</ButtonPrimitive.Root>