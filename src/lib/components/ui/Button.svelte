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
		primary: "bg-cyan-600 text-white shadow-[0_0_15px_rgba(8,145,178,0.3)] hover:bg-cyan-500 hover:shadow-[0_0_20px_rgba(8,145,178,0.5)] border-cyan-400",
		outline: "border border-zinc-700 text-zinc-300 hover:bg-zinc-800 hover:text-white hover:border-zinc-600",
		ghost: "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
	};

	const sizes = {
		sm: "px-3 py-1.5 text-xs",
		md: "px-4 py-2 text-sm",
		lg: "px-6 py-3 text-base"
	};
</script>

<ButtonPrimitive.Root
	class={cn(
		"inline-flex items-center justify-center rounded-md font-medium transition-all duration-200 active:scale-[0.98] disabled:opacity-50 disabled:pointer-events-none border border-transparent",
		variants[variant],
		sizes[size],
		className
	)}
	{...rest}
>
	{@render children?.()}
</ButtonPrimitive.Root>
