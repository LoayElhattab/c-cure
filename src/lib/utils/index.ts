type ClassValue =
	| string
	| number
	| bigint
	| boolean
	| null
	| undefined
	| ClassValue[]
	| { [key: string]: boolean | null | undefined };

export function cn(...inputs: ClassValue[]) {
	const classes: string[] = [];

	for (const input of inputs) {
		if (!input) continue;

		if (
			typeof input === "string" ||
			typeof input === "number" ||
			typeof input === "bigint"
		) {
			classes.push(String(input));
		} else if (Array.isArray(input)) {
			const nested = cn(...input);
			if (nested) classes.push(nested);
		} else if (typeof input === "object") {
			for (const [key, value] of Object.entries(input)) {
				if (value) classes.push(key);
			}
		}
	}

	return classes.join(" ");
}
