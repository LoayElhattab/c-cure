export const CWE_DB: Record<string, {
    name: string;
    description: string;
    scenario: string;
    mitigations: string[];
    cvss_vector: string;
    cvss_score: number;
    cvss_severity: string;
}> = {
    "CWE-125": {
        name: "Out-of-bounds Read",
        description: "The software reads data past the end or before the beginning of the intended buffer.",
        scenario: "An attacker may read sensitive memory contents or trigger a crash by inducing out-of-bounds access.",
        mitigations: [
            "Validate all array indices and buffer lengths before access",
            "Use bounds-checking containers (std::vector, std::span)",
            "Enable AddressSanitizer and compiler flag -fstack-protector"
        ],
        cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
        cvss_score: 9.1,
        cvss_severity: "Critical"
    },
    "CWE-787": {
        name: "Out-of-bounds Write",
        description: "The software writes data past the end or before the beginning of the intended buffer.",
        scenario: "Enables attackers to corrupt heap/stack memory, potentially achieving arbitrary code execution.",
        mitigations: [
            "Replace unsafe functions (strcpy, sprintf) with bounded equivalents",
            "Perform explicit length checks before all write operations",
            "Enable ASLR, stack canaries, and DEP/NX"
        ],
        cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score: 9.8,
        cvss_severity: "Critical"
    },
    "CWE-190": {
        name: "Integer Overflow or Wraparound",
        description: "A calculation produces a value that exceeds the maximum size of the integer type.",
        scenario: "Integer overflow can silently produce incorrect allocation sizes, leading to heap buffer overflows.",
        mitigations: [
            "Validate input ranges before arithmetic operations",
            "Use checked arithmetic libraries or compiler intrinsics",
            "Cast to larger types before multiplication when overflow is possible"
        ],
        cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
        cvss_score: 8.6,
        cvss_severity: "High"
    },
    "CWE-369": {
        name: "Divide By Zero",
        description: "The product divides a value by zero, causing undefined behavior or a crash.",
        scenario: "An attacker supplying zero as input to a divisor can crash the process or trigger undefined behavior.",
        mitigations: [
            "Always validate that divisors are non-zero before division",
            "Add guard clauses at function entry points",
            "Use exception handling for arithmetic operations on untrusted input"
        ],
        cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        cvss_score: 7.5,
        cvss_severity: "High"
    },
    "CWE-415": {
        name: "Double Free",
        description: "The product calls free() twice on the same memory address, corrupting the allocator state.",
        scenario: "Corrupted allocator metadata can be leveraged to achieve arbitrary writes and code execution.",
        mitigations: [
            "Set pointers to NULL immediately after calling free()",
            "Use RAII and smart pointers (std::unique_ptr, std::shared_ptr)",
            "Run Valgrind or AddressSanitizer during testing"
        ],
        cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score: 8.1,
        cvss_severity: "High"
    },
    "CWE-476": {
        name: "NULL Pointer Dereference",
        description: "The application dereferences a pointer that it expects to be valid but is NULL.",
        scenario: "Typically causes an immediate crash (SIGSEGV), enabling denial-of-service attacks.",
        mitigations: [
            "Check all pointers for NULL before dereferencing",
            "Prefer references over raw pointers where ownership is clear",
            "Initialize all pointer variables at declaration"
        ],
        cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        cvss_score: 7.5,
        cvss_severity: "High"
    }
};

export function getCWEData(cwe: string | null) {
    if (!cwe) return null;
    return CWE_DB[cwe] ?? null;
}

export function getCVSSColor(score: number): string {
    if (score >= 9.0) return "#ef4444";
    if (score >= 7.0) return "#f97316";
    if (score >= 4.0) return "#eab308";
    return "#22c55e";
}

export function getSeverityBorderColor(severity: string | null): string {
    switch (severity) {
        case "Critical": return "#ef4444";
        case "High": return "#f97316";
        case "Medium": return "#eab308";
        case "Low": return "#3b82f6";
        default: return "var(--success)";
    }
}

export function getSeverityGlow(severity: string | null): string {
    switch (severity) {
        case "Critical": return "rgba(239,68,68,0.35)";
        case "High": return "rgba(249,115,22,0.30)";
        case "Medium": return "rgba(234,179,8,0.25)";
        case "Low": return "rgba(59,130,246,0.25)";
        default: return "transparent";
    }
}