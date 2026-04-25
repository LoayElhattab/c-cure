export interface AnalysisSummary {
    id: number;
    projectName: string;
    projectPath: string | null;
    timestamp: string;
    totalFunctions: number;
    vulnCount: number;
}

export interface Report {
    id: number;
    projectName: string;
    projectPath: string | null;
    timestamp: string;
    files: FileData[];
}

export interface FileData {
    filePath: string;
    functions: FunctionData[];
}

export interface FunctionData {
    id?: number | null;
    functionName: string;
    code: string;
    verdict: string;
    cwe: string | null;
    cweName: string | null;
    severity: string | null;
    confidence: number | null;
    startLine: number | null;
    endLine: number | null;
}

export interface DashboardStats {
    kpis: Kpis;
    cweCounts: CweCount[];
    severityCounts: SeverityCount[];
    fileRatios: FileRatio[];
    recentAnalyses: AnalysisSummary[];
}

export interface TrendData {
    timestamp: string;
    vulnCount: number;
}

export interface StatisticsData {
    dashboard: DashboardStats;
    trend: TrendData[];
}

export interface Kpis {
    totalAnalyses: number;
    totalFiles: number;
    totalFunctions: number;
    totalVulnerable: number;
    totalSafe: number;
}

export interface CweCount {
    cwe: string;
    cweName: string | null;
    severity: string | null;
    count: number;
}

export interface SeverityCount {
    severity: string;
    count: number;
}

export interface FileRatio {
    label: string;
    safe: number;
    vuln: number;
}

export interface WatchedProject {
    id: number;
    name: string;
    folderPath: string;
    registeredAt: string;
}

export interface AnalysisResult {
    analysisId: number;
    projectName: string;
    path: string;
    filesScanned: number;
    totalFunctions: number;
    vulnCount: number;
    functions: FunctionData[];
}

export interface ExtractedFunction {
    functionName: string;
    code: string;
    startLine: number;
    endLine: number;
}

export interface MonitorChangeResult {
    projectId: number;
    projectName: string;
    folderPath: string;
    changed: string[];
    added: string[];
    deleted: string[];
    totalChanges: number;
}

// Command Response Interfaces
export interface VulnCountResponse {
    count: number;
}

export interface ExtractFunctionsResponse {
    functions: ExtractedFunction[];
    count: number;
}

export interface CheckApiResponse {
    reachable: boolean;
}

export interface GetSettingsResponse {
    kaggleUrl: string;
}

export interface SaveSettingsResponse {
    saved: boolean;
}

export interface GeneratePdfResponse {
    path: string;
}

export interface MonitorRegisterResponse {
    id: number;
    name: string;
    folderPath: string;
    filesTracked: number;
}

export interface MonitorRefreshResponse {
    refreshed: boolean;
    filesTracked: number;
}

export interface MonitorRemoveResponse {
    removed: boolean;
}
