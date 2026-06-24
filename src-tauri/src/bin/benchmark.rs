// CCure DuckDB Performance Benchmark
//
// Run with:  cargo run --bin benchmark --release
//
// This binary creates an in-memory DuckDB database, seeds it with realistic
// data (1 analysis, 2 000 files, 100 000 functions), then runs four
// isolated benchmarks so you can pinpoint exactly where the 3-minute load
// time is coming from.
//
// ┌──────────────────────────────────────────────────────┐
// │  Benchmark 0 – Data seeding (Appender insert speed)  │
// │  Benchmark 1 – OLAP aggregation  (stats_repo queries)│
// │  Benchmark 2 – Full table scan   (100 k rows → Vec)  │
// │  Benchmark 3 – JSON serialization (serde_json)       │
// └──────────────────────────────────────────────────────┘

// Windows only – keeps the linker happy without the full Tauri harness.
#[cfg(target_os = "windows")]
#[link(name = "rstrtmgr")]
extern "C" {}

use duckdb::{params, Connection, Result as DuckResult};
use serde::{Deserialize, Serialize};
use std::time::Instant;

// ─────────────────────────────────────────────────────────────────────────────
// Mirror of the application's FunctionData struct (no Tauri / AppError deps)
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Serialize, Deserialize, Debug, Clone)]
struct FunctionData {
    id: Option<i32>,
    function_name: String,
    code: String,
    verdict: String,
    cwe: Option<String>,
    cwe_name: Option<String>,
    severity: Option<String>,
    confidence: Option<f64>,
    start_line: Option<i32>,
    end_line: Option<i32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Static data pools (mirrors generate_gigantic_report.rs)
// ─────────────────────────────────────────────────────────────────────────────
const CWES: &[(&str, &str, &str)] = &[
    ("CWE-125", "Out-of-bounds Read", "High"),
    ("CWE-787", "Out-of-bounds Write", "Critical"),
    ("CWE-190", "Integer Overflow or Wraparound", "High"),
    ("CWE-369", "Divide By Zero", "Medium"),
    ("CWE-415", "Double Free", "High"),
    ("CWE-476", "NULL Pointer Dereference", "High"),
];

/// ~200-character C++ code snippets for realistic payload sizes.
const CODE_TEMPLATES: &[&str] = &[
    // ~200 chars
    "void copy_buffer(const char* src, size_t len) {\n    char dest[64];\n    // UNSAFE: No length check before strcpy call\n    strcpy(dest, src);\n    dest[63] = '\\0';\n}",
    "int read_idx(const int* arr, size_t sz, int idx) {\n    // UNSAFE: index never validated against sz\n    return arr[idx];\n}",
    "void* alloc_buf(int count) {\n    // UNSAFE: integer overflow on multiplication\n    size_t total = count * sizeof(double);\n    return malloc(total);\n}",
    "double avg(double sum, int count) {\n    // UNSAFE: no zero-check before division\n    return sum / count;\n}",
    "void free_res(char* ptr) {\n    free(ptr);\n    // ... complex logic elided ...\n    free(ptr); // UNSAFE: double-free\n}",
    "const char* get_name(struct User* u) {\n    // UNSAFE: NULL pointer not checked\n    return u->username;\n}",
    "int safe_sum(const int* arr, size_t sz) {\n    int s = 0;\n    for (size_t i = 0; i < sz; ++i) s += arr[i];\n    return s;\n}",
    "bool valid_age(int age) { return age >= 0 && age <= 150; }",
    "std::string greet(const std::string& n) {\n    if (n.empty()) return \"Hello, Guest!\";\n    return \"Hello, \" + n + \"!\";\n}",
    "void safe_free(char** p) {\n    if (p && *p) { free(*p); *p = nullptr; }\n}",
    "int safe_div(int a, int b) {\n    if (b == 0) return 0;\n    return a / b;\n}",
    "void log_event(const char* msg, int level) {\n    if (!msg) return;\n    fprintf(stderr, \"[%d] %s\\n\", level, msg);\n}",
];

// ─────────────────────────────────────────────────────────────────────────────
// Schema initialisation (identical to db/mod.rs init_db_on_conn)
// ─────────────────────────────────────────────────────────────────────────────
fn init_schema(conn: &Connection) -> DuckResult<()> {
    conn.execute_batch(
        "
        CREATE SEQUENCE IF NOT EXISTS seq_analyses  START 1;
        CREATE SEQUENCE IF NOT EXISTS seq_files     START 1;
        CREATE SEQUENCE IF NOT EXISTS seq_functions START 1;

        CREATE TABLE IF NOT EXISTS analyses (
            id           INTEGER PRIMARY KEY DEFAULT nextval('seq_analyses'),
            timestamp    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            project_name VARCHAR NOT NULL,
            project_path VARCHAR
        );
        CREATE TABLE IF NOT EXISTS files (
            id          INTEGER PRIMARY KEY DEFAULT nextval('seq_files'),
            analysis_id INTEGER NOT NULL,
            file_path   VARCHAR NOT NULL,
            FOREIGN KEY(analysis_id) REFERENCES analyses(id)
        );
        CREATE TABLE IF NOT EXISTS functions (
            id            INTEGER PRIMARY KEY DEFAULT nextval('seq_functions'),
            file_id       INTEGER NOT NULL,
            function_name VARCHAR NOT NULL,
            code          VARCHAR NOT NULL,
            verdict       VARCHAR NOT NULL,
            cwe           VARCHAR,
            cwe_name      VARCHAR,
            severity      VARCHAR,
            confidence    DOUBLE,
            start_line    INTEGER,
            end_line      INTEGER,
            FOREIGN KEY(file_id) REFERENCES files(id)
        );

        CREATE INDEX IF NOT EXISTS idx_files_analysis_id    ON files(analysis_id);
        CREATE INDEX IF NOT EXISTS idx_functions_file_id    ON functions(file_id);
        CREATE INDEX IF NOT EXISTS idx_functions_verdict    ON functions(verdict);
        CREATE INDEX IF NOT EXISTS idx_functions_file_v     ON functions(file_id, verdict);
        ",
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Pretty-printing helpers
// ─────────────────────────────────────────────────────────────────────────────
fn print_header(title: &str) {
    let width = 62usize;
    let pad = (width.saturating_sub(title.len() + 4)) / 2;
    println!();
    println!("┌{}┐", "─".repeat(width));
    println!("│{:pad$}  {}  {:pad$}│", "", title, "", pad = pad);
    println!("└{}┘", "─".repeat(width));
}

fn print_row(label: &str, value: &str) {
    println!("  {:<38}  {}", label, value);
}

fn print_separator() {
    println!("  {}", "─".repeat(58));
}

fn print_result_header() {
    println!();
    println!("  {:<38}  Value", "Metric");
    print_separator();
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────
fn main() -> Result<(), Box<dyn std::error::Error>> {
    const FILES: usize = 2_000;
    const FUNCS_PER_FILE: usize = 50;
    const TOTAL_FUNCTIONS: usize = FILES * FUNCS_PER_FILE;
    const VULN_RATE_PCT: usize = 10; // ≈ 10 %

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║          CCure DuckDB Performance Benchmark Suite            ║");
    println!("║                  (in-memory database)                        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!(
        "  Dataset: {} analyses · {} files · {} functions",
        1, FILES, TOTAL_FUNCTIONS
    );
    println!(
        "  Vulnerable: ~{}% ({} funcs with CWE data)",
        VULN_RATE_PCT,
        TOTAL_FUNCTIONS * VULN_RATE_PCT / 100
    );

    // ── Open in-memory DuckDB ─────────────────────────────────────────────
    let mut conn = Connection::open_in_memory()?;
    init_schema(&conn)?;

    // ─────────────────────────────────────────────────────────────────────
    // BENCHMARK 0 – Data seeding via Appender
    // ─────────────────────────────────────────────────────────────────────
    print_header("Benchmark 0 · Data Seeding (Appender)");
    print_result_header();

    let seed_start = Instant::now();

    // Insert the single analysis row.
    let mut astmt = conn
        .prepare("INSERT INTO analyses (project_name, project_path) VALUES (?, ?) RETURNING id")?;
    let analysis_id: i64 = astmt.query_row(
        params!["BENCHMARK_PROJECT", "/mock/projects/benchmark"],
        |row| row.get(0),
    )?;
    drop(astmt);

    let tx = conn.transaction()?;

    // File insert statement (returns generated id).
    let mut file_stmt =
        tx.prepare("INSERT INTO files (analysis_id, file_path) VALUES (?, ?) RETURNING id")?;

    // Function appender.
    let mut appender = tx.appender("functions")?;
    appender.add_column("file_id")?;
    appender.add_column("function_name")?;
    appender.add_column("code")?;
    appender.add_column("verdict")?;
    appender.add_column("cwe")?;
    appender.add_column("cwe_name")?;
    appender.add_column("severity")?;
    appender.add_column("confidence")?;
    appender.add_column("start_line")?;
    appender.add_column("end_line")?;

    let n_codes = CODE_TEMPLATES.len();
    let n_cwes = CWES.len();

    for f_idx in 1..=FILES {
        let file_path = format!("src/module_{:04}/component_{:04}.cpp", f_idx / 10, f_idx);
        let file_id: i64 =
            file_stmt.query_row(params![analysis_id, file_path], |row| row.get(0))?;

        for fn_idx in 1..=FUNCS_PER_FILE {
            let func_index = (f_idx - 1) * FUNCS_PER_FILE + fn_idx;

            // Deterministic pseudo-random: ~10 % vulnerable
            let is_vulnerable = ((func_index * 17 + 5) % 100) < VULN_RATE_PCT;
            let code = CODE_TEMPLATES[func_index % n_codes];
            let start_line = (fn_idx * 15) as i32;
            let end_line = start_line + 12;

            if is_vulnerable {
                let (cwe, cwe_name, severity) = CWES[func_index % n_cwes];
                let confidence = 0.70 + (((func_index * 3) % 25) as f64) / 100.0;
                appender.append_row(params![
                    file_id,
                    format!("vuln_fn_{func_index}"),
                    code,
                    "vulnerable",
                    Some(cwe.to_string()),
                    Some(cwe_name.to_string()),
                    Some(severity.to_string()),
                    Some(confidence),
                    Some(start_line),
                    Some(end_line),
                ])?;
            } else {
                let confidence = 0.85 + (((func_index * 7) % 15) as f64) / 100.0;
                appender.append_row(params![
                    file_id,
                    format!("safe_fn_{func_index}"),
                    code,
                    "safe",
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    Some(confidence),
                    Some(start_line),
                    Some(end_line),
                ])?;
            }
        }
    }

    appender.flush()?;
    drop(appender);
    drop(file_stmt);
    tx.commit()?;

    let seed_ms = seed_start.elapsed().as_millis();
    let seed_rate = TOTAL_FUNCTIONS as f64 / seed_start.elapsed().as_secs_f64();

    print_row("Analysis ID", &analysis_id.to_string());
    print_row("Files inserted", &FILES.to_string());
    print_row("Functions inserted", &TOTAL_FUNCTIONS.to_string());
    print_row("⏱  Elapsed", &format!("{seed_ms} ms"));
    print_row("   Insert throughput", &format!("{seed_rate:.0} rows/s"));
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // BENCHMARK 1 – OLAP Aggregation (mirrors stats_repo.rs)
    // ─────────────────────────────────────────────────────────────────────
    print_header("Benchmark 1 · OLAP Aggregation (stats_repo queries)");
    print_result_header();

    let olap_start = Instant::now();

    // ── KPI aggregate (single pass join) ─────────────────────────────────
    let kpi_t0 = Instant::now();
    let (_total_analyses, _total_files, _total_functions, _total_vuln, _total_safe): (
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = conn.query_row(
        "SELECT
            COUNT(DISTINCT a.id),
            COUNT(DISTINCT fi.id),
            COUNT(f.id),
            SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END),
            SUM(CASE WHEN f.verdict = 'safe'       THEN 1 ELSE 0 END)
         FROM analyses a
         LEFT JOIN files fi ON fi.analysis_id = a.id
         LEFT JOIN functions f ON f.file_id = fi.id",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    let kpi_ms = kpi_t0.elapsed().as_millis();

    // ── CWE group-by ─────────────────────────────────────────────────────
    let cwe_t0 = Instant::now();
    let mut stmt = conn.prepare(
        "SELECT cwe, cwe_name, severity, COUNT(*) AS count
         FROM functions
         WHERE verdict = 'vulnerable' AND cwe IS NOT NULL
         GROUP BY cwe, cwe_name, severity
         ORDER BY count DESC",
    )?;
    let cwe_rows: Vec<(String, String, String, i64)> = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .filter_map(|r| r.ok())
        .collect();
    let cwe_ms = cwe_t0.elapsed().as_millis();

    // ── Severity group-by ─────────────────────────────────────────────────
    let sev_t0 = Instant::now();
    let mut stmt = conn.prepare(
        "SELECT severity, COUNT(*) AS count
         FROM functions
         WHERE verdict = 'vulnerable' AND severity IS NOT NULL
         GROUP BY severity",
    )?;
    let _sev_rows: Vec<(String, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    let sev_ms = sev_t0.elapsed().as_millis();

    // ── Top-10 files by vuln count ────────────────────────────────────────
    let file_t0 = Instant::now();
    let mut stmt = conn.prepare(
        "SELECT
            fi.file_path,
            SUM(CASE WHEN f.verdict = 'safe'       THEN 1 ELSE 0 END) AS safe_count,
            SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) AS vuln_count
         FROM files fi
         JOIN functions f ON f.file_id = fi.id
         GROUP BY fi.id, fi.file_path
         ORDER BY vuln_count DESC LIMIT 10",
    )?;
    let _file_rows: Vec<(String, i64, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .filter_map(|r| r.ok())
        .collect();
    let file_ms = file_t0.elapsed().as_millis();

    // ── Recent analyses list ──────────────────────────────────────────────
    let recent_t0 = Instant::now();
    let mut stmt = conn.prepare(
        "SELECT
            a.id, a.project_name, a.project_path, CAST(a.timestamp AS VARCHAR),
            COUNT(f.id) AS total_functions,
            SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) AS vuln_count
         FROM analyses a
         LEFT JOIN files fi ON fi.analysis_id = a.id
         LEFT JOIN functions f ON f.file_id = fi.id
         GROUP BY a.id, a.project_name, a.project_path, a.timestamp
         ORDER BY a.timestamp DESC LIMIT 7",
    )?;
    let _recent: Vec<(i32, String, Option<String>, String, i64, i64)> = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();
    let recent_ms = recent_t0.elapsed().as_millis();

    // ── Trend query ───────────────────────────────────────────────────────
    let trend_t0 = Instant::now();
    let mut stmt = conn.prepare(
        "SELECT
            CAST(a.timestamp AS VARCHAR),
            SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) AS vuln_count
         FROM analyses a
         LEFT JOIN files fi ON fi.analysis_id = a.id
         LEFT JOIN functions f ON f.file_id = fi.id
         GROUP BY a.id, a.timestamp
         ORDER BY a.timestamp ASC",
    )?;
    let _trend: Vec<(String, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    let trend_ms = trend_t0.elapsed().as_millis();

    let olap_total_ms = olap_start.elapsed().as_millis();

    print_row("KPI aggregate join", &format!("{kpi_ms} ms"));
    print_row(
        "CWE group-by",
        &format!("{cwe_ms} ms  ({} CWEs)", cwe_rows.len()),
    );
    print_row("Severity group-by", &format!("{sev_ms} ms"));
    print_row("Top-10 file ratios", &format!("{file_ms} ms"));
    print_row("Recent analyses list", &format!("{recent_ms} ms"));
    print_row("Trend time-series", &format!("{trend_ms} ms"));
    print_separator();
    print_row("⏱  Total OLAP time", &format!("{olap_total_ms} ms"));
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // BENCHMARK 2 – Full table scan: SELECT * FROM functions
    // ─────────────────────────────────────────────────────────────────────
    print_header("Benchmark 2 · Full Table Scan (100 k rows → Vec<FunctionData>)");
    print_result_header();

    let fetch_start = Instant::now();

    let mut stmt = conn.prepare(
        "SELECT
            id, function_name, code, verdict,
            cwe, cwe_name, severity, confidence,
            start_line, end_line
         FROM functions",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(FunctionData {
            id: row.get(0)?,
            function_name: row.get(1)?,
            code: row.get(2)?,
            verdict: row.get(3)?,
            cwe: row.get(4)?,
            cwe_name: row.get(5)?,
            severity: row.get(6)?,
            confidence: row.get(7)?,
            start_line: row.get(8)?,
            end_line: row.get(9)?,
        })
    })?;

    let functions: Vec<FunctionData> = rows.filter_map(|r| r.ok()).collect();
    let fetch_ms = fetch_start.elapsed().as_millis();

    // Compute average code payload size for context.
    let avg_code_bytes: usize = if functions.is_empty() {
        0
    } else {
        functions.iter().map(|f| f.code.len()).sum::<usize>() / functions.len()
    };
    let total_heap_mb = functions
        .iter()
        .map(|f| f.code.len() + f.function_name.len())
        .sum::<usize>() as f64
        / 1_048_576.0;

    print_row("Rows fetched", &format!("{}", functions.len()));
    print_row("Avg code payload / row", &format!("{avg_code_bytes} bytes"));
    print_row("Estimated Vec heap", &format!("{total_heap_mb:.2} MB"));
    print_row("⏱  Elapsed", &format!("{fetch_ms} ms"));
    print_row(
        "   Throughput",
        &format!(
            "{:.0} rows/s",
            functions.len() as f64 / fetch_start.elapsed().as_secs_f64()
        ),
    );
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // BENCHMARK 3 – JSON serialisation (Tauri IPC simulation)
    // ─────────────────────────────────────────────────────────────────────
    print_header("Benchmark 3 · JSON Serialisation (serde_json simulation)");
    print_result_header();

    let ser_start = Instant::now();
    let json_str = serde_json::to_string(&functions)?;
    let ser_ms = ser_start.elapsed().as_millis();

    let json_mb = json_str.len() as f64 / 1_048_576.0;
    let json_kb_per_row = (json_str.len() as f64 / functions.len() as f64) / 1_024.0;

    print_row(
        "JSON payload size",
        &format!("{json_mb:.2} MB ({} bytes)", json_str.len()),
    );
    print_row("Avg size per row", &format!("{json_kb_per_row:.2} KB"));
    print_row("⏱  Elapsed", &format!("{ser_ms} ms"));
    print_row(
        "   Throughput",
        &format!(
            "{:.0} rows/s  ·  {:.1} MB/s",
            functions.len() as f64 / ser_start.elapsed().as_secs_f64(),
            json_mb / ser_start.elapsed().as_secs_f64(),
        ),
    );
    println!();

    // ─────────────────────────────────────────────────────────────────────
    // SUMMARY TABLE
    // ─────────────────────────────────────────────────────────────────────
    let total_pipeline_ms = fetch_ms + ser_ms;

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                     BENCHMARK SUMMARY                        ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Stage                               Time        Share       ║");
    println!("╠══════════════════════════════════════════════════════════════╣");

    let stages: &[(&str, u128)] = &[
        ("  Data seeding (Appender, 100 k rows)", seed_ms),
        ("  OLAP aggregation (6 queries)", olap_total_ms),
        ("  Full scan → Vec<FunctionData>", fetch_ms),
        ("  JSON serialisation (serde_json)", ser_ms),
    ];

    let grand_total: u128 = stages.iter().map(|(_, ms)| ms).sum();

    for (label, ms) in stages {
        let pct = if grand_total > 0 {
            (*ms as f64 / grand_total as f64) * 100.0
        } else {
            0.0
        };
        println!("║  {:<38}  {:>6} ms  {:>5.1}%  ║", label, ms, pct);
    }

    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║  {:<38}  {:>6} ms  100.0%  ║",
        "TOTAL (all stages)", grand_total
    );
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║  Fetch + Serialise (IPC suspect)     {:>6} ms              ║",
        total_pipeline_ms
    );
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║  JSON payload                        {:>8.2} MB           ║",
        json_mb
    );
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Interpretation guide:");
    println!("  ─────────────────────────────────────────────────────────────");
    println!("  • If 'OLAP aggregation' is fast  → dashboard stats are NOT the bottleneck.");
    println!("  • If 'Full scan' is slow         → DuckDB row deserialisation is the issue.");
    println!("  • If 'JSON serialisation' is slow → serde / IPC payload size is the issue.");
    println!("  • If all are fast here but the app is slow → Tauri IPC overhead is suspect.");
    println!("    Consider paginating the functions table or streaming via chunks.");
    println!();

    Ok(())
}
