#[link(name = "rstrtmgr")]
extern "C" {}

use duckdb::{params, Connection, Result};
use std::env;
use std::path::PathBuf;
use std::time::Instant;

const CWES: &[(&str, &str, &str)] = &[
    ("CWE-79", "Cross-site Scripting (XSS)", "High"),
    ("CWE-89", "SQL Injection", "Critical"),
    ("CWE-125", "Out-of-bounds Read", "High"),
    ("CWE-787", "Out-of-bounds Write", "Critical"),
    ("CWE-190", "Integer Overflow or Wraparound", "High"),
    ("CWE-369", "Divide By Zero", "Medium"),
    ("CWE-415", "Double Free", "High"),
    ("CWE-476", "NULL Pointer Dereference", "High"),
];

const VULN_TEMPLATES: &[(&str, &str)] = &[
    (
        "CWE-79",
        "void render_comment(const char* user_input) {\n    char html[256];\n    // UNSAFE: Directly concatenating user input into HTML without escaping\n    sprintf(html, \"<div class='comment'>%s</div>\", user_input);\n    printf(\"%s\", html);\n}"
    ),
    (
        "CWE-89",
        "void search_user(const char* username) {\n    char query[256];\n    // UNSAFE: String concatenation into SQL query\n    sprintf(query, \"SELECT * FROM users WHERE name = '%s'\", username);\n    // execute_query(query);\n}"
    ),
    (
        "CWE-787",
        "void copy_buffer(const char* src, size_t len) {\n    char dest[64];\n    // UNSAFE: No length check\n    strcpy(dest, src);\n}"
    ),
    (
        "CWE-125",
        "int read_from_index(const int* array, size_t size, int index) {\n    // UNSAFE: Array index not validated\n    return array[index];\n}"
    ),
    (
        "CWE-190",
        "void* allocate_buffer(int count) {\n    // UNSAFE: Integer multiplication overflow check missing\n    size_t total = count * sizeof(double);\n    return malloc(total);\n}"
    ),
    (
        "CWE-369",
        "double compute_average(double sum, int count) {\n    // UNSAFE: Count not checked for zero before division\n    return sum / count;\n}"
    ),
    (
        "CWE-415",
        "void free_resources(char* ptr) {\n    free(ptr);\n    // ... complex logic ...\n    // UNSAFE: Double free of the same pointer\n    free(ptr);\n}"
    ),
    (
        "CWE-476",
        "const char* get_username(struct User* user) {\n    // UNSAFE: NULL check missing on struct pointer\n    return user->username;\n}"
    ),
];

const SAFE_TEMPLATES: &[&str] = &[
    "int sum_array(const int* array, size_t size) {\n    int sum = 0;\n    for (size_t i = 0; i < size; ++i) {\n        sum += array[i];\n    }\n    return sum;\n}",
    "void print_status(int status_code) {\n    switch (status_code) {\n        case 200: printf(\"OK\\n\"); break;\n        case 404: printf(\"Not Found\\n\"); break;\n        default: printf(\"Unknown Code: %d\\n\", status_code); break;\n    }\n}",
    "bool is_valid_age(int age) {\n    return age >= 0 && age <= 150;\n}",
    "std::string make_greeting(const std::string& name) {\n    if (name.empty()) {\n        return \"Hello, Guest!\";\n    }\n    return \"Hello, \" + name + \"!\";\n}",
    "void cleanup_safe(char** ptr) {\n    if (ptr && *ptr) {\n        free(*ptr);\n        *ptr = nullptr;\n    }\n}",
    "int safe_divide(int dividend, int divisor) {\n    if (divisor == 0) {\n        return 0; // Prevent divide-by-zero\n    }\n    return dividend / divisor;\n}",
    "void render_comment_safe(const char* user_input) {\n    // SAFE: HTML-escape user input before output\n    printf(\"<div class='comment'>\");\n    for (const char* p = user_input; *p; ++p) {\n        switch (*p) {\n            case '<': printf(\"&lt;\"); break;\n            case '>': printf(\"&gt;\"); break;\n            case '&': printf(\"&amp;\"); break;\n            case '\\\"': printf(\"&quot;\"); break;\n            default: putchar(*p); break;\n        }\n    }\n    printf(\"</div>\");\n}",
    "void search_user_safe(const char* username) {\n    // SAFE: Use parameterized query (prepared statement)\n    // sqlite3_stmt* stmt;\n    // sqlite3_prepare_v2(db, \"SELECT * FROM users WHERE name = ?\", -1, &stmt, NULL);\n    // sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);\n    // sqlite3_step(stmt);\n}",
];

const FILE_PROFILES: &[(usize, usize, usize, usize)] = &[
    (40, 60, 3, 8),   // Large files, moderate vulns
    (10, 20, 1, 4),   // Small files, few vulns
    (5, 15, 5, 10),   // Small files, high vuln density
    (80, 120, 2, 5),  // Very large files, sparse vulns
    (20, 40, 8, 15),  // Medium files, high vuln count
    (30, 50, 0, 2),   // Medium-large files, mostly safe
    (2, 8, 0, 1),     // Tiny files
];

fn print_help() {
    println!(
        "CCure DuckDB Database Seeding Utility\n\n\
        Usage: cargo run --bin generate_gigantic_report [OPTIONS]\n\n\
        Options:\n  \
          --db <PATH>                  Path to the DuckDB database file\n  \
          --files <COUNT>              Number of files to generate (default: 1000)\n  \
          --project-name <NAME>        Name of the project (default: GIGANTIC_TEST_PROJECT)\n  \
          --seed <NUMBER>              Random seed for reproducibility (default: 42)\n  \
          --help, -h                   Show this help message\n\n\
        File profiles are now built-in. Each file gets a random profile from:\n  \
          - Large files (40-60 safe, 3-8 vuln)\n  \
          - Small files (10-20 safe, 1-4 vuln)\n  \
          - High-density small files (5-15 safe, 5-10 vuln)\n  \
          - Very large sparse files (80-120 safe, 2-5 vuln)\n  \
          - Medium high-vuln files (20-40 safe, 8-15 vuln)\n  \
          - Mostly-safe files (30-50 safe, 0-2 vuln)\n  \
          - Tiny files (2-8 safe, 0-1 vuln)\n"
    );
}

fn get_default_db_path() -> PathBuf {
    if let Some(local_dir) = dirs::data_local_dir() {
        let p = local_dir.join("fcis").join("ccure.db");
        if p.exists() {
            return p;
        }
    }
    if let Some(roaming_dir) = dirs::data_dir() {
        let p = roaming_dir.join("fcis").join("ccure.db");
        if p.exists() {
            return p;
        }
    }
    let p = PathBuf::from("ccure.db");
    if p.exists() {
        return p;
    }
    if let Some(local_dir) = dirs::data_local_dir() {
        local_dir.join("fcis").join("ccure.db")
    } else {
        PathBuf::from("ccure.db")
    }
}

fn init_db_on_conn(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE SEQUENCE IF NOT EXISTS seq_analyses START 1;
        CREATE SEQUENCE IF NOT EXISTS seq_files START 1;
        CREATE SEQUENCE IF NOT EXISTS seq_functions START 1;
        CREATE SEQUENCE IF NOT EXISTS seq_watched_projects START 1;
        CREATE SEQUENCE IF NOT EXISTS seq_file_hashes START 1;

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
        CREATE TABLE IF NOT EXISTS watched_projects (
            id            INTEGER PRIMARY KEY DEFAULT nextval('seq_watched_projects'),
            name          VARCHAR NOT NULL,
            folder_path   VARCHAR NOT NULL UNIQUE,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS file_hashes (
            id         INTEGER PRIMARY KEY DEFAULT nextval('seq_file_hashes'),
            project_id INTEGER NOT NULL,
            file_path  VARCHAR NOT NULL,
            file_hash  VARCHAR NOT NULL,
            hashed_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(project_id, file_path),
            FOREIGN KEY(project_id) REFERENCES watched_projects(id)
        );

        CREATE INDEX IF NOT EXISTS idx_files_analysis_id ON files(analysis_id);
        CREATE INDEX IF NOT EXISTS idx_functions_file_id ON functions(file_id);
        CREATE INDEX IF NOT EXISTS idx_functions_verdict ON functions(verdict);
        CREATE INDEX IF NOT EXISTS idx_functions_file_verdict ON functions(file_id, verdict);
        CREATE INDEX IF NOT EXISTS idx_file_hashes_project ON file_hashes(project_id);
        ",
    )?;
    Ok(())
}

struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }

    fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        (self.next() as usize) % max
    }

    fn range_usize(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        min + self.next_usize(max - min + 1)
    }

    fn next_f64(&mut self) -> f64 {
        (self.next() as f64) / (u64::MAX as f64 + 1.0)
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let mut db_path: Option<PathBuf> = None;
    let mut files_count = 1000;
    let mut project_name = "GIGANTIC_TEST_PROJECT".to_string();
    let mut seed: u64 = 42;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                if i + 1 < args.len() {
                    db_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    return Err("Missing value for --db".into());
                }
            }
            "--files" => {
                if i + 1 < args.len() {
                    files_count = args[i + 1].parse()?;
                    i += 2;
                } else {
                    return Err("Missing value for --files".into());
                }
            }
            "--project-name" => {
                if i + 1 < args.len() {
                    project_name = args[i + 1].clone();
                    i += 2;
                } else {
                    return Err("Missing value for --project-name".into());
                }
            }
            "--seed" => {
                if i + 1 < args.len() {
                    seed = args[i + 1].parse()?;
                    i += 2;
                } else {
                    return Err("Missing value for --seed".into());
                }
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            _ => {
                println!("Unknown argument: {}", args[i]);
                print_help();
                return Err("Invalid arguments".into());
            }
        }
    }

    let resolved_db_path = db_path.unwrap_or_else(get_default_db_path);
    println!("Target Database Path: {:?}", resolved_db_path);
    println!("Random Seed: {}", seed);

    if let Some(parent) = resolved_db_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let start_time = Instant::now();
    println!("Connecting to DuckDB...");
    let mut conn = Connection::open(&resolved_db_path)?;

    println!("Initializing tables...");
    init_db_on_conn(&conn)?;

    println!("Starting database transaction...");
    let tx = conn.transaction()?;

    println!("Seeding analysis meta info...");
    let project_path = format!("/mock/projects/{}", project_name);
    let mut stmt = tx.prepare(
        "INSERT INTO analyses (project_name, project_path, timestamp) VALUES (?, ?, CURRENT_TIMESTAMP) RETURNING id"
    )?;
    let analysis_id: i64 = stmt.query_row(params![project_name, project_path], |row| row.get(0))?;
    drop(stmt);
    println!("Generated Analysis ID: {}", analysis_id);

    let mut rng = SimpleRng::new(seed);

    let mut file_configs: Vec<(usize, usize)> = Vec::with_capacity(files_count);
    let mut total_safe_planned = 0usize;
    let mut total_vuln_planned = 0usize;

    for _ in 0..files_count {
        let profile_idx = rng.next_usize(FILE_PROFILES.len());
        let (min_safe, max_safe, min_vuln, max_vuln) = FILE_PROFILES[profile_idx];
        let safe_count = rng.range_usize(min_safe, max_safe);
        let vuln_count = rng.range_usize(min_vuln, max_vuln);
        file_configs.push((safe_count, vuln_count));
        total_safe_planned += safe_count;
        total_vuln_planned += vuln_count;
    }

    let total_functions = total_safe_planned + total_vuln_planned;
    println!(
        "Plan: Generate {} files with varied sizes (Total: {} functions, ~{} safe, ~{} vulnerable)",
        files_count,
        total_functions,
        total_safe_planned,
        total_vuln_planned
    );

    let mut file_stmt =
        tx.prepare("INSERT INTO files (analysis_id, file_path) VALUES (?, ?) RETURNING id")?;

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

    let mut seeded_vulnerable = 0usize;
    let mut seeded_safe = 0usize;
    let mut global_func_index = 0usize;

    let vuln_templates_count = VULN_TEMPLATES.len();
    let safe_templates_count = SAFE_TEMPLATES.len();

    let mut report_interval = files_count / 10;
    if report_interval == 0 {
        report_interval = 1;
    }

    for f_idx in 1..=files_count {
        let file_path = format!(
            "src/components/module_{:04}/component_{:04}.cpp",
            f_idx / 10,
            f_idx
        );

        let file_id: i64 =
            file_stmt.query_row(params![analysis_id, file_path], |row| row.get(0))?;

        let (safe_count, vuln_count) = file_configs[f_idx - 1];
        let total_file_funcs = safe_count + vuln_count;

        let mut verdicts: Vec<bool> = Vec::with_capacity(total_file_funcs);
        for _ in 0..vuln_count {
            verdicts.push(true);
        }
        for _ in 0..safe_count {
            verdicts.push(false);
        }

        for i in (1..verdicts.len()).rev() {
            let j = rng.next_usize(i + 1);
            verdicts.swap(i, j);
        }

        let mut current_line = 1i32;

        for is_vulnerable in verdicts {
            global_func_index += 1;

            let function_name = if is_vulnerable {
                format!("process_input_vulnerable_{}", global_func_index)
            } else {
                format!("calculate_metrics_safe_{}", global_func_index)
            };

            let start_line = current_line;
            let end_line = start_line + 10 + (rng.next_usize(5) as i32);
            current_line = end_line + 2;

            let confidence = if is_vulnerable {
                0.70 + (rng.next_f64() * 0.25)
            } else {
                0.85 + (rng.next_f64() * 0.14)
            };

            if is_vulnerable {
                let t_idx = rng.next_usize(vuln_templates_count);
                let (cwe, code) = VULN_TEMPLATES[t_idx];

                let mut cwe_name = "Unknown Weakness";
                let mut severity = "Medium";
                for &(c, cn, sev) in CWES {
                    if c == cwe {
                        cwe_name = cn;
                        severity = sev;
                        break;
                    }
                }

                appender.append_row(params![
                    file_id,
                    function_name,
                    code,
                    "vulnerable",
                    Some(cwe.to_string()),
                    Some(cwe_name.to_string()),
                    Some(severity.to_string()),
                    Some(confidence),
                    Some(start_line),
                    Some(end_line),
                ])?;
                seeded_vulnerable += 1;
            } else {
                let t_idx = rng.next_usize(safe_templates_count);
                let code = SAFE_TEMPLATES[t_idx];

                appender.append_row(params![
                    file_id,
                    function_name,
                    code,
                    "safe",
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    Some(confidence),
                    Some(start_line),
                    Some(end_line),
                ])?;
                seeded_safe += 1;
            }
        }

        if f_idx % report_interval == 0 || f_idx == files_count {
            let elapsed = start_time.elapsed();
            println!(
                "Progress: {}/{} files generated ({:.1}%). Elapsed time: {:.2?} | Functions so far: {} safe, {} vuln",
                f_idx,
                files_count,
                (f_idx as f64 / files_count as f64) * 100.0,
                elapsed,
                seeded_safe,
                seeded_vulnerable
            );
        }
    }

    println!("Flushing Appender...");
    appender.flush()?;
    drop(appender);
    drop(file_stmt);

    println!("Committing transaction to database...");
    tx.commit()?;

    let total_elapsed = start_time.elapsed();
    println!("\nSeeding Completed Successfully!");
    println!("--------------------------------");
    println!("Database Path:       {:?}", resolved_db_path);
    println!("Analysis ID:         {}", analysis_id);
    println!("Files Generated:     {}", files_count);
    println!("Safe Functions:      {}", seeded_safe);
    println!("Vulnerable Functions: {}", seeded_vulnerable);
    println!("Total Functions:     {}", seeded_safe + seeded_vulnerable);
    println!("Execution Time:      {:.2?}", total_elapsed);
    println!(
        "Avg Insert Rate:     {:.0} functions/sec",
        (total_functions as f64) / total_elapsed.as_secs_f64()
    );

    println!("\n--- File Size Distribution ---");
    let mut size_buckets: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (safe, vuln) in &file_configs {
        let total = safe + vuln;
        let bucket = if total < 10 {
            "tiny (<10)".to_string()
        } else if total < 30 {
            "small (10-29)".to_string()
        } else if total < 60 {
            "medium (30-59)".to_string()
        } else if total < 100 {
            "large (60-99)".to_string()
        } else {
            "huge (100+)".to_string()
        };
        *size_buckets.entry(bucket).or_insert(0) += 1;
    }
    let mut buckets: Vec<_> = size_buckets.into_iter().collect();
    buckets.sort_by(|a, b| a.0.cmp(&b.0));
    for (bucket, count) in buckets {
        println!("  {:20}: {:4} files", bucket, count);
    }

    Ok(())
}