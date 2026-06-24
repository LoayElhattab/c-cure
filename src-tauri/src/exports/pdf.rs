use serde::Deserialize;
use std::path::Path;
use typst_as_lib::TypstEngine;
use typst_pdf::PdfOptions;

use crate::db::{FunctionData, VulnerabilityReport};
use crate::error::AppError;

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ExportSettings {
    pub executive_summary_only: bool,
    pub max_findings: Option<usize>,
    pub include_source_code: Option<bool>,
}

struct RankedFinding<'a> {
    file_path: &'a str,
    func: &'a FunctionData,
}

const TYPST_THEME: &str = r##"#set page(
  paper: "a4",
  margin: (x: 2cm, y: 2.5cm),
  header: [],
  footer: context align(center)[#counter(page).display("1")],
)
#set text(font: ("Arial", "Helvetica", "DejaVu Sans"), size: 10pt, fill: rgb("#111827"))
#set par(justify: false, leading: 0.62em)
#show heading: it => block(above: 18pt, below: 10pt)[
  #text(weight: "bold", fill: rgb("#111827"))[#it.body]
]
#show table.cell: set text(size: 9pt)

#let severity-box(sev) = {
  let palette = (
    "Critical": (fill: rgb("#dc2626"), text: white),
    "High": (fill: rgb("#ea580c"), text: white),
    "Medium": (fill: rgb("#ca8a04"), text: white),
    "Low": (fill: rgb("#2563eb"), text: white),
  )
  let style = palette.at(sev, default: (fill: rgb("#6b7280"), text: white))
  box(fill: style.fill, inset: (x: 6pt, y: 2pt), radius: 2pt)[
    #text(fill: style.text, weight: "bold", size: 8pt)[#sev]
  ]
}

#let stat-card(label, value) = {
  block(
    fill: luma(245),
    inset: 10pt,
    radius: 4pt,
    width: 45%,
  )[
    #text(size: 8pt, fill: gray)[#label] \
    #text(size: 14pt, weight: "bold")[#value]
  ]
}

#let code-snippet(body) = block(
  fill: rgb("#f6f7f9"),
  inset: 9pt,
  radius: 3pt,
  breakable: true,
)[#body]

"##;

pub fn generate_pdf<F>(
    report: &VulnerabilityReport,
    settings: ExportSettings,
    output_path: &Path,
    mut on_progress: Option<F>,
) -> Result<String, AppError>
where
    F: FnMut(&str),
{
    if let Some(progress) = on_progress.as_mut() {
        progress("Building Typst Template...");
    }
    let source = build_typst_source(report, &settings);
    if let Some(progress) = on_progress.as_mut() {
        progress("Compiling PDF (this may take a few seconds)...");
    }
    let bytes = compile_typst(source)?;
    if let Some(progress) = on_progress.as_mut() {
        progress("Finalizing File...");
    }
    std::fs::write(output_path, bytes)
        .map_err(|e| AppError::Custom(format!("Failed to save PDF: {e}")))?;
    Ok(output_path.to_string_lossy().to_string())
}

fn compile_typst(source: String) -> Result<Vec<u8>, AppError> {
    let engine = TypstEngine::builder()
        .fonts(typst_assets::fonts())
        .with_static_source_file_resolver([("report.typ", source)])
        .build();

    let doc = engine
        .compile("report.typ")
        .output
        .map_err(|e| AppError::Custom(format!("Typst compilation failed: {e}")))?;

    typst_pdf::pdf(&doc, &PdfOptions::default())
        .map_err(|e| AppError::Custom(format!("PDF export failed: {e:?}")))
}

fn build_typst_source(report: &VulnerabilityReport, settings: &ExportSettings) -> String {
    let mut out = String::with_capacity(16_384);
    out.push_str(TYPST_THEME);

    if settings.executive_summary_only {
        append_executive_report(&mut out, report);
    } else {
        append_technical_report(&mut out, report, settings);
    }

    out
}

fn append_technical_report(
    out: &mut String,
    report: &VulnerabilityReport,
    settings: &ExportSettings,
) {
    out.push_str(&format!(
        "= #raw(\"{}\")\n\n",
        typst_escape(&report.project_name)
    ));
    out.push_str(&format!(
        "#text(size: 9pt, fill: rgb(\"#6b7280\"))[Date: #raw(\"{}\") \\ Total Functions Scanned: {} \\ Total Vulnerabilities Found: {}]\n\n",
        typst_escape(&report.timestamp),
        report.total_functions,
        report.vulnerable_functions,
    ));

    out.push_str("== Detailed Findings\n\n");
    append_detailed_findings(out, report, settings);
}

fn append_executive_report(out: &mut String, report: &VulnerabilityReport) {
    out.push_str(&format!(
        "= #raw(\"{}\") - Executive Summary\n\n",
        typst_escape(&report.project_name)
    ));
    out.push_str(&format!(
        "#text(size: 9pt, fill: rgb(\"#6b7280\"))[Date: #raw(\"{}\")]\n\n",
        typst_escape(&report.timestamp),
    ));

    out.push_str("== Summary\n\n");
    out.push_str("#grid(columns: 2, gutter: 8pt,\n");
    out.push_str(&format!(
        "  stat-card(\"Total Functions Scanned\", {}),\n",
        report.total_functions
    ));
    out.push_str(&format!(
        "  stat-card(\"Vulnerable Functions\", {}),\n",
        report.vulnerable_functions
    ));
    out.push_str(&format!(
        "  stat-card(\"Clean Functions\", {}),\n",
        report.clean_functions
    ));
    out.push_str(&format!(
        "  stat-card(\"Files Scanned\", {}),\n",
        report.total_files
    ));
    out.push_str(")\n\n");

    if !report.severity_breakdown.is_empty() {
        out.push_str("== Severity Breakdown\n\n");
        out.push_str("#table(\n");
        out.push_str("  columns: (1fr, auto),\n");
        out.push_str("  inset: 8pt,\n");
        out.push_str("  align: (left, center),\n");
        out.push_str("  table.header[*Severity*][*Count*],\n");
        for severity in ["Critical", "High", "Medium", "Low"] {
            let count = report
                .severity_breakdown
                .get(severity)
                .copied()
                .unwrap_or(0);
            out.push_str(&format!("  [#severity-box(\"{severity}\")], [{count}],\n"));
        }
        out.push_str(")\n\n");
    }

    if !report.top_vulnerabilities.is_empty() {
        out.push_str("== Top Vulnerability Types\n\n");
        out.push_str("#table(\n");
        out.push_str("  columns: (auto, 1fr, auto, auto),\n");
        out.push_str("  inset: 8pt,\n");
        out.push_str("  table.header[*CWE*][*Name*][*Severity*][*Hits*],\n");
        for hit in &report.top_vulnerabilities {
            let name = hit.cwe_name.as_deref().unwrap_or("Unknown");
            let severity = hit.severity.as_deref().unwrap_or("Unknown");
            out.push_str(&format!(
                "  [#raw(\"{}\")], [#raw(\"{}\")], [#severity-box(\"{}\")], [{}],\n",
                typst_escape(&hit.cwe),
                typst_escape(name),
                typst_escape(severity),
                hit.count,
            ));
        }
        out.push_str(")\n\n");
    }

    if report.vulnerable_functions > 0 {
        out.push_str("== Top 10 Most Affected Files\n\n");
        out.push_str(&format!(
            "Files with vulnerable findings: *{}*\n\n",
            report.files.len()
        ));
        out.push_str("#table(\n");
        out.push_str("  columns: (1fr, auto),\n");
        out.push_str("  inset: 8pt,\n");
        out.push_str("  table.header[*File*][*Findings*],\n");
        let mut files: Vec<_> = report.files.iter().collect();
        files.sort_by(|left, right| {
            right
                .functions
                .len()
                .cmp(&left.functions.len())
                .then_with(|| left.file_path.cmp(&right.file_path))
        });
        for file_data in files.into_iter().take(10) {
            out.push_str(&format!(
                "  [#raw(\"{}\")], [{}],\n",
                typst_escape(&file_data.file_path),
                file_data.functions.len(),
            ));
        }
        out.push_str(")\n\n");
    }
}

fn append_detailed_findings(
    out: &mut String,
    report: &VulnerabilityReport,
    settings: &ExportSettings,
) {
    let mut findings = collect_ranked_findings(report);
    let total_findings = findings.len();

    if let Some(max) = settings.max_findings {
        findings.truncate(max);
    }

    let include_code = settings.include_source_code.unwrap_or(true);

    if findings.len() < total_findings {
        out.push_str(&format!(
            "_Showing top {} of {} vulnerable findings (sorted by severity). Safe functions omitted._\n\n",
            findings.len(),
            total_findings
        ));
    } else {
        out.push_str("_Safe functions omitted._\n\n");
    }

    for finding in &findings {
        append_function_finding(out, finding.file_path, finding.func, include_code);
    }
}

fn collect_ranked_findings(report: &VulnerabilityReport) -> Vec<RankedFinding<'_>> {
    let mut findings: Vec<RankedFinding<'_>> = report
        .files
        .iter()
        .flat_map(|file| {
            file.functions.iter().map(|func| RankedFinding {
                file_path: &file.file_path,
                func,
            })
        })
        .collect();

    findings.sort_by(|left, right| {
        severity_rank(right.func.severity.as_deref())
            .cmp(&severity_rank(left.func.severity.as_deref()))
            .then_with(|| left.file_path.cmp(right.file_path))
            .then_with(|| left.func.function_name.cmp(&right.func.function_name))
    });

    findings
}

fn severity_rank(severity: Option<&str>) -> u8 {
    match severity {
        Some("Critical") => 4,
        Some("High") => 3,
        Some("Medium") => 2,
        Some("Low") => 1,
        _ => 0,
    }
}

fn append_function_finding(
    out: &mut String,
    file_path: &str,
    func: &FunctionData,
    include_code: bool,
) {
    let start = func.start_line.unwrap_or(0);
    let end = func.end_line.unwrap_or(0);
    let sev = func.severity.as_deref().unwrap_or("Unknown");
    let cwe = func.cwe.as_deref().unwrap_or("Unknown");
    let cwe_name = func.cwe_name.as_deref().unwrap_or("Unknown");

    out.push_str("#block(below: 14pt, breakable: true)[\n");
    out.push_str(&format!(
        "#text(weight: \"bold\", size: 11pt)[#raw(\"{}\")] #severity-box(\"{}\")\n\n",
        typst_escape(&func.function_name),
        typst_escape(sev),
    ));
    out.push_str(&format!(
        "#text(size: 8.5pt, fill: rgb(\"#6b7280\"))[#raw(\"{}\") \\ Lines {start}-{end}]\n\n",
        typst_escape(file_path),
    ));
    out.push_str(&format!(
        "#text(size: 9.5pt)[*CWE:* #raw(\"{}\") - #raw(\"{}\")]\n\n",
        typst_escape(cwe),
        typst_escape(cwe_name),
    ));
    if include_code {
        out.push_str("#code-snippet[\n");
        out.push_str(&typst_code_block("cpp", &func.code));
        out.push_str("]\n\n");
    }
    out.push_str("#line(length: 100%, stroke: rgb(\"#e5e7eb\"))\n");
    out.push_str("]\n\n");
}

/// Escape text embedded inside Typst `#raw("...")` string literals.
fn typst_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Emit a Typst fenced raw code block with a fence long enough to avoid collisions.
fn typst_code_block(lang: &str, code: &str) -> String {
    let mut fence_len = 3;
    let backtick = '`';
    while code.contains(&backtick.to_string().repeat(fence_len)) {
        fence_len += 1;
    }
    let fence = backtick.to_string().repeat(fence_len);
    format!("{fence}{lang}\n{code}\n{fence}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::FileData;
    use std::collections::HashMap;

    #[test]
    fn test_generate_pdf_file_creation() {
        let report = VulnerabilityReport {
            id: 99,
            project_name: "TestPDF".into(),
            project_path: None,
            timestamp: "2024-01-01 10:00:00".into(),
            total_files: 1,
            total_functions: 10,
            vulnerable_functions: 1,
            clean_functions: 9,
            severity_breakdown: HashMap::from([("High".to_string(), 1)]),
            top_vulnerabilities: vec![],
            files: vec![FileData {
                file_path: "src/main.cpp".into(),
                functions: vec![FunctionData {
                    id: Some(1),
                    function_name: "vuln_func".into(),
                    code: "void vuln_func() { char buf[8]; gets(buf); }".into(),
                    verdict: "vulnerable".into(),
                    cwe: Some("CWE-676".into()),
                    cwe_name: Some("Use of Dangerous Function".into()),
                    asvs_id: None,
                    severity: Some("High".into()),
                    confidence: Some(0.9),
                    start_line: Some(10),
                    end_line: Some(12),
                }],
            }],
        };

        let file = tempfile::NamedTempFile::new().expect("temp file");
        let path = file.path();

        let res = generate_pdf(&report, ExportSettings::default(), path, None::<fn(&str)>);
        assert!(res.is_ok(), "PDF generation failed: {:?}", res.err());

        let bytes = std::fs::read(path).expect("read pdf");
        assert!(bytes.starts_with(b"%PDF-"), "output is not a valid PDF");
    }

    #[test]
    fn typst_code_block_handles_embedded_backticks() {
        let block = typst_code_block("cpp", "code with ``` inside");
        assert!(block.starts_with("````cpp\n"));
        assert!(block.ends_with("````\n"));
    }

    #[test]
    fn max_findings_caps_detailed_section() {
        let report = sample_report_with_severities();
        let source = build_typst_source(
            &report,
            &ExportSettings {
                executive_summary_only: false,
                max_findings: Some(1),
                include_source_code: Some(false),
            },
        );

        assert!(source.contains("Showing top 1 of 2"));
        assert!(!source.contains("```cpp"));
        assert!(source.contains("critical_fn"));
        assert!(!source.contains("low_fn"));
    }

    fn sample_report_with_severities() -> VulnerabilityReport {
        VulnerabilityReport {
            id: 1,
            project_name: "CapTest".into(),
            project_path: None,
            timestamp: "2024-01-01".into(),
            total_files: 1,
            total_functions: 2,
            vulnerable_functions: 2,
            clean_functions: 0,
            severity_breakdown: HashMap::new(),
            top_vulnerabilities: vec![],
            files: vec![FileData {
                file_path: "main.cpp".into(),
                functions: vec![
                    FunctionData {
                        id: Some(1),
                        function_name: "low_fn".into(),
                        code: "void low_fn() {}".into(),
                        verdict: "vulnerable".into(),
                        cwe: Some("CWE-1".into()),
                        cwe_name: None,
                        asvs_id: None,
                        severity: Some("Low".into()),
                        confidence: None,
                        start_line: Some(1),
                        end_line: Some(2),
                    },
                    FunctionData {
                        id: Some(2),
                        function_name: "critical_fn".into(),
                        code: "void critical_fn() {}".into(),
                        verdict: "vulnerable".into(),
                        cwe: Some("CWE-2".into()),
                        cwe_name: None,
                        asvs_id: None,
                        severity: Some("Critical".into()),
                        confidence: None,
                        start_line: Some(10),
                        end_line: Some(12),
                    },
                ],
            }],
        }
    }
}
