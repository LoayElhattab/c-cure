use crate::db::{
    AnalysisFileRatios, AnalysisListItem, CweCount, DashboardStats, DbPool, FileRatio, Kpis,
    SeverityCount, StatisticsData, TrendData,
};
use crate::error::AppError;

pub async fn get_vuln_count(pool: &DbPool) -> Result<i64, AppError> {
    pool.with_conn(|conn| {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM functions WHERE verdict = 'vulnerable'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        Ok(count)
    })
    .await
}

pub async fn get_statistics(pool: &DbPool) -> Result<StatisticsData, AppError> {
    pool.with_conn(|conn| {
        let kpis: Kpis = conn
            .query_row(
                "SELECT
                COUNT(DISTINCT a.id),
                COUNT(DISTINCT fi.id),
                COUNT(f.id),
                SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END),
                SUM(CASE WHEN f.verdict = 'safe' THEN 1 ELSE 0 END)
            FROM analyses a
            LEFT JOIN files fi ON fi.analysis_id = a.id
            LEFT JOIN functions f ON f.file_id = fi.id",
                [],
                |row| {
                    Ok(Kpis {
                        total_analyses: row.get::<_, Option<i32>>(0)?.unwrap_or(0),
                        total_files: row.get::<_, Option<i32>>(1)?.unwrap_or(0),
                        total_functions: row.get::<_, Option<i32>>(2)?.unwrap_or(0),
                        total_vulnerable: row.get::<_, Option<i32>>(3)?.unwrap_or(0),
                        total_safe: row.get::<_, Option<i32>>(4)?.unwrap_or(0),
                    })
                },
            )
            .unwrap_or(Kpis {
                total_analyses: 0,
                total_files: 0,
                total_functions: 0,
                total_vulnerable: 0,
                total_safe: 0,
            });

        let mut stmt = conn.prepare(
            "SELECT cwe, cwe_name, severity, COUNT(*) as count
             FROM functions
             WHERE verdict = 'vulnerable' AND cwe IS NOT NULL
             GROUP BY cwe, cwe_name, severity
             ORDER BY count DESC",
        )?;
        let iter = stmt.query_map([], |row| {
            Ok(CweCount {
                cwe: row.get(0)?,
                cwe_name: row.get(1)?,
                severity: row.get(2)?,
                count: row.get(3)?,
            })
        })?;
        let mut cwe_counts = Vec::new();
        for r in iter {
            cwe_counts.push(r?);
        }

        let mut stmt = conn.prepare(
            "SELECT severity, COUNT(*) as count
             FROM functions
             WHERE verdict = 'vulnerable' AND severity IS NOT NULL
             GROUP BY severity",
        )?;
        let iter = stmt.query_map([], |row| {
            Ok(SeverityCount {
                severity: row.get(0)?,
                count: row.get(1)?,
            })
        })?;
        let mut severity_counts = Vec::new();
        for r in iter {
            severity_counts.push(r?);
        }

        let mut stmt = conn.prepare(
            "SELECT
                fi.file_path,
                SUM(CASE WHEN f.verdict = 'safe' THEN 1 ELSE 0 END) as safe_count,
                SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) as vuln_count
             FROM files fi
             JOIN functions f ON f.file_id = fi.id
             GROUP BY fi.id, fi.file_path
             ORDER BY vuln_count DESC LIMIT 10",
        )?;
        let iter = stmt.query_map([], |row| {
            let path: String = row.get(0)?;
            let label = path
                .replace('\\', "/")
                .split('/')
                .next_back()
                .unwrap_or("")
                .to_string();
            Ok(FileRatio {
                label,
                safe: row.get::<_, Option<i32>>(1)?.unwrap_or(0),
                vuln: row.get::<_, Option<i32>>(2)?.unwrap_or(0),
            })
        })?;
        let mut file_ratios = Vec::new();
        for r in iter {
            file_ratios.push(r?);
        }

        let mut stmt = conn.prepare(
            "SELECT analysis_id, file_path, safe_count, vuln_count
             FROM (
                SELECT
                    fi.analysis_id,
                    fi.file_path,
                    SUM(CASE WHEN f.verdict = 'safe' THEN 1 ELSE 0 END) as safe_count,
                    SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) as vuln_count,
                    ROW_NUMBER() OVER (
                        PARTITION BY fi.analysis_id
                        ORDER BY SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) DESC
                    ) as rank
                FROM files fi
                JOIN functions f ON f.file_id = fi.id
                GROUP BY fi.analysis_id, fi.id, fi.file_path
             )
             WHERE rank <= 10
             ORDER BY analysis_id, vuln_count DESC",
        )?;
        let iter = stmt.query_map([], |row| {
            let path: String = row.get(1)?;
            let label = path
                .replace('\\', "/")
                .split('/')
                .next_back()
                .unwrap_or("")
                .to_string();

            Ok((
                row.get::<_, i32>(0)?,
                FileRatio {
                    label,
                    safe: row.get::<_, Option<i32>>(2)?.unwrap_or(0),
                    vuln: row.get::<_, Option<i32>>(3)?.unwrap_or(0),
                },
            ))
        })?;

        let mut analysis_file_ratios = Vec::new();
        let mut active_analysis_id: Option<i32> = None;
        let mut active_file_ratios = Vec::new();

        for r in iter {
            let (analysis_id, file_ratio) = r?;

            if active_analysis_id != Some(analysis_id) {
                if let Some(previous_analysis_id) = active_analysis_id {
                    analysis_file_ratios.push(AnalysisFileRatios {
                        analysis_id: previous_analysis_id,
                        file_ratios: active_file_ratios,
                    });
                    active_file_ratios = Vec::new();
                }

                active_analysis_id = Some(analysis_id);
            }

            active_file_ratios.push(file_ratio);
        }

        if let Some(analysis_id) = active_analysis_id {
            analysis_file_ratios.push(AnalysisFileRatios {
                analysis_id,
                file_ratios: active_file_ratios,
            });
        }

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
        let iter = stmt.query_map([], |row| {
            Ok(AnalysisListItem {
                id: row.get(0)?,
                project_name: row.get(1)?,
                project_path: row.get(2)?,
                timestamp: row.get(3)?,
                total_functions: row.get::<_, Option<i32>>(4)?.unwrap_or(0),
                vuln_count: row.get::<_, Option<i32>>(5)?.unwrap_or(0),
            })
        })?;
        let mut recent_analyses = Vec::new();
        for r in iter {
            recent_analyses.push(r?);
        }

        let mut stmt = conn.prepare(
            "SELECT
                CAST(a.timestamp AS VARCHAR),
                SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) as vuln_count,
                COUNT(f.id) as total_functions
            FROM analyses a
            LEFT JOIN files fi ON fi.analysis_id = a.id
            LEFT JOIN functions f ON f.file_id = fi.id
            GROUP BY a.id, a.timestamp
            ORDER BY a.timestamp ASC",
        )?;
        let iter = stmt.query_map([], |row| {
            Ok(TrendData {
                timestamp: row.get(0)?,
                vuln_count: row.get::<_, Option<i32>>(1)?.unwrap_or(0),
                total_functions: row.get::<_, Option<i32>>(2)?.unwrap_or(0),
            })
        })?;
        let mut trend = Vec::new();
        for r in iter {
            trend.push(r?);
        }

        Ok(StatisticsData {
            dashboard: DashboardStats {
                kpis,
                cwe_counts,
                severity_counts,
                file_ratios,
                analysis_file_ratios,
                recent_analyses,
            },
            trend,
        })
    })
    .await
}

pub async fn get_file_ratios_for_analysis(
    pool: &DbPool,
    analysis_id: i32,
) -> Result<Vec<FileRatio>, AppError> {
    pool.with_conn(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT
                fi.file_path,
                SUM(CASE WHEN f.verdict = 'safe' THEN 1 ELSE 0 END) as safe_count,
                SUM(CASE WHEN f.verdict = 'vulnerable' THEN 1 ELSE 0 END) as vuln_count
             FROM files fi
             JOIN functions f ON f.file_id = fi.id
             WHERE fi.analysis_id = ?
             GROUP BY fi.id, fi.file_path
             ORDER BY vuln_count DESC
             LIMIT 10",
        )?;

        let iter = stmt.query_map([analysis_id], |row| {
            let path: String = row.get(0)?;
            let label = path
                .replace('\\', "/")
                .split('/')
                .next_back()
                .unwrap_or("")
                .to_string();

            Ok(FileRatio {
                label,
                safe: row.get::<_, Option<i32>>(1)?.unwrap_or(0),
                vuln: row.get::<_, Option<i32>>(2)?.unwrap_or(0),
            })
        })?;

        let mut file_ratios = Vec::new();
        for r in iter {
            file_ratios.push(r?);
        }

        Ok(file_ratios)
    })
    .await
}
