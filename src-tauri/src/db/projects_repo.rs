use deadpool_sqlite::Pool;
use rusqlite::params;
use std::collections::HashMap;

use crate::db::WatchedProject;
use crate::error::AppError;

pub async fn add_watched_project(
    pool: &Pool,
    name: String,
    folder_path: String,
) -> Result<i32, AppError> {
    let res = pool
        .get()
        .await?
        .interact(move |conn| {
            match conn.execute(
                "INSERT INTO watched_projects (name, folder_path) VALUES (?1, ?2)",
                params![name, folder_path],
            ) {
                Ok(_) => Ok(conn.last_insert_rowid() as i32),
                Err(e) => {
                    if let rusqlite::Error::SqliteFailure(e_code, _) = &e {
                        if e_code.code == rusqlite::ErrorCode::ConstraintViolation {
                            return Err(rusqlite::Error::InvalidParameterName("Constraint".into()));
                        }
                    }
                    Err(e)
                }
            }
        })
        .await??;
    Ok(res)
}

pub async fn get_watched_projects(pool: &Pool) -> Result<Vec<WatchedProject>, AppError> {
    let projects = pool.get().await?.interact(|conn| {
        let mut stmt = conn.prepare("SELECT id, name, folder_path, registered_at FROM watched_projects ORDER BY registered_at DESC")?;
        let iter = stmt.query_map([], |row| {
            Ok(WatchedProject {
                id: row.get(0)?,
                name: row.get(1)?,
                folder_path: row.get(2)?,
                registered_at: row.get(3)?,
            })
        })?;
        let mut projects = Vec::new();
        for r in iter {
            projects.push(r?);
        }
        Ok::<_, rusqlite::Error>(projects)
    }).await??;
    Ok(projects)
}

pub async fn save_file_hashes(
    pool: &Pool,
    project_id: i32,
    hashes: HashMap<String, String>,
) -> Result<(), AppError> {
    pool.get()
        .await?
        .interact(move |conn| {
            let mut stmt = conn.prepare(
                "INSERT INTO file_hashes (project_id, file_path, file_hash)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(project_id, file_path)
             DO UPDATE SET file_hash = excluded.file_hash, hashed_at = CURRENT_TIMESTAMP",
            )?;
            for (path, hash) in &hashes {
                stmt.execute(params![project_id, path, hash])?;
            }
            Ok::<_, rusqlite::Error>(())
        })
        .await??;
    Ok(())
}

pub async fn get_file_hashes(
    pool: &Pool,
    project_id: i32,
) -> Result<HashMap<String, String>, AppError> {
    let hashes = pool
        .get()
        .await?
        .interact(move |conn| {
            let mut stmt =
                conn.prepare("SELECT file_path, file_hash FROM file_hashes WHERE project_id = ?1")?;
            let iter = stmt.query_map(params![project_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut hashes = HashMap::new();
            for r in iter {
                let (path, hash) = r?;
                hashes.insert(path, hash);
            }
            Ok::<_, rusqlite::Error>(hashes)
        })
        .await??;
    Ok(hashes)
}

pub async fn remove_watched_project(pool: &Pool, project_id: i32) -> Result<(), AppError> {
    pool.get()
        .await?
        .interact(move |conn| {
            conn.execute(
                "DELETE FROM watched_projects WHERE id = ?1",
                params![project_id],
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await??;
    Ok(())
}
