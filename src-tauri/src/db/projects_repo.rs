use duckdb::params;
use std::collections::HashMap;

use crate::db::{DbPool, WatchedProject};
use crate::error::AppError;

fn is_unique_violation(err: &duckdb::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("unique")
        || msg.contains("constraint")
        || msg.contains("duplicate")
        || msg.contains("primary key")
}

pub async fn add_watched_project(
    pool: &DbPool,
    name: String,
    folder_path: String,
) -> Result<i32, AppError> {
    pool.with_conn(move |conn| {
        match conn.execute(
            "INSERT INTO watched_projects (name, folder_path) VALUES (?, ?)",
            params![name, folder_path],
        ) {
            Ok(_) => {
                let mut stmt = conn.prepare("SELECT last_insert_rowid()")?;
                let id: i64 = stmt.query_row([], |row| row.get(0))?;
                Ok(id as i32)
            }
            Err(e) if is_unique_violation(&e) => {
                Err(duckdb::Error::InvalidParameterName("Constraint".into()))
            }
            Err(e) => Err(e),
        }
    })
    .await
}

pub async fn upsert_watched_project(
    pool: &DbPool,
    name: String,
    folder_path: String,
) -> Result<i32, AppError> {
    pool.with_conn(move |conn| {
        conn.execute(
            "INSERT INTO watched_projects (name, folder_path)
             VALUES (?, ?)
             ON CONFLICT (folder_path)
             DO UPDATE SET name = EXCLUDED.name",
            params![name, folder_path.clone()],
        )?;

        let mut stmt = conn.prepare("SELECT id FROM watched_projects WHERE folder_path = ?")?;
        let id: i32 = stmt.query_row(params![folder_path], |row| row.get(0))?;
        Ok(id)
    })
    .await
}

pub async fn get_watched_projects(pool: &DbPool) -> Result<Vec<WatchedProject>, AppError> {
    pool.with_conn(|conn| {
        let mut stmt = conn.prepare(
            "SELECT id, name, folder_path, CAST(registered_at AS VARCHAR)
             FROM watched_projects ORDER BY registered_at DESC",
        )?;
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
        Ok(projects)
    })
    .await
}

pub async fn remove_watched_project_by_path(
    pool: &DbPool,
    folder_path: String,
) -> Result<(), AppError> {
    pool.with_conn(move |conn| {
        let project_id = {
            let mut stmt = conn.prepare("SELECT id FROM watched_projects WHERE folder_path = ?")?;
            match stmt.query_row(params![folder_path.clone()], |row| row.get::<_, i32>(0)) {
                Ok(id) => Some(id),
                Err(duckdb::Error::QueryReturnedNoRows) => None,
                Err(err) => return Err(err),
            }
        };

        if let Some(id) = project_id {
            conn.execute("DELETE FROM file_hashes WHERE project_id = ?", params![id])?;
            conn.execute("DELETE FROM watched_projects WHERE id = ?", params![id])?;
        }

        Ok(())
    })
    .await
}

pub async fn save_file_hashes(
    pool: &DbPool,
    project_id: i32,
    hashes: HashMap<String, String>,
) -> Result<(), AppError> {
    pool.with_conn(move |conn| {
        let mut stmt = conn.prepare(
            "INSERT INTO file_hashes (project_id, file_path, file_hash)
             VALUES (?, ?, ?)
             ON CONFLICT (project_id, file_path)
             DO UPDATE SET file_hash = EXCLUDED.file_hash, hashed_at = now()",
        )?;
        for (path, hash) in &hashes {
            stmt.execute(params![project_id, path, hash])?;
        }
        Ok(())
    })
    .await
}

pub async fn get_file_hashes(
    pool: &DbPool,
    project_id: i32,
) -> Result<HashMap<String, String>, AppError> {
    pool.with_conn(move |conn| {
        let mut stmt =
            conn.prepare("SELECT file_path, file_hash FROM file_hashes WHERE project_id = ?")?;
        let iter = stmt.query_map(params![project_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut hashes = HashMap::new();
        for r in iter {
            let (path, hash) = r?;
            hashes.insert(path, hash);
        }
        Ok(hashes)
    })
    .await
}

pub async fn remove_watched_project(pool: &DbPool, project_id: i32) -> Result<(), AppError> {
    pool.with_conn(move |conn| {
        // DuckDB does not support ON DELETE CASCADE; delete children explicitly.
        conn.execute(
            "DELETE FROM file_hashes WHERE project_id = ?",
            params![project_id],
        )?;
        conn.execute(
            "DELETE FROM watched_projects WHERE id = ?",
            params![project_id],
        )?;
        Ok(())
    })
    .await
}

pub async fn get_project_id_by_path(
    pool: &DbPool,
    folder_path: String,
) -> Result<Option<i32>, AppError> {
    pool.with_conn(move |conn| {
        let mut stmt = conn.prepare("SELECT id FROM watched_projects WHERE folder_path = ?")?;
        match stmt.query_row(params![folder_path], |row| row.get::<_, i32>(0)) {
            Ok(id) => Ok(Some(id)),
            Err(duckdb::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err),
        }
    })
    .await
}

pub async fn get_file_hash(
    pool: &DbPool,
    project_id: i32,
    file_path: String,
) -> Result<Option<u64>, AppError> {
    pool.with_conn(move |conn| {
        let mut stmt = conn
            .prepare("SELECT file_hash FROM file_hashes WHERE project_id = ? AND file_path = ?")?;
        match stmt.query_row(params![project_id, file_path], |row| {
            row.get::<_, String>(0)
        }) {
            Ok(hash_str) => {
                let parsed = hash_str.parse::<u64>().ok();
                Ok(parsed)
            }
            Err(duckdb::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err),
        }
    })
    .await
}

pub async fn upsert_file_hash(
    pool: &DbPool,
    project_id: i32,
    file_path: String,
    hash_value: u64,
) -> Result<(), AppError> {
    pool.with_conn(move |conn| {
        conn.execute(
            "INSERT INTO file_hashes (project_id, file_path, file_hash)
             VALUES (?, ?, ?)
             ON CONFLICT (project_id, file_path)
             DO UPDATE SET file_hash = EXCLUDED.file_hash, hashed_at = now()",
            params![project_id, file_path, hash_value.to_string()],
        )?;
        Ok(())
    })
    .await
}
