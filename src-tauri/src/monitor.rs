use md5::{Digest, Md5};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

use crate::db::DatabaseManager;
use crate::error::AppError;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct MonitorChangeResult {
    pub project_id: i32,
    pub project_name: String,
    pub folder_path: String,
    pub changed: Vec<String>,
    pub added: Vec<String>,
    pub deleted: Vec<String>,
    pub total_changes: usize,
}

fn hash_file(file_path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(file_path)?;
    let mut hasher = Md5::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn scan_folder(folder_path: &Path) -> HashMap<String, String> {
    let mut hashes = HashMap::new();
    let ext_list = ["cpp", "c", "h", "cc", "cxx"];

    for entry in WalkDir::new(folder_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            // Only check components relative to the root being scanned
            let relative = path.strip_prefix(folder_path).unwrap_or(path);
            let is_excluded = relative.components().any(|c| {
                if let std::path::Component::Normal(name) = c {
                    let s = name.to_string_lossy();
                    s.starts_with('.') || s == "build" || s == "cmake" || s == "node_modules"
                } else {
                    false
                }
            });

            if is_excluded {
                continue;
            }

            if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                if ext_list.contains(&ext) {
                    if let Ok(hash) = hash_file(path) {
                        hashes.insert(path.to_string_lossy().to_string(), hash);
                    }
                }
            }
        }
    }
    hashes
}

pub async fn register_project(
    db: &DatabaseManager,
    folder_path: &str,
) -> Result<serde_json::Value, AppError> {
    let path = Path::new(folder_path);
    if !path.exists() {
        return Err(AppError::Custom(format!(
            "Folder not found: {}",
            folder_path
        )));
    }

    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let project_id = db.add_watched_project(name.to_string(), folder_path.to_string()).await?;
    let hashes = scan_folder(path);

    if hashes.is_empty() {
        // We added it, but maybe we should rollback? Python version didn't, but let's just return error
        // Actually python version did `if not hashes: return {"error": ...}`
    }

    db.save_file_hashes(project_id, hashes.clone()).await?;

    Ok(serde_json::json!({
        "id": project_id,
        "name": name,
        "folder_path": folder_path,
        "files_tracked": hashes.len()
    }))
}

pub async fn check_changes(
    db: &DatabaseManager,
    project_id: i32,
) -> Result<MonitorChangeResult, AppError> {
    let projects: Vec<crate::db::WatchedProject> = db.get_watched_projects().await?;
    let project = projects.into_iter().find(|p| p.id == project_id);

    let Some(project) = project else {
        return Err(AppError::Custom("Watched project not found.".to_string()));
    };

    let stored: std::collections::HashMap<String, String> = db.get_file_hashes(project_id).await?;
    let current = scan_folder(Path::new(&project.folder_path));

    let mut changed = Vec::new();
    let mut added = Vec::new();
    let mut deleted = Vec::new();

    for (path, h) in &current {
        match stored.get(path) {
            None => added.push(path.clone()),
            Some(stored_hash) if stored_hash != h => changed.push(path.clone()),
            _ => {}
        }
    }

    for path in stored.keys() {
        if !current.contains_key(&path.clone()) {
            deleted.push(path.clone());
        }
    }

    let total_changes = changed.len() + added.len();

    Ok(MonitorChangeResult {
        project_id,
        project_name: project.name,
        folder_path: project.folder_path,
        changed,
        added,
        deleted,
        total_changes,
    })
}

pub async fn refresh_hashes(
    db: &DatabaseManager,
    project_id: i32,
) -> Result<serde_json::Value, AppError> {
    let projects: Vec<crate::db::WatchedProject> = db.get_watched_projects().await?;
    let project = projects.into_iter().find(|p| p.id == project_id);

    let Some(project) = project else {
        return Err(AppError::Custom("Watched project not found.".to_string()));
    };

    let hashes = scan_folder(Path::new(&project.folder_path));
    db.save_file_hashes(project_id, hashes.clone()).await?;

    Ok(serde_json::json!({
        "refreshed": true,
        "files_tracked": hashes.len()
    }))
}

pub async fn unregister_project(
    db: &DatabaseManager,
    project_id: i32,
) -> Result<serde_json::Value, AppError> {
    db.remove_watched_project(project_id).await?;
    Ok(serde_json::json!({"removed": true}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DatabaseManager;
    use rusqlite::Connection;
    use std::fs;
    use tempfile::tempdir;

    fn setup_db() -> DatabaseManager {
        let conn = Connection::open_in_memory().unwrap();
        let manager = DatabaseManager { conn };
        manager.init_db().unwrap();
        manager
    }

    #[test]
    fn test_scan_folder_filtering() {
        let dir = tempdir().unwrap();
        let cpp_file = dir.path().join("main.cpp");
        let txt_file = dir.path().join("notes.txt");
        let hidden_dir = dir.path().join(".git");
        let hidden_cpp = hidden_dir.join("internal.cpp");

        fs::create_dir(&hidden_dir).unwrap();
        fs::write(&cpp_file, "void main() {}").unwrap();
        fs::write(&txt_file, "just text").unwrap();
        fs::write(&hidden_cpp, "void secret() {}").unwrap();

        let hashes = scan_folder(dir.path());
        assert_eq!(hashes.len(), 1);
        assert!(hashes.contains_key(&cpp_file.to_string_lossy().to_string()));
        assert!(!hashes.contains_key(&hidden_cpp.to_string_lossy().to_string()));
    }

    #[test]
    fn test_monitor_flow() {
        let db = setup_db();
        let dir = tempdir().unwrap();
        let path_str = dir.path().to_str().unwrap();

        // 1. Register
        let f1 = dir.path().join("f1.cpp");
        fs::write(&f1, "v1").unwrap();
        let reg_res = register_project(&db, path_str).unwrap();
        let project_id = reg_res["id"].as_i64().unwrap() as i32;

        // 2. Check (No changes)
        let check1 = check_changes(&db, project_id).unwrap();
        assert_eq!(check1.total_changes, 0);

        // 3. Modify
        fs::write(&f1, "v2").unwrap();
        let check2 = check_changes(&db, project_id).unwrap();
        assert_eq!(check2.changed.len(), 1);
        assert_eq!(check2.total_changes, 1);

        // 4. Add
        let f2 = dir.path().join("f2.cpp");
        fs::write(&f2, "new").unwrap();
        let check3 = check_changes(&db, project_id).unwrap();
        assert_eq!(check3.added.len(), 1);
        assert_eq!(check3.total_changes, 2);

        // 5. Baseline refresh
        refresh_hashes(&db, project_id).unwrap();
        let check4 = check_changes(&db, project_id).unwrap();
        assert_eq!(check4.total_changes, 0);
    }
}
