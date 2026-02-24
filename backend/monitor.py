import os
import hashlib
import sys
import json
from database import db


CPP_EXTENSIONS = ('.cpp', '.c', '.h', '.cc', '.cxx')


def hash_file(file_path: str) -> str:
    h = hashlib.md5()
    with open(file_path, 'rb') as f:
        h.update(f.read())
    return h.hexdigest()


def scan_folder(folder_path: str) -> dict:
    hashes = {}
    for root, dirs, files in os.walk(folder_path):
        dirs[:] = [d for d in dirs if not d.startswith('.')
                   and d not in ('build', 'cmake', 'node_modules')]
        for file in files:
            if file.endswith(CPP_EXTENSIONS):
                full_path = os.path.join(root, file)
                try:
                    hashes[full_path] = hash_file(full_path)
                except Exception:
                    pass
    return hashes


def register_project(folder_path: str) -> dict:
    if not os.path.exists(folder_path):
        return {"error": f"Folder not found: {folder_path}"}
    name   = os.path.basename(folder_path.rstrip('/\\'))
    result = db.add_watched_project(name, folder_path)
    if "error" in result:
        return result
    hashes = scan_folder(folder_path)
    if not hashes:
        return {"error": "No C++ files found in folder."}
    db.save_file_hashes(result["id"], hashes)
    return {"id": result["id"], "name": name, "folder_path": folder_path, "files_tracked": len(hashes)}


def check_changes(project_id: int) -> dict:
    projects = db.get_watched_projects()
    project  = next((p for p in projects if p["id"] == project_id), None)
    if not project:
        return {"error": "Watched project not found."}
    stored  = db.get_file_hashes(project_id)
    current = scan_folder(project["folder_path"])
    changed, added, deleted = [], [], []
    for path, h in current.items():
        if path not in stored:
            added.append(path)
        elif stored[path] != h:
            changed.append(path)
    for path in stored:
        if path not in current:
            deleted.append(path)
    return {
        "project_id":    project_id,
        "project_name":  project["name"],
        "folder_path":   project["folder_path"],
        "changed":       changed,
        "added":         added,
        "deleted":       deleted,
        "total_changes": len(changed) + len(added),
    }


def refresh_hashes(project_id: int) -> dict:
    projects = db.get_watched_projects()
    project  = next((p for p in projects if p["id"] == project_id), None)
    if not project:
        return {"error": "Watched project not found."}
    hashes = scan_folder(project["folder_path"])
    db.save_file_hashes(project_id, hashes)
    return {"refreshed": True, "files_tracked": len(hashes)}


def unregister_project(project_id: int) -> dict:
    db.remove_watched_project(project_id)
    return {"removed": True}


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "register":
        print(json.dumps(register_project(sys.argv[2])))
    elif command == "list":
        print(json.dumps(db.get_watched_projects()))
    elif command == "check":
        print(json.dumps(check_changes(int(sys.argv[2]))))
    elif command == "refresh":
        print(json.dumps(refresh_hashes(int(sys.argv[2]))))
    elif command == "remove":
        print(json.dumps(unregister_project(int(sys.argv[2]))))
    else:
        print(json.dumps({"error": "Unknown command"}))