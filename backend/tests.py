import os
import sys
import json
import sqlite3
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(__file__))

from parser import extract_functions
from database import db, DB_PATH
from main import service


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def make_temp_cpp(code: str) -> str:
    f = tempfile.NamedTemporaryFile(suffix='.cpp', delete=False, mode='w')
    f.write(code)
    f.close()
    return f.name


def wipe_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        DELETE FROM functions;
        DELETE FROM files;
        DELETE FROM analyses;
    """)
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# Parser Tests
# ─────────────────────────────────────────────

class TestParser(unittest.TestCase):

    def test_extracts_basic_function(self):
        path = make_temp_cpp("void hello() {\n    printf(\"hello\");\n}\n")
        fns = extract_functions(path)
        os.unlink(path)
        self.assertEqual(len(fns), 1)
        self.assertEqual(fns[0]['name'], 'hello')

    def test_extracts_multiple_functions(self):
        path = make_temp_cpp("void foo() {}\nint bar(int x) { return x; }\nbool baz(char* s) { return s != nullptr; }\n")
        fns = extract_functions(path)
        os.unlink(path)
        self.assertEqual(len(fns), 3)
        names = [f['name'] for f in fns]
        self.assertIn('foo', names)
        self.assertIn('bar', names)
        self.assertIn('baz', names)

    def test_extracts_template_function(self):
        path = make_temp_cpp("template<typename T>\nT safeDivide(T a, T b) {\n    if (b == 0) return 0;\n    return a / b;\n}\n")
        fns = extract_functions(path)
        os.unlink(path)
        self.assertEqual(len(fns), 1)
        self.assertEqual(fns[0]['name'], 'safeDivide')

    def test_returns_correct_line_numbers(self):
        path = make_temp_cpp("void foo() {\n    int x = 1;\n}\n\nvoid bar() {\n    int y = 2;\n}\n")
        fns = extract_functions(path)
        os.unlink(path)
        self.assertEqual(fns[0]['start_line'], 1)
        self.assertEqual(fns[1]['start_line'], 5)

    def test_empty_file_returns_empty_list(self):
        path = make_temp_cpp("")
        fns = extract_functions(path)
        os.unlink(path)
        self.assertEqual(fns, [])

    def test_file_with_only_comments(self):
        path = make_temp_cpp("// just a comment\n/* nothing here */\n")
        fns = extract_functions(path)
        os.unlink(path)
        self.assertEqual(fns, [])

    def test_nonexistent_file_returns_empty(self):
        fns = extract_functions("/nonexistent/path/file.cpp")
        self.assertEqual(fns, [])

    def test_code_snippet_is_correct(self):
        path = make_temp_cpp("void greet() {\n    printf(\"hi\");\n}\n")
        fns = extract_functions(path)
        os.unlink(path)
        self.assertIn('greet', fns[0]['code'])
        self.assertIn('printf', fns[0]['code'])


# ─────────────────────────────────────────────
# Database Tests
# ─────────────────────────────────────────────

class TestDatabase(unittest.TestCase):

    def setUp(self):
        wipe_db()

    def test_save_and_fetch_analysis(self):
        aid = db.save_analysis("test.cpp", "/path/test.cpp")
        self.assertIsInstance(aid, int)
        self.assertGreater(aid, 0)

    def test_save_file_under_analysis(self):
        aid = db.save_analysis("test.cpp", "/path/test.cpp")
        fid = db.save_file(aid, "/path/test.cpp")
        self.assertIsInstance(fid, int)
        self.assertGreater(fid, 0)

    def test_save_vulnerable_function(self):
        aid = db.save_analysis("test.cpp", "/path/test.cpp")
        fid = db.save_file(aid, "/path/test.cpp")
        db.save_function(fid, {
            "name": "readBuffer", "code": "void readBuffer() {}",
            "verdict": "vulnerable", "cwe": "CWE-125",
            "cwe_name": "Out-of-bounds Read", "severity": "High",
            "confidence": 0.92, "start_line": 1, "end_line": 3,
        })
        report = db.get_report(aid)
        fn = report['files'][0]['functions'][0]
        self.assertEqual(fn['verdict'], 'vulnerable')
        self.assertEqual(fn['cwe'], 'CWE-125')
        self.assertAlmostEqual(fn['confidence'], 0.92)

    def test_save_safe_function(self):
        aid = db.save_analysis("test.cpp", "/path/test.cpp")
        fid = db.save_file(aid, "/path/test.cpp")
        db.save_function(fid, {
            "name": "cleanup", "code": "void cleanup() {}",
            "verdict": "safe", "cwe": None, "cwe_name": None,
            "severity": None, "confidence": None,
            "start_line": 1, "end_line": 1,
        })
        report = db.get_report(aid)
        fn = report['files'][0]['functions'][0]
        self.assertEqual(fn['verdict'], 'safe')
        self.assertIsNone(fn['cwe'])

    def test_get_all_analyses_returns_list(self):
        db.save_analysis("a.cpp", "/a.cpp")
        db.save_analysis("b.cpp", "/b.cpp")
        history = db.get_all_analyses()
        self.assertGreaterEqual(len(history), 2)

    def test_history_counts_are_correct(self):
        aid = db.save_analysis("test.cpp", "/test.cpp")
        fid = db.save_file(aid, "/test.cpp")
        db.save_function(fid, {"name": "f1", "code": "", "verdict": "vulnerable",
                               "cwe": "CWE-125", "cwe_name": "OOB", "severity": "High",
                               "confidence": 0.9, "start_line": 1, "end_line": 2})
        db.save_function(fid, {"name": "f2", "code": "", "verdict": "safe",
                               "cwe": None, "cwe_name": None, "severity": None,
                               "confidence": None, "start_line": 3, "end_line": 4})
        history = db.get_all_analyses()
        entry = next(h for h in history if h['id'] == aid)
        self.assertEqual(entry['total_functions'], 2)
        self.assertEqual(entry['vuln_count'], 1)

    def test_get_report_invalid_id_returns_none(self):
        report = db.get_report(99999)
        self.assertIsNone(report)

    def test_delete_analysis(self):
        aid = db.save_analysis("test.cpp", "/test.cpp")
        db.delete_analysis(aid)
        report = db.get_report(aid)
        self.assertIsNone(report)

    def test_cascade_delete(self):
        aid = db.save_analysis("test.cpp", "/test.cpp")
        fid = db.save_file(aid, "/test.cpp")
        db.save_function(fid, {"name": "fn", "code": "", "verdict": "safe",
                               "cwe": None, "cwe_name": None, "severity": None,
                               "confidence": None, "start_line": 1, "end_line": 1})
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("DELETE FROM analyses WHERE id = ?", (aid,))
        conn.commit()
        fns = conn.execute("SELECT * FROM functions WHERE file_id = ?", (fid,)).fetchall()
        conn.close()
        self.assertEqual(len(fns), 0)


# ─────────────────────────────────────────────
# Main / Pipeline Tests (no API needed)
# ─────────────────────────────────────────────

class TestMain(unittest.TestCase):

    def setUp(self):
        wipe_db()

    def test_run_file_missing_file(self):
        result = service.run_file("/nonexistent/file.cpp")
        self.assertIn("error", result)

    def test_fetch_report_invalid_id(self):
        report = db.get_report(99999)
        self.assertIsNone(report)

    def test_fetch_history_returns_list(self):
        result = db.get_all_analyses()
        self.assertIsInstance(result, list)

    def test_history_reflects_saved_data(self):
        aid = db.save_analysis("demo.cpp", "/demo.cpp")
        history = db.get_all_analyses()
        ids = [h['id'] for h in history]
        self.assertIn(aid, ids)

    def test_fetch_report_returns_correct_structure(self):
        aid = db.save_analysis("demo.cpp", "/demo.cpp")
        fid = db.save_file(aid, "/demo.cpp")
        db.save_function(fid, {"name": "foo", "code": "void foo(){}", "verdict": "safe",
                               "cwe": None, "cwe_name": None, "severity": None,
                               "confidence": None, "start_line": 1, "end_line": 1})
        report = db.get_report(aid)
        self.assertIn("files", report)
        self.assertIn("project_name", report)
        self.assertEqual(report["project_name"], "demo.cpp")
        self.assertEqual(len(report["files"][0]["functions"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)