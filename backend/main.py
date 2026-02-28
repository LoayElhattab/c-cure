import sys
import json
import os

from database import db


class AnalysisService:

    CPP_EXTENSIONS = ('.cpp', '.c', '.h', '.cc', '.cxx')

    def run_file(self, file_path: str) -> dict:
        from parser import extract_functions
        from inference import check_api_health, analyze_function

        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
        if not check_api_health():
            return {"error": "Kaggle API is unreachable. Make sure the notebook is running and the URL is set."}

        project_name = os.path.basename(file_path)
        analysis_id  = db.save_analysis(project_name, file_path)
        file_id      = db.save_file(analysis_id, file_path)

        functions = extract_functions(file_path)
        if not functions:
            db.delete_analysis(analysis_id)
            return {"error": "No functions found in file. Is it a valid C++ file?"}

        results = []
        for fn in functions:
            result = analyze_function(fn["code"])
            if "error" in result:
                db.delete_analysis(analysis_id)
                return {"error": result["error"]}
            full_fn = {**fn, **result}
            db.save_function(file_id, full_fn)
            results.append(full_fn)

        vuln_count = sum(1 for r in results if r["verdict"] == "vulnerable")
        return {
            "analysis_id":     analysis_id,
            "project_name":    project_name,
            "file_path":       file_path,
            "total_functions": len(results),
            "vuln_count":      vuln_count,
            "functions":       results,
        }

    def run_folder(self, folder_path: str) -> dict:
        from parser import extract_functions
        from inference import check_api_health, analyze_function

        if not os.path.exists(folder_path):
            return {"error": f"Folder not found: {folder_path}"}
        if not check_api_health():
            return {"error": "Kaggle API is unreachable. Make sure the notebook is running."}

        cpp_files = []
        for root, dirs, files in os.walk(folder_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')
                       and d not in ('build', 'cmake', 'node_modules')]
            for file in files:
                if file.endswith(self.CPP_EXTENSIONS):
                    cpp_files.append(os.path.join(root, file))

        if not cpp_files:
            return {"error": "No C++ files found in folder."}

        project_name = os.path.basename(folder_path.rstrip('/\\'))
        analysis_id  = db.save_analysis(project_name, folder_path)

        all_functions, total_vuln = [], 0

        for file_path in cpp_files:
            file_id   = db.save_file(analysis_id, file_path)
            functions = extract_functions(file_path)
            for fn in functions:
                result = analyze_function(fn["code"])
                if "error" in result:
                    db.delete_analysis(analysis_id)
                    return {"error": result["error"]}
                full_fn = {**fn, **result, "file_path": file_path}
                db.save_function(file_id, full_fn)
                all_functions.append(full_fn)
                if full_fn["verdict"] == "vulnerable":
                    total_vuln += 1

        return {
            "analysis_id":     analysis_id,
            "project_name":    project_name,
            "folder_path":     folder_path,
            "files_scanned":   len(cpp_files),
            "total_functions": len(all_functions),
            "vuln_count":      total_vuln,
            "functions":       all_functions,
        }


# Global singleton
service = AnalysisService()


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No command provided"}))
        sys.exit(1)

    command = sys.argv[1]

    # ── Fast commands — only sqlite3 + json, no heavy imports ──────────────

    if command == "history":
        print(json.dumps(db.get_all_analyses(), indent=2))

    elif command == "report":
        if len(sys.argv) < 3:
            print(json.dumps({"error": "No analysis ID provided"}))
            sys.exit(1)
        report = db.get_report(int(sys.argv[2]))
        print(json.dumps(report if report else {"error": "Report not found"}, indent=2))

    elif command == "delete_analysis":
        if len(sys.argv) < 3:
            print(json.dumps({"error": "No analysis ID provided"}))
            sys.exit(1)
        db.delete_analysis(int(sys.argv[2]))
        print(json.dumps({"deleted": True}))

    elif command == "dashboard":
        print(json.dumps(db.get_dashboard_stats(), indent=2))

    elif command == "get_trend_data":
        print(json.dumps(db.get_trend_data(), indent=2))

    elif command == "statistics":
        print(json.dumps(db.get_dashboard_and_trend(), indent=2))

    elif command == "vuln_count":
        print(json.dumps({"count": db.get_vuln_count()}))

    elif command == "get_settings":
        config_path = os.path.join(os.path.dirname(__file__), 'config.json')
        if os.path.exists(config_path):
            with open(config_path) as f:
                print(json.dumps(json.load(f)))
        else:
            print(json.dumps({"kaggle_url": ""}))

    elif command == "save_settings":
        if len(sys.argv) < 3:
            print(json.dumps({"error": "No URL provided"}))
            sys.exit(1)
        config_path = os.path.join(os.path.dirname(__file__), 'config.json')
        try:
            with open(config_path, 'w') as f:
                json.dump({"kaggle_url": sys.argv[2]}, f)
            print(json.dumps({"saved": True}))
        except Exception as e:
            print(json.dumps({"error": str(e)}))

    # ── Medium commands — needs requests only ──────────────────────────────

    elif command == "check_api":
        from inference import check_api_health
        print(json.dumps({"reachable": check_api_health()}))

    # ── Heavy commands — needs tree_sitter + requests ──────────────────────

    elif command == "extract_functions":
        if len(sys.argv) < 3:
            print(json.dumps({"error": "No file path provided"}))
            sys.exit(1)
        from parser import extract_functions
        functions = extract_functions(sys.argv[2])
        print(json.dumps({"functions": functions, "count": len(functions)}))

    elif command == "analyze":
        if len(sys.argv) < 3:
            print(json.dumps({"error": "No file path provided"}))
            sys.exit(1)
        print(json.dumps(service.run_file(sys.argv[2]), indent=2))

    elif command == "analyze_folder":
        if len(sys.argv) < 3:
            print(json.dumps({"error": "No folder path provided"}))
            sys.exit(1)
        print(json.dumps(service.run_folder(sys.argv[2]), indent=2))

    # ── PDF — needs reportlab ──────────────────────────────────────────────

    elif command == "generate_pdf":
        if len(sys.argv) < 3:
            print(json.dumps({"error": "No analysis ID provided"}))
            sys.exit(1)

        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        import tempfile

        analysis_id = int(sys.argv[2])
        report = db.get_report(analysis_id)
        if not report:
            print(json.dumps({"error": "Report not found"}))
            sys.exit(1)

        pdf_path = os.path.join(tempfile.gettempdir(), f"c-cure-report-{analysis_id}.pdf")
        doc      = SimpleDocTemplate(pdf_path, pagesize=A4,
                                     rightMargin=30, leftMargin=30,
                                     topMargin=30, bottomMargin=30)
        styles    = getSampleStyleSheet()
        flowables = []

        flowables.append(Paragraph("C-Cure Vulnerability Report", styles['Title']))
        flowables.append(Paragraph(f"Project: {report.get('project_name', 'Unknown')}", styles['Heading2']))
        flowables.append(Paragraph(f"Date: {report.get('timestamp', 'Unknown')}", styles['Normal']))
        flowables.append(Spacer(1, 20))

        total_fns  = sum(len(f.get('functions', [])) for f in report.get('files', []))
        total_vuln = sum(1 for f in report.get('files', [])
                         for fn in f.get('functions', [])
                         if fn.get('verdict') == 'vulnerable')

        flowables.append(Paragraph("Summary", styles['Heading3']))
        flowables.append(Paragraph(f"Total Functions Scanned: {total_fns}", styles['Normal']))
        flowables.append(Paragraph(f"Vulnerable Functions: <font color='red'>{total_vuln}</font>", styles['Normal']))
        flowables.append(Spacer(1, 20))

        for file_data in report.get('files', []):
            flowables.append(Paragraph(file_data.get('file_path', 'Unknown File'), styles['Heading3']))
            for fn in file_data.get('functions', []):
                fn_name       = fn.get('function_name', 'Unknown')
                start         = fn.get('start_line', '?')
                end           = fn.get('end_line', '?')
                verdict       = fn.get('verdict', 'safe')
                heading_color = "red" if verdict == "vulnerable" else "green"
                flowables.append(Paragraph(
                    f"<b>{fn_name}</b> (Lines {start}-{end}) - "
                    f"<font color='{heading_color}'>{verdict.upper()}</font>",
                    styles['Normal']
                ))
                if verdict == "vulnerable":
                    cwe      = fn.get('cwe', 'Unknown')
                    severity = fn.get('severity', 'Unknown')
                    flowables.append(Paragraph(f"CWE: {cwe} | Severity: {severity}", styles['Normal']))
                flowables.append(Spacer(1, 10))
            flowables.append(Spacer(1, 10))

        doc.build(flowables)
        print(json.dumps({"path": pdf_path}))

    else:
        print(json.dumps({"error": f"Unknown command: {command}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()