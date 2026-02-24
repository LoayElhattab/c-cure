import requests

# Your ML teammate pastes their ngrok URL here when the notebook is running
KAGGLE_API_URL = "https://compressibly-platinous-emiko.ngrok-free.dev"

FAMILY_MAP = {
    "memory_corruption": ["CWE-125", "CWE-787"],
    "input_validation":  ["CWE-190", "CWE-369"],
    "memory_lifecycle":  ["CWE-415", "CWE-476"],
}

CWE_INFO = {
    "CWE-125": {"name": "Out-of-bounds Read",       "severity": "High"},
    "CWE-787": {"name": "Out-of-bounds Write",      "severity": "Critical"},
    "CWE-190": {"name": "Integer Overflow",         "severity": "Medium"},
    "CWE-369": {"name": "Divide By Zero",           "severity": "Medium"},
    "CWE-415": {"name": "Double Free",              "severity": "High"},
    "CWE-476": {"name": "NULL Pointer Dereference", "severity": "High"},
}


def check_api_health() -> bool:
    try:
        r = requests.get(f"{KAGGLE_API_URL}", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def analyze_function(code: str) -> dict:
    """
    Run a single function through triage → classify.
    Returns a result dict ready to be saved to SQLite.
    """
    try:
        classify_response = requests.post(
            f"{KAGGLE_API_URL}/predict",
            json={"code": code},
            timeout=30
        )
        classify_response.raise_for_status()
        data = classify_response.json()
        import sys
        print(f"[DEBUG] Raw API response: {data}", file=sys.stderr)

        result = data.get("result", {})
        output = result.get("output") if isinstance(result, dict) else result
        confidence = result.get("confidence") if isinstance(result, dict) else data.get("confidence")

        # Also check top-level confidence (some API versions put it there)
        if confidence is None:
            confidence = data.get("confidence")

        # Ensure confidence is always a number, never a dict
        if isinstance(confidence, dict):
            confidence = confidence.get("output", confidence.get("value", 0.0))
        if confidence is not None:
            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                confidence = None

        # Check if the code is safe
        if isinstance(output, str) and output.lower() in ("code is safe", "safe"):
            return {
                "verdict": "safe",
                "cwe": "safe",
                "cwe_name": "safe",
                "severity": "safe",
                "confidence": confidence if confidence is not None else 1.0,
                "family": "safe",
            }

        # Vulnerable: output is a list like ["CWE-476"]
        cwe = output[0] if isinstance(output, list) else output
        if isinstance(cwe, str) and cwe.lower() in ("code is safe", "safe","SAFE"):
            return {
                "verdict": "safe",
                "cwe": "safe",
                "cwe_name": "safe",
                "severity": "safe",
                "confidence": confidence if confidence is not None else 1.0,
                "family": "safe",
            }
        cwe_meta = CWE_INFO.get(cwe, {"name": "Unknown", "severity": "Unknown"})
        return {
            "verdict": "vulnerable",
            "cwe": cwe,
            "cwe_name": cwe_meta["name"],
            "severity": cwe_meta["severity"],
            "confidence": confidence,
        }

    except requests.exceptions.ConnectionError:
        return {"error": "Cannot reach Kaggle API. Is the notebook running?"}
    except requests.exceptions.Timeout:
        return {"error": "Kaggle API timed out."}
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    # Quick health check test
    print("Checking API health...")
    if check_api_health():
        print("✓ API is reachable")
    else:
        print("✗ API not reachable — paste your ngrok URL into KAGGLE_API_URL first")