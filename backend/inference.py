import requests
import os
import json

# ── Configurable Kaggle API URL ───────────────────────
def _load_url() -> str:
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                return json.load(f).get('kaggle_url', '')
        except Exception:
            pass
    return ''

KAGGLE_API_URL = _load_url()

if not KAGGLE_API_URL:
    print("[WARNING] KAGGLE_API_URL not set in config.json — inference will fail")

CWE_INFO = {
    "CWE-125": {"name": "Out-of-bounds Read", "severity": "High"},
    "CWE-787": {"name": "Out-of-bounds Write", "severity": "Critical"},
    "CWE-190": {"name": "Integer Overflow or Wraparound", "severity": "High"},
    "CWE-369": {"name": "Divide By Zero", "severity": "Medium"},
    "CWE-415": {"name": "Double Free", "severity": "High"},
    "CWE-476": {"name": "NULL Pointer Dereference", "severity": "High"},
}


def check_api_health() -> bool:
    """Quick health check for the ML notebook."""
    if not KAGGLE_API_URL:
        return False
    try:
        r = requests.get(f"{KAGGLE_API_URL}", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def analyze_function(code: str) -> dict:
    """
    Run a single function through the ML model.
    Returns dict ready to be saved to SQLite.
    """
    if not KAGGLE_API_URL:
        return {"error": "Kaggle API URL not configured (check config.json)"}

    try:
        response = requests.post(
            f"{KAGGLE_API_URL}/predict",
            json={"code": code},
            timeout=30
        )
        response.raise_for_status()
        data = response.json()

        # Debug print (helpful during testing)
        print(f"[DEBUG] ML API response: {data}")

        result = data.get("result", {})
        output = result.get("output") if isinstance(result, dict) else result
        confidence = result.get("confidence") if isinstance(result, dict) else data.get("confidence")

        # Ensure confidence is always a number
        if isinstance(confidence, dict):
            confidence = confidence.get("value") or confidence.get("output") or 0.0
        if confidence is not None:
            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                confidence = 0.0

        # Safe code
        if isinstance(output, str) and output.lower() in ("code is safe", "safe", "SAFE"):
            return {
                "verdict": "safe",
                "cwe": None,
                "cwe_name": None,
                "severity": None,
                "confidence": confidence,
            }

        # Vulnerable: output is list like ["CWE-787"]
        cwe_list = output if isinstance(output, list) else [output] if output else []
        cwe = cwe_list[0] if cwe_list else None

        if not cwe or cwe.lower() in ("code is safe", "safe", "SAFE"):
            return {
                "verdict": "safe",
                "cwe": None,
                "cwe_name": None,
                "severity": None,
                "confidence": confidence,
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
        return {"error": "Cannot reach Kaggle API. Is the notebook running and ngrok active?"}
    except requests.exceptions.Timeout:
        return {"error": "Kaggle API timed out."}
    except Exception as e:
        return {"error": f"ML inference failed: {str(e)}"}


# Global singleton
client = None  # not needed anymore — we use standalone functions now