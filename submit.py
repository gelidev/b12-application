import os
import json
import hmac
import hashlib
import datetime
import urllib.request
from typing import Dict, Any

SUBMISSION_URL = "https://b12.io/apply/submission"

def iso_utc_now() -> str:
    # ISO 8601 with milliseconds and Z suffix like 2026-01-06T16:59:37.571Z
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.isoformat(timespec="milliseconds").replace("+00:00", "Z")

def canonical_json(payload: dict) -> bytes:
    """
    Requirements:
    - JSON body contains no extra whitespace -> separators=(',', ':')
    - keys sorted alphabetically -> sort_keys=True
    - UTF-8 encoded -> encode('utf-8')
    """
    s = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return s.encode("utf-8")

def generate_signature(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"

def get_config_from_env() -> Dict[str, str]:
    # Extracts and validates environment variables
    run_id = os.environ.get("GITHUB_RUN_ID")
    if not run_id:
        raise RuntimeError("Missing GITHUB_RUN_ID; are you running in GitHub Actions?")

    repo_link = os.environ["REPOSITORY_LINK"]
    
    return {
        "name": os.environ["NAME"],
        "email": os.environ["EMAIL"],
        "resume_link": os.environ["RESUME_LINK"],
        "repository_link": repo_link,
        "action_run_link": f"{repo_link}/actions/runs/{run_id}",
        "signing_secret": os.environ["SIGNING_SECRET"],
    }

def submit_application(url: str, payload: Dict[str, Any], secret: str) -> str:
    # Handles the transmission and signature of the application
    body = canonical_json(payload)
    signature = generate_signature(secret, body)

    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "X-Signature-256": signature,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode("utf-8")
            data = json.loads(resp_body)
            
            if resp.status != 200 or not data.get("receipt"):
                raise RuntimeError(f"Invalid response: {resp.status} - {resp_body}")
            
            return data["receipt"]
            
    except Exception as e:
        # Mask the full signature in logs for security
        print(f"Submission failed. Action Link: {payload.get('action_run_link')}")
        print(f"Signature (masked): {signature[:15]}...")
        raise e

# --- Main Entry Point ---

def main():
    # 1. Configuration
    config = get_config_from_env()

    # 2. Build Payload
    payload = {
        "timestamp": iso_utc_now(),
        "name": config["name"],
        "email": config["email"],
        "resume_link": config["resume_link"],
        "repository_link": config["repository_link"],
        "action_run_link": config["action_run_link"],
    }

    # 3. Execution
    receipt = submit_application(SUBMISSION_URL, payload, config["signing_secret"])
    print(receipt)

if __name__ == "__main__":
    main()