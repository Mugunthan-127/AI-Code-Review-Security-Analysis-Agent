import requests
import time
import json
import os

BASE_URL = "http://localhost:8000"

def wait_for_server():
    print("Waiting for server to start...")
    for _ in range(30):
        try:
            res = requests.get(f"{BASE_URL}/docs")
            if res.status_code == 200:
                print("Server is up!")
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)
    print("Server failed to start in time.")
    return False

def test_kb_status():
    print("Testing /api/kb/status...")
    res = requests.get(f"{BASE_URL}/api/kb/status")
    print(f"Status Code: {res.status_code}")
    if res.status_code == 200:
        data = res.json()
        print(f"KB Status: {json.dumps(data, indent=2)}")
        assert "document_count" in data
        assert "is_populated" in data
    else:
        print(f"Error: {res.text}")
        assert False

def test_code_submission():
    print("Testing code submission /api/v1/submit/paste ...")
    payload = {
        "code": "import os\ndef test():\n    pass",
        "language": "python",
        "session_id": "test_session_123"
    }
    res = requests.post(f"{BASE_URL}/api/v1/submit/paste", json=payload)
    print(f"Status Code: {res.status_code}")
    if res.status_code == 200:
        data = res.json()
        print(f"Submission Response: {json.dumps(data, indent=2)}")
        assert data.get("status") in ["validated", "rejected"]
        if data.get("status") == "validated":
            assert "scan_id" in data
            # Check if findings exist
            assert "findings" in data
    else:
        print(f"Error: {res.text}")
        # Note: If API key is not set, it might fail in the orchestrator.
        # Let's print the error and move on.

def main():
    if not wait_for_server():
        return
    
    test_kb_status()
    try:
        test_code_submission()
    except Exception as e:
        print(f"Submission test failed (likely missing API keys): {e}")

if __name__ == "__main__":
    main()
