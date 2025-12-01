import requests
import json
import time

BASE_URL = "http://localhost:5000"

def test_endpoint(name, method, endpoint, data=None):
    print(f"\n{'='*60}")
    print(f"Testing: {name}")
    print(f"{'='*60}")
    
    try:
        if method == "GET":
            response = requests.get(f"{BASE_URL}{endpoint}", timeout=5)
        else:
            response = requests.post(f"{BASE_URL}{endpoint}", json=data, timeout=5)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(json.dumps(result, indent=2)[:800])
        else:
            print(f"Error: {response.text}")

    except Exception as e:
        print(f"Exception: {str(e)}")

print("\n🚀 Starting SecureZone Advanced API Tests\n")

test_endpoint("System Status", "GET", "/api/status")
time.sleep(1)

test_endpoint("Quick Scan", "POST", "/api/run_scan", {"scan_type": "quick"})
time.sleep(1)

test_endpoint("Get Alerts", "GET", "/api/alerts")
time.sleep(1)

test_endpoint("Advanced Metrics", "GET", "/api/advanced_metrics")
time.sleep(1)

test_endpoint("Detection Layers", "GET", "/api/detection_layers")
time.sleep(1)

test_endpoint("Network Topology", "GET", "/api/network")
time.sleep(1)

test_endpoint("Deep Scan", "POST", "/api/run_scan", {"scan_type": "deep"})

print("\n✅ All tests completed!")
