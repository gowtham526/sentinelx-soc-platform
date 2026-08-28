import time
import requests
import statistics
import threading
import json

TARGET_URL = "http://127.0.0.1:5000"
CONCURRENT_USERS = 100
DURATION_SECONDS = 60  # 1 minute continuous load
TEST_ENDPOINTS = [
    ("/", "GET", None),
    ("/api/version", "GET", None),
    ("/api/system/health", "GET", None),
    ("/api/metrics", "GET", None),
    ("/api/auth/login", "POST", {"username": "analyst", "password": "analyst123"}),
]

latencies = []
errors = 0
total_requests = 0
lock = threading.Lock()
stop_flag = False

def worker_thread(user_id):
    global errors, total_requests
    session = requests.Session()
    token = None
    
    while not stop_flag:
        for path, method, payload in TEST_ENDPOINTS:
            if stop_flag:
                break
            url = f"{TARGET_URL}{path}"
            headers = {}
            if token and path != "/api/auth/login":
                headers["Authorization"] = f"Bearer {token}"
                
            start_t = time.perf_counter()
            try:
                if method == "GET":
                    r = session.get(url, headers=headers, timeout=5)
                else:
                    r = session.post(url, json=payload, headers=headers, timeout=5)
                    if path == "/api/auth/login" and r.status_code == 200:
                        token = r.json().get("token")
                        
                latency_ms = (time.perf_counter() - start_t) * 1000.0
                
                with lock:
                    latencies.append(latency_ms)
                    total_requests += 1
                    if r.status_code >= 500:
                        errors += 1
            except Exception:
                with lock:
                    errors += 1
                    total_requests += 1
            time.sleep(0.05)  # slight throttle between requests per user

def run_benchmark():
    global stop_flag
    print("=" * 60)
    print(f"🚀 Launching SentinelX Baseline Load Test: {CONCURRENT_USERS} Concurrent Users for {DURATION_SECONDS}s")
    print("=" * 60)
    
    threads = []
    start_time = time.time()
    
    for i in range(CONCURRENT_USERS):
        t = threading.Thread(target=worker_thread, args=(i,), daemon=True)
        t.start()
        threads.append(t)
        
    time.sleep(DURATION_SECONDS)
    stop_flag = True
    
    for t in threads:
        t.join(timeout=1.0)
        
    actual_duration = time.time() - start_time
    rps = total_requests / actual_duration if actual_duration > 0 else 0
    
    avg_lat = statistics.mean(latencies) if latencies else 0
    min_lat = min(latencies) if latencies else 0
    max_lat = max(latencies) if latencies else 0
    p95_lat = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else avg_lat
    
    print("\n" + "=" * 60)
    print("📊 BENCHMARK LOAD TEST RESULTS")
    print("=" * 60)
    print(f"  Total Requests Processed : {total_requests:,}")
    print(f"  Duration                 : {actual_duration:.2f} seconds")
    print(f"  Throughput (RPS)         : {rps:.2f} req/sec")
    print(f"  Failed Requests          : {errors} ({(errors/total_requests*100) if total_requests else 0:.2f}%)")
    print("-" * 60)
    print(f"  Average Latency          : {avg_lat:.2f} ms")
    print(f"  Min Latency              : {min_lat:.2f} ms")
    print(f"  Max Latency              : {max_lat:.2f} ms")
    print(f"  95th Percentile (p95)    : {p95_lat:.2f} ms")
    print("=" * 60)
    
    # Save results to JSON and update markdown
    results = {
        "concurrent_users": CONCURRENT_USERS,
        "duration_seconds": actual_duration,
        "total_requests": total_requests,
        "rps": round(rps, 2),
        "avg_latency_ms": round(avg_lat, 2),
        "min_latency_ms": round(min_lat, 2),
        "max_latency_ms": round(max_lat, 2),
        "p95_latency_ms": round(p95_lat, 2),
        "error_rate_percent": round((errors/total_requests*100) if total_requests else 0, 2)
    }
    with open("Vulnerability Test Results/load_test_results.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    run_benchmark()
