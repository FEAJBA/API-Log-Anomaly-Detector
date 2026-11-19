from flask import Flask, jsonify, request
from collections import defaultdict, Counter
from datetime import datetime
import json

app = Flask(__name__)

# In-memory log store
logs = []
alerts = []

# Sample logs to demo
SAMPLE_LOGS = [
    {"ip": "192.168.1.10", "endpoint": "/api/login", "status": 200, "method": "GET"},
    {"ip": "10.0.0.5", "endpoint": "/api/login", "status": 401, "method": "POST"},
    {"ip": "10.0.0.5", "endpoint": "/api/login", "status": 401, "method": "POST"},
    {"ip": "10.0.0.5", "endpoint": "/api/login", "status": 401, "method": "POST"},
    {"ip": "10.0.0.5", "endpoint": "/api/login", "status": 401, "method": "POST"},
    {"ip": "10.0.0.5", "endpoint": "/api/login", "status": 401, "method": "POST"},
    {"ip": "10.0.0.5", "endpoint": "/api/admin", "status": 403, "method": "GET"},
    {"ip": "45.155.204.1", "endpoint": "/api/users", "status": 500, "method": "GET"},
]

def analyze_logs():
    alerts.clear()
    ip_counts = Counter(l['ip'] for l in logs)
    ip_fails = Counter(l['ip'] for l in logs if l['status'] in [401,403])

    for ip, count in ip_counts.items():
        risk = 0
        reasons = []
        if ip_fails[ip] >= 5:
            risk += 70
            reasons.append(f"Brute Force: {ip_fails[ip]} failed logins")
        if count > 20:
            risk += 50
            reasons.append(f"High Rate: {count} requests")
        if any(l['ip']==ip and l['endpoint']=='/api/admin' for l in logs):
            risk += 30
            reasons.append("Admin endpoint probing")
        if risk >= 50:
            alerts.append({
                "ip": ip,
                "risk_score": min(risk, 100),
                "severity": "HIGH" if risk >= 70 else "MEDIUM",
                "reasons": reasons,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "NEW - Needs Investigation"
            })
    return alerts

@app.route('/')
def home():
    return jsonify({"message": "API Log Anomaly Detector Running", "endpoints": ["/logs", "/analyze", "/alerts"]})

@app.route('/logs', methods=['GET','POST'])
def handle_logs():
    if request.method == 'POST':
        data = request.json
        data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logs.append(data)
        return jsonify({"status": "log added", "log": data})
    return jsonify({"total_logs": len(logs), "logs": logs})

@app.route('/analyze')
def analyze():
    result = analyze_logs()
    return jsonify({"total_alerts": len(result), "alerts": result})

@app.route('/alerts')
def get_alerts():
    return jsonify({"alerts": alerts})

@app.route('/load-sample')
def load_sample():
    logs.extend(SAMPLE_LOGS)
    analyze_logs()
    return jsonify({"message": f"Loaded {len(SAMPLE_LOGS)} sample logs", "alerts": alerts})

if __name__ == '__main__':
    print("="*50)
    print("API LOG ANOMALY DETECTOR STARTED")
    print("Dashboard: http://127.0.0.1:5001/alerts")
    print("="*50)
    app.run(port=5001, debug=True)
