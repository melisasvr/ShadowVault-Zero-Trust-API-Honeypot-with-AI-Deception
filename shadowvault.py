"""
ShadowVault - Zero-Trust API Honeypot with AI Deception
Educational cybersecurity honeypot for learning attack patterns
"""

from flask import Flask, request, jsonify, send_from_directory 
from datetime import datetime, timedelta
import json
import sqlite3
import hashlib
import secrets
import re
from collections import defaultdict, Counter
import threading
import time
from flask_cors import CORS 
app = Flask(__name__)
CORS(app)  

# ==================== DATABASE SETUP ====================
def init_db():
    conn = sqlite3.connect('shadowvault.db')
    c = conn.cursor()
    
    # Attack logs table
    c.execute('''CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip_address TEXT,
        user_agent TEXT,
        method TEXT,
        endpoint TEXT,
        headers TEXT,
        payload TEXT,
        attack_type TEXT,
        severity TEXT
    )''')
    
    # IOC table
    c.execute('''CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ioc_type TEXT,
        value TEXT,
        confidence REAL,
        attack_pattern TEXT
    )''')
    
    # Session tracking
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        ip_address TEXT,
        created_at TEXT,
        last_seen TEXT,
        request_count INTEGER,
        attack_score REAL
    )''')
    
    conn.commit()
    conn.close()

init_db()

# ==================== DECEPTION DATA ====================
FAKE_ACCOUNTS = [
    {"account_id": "ACC100234567", "balance": 125430.50, "type": "checking"},
    {"account_id": "ACC100234568", "balance": 543210.75, "type": "savings"},
    {"account_id": "ACC100234569", "balance": 89234.25, "type": "investment"}
]

FAKE_USERS = {
    "admin": {"password": "P@ssw0rd123", "role": "admin", "token": None},
    "john.doe": {"password": "Banking2024!", "role": "user", "token": None},
    "jane.smith": {"password": "SecurePass456", "role": "user", "token": None}
}

# ==================== ATTACK DETECTION ====================
class AttackDetector:
    def __init__(self):
        self.patterns = {
            'sql_injection': [
                r"(\bunion\b.*\bselect\b)", r"(\bor\b.*=.*)",
                r"(';|--;|\/\*|\*\/)", r"(\bdrop\b.*\btable\b)",
                r"(\binsert\b.*\binto\b)", r"(\bupdate\b.*\bset\b)"
            ],
            'xss': [
                r"<script[^>]*>.*?</script>", r"javascript:",
                r"onerror\s*=", r"onload\s*="
            ],
            'path_traversal': [
                r"\.\./", r"\.\.\\", r"%2e%2e", r"..%2f"
            ],
            'command_injection': [
                r";\s*(cat|ls|pwd|whoami|id)", r"\|\s*(cat|ls|pwd)",
                r"`.*`", r"\$\(.*\)"
            ],
            'auth_bypass': [
                r"'\s*or\s*'1'\s*=\s*'1", r"admin'\s*--",
                r"'\s*or\s*1\s*=\s*1"
            ]
        }
        
    def detect(self, data):
        detected = []
        data_str = json.dumps(data) if isinstance(data, dict) else str(data)
        
        for attack_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, data_str, re.IGNORECASE):
                    detected.append(attack_type)
                    break
        
        return detected

detector = AttackDetector()

# ==================== SESSION MANAGEMENT ====================
def get_or_create_session(ip):
    conn = sqlite3.connect('shadowvault.db')
    c = conn.cursor()
    
    session_id = hashlib.md5(ip.encode()).hexdigest()
    now = datetime.now().isoformat()
    
    c.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
    session = c.fetchone()
    
    if session:
        c.execute('''UPDATE sessions SET last_seen = ?, request_count = request_count + 1 
                     WHERE session_id = ?''', (now, session_id))
    else:
        c.execute('''INSERT INTO sessions (session_id, ip_address, created_at, last_seen, 
                     request_count, attack_score) VALUES (?, ?, ?, ?, 0, 0.0)''',
                  (session_id, ip, now, now))
    
    conn.commit()
    conn.close()
    return session_id

def update_attack_score(session_id, increment):
    conn = sqlite3.connect('shadowvault.db')
    c = conn.cursor()
    c.execute('UPDATE sessions SET attack_score = attack_score + ? WHERE session_id = ?',
              (increment, session_id))
    conn.commit()
    conn.close()

# ==================== LOGGING ====================
def log_attack(ip, user_agent, method, endpoint, headers, payload, attack_types):
    conn = sqlite3.connect('shadowvault.db')
    c = conn.cursor()
    
    severity = "high" if len(attack_types) > 2 else "medium" if attack_types else "low"
    
    c.execute('''INSERT INTO attack_logs (timestamp, ip_address, user_agent, method, 
                 endpoint, headers, payload, attack_type, severity) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (datetime.now().isoformat(), ip, user_agent, method, endpoint,
               json.dumps(dict(headers)), json.dumps(payload), 
               ','.join(attack_types) if attack_types else 'recon', severity))
    
    conn.commit()
    conn.close()

# ==================== MIDDLEWARE ====================
@app.before_request
def intercept_request():
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    session_id = get_or_create_session(ip)
    
    # Detect attacks in various parts of request
    attack_types = []
    
    # Check URL parameters
    for key, value in request.args.items():
        attack_types.extend(detector.detect(f"{key}={value}"))
    
    # Check JSON payload
    if request.is_json:
        attack_types.extend(detector.detect(request.get_json()))
    
    # Check headers
    attack_types.extend(detector.detect(dict(request.headers)))
    
    # Remove duplicates
    attack_types = list(set(attack_types))
    
    # Log the request
    payload = request.get_json() if request.is_json else request.args.to_dict()
    log_attack(ip, user_agent, request.method, request.path, 
               request.headers, payload, attack_types)
    
    # Update attack score
    if attack_types:
        update_attack_score(session_id, len(attack_types) * 10)

# ==================== FAKE API ENDPOINTS ====================
@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Simulate successful login with weak credentials
    if username in FAKE_USERS:
        # Always return success to deceive attacker
        token = secrets.token_hex(32)
        FAKE_USERS[username]['token'] = token
        
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "token": token,
            "user": {
                "username": username,
                "role": FAKE_USERS[username]['role']
            }
        }), 200
    
    # Even invalid logins get "success" sometimes to confuse attackers
    if secrets.randbelow(3) == 0:
        fake_token = secrets.token_hex(32)
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "token": fake_token,
            "user": {"username": username, "role": "user"}
        }), 200
    
    return jsonify({
        "status": "error",
        "message": "Invalid credentials"
    }), 401

@app.route('/api/v1/accounts', methods=['GET'])
def get_accounts():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    # Accept any token format to keep attacker engaged
    if token:
        return jsonify({
            "status": "success",
            "accounts": FAKE_ACCOUNTS
        }), 200
    
    return jsonify({
        "status": "error",
        "message": "Unauthorized"
    }), 401

@app.route('/api/v1/accounts/<account_id>', methods=['GET'])
def get_account(account_id):
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if token:
        # Return fake account data even for made-up IDs
        account = next((acc for acc in FAKE_ACCOUNTS if acc['account_id'] == account_id), None)
        
        if account:
            return jsonify({
                "status": "success",
                "account": account
            }), 200
        else:
            # Return believable fake data for any account ID
            return jsonify({
                "status": "success",
                "account": {
                    "account_id": account_id,
                    "balance": secrets.randbelow(1000000) / 100,
                    "type": "checking"
                }
            }), 200
    
    return jsonify({"status": "error", "message": "Unauthorized"}), 401

@app.route('/api/v1/transfer', methods=['POST'])
def transfer():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    data = request.get_json() or {}
    
    if token:
        # Log the transfer attempt but always return success
        return jsonify({
            "status": "success",
            "message": "Transfer initiated",
            "transaction_id": f"TXN{secrets.randbelow(1000000):08d}",
            "amount": data.get('amount', 0),
            "from_account": data.get('from_account'),
            "to_account": data.get('to_account')
        }), 200
    
    return jsonify({"status": "error", "message": "Unauthorized"}), 401

@app.route('/api/v1/users', methods=['GET'])
def get_users():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    # Leak "sensitive" data to keep attacker interested
    if token:
        users = [{"username": u, "role": d['role']} for u, d in FAKE_USERS.items()]
        return jsonify({
            "status": "success",
            "users": users
        }), 200
    
    return jsonify({"status": "error", "message": "Unauthorized"}), 401

@app.route('/admin/config', methods=['GET'])
def admin_config():
    # Fake admin endpoint with enticing but fake data
    return jsonify({
        "status": "success",
        "config": {
            "database": "postgresql://admin:P@ssw0rd@localhost:5432/banking",
            "api_key": "sk_live_" + secrets.token_hex(24),
            "debug_mode": True,
            "secret_key": secrets.token_hex(32)
        }
    }), 200

@app.route('/api/v1/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "version": "1.2.3",
        "timestamp": datetime.now().isoformat()
    }), 200

# ==================== IOC GENERATION ====================
def generate_iocs():
    """Analyze attack patterns and generate IOCs"""
    conn = sqlite3.connect('shadowvault.db')
    c = conn.cursor()
    
    # Get recent attacks (last hour)
    one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
    c.execute('''SELECT ip_address, user_agent, attack_type FROM attack_logs 
                 WHERE timestamp > ?''', (one_hour_ago,))
    attacks = c.fetchall()
    
    if not attacks:
        conn.close()
        return
    
    # Analyze patterns
    ip_counts = Counter([a[0] for a in attacks])
    ua_counts = Counter([a[1] for a in attacks])
    attack_patterns = Counter([a[2] for a in attacks if a[2] != 'recon'])
    
    # Generate IOCs for high-frequency IPs
    for ip, count in ip_counts.items():
        if count > 10:  # Threshold
            confidence = min(count / 100.0, 1.0)
            patterns = [a[2] for a in attacks if a[0] == ip and a[2] != 'recon']
            
            c.execute('''INSERT INTO iocs (timestamp, ioc_type, value, confidence, attack_pattern)
                         VALUES (?, ?, ?, ?, ?)''',
                      (datetime.now().isoformat(), 'ip_address', ip, confidence, 
                       ','.join(set(patterns))))
    
    # Generate IOCs for suspicious user agents
    for ua, count in ua_counts.items():
        if count > 5 and ('bot' in ua.lower() or 'scan' in ua.lower()):
            c.execute('''INSERT INTO iocs (timestamp, ioc_type, value, confidence, attack_pattern)
                         VALUES (?, ?, ?, ?, ?)''',
                      (datetime.now().isoformat(), 'user_agent', ua, 0.8, 'automated_scan'))
    
    conn.commit()
    conn.close()

# Background IOC generation
def ioc_generator_thread():
    while True:
        time.sleep(300)  # Every 5 minutes
        try:
            generate_iocs()
        except Exception as e:
            print(f"IOC generation error: {e}")

threading.Thread(target=ioc_generator_thread, daemon=True).start()

# ==================== ANALYTICS ENDPOINTS ====================
@app.route('/honeypot/stats', methods=['GET'])
def get_stats():
    """Get honeypot statistics"""
    conn = sqlite3.connect('shadowvault.db')
    c = conn.cursor()
    
    # Total attacks
    c.execute('SELECT COUNT(*) FROM attack_logs')
    total = c.fetchone()[0]
    
    # Attacks by type
    c.execute('SELECT attack_type, COUNT(*) FROM attack_logs GROUP BY attack_type')
    by_type = dict(c.fetchall())
    
    # Top attackers
    c.execute('''SELECT ip_address, COUNT(*) as cnt FROM attack_logs 
                 GROUP BY ip_address ORDER BY cnt DESC LIMIT 10''')
    top_ips = [{"ip": row[0], "count": row[1]} for row in c.fetchall()]
    
    # Recent attacks
    c.execute('''SELECT timestamp, ip_address, attack_type, endpoint FROM attack_logs 
                 ORDER BY timestamp DESC LIMIT 20''')
    recent = [{"timestamp": r[0], "ip": r[1], "type": r[2], "endpoint": r[3]} 
              for r in c.fetchall()]
    
    conn.close()
    
    return jsonify({
        "total_attacks": total,
        "attacks_by_type": by_type,
        "top_attackers": top_ips,
        "recent_attacks": recent
    }), 200

@app.route('/honeypot/iocs', methods=['GET'])
def get_iocs():
    """Get generated IOCs"""
    conn = sqlite3.connect('shadowvault.db')
    c = conn.cursor()
    
    c.execute('SELECT * FROM iocs ORDER BY timestamp DESC LIMIT 100')
    iocs = [{"timestamp": r[1], "type": r[2], "value": r[3], 
             "confidence": r[4], "pattern": r[5]} for r in c.fetchall()]
    
    conn.close()
    
    return jsonify({"iocs": iocs}), 200

@app.route('/honeypot/export', methods=['GET'])
def export_data():
    """Export all data in STIX format"""
    conn = sqlite3.connect('shadowvault.db')
    c = conn.cursor()
    
    c.execute('SELECT * FROM attack_logs')
    attacks = c.fetchall()
    
    c.execute('SELECT * FROM iocs')
    iocs = c.fetchall()
    
    conn.close()
    
    export = {
        "export_time": datetime.now().isoformat(),
        "attacks": [{"id": a[0], "timestamp": a[1], "ip": a[2], "user_agent": a[3],
                     "method": a[4], "endpoint": a[5], "attack_type": a[7]} 
                    for a in attacks],
        "iocs": [{"timestamp": i[1], "type": i[2], "value": i[3], 
                  "confidence": i[4], "pattern": i[5]} for i in iocs]
    }
    
    return jsonify(export), 200

# ==================== SERVE DASHBOARD ====================  # <--- ADDED
@app.route('/')
def index():
    """Serve the index.html dashboard."""
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve other static files if needed (e.g., CSS, JS)."""
    return send_from_directory('.', path)
# <--- END OF ADDED SECTION

if __name__ == '__main__':
    print("🕵️  ShadowVault Honeypot Starting...")
    print("📊 Dashboard: http://localhost:5000/honeypot/stats")
    print("🎯 IOCs: http://localhost:5000/honeypot/iocs")
    print("📤 Export: http://localhost:5000/honeypot/export")
    print("\n🎭 Fake Banking API Endpoints:")
    print("   POST /api/v1/auth/login")
    print("   GET  /api/v1/accounts")
    print("   GET  /api/v1/accounts/<id>")
    print("   POST /api/v1/transfer")
    print("   GET  /api/v1/users")
    print("   GET  /admin/config")
    
    app.run(host='0.0.0.0', port=5000, debug=False)