# 🕵️ ShadowVault-Zero-Trust API Honeypot with AI Deception

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Status](https://img.shields.io/badge/status-active-success)

- A self-learning honeypot system that mimics real banking APIs, lures attackers, learns their Tactics, Techniques, and Procedures (TTPs), and automatically generates Indicators of Compromise (IOCs) all in pure Python, 100% offline.

> ⚠️ **Educational Purpose Only**: This project is designed for cybersecurity education and research purposes only. Always deploy honeypots in isolated environments.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [API Endpoints](#-api-endpoints)
- [Dashboard](#-dashboard)
- [Attack Detection](#-attack-detection)
- [IOC Generation](#-ioc-generation)
- [Testing](#-testing)
- [Project Structure](#-project-structure)
- [Security Considerations](#-security-considerations)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

### Core Capabilities
- 🎭 **Realistic Deception**: Mimics a fully functional banking API with accounts, transfers, and user management
- 🔍 **Attack Detection**: Detects 5+ attack types, including SQL injection, XSS, path traversal, command injection, and auth bypass
- 🧠 **Self-Learning**: Automatically learns from attack patterns and generates IOCs
- 📊 **Real-Time Dashboard**: Beautiful web-based monitoring interface with live attack statistics
- 🎯 **IOC Generation**: Automatically creates Indicators of Compromise every 5 minutes
- 💾 **Offline Operation**: Works completely offline with SQLite database
- 📈 **Session Tracking**: Monitors attacker behavior and builds attack profiles
- 📤 **Data Export**: Export all data in JSON format for analysis

### Attack Detection Types
1. **SQL Injection** - Detects UNION, OR, DROP TABLE, and other SQL attacks
2. **Cross-Site Scripting (XSS)** - Identifies script tags and JavaScript injection
3. **Path Traversal** - Catches directory traversal attempts
4. **Command Injection** - Detects shell command execution attempts
5. **Authentication Bypass** - Identifies credential bypass attempts

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Client Request                       │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│              Flask Middleware (Interceptor)              │
│  • Request Analysis                                      │
│  • Attack Pattern Detection                              │
│  • Session Management                                    │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                 Attack Detector Engine                   │
│  • Pattern Matching (Regex)                              │
│  • Multi-vector Analysis                                 │
│  • Severity Classification                               │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                  Logging & Storage                       │
│  • SQLite Database                                       │
│  • Attack Logs                                           │
│  • Session Tracking                                      │
│  • IOC Storage                                           │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│             IOC Generator (Background)                   │
│  • Pattern Analysis                                      │
│  • Threat Intelligence                                   │
│  • Confidence Scoring                                    │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                Deceptive API Response                    │
│  • Fake Success Messages                                 │
│  • Believable Data                                       │
│  • Strategic Honeytokens                                 │
└─────────────────────────────────────────────────────────┘
```

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Install Dependencies

```bash
pip install flask flask-cors
```

### Step 2: Download Files
- Save these two files in the same directory:
- `shadowvault.py` - The main Python backend
- `index.html` - The dashboard interface

### Step 3: Verify Installation

```bash
python shadowvault.py
```

You should see:
```
🕵️  ShadowVault Honeypot Starting...
📊 Dashboard: http://localhost:5000/honeypot/stats
🎯 IOCs: http://localhost:5000/honeypot/iocs
📤 Export: http://localhost:5000/honeypot/export
...
```

---

## 💻 Usage

### Starting the Honeypot

```bash
python shadowvault.py
```

- The honeypot will start on `http://localhost:5000`

### Accessing the Dashboard
- Open your web browser and navigate to:
```
http://localhost:5000
```

- The dashboard will automatically connect and display real-time attack data.

### Testing the Honeypot
- Try these example attacks to see the honeypot in action:

#### 1. SQL Injection Test
```bash
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin OR 1=1"}'
```

#### 2. Path Traversal Test
```bash
curl "http://localhost:5000/api/v1/accounts/../../../etc/passwd"
```

#### 3. XSS Attack Test
```bash
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"<script>alert(1)</script>","password":"test"}'
```

#### 4. Command Injection Test
```bash
curl "http://localhost:5000/api/v1/accounts?id=1;ls"
```

---

## 🔌 API Endpoints

### Fake Banking API (Honeypot Endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | Fake login endpoint |
| GET | `/api/v1/accounts` | List all accounts |
| GET | `/api/v1/accounts/<id>` | Get specific account |
| POST | `/api/v1/transfer` | Fake money transfer |
| GET | `/api/v1/users` | List all users |
| GET | `/admin/config` | Fake admin configuration |
| GET | `/api/v1/health` | System health check |

### Analytics & Monitoring API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/honeypot/stats` | Get attack statistics |
| GET | `/honeypot/iocs` | Get generated IOCs |
| GET | `/honeypot/export` | Export all data |

### Example: Login Attempt

**Request:**
```bash
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "P@ssw0rd123"}'
```

**Response:**
```json
{
  "status": "success",
  "message": "Login successful",
  "token": "a1b2c3d4e5f6...",
  "user": {
    "username": "admin",
    "role": "admin"
  }
}
```

---

## 📊 Dashboard
- The web dashboard provides real-time monitoring:

### Features
- **Total Attacks Counter** - Shows cumulative attack count
- **Unique IPs** - Number of unique attackers
- **Generated IOCs** - Automatically created threat indicators
- **Active Sessions** - Currently active attack sessions
- **Attack Type Chart** - Visual breakdown of attack types
- **Top Attackers** - Ranked list of most active IPs
- **Recent Attacks Table** - Live feed of incoming attacks
- **IOC List** - Generated indicators with confidence scores

### Auto-Refresh
- The dashboard automatically refreshes every 5 seconds to show the latest data.

### Export Functionality
- Click the "📥 Export" button to download all honeypot data in JSON format.

---

## 🔍 Attack Detection

### Detection Patterns
- The honeypot uses regex-based pattern matching to detect attacks:

```python
# SQL Injection Patterns
r"(\bunion\b.*\bselect\b)"  # UNION SELECT
r"(';|--;|\/\*|\*\/)"        # Comment markers
r"(\bdrop\b.*\btable\b)"     # DROP TABLE

# XSS Patterns
r"<script[^>]*>.*?</script>" # Script tags
r"javascript:"                # JavaScript protocol
r"onerror\s*="               # Event handlers

# Path Traversal
r"\.\./"                     # Directory traversal
r"%2e%2e"                    # Encoded traversal

# Command Injection
r";\s*(cat|ls|pwd|whoami)"   # Shell commands
r"`.*`"                      # Command substitution
```

### Severity Classification

| Severity | Criteria |
|----------|----------|
| **High** | 3+ attack types in single request |
| **Medium** | 1-2 attack types detected |
| **Low** | No attacks detected (reconnaissance) |

---

## 🎯 IOC Generation

### Automatic IOC Creation
- The honeypot generates IOCs every **5 minutes** based on:
1. **High-Frequency IPs** - IPs with >10 attacks
2. **Suspicious User Agents** - Bots, scanners, crawlers
3. **Attack Patterns** - Repeated attack signatures

### IOC Format

```json
{
  "timestamp": "2025-11-16T13:45:00",
  "type": "ip_address",
  "value": "192.168.1.100",
  "confidence": 0.85,
  "pattern": "sql_injection,xss",
  "severity": "high"
}
```

### Confidence Scoring

- **0.0 - 0.3**: Low confidence (possible false positive)
- **0.4 - 0.7**: Medium confidence
- **0.8 - 1.0**: High confidence (confirmed threat)

---

## 🧪 Testing

### Manual Testing with cURL

```bash
# Test 1: Valid Login
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password" :"P@ssw0rd123"}'

# Test 2: SQL Injection
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''--","password":"anything"}'

# Test 3: Get Accounts (with token)
curl -X GET http://localhost:5000/api/v1/accounts \
  -H "Authorization: Bearer your_token_here"

# Test 4: Check Statistics
curl http://localhost:5000/honeypot/stats
```

### Automated Testing Script

Create a file `test_honeypot.py`:

```python
import requests
import time

BASE_URL = "http://localhost:5000"

attacks = [
    {"username": "admin' OR '1'='1", "password": "test"},
    {"username": "<script>alert(1)</script>", "password": "test"},
    {"username": "admin", "password": "../../../etc/passwd"},
    {"username": "admin; ls", "password": "test"},
]

for i, attack in enumerate(attacks):
    print(f"Attack {i+1}: {attack['username']}")
    response = requests.post(
        f"{BASE_URL}/api/v1/auth/login",
        json=attack
    )
    print(f"Response: {response.status_code}")
    time.sleep(1)

# Check stats
stats = requests.get(f"{BASE_URL}/honeypot/stats").json()
print(f"\nTotal attacks detected: {stats['total_attacks']}")
```

Run with:
```bash
python test_honeypot.py
```

---

## 📁 Project Structure

```
ShadowVault/
│
├── shadowvault.py          # Main Python backend
├── index.html              # Web dashboard
├── shadowvault.db          # SQLite database (auto-created)
├── README.md               # This file
│
└── (Optional)
    ├── test_honeypot.py    # Testing script
    └── requirements.txt    # Dependencies
```

### Database Schema

**attack_logs table:**
```sql
id, timestamp, ip_address, user_agent, method, 
endpoint, headers, payload, attack_type, severity
```

**iocs table:**
```sql
id, timestamp, ioc_type, value, confidence, attack_pattern
```

**sessions table:**
```sql
session_id, ip_address, created_at, last_seen, 
request_count, attack_score
```

---

## 🔒 Security Considerations
### Deployment Best Practices
1. **Isolated Environment**: Deploy in a separate network segment
2. **No Real Data**: Never use actual credentials or real data
3. **Monitoring**: Regularly review attack logs
4. **Legal Compliance**: Ensure compliance with local laws
5. **Access Control**: Restrict dashboard access to authorized users

### What NOT to Do
- ❌ Deploy on production networks
- ❌ Use real credentials
- ❌ Store sensitive information
- ❌ Leave it publicly accessible without proper isolation
- ❌ Use for malicious purposes

### Recommended Setup

```
Internet → Firewall → DMZ → Honeypot
                          ↓
                    Isolated VLAN
                          ↓
                    Monitoring System
```

---

## 📈 Performance

### Resource Usage
- **Memory**: ~50-100 MB
- **CPU**: <5% (idle), ~10-20% (under attack)
- **Storage**: ~10 MB database for 10,000 attacks
- **Network**: Minimal bandwidth

### Scalability
- Tested with up to 1,000 concurrent requests
- Database can handle 100,000+ attack records
- IOC generation scales linearly

---

## 🛠️ Troubleshooting

### Issue: Dashboard shows "Loading..." forever

**Solution:**
```bash
# Check if the server is running
curl http://localhost:5000/honeypot/stats

# Check CORS is enabled
pip install flask-cors
```

### Issue: Database locked error

**Solution:**
```bash
# Stop the server
# Delete the database
rm shadowvault.db
# Restart the server
python shadowvault.py
```

### Issue: Port 5000 already in use

**Solution:**
Edit `shadowvault.py` and change:
```python
app.run(host='0.0.0.0', port=5000)  # Change 5000 to 5001
```

---

## 🤝 Contributing
- Contributions are welcome! Here's how you can help:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Ideas for Contributions
- Add more attack detection patterns
- Improve ML-based detection
- Add geolocation tracking
- Create Docker container
- Add email/Slack alerts
- Implement STIX 2.1 export
- Add more deceptive endpoints

---

## 📜 License
- This project is licensed under the MIT License - see below for details:

```
MIT License

Copyright (c) 2025 ShadowVault Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including, without limitation, the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgments
- Flask framework for the web server
- SQLite for a lightweight database
- The cybersecurity community for attack pattern research
- All contributors and testers

---

## 📞 Contact & Support
- **Issues**: Open an issue on GitHub
- **Documentation**: Check this README
- **Community**: Join discussions

---

## 🎓 Educational Resources
### Learn More About Honeypots
- [SANS Honeypot Guide](https://www.sans.org)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [ATT&CK Framework](https://attack.mitre.org/)

### Related Projects
- Cowrie - SSH/Telnet Honeypot
- T-Pot - Multi-honeypot platform
- Modern Honey Network (MHN)

---

**Made with ❤️ for cybersecurity education**

*Remember: Use responsibly and ethically!*
