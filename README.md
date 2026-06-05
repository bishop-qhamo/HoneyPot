# 🍯 Advanced Honeypot System

A comprehensive SSH/Telnet honeypot for detecting and logging attack attempts with real-time threat detection, database storage, alerts, and a web dashboard.

## Features

✅ **Multi-Protocol Support**
- SSH (port 22) and Telnet (port 23) honeypots
- Customizable ports and services

✅ **Threat Detection**
- Real-time command analysis
- Brute force detection
- Exploit pattern recognition
- Payload analysis

✅ **Logging & Storage**
- SQLite database for session tracking
- Complete command logging
- Binary data capture
- Structured logging with rotation

✅ **Alerts & Notifications**
- Email notifications (configurable)
- Webhook support
- Threat level classification
- Alert history and tracking

✅ **Web Dashboard**
- Real-time statistics
- Session browser
- Alert viewer
- Top attacking IPs
- Threat visualization

✅ **Fingerprint Evasion & Detection Avoidance**
- Randomized SSH/Telnet banners (prevent automated scanner fingerprinting)
- Realistic shell command responses with OS-specific behavior
- Session-consistent personality emulation (per-connection OS/user profile)
- Response timing jitter (Gaussian distribution + random spikes)
- Varied login failure messages
- TCP stack option randomization
- Prevents detection by:
  - Shodan/Censys automated scanners
  - Honeypot detection tools (e.g., Nmap, p0f)
  - Signature-based fingerprinting
  - Temporal analysis attacks

## Installation

### 1. Clone and Setup

```bash
# Navigate to project directory
cd "My Projects"

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configuration

Create `config.json`:

```json
{
  "ports": [
    {"port": 22, "service": "ssh"},
    {"port": 23, "service": "telnet"}
  ],
  "log_file": "logs/honeypot.log",
  "db_path": "honeypot.db",
  "alert_email": null,
  "alert_webhook": null,
  "suspicious_commands": [
    "cat /etc/passwd",
    "sudo",
    "rm -rf",
    "wget",
    "curl"
  ],
  "suspicious_ssh_patterns": [
    "root@",
    "admin@"
  ]
}
```

## Usage

### Starting the Honeypot

```bash
python honeyPot.py
```

The honeypot will:
- Start listening on configured ports (default: 22 and 23)
- Log all connection attempts
- Detect and alert on suspicious activity
- Store data in SQLite database

### Starting the Dashboard

In another terminal:

```bash
python dashboard.py
```

Dashboard available at: **http://localhost:5000**

## Project Structure

```
.
├── honeyPot.py              # Main honeypot server
├── fingerprint_evasion.py   # Anti-detection & randomization
├── config.py                # Configuration management
├── database.py              # SQLite database layer
├── logger.py                # Logging system
├── alert_system.py          # Alert notifications
├── threat_detection.py      # Threat analysis engine
├── dashboard.py             # Flask web dashboard
├── dashboard.html           # Web UI
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

## Key Components

### Fingerprint Evasion System

The honeypot includes sophisticated anti-detection capabilities to avoid being identified by automated scanners and fingerprinting tools:

**Behavioral Randomization:**
- Multiple SSH server versions (OpenSSH 7.4, 8.0, 8.2, 9.0, libssh, Paramiko)
- Varied Telnet welcome messages and banners
- Realistic HTTP and FTP server identifications
- Per-connection randomization prevents pattern matching

**Session Personality Emulation:**
- 5+ Linux OS variants plus FreeBSD and CentOS profiles
- Consistent user/hostname per session (within same connection)
- Realistic shell response generation for commands like `ls`, `whoami`, `uname`, `id`
- Failed login messages vary realistically

**Response Timing Jitter:**
- Gaussian-distributed delays (not uniform) for realistic behavior
- 5% chance of unexpected delays (100-500ms spikes) to simulate system load
- Login delays between 0.2-0.8 seconds for authenticity

**Command Response Engine:**
- Adaptive responses based on OS personality (e.g., FreeBSD vs Ubuntu)
- Realistic `ls` output with proper formatting and permissions
- Shell errors for unavailable commands
- Prevents static signature detection

**Integration Details:**
The `FingerprintEvasion` class is instantiated in `HoneyPot.__init__()` and used for:
- Initializing randomized SSH/Telnet banners at startup
- Generating responses via `evasion.generate_shell_response(command, session_id)`
- Applying realistic delays via `evasion.get_response_delay()`
- Emulating failed login attempts with `evasion.randomize_failed_login_response()`

### Threat Detection System

Analyzes threats across multiple dimensions:

| Threat Level | Score | Description |
|:--|--|--|
| **CRITICAL** | 5 | Exploit attempts, shellcode, known CVEs |
| **HIGH** | 4 | Privilege escalation, sensitive file access |
| **MEDIUM** | 3 | SQL injection, command injection attempts |
| **LOW** | 2 | Suspicious patterns, version scanning |
| **INFO** | 1 | Normal probing, information gathering |

### Database Schema

**Sessions Table**
- Connection metadata (IP, port, service)
- Timing information (start/end time, duration)
- Command count and threat level
- Raw data capture

**Commands Table**
- Individual command tracking
- Per-command threat analysis
- Timestamp tracking

**Alerts Table**
- Alert history with threat levels
- Client IP and message
- Status tracking (new/acknowledged)

**Statistics Table**
- Metrics and trends
- Performance tracking

### Web Dashboard Features

- **Real-time Stats**: Total sessions, unique IPs, active alerts
- **Session Browser**: View all attack sessions with details
- **Alert Viewer**: Track security alerts by threat level
- **Top IPs**: Identify most active attackers
- **Live Updates**: Auto-refresh every 30 seconds

## Configuration Options

### Email Alerts

```json
{
  "alert_email": {
    "from": "honeypot@example.com",
    "to": "admin@example.com",
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "your-email",
    "password": "your-password"
  }
}
```

### Webhook Integration

```json
{
  "alert_webhook": "https://your-webhook-url.com/honeypot"
}
```

Webhook will receive JSON payload:
```json
{
  "timestamp": "2024-01-15T10:30:45.123456",
  "message": "Suspicious command from 192.168.1.100: cat /etc/passwd",
  "threat_level": 4,
  "level_name": "HIGH",
  "client_ip": "192.168.1.100"
}
```

## Monitoring Commands

### View Recent Logs

```bash
tail -f logs/honeypot.log
```

### Query Database

```bash
sqlite3 honeypot.db

# List all sessions
SELECT client_ip, service, COUNT(*) FROM sessions GROUP BY client_ip, service;

# Get alert count by threat level
SELECT threat_level, COUNT(*) FROM alerts GROUP BY threat_level;

# Find commands from specific IP
SELECT command FROM commands c 
JOIN sessions s ON c.session_id = s.id 
WHERE s.client_ip = '192.168.x.x';
```

## Advanced Usage

### Custom Threat Patterns

Edit `threat_detection.py` to add custom patterns:

```python
SUSPICIOUS_COMMANDS = [
    r'custom_malware_signature',
    r'known_exploit_pattern'
]
```

### Port Forwarding (for production)

```bash
# SSH port 22
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Telnet port 23
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323
```

### Running as Service (systemd)

Create `/etc/systemd/system/honeypot.service`:

```ini
[Unit]
Description=HoneyPot Security System
After=network.target

[Service]
Type=simple
User=honeypot
WorkingDirectory=/opt/honeypot
ExecStart=/usr/bin/python3 /opt/honeypot/honeyPot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Start service:
```bash
sudo systemctl enable honeypot
sudo systemctl start honeypot
```

## Security Considerations

⚠️ **Important**: Deploy honeypot in isolated network environment

- Run on dedicated server or VM
- Use firewall rules to limit outbound connections
- Monitor database and log file sizes
- Regularly review and clean up old data
- Keep system patched and updated

## Troubleshooting

### Port Already in Use

```bash
# Linux/Mac - find process on port
lsof -i :22
lsof -i :23

# Windows - find process on port
netstat -ano | findstr :22
```

### Permission Denied

On Linux, listening on ports < 1024 requires root:
```bash
sudo python honeyPot.py
```

Or use higher ports and forward traffic:
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

### Database Locked

SQLite locks during write operations. If encountering locks:
```bash
# Remove database and restart
rm honeypot.db
python honeyPot.py
```

## Performance Tuning

### High Connection Load

Adjust thread pool and timeouts in `honeyPot.py`:

```python
client_sock.settimeout(5)  # Reduce timeout
server.listen(10)          # Increase backlog
```

### Database Optimization

Add indexes for frequent queries:

```sql
CREATE INDEX idx_client_threat ON sessions(client_ip, threat_level);
CREATE INDEX idx_command_analysis ON commands(command, threat_level);
```

## Metrics & Logging

Dashboard provides real-time metrics:

- Sessions per hour/day
- Threat distribution
- Most targeted services
- Top attacking countries (with GeoIP)
- Command frequency analysis

## API Endpoints

Dashboard exposes REST API:

```
GET  /api/sessions           - List sessions (paginated)
GET  /api/sessions/<id>      - Session details
GET  /api/alerts             - List alerts (paginated)
GET  /api/stats              - Current statistics
GET  /api/top-ips            - Top attacking IPs
GET  /api/search?q=IP        - Search by IP address
GET  /api/health             - Health check
```

## Contributing & Extending

The modular design allows easy extensions:

1. **Add new service**: Extend `HoneyPot._handle_<service>()` method
2. **Custom detection**: Add patterns to `ThreatDetector` class
3. **New alerts**: Implement in `AlertSystem` class
4. **Dashboard features**: Add endpoints to `Dashboard` class

## License

MIT License - See LICENSE file for details

## Author

HoneyPot Security Team

---

**Happy Monitoring! 🍯** 🛡️
