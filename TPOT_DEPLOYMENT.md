# T-Pot Style Honeypot Deployment Guide

## Overview

This is an advanced honeypot system modeled after T-Pot, featuring:
- **Multi-Protocol Support**: SSH, Telnet, HTTP, FTP, RDP
- **Centralized Logging**: Elasticsearch + Logstash + Kibana stack
- **Real-time Analytics**: Advanced dashboards and threat visualization
- **Docker Containerization**: Easy deployment and scaling
- **Threat Detection**: Pattern-based and heuristic analysis
- **Alert System**: Email and webhook notifications

## Architecture

```
┌─────────────────────────────────────┐
│      Honeypot Services              │
│  ├─ SSH (port 22)                  │
│  ├─ Telnet (port 23)               │
│  ├─ HTTP (port 80)                 │
│  ├─ FTP (port 21)                  │
│  └─ RDP (port 3389)                │
└──────────────┬──────────────────────┘
               │
               ↓
┌─────────────────────────────────────┐
│   Centralized Logging (Logstash)    │
└──────────────┬──────────────────────┘
               │
               ↓
┌─────────────────────────────────────┐
│  Data Store (Elasticsearch)         │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────┐
       ↓                ↓
   Kibana         Dashboard
  (Advanced)      (Custom)
```

## Quick Start with Docker

### Prerequisites
- Docker and Docker Compose installed
- Minimum 4GB RAM
- Minimum 20GB disk space

### Deploy

```bash
# Clone the project
cd "My Projects"

# Build and start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f honeypot
```

### Access Points

| Service | URL/Port |
|---------|----------|
| **Kibana** | http://localhost:5601 |
| **Custom Dashboard** | http://localhost:5000 |
| **Elasticsearch** | http://localhost:9200 |
| **Dashboard Service** | `dashboard` container on port 5000 |

> Docker Compose now runs a dedicated `dashboard` service with access to the shared honeypot database volume.
| **SSH** | localhost:22 |
| **Telnet** | localhost:23 |
| **HTTP** | localhost:80 |
| **FTP** | localhost:21 |
| **RDP** | localhost:3389 |

## Manual Deployment (Non-Docker)

### Install Dependencies

```bash
# Create virtual environment
python -m venv venv

# Activate
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install packages
pip install -r requirements.txt
```

### Install ELK Stack

#### Option 1: Local Installation

```bash
# Elasticsearch
# Download from https://www.elastic.co/downloads/elasticsearch
# Extract and run:
./bin/elasticsearch

# Kibana
# Download from https://www.elastic.co/downloads/kibana
# Extract and run:
./bin/kibana

# Logstash
# Download from https://www.elastic.co/downloads/logstash
# Configure logstash.conf, then run:
./bin/logstash -f logstash.conf
```

#### Option 2: Docker Containers Only

```bash
# Start Elasticsearch
docker run -d --name elasticsearch \
  -e discovery.type=single-node \
  -e xpack.security.enabled=false \
  -p 9200:9200 \
  docker.elastic.co/elasticsearch/elasticsearch:8.5.0

# Start Kibana
docker run -d --name kibana \
  -e ELASTICSEARCH_HOSTS=http://localhost:9200 \
  -p 5601:5601 \
  docker.elastic.co/kibana/kibana:8.5.0

# Start Logstash
docker run -d --name logstash \
  -v $(pwd)/logstash.conf:/usr/share/logstash/pipeline/logstash.conf \
  -e ELASTICSEARCH_HOST=localhost:9200 \
  -p 5000:5000 \
  docker.elastic.co/logstash/logstash:8.5.0
```

### Run Honeypot

```bash
# Using original version
python honeyPot.py

# Using T-Pot version with all protocols
python honeyPot_v2.py
```

## Configuration

### config.json

```json
{
  "ports": [
    {"port": 22, "service": "ssh"},
    {"port": 23, "service": "telnet"},
    {"port": 80, "service": "http"},
    {"port": 21, "service": "ftp"},
    {"port": 3389, "service": "rdp"}
  ],
  "log_file": "logs/honeypot.log",
  "db_path": "honeypot.db",
  "alert_email": {
    "from": "honeypot@example.com",
    "to": "admin@example.com",
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "your-email@gmail.com",
    "password": ""
  },
  "alert_webhook": "https://your-webhook-url.com/honeypot",
  "max_sessions_to_keep": 10000,
  "threat_levels": {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1
  },
  "elasticsearch": {
    "host": "localhost",
    "port": 9200,
    "enabled": true
  },
  "suspicious_commands": [
    "cat /etc/passwd",
    "sudo",
    "rm -rf",
    "wget",
    "curl"
  ]
}
```

If you prefer not to store SMTP credentials in `config.json`, set these environment variables instead:

- `SMTP_USER=your-email@gmail.com`
- `SMTP_PASS=your-gmail-app-password`
- `SMTP_SERVER=smtp.gmail.com`
- `SMTP_PORT=587`
- `SMTP_TLS=true`

## Kibana Setup

### Create Index Pattern

1. Go to http://localhost:5601
2. Click **Menu** → **Stack Management** → **Index Patterns**
3. Click **Create Index Pattern**
4. Pattern: `honeypot-*`
5. Timestamp: `@timestamp`
6. Click **Create Index Pattern**

### Create Dashboard

```bash
# Go to Dashboards → Create Dashboard
# Add visualizations:
# 1. Attack timeline
# 2. Threat level distribution
# 3. Top attacking IPs
# 4. Service breakdown
# 5. Command frequency
```

### Sample Kibana Query

```
source: "honeypot" AND threat_level: >= 3
```

## Monitoring

### View Honeypot Logs

```bash
# Docker
docker-compose logs -f honeypot

# Local
tail -f logs/honeypot.log
```

### Query Elasticsearch

```bash
# Get recent attacks
curl -X GET "http://localhost:9200/honeypot-*/_search?pretty"

# Filter by threat level
curl -X GET "http://localhost:9200/honeypot-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d'{
    "query": {
      "range": {
        "threat_level": {
          "gte": 4
        }
      }
    }
  }'

# Get top attacking IPs
curl -X GET "http://localhost:9200/honeypot-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d'{
    "aggs": {
      "top_ips": {
        "terms": {
          "field": "client_ip"
        }
      }
    }
  }'
```

## Threat Levels

| Level | Name | Description |
|-------|------|-------------|
| 1 | INFO | Normal probing, version scanning |
| 2 | LOW | Suspicious patterns, weak attacks |
| 3 | MEDIUM | SQL injection, command injection |
| 4 | HIGH | Privilege escalation, exploit attempts |
| 5 | CRITICAL | Shellcode, known CVEs, active attacks |

## Performance Tuning

### Elasticsearch

```bash
# Increase heap size (logstash-elasticsearch setup)
export ES_JAVA_OPTS="-Xms2g -Xmx2g"
```

### Logstash

```bash
# Increase workers
bin/logstash -f logstash.conf -w 8
```

### Database

```sql
-- Create indexes for faster queries
CREATE INDEX idx_threat_level ON sessions(threat_level);
CREATE INDEX idx_client_ip_service ON sessions(client_ip, service);
CREATE INDEX idx_timestamp ON sessions(start_time DESC);
```

## Scaling

### Multiple Honeypot Instances

```yaml
# docker-compose.yml
services:
  honeypot-1:
    # ... same config
    environment:
      - INSTANCE_ID=1
    
  honeypot-2:
    # ... same config
    environment:
      - INSTANCE_ID=2
    
  honeypot-3:
    # ... same config
    environment:
      - INSTANCE_ID=3
```

### Load Balancing

Use nginx or HAProxy to distribute traffic:

```nginx
upstream honeypot {
    server honeypot-1:22;
    server honeypot-2:22;
    server honeypot-3:22;
}

server {
    listen 22;
    proxy_pass honeypot;
}
```

## Threat Intelligence Integration

### Setup Threat Feeds

```python
# In threat_detection.py
import requests

class ThreatIntelligence:
    def get_malicious_ips(self):
        # AlienVault OTX API
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        resp = requests.get(url, headers={"X-OTX-API-KEY": "YOUR_KEY"})
        return resp.json()
    
    def check_ip_reputation(self, ip):
        # VirusTotal API
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        resp = requests.get(url, headers={"x-apikey": "YOUR_KEY"})
        return resp.json()
```

## Maintenance

### Cleanup Old Data

```bash
# Remove data older than 30 days
python -c "
from database import Database
db = Database('honeypot.db')
result = db.cleanup_old_data(days=30)
print(f'Deleted: {result}')
"
```

### Backup

```bash
# Backup database
cp honeypot.db honeypot.db.backup

# Backup Elasticsearch
curl -X POST "http://localhost:9200/_snapshot/backup/honeypot_$(date +%Y%m%d)?pretty"
```

## Troubleshooting

### Elasticsearch Connection Failed

```bash
# Check Elasticsearch status
curl http://localhost:9200

# Check Logstash logs
docker-compose logs logstash

# Verify network connectivity
docker network inspect honeypot_network
```

### No Data in Kibana

```bash
# Check index was created
curl http://localhost:9200/_cat/indices

# Force Logstash to process logs
docker-compose restart logstash

# Check log permissions
chmod 644 logs/honeypot.log
```

### High Memory Usage

```bash
# Reduce Elasticsearch heap
docker-compose.yml: set -Xmx1g

# Limit Logstash workers
logstash.conf: -w 2
```

## Security Notes

⚠️ **Important**: Deploy in isolated network environment

- Run on dedicated server or VM
- Use firewall to limit outbound connections
- Monitor database and log file sizes
- Regularly review and clean up old data
- Keep system patched and updated
- Use authentication for Kibana (setup in production)
- Encrypt Elasticsearch traffic (setup X-Pack)

## Next Steps

1. Deploy with Docker Compose
2. Configure threat feeds
3. Set up email/webhook alerts
4. Create custom Kibana dashboards
5. Integrate with SIEM (Splunk, ArcSight)
6. Set up automated response playbooks
7. Monitor metrics and tune performance

## References

- [T-Pot GitHub](https://github.com/telekom-security/tpotce)
- [Elasticsearch Docs](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Kibana Dashboards](https://www.elastic.co/guide/en/kibana/current/dashboard.html)
- [Logstash Filters](https://www.elastic.co/guide/en/logstash/current/filter-plugins.html)
