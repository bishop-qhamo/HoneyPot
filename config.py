"""
Configuration management for HoneyPot
"""

import json
import os
from pathlib import Path


class Config:
    """Load and manage configuration"""
    
    DEFAULT_CONFIG = {
        "ports": [
            {"port": 22, "service": "ssh"},
            {"port": 23, "service": "telnet"},
            {"port": 80, "service": "http"},
            {"port": 21, "service": "ftp"},
            {"port": 3389, "service": "rdp"}
        ],
        "realistic_response": True,
        "response_delay_ms": {"min": 20, "max": 120},
        "log_file": "honeypot.log",
        "db_path": "honeypot.db",
        "alert_email": None,
        "alert_webhook": None,
        "max_sessions_to_keep": 10000,
        "threat_levels": {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1
        },
        "http_server_banners": [
            "Apache/2.4.41 (Ubuntu)",
            "nginx/1.18.0",
            "Microsoft-IIS/10.0",
            "LiteSpeed"
        ],
        "ftp_server_banners": [
            "220 (vsFTPd 3.0.3)",
            "220 ProFTPD 1.3.5 Server ready.",
            "220 (FileZilla Server 0.9.60 beta)",
            "220 Welcome to Pure-FTPd [TLS]"
        ],
        "ssh_server_banners": [
            "SSH-2.0-OpenSSH_7.4",
            "SSH-2.0-OpenSSH_7.9",
            "SSH-2.0-OpenSSH_8.0",
            "SSH-2.0-OpenSSH_8.6"
        ],
        "telnet_welcome_messages": [
            "Welcome to HoneyPot Telnet Server\r\nUsername: ",
            "Login: ",
            "SSH/Telnet Service Ready\r\nUsername: "
        ],
        "rdp_server_variants": [
            "Microsoft Terminal Services",
            "Windows Remote Desktop Services",
            "RD Connection Broker"
        ],
        "suspicious_commands": [
            "cat /etc/passwd",
            "cat /etc/shadow",
            "sudo",
            "rm -rf",
            "chmod",
            "chown",
            "wget",
            "curl",
            "nc",
            "bash",
            "sh",
            "python",
            "perl",
            "exploit",
            "shellcode",
            "payload",
            "mirai",
            "tsunami"
        ],
        "suspicious_ssh_patterns": [
            "root@",
            "admin@",
            "test@",
            "cve-2018",
            "cve-2019",
            "rce"
        ]
    }
    
    def __init__(self, config_file='config.json'):
        """Load configuration from file or use defaults"""
        self.config_file = config_file
        self.data = self.DEFAULT_CONFIG.copy()
        
        if Path(config_file).exists():
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                self.data.update(user_config)

        # Allow environment overrides for container deployments
        env_map = {
            'DB_PATH': 'db_path',
            'LOG_FILE': 'log_file',
            'ALERT_EMAIL': 'alert_email',
            'ALERT_WEBHOOK': 'alert_webhook'
        }
        for env_key, config_key in env_map.items():
            env_value = os.environ.get(env_key)
            if env_value is not None:
                self.data[config_key] = env_value
    
    def save(self):
        """Save current configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    @property
    def ports(self):
        return self.data['ports']
    
    @property
    def log_file(self):
        return self.data['log_file']
    
    @property
    def db_path(self):
        return self.data['db_path']
    
    @property
    def alert_email(self):
        return self.data.get('alert_email')
    
    @property
    def alert_webhook(self):
        return self.data.get('alert_webhook')
    
    @property
    def realistic_response(self):
        return bool(self.data.get('realistic_response', True))
    
    @property
    def response_delay_ms(self):
        return self.data.get('response_delay_ms', {"min": 20, "max": 120})
    
    @property
    def http_server_banners(self):
        return self.data.get('http_server_banners', [])
    
    @property
    def ftp_server_banners(self):
        return self.data.get('ftp_server_banners', [])
    
    @property
    def rdp_server_variants(self):
        return self.data.get('rdp_server_variants', [])
    
    @property
    def ssh_server_banners(self):
        return self.data.get('ssh_server_banners', [])
    
    @property
    def telnet_welcome_messages(self):
        return self.data.get('telnet_welcome_messages', [])
    
    @property
    def suspicious_commands(self):
        return self.data['suspicious_commands']
    
    @property
    def suspicious_ssh_patterns(self):
        return self.data['suspicious_ssh_patterns']
    
    @property
    def max_sessions_to_keep(self):
        return int(self.data.get('max_sessions_to_keep', 10000))
