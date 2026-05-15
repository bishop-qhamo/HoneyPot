"""
Configuration management for HoneyPot
"""

import json
from pathlib import Path


class Config:
    """Load and manage configuration"""
    
    DEFAULT_CONFIG = {
        "ports": [
            {"port": 22, "service": "ssh"},
            {"port": 23, "service": "telnet"}
        ],
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
        "suspicious_commands": [
            "cat /etc/passwd",
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
            "perl"
        ],
        "suspicious_ssh_patterns": [
            "root@",
            "admin@",
            "test@"
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
    def suspicious_commands(self):
        return self.data['suspicious_commands']
    
    @property
    def suspicious_ssh_patterns(self):
        return self.data['suspicious_ssh_patterns']
