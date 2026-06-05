"""
Threat detection and analysis
Identifies suspicious patterns and behaviors
"""

import re
from typing import Dict, Optional


class ThreatDetector:
    """Analyzes data for security threats"""
    
    # Default suspicious command patterns
    DEFAULT_SUSPICIOUS_COMMANDS = [
        r'cat\s+/etc/(passwd|shadow)',
        r'sudo\s+',
        r'rm\s+-rf',
        r'chmod\s+',
        r'chown\s+',
        r'wget\s+',
        r'curl\s+',
        r'nc\s+',
        r'bash\s+',
        r'sh\s+',
        r'python\s+',
        r'perl\s+',
        r'dd\s+',
        r'mkfs\s+',
        r'mount\s+',
        r'iptables\s+',
        r'ssh-keygen\s+',
    ]
    
    # Default SSH suspicious patterns
    DEFAULT_SSH_SUSPICIOUS_PATTERNS = [
        r'root@',
        r'admin@',
        r'test@',
        r'SSH.*version.*OpenSSH',
    ]
    
    # Brute force detection
    BRUTE_FORCE_THRESHOLD = 5  # Failed attempts before flagging
    
    def __init__(self, config=None):
        """Initialize threat detector"""
        self.config = config
        
        command_patterns = self.DEFAULT_SUSPICIOUS_COMMANDS
        ssh_patterns = self.DEFAULT_SSH_SUSPICIOUS_PATTERNS
        
        if self.config is not None:
            if isinstance(getattr(self.config, 'suspicious_commands', None), list):
                command_patterns = self.config.suspicious_commands
            if isinstance(getattr(self.config, 'suspicious_ssh_patterns', None), list):
                ssh_patterns = self.config.suspicious_ssh_patterns
        
        self.compiled_commands = [re.compile(pattern, re.IGNORECASE) for pattern in command_patterns]
        self.compiled_ssh = [re.compile(pattern, re.IGNORECASE) for pattern in ssh_patterns]
        self.failed_attempts = {}  # Track failed attempts per IP
    
    def analyze_command(self, command: str) -> int:
        """
        Analyze command for threats
        Returns threat level 0-5 (0 = safe, 5 = critical)
        """
        threat_level = 0
        command_lower = command.lower()
        
        for pattern in self.compiled_commands:
            if pattern.search(command_lower):
                threat_level = max(threat_level, 4)
                break
        
        if any(indicator in command_lower for indicator in ['exploit', 'shellcode', 'payload']):
            threat_level = max(threat_level, 5)
        
        if any(path in command_lower for path in ['/etc/shadow', '/etc/passwd', '/root', '/.ssh']):
            threat_level = max(threat_level, 4)
        
        if any(priv in command_lower for priv in ['sudo -i', 'sudo su', 'su -']):
            threat_level = max(threat_level, 4)
        
        if any(bot in command_lower for bot in ['mirai', 'dofloo', 'tsunami']):
            threat_level = max(threat_level, 5)
        
        return threat_level
    
    def analyze_ssh(self, ssh_data: str) -> int:
        """
        Analyze SSH handshake/data for threats
        Returns threat level 0-5
        """
        threat_level = 0
        ssh_data_lower = ssh_data.lower()
        
        for pattern in self.compiled_ssh:
            if pattern.search(ssh_data_lower):
                threat_level = max(threat_level, 2)
                break
        
        if 'openssh' in ssh_data_lower or 'libssh' in ssh_data_lower:
            threat_level = max(threat_level, 1)
        
        if any(exploit in ssh_data_lower for exploit in ['cve-2018', 'cve-2019', 'rce']):
            threat_level = max(threat_level, 4)
        
        return threat_level
    
    def analyze_payload(self, data: bytes) -> int:
        """
        Analyze binary payload for threats
        Returns threat level 0-5
        """
        threat_level = 0
        
        if data.startswith(b'\x7fELF'):
            threat_level = max(threat_level, 4)
        
        if data.startswith(b'MZ'):
            threat_level = max(threat_level, 4)
        
        if self._contains_shellcode_pattern(data):
            threat_level = max(threat_level, 4)
        
        return threat_level
    
    def _contains_shellcode_pattern(self, data: bytes) -> bool:
        """Detect common shellcode patterns"""
        shellcode_patterns = [
            b'\xff\xe4',
            b'\x90\x90\x90',
            b'/bin/sh',
            b'/bin/bash',
        ]
        
        for pattern in shellcode_patterns:
            if pattern in data:
                return True
        return False
    
    def check_brute_force(self, client_ip: str, failed: bool = False) -> bool:
        """
        Track and detect brute force attempts
        Returns True if brute force is detected
        """
        if client_ip not in self.failed_attempts:
            self.failed_attempts[client_ip] = 0
        
        if failed:
            self.failed_attempts[client_ip] += 1
        else:
            self.failed_attempts[client_ip] = 0
        
        if self.failed_attempts[client_ip] >= self.BRUTE_FORCE_THRESHOLD:
            return True
        return False
    
    def analyze_http_request(self, method: str, path: str, request_str: str, headers: Optional[Dict[str, str]] = None) -> int:
        """
        Analyze HTTP request for threats
        Returns threat level 0-5
        """
        threat_level = 0
        path_lower = path.lower()
        request_lower = request_str.lower()
        ua = ''
        if headers:
            ua = headers.get('user-agent', '').lower()
        
        sql_indicators = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'exec', 'cast']
        if any(indicator in path_lower for indicator in sql_indicators):
            threat_level = max(threat_level, 3)
        
        if '../' in path_lower or '..\\' in path_lower or '%2e%2e' in path_lower:
            threat_level = max(threat_level, 3)
        
        if any(char in path for char in ['|', ';', '&', '$', '`']):
            threat_level = max(threat_level, 3)
        
        if any(keyword in request_lower for keyword in ['sqlmap', 'nikto', 'acunetix', 'w3af']):
            threat_level = max(threat_level, 4)
        
        if any(method in request_lower for method in ['delete', 'put', 'patch']):
            threat_level = max(threat_level, 1)
        
        if 'sqlmap' in ua or 'nikto' in ua:
            threat_level = max(threat_level, 4)
        
        if 'curl/' in request_lower and 'http' in request_lower:
            threat_level = max(threat_level, 1)
        
        return threat_level
