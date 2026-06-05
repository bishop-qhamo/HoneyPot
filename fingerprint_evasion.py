"""
Fingerprint Evasion Module
Makes the honeypot harder to detect by randomizing responses,
timing, and protocol behavior
"""

import random
import string
from datetime import datetime, timedelta


class FingerprintEvasion:
    """Generates realistic, varied responses to avoid detection"""
    
    def __init__(self, config=None):
        """Initialize with optional config for customization"""
        self.config = config
        self.session_personalities = {}
        
        # Real OS/service fingerprints to emulate
        self.os_types = [
            'Linux 5.4.0-42-generic #46-Ubuntu',
            'Linux 4.19.0-13-generic #14-Ubuntu',
            'FreeBSD 12.2-RELEASE',
            'CentOS Linux 7 (Core)',
            'Linux 5.10.0-8-generic #1-Ubuntu'
        ]
        
        self.bash_versions = [
            'GNU bash, version 5.0.17(1)-release',
            'GNU bash, version 4.4.20(1)-release',
            'GNU bash, version 3.2.57(1)-release'
        ]
        
        self.usernames = ['admin', 'root', 'user', 'test', 'oracle', 'postgres', 'www-data']
        self.hostnames = ['localhost', 'server', 'host', 'debian', 'ubuntu', 'centos', 'honeypot']
    
    def get_session_personality(self, session_id):
        """Get or create a consistent personality for a session"""
        if session_id not in self.session_personalities:
            self.session_personalities[session_id] = {
                'os': random.choice(self.os_types),
                'bash_version': random.choice(self.bash_versions),
                'username': random.choice(self.usernames),
                'hostname': random.choice(self.hostnames),
                'shell': random.choice(['bash', 'sh']),
                'pwd': random.choice(['/', '/home/user', '/root', '/opt']),
                'session_start': datetime.now()
            }
        return self.session_personalities[session_id]
    
    def randomize_ssh_banner(self):
        """Return a realistic SSH banner with random variation"""
        banners = [
            'SSH-2.0-OpenSSH_7.4',
            'SSH-2.0-OpenSSH_7.9',
            'SSH-2.0-OpenSSH_8.0',
            'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5',
            'SSH-2.0-OpenSSH_8.6',
            'SSH-2.0-OpenSSH_9.0',
            'SSH-2.0-libssh_0.8.9',
            'SSH-2.0-Paramiko_2.11.0'
        ]
        return random.choice(banners) + '\r\n'
    
    def randomize_telnet_banner(self):
        """Return a realistic Telnet welcome prompt with variation"""
        banners = [
            'Welcome\r\nUsername: ',
            'Login: ',
            'Connected to localhost\r\nEscape character is \'^]\'.\r\n\r\nUsername: ',
            'User Access Verification\r\n\r\nUsername: ',
            'BusyBox v1.35.0\r\nLogin: ',
        ]
        return random.choice(banners)
    
    def randomize_http_banner(self):
        """Return a realistic HTTP Server banner"""
        banners = [
            'Apache/2.4.41 (Ubuntu)',
            'nginx/1.18.0 (Ubuntu)',
            'Microsoft-IIS/10.0',
            'Apache/2.4.29 (Ubuntu)',
            'LiteSpeed',
            'Lighttpd/1.4.53',
            'Apache/2.2.22 (Debian)',
        ]
        return random.choice(banners)
    
    def randomize_ftp_banner(self):
        """Return a realistic FTP banner"""
        banners = [
            '220 (vsFTPd 3.0.3)\r\n',
            '220 ProFTPD 1.3.5 Server ready.\r\n',
            '220 (FileZilla Server 0.9.60 beta)\r\n',
            '220 Welcome to Pure-FTPd [TLS]\r\n',
            '220 BusyBox ftpd ready.\r\n',
        ]
        return random.choice(banners)
    
    def generate_shell_response(self, command, session_id):
        """Generate realistic shell response based on command and session personality"""
        personality = self.get_session_personality(session_id)
        command_lower = command.lower().strip()
        
        if command_lower in ['ls', 'ls -la', 'dir']:
            return self._generate_ls_output(personality)
        elif command_lower == 'whoami':
            return f"{personality['username']}\n"
        elif command_lower == 'hostname':
            return f"{personality['hostname']}\n"
        elif command_lower in ['pwd', 'cd']:
            return f"{personality['pwd']}\n"
        elif command_lower == 'id':
            uid = random.randint(0, 1000)
            gid = random.randint(0, 1000)
            return f"uid={uid}({personality['username']}) gid={gid}(wheel)\n"
        elif command_lower == 'uname -a':
            return f"Linux {personality['hostname']} {personality['os']} x86_64 x86_64 x86_64 GNU/Linux\n"
        elif command_lower in ['bash', '--version']:
            return f"{personality['bash_version']}\n"
        elif command_lower in ['echo $SHELL']:
            return f"/bin/{personality['shell']}\n"
        elif command_lower == 'date':
            return datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y") + "\n"
        elif command_lower in ['help', '?']:
            return self._generate_help_text()
        else:
            # Realistic "command not found" with slight variation
            responses = [
                f"{command}: command not found\n",
                f"-bash: {command}: command not found\n",
                f"bash: {command.split()[0]}: command not found\n",
                f"sh: {command.split()[0]}: not found\n",
            ]
            return random.choice(responses)
    
    def _generate_ls_output(self, personality):
        """Generate realistic ls -la output"""
        files = [
            'total 48',
            'drwxr-xr-x  2 root   root   4096 Jan  1 00:00 .',
            'drwxr-xr-x  3 root   root   4096 Jan  1 00:00 ..',
            f'-rw-r--r--  1 {personality["username"]:8} root    220 Jan  1 00:00 .bashrc',
            '-rw-r--r--  1 root   root    807 Jan  1 00:00 .profile',
            '-rw-r--r--  1 root   root   1234 Jan  1 00:00 README.md',
            'drwxrwxr-x  4 root   root   4096 Jan  1 00:00 .git',
        ]
        return '\n'.join(random.sample(files, random.randint(4, 7))) + '\n'
    
    def _generate_help_text(self):
        """Generate realistic help output"""
        return """Available commands:
  ls, dir         - List directory contents
  pwd             - Print working directory
  cd              - Change directory
  whoami          - Show current user
  id              - Show user and group info
  hostname        - Show hostname
  date            - Show current date/time
  uname           - Show system information
  echo            - Print text
  help, ?         - Show this help
  exit, logout    - Exit the shell
"""
    
    def get_response_delay(self, base_delay_ms=50):
        """Generate realistic response delay with jitter"""
        # Add Gaussian noise around base delay
        jitter = random.gauss(0, base_delay_ms * 0.3)
        delay = base_delay_ms + jitter
        # Occasionally add a longer delay (network latency simulation)
        if random.random() < 0.05:
            delay += random.uniform(100, 500)
        return max(1, delay / 1000.0)  # Convert to seconds, ensure positive
    
    def get_login_delay(self):
        """Simulate realistic login handshake delay"""
        return random.uniform(0.2, 0.8)
    
    def randomize_tcp_options(self):
        """Return TCP stack fingerprint variation (for future use)"""
        # In the future, this could influence response timing
        # and other low-level TCP behavior
        return {
            'mss': random.choice([512, 1024, 1460, 1500]),
            'window_size': random.choice([4096, 8192, 16384, 32768]),
            'ttl': random.choice([64, 128, 255])
        }
    
    def randomize_failed_login_response(self):
        """Return realistic failed login response with variation"""
        responses = [
            'Login incorrect\n',
            'Authentication failed\n',
            'Access denied\n',
            'Invalid credentials\n',
            'Sorry, try again\n',
        ]
        return random.choice(responses)
