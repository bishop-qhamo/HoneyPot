#!/usr/bin/env python3
"""
Abstract Protocol Handler Framework
Enables pluggable, scalable multi-protocol honeypot support
"""

from abc import ABC, abstractmethod
import socket
import time
import logging
from typing import Dict, Any, Optional


class ProtocolHandler(ABC):
    """
    Base class for all protocol handlers.
    Subclass this to implement support for any service/protocol.
    """
    
    # Override these in subclasses
    PROTOCOL_NAME = "Unknown"
    DEFAULT_PORT = 0
    DEFAULT_BANNER = ""
    PROTOCOL_FAMILY = socket.AF_INET
    SOCKET_TYPE = socket.SOCK_STREAM
    
    def __init__(self, config: Any, threat_detector: Any, evasion: Any, logger: Any = None):
        """
        Initialize protocol handler
        
        Args:
            config: Config object with honeypot settings
            threat_detector: ThreatDetector instance for analysis
            evasion: FingerprintEvasion instance for anti-detection
            logger: Optional logger instance
        """
        self.config = config
        self.threat_detector = threat_detector
        self.evasion = evasion
        self.logger = logger or logging.getLogger(self.PROTOCOL_NAME)
        self.session_data = {}
    
    @abstractmethod
    def handle_connection(self, client_socket: socket.socket, session_data: Dict[str, Any]) -> None:
        """
        Handle incoming connection for this protocol.
        
        Args:
            client_socket: Connected socket from client
            session_data: Session metadata dict with:
                - connection_id: Unique connection identifier
                - client_ip: Client IP address
                - client_port: Client port
                - start_time: Connection start datetime
                - service: Service name (e.g., 'ssh', 'telnet')
                - raw_data: Binary data buffer
                - commands: List of parsed commands
                - threat_level: Current max threat level
        """
        pass
    
    @abstractmethod
    def get_banner(self) -> str:
        """Get initial protocol banner with randomization via evasion module"""
        pass
    
    def send_data(self, sock: socket.socket, data: str, encode: bool = True) -> bool:
        """
        Send data to client with error handling
        
        Args:
            sock: Socket to send on
            data: String or bytes to send
            encode: Convert str to bytes if True
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if encode and isinstance(data, str):
                sock.send(data.encode('utf-8', errors='ignore'))
            else:
                sock.send(data if isinstance(data, bytes) else data.encode())
            return True
        except Exception as e:
            self.logger.error(f"Send error: {e}")
            return False
    
    def recv_data(self, sock: socket.socket, bufsize: int = 1024, timeout: int = 10) -> Optional[str]:
        """
        Receive data from client with error handling
        
        Args:
            sock: Socket to receive from
            bufsize: Buffer size in bytes
            timeout: Socket timeout in seconds
            
        Returns:
            Decoded string data or None on error
        """
        try:
            sock.settimeout(timeout)
            data = sock.recv(bufsize)
            if not data:
                return None
            return data.decode('utf-8', errors='ignore')
        except socket.timeout:
            return None
        except Exception as e:
            self.logger.error(f"Recv error: {e}")
            return None
    
    def apply_response_delay(self, delay_ms: int = 50) -> None:
        """Apply realistic response delay using evasion jitter"""
        if self.evasion:
            delay = self.evasion.get_response_delay(delay_ms)
            time.sleep(delay)
        else:
            time.sleep(delay_ms / 1000.0)
    
    def log_command(self, session_data: Dict[str, Any], command: str, threat_level: int = 0) -> None:
        """Log command to session and threat detector"""
        session_data['commands'].append({
            'command': command,
            'threat_level': threat_level,
            'timestamp': time.time()
        })
        session_data['threat_level'] = max(session_data.get('threat_level', 0), threat_level)
        
        if threat_level > 0:
            self.logger.warning(f"[{session_data['connection_id']}] Threat detected: {command} (Level {threat_level})")
        else:
            self.logger.info(f"[{session_data['connection_id']}] Command: {command}")
    
    def analyze_payload(self, data: str) -> int:
        """Analyze received data for threats and return threat level"""
        if not self.threat_detector:
            return 0
        
        # Try different analysis methods based on content
        threat_level = 0
        
        # Analyze as command
        if len(data) < 256:
            threat_level = max(threat_level, self.threat_detector.analyze_command(data))
        
        # Analyze as HTTP if applicable
        if data.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ')):
            threat_level = max(threat_level, self.threat_detector.analyze_http_request(data))
        
        # Analyze as payload/shellcode
        threat_level = max(threat_level, self.threat_detector.analyze_payload(data))
        
        return threat_level
    
    def get_protocol_response(self, command: str, session_id: str) -> str:
        """
        Get a protocol-appropriate response to a command.
        Can use evasion module for realistic responses.
        
        Args:
            command: Command/input from client
            session_id: Session ID for personality consistency
            
        Returns:
            Response string
        """
        if self.evasion:
            return self.evasion.generate_shell_response(command, session_id)
        return f"{command}: command not found\n"


# ==================== Common Protocol Handlers ====================


class SSHHandler(ProtocolHandler):
    """SSH Protocol Handler (Port 22)"""
    PROTOCOL_NAME = "SSH"
    DEFAULT_PORT = 22
    PROTOCOL_FAMILY = socket.AF_INET
    
    def get_banner(self) -> str:
        if self.evasion:
            return self.evasion.randomize_ssh_banner()
        return "SSH-2.0-OpenSSH_7.4\r\n"
    
    def handle_connection(self, client_socket: socket.socket, session_data: Dict[str, Any]) -> None:
        """Basic SSH honeypot behavior"""
        self.apply_response_delay(100)
        
        try:
            banner = self.get_banner()
            self.send_data(client_socket, banner)
            self.log_command(session_data, "SSH_BANNER_SENT")
            
            # Wait for client identification
            client_id = self.recv_data(client_socket, timeout=5)
            if client_id:
                session_data['raw_data'] += client_id.encode() if isinstance(client_id, str) else client_id
                threat = self.analyze_payload(client_id)
                self.log_command(session_data, f"SSH_CLIENT: {client_id[:50]}", threat)
            
            # Simulate key exchange timeout
            time.sleep(0.5)
            
        except Exception as e:
            self.logger.error(f"SSH handler error: {e}")


class TelnetHandler(ProtocolHandler):
    """Telnet Protocol Handler (Port 23)"""
    PROTOCOL_NAME = "Telnet"
    DEFAULT_PORT = 23
    
    def get_banner(self) -> str:
        if self.evasion:
            return self.evasion.randomize_telnet_banner()
        return "Welcome\r\nUsername: "
    
    def handle_connection(self, client_socket: socket.socket, session_data: Dict[str, Any]) -> None:
        """Telnet honeypot with login simulation"""
        self.apply_response_delay(50)
        
        try:
            banner = self.get_banner()
            self.send_data(client_socket, banner)
            
            username_input = self.recv_data(client_socket, timeout=10)
            if not username_input:
                return
            
            username = username_input.strip()
            session_data['raw_data'] += username_input.encode()
            threat = self.analyze_payload(username)
            self.log_command(session_data, f"TELNET_USERNAME: {username}", threat)
            
            # Request password
            self.apply_response_delay(50)
            self.send_data(client_socket, "Password: ")
            
            password_input = self.recv_data(client_socket, timeout=10)
            if not password_input:
                return
            
            session_data['raw_data'] += password_input.encode()
            
            # Simple authentication simulation
            if username.lower() in ['admin', 'root', 'user'] and password_input.strip().lower() in ['admin', 'password', '1234']:
                self.send_data(client_socket, "Login successful\r\n$ ")
                authenticated = True
            else:
                if self.evasion:
                    fail_msg = self.evasion.randomize_failed_login_response()
                else:
                    fail_msg = "Login incorrect\r\n"
                self.send_data(client_socket, fail_msg + "Username: ")
                authenticated = False
                threat = self.analyze_payload(f"{username}:{password_input}")
                self.log_command(session_data, f"TELNET_AUTH_FAIL: {username}", max(threat, 1))
            
            # Command shell simulation
            while authenticated:
                command_input = self.recv_data(client_socket, timeout=10)
                if not command_input:
                    break
                
                command = command_input.strip()
                session_data['raw_data'] += command_input.encode()
                
                if not command:
                    self.send_data(client_socket, "$ ")
                    continue
                
                threat = self.analyze_payload(command)
                self.log_command(session_data, command, threat)
                
                # Generate response
                response = self.get_protocol_response(command, session_data['connection_id'])
                self.apply_response_delay(75)
                self.send_data(client_socket, response + "\r\n$ ")
                
                if command.lower() in ['exit', 'logout', 'quit']:
                    break
        
        except Exception as e:
            self.logger.error(f"Telnet handler error: {e}")


class HTTPHandler(ProtocolHandler):
    """HTTP Protocol Handler (Port 80)"""
    PROTOCOL_NAME = "HTTP"
    DEFAULT_PORT = 80
    
    def get_banner(self) -> str:
        if self.evasion:
            return self.evasion.randomize_http_banner()
        return "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n"
    
    def handle_connection(self, client_socket: socket.socket, session_data: Dict[str, Any]) -> None:
        """HTTP honeypot with simple response"""
        try:
            request = self.recv_data(client_socket, bufsize=4096, timeout=5)
            if not request:
                return
            
            session_data['raw_data'] += request.encode()
            
            # Parse request line
            lines = request.split('\r\n')
            if lines:
                request_line = lines[0]
                self.log_command(session_data, request_line)
                
                threat = self.analyze_payload(request)
                self.log_command(session_data, f"HTTP_REQUEST: {request_line[:100]}", threat)
                
                # Send response
                self.apply_response_delay(50)
                response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome</body></html>"
                self.send_data(client_socket, response)
        
        except Exception as e:
            self.logger.error(f"HTTP handler error: {e}")


class DNSHandler(ProtocolHandler):
    """DNS Protocol Handler (Port 53, UDP)"""
    PROTOCOL_NAME = "DNS"
    DEFAULT_PORT = 53
    SOCKET_TYPE = socket.SOCK_DGRAM
    
    def get_banner(self) -> str:
        return ""
    
    def handle_connection(self, client_socket: socket.socket, session_data: Dict[str, Any]) -> None:
        """DNS honeypot - UDP based, responses to DNS queries"""
        try:
            # DNS is typically UDP, would need different handling
            # This is a placeholder for future implementation
            self.log_command(session_data, "DNS_QUERY_RECEIVED")
        except Exception as e:
            self.logger.error(f"DNS handler error: {e}")


class SMTPHandler(ProtocolHandler):
    """SMTP Protocol Handler (Port 25)"""
    PROTOCOL_NAME = "SMTP"
    DEFAULT_PORT = 25
    
    def get_banner(self) -> str:
        return "220 mail.example.com ESMTP Service Ready\r\n"
    
    def handle_connection(self, client_socket: socket.socket, session_data: Dict[str, Any]) -> None:
        """SMTP honeypot with basic command handling"""
        try:
            self.apply_response_delay(50)
            self.send_data(client_socket, self.get_banner())
            
            while True:
                command = self.recv_data(client_socket, timeout=30)
                if not command:
                    break
                
                command = command.strip()
                session_data['raw_data'] += command.encode()
                
                threat = self.analyze_payload(command)
                self.log_command(session_data, f"SMTP: {command[:100]}", threat)
                
                cmd_upper = command.upper()
                self.apply_response_delay(50)
                
                if cmd_upper.startswith('HELO') or cmd_upper.startswith('EHLO'):
                    self.send_data(client_socket, "250 OK\r\n")
                elif cmd_upper.startswith('MAIL FROM'):
                    self.send_data(client_socket, "250 OK\r\n")
                elif cmd_upper.startswith('RCPT TO'):
                    self.send_data(client_socket, "250 OK\r\n")
                elif cmd_upper.startswith('DATA'):
                    self.send_data(client_socket, "354 End data with <CR><LF>.<CR><LF>\r\n")
                elif cmd_upper.startswith('QUIT'):
                    self.send_data(client_socket, "221 Goodbye\r\n")
                    break
                else:
                    self.send_data(client_socket, "500 Unknown command\r\n")
        
        except Exception as e:
            self.logger.error(f"SMTP handler error: {e}")


class MySQLHandler(ProtocolHandler):
    """MySQL Protocol Handler (Port 3306)"""
    PROTOCOL_NAME = "MySQL"
    DEFAULT_PORT = 3306
    
    def get_banner(self) -> str:
        # MySQL protocol starts with server greeting
        return "\x00\x00\x00\x0a5.7.30-28-log\x00\x01\x00\x00\x00"
    
    def handle_connection(self, client_socket: socket.socket, session_data: Dict[str, Any]) -> None:
        """MySQL honeypot - detects SQL injection attempts"""
        try:
            self.apply_response_delay(50)
            # Send greeting (simplified, real MySQL is complex)
            self.send_data(client_socket, "MySQL 5.7 Server", encode=False)
            
            while True:
                data = self.recv_data(client_socket, timeout=30)
                if not data:
                    break
                
                session_data['raw_data'] += data.encode()
                
                threat = self.analyze_payload(data)
                self.log_command(session_data, f"MYSQL: {data[:100]}", threat)
                
                if threat > 0:
                    self.log_command(session_data, f"SQL_INJECTION_ATTEMPT: {data[:100]}", threat)
        
        except Exception as e:
            self.logger.error(f"MySQL handler error: {e}")


class RedisHandler(ProtocolHandler):
    """Redis Protocol Handler (Port 6379)"""
    PROTOCOL_NAME = "Redis"
    DEFAULT_PORT = 6379
    
    def get_banner(self) -> str:
        return ""
    
    def handle_connection(self, client_socket: socket.socket, session_data: Dict[str, Any]) -> None:
        """Redis honeypot - detects unauthorized access"""
        try:
            while True:
                command = self.recv_data(client_socket, timeout=30)
                if not command:
                    break
                
                command = command.strip()
                session_data['raw_data'] += command.encode()
                
                threat = self.analyze_payload(command)
                self.log_command(session_data, f"REDIS: {command[:100]}", threat)
                
                self.apply_response_delay(25)
                
                if command.upper().startswith('PING'):
                    self.send_data(client_socket, "+PONG\r\n")
                elif command.upper().startswith('INFO'):
                    self.send_data(client_socket, "+redis_version:6.0.0\r\n")
                elif command.upper().startswith('AUTH'):
                    self.send_data(client_socket, "-ERR invalid password\r\n")
                else:
                    self.send_data(client_socket, "-ERR unknown command\r\n")
        
        except Exception as e:
            self.logger.error(f"Redis handler error: {e}")


class FTPHandler(ProtocolHandler):
    """FTP Protocol Handler (Port 21)"""
    PROTOCOL_NAME = "FTP"
    DEFAULT_PORT = 21
    
    def get_banner(self) -> str:
        return "220 FTP Server Ready\r\n"
    
    def handle_connection(self, client_socket: socket.socket, session_data: Dict[str, Any]) -> None:
        """FTP honeypot"""
        try:
            self.apply_response_delay(50)
            self.send_data(client_socket, self.get_banner())
            
            authenticated = False
            
            while True:
                command = self.recv_data(client_socket, timeout=30)
                if not command:
                    break
                
                command = command.strip()
                session_data['raw_data'] += command.encode()
                
                threat = self.analyze_payload(command)
                self.log_command(session_data, f"FTP: {command[:100]}", threat)
                
                self.apply_response_delay(50)
                
                cmd_parts = command.split()
                if not cmd_parts:
                    continue
                
                cmd = cmd_parts[0].upper()
                
                if cmd == 'USER':
                    self.send_data(client_socket, "331 Password required\r\n")
                elif cmd == 'PASS':
                    self.send_data(client_socket, "230 Login successful\r\n")
                    authenticated = True
                elif cmd == 'QUIT':
                    self.send_data(client_socket, "221 Goodbye\r\n")
                    break
                else:
                    self.send_data(client_socket, "500 Unknown command\r\n")
        
        except Exception as e:
            self.logger.error(f"FTP handler error: {e}")


class MongoDBHandler(ProtocolHandler):
    """MongoDB Protocol Handler (Port 27017)"""
    PROTOCOL_NAME = "MongoDB"
    DEFAULT_PORT = 27017
    
    def get_banner(self) -> str:
        return ""  # MongoDB doesn't send a banner
    
    def handle_connection(self, client_socket: socket.socket, session_data: Dict[str, Any]) -> None:
        """MongoDB honeypot - detects unauthorized access and injection"""
        try:
            while True:
                data = self.recv_data(client_socket, bufsize=1024, timeout=30)
                if not data:
                    break
                
                session_data['raw_data'] += data.encode()
                
                threat = self.analyze_payload(data)
                self.log_command(session_data, f"MONGODB: {data[:100]}", threat)
                
                # Simulate authentication failure
                self.apply_response_delay(100)
                response = '{"ok":0,"errmsg":"auth failed"}'
                self.send_data(client_socket, response)
        
        except Exception as e:
            self.logger.error(f"MongoDB handler error: {e}")


class SMBHandler(ProtocolHandler):
    """SMB/CIFS Protocol Handler (Port 445)"""
    PROTOCOL_NAME = "SMB"
    DEFAULT_PORT = 445
    
    def get_banner(self) -> str:
        return "SMB/CIFS Service\r\n"
    
    def handle_connection(self, client_socket: socket.socket, session_data: Dict[str, Any]) -> None:
        """SMB honeypot - detects ransomware, lateral movement, file access"""
        try:
            self.apply_response_delay(50)
            self.send_data(client_socket, self.get_banner())
            
            while True:
                data = self.recv_data(client_socket, bufsize=2048, timeout=30)
                if not data:
                    break
                
                session_data['raw_data'] += data.encode()
                
                threat = self.analyze_payload(data)
                self.log_command(session_data, f"SMB: {data[:100]}", threat)
                
                # Simulate share access denial
                self.apply_response_delay(75)
                if 'share' in data.lower() or 'open' in data.lower():
                    self.send_data(client_socket, "ERROR: Access Denied\r\n")
                    threat_level = max(threat, 2)  # Suspicious activity
                    self.log_command(session_data, f"SMB_SHARE_ACCESS_ATTEMPT: {data[:50]}", threat_level)
                else:
                    self.send_data(client_socket, "ERROR: Invalid command\r\n")
        
        except Exception as e:
            self.logger.error(f"SMB handler error: {e}")


class LDAPHandler(ProtocolHandler):
    """LDAP Protocol Handler (Port 389)"""
    PROTOCOL_NAME = "LDAP"
    DEFAULT_PORT = 389
    
    def get_banner(self) -> str:
        return ""  # LDAP doesn't send a banner
    
    def handle_connection(self, client_socket: socket.socket, session_data: Dict[str, Any]) -> None:
        """LDAP honeypot - detects directory enumeration and null bind"""
        try:
            while True:
                data = self.recv_data(client_socket, timeout=30)
                if not data:
                    break
                
                session_data['raw_data'] += data.encode()
                
                threat = self.analyze_payload(data)
                self.log_command(session_data, f"LDAP: {data[:100]}", threat)
                
                # Detect null bind attempts
                if 'bind' in data.lower() and 'null' in data.lower():
                    self.log_command(session_data, "LDAP_NULL_BIND_ATTEMPT", 3)
                
                # Detect base object enumeration
                if 'search' in data.lower():
                    threat = max(threat, 2)
                    self.log_command(session_data, "LDAP_ENUMERATION_ATTEMPT", threat)
                
                self.apply_response_delay(50)
                self.send_data(client_socket, "LDAP: Unauthorized\r\n")
        
        except Exception as e:
            self.logger.error(f"LDAP handler error: {e}")


class PostgreSQLHandler(ProtocolHandler):
    """PostgreSQL Protocol Handler (Port 5432)"""
    PROTOCOL_NAME = "PostgreSQL"
    DEFAULT_PORT = 5432
    
    def get_banner(self) -> str:
        return "PostgreSQL 13.0\r\n"
    
    def handle_connection(self, client_socket: socket.socket, session_data: Dict[str, Any]) -> None:
        """PostgreSQL honeypot - detects SQL injection and auth attacks"""
        try:
            self.apply_response_delay(50)
            self.send_data(client_socket, self.get_banner())
            
            while True:
                query = self.recv_data(client_socket, timeout=30)
                if not query:
                    break
                
                session_data['raw_data'] += query.encode()
                
                threat = self.analyze_payload(query)
                self.log_command(session_data, f"PGSQL_QUERY: {query[:100]}", threat)
                
                # Detect SQL injection
                if any(pattern in query.lower() for pattern in ['union', 'select', 'insert', 'drop', '--']):
                    threat = max(threat, 3)
                    self.log_command(session_data, f"SQL_INJECTION: {query[:100]}", threat)
                
                self.apply_response_delay(100)
                self.send_data(client_socket, "ERROR: Authentication failed\r\n")
        
        except Exception as e:
            self.logger.error(f"PostgreSQL handler error: {e}")


class ElasticsearchHandler(ProtocolHandler):
    """Elasticsearch Protocol Handler (Port 9200)"""
    PROTOCOL_NAME = "Elasticsearch"
    DEFAULT_PORT = 9200
    
    def get_banner(self) -> str:
        return ""  # Elasticsearch responds to HTTP GET
    
    def handle_connection(self, client_socket: socket.socket, session_data: Dict[str, Any]) -> None:
        """Elasticsearch honeypot - detects data exfiltration attempts"""
        try:
            request = self.recv_data(client_socket, bufsize=4096, timeout=10)
            if not request:
                return
            
            session_data['raw_data'] += request.encode()
            
            # Parse as HTTP request
            if request.startswith(('GET ', 'POST ', 'DELETE ')):
                self.log_command(session_data, f"ELASTICSEARCH: {request[:100]}")
                
                threat = self.analyze_payload(request)
                
                # Detect cluster enumeration
                if '_cluster' in request or '_cat' in request:
                    threat = max(threat, 2)
                    self.log_command(session_data, "ELASTICSEARCH_ENUMERATION", threat)
                
                # Detect data access
                if '_search' in request or '_all' in request:
                    threat = max(threat, 3)
                    self.log_command(session_data, "ELASTICSEARCH_DATA_ACCESS", threat)
                
                self.apply_response_delay(50)
                response = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nAccess Denied"
                self.send_data(client_socket, response)
        
        except Exception as e:
            self.logger.error(f"Elasticsearch handler error: {e}")

