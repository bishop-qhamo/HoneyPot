#!/usr/bin/env python3
"""
FTP Server Honeypot
Emulates FTP service for attack detection with realistic login and directory behavior.
"""

import socket
import threading
import logging
import random
import time
from datetime import datetime


class FTPHoneypot:
    """FTP server honeypot"""
    
    def __init__(self, port=21, logger=None, database=None, alerts=None, threat_detector=None, config=None):
        """Initialize FTP honeypot"""
        self.port = port
        self.logger = logger or logging.getLogger(__name__)
        self.db = database
        self.alerts = alerts
        self.threat_detector = threat_detector
        self.config = config
        self.running = False
        self.server = None
        self.connection_count = 0
        self.lock = threading.Lock()
        self.banner = self._choose_banner()
        self.delay_range = self._get_delay_range()
        self.cwd = '/'
        self.username = None
        self.authenticated = False
        self.files = {
            '/': ['readme.txt', 'uploads', 'logs.txt'],
            '/uploads': ['secret.txt', 'backup.tar.gz']
        }
        self.file_contents = {
            '/readme.txt': 'Welcome to the FTP service.\nPlease contact admin for access.\n',
            '/uploads/secret.txt': 'Top secret data.\nDo not share.\n'
        }
    
    def _choose_banner(self):
        if self.config and self.config.ftp_server_banners:
            return random.choice(self.config.ftp_server_banners)
        return '220 Welcome to FTP Server\r\n'
    
    def _get_delay_range(self):
        if self.config and isinstance(self.config.response_delay_ms, dict):
            return self.config.response_delay_ms
        return {'min': 20, 'max': 120}
    
    def start(self):
        """Start FTP listener"""
        self.running = True
        thread = threading.Thread(
            target=self._start_listener,
            daemon=True
        )
        thread.start()
        self.logger.info(f"Started FTP honeypot listener on port {self.port}")
    
    def _start_listener(self):
        """Listen for FTP connections"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', self.port))
            server.listen(5)
            self.server = server
            
            self.logger.info(f"FTP listener bound to port {self.port}")
            
            while self.running:
                try:
                    client_sock, client_addr = server.accept()
                    thread = threading.Thread(
                        target=self._handle_ftp_connection,
                        args=(client_sock, client_addr),
                        daemon=True
                    )
                    thread.start()
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting FTP connection: {e}")
        
        except Exception as e:
            self.logger.error(f"Failed to start FTP listener on port {self.port}: {e}")
        finally:
            try:
                server.close()
            except:
                pass
    
    def _handle_ftp_connection(self, client_sock, client_addr):
        """Handle FTP connection"""
        with self.lock:
            self.connection_count += 1
            conn_id = self.connection_count
        
        client_ip, client_port = client_addr
        self.cwd = '/'
        self.username = None
        self.authenticated = False
        
        session_data = {
            'connection_id': conn_id,
            'client_ip': client_ip,
            'client_port': client_port,
            'service': 'ftp',
            'start_time': datetime.now(),
            'end_time': None,
            'commands': [],
            'raw_data': b'',
            'threat_level': 0
        }
        
        try:
            self.logger.info(f"[{conn_id}] FTP connection from {client_ip}:{client_port}")
            client_sock.send(self.banner.encode())
            
            client_sock.settimeout(10)
            while True:
                data = client_sock.recv(1024)
                if not data:
                    break
                
                session_data['raw_data'] += data
                command = data.decode('utf-8', errors='ignore').strip()
                
                if command:
                    threat_level = self._analyze_ftp_command(command)
                    session_data['commands'].append({
                        'command': command,
                        'threat_level': threat_level
                    })
                    session_data['threat_level'] = max(session_data['threat_level'], threat_level)
                    self.logger.info(f"[{conn_id}] FTP command: {command}")
                    
                    if threat_level > 0:
                        self.logger.warning(
                            f"[{conn_id}] FTP threat detected: {command} "
                            f"(level: {threat_level}) from {client_ip}"
                        )
                        if self.alerts:
                            self.alerts.send_alert(
                                f"FTP threat detected from {client_ip}: {command}",
                                threat_level,
                                client_ip
                            )
                    
                    response = self._handle_ftp_command(command)
                    self._send_control_response(client_sock, response)
        
        except socket.timeout:
            self.logger.debug(f"[{conn_id}] FTP timeout")
        except Exception as e:
            self.logger.error(f"[{conn_id}] FTP error: {e}")
        finally:
            session_data['end_time'] = datetime.now()
            if self.db:
                try:
                    self.db.store_session(session_data)
                except Exception as e:
                    self.logger.error(f"[{conn_id}] Failed to store FTP session: {e}")
            try:
                client_sock.close()
            except:
                pass
            
            self.logger.info(
                f"[{conn_id}] FTP connection closed. Commands: {len(session_data['commands'])}"
            )
    
    def _send_control_response(self, client_sock, response):
        if self.delay_range:
            delay_ms = random.uniform(self.delay_range.get('min', 20), self.delay_range.get('max', 120))
            time.sleep(delay_ms / 1000.0)
        try:
            client_sock.send(response.encode())
        except Exception:
            pass
    
    def _analyze_ftp_command(self, command: str) -> int:
        """
        Analyze FTP command for threats
        Returns threat level 0-5
        """
        threat_level = 0
        cmd_upper = command.upper()
        
        if cmd_upper.startswith('USER '):
            threat_level = max(threat_level, 1)
        
        if 'ANONYMOUS' in cmd_upper:
            threat_level = max(threat_level, 1)
        
        if '../' in command or '..\\' in command:
            threat_level = max(threat_level, 3)
        
        if any(path in command.lower() for path in ['/etc/', '/root', '/bin', '/usr/bin']):
            threat_level = max(threat_level, 3)
        
        if any(char in command for char in ['$(', '`', '|', ';']):
            threat_level = max(threat_level, 4)
        
        return threat_level
    
    def _handle_ftp_command(self, command: str) -> str:
        """Handle FTP command and return response"""
        cmd_upper = command.upper()
        
        if cmd_upper.startswith('USER '):
            self.username = command[5:].strip()
            return '331 Please specify password\r\n'
        elif cmd_upper.startswith('PASS '):
            self.authenticated = True
            return '230 Login successful.\r\n'
        elif cmd_upper == 'QUIT':
            return '221 Goodbye\r\n'
        elif cmd_upper == 'SYST':
            return '215 UNIX Type: L8\r\n'
        elif cmd_upper == 'PWD':
            return f'257 "{self.cwd}" is current directory\r\n'
        elif cmd_upper == 'TYPE A':
            return '200 Type set to A\r\n'
        elif cmd_upper == 'TYPE I':
            return '200 Type set to I\r\n'
        elif cmd_upper == 'FEAT':
            return '211-Features:\r\n UTF8\r\n PBSZ\r\n PROT\r\n211 End\r\n'
        elif cmd_upper == 'OPTS UTF8 ON':
            return '200 UTF8 set to on\r\n'
        elif cmd_upper == 'NOOP':
            return '200 NOOP ok\r\n'
        elif cmd_upper == 'PASV':
            return '227 Entering Passive Mode (127,0,0,1,195,80)\r\n'
        elif cmd_upper.startswith('CWD '):
            return self._handle_cwd(command[4:].strip())
        elif cmd_upper == 'LIST':
            return self._handle_list()
        elif cmd_upper.startswith('RETR '):
            return self._handle_retr(command[5:].strip())
        elif cmd_upper.startswith('STOR '):
            return self._handle_stor(command[5:].strip())
        else:
            return '502 Command not implemented\r\n'
    
    def _handle_cwd(self, directory: str) -> str:
        target = directory if directory.startswith('/') else f'{self.cwd.rstrip("/")}/{directory}'.replace('//', '/')
        if target in self.files:
            self.cwd = target
            return f'250 Directory changed to {self.cwd}\r\n'
        return '550 Failed to change directory.\r\n'
    
    def _handle_list(self) -> str:
        if not self.authenticated:
            return '530 Please login with USER and PASS.\r\n'
        entries = self.files.get(self.cwd, [])
        listing = []
        for entry in entries:
            if self.cwd == '/':
                path = f'/{entry}'
            else:
                path = f'{self.cwd}/{entry}'
            if path in self.files:
                listing.append(f'drwxr-xr-x 2 owner group 4096 Jan 01 00:00 {entry}')
            else:
                listing.append(f'-rw-r--r-- 1 owner group 1024 Jan 01 00:00 {entry}')
        body = '\r\n'.join(listing) + '\r\n'
        return f'150 Opening ASCII mode data connection for file list.\r\n{body}226 Directory send OK.\r\n'
    
    def _handle_retr(self, filename: str) -> str:
        if not self.authenticated:
            return '530 Please login with USER and PASS.\r\n'
        path = filename if filename.startswith('/') else f'{self.cwd.rstrip("/")}/{filename}'.replace('//', '/')
        if path in self.file_contents:
            content = self.file_contents[path]
            return f'150 Opening BINARY mode data connection for {filename}.\r\n{content}226 Transfer complete.\r\n'
        return '550 File not found.\r\n'
    
    def _handle_stor(self, filename: str) -> str:
        if not self.authenticated:
            return '530 Please login with USER and PASS.\r\n'
        return '550 Permission denied.\r\n'
    
    def stop(self):
        """Stop FTP honeypot"""
        self.running = False
        if self.server:
            try:
                self.server.close()
            except Exception:
                pass
        self.logger.info("FTP honeypot stopped")
