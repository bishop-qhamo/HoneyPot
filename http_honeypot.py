#!/usr/bin/env python3
"""
HTTP/Web Server Honeypot
Emulates vulnerable web services with realistic responses and server fingerprints.
"""

import socket
import threading
import logging
import random
import time
from datetime import datetime
from urllib.parse import parse_qs, urlparse


class HTTPHoneypot:
    """HTTP/Web server honeypot"""
    
    def __init__(self, port=80, logger=None, database=None, alerts=None, threat_detector=None, config=None):
        """Initialize HTTP honeypot"""
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
        self.server_header = self._choose_server_header()
        self.delay_range = self._get_delay_range()
        self.common_pages = self._build_common_pages()
    
    def _choose_server_header(self):
        if self.config and self.config.http_server_banners:
            return random.choice(self.config.http_server_banners)
        return "Apache/2.4.41 (Ubuntu)"
    
    def _get_delay_range(self):
        if self.config and isinstance(self.config.response_delay_ms, dict):
            return self.config.response_delay_ms
        return {'min': 20, 'max': 120}
    
    def _build_common_pages(self):
        return {
            '/': '<html><head><title>Home</title></head><body><h1>Welcome to Example Web Service</h1><p>This site is running on a shared server.</p></body></html>',
            '/index.html': '<html><head><title>Home</title></head><body><h1>Welcome</h1><p>Apache/2.4.41 (Ubuntu) server at example.com.</p></body></html>',
            '/login': '<html><head><title>Login</title></head><body><h1>Login Required</h1><form method="post"><input name="username"/><input name="password" type="password"/><button>Sign in</button></form></body></html>',
            '/about': '<html><head><title>About</title></head><body><h1>About Us</h1><p>Secure hosting and web services.</p></body></html>'
        }
    
    def start(self):
        """Start HTTP listener"""
        self.running = True
        thread = threading.Thread(
            target=self._start_listener,
            daemon=True
        )
        thread.start()
        self.logger.info(f"Started HTTP honeypot listener on port {self.port}")
    
    def _start_listener(self):
        """Listen for HTTP connections"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', self.port))
            server.listen(5)
            self.server = server
            
            self.logger.info(f"HTTP listener bound to port {self.port}")
            
            while self.running:
                try:
                    client_sock, client_addr = server.accept()
                    thread = threading.Thread(
                        target=self._handle_http_request,
                        args=(client_sock, client_addr),
                        daemon=True
                    )
                    thread.start()
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting HTTP connection: {e}")
        
        except Exception as e:
            self.logger.error(f"Failed to start HTTP listener on port {self.port}: {e}")
        finally:
            try:
                server.close()
            except:
                pass
    
    def _handle_http_request(self, client_sock, client_addr):
        """Handle HTTP request"""
        with self.lock:
            self.connection_count += 1
            conn_id = self.connection_count
        
        client_ip, client_port = client_addr
        session_data = {
            'connection_id': conn_id,
            'client_ip': client_ip,
            'client_port': client_port,
            'service': 'http',
            'start_time': datetime.now(),
            'end_time': None,
            'commands': [],
            'raw_data': b'',
            'threat_level': 0
        }
        
        try:
            client_sock.settimeout(5)
            request_data = client_sock.recv(8192)
            session_data['raw_data'] = request_data or b''
            
            if not request_data:
                return
            
            request_str = request_data.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            
            if not lines:
                return
            
            request_line = lines[0].split(' ')
            if len(request_line) < 3:
                return
            
            method, path, version = request_line[0], request_line[1], request_line[2]
            headers = self._parse_headers(lines[1:])
            
            self.logger.info(
                f"[{conn_id}] HTTP {method} {path} from {client_ip}:{client_port}"
            )
            
            if self.threat_detector:
                threat_level = self.threat_detector.analyze_http_request(method, path, request_str, headers)
            else:
                threat_level = self._analyze_http_request(method, path, request_str)
            session_data['threat_level'] = threat_level
            
            if threat_level > 0:
                self.logger.warning(
                    f"[{conn_id}] HTTP threat detected: {method} {path} "
                    f"(level: {threat_level}) from {client_ip}"
                )
                if self.alerts:
                    self.alerts.send_alert(
                        f"HTTP threat detected from {client_ip}: {method} {path}",
                        threat_level,
                        client_ip
                    )
            
            status_code, body, content_type = self._build_response(method, path, headers)
            self._send_http_response(client_sock, status_code, body, content_type)
        
        except socket.timeout:
            self.logger.debug(f"[{conn_id}] HTTP timeout")
        except Exception as e:
            self.logger.error(f"[{conn_id}] HTTP error: {e}")
        finally:
            session_data['end_time'] = datetime.now()
            if self.db:
                try:
                    self.db.store_session(session_data)
                except Exception as e:
                    self.logger.error(f"[{conn_id}] Failed to store HTTP session: {e}")
            try:
                client_sock.close()
            except:
                pass
    
    def _parse_headers(self, header_lines):
        headers = {}
        for line in header_lines:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        return headers
    
    def _build_response(self, method, path, headers):
        parsed = urlparse(path)
        clean_path = parsed.path.lower()
        
        if method not in ['GET', 'HEAD', 'POST', 'OPTIONS']:
            return 405, '<html><body><h1>405 Method Not Allowed</h1></body></html>', 'text/html'
        
        if clean_path in self.common_pages:
            body = self.common_pages[clean_path]
            if method == 'HEAD':
                return 200, '', 'text/html'
            return 200, body, 'text/html'
        
        if clean_path.startswith('/api/'):
            body = '{"status": "ok", "message": "API endpoint available"}'
            return 200, body, 'application/json'
        
        if clean_path.startswith('/admin') or clean_path.startswith('/wp-admin'):
            return 403, '<html><body><h1>403 Forbidden</h1><p>Access denied.</p></body></html>', 'text/html'
        
        if clean_path.endswith('.txt'):
            body = 'Sample log file contents\nGenerated by web service.\n'
            return 200, body, 'text/plain'
        
        if clean_path.endswith('.php') or clean_path.endswith('.asp') or clean_path.endswith('.jsp'):
            return 200, '<html><body><h1>Web Application</h1><p>File included.</p></body></html>', 'text/html'
        
        return 404, '<html><body><h1>404 Not Found</h1><p>The requested resource was not found.</p></body></html>', 'text/html'
    
    def _analyze_http_request(self, method, path, request_str) -> int:
        """
        Analyze HTTP request for threats
        Returns threat level 0-5
        """
        threat_level = 0
        path_lower = path.lower()
        request_lower = request_str.lower()
        
        sql_indicators = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'exec', 'script']
        if any(indicator in path_lower for indicator in sql_indicators):
            threat_level = max(threat_level, 3)
        
        if '../' in path or '..\\' in path or '%2e%2e' in path_lower:
            threat_level = max(threat_level, 3)
        
        if any(char in path for char in ['|', ';', '&', '$', '`', '(', ')']):
            threat_level = max(threat_level, 3)
        
        rce_patterns = ['/cmd', '/system', '/exec', '/shell', '/bash', '/sh ']
        if any(pattern in path_lower for pattern in rce_patterns):
            threat_level = max(threat_level, 4)
        
        exploit_paths = ['.php?', '.jsp?', '.asp?', 'upload', '/admin/', '/config/']
        if any(exp in path_lower for exp in exploit_paths):
            threat_level = max(threat_level, 2)
        
        if method in ['DELETE', 'PUT', 'PATCH']:
            threat_level = max(threat_level, 1)
        
        if 'sqlmap' in request_lower or 'nikto' in request_lower or 'acunetix' in request_lower:
            threat_level = max(threat_level, 4)
        
        if 'curl/' in request_lower and 'http' in request_lower:
            threat_level = max(threat_level, 1)
        
        return threat_level
    
    def _send_http_response(self, client_sock, status_code=404, body='', content_type='text/html'):
        """Send HTTP response"""
        responses = {
            200: "OK",
            404: "Not Found",
            500: "Internal Server Error",
            403: "Forbidden",
            405: "Method Not Allowed"
        }
        status_msg = responses.get(status_code, "Unknown")
        
        if self.delay_range:
            delay_ms = random.uniform(self.delay_range.get('min', 20), self.delay_range.get('max', 120))
            time.sleep(delay_ms / 1000.0)
        
        body_bytes = body.encode('utf-8') if isinstance(body, str) else body
        headers = [
            f"HTTP/1.1 {status_code} {status_msg}",
            f"Date: {datetime.utcnow():%a, %d %b %Y %H:%M:%S} GMT",
            f"Server: {self.server_header}",
            f"Content-Type: {content_type}; charset=utf-8",
            f"Content-Length: {len(body_bytes)}",
            "Connection: close",
            "Cache-Control: no-cache",
            f"Set-Cookie: sessionid={random.randint(100000,999999)}; HttpOnly; Path=/",
            ""
        ]
        response = '\r\n'.join(headers).encode('utf-8') + b'\r\n' + body_bytes
        
        try:
            client_sock.send(response)
        except Exception:
            pass
    
    def stop(self):
        """Stop HTTP honeypot"""
        self.running = False
        if self.server:
            try:
                self.server.close()
            except Exception:
                pass
        self.logger.info("HTTP honeypot stopped")
