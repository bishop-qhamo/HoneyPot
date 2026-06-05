#!/usr/bin/env python3
"""
RDP (Remote Desktop Protocol) Honeypot
Emulates Windows RDP service with more realistic handshake behavior.
"""

import socket
import threading
import logging
import random
import time
from datetime import datetime


class RDPHoneypot:
    """RDP service honeypot"""
    
    def __init__(self, port=3389, logger=None, database=None, alerts=None, threat_detector=None, config=None):
        """Initialize RDP honeypot"""
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
        self.server_name = self._choose_server_name()
        self.delay_range = self._get_delay_range()
    
    def _choose_server_name(self):
        if self.config and self.config.rdp_server_variants:
            return random.choice(self.config.rdp_server_variants)
        return 'Microsoft Terminal Services'
    
    def _get_delay_range(self):
        if self.config and isinstance(self.config.response_delay_ms, dict):
            return self.config.response_delay_ms
        return {'min': 20, 'max': 120}
    
    def start(self):
        """Start RDP listener"""
        self.running = True
        thread = threading.Thread(
            target=self._start_listener,
            daemon=True
        )
        thread.start()
        self.logger.info(f"Started RDP honeypot listener on port {self.port}")
    
    def _start_listener(self):
        """Listen for RDP connections"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', self.port))
            server.listen(5)
            self.server = server
            
            self.logger.info(f"RDP listener bound to port {self.port}")
            
            while self.running:
                try:
                    client_sock, client_addr = server.accept()
                    thread = threading.Thread(
                        target=self._handle_rdp_connection,
                        args=(client_sock, client_addr),
                        daemon=True
                    )
                    thread.start()
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting RDP connection: {e}")
        
        except Exception as e:
            self.logger.error(f"Failed to start RDP listener on port {self.port}: {e}")
        finally:
            try:
                server.close()
            except:
                pass
    
    def _handle_rdp_connection(self, client_sock, client_addr):
        """Handle RDP connection"""
        with self.lock:
            self.connection_count += 1
            conn_id = self.connection_count
        
        client_ip, client_port = client_addr
        session_data = {
            'connection_id': conn_id,
            'client_ip': client_ip,
            'client_port': client_port,
            'service': 'rdp',
            'start_time': datetime.now(),
            'end_time': None,
            'commands': [],
            'raw_data': b'',
            'threat_level': 0
        }
        
        try:
            self.logger.info(f"[{conn_id}] RDP connection from {client_ip}:{client_port}")
            client_sock.settimeout(5)
            data = client_sock.recv(2048)
            if data:
                session_data['raw_data'] += data
                threat_level = self._analyze_rdp_handshake(data)
                session_data['threat_level'] = threat_level
                
                if threat_level > 0:
                    self.logger.warning(
                        f"[{conn_id}] RDP threat detected (level: {threat_level}) from {client_ip}"
                    )
                    if self.alerts:
                        self.alerts.send_alert(
                            f"RDP threat detected from {client_ip}",
                            threat_level,
                            client_ip
                        )
                
                self._send_rdp_response(client_sock)
        
        except socket.timeout:
            self.logger.debug(f"[{conn_id}] RDP timeout")
        except Exception as e:
            self.logger.error(f"[{conn_id}] RDP error: {e}")
        finally:
            session_data['end_time'] = datetime.now()
            if self.db:
                try:
                    self.db.store_session(session_data)
                except Exception as e:
                    self.logger.error(f"[{conn_id}] Failed to store RDP session: {e}")
            try:
                client_sock.close()
            except:
                pass
            
            self.logger.info(f"[{conn_id}] RDP connection closed")
    
    def _analyze_rdp_handshake(self, data: bytes) -> int:
        """
        Analyze RDP handshake for threats
        Returns threat level 0-5
        """
        threat_level = 0
        data_lower = data.lower()
        
        if data[:3] == b'\x03\x00':
            threat_level = max(threat_level, 1)
        
        if b'ms_t120' in data_lower or b'global' in data_lower:
            threat_level = max(threat_level, 4)
        
        if len(data) > 2000:
            threat_level = max(threat_level, 2)
        
        if b'cve-2019' in data_lower or b'cve-2020' in data_lower:
            threat_level = max(threat_level, 4)
        
        return threat_level
    
    def _send_rdp_response(self, client_sock):
        """Send RDP handshake response"""
        if self.delay_range:
            delay_ms = random.uniform(self.delay_range.get('min', 20), self.delay_range.get('max', 120))
            time.sleep(delay_ms / 1000.0)
        try:
            response = b'\x03\x00\x00\x17\x06\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            client_sock.send(response)
        except Exception:
            pass
    
    def stop(self):
        """Stop RDP honeypot"""
        self.running = False
        if self.server:
            try:
                self.server.close()
            except Exception:
                pass
        self.logger.info("RDP honeypot stopped")
