#!/usr/bin/env python3
"""
Advanced T-Pot Style SSH/Telnet/HTTP/FTP/RDP Honeypot System
- Logs and detects attack attempts across multiple protocols
- Stores data in SQLite database
- Sends data to Elasticsearch for centralized logging
- Sends real-time alerts
- Provides web dashboard
"""

import socket
import threading
import logging
import json
import sqlite3
import hashlib
import random
import time
from datetime import datetime
from pathlib import Path
import subprocess
import sys
from config import Config
from database import Database
from logger import Logger
from alert_system import AlertSystem
from threat_detection import ThreatDetector
from http_honeypot import HTTPHoneypot
from ftp_honeypot import FTPHoneypot
from rdp_honeypot import RDPHoneypot


class HoneyPot:
    """Main honeypot server handling multiple protocols"""
    
    def __init__(self, config_file='config.json'):
        """Initialize honeypot with configuration"""
        self.config = Config(config_file)
        self.db = Database(self.config.db_path)
        self.logger = Logger(self.config.log_file)
        self.alerts = AlertSystem(self.config, self.db)
        self.threat_detector = ThreatDetector(self.config)
        
        self.delay_range = self.config.response_delay_ms
        self.ssh_banner = self._choose_ssh_banner()
        self.telnet_welcome = self._choose_telnet_welcome()
        self.server_socket = None
        self.running = False
        self.connection_count = 0
        self.lock = threading.Lock()
        
        self.protocol_classes = {
            'http': HTTPHoneypot,
            'ftp': FTPHoneypot,
            'rdp': RDPHoneypot
        }
        self.protocol_services = []
        self.protocol_handlers = []
        self.listener_sockets = []
        self.default_protocol_ports = [
            {'port': 80, 'service': 'http'},
            {'port': 21, 'service': 'ftp'},
            {'port': 3389, 'service': 'rdp'}
        ]
        
        self.logger.info("T-Pot Style HoneyPot initialized with multiple protocols")
    
    def _choose_ssh_banner(self):
        if self.config and self.config.ssh_server_banners:
            return random.choice(self.config.ssh_server_banners) + '\r\n'
        return 'SSH-2.0-OpenSSH_7.4\r\n'

    def _choose_telnet_welcome(self):
        if self.config and self.config.telnet_welcome_messages:
            return random.choice(self.config.telnet_welcome_messages)
        return 'Welcome to HoneyPot Telnet Server\r\nUsername: '

    def _delay_response(self):
        if not self.config.realistic_response or not isinstance(self.delay_range, dict):
            return
        delay_ms = random.uniform(self.delay_range.get('min', 20), self.delay_range.get('max', 120))
        time.sleep(delay_ms / 1000.0)

    def _send_telnet_response(self, client_sock, text):
        self._delay_response()
        try:
            client_sock.send(text.encode())
        except Exception:
            pass

    def _format_telnet_response(self, command):
        command_lower = command.strip().lower()
        if command_lower in ['help', '?']:
            return 'Available commands: help, ls, whoami, uname, exit\r\n$ '
        if command_lower in ['ls', 'dir']:
            return 'drwxr-xr-x 2 root root 4096 Jan 01 00:00 .\r\n' \
                   'drwxr-xr-x 3 root root 4096 Jan 01 00:00 ..\r\n' \
                   '-rw-r--r-- 1 root root  220 Jan 01 00:00 .bashrc\r\n$ '
        if command_lower == 'whoami':
            return 'root\r\n$ '
        if command_lower == 'uname -a':
            return 'Linux honeypot 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux\r\n$ '
        if command_lower in ['exit', 'logout', 'quit']:
            return 'Logout\r\n'
        return f'{command}: command not found\r\n$ '

    def start(self):
        """Start all honeypot services"""
        self.running = True
        
        configured_ports = list(self.config.ports)
        configured_services = {p['service'] for p in configured_ports}
        for default_port in self.default_protocol_ports:
            if default_port['service'] not in configured_services:
                configured_ports.append(default_port)
        
        for port_config in configured_ports:
            port = port_config['port']
            service = port_config['service']
            if service in ('ssh', 'telnet'):
                thread = threading.Thread(
                    target=self._start_listener,
                    args=(port, service),
                    daemon=True
                )
                thread.start()
                self.logger.info(f"Started {service} listener on port {port}")
            elif service in self.protocol_classes:
                handler_cls = self.protocol_classes[service]
                handler = handler_cls(
                    port=port,
                    logger=self.logger,
                    database=self.db,
                    alerts=self.alerts,
                    threat_detector=self.threat_detector,
                    config=self.config
                )
                self.protocol_services.append(handler)
                self.protocol_handlers.append((service, handler))
                handler.start()
                self.logger.info(f"Started {service.upper()} listener on port {port}")
            else:
                self.logger.warning(f"Unsupported service '{service}' configured on port {port}")
    
    def _start_listener(self, port, service):
        """Start listening on a specific port"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.listen(5)
            self.listener_sockets.append(server)
            
            self.logger.info(f"{service} listener bound to port {port}")
            
            while self.running:
                try:
                    client_sock, client_addr = server.accept()
                    thread = threading.Thread(
                        target=self._handle_connection,
                        args=(client_sock, client_addr, service),
                        daemon=True
                    )
                    thread.start()
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting connection: {e}")
        
        except Exception as e:
            self.logger.error(f"Failed to start {service} listener on port {port}: {e}")
        finally:
            try:
                server.close()
            except:
                pass
    
    def _handle_connection(self, client_sock, client_addr, service):
        """Handle incoming connection"""
        with self.lock:
            self.connection_count += 1
            conn_id = self.connection_count
        
        client_ip, client_port = client_addr
        session_data = {
            'connection_id': conn_id,
            'client_ip': client_ip,
            'client_port': client_port,
            'service': service,
            'start_time': datetime.now(),
            'commands': [],
            'raw_data': b'',
            'threat_level': 0
        }
        
        try:
            self.logger.info(f"[{conn_id}] Connection from {client_ip}:{client_port} on {service}")
            
            if service == 'ssh':
                self._handle_ssh(client_sock, session_data)
            elif service == 'telnet':
                self._handle_telnet(client_sock, session_data)
            
        except Exception as e:
            self.logger.error(f"[{conn_id}] Connection error: {e}")
        finally:
            self._close_connection(client_sock, session_data)
    
    def _handle_ssh(self, client_sock, session_data):
        """Handle SSH connection"""
        conn_id = session_data['connection_id']
        
        self._delay_response()
        client_sock.send(self.ssh_banner.encode())
        
        client_sock.settimeout(5)
        try:
            data = client_sock.recv(1024)
            if data:
                session_data['raw_data'] += data
                self.logger.debug(f"[{conn_id}] SSH data: {data[:100]}")
                
                threat_level = self.threat_detector.analyze_ssh(data.decode('utf-8', errors='ignore'))
                session_data['threat_level'] = max(session_data.get('threat_level', 0), threat_level)
                if threat_level > 0:
                    self.alerts.send_alert(
                        f"SSH threat detected from {session_data['client_ip']}",
                        threat_level,
                        session_data['client_ip']
                    )
        except socket.timeout:
            self.logger.debug(f"[{conn_id}] SSH connection timeout")
        except Exception as e:
            self.logger.error(f"[{conn_id}] SSH error: {e}")
    
    def _handle_telnet(self, client_sock, session_data):
        """Handle Telnet connection"""
        conn_id = session_data['connection_id']
        
        self._delay_response()
        client_sock.send(self.telnet_welcome.encode())
        self.telnet_username = None
        self.telnet_stage = 'username'
        self.telnet_authenticated = False
        
        client_sock.settimeout(10)
        try:
            while True:
                data = client_sock.recv(1024)
                if not data:
                    break
                
                session_data['raw_data'] += data
                command = data.decode('utf-8', errors='ignore').strip()
                if not command:
                    continue
                
                threat_level = self.threat_detector.analyze_command(command)
                session_data['commands'].append({
                    'command': command,
                    'threat_level': threat_level
                })
                self.logger.info(f"[{conn_id}] Telnet command: {command}")
                session_data['threat_level'] = max(session_data.get('threat_level', 0), threat_level)
                if threat_level > 0:
                    self.alerts.send_alert(
                        f"Suspicious command from {session_data['client_ip']}: {command}",
                        threat_level,
                        session_data['client_ip']
                    )
                
                if self.telnet_stage == 'username':
                    self.telnet_username = command
                    self.telnet_stage = 'password'
                    self._send_telnet_response(client_sock, 'Password: ')
                    continue
                
                if self.telnet_stage == 'password':
                    self.telnet_stage = 'shell'
                    self.telnet_authenticated = True
                    self._send_telnet_response(client_sock, 'Login successful\r\n$ ')
                    continue
                
                response = self._format_telnet_response(command)
                self._send_telnet_response(client_sock, response)
                if command.lower() in ['exit', 'logout', 'quit']:
                    break
        
        except socket.timeout:
            self.logger.debug(f"[{conn_id}] Telnet timeout")
        except Exception as e:
            self.logger.error(f"[{conn_id}] Telnet error: {e}")
    
    def _close_connection(self, client_sock, session_data):
        """Close connection and store data"""
        try:
            client_sock.close()
        except:
            pass
        
        session_data['end_time'] = datetime.now()
        duration = (session_data['end_time'] - session_data['start_time']).total_seconds()
        
        # Store in database
        self.db.store_session(session_data)
        if hasattr(self.config, 'max_sessions_to_keep'):
            self.db.enforce_max_sessions(getattr(self.config, 'max_sessions_to_keep', 10000))
        
        self.logger.info(
            f"[{session_data['connection_id']}] Connection closed. "
            f"Duration: {duration:.1f}s, Commands: {len(session_data['commands'])}"
        )
    
    def stop(self):
        """Stop all honeypot services"""
        self.running = False
        for server in self.listener_sockets:
            try:
                server.close()
            except Exception:
                pass
        self.listener_sockets.clear()

        for service, handler in self.protocol_handlers:
            try:
                handler.stop()
                self.logger.info(f"Stopped {service.upper()} handler")
            except Exception as e:
                self.logger.error(f"Failed to stop {service.upper()} handler: {e}")

        self.logger.info("T-Pot Style HoneyPot stopped")


def main():
    """Main entry point"""
    honeypot = HoneyPot()
    
    try:
        honeypot.start()
        honeypot.logger.info("T-Pot Style HoneyPot is running. Press Ctrl+C to stop.")
        honeypot.logger.info("Services: SSH(22), Telnet(23), HTTP(80), FTP(21), RDP(3389)")
        
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        honeypot.logger.info("Received shutdown signal")
        honeypot.stop()
        sys.exit(0)
    except Exception as e:
        honeypot.logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
