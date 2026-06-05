#!/usr/bin/env python3
"""
Advanced SSH/Telnet Honeypot System
- Logs and detects attack attempts
- Stores data in SQLite database
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
import getpass
from datetime import datetime
from pathlib import Path
import subprocess
import sys
from config import Config
from database import Database
from logger import Logger
from alert_system import AlertSystem
from threat_detection import ThreatDetector
from fingerprint_evasion import FingerprintEvasion
from protocol_handler import (
    ProtocolHandler,
    SSHHandler, TelnetHandler, HTTPHandler, DNSHandler,
    SMTPHandler, MySQLHandler, RedisHandler, FTPHandler,
    MongoDBHandler, SMBHandler, LDAPHandler, PostgreSQLHandler, ElasticsearchHandler
)


class HoneyPot:
    """Main honeypot server handling multi-protocol connections"""
    
    # Protocol handler registry
    PROTOCOL_HANDLERS = {
        'ssh': SSHHandler,
        'telnet': TelnetHandler,
        'http': HTTPHandler,
        'dns': DNSHandler,
        'smtp': SMTPHandler,
        'mysql': MySQLHandler,
        'redis': RedisHandler,
        'ftp': FTPHandler,
        'mongodb': MongoDBHandler,
        'smb': SMBHandler,
        'ldap': LDAPHandler,
        'postgresql': PostgreSQLHandler,
        'elasticsearch': ElasticsearchHandler,
    }
    
    def __init__(self, config_file='config.json'):
        """Initialize honeypot with configuration"""
        self.config = Config(config_file)
        self.db = Database(self.config.db_path)
        self.logger = Logger(self.config.log_file)
        self.alerts = AlertSystem(self.config, self.db, self.logger)
        self.threat_detector = ThreatDetector(self.config)
        self.evasion = FingerprintEvasion(self.config)
        
        self.delay_range = self.config.response_delay_ms
        self.server_socket = None
        self.running = False
        self.connection_count = 0
        self.lock = threading.Lock()
        
        # Initialize protocol handlers
        self.handlers = {}
        self._initialize_handlers()
        
        # Legacy banner support (for backward compatibility)
        self.ssh_banner = self.evasion.randomize_ssh_banner()
        self.telnet_banner = self.evasion.randomize_telnet_banner()
        
        self.logger.info(f"HoneyPot initialized with {len(self.handlers)} protocol handlers")
    
    def _initialize_handlers(self):
        """Initialize all protocol handlers from registry"""
        for protocol_name, handler_class in self.PROTOCOL_HANDLERS.items():
            try:
                self.handlers[protocol_name] = handler_class(
                    self.config,
                    self.threat_detector,
                    self.evasion,
                    self.logger
                )
                self.logger.info(f"Registered protocol handler: {protocol_name.upper()}")
            except Exception as e:
                self.logger.error(f"Failed to initialize {protocol_name} handler: {e}")
    
    def get_handler(self, service_name: str) -> ProtocolHandler:
        """Get handler for a service, falls back to generic handler"""
        handler = self.handlers.get(service_name.lower())
        if not handler:
            self.logger.warning(f"No handler for service '{service_name}', using generic handler")
            # Return a generic handler (could create a default one)
            return self.handlers.get('telnet')  # Fallback
        return handler

    def prompt_email_setup(self):
        """Prompt the user to configure SMTP email alerts if not already configured."""
        if self.config.alert_email:
            return
        if not sys.stdin.isatty():
            return

        answer = input("Email alerting is not configured. Set up SMTP email alerts now? (y/N): ").strip().lower()
        if answer not in ('y', 'yes'):
            return

        smtp_server = input("SMTP server (example: smtp.gmail.com): ").strip()
        smtp_port = input("SMTP port [587]: ").strip() or '587'
        from_addr = input("From address: ").strip()
        to_addr = input("To address(es) (comma-separated): ").strip()
        username = input("SMTP username (leave blank to skip): ").strip()
        password = getpass.getpass("SMTP password (leave blank to skip): ")
        use_ssl = input("Use SSL? (y/N): ").strip().lower() in ('y', 'yes')
        use_tls = not use_ssl and input("Use TLS? (Y/n): ").strip().lower() not in ('n', 'no')

        if not smtp_server or not from_addr or not to_addr:
            self.logger.warning("Email alert setup aborted. Required settings were not provided.")
            return

        email_config = {
            'smtp_server': smtp_server,
            'smtp_port': int(smtp_port),
            'from': from_addr,
            'to': [addr.strip() for addr in to_addr.split(',') if addr.strip()],
            'username': username or None,
            'password': password or None,
            'use_ssl': use_ssl,
            'use_tls': use_tls
        }

        self.config.data['alert_email'] = email_config
        try:
            self.config.save()
            self.logger.info("SMTP email alert configuration saved to config.json")
        except Exception as e:
            self.logger.error(f"Failed to save email configuration: {e}")

    def _choose_ssh_banner(self):
        """Get randomized SSH banner via evasion module"""
        return self.evasion.randomize_ssh_banner()

    def _choose_telnet_banner(self):
        """Get randomized Telnet banner via evasion module"""
        return self.evasion.randomize_telnet_banner()

    def _delay_response(self):
        """Use realistic response delay with jitter"""
        delay = self.evasion.get_response_delay(self.delay_range.get('min', 50))
        time.sleep(delay)

    def _send_telnet_line(self, client_sock, text):
        self._delay_response()
        try:
            client_sock.send(text.encode())
        except Exception:
            pass

    def _format_telnet_response(self, command, session_id):
        """Generate realistic shell response based on command"""
        response = self.evasion.generate_shell_response(command, session_id)
        return response.replace('\n', '\r\n')
    
    def start(self):
        """Start the honeypot server"""
        self.running = True
        
        for port_config in self.config.ports:
            thread = threading.Thread(
                target=self._start_listener,
                args=(port_config['port'], port_config['service']),
                daemon=True
            )
            thread.start()
            self.logger.info(f"Started {port_config['service']} listener on port {port_config['port']}")
    
    def _start_listener(self, port, service):
        """Start listening on a specific port"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.listen(5)
            
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
        """Handle incoming connection using protocol handlers"""
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
            
            # Get appropriate protocol handler
            handler = self.get_handler(service)
            if handler:
                handler.handle_connection(client_sock, session_data)
            else:
                self.logger.warning(f"[{conn_id}] No handler for service: {service}")
            
        except Exception as e:
            self.logger.error(f"[{conn_id}] Connection error: {e}")
        finally:
            self._close_connection(client_sock, session_data)
    
    def _handle_ssh(self, client_sock, session_data):
        """Handle SSH connection"""
        conn_id = session_data['connection_id']
        self._delay_response()
        try:
            client_sock.send(self.ssh_banner.encode())
            client_sock.settimeout(5)
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
        try:
            client_sock.send(self.telnet_banner.encode())
            self.telnet_username = None
            self.telnet_authenticated = False
            self.telnet_stage = 'username'
            
            client_sock.settimeout(10)
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
                session_data['threat_level'] = max(session_data.get('threat_level', 0), threat_level)
                self.logger.info(f"[{conn_id}] Telnet input: {command}")
                if threat_level > 0:
                    self.alerts.send_alert(
                        f"Suspicious command from {session_data['client_ip']}: {command}",
                        threat_level,
                        session_data['client_ip']
                    )
                
                if self.telnet_stage == 'username':
                    self.telnet_username = command
                    self.telnet_stage = 'password'
                    self._send_telnet_line(client_sock, 'Password: ')
                    continue
                
                if self.telnet_stage == 'password':
                    password = command
                    if self.telnet_username.lower() in ['admin', 'root', 'user'] and password.lower() in ['admin', 'password', '1234']:
                        self.telnet_authenticated = True
                        self.telnet_stage = 'shell'
                        self._send_telnet_line(client_sock, 'Login successful\r\n$ ')
                    else:
                        self.telnet_username = None
                        self.telnet_stage = 'username'
                        response = self.evasion.randomize_failed_login_response()
                        self._send_telnet_line(client_sock, response.replace('\n', '\r\n') + 'Username: ')
                    continue
                
                if self.telnet_authenticated:
                    conn_id = session_data['connection_id']
                    response = self._format_telnet_response(command, conn_id)
                    self._send_telnet_line(client_sock, response + '\r\n$ ')
                    if command.lower() in ['exit', 'logout', 'quit']:
                        break
                else:
                    self._send_telnet_line(client_sock, 'Username: ')
        
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
        """Stop the honeypot server"""
        self.running = False
        self.logger.info("HoneyPot stopped")


def main():
    """Main entry point"""
    honeypot = HoneyPot()
    
    try:
        honeypot.prompt_email_setup()
        honeypot.start()
        honeypot.logger.info("HoneyPot is running. Press Ctrl+C to stop.")
        
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
