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


class HoneyPot:
    """Main honeypot server handling SSH/Telnet connections"""
    
    def __init__(self, config_file='config.json'):
        """Initialize honeypot with configuration"""
        self.config = Config(config_file)
        self.db = Database(self.config.db_path)
        self.logger = Logger(self.config.log_file)
        self.alerts = AlertSystem(self.config, self.db)
        self.threat_detector = ThreatDetector()
        
        self.server_socket = None
        self.running = False
        self.connection_count = 0
        self.lock = threading.Lock()
        
        self.logger.info("HoneyPot initialized")
    
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
        
        # Send SSH banner
        banner = "SSH-2.0-OpenSSH_7.4\r\n"
        client_sock.send(banner.encode())
        
        client_sock.settimeout(5)
        try:
            data = client_sock.recv(1024)
            if data:
                session_data['raw_data'] += data
                self.logger.debug(f"[{conn_id}] SSH data: {data[:100]}")
                
                # Threat detection
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
        
        # Send Telnet welcome
        welcome = "Welcome to HoneyPot Telnet Server\r\nUsername: "
        client_sock.send(welcome.encode())
        
        client_sock.settimeout(10)
        try:
            while True:
                data = client_sock.recv(1024)
                if not data:
                    break
                
                session_data['raw_data'] += data
                command = data.decode('utf-8', errors='ignore').strip()
                
                if command:
                    threat_level = self.threat_detector.analyze_command(command)
                    session_data['commands'].append({
                        'command': command,
                        'threat_level': threat_level
                    })
                    self.logger.info(f"[{conn_id}] Command: {command}")
                    
                    # Threat detection
                    session_data['threat_level'] = max(session_data.get('threat_level', 0), threat_level)
                    if threat_level > 0:
                        self.alerts.send_alert(
                            f"Suspicious command from {session_data['client_ip']}: {command}",
                            threat_level,
                            session_data['client_ip']
                        )
                    
                    # Fake response
                    response = f"{command}\r\n$ "
                    client_sock.send(response.encode())
        
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
