#!/usr/bin/env python3
"""
Threat Intelligence Integration
Pulls threat data from external feeds and correlates with honeypot events
"""

import requests
import logging
from datetime import datetime
from typing import List, Dict


class ThreatIntelligence:
    """Threat intelligence feeds integration"""
    
    def __init__(self, logger=None):
        """Initialize threat intelligence"""
        self.logger = logger or logging.getLogger(__name__)
        self.malicious_ips = set()
        self.known_exploits = []
        self.last_update = None
    
    def update_feeds(self):
        """Update all threat intelligence feeds"""
        self.logger.info("Updating threat intelligence feeds...")
        
        try:
            self._update_alienvault_otx()
            self._update_emergingthreats()
            self._update_shodan()
            self.last_update = datetime.now()
            self.logger.info("Threat intelligence feeds updated")
        except Exception as e:
            self.logger.error(f"Error updating threat feeds: {e}")
    
    def _update_alienvault_otx(self):
        """Update AlienVault OTX threat data"""
        try:
            # Note: Replace with your actual API key
            api_key = "YOUR_OTX_API_KEY"
            
            if api_key == "YOUR_OTX_API_KEY":
                self.logger.debug("AlienVault OTX API key not configured")
                return
            
            url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
            headers = {"X-OTX-API-KEY": api_key}
            
            resp = requests.get(url, headers=headers, timeout=10)
            resp.raise_for_status()
            
            data = resp.json()
            
            # Extract IPs from pulses
            for pulse in data.get('results', []):
                for indicator in pulse.get('indicators', []):
                    if indicator['type'] == 'IPv4':
                        self.malicious_ips.add(indicator['indicator'])
            
            self.logger.info(f"Loaded {len(self.malicious_ips)} malicious IPs from OTX")
        
        except Exception as e:
            self.logger.error(f"Error updating AlienVault OTX: {e}")
    
    def _update_emergingthreats(self):
        """Update Emerging Threats feed"""
        try:
            url = "https://rules.emergingthreats.net/open/snort/emerging-malware.rules"
            
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            
            # Parse Snort rules for threat patterns
            for line in resp.text.split('\n'):
                if line.startswith('alert') and 'malware' in line.lower():
                    self.known_exploits.append({
                        'rule': line,
                        'source': 'Emerging Threats',
                        'timestamp': datetime.now()
                    })
            
            self.logger.info(f"Loaded {len(self.known_exploits)} exploit patterns from Emerging Threats")
        
        except Exception as e:
            self.logger.error(f"Error updating Emerging Threats: {e}")
    
    def _update_shodan(self):
        """Update Shodan threat data"""
        try:
            # Note: Replace with your actual Shodan API key
            api_key = "YOUR_SHODAN_API_KEY"
            
            if api_key == "YOUR_SHODAN_API_KEY":
                self.logger.debug("Shodan API key not configured")
                return
            
            # You can use Shodan to find honeypot-like services being scanned
            # This is informational for understanding attack patterns
            
            self.logger.debug("Shodan threat data update skipped (key not configured)")
        
        except Exception as e:
            self.logger.error(f"Error updating Shodan: {e}")
    
    def is_malicious_ip(self, ip: str) -> bool:
        """Check if IP is in threat intelligence database"""
        return ip in self.malicious_ips
    
    def correlate_attack(self, client_ip: str, command: str, threat_level: int) -> Dict:
        """
        Correlate honeypot event with threat intelligence
        Returns correlation data
        """
        correlation = {
            'client_ip': client_ip,
            'command': command,
            'threat_level': threat_level,
            'in_threat_feed': self.is_malicious_ip(client_ip),
            'matched_exploits': [],
            'timestamp': datetime.now()
        }
        
        # Check if command matches known exploits
        command_lower = command.lower()
        for exploit in self.known_exploits:
            if any(pattern in command_lower for pattern in [
                'shellcode', 'payload', 'exploit', 'cve-', 'rce', 'backdoor'
            ]):
                correlation['matched_exploits'].append(exploit)
        
        return correlation
    
    def get_ip_reputation(self, ip: str) -> Dict:
        """Get detailed IP reputation"""
        reputation = {
            'ip': ip,
            'is_malicious': self.is_malicious_ip(ip),
            'feeds': [],
            'last_seen': None
        }
        
        # Check multiple sources
        if self.is_malicious_ip(ip):
            reputation['feeds'].append('OTX')
        
        return reputation
    
    def generate_threat_report(self, session_data: Dict) -> Dict:
        """Generate threat report with intelligence correlation"""
        client_ip = session_data.get('client_ip')
        commands = session_data.get('commands', [])
        threat_level = session_data.get('threat_level', 0)
        
        report = {
            'timestamp': datetime.now(),
            'client_ip': client_ip,
            'threat_level': threat_level,
            'ip_reputation': self.get_ip_reputation(client_ip),
            'correlated_events': [],
            'threat_indicators': {
                'is_known_malicious': self.is_malicious_ip(client_ip),
                'command_count': len(commands),
                'high_risk_commands': []
            }
        }
        
        # Analyze each command
        for cmd_data in commands:
            cmd = cmd_data.get('command', '') if isinstance(cmd_data, dict) else str(cmd_data)
            cmd_threat = cmd_data.get('threat_level', 0) if isinstance(cmd_data, dict) else 0
            
            if cmd_threat >= 3:
                report['threat_indicators']['high_risk_commands'].append(cmd)
                correlation = self.correlate_attack(client_ip, cmd, cmd_threat)
                report['correlated_events'].append(correlation)
        
        return report


class ThreatAnalyzer:
    """Advanced threat analysis combining multiple signals"""
    
    def __init__(self, threat_intel: ThreatIntelligence = None, logger=None):
        """Initialize threat analyzer"""
        self.threat_intel = threat_intel or ThreatIntelligence(logger)
        self.logger = logger or logging.getLogger(__name__)
    
    def analyze_session(self, session_data: Dict) -> Dict:
        """
        Perform advanced analysis on a session
        Combines pattern detection, threat intel, and behavioral analysis
        """
        analysis = {
            'session_id': session_data.get('connection_id'),
            'client_ip': session_data.get('client_ip'),
            'service': session_data.get('service'),
            'threat_level': session_data.get('threat_level', 0),
            'analysis_timestamp': datetime.now(),
            'signals': {
                'pattern_based': False,
                'threat_intel_match': False,
                'behavioral_anomaly': False,
                'exploit_detected': False
            },
            'risk_score': 0,
            'recommendations': []
        }
        
        client_ip = session_data.get('client_ip')
        commands = session_data.get('commands', [])
        
        # Signal 1: Threat intelligence match
        if self.threat_intel.is_malicious_ip(client_ip):
            analysis['signals']['threat_intel_match'] = True
            analysis['risk_score'] += 2
            analysis['recommendations'].append("IP is known malicious actor")
        
        # Signal 2: Pattern-based detection
        if session_data.get('threat_level', 0) > 2:
            analysis['signals']['pattern_based'] = True
            analysis['risk_score'] += 1
            analysis['recommendations'].append("Suspicious command patterns detected")
        
        # Signal 3: Behavioral anomaly
        if len(commands) > 10:
            analysis['signals']['behavioral_anomaly'] = True
            analysis['risk_score'] += 1
            analysis['recommendations'].append("Excessive command execution detected")
        
        # Signal 4: Exploit detection
        threat_report = self.threat_intel.generate_threat_report(session_data)
        if threat_report['correlated_events']:
            analysis['signals']['exploit_detected'] = True
            analysis['risk_score'] += 2
            analysis['recommendations'].append("Exploit signature detected")
        
        # Final risk assessment
        if analysis['risk_score'] >= 4:
            analysis['final_risk'] = 'CRITICAL'
        elif analysis['risk_score'] >= 3:
            analysis['final_risk'] = 'HIGH'
        elif analysis['risk_score'] >= 2:
            analysis['final_risk'] = 'MEDIUM'
        elif analysis['risk_score'] >= 1:
            analysis['final_risk'] = 'LOW'
        else:
            analysis['final_risk'] = 'INFO'
        
        return analysis
