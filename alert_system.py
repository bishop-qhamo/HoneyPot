"""
Alert system for HoneyPot
Sends notifications for threats
"""

import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


class AlertSystem:
    """Handles alerts and notifications"""
    
    THREAT_LEVELS = {
        1: 'INFO',
        2: 'LOW',
        3: 'MEDIUM',
        4: 'HIGH',
        5: 'CRITICAL'
    }
    
    def __init__(self, config, database=None):
        """Initialize alert system"""
        self.config = config
        self.database = database
        self.alerts = []
    
    def send_alert(self, message, threat_level=1, client_ip=None, session_id=None):
        """Send alert for detected threat"""
        alert = {
            'timestamp': datetime.now(),
            'message': message,
            'threat_level': threat_level,
            'level_name': self.THREAT_LEVELS.get(threat_level, 'UNKNOWN'),
            'client_ip': client_ip,
            'session_id': session_id
        }
        
        self.alerts.append(alert)
        
        if self.database:
            try:
                self.database.store_alert(alert)
            except Exception as e:
                print(f"Failed to persist alert: {e}")
        
        # Send notifications
        if threat_level >= 3:  # MEDIUM and above
            self._notify_email(alert)
            self._notify_webhook(alert)
        
        return alert
    
    def _notify_email(self, alert):
        """Send email notification"""
        if not self.config.alert_email:
            return
        
        try:
            email_config = self.config.alert_email
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{alert['level_name']}] HoneyPot Alert"
            msg['From'] = email_config['from']
            msg['To'] = email_config['to']
            
            body = f"""
HoneyPot Alert
==============

Level: {alert['level_name']} (Level {alert['threat_level']})
Time: {alert['timestamp']}
Message: {alert['message']}
{f"Client IP: {alert['client_ip']}" if alert['client_ip'] else ""}

This is an automated alert from the HoneyPot security system.
            """
            
            part = MIMEText(body, 'plain')
            msg.attach(part)
            
            # This would require SMTP configuration
            # Uncomment when email is configured
            # with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
            #     server.starttls()
            #     server.login(email_config['username'], email_config['password'])
            #     server.send_message(msg)
        
        except Exception as e:
            print(f"Failed to send email alert: {e}")
    
    def _notify_webhook(self, alert):
        """Send webhook notification"""
        if not self.config.alert_webhook:
            return
        
        try:
            payload = {
                'timestamp': str(alert['timestamp']),
                'message': alert['message'],
                'threat_level': alert['threat_level'],
                'level_name': alert['level_name'],
                'client_ip': alert['client_ip']
            }
            
            response = requests.post(
                self.config.alert_webhook,
                json=payload,
                timeout=5
            )
            
            if response.status_code != 200:
                print(f"Webhook returned status {response.status_code}")
        
        except Exception as e:
            print(f"Failed to send webhook notification: {e}")
    
    def get_recent_alerts(self, limit=50):
        """Get recent alerts"""
        return sorted(self.alerts, key=lambda x: x['timestamp'], reverse=True)[:limit]
