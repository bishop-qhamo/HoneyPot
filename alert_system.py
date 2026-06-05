"""
Alert system for HoneyPot
Sends notifications for threats
"""

import json
import os
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
    
    def __init__(self, config, database=None, logger=None):
        """Initialize alert system"""
        self.config = config
        self.database = database
        self.logger = logger
        self.alerts = []

    def _log(self, level, message):
        if self.logger:
            if level == 'info':
                self.logger.info(message)
            elif level == 'warning':
                self.logger.warning(message)
            elif level == 'error':
                self.logger.error(message)
            else:
                self.logger.debug(message)
        else:
            print(message)
    
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
                self._log('error', f"Failed to persist alert: {e}")
        
        # Send notifications
        if threat_level >= 3:  # MEDIUM and above
            self._notify_email(alert)
            self._notify_webhook(alert)
        
        return alert
    
    def _notify_email(self, alert):
        """Send email notification"""
        try:
            email_config = self.config.alert_email
            if isinstance(email_config, str):
                try:
                    email_config = json.loads(email_config)
                except Exception:
                    email_config = None
            if not isinstance(email_config, dict):
                email_config = None

            smtp_server = os.environ.get('SMTP_SERVER') or (email_config.get('smtp_server') if email_config else None)
            smtp_port = int(os.environ.get('SMTP_PORT') or (email_config.get('smtp_port') if email_config else 0) or 0)
            from_addr = os.environ.get('SMTP_FROM') or (email_config.get('from') if email_config else None)
            username = os.environ.get('SMTP_USER') or (email_config.get('username') if email_config else None)
            password = os.environ.get('SMTP_PASS') or (email_config.get('password') if email_config else None)
            use_ssl = bool(os.environ.get('SMTP_SSL', email_config.get('use_ssl') if email_config else False))
            use_tls = bool(os.environ.get('SMTP_TLS', email_config.get('use_tls') if email_config else True))

            recipient_emails = set()
            if email_config:
                to_addrs = email_config.get('to')
                if isinstance(to_addrs, str):
                    to_addrs = [to_addrs]
                if isinstance(to_addrs, (list, tuple)):
                    for addr in to_addrs:
                        if isinstance(addr, str) and addr.strip():
                            recipient_emails.add(addr.strip())

            if self.database:
                try:
                    subs = self.database.list_subscriptions()
                    for sub in subs:
                        if isinstance(sub, dict) and sub.get('email'):
                            recipient_emails.add(sub['email'].strip())
                except Exception:
                    pass

            if not smtp_server or not smtp_port or not from_addr or not recipient_emails:
                self._log('warning', "Email alert not sent: SMTP settings or recipient addresses are not configured.")
                return

            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{alert['level_name']}] HoneyPot Alert"
            msg['From'] = from_addr
            msg['To'] = ', '.join(sorted(recipient_emails))
            
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
            
            if use_ssl or smtp_port == 465:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10)
            else:
                server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
                server.ehlo()
                if use_tls:
                    server.starttls()
                    server.ehlo()

            if username and password:
                server.login(username, password)

            server.sendmail(from_addr, to_addrs, msg.as_string())
            server.quit()
            self._log('info', f"Email alert sent to {', '.join(to_addrs)}")
        except Exception as e:
            self._log('error', f"Failed to send email alert: {e}")
    
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
                self._log('warning', f"Webhook returned status {response.status_code}")
        
        except Exception as e:
            self._log('error', f"Failed to send webhook notification: {e}")
    
    def get_recent_alerts(self, limit=50):
        """Get recent alerts"""
        return sorted(self.alerts, key=lambda x: x['timestamp'], reverse=True)[:limit]
