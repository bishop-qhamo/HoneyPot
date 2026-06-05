#!/usr/bin/env python3
"""
Web Dashboard for HoneyPot
Flask-based interface to view attacks and statistics
"""

from flask import Flask, send_file, request, jsonify
from flask_cors import CORS
from database import Database
from config import Config
from pathlib import Path
from datetime import datetime
import os
import smtplib
from email.message import EmailMessage
from alert_system import AlertSystem
from logger import Logger


class Dashboard:
    """Web dashboard for HoneyPot"""
    
    def __init__(self, config_file='config.json', port=5000):
        """Initialize dashboard"""
        self.config = Config(config_file)
        self.db = Database(self.config.db_path)
        self.port = port
        self.logger = Logger(self.config.log_file)
        self.alerts = AlertSystem(self.config, self.db, self.logger)
        
        self.app = Flask(__name__)
        CORS(self.app)
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        @self.app.route('/dashboard')
        def index():
            """Serve the dashboard UI"""
            dashboard_path = Path(__file__).resolve().parent / 'dashboard.html'
            if dashboard_path.exists():
                return send_file(dashboard_path)
            return jsonify({'error': 'Dashboard UI not found'}), 404
        
        @self.app.route('/api/sessions')
        def get_sessions():
            """Get sessions list"""
            page = request.args.get('page', 1, type=int)
            limit = 50
            offset = (page - 1) * limit
            
            sessions = self.db.get_sessions(limit=limit, offset=offset)
            
            # Convert datetime objects to strings
            for session in sessions:
                if isinstance(session['start_time'], str):
                    continue
                session['start_time'] = str(session['start_time'])
                if session['end_time']:
                    session['end_time'] = str(session['end_time'])
            
            return jsonify({
                'sessions': sessions,
                'page': page
            })
        
        @self.app.route('/api/sessions/<int:session_id>')
        def get_session_detail(session_id):
            """Get session details"""
            try:
                session = self.db.get_session_details(session_id)
                
                # Convert datetime objects
                session['start_time'] = str(session['start_time'])
                if session['end_time']:
                    session['end_time'] = str(session['end_time'])
                
                return jsonify(session)
            except Exception as e:
                return jsonify({'error': str(e)}), 404
        
        @self.app.route('/api/alerts')
        def get_alerts():
            """Get alerts"""
            page = request.args.get('page', 1, type=int)
            limit = 50
            offset = (page - 1) * limit
            
            alerts = self.db.get_alerts(limit=limit, offset=offset)
            
            # Convert datetime objects
            for alert in alerts:
                if isinstance(alert['timestamp'], str):
                    continue
                alert['timestamp'] = str(alert['timestamp'])
            
            return jsonify({
                'alerts': alerts,
                'page': page
            })
        
        @self.app.route('/api/stats')
        def get_stats():
            """Get base statistics"""
            stats = self.db.get_stats()
            
            # Add time-based stats
            sessions = self.db.get_sessions(limit=10000)
            
            hourly_attacks = {}
            for session in sessions:
                if isinstance(session['start_time'], str):
                    dt = datetime.fromisoformat(session['start_time'])
                else:
                    dt = session['start_time']
                hour = dt.strftime('%Y-%m-%d %H:00')
                hourly_attacks[hour] = hourly_attacks.get(hour, 0) + 1
            
            stats['hourly_attacks'] = hourly_attacks
            
            return jsonify(stats)

        @self.app.route('/api/overview')
        def get_overview():
            """Get dashboard overview metrics"""
            stats = self.db.get_stats()
            alert_counts = self.db.get_alert_counts_by_level()
            service_counts = self.db.get_session_counts_by_service()
            
            return jsonify({
                'stats': stats,
                'alert_counts': alert_counts,
                'service_counts': service_counts
            })

        @self.app.route('/api/status')
        def get_status():
            """Get configured services and recent activity counts"""
            try:
                configured = self.config.ports
            except Exception:
                configured = []

            try:
                service_counts = self.db.get_session_counts_by_service()
            except Exception:
                service_counts = {}

            return jsonify({
                'configured_ports': configured,
                'service_counts': service_counts
            })
        
        @self.app.route('/api/top-ips')
        def get_top_ips():
            """Get top attacking IPs"""
            sessions = self.db.get_sessions(limit=10000)
            
            ip_counts = {}
            for session in sessions:
                ip = session['client_ip']
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]
            
            return jsonify({
                'top_ips': [{'ip': ip, 'count': count} for ip, count in top_ips]
            })
        
        @self.app.route('/api/search')
        def search():
            """Search sessions by IP"""
            query = request.args.get('q', '')
            
            if not query:
                return jsonify({
                    'results': [],
                    'total': 0,
                    'message': 'No search query provided'
                })
            
            sessions = self.db.get_sessions(limit=10000)
            results = [s for s in sessions if query.lower() in s['client_ip'].lower()]
            
            return jsonify({
                'results': results[:50],
                'total': len(results)
            })
        
        @self.app.route('/api/health')
        def health():
            """Health check endpoint"""
            return jsonify({'status': 'ok'})

        @self.app.route('/api/subscribe-email', methods=['POST'])
        def subscribe_email():
            """Subscribe an email address to alerts (stores in config and optionally sends confirmation)"""
            try:
                data = request.get_json(force=True)
                email = (data or {}).get('email')
                if not email or '@' not in email:
                    return jsonify({'error': 'Invalid email'}), 400

                # Persist subscription to database
                try:
                    self.db.add_subscription(email)
                except Exception:
                    # fallback: save to config if DB not writable
                    self.config.data['alert_email'] = email
                    try:
                        self.config.save()
                    except Exception:
                        pass

                # Attempt to send confirmation email if SMTP settings are provided via env or config
                smtp_host = os.environ.get('SMTP_HOST') or self.config.data.get('smtp_host') or self.config.data.get('smtp_server')
                smtp_port = int(os.environ.get('SMTP_PORT') or self.config.data.get('smtp_port') or 0)
                smtp_user = os.environ.get('SMTP_USER') or self.config.data.get('smtp_user') or self.config.data.get('smtp_username')
                smtp_pass = os.environ.get('SMTP_PASS') or self.config.data.get('smtp_pass') or self.config.data.get('smtp_password')
                smtp_from = os.environ.get('SMTP_FROM') or self.config.data.get('smtp_from')

                if smtp_host and smtp_port:
                    try:
                        msg = EmailMessage()
                        msg['Subject'] = 'HoneyPot Alert Subscription'
                        msg['From'] = smtp_from or smtp_user or f'no-reply@{smtp_host}'
                        msg['To'] = email
                        msg.set_content('You have been subscribed to HoneyPot alert notifications.')

                        if smtp_port == 465:
                            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
                        else:
                            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                            server.starttls()

                        if smtp_user and smtp_pass:
                            server.login(smtp_user, smtp_pass)

                        server.send_message(msg)
                        server.quit()
                    except Exception:
                        # don't fail subscription on email send failure
                        pass

                return jsonify({'status': 'subscribed', 'email': email})
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/subscriptions')
        def list_subscriptions():
            """Return list of subscribed emails"""
            try:
                subs = self.db.list_subscriptions()
                return jsonify({'subscriptions': subs})
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/unsubscribe', methods=['POST'])
        def unsubscribe():
            """Remove an email subscription"""
            try:
                data = request.get_json(force=True)
                email = (data or {}).get('email')
                if not email:
                    return jsonify({'error': 'email required'}), 400
                removed = self.db.remove_subscription(email)
                if removed:
                    return jsonify({'status': 'unsubscribed', 'email': email})
                else:
                    return jsonify({'status': 'not_found', 'email': email}), 404
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/test-alert', methods=['POST'])
        def test_alert():
            """Send a test alert email to verify SMTP configuration"""
            try:
                data = request.get_json(force=True) or {}
                email = data.get('email') or (self.config.alert_email.get('to')[0] if isinstance(self.config.alert_email, dict) and self.config.alert_email.get('to') else None)
                
                if not email:
                    return jsonify({'error': 'No recipient email configured'}), 400

                # Send test alert via the alert system (MEDIUM threat level)
                self.alerts.send_alert(
                    f'Test alert from HoneyPot Dashboard at {datetime.now().isoformat()}',
                    threat_level=3,
                    client_ip='127.0.0.1'
                )
                
                return jsonify({'status': 'test_alert_sent', 'email': email})
            except Exception as e:
                return jsonify({'error': str(e)}), 500

    
    def run(self):
        """Start the dashboard"""
        print(f"Starting Dashboard on http://localhost:{self.port}")
        self.app.run(host='0.0.0.0', port=self.port, debug=False)


if __name__ == '__main__':
    dashboard = Dashboard()
    dashboard.run()
