"""
Database layer for HoneyPot
SQLite database to store sessions and attack data
"""

import sqlite3
from datetime import datetime, timedelta
import json


class Database:
    """SQLite database manager"""
    
    def __init__(self, db_path='honeypot.db'):
        """Initialize database"""
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Create tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_id INTEGER NOT NULL,
                client_ip TEXT NOT NULL,
                client_port INTEGER NOT NULL,
                service TEXT NOT NULL,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                duration_seconds REAL,
                command_count INTEGER DEFAULT 0,
                threat_level INTEGER DEFAULT 0,
                raw_data BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_client_ip ON sessions(client_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_start_time ON sessions(start_time)')
        
        # Commands table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                command TEXT NOT NULL,
                threat_level INTEGER DEFAULT 0,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_session_id ON commands(session_id)')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                client_ip TEXT NOT NULL,
                threat_level INTEGER NOT NULL,
                message TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'new',
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_level ON alerts(threat_level)')
        
        # Statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric TEXT NOT NULL,
                value INTEGER NOT NULL,
                date_recorded TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_metric ON statistics(metric)')

        # Subscriptions table for alert email addresses
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sub_email ON subscriptions(email)')
        
        conn.commit()
        conn.close()
    
    def store_session(self, session_data):
        """Store session data in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            duration = (session_data['end_time'] - session_data['start_time']).total_seconds()
            threat_level = session_data.get('threat_level', 0)
            raw_data = session_data.get('raw_data', b'') or b''
            
            cursor.execute('''
                INSERT INTO sessions 
                (connection_id, client_ip, client_port, service, start_time, end_time, 
                 duration_seconds, command_count, threat_level, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_data['connection_id'],
                session_data['client_ip'],
                session_data['client_port'],
                session_data['service'],
                session_data['start_time'],
                session_data['end_time'],
                duration,
                len(session_data['commands']),
                threat_level,
                sqlite3.Binary(raw_data)
            ))
            
            session_id = cursor.lastrowid
            
            # Store commands
            for cmd in session_data['commands']:
                if isinstance(cmd, dict):
                    command_text = cmd.get('command', '')
                    command_threat = cmd.get('threat_level', 0)
                else:
                    command_text = str(cmd)
                    command_threat = 0
                cursor.execute('''
                    INSERT INTO commands (session_id, command, threat_level)
                    VALUES (?, ?, ?)
                ''', (session_id, command_text, command_threat))
            
            conn.commit()
            return session_id
        finally:
            conn.close()
    
    def store_alert(self, alert_data):
        """Store alert in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO alerts 
                (session_id, client_ip, threat_level, message)
                VALUES (?, ?, ?, ?)
            ''', (
                alert_data.get('session_id'),
                alert_data['client_ip'],
                alert_data['threat_level'],
                alert_data['message']
            ))
            conn.commit()
        finally:
            conn.close()
    
    def cleanup_old_data(self, days=30):
        """Delete sessions, commands, alerts, and statistics older than the cutoff"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cutoff = datetime.now() - timedelta(days=days)
            cutoff_value = cutoff.isoformat(sep=' ')
            
            cursor.execute('SELECT id FROM sessions WHERE start_time < ?', (cutoff_value,))
            old_session_ids = [row[0] for row in cursor.fetchall()]
            deleted_commands = 0
            deleted_alerts = 0
            deleted_sessions = 0
            
            if old_session_ids:
                placeholders = ','.join('?' for _ in old_session_ids)
                cursor.execute(f'DELETE FROM commands WHERE session_id IN ({placeholders})', old_session_ids)
                deleted_commands = cursor.rowcount
                cursor.execute(f'DELETE FROM alerts WHERE session_id IN ({placeholders})', old_session_ids)
                deleted_alerts += cursor.rowcount
                cursor.execute(f'DELETE FROM sessions WHERE id IN ({placeholders})', old_session_ids)
                deleted_sessions = cursor.rowcount
            
            cursor.execute('DELETE FROM alerts WHERE timestamp < ?', (cutoff_value,))
            deleted_alerts += cursor.rowcount
            cursor.execute('DELETE FROM statistics WHERE date_recorded < ?', (cutoff_value,))
            deleted_stats = cursor.rowcount
            
            conn.commit()
            return {
                'sessions': deleted_sessions,
                'commands': deleted_commands,
                'alerts': deleted_alerts,
                'statistics': deleted_stats
            }
        finally:
            conn.close()
    
    def get_sessions(self, limit=100, offset=0):
        """Get recent sessions"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM sessions
            ORDER BY start_time DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        
        rows = cursor.fetchall()
        conn.close()
        
        sessions = []
        for row in rows:
            session = dict(row)
            raw_data = session.get('raw_data')
            if isinstance(raw_data, (bytes, bytearray)):
                session['raw_data'] = raw_data.decode('utf-8', errors='replace')
            sessions.append(session)
        return sessions

    def get_session_details(self, session_id):
        """Get detailed session information"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM sessions WHERE id = ?', (session_id,))
        row = cursor.fetchone()
        if row is None:
            conn.close()
            raise ValueError(f"Session with id {session_id} not found")
        session = dict(row)
        
        raw_data = session.get('raw_data')
        if isinstance(raw_data, (bytes, bytearray)):
            session['raw_data'] = raw_data.decode('utf-8', errors='replace')
        
        cursor.execute('SELECT * FROM commands WHERE session_id = ? ORDER BY timestamp', (session_id,))
        commands = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        session['commands'] = commands
        return session

    def get_alerts(self, limit=100, offset=0):
        """Get recent alerts"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM alerts
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_stats(self):
        """Get statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        cursor.execute('SELECT COUNT(*) FROM sessions')
        stats['total_sessions'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(DISTINCT client_ip) FROM sessions')
        stats['unique_ips'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM alerts')
        stats['total_alerts'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE status = "new"')
        stats['new_alerts'] = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT service, COUNT(*) as count 
            FROM sessions 
            GROUP BY service
        ''')
        stats['by_service'] = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        return stats

    def get_alert_counts_by_level(self):
        """Get alert counts grouped by threat level"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT threat_level, COUNT(*) as count
            FROM alerts
            GROUP BY threat_level
            ORDER BY threat_level DESC
        ''')
        rows = cursor.fetchall()
        conn.close()
        return {int(row[0]): row[1] for row in rows}

    def add_subscription(self, email):
        """Add an email subscription (no duplicates). Returns lastrowid or 0 if ignored."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT OR IGNORE INTO subscriptions (email) VALUES (?)', (email,))
            conn.commit()
            return cursor.lastrowid or 0
        finally:
            conn.close()

    def remove_subscription(self, email):
        """Remove an email subscription. Returns number of rows deleted."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('DELETE FROM subscriptions WHERE email = ?', (email,))
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    def list_subscriptions(self):
        """Return list of subscriptions as dicts."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT email, created_at FROM subscriptions ORDER BY created_at DESC')
            rows = cursor.fetchall()
            return [{'email': r[0], 'created_at': r[1]} for r in rows]
        finally:
            conn.close()

    def enforce_max_sessions(self, max_sessions=10000):
        """Remove oldest sessions to keep only the most recent max_sessions"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM sessions')
        total_sessions = cursor.fetchone()[0]

        if total_sessions > max_sessions:
            cursor.execute('''
                DELETE FROM sessions
                WHERE id IN (
                    SELECT id FROM sessions
                    ORDER BY timestamp ASC
                    LIMIT ?
                )
            ''', (total_sessions - max_sessions,))
            conn.commit()

        conn.close()

    def get_session_counts_by_service(self):
        """Get session counts grouped by service"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT service, COUNT(*) as count
            FROM sessions
            GROUP BY service
        ''')
        rows = cursor.fetchall()
        conn.close()
        return {row[0]: row[1] for row in rows}
