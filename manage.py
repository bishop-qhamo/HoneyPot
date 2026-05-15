#!/usr/bin/env python3
"""
Helper script to manage HoneyPot operations
Provides CLI for common tasks
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path
from database import Database
from config import Config
from datetime import datetime, timedelta


class HoneyPotCLI:
    """Command-line interface for HoneyPot management"""
    
    def __init__(self):
        self.config = Config()
        self.db = Database(self.config.db_path)
    
    def start_honeypot(self):
        """Start the honeypot server"""
        print("Starting HoneyPot server...")
        try:
            subprocess.run([sys.executable, 'honeyPot.py'])
        except KeyboardInterrupt:
            print("\nHoneyPot stopped")
    
    def start_dashboard(self):
        """Start the web dashboard"""
        print("Starting HoneyPot Dashboard...")
        print("Access at: http://localhost:5000")
        try:
            subprocess.run([sys.executable, 'dashboard.py'])
        except KeyboardInterrupt:
            print("\nDashboard stopped")
    
    def status(self):
        """Show system status"""
        stats = self.db.get_stats()
        
        print("\n" + "="*50)
        print("HoneyPot System Status")
        print("="*50)
        print(f"Total Sessions:    {stats['total_sessions']}")
        print(f"Unique IPs:        {stats['unique_ips']}")
        print(f"Total Alerts:      {stats['total_alerts']}")
        print(f"New Alerts:        {stats['new_alerts']}")
        print(f"By Service:        {stats['by_service']}")
        print("="*50 + "\n")
    
    def show_alerts(self, limit=10):
        """Show recent alerts"""
        alerts = self.db.get_alerts(limit=limit)
        
        if not alerts:
            print("No alerts found")
            return
        
        print(f"\nRecent {limit} Alerts:")
        print("-" * 80)
        
        for alert in alerts:
            threat = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][alert['threat_level'] - 1]
            print(f"[{threat:8}] {alert['timestamp']:20} | {alert['client_ip']:15} | {alert['message']}")
        
        print("-" * 80 + "\n")
    
    def show_sessions(self, limit=10):
        """Show recent sessions"""
        sessions = self.db.get_sessions(limit=limit)
        
        if not sessions:
            print("No sessions found")
            return
        
        print(f"\nRecent {limit} Sessions:")
        print("-" * 100)
        print(f"{'Timestamp':20} | {'Client IP':15} | {'Service':10} | {'Duration':10} | {'Commands':8}")
        print("-" * 100)
        
        for session in sessions:
            duration = f"{session['duration_seconds']:.1f}s" if session['duration_seconds'] else "N/A"
            print(f"{str(session['start_time'])[:19]:20} | {session['client_ip']:15} | {session['service']:10} | {duration:10} | {session['command_count']:8}")
        
        print("-" * 100 + "\n")
    
    def show_top_ips(self, limit=10):
        """Show top attacking IPs"""
        sessions = self.db.get_sessions(limit=10000)
        
        ip_counts = {}
        for session in sessions:
            ip = session['client_ip']
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        if not ip_counts:
            print("No data available")
            return
        
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        
        print(f"\nTop {limit} Attacking IPs:")
        print("-" * 40)
        print(f"{'IP Address':20} | {'Count':10}")
        print("-" * 40)
        
        for ip, count in top_ips:
            print(f"{ip:20} | {count:10}")
        
        print("-" * 40 + "\n")
    
    def show_overview(self):
        """Show threat overview and alert distribution"""
        stats = self.db.get_stats()
        alert_counts = self.db.get_alert_counts_by_level()
        service_counts = self.db.get_session_counts_by_service()

        print("\nHoneyPot Threat Overview")
        print("=" * 30)
        print(f"Total Sessions: {stats['total_sessions']}")
        print(f"Total Alerts:   {stats['total_alerts']}")
        print(f"New Alerts:     {stats['new_alerts']}\n")

        print("Alerts by Threat Level:")
        for level in sorted(alert_counts.keys(), reverse=True):
            threat_name = ['UNKNOWN', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][level] if 0 <= level <= 5 else 'UNKNOWN'
            print(f"  {threat_name:8} : {alert_counts[level]}")

        print("\nSessions by Service:")
        for service, count in service_counts.items():
            print(f"  {service:10} : {count}")
        print("=" * 30 + "\n")

    def export_data(self, format='json', days=30):
        """Export sessions from last N days"""
        cutoff_date = datetime.now() - timedelta(days=days)
        sessions = self.db.get_sessions(limit=10000)
        
        export_sessions = [s for s in sessions 
                          if isinstance(s['start_time'], str) or s['start_time'] > cutoff_date]
        
        filename = f"honeypot_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
        
        if format == 'json':
            import json
            with open(filename, 'w') as f:
                json.dump(export_sessions, f, indent=2, default=str)
        
        elif format == 'csv':
            import csv
            if export_sessions:
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=export_sessions[0].keys())
                    writer.writeheader()
                    writer.writerows(export_sessions)
        
        print(f"Data exported to: {filename}")
    
    def cleanup(self, days=30):
        """Clean up old data"""
        print(f"Cleaning data older than {days} days...")
        try:
            result = self.db.cleanup_old_data(days)
            print("Cleanup complete:")
            print(f"  Sessions removed: {result['sessions']}")
            print(f"  Commands removed: {result['commands']}")
            print(f"  Alerts removed:   {result['alerts']}")
            print(f"  Statistics removed: {result['statistics']}")
        except Exception as e:
            print(f"Cleanup failed: {e}")
    
    def create_backup(self):
        """Backup database"""
        from shutil import copy
        
        backup_name = f"honeypot_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        
        try:
            copy(self.config.db_path, backup_name)
            print(f"Database backed up to: {backup_name}")
        except Exception as e:
            print(f"Backup failed: {e}")


def main():
    parser = argparse.ArgumentParser(description='HoneyPot Management CLI')
    parser.add_argument('command', nargs='?', help='Command to run')
    parser.add_argument('--limit', type=int, default=10, help='Limit for queries')
    parser.add_argument('--days', type=int, default=30, help='Days to export/cleanup')
    parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Export format')
    
    args = parser.parse_args()
    
    cli = HoneyPotCLI()
    
    commands = {
        'honeypot': cli.start_honeypot,
        'dashboard': cli.start_dashboard,
        'status': cli.status,
        'alerts': lambda: cli.show_alerts(args.limit),
        'sessions': lambda: cli.show_sessions(args.limit),
        'top-ips': lambda: cli.show_top_ips(args.limit),
        'export': lambda: cli.export_data(args.format, args.days),
        'cleanup': lambda: cli.cleanup(args.days),
        'backup': cli.create_backup,
    }
    
    if args.command in commands:
        commands[args.command]()
    elif args.command is None:
        parser.print_help()
    else:
        print(f"Unknown command: {args.command}")
        print(f"Available commands: {', '.join(commands.keys())}")


if __name__ == '__main__':
    main()
