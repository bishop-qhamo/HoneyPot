import socketserver
import threading
import sys
import tempfile
import time

sys.path.insert(0, r"c:\Users\Murungi\OneDrive\My Projects")

from config import Config
from database import Database
from logger import Logger
from alert_system import AlertSystem

class SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b'220 localhost Simple SMTP Service\r\n')
        received_data = []
        while True:
            line = self.rfile.readline()
            if not line:
                break
            cmd = line.decode('utf-8', errors='ignore').strip()
            if cmd.upper().startswith('EHLO') or cmd.upper().startswith('HELO'):
                self.wfile.write(b'250-localhost\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 OK\r\n')
            elif cmd.upper().startswith('STARTTLS'):
                self.wfile.write(b'220 Ready to start TLS\r\n')
            elif cmd.upper().startswith('MAIL FROM'):
                self.wfile.write(b'250 OK\r\n')
            elif cmd.upper().startswith('RCPT TO'):
                self.wfile.write(b'250 OK\r\n')
            elif cmd.upper() == 'DATA':
                self.wfile.write(b'354 End data with <CR><LF>.<CR><LF>\r\n')
                data_lines = []
                while True:
                    data_line = self.rfile.readline()
                    if not data_line:
                        break
                    if data_line == b'.\r\n':
                        break
                    data_lines.append(data_line)
                received_data = b''.join(data_lines).decode('utf-8', errors='ignore')
                self.wfile.write(b'250 OK queued as 12345\r\n')
            elif cmd.upper().startswith('QUIT'):
                self.wfile.write(b'221 Bye\r\n')
                break
            else:
                self.wfile.write(b'250 OK\r\n')
        if received_data:
            self.server.received.append(received_data)

class SMTPServer(threading.Thread):
    def __init__(self, host='127.0.0.1', port=8025):
        super().__init__(daemon=True)
        self.server = socketserver.TCPServer((host, port), SMTPHandler)
        self.server.received = []

    def run(self):
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def main():
    smtp_server = SMTPServer()
    smtp_server.start()
    time.sleep(1)

    cfg = Config()
    cfg.data['alert_email'] = {
        'smtp_server': '127.0.0.1',
        'smtp_port': 8025,
        'from': 'alerts@example.com',
        'to': ['recipient@example.com'],
        'username': None,
        'password': None,
        'use_ssl': False,
        'use_tls': False
    }
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmpdb:
        db = Database(tmpdb.name)
        logger = Logger('logs/test_alert.log')
        alert_sys = AlertSystem(cfg, db, logger)

        alert = alert_sys.send_alert('Test alert message from automated test', threat_level=3, client_ip='127.0.0.1')
        print('Alert created:', alert)
        time.sleep(2)
        print('SMTP server received messages:', len(smtp_server.server.received))
        if smtp_server.server.received:
            print(smtp_server.server.received[0])

    smtp_server.stop()


if __name__ == '__main__':
    main()
