#!/usr/bin/env python3
"""Test script to simulate attacks on the honeypot"""
import socket
import time
import sys

def test_ssh():
    """Test SSH port"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('localhost', 22))
        s.send(b'SSH-2.0-OpenSSH_7.4\r\n')
        s.send(b'admin:password\r\n')
        data = s.recv(1024)
        s.close()
        print("[+] SSH test sent - connection successful")
        return True
    except Exception as e:
        print(f"[-] SSH test failed: {e}")
        return False

def test_telnet():
    """Test Telnet port"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('localhost', 23))
        s.send(b'admin\r\n')
        s.send(b'password\r\n')
        data = s.recv(1024)
        s.close()
        print("[+] Telnet test sent - connection successful")
        return True
    except Exception as e:
        print(f"[-] Telnet test failed: {e}")
        return False

def test_http():
    """Test HTTP port with suspicious request"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('localhost', 80))
        request = b"GET /admin?id=1' OR '1'='1 HTTP/1.1\r\nHost: localhost\r\n\r\n"
        s.send(request)
        data = s.recv(1024)
        s.close()
        print("[+] HTTP test sent - SQL injection attempt")
        return True
    except Exception as e:
        print(f"[-] HTTP test failed: {e}")
        return False

def test_ftp():
    """Test FTP port"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('localhost', 21))
        s.send(b'USER admin\r\n')
        s.send(b'PASS wrongpass\r\n')
        data = s.recv(1024)
        s.close()
        print("[+] FTP test sent - brute force attempt")
        return True
    except Exception as e:
        print(f"[-] FTP test failed: {e}")
        return False

def test_rdp():
    """Test RDP port"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('localhost', 3389))
        # Send TPKT header
        s.send(b'\x03\x00\x00\x13\x0eE0\x81\x0a\x06\x09\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x09')
        data = s.recv(1024)
        s.close()
        print("[+] RDP test sent - BlueKeep detection attempt")
        return True
    except Exception as e:
        print(f"[-] RDP test failed: {e}")
        return False

if __name__ == "__main__":
    print("=" * 50)
    print("Honeypot Test Suite")
    print("=" * 50)
    
    tests = [
        ("SSH", test_ssh),
        ("Telnet", test_telnet),
        ("HTTP", test_http),
        ("FTP", test_ftp),
        ("RDP", test_rdp),
    ]
    
    for name, test_func in tests:
        print(f"\nTesting {name}...", flush=True)
        test_func()
        time.sleep(0.5)
    
    print("\n" + "=" * 50)
    print("Tests completed! Check dashboard for results.")
    print("=" * 50)
