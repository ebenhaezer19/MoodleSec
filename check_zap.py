#!/usr/bin/env python
import socket

def check_zap():
    try:
        with socket.create_connection(('localhost', 8080), timeout=2):
            print("✅ ZAP is listening on localhost:8080")
            return True
    except Exception as e:
        print(f"❌ ZAP NOT accessible: {e}")
        return False

if __name__ == "__main__":
    check_zap()
