#!/usr/bin/env python3
"""
Simple Traffic Generator for TOR Unveil Testing
Generates realistic network traffic including simulated TOR traffic
"""

import socket
import threading
import time
import random
import requests
from datetime import datetime

class TrafficGenerator:
    def __init__(self):
        self.running = False
        self.thread = None
        
    def start(self):
        """Start generating traffic"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._generate_traffic, daemon=True)
        self.thread.start()
        print("[TRAFFIC] Traffic generator started")
    
    def stop(self):
        """Stop generating traffic"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[TRAFFIC] Traffic generator stopped")
    
    def _generate_traffic(self):
        """Generate various types of network traffic"""
        while self.running:
            try:
                # Generate different types of traffic
                traffic_type = random.choice(['http', 'https', 'dns', 'tor_sim'])
                
                if traffic_type == 'http':
                    self._generate_http_traffic()
                elif traffic_type == 'https':
                    self._generate_https_traffic()
                elif traffic_type == 'dns':
                    self._generate_dns_traffic()
                elif traffic_type == 'tor_sim':
                    self._generate_tor_simulation()
                
                # Wait between requests
                time.sleep(random.uniform(0.5, 3.0))
                
            except Exception as e:
                print(f"[TRAFFIC] Error: {e}")
                time.sleep(1)
    
    def _generate_http_traffic(self):
        """Generate HTTP traffic"""
        try:
            urls = [
                'http://httpbin.org/get',
                'http://example.com',
                'http://httpforever.com'
            ]
            url = random.choice(urls)
            response = requests.get(url, timeout=5)
            print(f"[TRAFFIC] HTTP: {url} -> {response.status_code}")
        except:
            pass
    
    def _generate_https_traffic(self):
        """Generate HTTPS traffic"""
        try:
            urls = [
                'https://httpbin.org/get',
                'https://www.google.com',
                'https://github.com',
                'https://stackoverflow.com'
            ]
            url = random.choice(urls)
            response = requests.get(url, timeout=5)
            print(f"[TRAFFIC] HTTPS: {url} -> {response.status_code}")
        except:
            pass
    
    def _generate_dns_traffic(self):
        """Generate DNS lookups"""
        try:
            domains = [
                'google.com',
                'github.com',
                'stackoverflow.com',
                'reddit.com',
                'wikipedia.org'
            ]
            domain = random.choice(domains)
            socket.gethostbyname(domain)
            print(f"[TRAFFIC] DNS: {domain}")
        except:
            pass
    
    def _generate_tor_simulation(self):
        """Simulate TOR-like traffic patterns"""
        try:
            # Simulate connection to TOR-like ports
            tor_ips = [
                '185.220.101.32',  # Known TOR relay
                '199.87.154.255',  # Known TOR relay
                '176.10.104.240',  # Known TOR relay
                '51.15.43.205',    # Potential TOR relay
                '95.216.163.36'    # Potential TOR relay
            ]
            
            tor_ports = [9001, 9030, 443, 80]
            
            ip = random.choice(tor_ips)
            port = random.choice(tor_ports)
            
            # Attempt connection (will likely fail, but generates traffic)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            try:
                sock.connect((ip, port))
                print(f"[TRAFFIC] TOR SIM: Connected to {ip}:{port}")
            except:
                print(f"[TRAFFIC] TOR SIM: Attempted {ip}:{port}")
            finally:
                sock.close()
        except:
            pass

def main():
    """Main function for standalone usage"""
    generator = TrafficGenerator()
    
    try:
        print("Starting TOR Unveil Traffic Generator...")
        print("This will generate realistic network traffic for testing")
        print("Press Ctrl+C to stop")
        
        generator.start()
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping traffic generator...")
        generator.stop()

if __name__ == '__main__':
    main()