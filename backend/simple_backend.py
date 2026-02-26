#!/usr/bin/env python3
import json
import threading
import time
import sys
import os
import socket
import logging
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import random

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Simulated packet data for demo
demo_packets = []
demo_active = False

def generate_demo_packet():
    """Generate realistic demo packet"""
    protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS']
    
    # Generate realistic IPs
    src_ip = f"192.168.1.{random.randint(2, 254)}"
    dst_ips = [
        f"8.8.{random.randint(4, 8)}.{random.randint(4, 8)}",  # Google DNS
        f"1.1.1.{random.randint(1, 4)}",  # Cloudflare
        f"208.67.{random.randint(220, 222)}.{random.randint(220, 222)}",  # OpenDNS
        f"74.125.{random.randint(1, 255)}.{random.randint(1, 255)}",  # Google
        f"151.101.{random.randint(1, 255)}.{random.randint(1, 255)}",  # Reddit/Fastly
        f"172.217.{random.randint(1, 255)}.{random.randint(1, 255)}",  # Google
        f"13.{random.randint(32, 107)}.{random.randint(1, 255)}.{random.randint(1, 255)}"  # AWS
    ]
    
    protocol = random.choice(protocols)
    is_tor = random.random() < 0.15  # 15% TOR traffic
    
    if is_tor:
        dst_port = random.choice([9001, 9030, 443, 80])
        protocol = random.choice(['TCP', 'HTTPS'])
    else:
        dst_port = random.choice([80, 443, 53, 22, 21, 25, 110, 143, 993, 995])
    
    return {
        'protocol': protocol,
        'src_ip': src_ip,
        'dst_ip': random.choice(dst_ips),
        'src_port': random.randint(1024, 65535),
        'dst_port': dst_port,
        'length': random.randint(64, 1500),
        'size': random.randint(64, 1500),
        'timestamp': datetime.now().isoformat(),
        'is_tor': is_tor,
        'flags': random.choice(['SYN', 'ACK', 'FIN', 'PSH', 'RST']),
        'ttl': random.randint(32, 128),
        'checksum': f"0x{random.randint(0, 65535):04x}",
        'window_size': random.randint(1024, 65535)
    }

def demo_packet_generator():
    """Background thread to generate demo packets"""
    global demo_packets, demo_active
    
    while demo_active:
        for _ in range(random.randint(1, 3)):
            if not demo_active:
                break
            packet = generate_demo_packet()
            demo_packets.append(packet)
            
            if len(demo_packets) > 1000:
                demo_packets = demo_packets[-1000:]
        
        time.sleep(1)

class Handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Access-Control-Max-Age', '86400')
        self.end_headers()

    def do_GET(self):
        """Handle GET requests"""
        global demo_packets, demo_active
        
        if self.path == '/' or self.path == '/index.html':
            self.serve_file('index.html', 'text/html')
            return
        elif self.path.endswith('.js'):
            self.serve_file(self.path[1:], 'application/javascript')
            return
        elif self.path.endswith('.css'):
            self.serve_file(self.path[1:], 'text/css')
            return
        elif self.path.endswith('.html'):
            self.serve_file(self.path[1:], 'text/html')
            return
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()
        
        if self.path == '/api/health':
            data = {
                'status': 'healthy',
                'sniffer_available': True,
                'sniffer_active': demo_active,
                'sniffer_mode': 'demo',
                'tor_connected': False,
                'admin_required': False,
                'is_admin': True
            }
        elif self.path.startswith('/api/packets') or self.path.startswith('/api/capture/packets'):
            from urllib.parse import parse_qs, urlparse
            query = parse_qs(urlparse(self.path).query)
            limit = int(query.get('limit', ['50'])[0])
            
            packets = demo_packets[-limit:] if len(demo_packets) > limit else demo_packets
            data = packets
        elif self.path == '/api/geo/packets':
            geo_packets = []
            for packet in demo_packets[-20:]:
                if packet.get('dst_ip') and not packet['dst_ip'].startswith(('192.168.', '10.', '127.')):
                    geo_data = self.lookup_ip_location(packet['dst_ip'])
                    geo_packets.append({
                        'src_ip': packet['src_ip'],
                        'dst_ip': packet['dst_ip'],
                        'protocol': packet['protocol'],
                        'is_tor': packet.get('is_tor', False),
                        'location': geo_data['location']
                    })
            data = geo_packets
        elif self.path.startswith('/api/geo/lookup'):
            from urllib.parse import parse_qs, urlparse
            query = parse_qs(urlparse(self.path).query)
            ip = query.get('ip', [''])[0]
            data = self.lookup_ip_location(ip)
        elif self.path == '/api/tor/connect':
            data = {
                'status': 'success',
                'message': 'TOR connection simulated',
                'tor_connected': True
            }
        else:
            data = {'error': 'Not found'}

        try:
            response_data = json.dumps(data, default=str)
            self.wfile.write(response_data.encode())
        except Exception as e:
            try:
                error_data = json.dumps({'error': 'Response error'}, default=str)
                self.wfile.write(error_data.encode())
            except:
                pass

    def do_POST(self):
        """Handle POST requests"""
        global demo_active, demo_packets
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()
        
        try:
            if self.path == '/api/capture/start':
                if demo_active:
                    data = {'status': 'already_running', 'message': 'Demo capture already active'}
                else:
                    demo_active = True
                    demo_packets = []
                    threading.Thread(target=demo_packet_generator, daemon=True).start()
                    data = {'status': 'started', 'message': 'Demo packet capture started'}
            elif self.path == '/api/capture/stop':
                demo_active = False
                packet_count = len(demo_packets)
                data = {'status': 'stopped', 'packets_captured': packet_count}
            elif self.path == '/api/tor/correlate':
                tor_packets = [p for p in demo_packets if p.get('is_tor', False)]
                unique_ips = set(p['dst_ip'] for p in demo_packets if p.get('dst_ip') and not p['dst_ip'].startswith(('192.168.', '10.', '127.')))
                
                data = {
                    'status': 'success',
                    'results': {
                        'statistics': {
                            'total_packets': len(demo_packets),
                            'total_tor_packets': len(tor_packets),
                            'total_circuits': random.randint(5, 15),
                            'unique_entry_nodes': random.randint(3, 8),
                            'unique_exit_nodes': random.randint(3, 6),
                            'unique_relay_nodes': random.randint(8, 15),
                            'correlations_found': random.randint(2, 8),
                            'unique_destinations': len(unique_ips)
                        },
                        'confidence_scores': {
                            'overall_confidence': random.uniform(75, 95)
                        },
                        'circuits': [
                            {'confidence': random.randint(80, 95), 'total_packets': random.randint(20, 50)},
                            {'confidence': random.randint(70, 85), 'total_packets': random.randint(15, 35)},
                            {'confidence': random.randint(75, 90), 'total_packets': random.randint(10, 30)}
                        ],
                        'connections': [
                            {
                                'src_ip': '192.168.1.100',
                                'dst_ip': random.choice(list(unique_ips)) if unique_ips else '185.220.101.45',
                                'tor_confidence': random.randint(85, 98),
                                'tor_reasons': ['TOR relay IP', 'Port 9001', 'Timing correlation']
                            },
                            {
                                'src_ip': '192.168.1.100', 
                                'dst_ip': random.choice(list(unique_ips)) if unique_ips else '199.87.154.255',
                                'tor_confidence': random.randint(75, 92),
                                'tor_reasons': ['HTTPS pattern', 'Traffic analysis', 'Node fingerprint']
                            }
                        ],
                        'user_ips': list(set(p['src_ip'] for p in tor_packets)),
                        'destination_ips': list(unique_ips)[:10],
                        'accuracy': random.uniform(80, 95)
                    }
                }
            else:
                data = {'error': 'Not found'}
            
            response_data = json.dumps(data, default=str)
            self.wfile.write(response_data.encode())
            
        except Exception as e:
            error_data = {'status': 'error', 'message': str(e)}
            self.wfile.write(json.dumps(error_data).encode())

    def serve_file(self, filename, content_type):
        """Serve static files from the parent directory"""
        try:
            file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), filename)
            if os.path.exists(file_path):
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                with open(file_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'File not found')
        except Exception as e:
            self.send_error(500, str(e))

    def lookup_ip_location(self, ip):
        """Lookup IP location with enhanced data"""
        if not ip or ip in ['127.0.0.1', 'localhost', '0.0.0.0']:
            return {
                'location': {
                    'lat': 28.6139,
                    'lng': 77.2090,
                    'city': 'New Delhi',
                    'country': 'India',
                    'flag': '🇮🇳'
                }
            }
        
        # Enhanced known locations with flags
        known_locations = {
            '8.8.8.8': {'lat': 37.4056, 'lng': -122.0775, 'city': 'Mountain View', 'country': 'United States', 'flag': '🇺🇸'},
            '8.8.4.4': {'lat': 37.4056, 'lng': -122.0775, 'city': 'Mountain View', 'country': 'United States', 'flag': '🇺🇸'},
            '1.1.1.1': {'lat': -33.8688, 'lng': 151.2093, 'city': 'Sydney', 'country': 'Australia', 'flag': '🇦🇺'},
            '208.67.222.222': {'lat': 37.7749, 'lng': -122.4194, 'city': 'San Francisco', 'country': 'United States', 'flag': '🇺🇸'},
            '74.125.224.72': {'lat': 37.4056, 'lng': -122.0775, 'city': 'Mountain View', 'country': 'United States', 'flag': '🇺🇸'},
            '151.101.193.140': {'lat': 37.7749, 'lng': -122.4194, 'city': 'San Francisco', 'country': 'United States', 'flag': '🇺🇸'},
            '172.217.164.110': {'lat': 37.4056, 'lng': -122.0775, 'city': 'Mountain View', 'country': 'United States', 'flag': '🇺🇸'}
        }
        
        if ip in known_locations:
            return {'location': known_locations[ip]}
        
        # Generate realistic locations based on IP ranges
        parts = ip.split('.')
        if len(parts) == 4:
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            # More diverse location mapping
            locations = [
                {'lat': 51.5074, 'lng': -0.1278, 'city': 'London', 'country': 'United Kingdom', 'flag': '🇬🇧'},
                {'lat': 48.8566, 'lng': 2.3522, 'city': 'Paris', 'country': 'France', 'flag': '🇫🇷'},
                {'lat': 52.5200, 'lng': 13.4050, 'city': 'Berlin', 'country': 'Germany', 'flag': '🇩🇪'},
                {'lat': 35.6762, 'lng': 139.6503, 'city': 'Tokyo', 'country': 'Japan', 'flag': '🇯🇵'},
                {'lat': 40.7128, 'lng': -74.0060, 'city': 'New York', 'country': 'United States', 'flag': '🇺🇸'},
                {'lat': 34.0522, 'lng': -118.2437, 'city': 'Los Angeles', 'country': 'United States', 'flag': '🇺🇸'},
                {'lat': 55.7558, 'lng': 37.6176, 'city': 'Moscow', 'country': 'Russia', 'flag': '🇷🇺'},
                {'lat': 39.9042, 'lng': 116.4074, 'city': 'Beijing', 'country': 'China', 'flag': '🇨🇳'},
                {'lat': 52.3676, 'lng': 4.9041, 'city': 'Amsterdam', 'country': 'Netherlands', 'flag': '🇳🇱'},
                {'lat': 59.3293, 'lng': 18.0686, 'city': 'Stockholm', 'country': 'Sweden', 'flag': '🇸🇪'}
            ]
            
            # Use IP to deterministically select location
            location_index = (first_octet + second_octet) % len(locations)
            return {'location': locations[location_index]}
        
        return {
            'location': {
                'lat': 0,
                'lng': 0,
                'city': 'Unknown',
                'country': 'Unknown',
                'flag': '🌍'
            }
        }

    def log_message(self, format, *args):
        pass

def run_server():
    """Run the HTTP server"""
    print("Starting TOR Unveil Enhanced Backend...")
    print("Demo mode enabled for packet generation")
    print("Starting server on port 5000...")
    
    server = HTTPServer(('', 5000), Handler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    print("Backend ready at http://localhost:5000")
    print("Open http://localhost:5000/index.html to view dashboard")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
    except Exception as e:
        print(f"[SERVER] Error: {e}")
    finally:
        global demo_active
        demo_active = False
        try:
            server.shutdown()
            server.server_close()
        except:
            pass

if __name__ == '__main__':
    run_server()