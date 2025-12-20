#!/usr/bin/env python3
import json
import socket
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from urllib.parse import urlparse, parse_qs

class TORController:
    def __init__(self, host='127.0.0.1', port=9051):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        
    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.connect((self.host, self.port))
            
            # Authenticate (assuming no password for demo)
            self.send_command('AUTHENTICATE ""')
            response = self.read_response()
            
            if '250 OK' in response:
                self.connected = True
                print(f"[TOR] Connected to control port {self.host}:{self.port}")
                return True
            else:
                print(f"[TOR] Authentication failed: {response}")
                return False
                
        except Exception as e:
            print(f"[TOR] Connection failed: {e}")
            self.connected = False
            return False
    
    def send_command(self, command):
        if not self.socket:
            return None
        try:
            self.socket.send(f"{command}\r\n".encode())
        except Exception as e:
            print(f"[TOR] Send error: {e}")
            self.connected = False
    
    def read_response(self):
        if not self.socket:
            return ""
        try:
            response = ""
            while True:
                data = self.socket.recv(1024).decode()
                response += data
                if '250 OK' in data or '250-' not in data:
                    break
            return response
        except Exception as e:
            print(f"[TOR] Read error: {e}")
            return ""
    
    def get_circuits(self):
        if not self.connected:
            return []
        
        self.send_command('GETINFO circuit-status')
        response = self.read_response()
        
        circuits = []
        for line in response.split('\n'):
            if line.startswith('250+circuit-status=') or line.startswith('250-circuit-status='):
                continue
            if line.strip() and not line.startswith('250'):
                parts = line.strip().split()
                if len(parts) >= 3:
                    circuits.append({
                        'id': parts[0],
                        'status': parts[1],
                        'path': parts[2] if len(parts) > 2 else '',
                        'created_at': datetime.now().isoformat()
                    })
        
        return circuits[:10]  # Limit to 10 circuits
    
    def get_relays(self):
        if not self.connected:
            return []
        
        self.send_command('GETINFO ns/all')
        response = self.read_response()
        
        relays = []
        current_relay = {}
        
        for line in response.split('\n'):
            if line.startswith('r '):
                if current_relay:
                    relays.append(current_relay)
                parts = line.split()
                if len(parts) >= 8:
                    current_relay = {
                        'nickname': parts[1],
                        'fingerprint': parts[2],
                        'ip': parts[6],
                        'or_port': parts[7],
                        'dir_port': parts[8] if len(parts) > 8 else '0'
                    }
            elif line.startswith('s ') and current_relay:
                current_relay['flags'] = line[2:].split()
        
        if current_relay:
            relays.append(current_relay)
        
        return relays[:20]  # Limit to 20 relays

class PacketSniffer:
    def __init__(self):
        self.active = False
        self.packets_captured = 0
        self.tor_packets = 0
        self.start_time = None
        
    def start_sniffing(self):
        if self.active:
            return False
        
        self.active = True
        self.start_time = datetime.now()
        self.packets_captured = 0
        self.tor_packets = 0
        
        # Start background thread for packet simulation
        threading.Thread(target=self._simulate_capture, daemon=True).start()
        print("[SNIFFER] Packet capture started")
        return True
    
    def stop_sniffing(self):
        self.active = False
        print("[SNIFFER] Packet capture stopped")
    
    def _simulate_capture(self):
        """Simulate packet capture for demo purposes"""
        while self.active:
            time.sleep(0.1)  # Simulate 10 packets per second
            self.packets_captured += 1
            
            # Simulate TOR traffic (about 20% of packets)
            if self.packets_captured % 5 == 0:
                self.tor_packets += 1
    
    def get_stats(self):
        return {
            'active': self.active,
            'packets_captured': self.packets_captured,
            'tor_packets': self.tor_packets,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'duration': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        }

class EnhancedHandler(BaseHTTPRequestHandler):
    tor_controller = None
    packet_sniffer = None
    
    @classmethod
    def initialize(cls):
        cls.tor_controller = TORController()
        cls.packet_sniffer = PacketSniffer()
        
        # Try to connect to TOR
        cls.tor_controller.connect()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-API-KEY')
        self.end_headers()

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query)
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        if path == '/api/health':
            response = {
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'version': '2.0.0-enhanced',
                'tor_connected': self.tor_controller.connected,
                'sniffer_available': True,
                'sniffer_active': self.packet_sniffer.active
            }
        
        elif path == '/api/status':
            sniffer_stats = self.packet_sniffer.get_stats()
            response = {
                'status': 'operational',
                'tor_connected': self.tor_controller.connected,
                'packets_captured': sniffer_stats['packets_captured'],
                'tor_packets': sniffer_stats['tor_packets'],
                'sniffer_active': sniffer_stats['active'],
                'uptime': sniffer_stats['duration'],
                'timestamp': datetime.now().isoformat()
            }
        
        elif path == '/api/circuits':
            circuits = self.tor_controller.get_circuits()
            response = {
                'count': len(circuits),
                'circuits': circuits,
                'tor_connected': self.tor_controller.connected
            }
        
        elif path == '/api/relays':
            relays = self.tor_controller.get_relays()
            response = {
                'count': len(relays),
                'relays': relays,
                'tor_connected': self.tor_controller.connected
            }
        
        elif path == '/api/sniffer/start':
            success = self.packet_sniffer.start_sniffing()
            response = {
                'status': 'success' if success else 'already_running',
                'message': 'Packet capture started' if success else 'Sniffer already running'
            }
        
        elif path == '/api/sniffer/stop':
            self.packet_sniffer.stop_sniffing()
            response = {
                'status': 'success',
                'message': 'Packet capture stopped'
            }
        
        elif path == '/api/sniffer/stats':
            response = self.packet_sniffer.get_stats()
        
        elif path == '/api/tor/reconnect':
            success = self.tor_controller.connect()
            response = {
                'status': 'success' if success else 'failed',
                'connected': self.tor_controller.connected,
                'message': 'TOR connection established' if success else 'Failed to connect to TOR'
            }
        
        elif path.startswith('/api/trace'):
            exit_fp = query_params.get('exit', [''])[0]
            if exit_fp:
                # Simulate correlation analysis
                response = {
                    'exit_fingerprint': exit_fp,
                    'correlations': [
                        {
                            'entry_node': '192.168.1.100',
                            'confidence': 0.85,
                            'timestamp': datetime.now().isoformat()
                        }
                    ],
                    'analysis_time': 2.3
                }
            else:
                response = {'error': 'Exit fingerprint required'}
        
        else:
            response = {
                'error': 'Endpoint not found',
                'available_endpoints': [
                    '/api/health', '/api/status', '/api/circuits', '/api/relays',
                    '/api/sniffer/start', '/api/sniffer/stop', '/api/sniffer/stats',
                    '/api/tor/reconnect', '/api/trace?exit=<fingerprint>'
                ]
            }
        
        self.wfile.write(json.dumps(response, indent=2).encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        if self.path == '/api/report/generate':
            response = {
                'status': 'success',
                'report_id': 'RPT_' + datetime.now().strftime('%Y%m%d_%H%M%S'),
                'report_url': '/api/report/download/enhanced_report.html',
                'message': 'Enhanced report generated successfully'
            }
        else:
            response = {'status': 'success', 'message': 'POST request received'}
        
        self.wfile.write(json.dumps(response).encode())
    
    def log_message(self, format, *args):
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] {format % args}")

def main():
    print("=" * 50)
    print("TOR Unveil Enhanced Backend v2.0")
    print("=" * 50)
    
    # Initialize components
    EnhancedHandler.initialize()
    
    print(f"[SERVER] Starting on port 5000...")
    server = HTTPServer(('', 5000), EnhancedHandler)
    
    print(f"[SERVER] Backend running at http://localhost:5000")
    print(f"[TOR] Control port: {'Connected' if EnhancedHandler.tor_controller.connected else 'Disconnected'}")
    print(f"[SNIFFER] Packet capture: Available")
    print("\nAvailable endpoints:")
    print("  GET  /api/health - System health check")
    print("  GET  /api/status - Current status")
    print("  GET  /api/circuits - TOR circuits")
    print("  GET  /api/relays - TOR relays")
    print("  GET  /api/sniffer/start - Start packet capture")
    print("  GET  /api/sniffer/stop - Stop packet capture")
    print("  GET  /api/tor/reconnect - Reconnect to TOR")
    print("\nPress Ctrl+C to stop...")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
        if EnhancedHandler.packet_sniffer:
            EnhancedHandler.packet_sniffer.stop_sniffing()
        server.shutdown()

if __name__ == '__main__':
    main()