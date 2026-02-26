#!/usr/bin/env python3
import json
import threading
import time
import sys
import os
import socket
import logging
import requests
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, get_if_list
import ctypes

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Live packet data
live_packets = []
capture_active = False
sniffer_thread = None

# TOR relay list (sample known TOR exit nodes)
TOR_EXIT_NODES = {
    '185.220.101.45', '199.87.154.255', '185.220.102.8', '185.220.100.240',
    '185.220.101.46', '185.220.102.4', '185.220.100.241', '185.220.101.47'
}

def is_admin():
    """Check if running with admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_wifi_interface():
    """Get WiFi interface name"""
    interfaces = get_if_list()
    for iface in interfaces:
        if 'wi-fi' in iface.lower() or 'wireless' in iface.lower() or 'wlan' in iface.lower():
            return iface
    return interfaces[0] if interfaces else None

def detect_tor_traffic(packet_data):
    """Detect if packet is TOR traffic"""
    dst_ip = packet_data.get('dst_ip', '')
    dst_port = packet_data.get('dst_port', 0)
    
    # Check against known TOR exit nodes
    if dst_ip in TOR_EXIT_NODES:
        return True
    
    # Check for TOR ports
    if dst_port in [9001, 9030, 9050, 9051]:
        return True
    
    # Check for HTTPS to suspicious IPs
    if dst_port == 443 and not dst_ip.startswith(('192.168.', '10.', '127.')):
        # Simple heuristic for potential TOR traffic
        return dst_ip.split('.')[0] in ['185', '199', '176', '198']
    
    return False

def packet_handler(packet):
    """Handle captured packets"""
    global live_packets
    
    if not capture_active:
        return
    
    try:
        if IP in packet:
            ip_layer = packet[IP]
            
            packet_data = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'length': len(packet),
                'ttl': ip_layer.ttl,
                'flags': str(ip_layer.flags) if hasattr(ip_layer, 'flags') else '',
                'checksum': hex(ip_layer.chksum) if hasattr(ip_layer, 'chksum') else '0x0'
            }
            
            # Add TCP/UDP specific info
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_data.update({
                    'protocol': 'TCP',
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'flags': str(tcp_layer.flags),
                    'window_size': tcp_layer.window
                })
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_data.update({
                    'protocol': 'UDP',
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport
                })
            
            # Detect TOR traffic
            packet_data['is_tor'] = detect_tor_traffic(packet_data)
            
            # Add to packet list
            live_packets.append(packet_data)
            
            # Keep only last 1000 packets
            if len(live_packets) > 1000:
                live_packets = live_packets[-1000:]
                
    except Exception as e:
        logger.error(f"Packet processing error: {e}")

def start_packet_capture():
    """Start live packet capture"""
    global capture_active, sniffer_thread
    
    if not is_admin():
        logger.error("Admin privileges required for packet capture")
        return False
    
    wifi_interface = get_wifi_interface()
    if not wifi_interface:
        logger.error("No WiFi interface found")
        return False
    
    capture_active = True
    
    def capture_loop():
        try:
            logger.info(f"Starting packet capture on {wifi_interface}")
            sniff(iface=wifi_interface, prn=packet_handler, stop_filter=lambda x: not capture_active)
        except Exception as e:
            logger.error(f"Capture error: {e}")
            global capture_active
            capture_active = False
    
    sniffer_thread = threading.Thread(target=capture_loop, daemon=True)
    sniffer_thread.start()
    return True

def stop_packet_capture():
    """Stop packet capture"""
    global capture_active
    capture_active = False

def lookup_ip_location(ip):
    """Real IP geolocation lookup"""
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = response.json()
        
        if data['status'] == 'success':
            return {
                'status': 'success',
                'location': {
                    'lat': data['lat'],
                    'lng': data['lon'],
                    'city': data['city'],
                    'country': data['country'],
                    'flag': '🌍'  # Default flag
                }
            }
    except:
        pass
    
    # Fallback to demo data
    return {
        'status': 'success',
        'location': {
            'lat': 0,
            'lng': 0,
            'city': 'Unknown',
            'country': 'Unknown',
            'flag': '🌍'
        }
    }

class Handler(BaseHTTPRequestHandler):
    def serve_file(self, filename, content_type):
        """Serve static files"""
        try:
            file_path = Path(filename)
            if file_path.exists():
                with open(file_path, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_response(404)
                self.end_headers()
        except Exception as e:
            logger.error(f'File serve error: {e}')
            self.send_response(500)
            self.end_headers()

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
        global live_packets, capture_active
        
        if self.path == '/' or self.path == '/index.html':
            self.serve_file('../index.html', 'text/html')
            return
        elif self.path.endswith('.js'):
            self.serve_file(f'../{self.path[1:]}', 'application/javascript')
            return
        elif self.path.endswith('.css'):
            self.serve_file(f'../{self.path[1:]}', 'text/css')
            return
        elif self.path.endswith('.html'):
            self.serve_file(f'../{self.path[1:]}', 'text/html')
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
                'sniffer_active': capture_active,
                'sniffer_mode': 'live',
                'tor_connected': False,
                'admin_required': True,
                'is_admin': is_admin()
            }
        elif self.path == '/api/status':
            data = {
                'packets_captured': len(live_packets),
                'tor_packets': len([p for p in live_packets if p.get('is_tor', False)]),
                'sniffer_active': capture_active,
                'total_bytes': sum(p.get('length', 0) for p in live_packets),
                'flow_count': len(set(f"{p['src_ip']}-{p['dst_ip']}" for p in live_packets))
            }
        elif self.path.startswith('/api/packets') or self.path.startswith('/api/capture/packets'):
            from urllib.parse import parse_qs, urlparse
            query = parse_qs(urlparse(self.path).query)
            limit = int(query.get('limit', ['50'])[0])
            
            packets = live_packets[-limit:] if len(live_packets) > limit else live_packets
            data = packets
        elif self.path == '/api/geo/packets':
            geo_packets = []
            for packet in live_packets[-20:]:
                if packet.get('dst_ip') and not packet['dst_ip'].startswith(('192.168.', '10.', '127.')):
                    geo_data = lookup_ip_location(packet['dst_ip'])
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
            data = lookup_ip_location(ip)
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
            logger.error(f'GET request error: {e}')
            try:
                error_data = json.dumps({'error': str(e)}, default=str)
                self.wfile.write(error_data.encode())
            except:
                pass

    def do_POST(self):
        """Handle POST requests"""
        global capture_active, live_packets
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()
        
        try:
            if self.path == '/api/capture/start':
                if start_packet_capture():
                    data = {'status': 'started', 'message': 'Live packet capture started'}
                else:
                    data = {'status': 'error', 'message': 'Failed to start capture - Admin privileges required'}
            elif self.path == '/api/capture/stop':
                stop_packet_capture()
                data = {'status': 'stopped', 'message': 'Live packet capture stopped', 'packets_captured': len(live_packets)}
            elif self.path == '/api/tor/correlate':
                tor_packets = [p for p in live_packets if p.get('is_tor', False)]
                
                data = {
                    'status': 'success',
                    'results': {
                        'statistics': {
                            'total_packets': len(live_packets),
                            'total_tor_packets': len(tor_packets),
                            'total_circuits': len(set(p['dst_ip'] for p in tor_packets)),
                            'unique_entry_nodes': len(set(p['src_ip'] for p in tor_packets)),
                            'unique_exit_nodes': len(set(p['dst_ip'] for p in tor_packets)),
                            'unique_relay_nodes': len(TOR_EXIT_NODES)
                        },
                        'connections': [
                            {
                                'src_ip': p['src_ip'],
                                'dst_ip': p['dst_ip'],
                                'tor_confidence': 95 if p['dst_ip'] in TOR_EXIT_NODES else 75,
                                'tor_reasons': ['Known TOR exit node'] if p['dst_ip'] in TOR_EXIT_NODES else ['Port analysis', 'Traffic pattern']
                            } for p in tor_packets[:5]
                        ]
                    },
                    'message': f'Found {len(tor_packets)} TOR packets'
                }
            else:
                data = {'error': 'Endpoint not found'}
            
            response_data = json.dumps(data, default=str)
            self.wfile.write(response_data.encode())
            
        except Exception as e:
            error_data = {'status': 'error', 'message': str(e)}
            self.wfile.write(json.dumps(error_data).encode())

    def log_message(self, format, *args):
        pass

def main():
    """Main server function"""
    print("Starting TOR Unveil Live Backend...")
    print("Live packet capture mode enabled")
    
    if not is_admin():
        print("WARNING: Admin privileges required for live packet capture")
        print("Please run as administrator for full functionality")
    
    # Create necessary directories
    Path('reports').mkdir(exist_ok=True)
    
    # Start HTTP server
    port = 5000
    server = HTTPServer(('localhost', port), Handler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    logger.info(f'TOR Unveil Live Backend starting on http://localhost:{port}')
    logger.info('Features enabled:')
    logger.info('  - Live WiFi packet capture')
    logger.info('  - Real-time TOR detection')
    logger.info('  - Live geo tracking')
    logger.info('  - TOR correlation analysis')
    
    print(f"Backend ready at http://localhost:{port}")
    print("Open http://localhost:5000/index.html to view dashboard")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
        stop_packet_capture()
        server.shutdown()
    except Exception as e:
        print(f"[SERVER] Error: {e}")
    finally:
        stop_packet_capture()
        try:
            server.shutdown()
            server.server_close()
        except:
            pass

if __name__ == '__main__':
    main()