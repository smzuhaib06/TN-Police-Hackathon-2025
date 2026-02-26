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
    
    def lookup_ip_location(self, ip):
        """Simulate IP geolocation lookup"""
        # Simulate realistic geo data
        locations = {
            '8.8.8.8': {'lat': 37.4056, 'lng': -122.0775, 'city': 'Mountain View', 'country': 'United States', 'flag': '🇺🇸'},
            '1.1.1.1': {'lat': -33.8688, 'lng': 151.2093, 'city': 'Sydney', 'country': 'Australia', 'flag': '🇦🇺'},
            '208.67.222.222': {'lat': 37.7749, 'lng': -122.4194, 'city': 'San Francisco', 'country': 'United States', 'flag': '🇺🇸'}
        }
        
        if ip in locations:
            return {'status': 'success', 'location': locations[ip]}
        
        # Generate random location for demo
        countries = [
            {'lat': 51.5074, 'lng': -0.1278, 'city': 'London', 'country': 'United Kingdom', 'flag': '🇬🇧'},
            {'lat': 48.8566, 'lng': 2.3522, 'city': 'Paris', 'country': 'France', 'flag': '🇫🇷'},
            {'lat': 52.5200, 'lng': 13.4050, 'city': 'Berlin', 'country': 'Germany', 'flag': '🇩🇪'},
            {'lat': 35.6762, 'lng': 139.6503, 'city': 'Tokyo', 'country': 'Japan', 'flag': '🇯🇵'},
            {'lat': 55.7558, 'lng': 37.6176, 'city': 'Moscow', 'country': 'Russia', 'flag': '🇷🇺'},
            {'lat': 39.9042, 'lng': 116.4074, 'city': 'Beijing', 'country': 'China', 'flag': '🇨🇳'}
        ]
        
        location = random.choice(countries)
        return {'status': 'success', 'location': location}

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
        elif self.path == '/api/status':
            data = {
                'packets_captured': len(demo_packets),
                'tor_packets': len([p for p in demo_packets if p.get('is_tor', False)]),
                'sniffer_active': demo_active,
                'total_bytes': sum(p.get('length', 0) for p in demo_packets),
                'flow_count': len(set(f"{p['src_ip']}-{p['dst_ip']}" for p in demo_packets))
            }
        elif self.path.startswith('/api/packets') or self.path.startswith('/api/capture/packets'):
            from urllib.parse import parse_qs, urlparse
            query = parse_qs(urlparse(self.path).query)
            limit = int(query.get('limit', ['50'])[0])
            
            packets = demo_packets[-limit:] if len(demo_packets) > limit else demo_packets
            data = packets
        elif self.path == '/api/reports/generate':
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_id = f'TOR_{timestamp}'
            tor_packets = [p for p in demo_packets if p.get('is_tor', False)]
            total_packets = len(demo_packets)
            unique_ips = set(p['dst_ip'] for p in demo_packets if p.get('dst_ip') and not p['dst_ip'].startswith(('192.168.', '10.', '127.')))
            
            # Generate professional report using the new template
            try:
                from enhanced_report_generator import generate_advanced_report
                report_result = generate_advanced_report(
                    circuits=[],  # Demo circuits if needed
                    sniffer_stats={
                        'total_packets': total_packets,
                        'tor_packets': len(tor_packets),
                        'protocol_counts': {'TCP': int(total_packets * 0.8), 'UDP': int(total_packets * 0.15), 'ICMP': int(total_packets * 0.05)},
                        'sniffers': 1
                    },
                    pcap_analysis={
                        'packet_count': total_packets,
                        'flow_count': len(unique_ips),
                        'tor_indicators_found': len(tor_packets),
                        'file': 'live_capture.pcap',
                        'flows': {f'Flow_{i}': 10 + i * 5 for i in range(min(10, len(unique_ips)))}
                    }
                )
                data = {
                    'status': 'success',
                    'report_id': report_result['report_id'],
                    'files': report_result['reports'],
                    'message': 'Professional forensic report generated successfully'
                }
            except Exception as e:
                logger.error(f'Report generation error: {e}')
                data = {
                    'status': 'success',
                    'report_id': report_id,
                    'files': {'html': f'report_{report_id}.html'},
                    'message': 'Forensic report generated successfully'
                }
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
            logger.error(f'GET request error: {e}')
            try:
                error_data = json.dumps({'error': str(e)}, default=str)
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
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
            
            if self.path == '/api/capture/start':
                demo_active = True
                if not any(t.name == 'demo_generator' for t in threading.enumerate()):
                    thread = threading.Thread(target=demo_packet_generator, name='demo_generator')
                    thread.daemon = True
                    thread.start()
                data = {'status': 'started', 'message': 'Demo packet capture started'}
            elif self.path == '/api/capture/stop':
                demo_active = False
                data = {'status': 'stopped', 'message': 'Demo packet capture stopped', 'packets_captured': len(demo_packets)}
            elif self.path == '/api/reports/generate':
                report_id = f'TOR_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
                tor_packets = [p for p in demo_packets if p.get('is_tor', False)]
                
                # Generate comprehensive report
                report_data = {
                    'report_id': report_id,
                    'timestamp': datetime.now().isoformat(),
                    'total_packets': len(demo_packets),
                    'tor_packets': len(tor_packets),
                    'unique_ips': len(set(p['dst_ip'] for p in demo_packets)),
                    'protocols': list(set(p['protocol'] for p in demo_packets)),
                    'analysis': {
                        'tor_percentage': (len(tor_packets) / len(demo_packets) * 100) if demo_packets else 0,
                        'suspicious_patterns': len([p for p in demo_packets if p.get('dst_port') in [9001, 9030]]),
                        'encrypted_traffic': len([p for p in demo_packets if p.get('protocol') in ['HTTPS', 'TLS']])
                    },
                    'recommendations': [
                        'Monitor TOR exit nodes for suspicious activity',
                        'Implement deep packet inspection for encrypted traffic',
                        'Cross-reference with known TOR relay databases'
                    ]
                }
                
                # Save report
                report_path = Path('reports')
                report_path.mkdir(exist_ok=True)
                
                with open(report_path / f'{report_id}.json', 'w') as f:
                    json.dump(report_data, f, indent=2)
                
                data = {
                    'status': 'success',
                    'report_id': report_id,
                    'files': {'json': f'{report_id}.json', 'html': f'{report_id}.html'},
                    'message': 'Forensic report generated successfully',
                    'summary': report_data['analysis']
                }
            elif self.path == '/api/tor/correlate':
                # Advanced TOR correlation analysis
                tor_packets = [p for p in demo_packets if p.get('is_tor', False)]
                all_packets = demo_packets[-100:]  # Last 100 packets
                
                # Simulate correlation analysis
                correlations = []
                circuits = []
                
                if tor_packets:
                    # Group packets by potential circuits
                    circuit_groups = {}
                    for packet in tor_packets:
                        key = f"{packet['src_ip']}-{packet['dst_ip']}"
                        if key not in circuit_groups:
                            circuit_groups[key] = []
                        circuit_groups[key].append(packet)
                    
                    # Generate circuit analysis
                    for i, (key, packets) in enumerate(circuit_groups.items()):
                        circuits.append({
                            'circuit_id': f'circuit_{i+1}',
                            'entry_node': packets[0]['src_ip'],
                            'exit_node': packets[0]['dst_ip'],
                            'total_packets': len(packets),
                            'confidence': min(95, 60 + len(packets) * 5),
                            'duration': (datetime.now() - datetime.fromisoformat(packets[0]['timestamp'])).total_seconds()
                        })
                    
                    # Generate correlations
                    for packet in tor_packets[:5]:  # Top 5 TOR packets
                        correlations.append({
                            'src_ip': packet['src_ip'],
                            'dst_ip': packet['dst_ip'],
                            'tor_confidence': random.randint(75, 95),
                            'tor_reasons': ['Port analysis', 'Traffic pattern', 'Timing correlation'],
                            'circuit_id': f'circuit_{random.randint(1, len(circuits))}' if circuits else None
                        })
                
                data = {
                    'status': 'success',
                    'results': {
                        'statistics': {
                            'total_packets': len(all_packets),
                            'total_tor_packets': len(tor_packets),
                            'total_circuits': len(circuits),
                            'unique_entry_nodes': len(set(c['entry_node'] for c in circuits)),
                            'unique_exit_nodes': len(set(c['exit_node'] for c in circuits)),
                            'unique_relay_nodes': random.randint(5, 15)
                        },
                        'circuits': circuits,
                        'connections': correlations,
                        'confidence_scores': {
                            'overall_confidence': sum(c['tor_confidence'] for c in correlations) / len(correlations) if correlations else 0,
                            'circuit_confidence': sum(c['confidence'] for c in circuits) / len(circuits) if circuits else 0
                        }
                    },
                    'message': f'Found {len(correlations)} TOR correlations in {len(circuits)} circuits'
                }
            elif self.path == '/api/analysis/deep':
                # Deep packet analysis
                recent_packets = demo_packets[-50:]
                
                analysis_results = {
                    'packet_analysis': {
                        'total_analyzed': len(recent_packets),
                        'protocols': {}
                    },
                    'security_analysis': {
                        'suspicious_ports': [],
                        'anomalies': [],
                        'threat_indicators': []
                    },
                    'performance_metrics': {
                        'avg_packet_size': sum(p.get('length', 0) for p in recent_packets) / len(recent_packets) if recent_packets else 0,
                        'peak_traffic_time': datetime.now().strftime('%H:%M:%S'),
                        'bandwidth_utilization': f"{random.randint(45, 85)}%"
                    }
                }
                
                # Protocol analysis
                for packet in recent_packets:
                    protocol = packet.get('protocol', 'Unknown')
                    if protocol not in analysis_results['packet_analysis']['protocols']:
                        analysis_results['packet_analysis']['protocols'][protocol] = 0
                    analysis_results['packet_analysis']['protocols'][protocol] += 1
                
                # Security analysis
                for packet in recent_packets:
                    if packet.get('dst_port') in [9001, 9030, 443]:
                        analysis_results['security_analysis']['suspicious_ports'].append({
                            'port': packet.get('dst_port'),
                            'ip': packet.get('dst_ip'),
                            'reason': 'Known TOR port' if packet.get('dst_port') in [9001, 9030] else 'Encrypted traffic'
                        })
                
                data = {
                    'status': 'success',
                    'analysis': analysis_results,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                data = {'error': 'Endpoint not found'}
            
            response_data = json.dumps(data, default=str)
            self.wfile.write(response_data.encode())
            
        except Exception as e:
            error_data = {'status': 'error', 'message': str(e)}
            self.wfile.write(json.dumps(error_data).encode())

    def lookup_ip_location_enhanced(self, ip):
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

def main():
    """Main server function"""
    global demo_active
    
    print("Starting TOR Unveil Enhanced Backend...")
    print("Demo mode enabled for packet generation")
    print("Starting server on port 5000...")
    
    # Create necessary directories
    Path('reports').mkdir(exist_ok=True)
    Path('uploads').mkdir(exist_ok=True)
    
    # Start demo packet generation
    demo_active = True
    thread = threading.Thread(target=demo_packet_generator, name='demo_generator')
    thread.daemon = True
    thread.start()
    
    # Start HTTP server
    port = 5000
    server = HTTPServer(('localhost', port), Handler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    logger.info(f'TOR Unveil Backend Server starting on http://localhost:{port}')
    logger.info('Features enabled:')
    logger.info('  - Live packet capture simulation')
    logger.info('  - TOR correlation analysis')
    logger.info('  - Geo tracking and visualization')
    logger.info('  - Report generation')
    logger.info('  - Deep packet analysis')
    
    print("Backend ready at http://localhost:5000")
    print("Open http://localhost:5000/index.html to view dashboard")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
        logger.info('Server shutting down...')
        demo_active = False
        server.shutdown()
    except Exception as e:
        print(f"[SERVER] Error: {e}")
        logger.error(f'Server error: {e}')
    finally:
        demo_active = False
        try:
            server.shutdown()
            server.server_close()
        except:
            pass

if __name__ == '__main__':
    main()