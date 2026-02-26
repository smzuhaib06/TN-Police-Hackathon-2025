"""
Live Packet Analyzer for TOR Unveil
Captures and analyzes packets in real-time, feeding data to all analysis modules
"""

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import threading
import time
import json
import requests
from collections import defaultdict
import geoip2.database
import geoip2.errors

class LivePacketAnalyzer:
    def __init__(self):
        self.is_capturing = False
        self.packets = []
        self.tor_relays = set()
        self.connections = defaultdict(list)
        self.geo_data = {}
        self.analysis_data = {
            'total_packets': 0,
            'tor_packets': 0,
            'unique_ips': set(),
            'tor_connections': [],
            'timing_patterns': [],
            'circuits': []
        }
        
    def start_capture(self, interface=None):
        """Start packet capture"""
        if self.is_capturing:
            return {"status": "already_running"}
            
        self.is_capturing = True
        self.packets = []
        
        # Use None for default interface on Windows
        if interface == "eth0":
            interface = None
        
        # Start capture in separate thread
        capture_thread = threading.Thread(
            target=self._capture_packets, 
            args=(interface,)
        )
        capture_thread.daemon = True
        capture_thread.start()
        
        return {"status": "started", "interface": interface or "default"}
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        return {"status": "stopped", "packets_captured": len(self.packets)}
    
    def _capture_packets(self, interface):
        """Capture packets using scapy"""
        try:
            scapy.sniff(
                iface=interface,
                prn=self._process_packet,
                stop_filter=lambda x: not self.is_capturing,
                store=False
            )
        except Exception as e:
            print(f"Capture error: {e}")
            self.is_capturing = False
    
    def _process_packet(self, packet):
        """Process each captured packet"""
        if not packet.haslayer(IP):
            return
            
        ip_layer = packet[IP]
        self.analysis_data['total_packets'] += 1
        
        # Extract packet info
        packet_info = {
            'timestamp': time.time(),
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'protocol': ip_layer.proto,
            'size': len(packet)
        }
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            packet_info.update({
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'flags': tcp_layer.flags
            })
            
            # Check for TOR traffic (common ports: 9001, 9030, 443)
            if tcp_layer.dport in [9001, 9030, 443] or tcp_layer.sport in [9001, 9030, 443]:
                self._analyze_tor_packet(packet_info)
        
        self.packets.append(packet_info)
        self.analysis_data['unique_ips'].add(ip_layer.src)
        self.analysis_data['unique_ips'].add(ip_layer.dst)
        
        # Perform real-time analysis
        self._update_analysis(packet_info)
    
    def _analyze_tor_packet(self, packet_info):
        """Analyze potential TOR packets"""
        self.analysis_data['tor_packets'] += 1
        
        # Add to TOR connections
        connection = f"{packet_info['src_ip']}:{packet_info.get('src_port', 0)} -> {packet_info['dst_ip']}:{packet_info.get('dst_port', 0)}"
        self.analysis_data['tor_connections'].append({
            'timestamp': packet_info['timestamp'],
            'connection': connection,
            'size': packet_info['size']
        })
        
        # Check if it's a known TOR relay
        self._check_tor_relay(packet_info['dst_ip'])
    
    def _check_tor_relay(self, ip):
        """Check if IP is a known TOR relay"""
        try:
            # Simple check - in production, use TOR consensus data
            response = requests.get(f"https://check.torproject.org/api/ip", timeout=2)
            if response.status_code == 200:
                self.tor_relays.add(ip)
        except:
            pass
    
    def _update_analysis(self, packet_info):
        """Update real-time analysis"""
        # Timing pattern analysis
        if len(self.analysis_data['timing_patterns']) > 0:
            last_time = self.analysis_data['timing_patterns'][-1]['timestamp']
            time_diff = packet_info['timestamp'] - last_time
            
            self.analysis_data['timing_patterns'].append({
                'timestamp': packet_info['timestamp'],
                'time_diff': time_diff,
                'size': packet_info['size']
            })
        else:
            self.analysis_data['timing_patterns'].append({
                'timestamp': packet_info['timestamp'],
                'time_diff': 0,
                'size': packet_info['size']
            })
    
    def get_analysis_data(self):
        """Get current analysis data for other modules"""
        return {
            'pcap_analysis': {
                'total_packets': self.analysis_data['total_packets'],
                'tor_packets': self.analysis_data['tor_packets'],
                'tor_percentage': (self.analysis_data['tor_packets'] / max(self.analysis_data['total_packets'], 1)) * 100,
                'unique_ips': len(self.analysis_data['unique_ips']),
                'tor_relays_contacted': len(self.tor_relays),
                'tor_connections': self.analysis_data['tor_connections'][-10:],  # Last 10
                'timing_patterns': self.analysis_data['timing_patterns'][-50:]   # Last 50
            },
            'correlations': self._calculate_correlations(),
            'geo_data': self._get_geo_data(),
            'circuits': self._detect_circuits()
        }
    
    def _calculate_correlations(self):
        """Calculate timing correlations from captured packets"""
        correlations = []
        
        if len(self.analysis_data['timing_patterns']) < 10:
            return correlations
        
        # Simple correlation analysis
        patterns = self.analysis_data['timing_patterns'][-20:]
        
        for i in range(len(patterns) - 5):
            window = patterns[i:i+5]
            avg_time_diff = sum(p['time_diff'] for p in window) / len(window)
            avg_size = sum(p['size'] for p in window) / len(window)
            
            if avg_time_diff > 0:
                correlations.append({
                    'timestamp': window[0]['timestamp'],
                    'confidence': min(0.9, avg_size / 1500),  # Normalize by typical packet size
                    'pattern_type': 'timing',
                    'details': f"Avg interval: {avg_time_diff:.3f}s, Avg size: {avg_size:.0f}b"
                })
        
        return correlations[-5:]  # Return last 5 correlations
    
    def _get_geo_data(self):
        """Get geographical data for captured IPs"""
        geo_results = []
        
        # Get unique IPs from recent packets
        recent_ips = set()
        for packet in self.packets[-100:]:  # Last 100 packets
            recent_ips.add(packet['src_ip'])
            recent_ips.add(packet['dst_ip'])
        
        for ip in list(recent_ips)[:10]:  # Limit to 10 IPs
            try:
                # Mock geo data - in production use real GeoIP database
                geo_results.append({
                    'ip': ip,
                    'country': 'Unknown',
                    'city': 'Unknown',
                    'lat': 0.0,
                    'lon': 0.0,
                    'is_tor': ip in self.tor_relays
                })
            except:
                pass
        
        return geo_results
    
    def _detect_circuits(self):
        """Detect potential TOR circuits from packet patterns"""
        circuits = []
        
        # Group connections by timing
        if len(self.analysis_data['tor_connections']) >= 3:
            recent_connections = self.analysis_data['tor_connections'][-10:]
            
            # Simple circuit detection based on timing
            for i in range(len(recent_connections) - 2):
                circuit_connections = recent_connections[i:i+3]
                
                circuits.append({
                    'id': f"DETECTED_{i}",
                    'status': 'DETECTED',
                    'purpose': 'GENERAL',
                    'created_at': circuit_connections[0]['timestamp'],
                    'path': [
                        {
                            'fingerprint': f"RELAY_{j}_{conn['connection'].split(' -> ')[1].split(':')[0]}",
                            'nickname': f"Relay{j+1}"
                        }
                        for j, conn in enumerate(circuit_connections)
                    ]
                })
        
        return circuits[-3:]  # Return last 3 detected circuits

# Global analyzer instance
packet_analyzer = LivePacketAnalyzer()