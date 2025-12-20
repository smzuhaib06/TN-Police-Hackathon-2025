"""
Enhanced PCAP Analysis Engine for TOR Unveil
Advanced packet analysis with TOR circuit correlation
"""

import os
import json
import dpkt
import socket
import struct
from datetime import datetime
from collections import defaultdict, Counter
import requests

class EnhancedPCAPAnalyzer:
    def __init__(self):
        self.tor_ports = [9001, 9002, 9030, 9050, 9051, 443, 80, 8080, 8443]
        self.relay_ips = set()
        self.guard_ips = set()
        self.exit_ips = set()
        self._load_relay_data()
    
    def _load_relay_data(self):
        """Load TOR relay data from Onionoo"""
        try:
            response = requests.get('https://onionoo.torproject.org/details?limit=2000', timeout=15)
            if response.status_code == 200:
                data = response.json()
                for relay in data.get('relays', []):
                    # Extract IPs
                    for addr in relay.get('or_addresses', []):
                        ip = addr.split(':')[0].strip('[]')
                        if ip:
                            self.relay_ips.add(ip)
                            
                            # Categorize by flags
                            flags = relay.get('flags', [])
                            if 'Guard' in flags:
                                self.guard_ips.add(ip)
                            if 'Exit' in flags:
                                self.exit_ips.add(ip)
                
                print(f"PCAP: Loaded {len(self.relay_ips)} relay IPs ({len(self.guard_ips)} guards, {len(self.exit_ips)} exits)")
        except Exception as e:
            print(f"PCAP: Failed to load relay data: {e}")
    
    def analyze_pcap(self, pcap_path):
        """Comprehensive PCAP analysis"""
        print(f"PCAP: Analyzing {pcap_path}")
        
        analysis = {
            'file': os.path.basename(pcap_path),
            'file_size': os.path.getsize(pcap_path),
            'analysis_time': datetime.now().isoformat(),
            'packets': [],
            'flows': defaultdict(list),
            'tor_connections': [],
            'tor_circuits': [],
            'statistics': {
                'total_packets': 0,
                'tor_packets': 0,
                'protocols': Counter(),
                'unique_ips': set(),
                'tor_relays_contacted': set(),
                'guard_connections': 0,
                'exit_connections': 0,
                'encrypted_connections': 0
            }
        }
        
        try:
            with open(pcap_path, 'rb') as f:
                # Try different PCAP formats
                try:
                    pcap = dpkt.pcap.Reader(f)
                except:
                    f.seek(0)
                    if hasattr(dpkt, 'pcapng'):
                        pcap = dpkt.pcapng.Reader(f)
                    else:
                        raise Exception("Unsupported PCAP format")
                
                for timestamp, buf in pcap:
                    packet_info = self._analyze_packet(timestamp, buf, analysis)
                    if packet_info:
                        analysis['packets'].append(packet_info)
                        analysis['statistics']['total_packets'] += 1
                        
                        # Track unique IPs
                        if 'src_ip' in packet_info:
                            analysis['statistics']['unique_ips'].add(packet_info['src_ip'])
                        if 'dst_ip' in packet_info:
                            analysis['statistics']['unique_ips'].add(packet_info['dst_ip'])
                        
                        # Limit packets stored for memory
                        if len(analysis['packets']) > 10000:
                            analysis['packets'] = analysis['packets'][-5000:]
            
            # Post-process analysis
            self._post_process_analysis(analysis)
            
        except Exception as e:
            analysis['error'] = str(e)
            print(f"PCAP: Analysis error: {e}")
        
        return analysis
    
    def _analyze_packet(self, timestamp, buf, analysis):
        """Analyze individual packet"""
        try:
            # Parse Ethernet frame
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip_data = eth.data
            except:
                # Try raw IP
                ip_data = dpkt.ip.IP(buf)
            
            if not isinstance(ip_data, dpkt.ip.IP):
                return None
            
            ip = ip_data
            packet_info = {
                'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                'src_ip': socket.inet_ntoa(ip.src),
                'dst_ip': socket.inet_ntoa(ip.dst),
                'protocol': ip.p,
                'length': len(buf),
                'ttl': ip.ttl
            }
            
            # Protocol-specific analysis
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                packet_info.update({
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'tcp_flags': tcp.flags,
                    'protocol_name': 'TCP',
                    'payload_size': len(tcp.data)
                })
                
                analysis['statistics']['protocols']['TCP'] += 1
                
                # TLS/SSL detection
                if len(tcp.data) > 0:
                    payload = tcp.data
                    if self._is_tls_handshake(payload):
                        packet_info['tls'] = True
                        analysis['statistics']['encrypted_connections'] += 1
                
            elif isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                packet_info.update({
                    'src_port': udp.sport,
                    'dst_port': udp.dport,
                    'protocol_name': 'UDP',
                    'payload_size': len(udp.data)
                })
                analysis['statistics']['protocols']['UDP'] += 1
            
            else:
                packet_info['protocol_name'] = f'IP_{ip.p}'
                analysis['statistics']['protocols'][f'IP_{ip.p}'] += 1
            
            # TOR traffic analysis
            tor_info = self._analyze_tor_traffic(packet_info, analysis)
            if tor_info:
                packet_info.update(tor_info)
                analysis['statistics']['tor_packets'] += 1
            
            # Flow tracking
            if 'src_port' in packet_info and 'dst_port' in packet_info:
                flow_key = f"{packet_info['src_ip']}:{packet_info['src_port']}-{packet_info['dst_ip']}:{packet_info['dst_port']}"
                analysis['flows'][flow_key].append(packet_info)
            
            return packet_info
            
        except Exception as e:
            return None
    
    def _is_tls_handshake(self, payload):
        """Detect TLS handshake"""
        if len(payload) < 6:
            return False
        
        # TLS record header: type(1) + version(2) + length(2)
        if payload[0] == 0x16:  # Handshake
            version = struct.unpack('>H', payload[1:3])[0]
            if version in [0x0301, 0x0302, 0x0303, 0x0304]:  # TLS 1.0-1.3
                return True
        
        return False
    
    def _analyze_tor_traffic(self, packet_info, analysis):
        """Analyze packet for TOR indicators"""
        tor_info = {}
        
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        
        # Check if connecting to known TOR relay
        if dst_ip in self.relay_ips:
            tor_info['tor_relay_connection'] = True
            tor_info['relay_ip'] = dst_ip
            analysis['statistics']['tor_relays_contacted'].add(dst_ip)
            
            # Determine relay type
            if dst_ip in self.guard_ips:
                tor_info['relay_type'] = 'guard'
                analysis['statistics']['guard_connections'] += 1
            elif dst_ip in self.exit_ips:
                tor_info['relay_type'] = 'exit'
                analysis['statistics']['exit_connections'] += 1
            else:
                tor_info['relay_type'] = 'middle'
        
        # Check TOR ports
        if dst_port in self.tor_ports:
            tor_info['tor_port_connection'] = True
            tor_info['tor_port'] = dst_port
            
            if dst_port == 9001:
                tor_info['connection_type'] = 'or_port'
            elif dst_port == 9030:
                tor_info['connection_type'] = 'dir_port'
            elif dst_port == 9050:
                tor_info['connection_type'] = 'socks_port'
            elif dst_port == 443:
                tor_info['connection_type'] = 'https_bridge'
        
        # TOR circuit patterns
        if packet_info.get('protocol_name') == 'TCP' and packet_info.get('tls'):
            if dst_port in [443, 9001] and packet_info.get('payload_size', 0) == 512:
                tor_info['possible_cell'] = True
                tor_info['cell_size'] = packet_info['payload_size']
        
        return tor_info if tor_info else None
    
    def _post_process_analysis(self, analysis):
        """Post-process analysis results"""
        stats = analysis['statistics']
        
        # Convert sets to counts for JSON serialization
        stats['unique_ips'] = len(stats['unique_ips'])
        stats['tor_relays_contacted'] = len(stats['tor_relays_contacted'])
        
        # Calculate percentages
        total = stats['total_packets']
        if total > 0:
            stats['tor_percentage'] = (stats['tor_packets'] / total) * 100
            stats['encryption_percentage'] = (stats['encrypted_connections'] / total) * 100
        
        # Identify potential TOR circuits
        circuits = self._identify_circuits(analysis)
        analysis['tor_circuits'] = circuits
        
        # Top flows analysis
        flow_stats = {}
        for flow_key, packets in analysis['flows'].items():
            flow_stats[flow_key] = {
                'packet_count': len(packets),
                'total_bytes': sum(p.get('length', 0) for p in packets),
                'duration': self._calculate_flow_duration(packets),
                'tor_indicators': sum(1 for p in packets if any(k.startswith('tor_') for k in p.keys()))
            }
        
        # Keep top 100 flows
        top_flows = dict(sorted(flow_stats.items(), key=lambda x: x[1]['packet_count'], reverse=True)[:100])
        analysis['top_flows'] = top_flows
        
        # Clean up large data structures
        analysis['flows'] = {}  # Remove detailed flow data to save memory
    
    def _identify_circuits(self, analysis):
        """Identify potential TOR circuits from traffic patterns"""
        circuits = []
        
        # Group connections by time windows
        time_windows = defaultdict(list)
        
        for packet in analysis['packets']:
            if packet.get('tor_relay_connection'):
                timestamp = datetime.fromisoformat(packet['timestamp'])
                window = timestamp.replace(second=0, microsecond=0)  # 1-minute windows
                time_windows[window].append(packet)
        
        # Look for 3-hop patterns (guard -> middle -> exit)
        for window, packets in time_windows.items():
            guard_connections = [p for p in packets if p.get('relay_type') == 'guard']
            exit_connections = [p for p in packets if p.get('relay_type') == 'exit']
            
            if guard_connections and exit_connections:
                circuit = {
                    'timestamp': window.isoformat(),
                    'guard_relays': list(set(p['relay_ip'] for p in guard_connections)),
                    'exit_relays': list(set(p['relay_ip'] for p in exit_connections)),
                    'confidence': min(len(guard_connections), len(exit_connections)) / 10.0
                }
                circuits.append(circuit)
        
        return circuits[:50]  # Limit to top 50 circuits
    
    def _calculate_flow_duration(self, packets):
        """Calculate flow duration"""
        if len(packets) < 2:
            return 0
        
        timestamps = [datetime.fromisoformat(p['timestamp']) for p in packets]
        return (max(timestamps) - min(timestamps)).total_seconds()

def analyze_pcap_file(pcap_path):
    """Analyze PCAP file - main entry point"""
    analyzer = EnhancedPCAPAnalyzer()
    return analyzer.analyze_pcap(pcap_path)

if __name__ == "__main__":
    # Test with a sample PCAP file
    import sys
    if len(sys.argv) > 1:
        result = analyze_pcap_file(sys.argv[1])
        print(json.dumps(result, indent=2, default=str))
    else:
        print("Usage: python enhanced_pcap_analyzer.py <pcap_file>")