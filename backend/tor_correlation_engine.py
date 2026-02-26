"""
Advanced TOR Correlation Engine
Analyzes packet patterns to identify TOR circuits and traffic
"""

import time
import json
import requests
import threading
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional
import statistics

class TORCorrelationEngine:
    def __init__(self):
        self.tor_nodes = {
            'entry': {},
            'exit': {},
            'relay': {}
        }
        self.correlation_results = {
            'circuits': [],
            'connections': [],
            'statistics': {},
            'confidence_scores': {},
            'last_updated': None
        }
        self.tor_ports = [9001, 9002, 9030, 9050, 9051, 443, 8080, 8443]
        self.local_tor_ports = [9050, 9051, 9150, 9151]  # TOR Browser uses 9150/9151
        self.tor_browser_socks_port = 9150  # TOR Browser SOCKS proxy
        self.tor_browser_control_port = 9051  # TOR Browser control port from config
        self.update_lock = threading.Lock()
        
    def fetch_tor_nodes(self) -> bool:
        """Fetch live TOR node directory from Onionoo"""
        try:
            print("[TOR CORRELATION] Fetching TOR node directory...")
            response = requests.get('https://onionoo.torproject.org/details', timeout=30)
            if response.status_code != 200:
                return False
                
            data = response.json()
            
            with self.update_lock:
                self.tor_nodes = {'entry': {}, 'exit': {}, 'relay': {}}
                
                for relay in data.get('relays', []):
                    fingerprint = relay.get('fingerprint', '')
                    or_addresses = relay.get('or_addresses', [])
                    flags = relay.get('flags', [])
                    
                    # Extract IPs from addresses
                    ips = []
                    for addr in or_addresses:
                        ip = addr.split(':')[0].strip('[]')
                        if ip:
                            ips.append(ip)
                    
                    node_info = {
                        'fingerprint': fingerprint,
                        'ips': ips,
                        'flags': flags,
                        'country': relay.get('country', 'Unknown'),
                        'bandwidth': relay.get('observed_bandwidth', 0),
                        'first_seen': relay.get('first_seen', ''),
                        'last_seen': relay.get('last_seen', '')
                    }
                    
                    # Categorize nodes
                    if 'Guard' in flags:
                        for ip in ips:
                            self.tor_nodes['entry'][ip] = node_info
                    if 'Exit' in flags:
                        for ip in ips:
                            self.tor_nodes['exit'][ip] = node_info
                    
                    # All nodes are potential relays
                    for ip in ips:
                        self.tor_nodes['relay'][ip] = node_info
            
            print(f"[TOR CORRELATION] Loaded {len(self.tor_nodes['entry'])} entry, {len(self.tor_nodes['exit'])} exit, {len(self.tor_nodes['relay'])} relay nodes")
            return True
            
        except Exception as e:
            print(f"[TOR CORRELATION] Failed to fetch TOR nodes: {e}")
            return False
    
    def analyze_packets(self, packets: List[Dict]) -> Dict:
        """Analyze packets for TOR patterns and circuits"""
        if not packets:
            return self.correlation_results
            
        print(f"[TOR CORRELATION] Analyzing {len(packets)} packets...")
        
        # Step 1: Identify TOR traffic
        tor_traffic = self._identify_tor_traffic(packets)
        print(f"[TOR CORRELATION] Found {len(tor_traffic)} TOR packets")
        
        # Step 2: Detect circuits
        circuits = self._detect_circuits(tor_traffic)
        print(f"[TOR CORRELATION] Detected {len(circuits)} potential circuits")
        
        # Step 3: Analyze timing patterns
        timing_analysis = self._analyze_timing_patterns(tor_traffic)
        
        # Step 4: Calculate confidence scores
        confidence_scores = self._calculate_confidence_scores(circuits, timing_analysis)
        
        # Step 5: Generate statistics
        statistics = self._generate_statistics(tor_traffic, circuits)
        
        # Update results
        with self.update_lock:
            self.correlation_results = {
                'circuits': circuits,
                'connections': tor_traffic,
                'statistics': statistics,
                'confidence_scores': confidence_scores,
                'timing_analysis': timing_analysis,
                'last_updated': datetime.now().isoformat()
            }
        
        return self.correlation_results
    
    def _identify_tor_traffic(self, packets: List[Dict]) -> List[Dict]:
        """Identify TOR traffic in packet stream"""
        tor_traffic = []
        
        for packet in packets:
            confidence = 0
            reasons = []
            
            src_ip = packet.get('src_ip', '')
            dst_ip = packet.get('dst_ip', '')
            src_port = packet.get('src_port', 0)
            dst_port = packet.get('dst_port', 0)
            
            # Check IP against TOR node directory
            if src_ip in self.tor_nodes['relay'] or dst_ip in self.tor_nodes['relay']:
                confidence += 40
                reasons.append('Known TOR node IP')
                
            if src_ip in self.tor_nodes['entry'] or dst_ip in self.tor_nodes['entry']:
                confidence += 30
                reasons.append('Entry node IP')
                
            if src_ip in self.tor_nodes['exit'] or dst_ip in self.tor_nodes['exit']:
                confidence += 30
                reasons.append('Exit node IP')
            
            # Check ports
            if dst_port in self.tor_ports or src_port in self.tor_ports:
                confidence += 20
                reasons.append(f'TOR port ({dst_port or src_port})')
            
            # Local TOR browser detection (TOR Browser uses 9150/9151)
            if dst_port in self.local_tor_ports or src_port in self.local_tor_ports:
                confidence += 60
                reasons.append(f'Local TOR browser port ({dst_port or src_port})')
            
            # Check for localhost TOR traffic
            if (src_ip in ['127.0.0.1', '::1'] or dst_ip in ['127.0.0.1', '::1']) and \
               (dst_port in self.local_tor_ports or src_port in self.local_tor_ports):
                confidence += 70
                reasons.append('Localhost TOR traffic')
            
            # Check for TOR Browser specific patterns
            if dst_port == 9150 or src_port == 9150:  # TOR Browser SOCKS port
                confidence += 80
                reasons.append('TOR Browser SOCKS proxy')
            
            if dst_port == 9151 or src_port == 9151:  # TOR Browser control port
                confidence += 75
                reasons.append('TOR Browser control port')
            
            # Packet size analysis (TOR cells are 512 bytes)
            packet_size = packet.get('size', 0)
            if packet_size in [512, 1024, 1536]:  # TOR cell multiples
                confidence += 15
                reasons.append('TOR cell size pattern')
            
            # Protocol analysis
            if packet.get('protocol') == 'TCP' and dst_port == 443:
                confidence += 10
                reasons.append('HTTPS over TCP')
            
            if confidence >= 30:  # Minimum threshold
                packet_copy = packet.copy()
                packet_copy['tor_confidence'] = confidence
                packet_copy['tor_reasons'] = reasons
                packet_copy['is_tor'] = True
                tor_traffic.append(packet_copy)
        
        return tor_traffic
    
    def _detect_circuits(self, tor_traffic: List[Dict]) -> List[Dict]:
        """Detect potential TOR circuits from traffic patterns"""
        circuits = []
        
        # Group packets by time windows (30 second windows)
        time_windows = defaultdict(list)
        
        for packet in tor_traffic:
            timestamp = packet.get('timestamp', '')
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                window = int(dt.timestamp() // 30) * 30
                time_windows[window].append(packet)
            except:
                continue
        
        # Analyze each time window for circuit patterns
        for window_time, packets in time_windows.items():
            if len(packets) < 3:  # Need at least 3 hops
                continue
                
            # Look for entry -> relay -> exit patterns
            entry_nodes = []
            exit_nodes = []
            relay_nodes = []
            
            for packet in packets:
                src_ip = packet.get('src_ip', '')
                dst_ip = packet.get('dst_ip', '')
                
                if src_ip in self.tor_nodes['entry'] or dst_ip in self.tor_nodes['entry']:
                    entry_nodes.append(packet)
                elif src_ip in self.tor_nodes['exit'] or dst_ip in self.tor_nodes['exit']:
                    exit_nodes.append(packet)
                else:
                    relay_nodes.append(packet)
            
            # If we have potential circuit components
            if entry_nodes and (exit_nodes or relay_nodes):
                circuit = {
                    'id': f"circuit_{window_time}",
                    'timestamp': datetime.fromtimestamp(window_time).isoformat(),
                    'entry_nodes': entry_nodes[:3],  # Limit to 3
                    'relay_nodes': relay_nodes[:3],
                    'exit_nodes': exit_nodes[:3],
                    'total_packets': len(packets),
                    'duration': self._calculate_circuit_duration(packets),
                    'confidence': self._calculate_circuit_confidence(entry_nodes, relay_nodes, exit_nodes)
                }
                circuits.append(circuit)
        
        return circuits
    
    def _analyze_timing_patterns(self, tor_traffic: List[Dict]) -> Dict:
        """Analyze timing patterns in TOR traffic"""
        if not tor_traffic:
            return {}
            
        timestamps = []
        intervals = []
        
        for packet in tor_traffic:
            try:
                timestamp = packet.get('timestamp', '')
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                timestamps.append(dt.timestamp())
            except:
                continue
        
        timestamps.sort()
        
        # Calculate intervals between packets
        for i in range(1, len(timestamps)):
            interval = timestamps[i] - timestamps[i-1]
            intervals.append(interval)
        
        if not intervals:
            return {}
        
        return {
            'total_packets': len(tor_traffic),
            'time_span': timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0,
            'avg_interval': statistics.mean(intervals),
            'median_interval': statistics.median(intervals),
            'min_interval': min(intervals),
            'max_interval': max(intervals),
            'std_deviation': statistics.stdev(intervals) if len(intervals) > 1 else 0,
            'burst_patterns': self._detect_burst_patterns(intervals)
        }
    
    def _detect_burst_patterns(self, intervals: List[float]) -> List[Dict]:
        """Detect burst patterns in packet timing"""
        bursts = []
        current_burst = []
        burst_threshold = 0.1  # 100ms
        
        for i, interval in enumerate(intervals):
            if interval < burst_threshold:
                current_burst.append(i)
            else:
                if len(current_burst) >= 3:  # Minimum burst size
                    bursts.append({
                        'start_index': current_burst[0],
                        'end_index': current_burst[-1],
                        'packet_count': len(current_burst),
                        'duration': sum(intervals[current_burst[0]:current_burst[-1]+1])
                    })
                current_burst = []
        
        return bursts
    
    def _calculate_circuit_duration(self, packets: List[Dict]) -> float:
        """Calculate duration of a circuit"""
        timestamps = []
        for packet in packets:
            try:
                timestamp = packet.get('timestamp', '')
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                timestamps.append(dt.timestamp())
            except:
                continue
        
        if len(timestamps) < 2:
            return 0
            
        return max(timestamps) - min(timestamps)
    
    def _calculate_circuit_confidence(self, entry_nodes: List, relay_nodes: List, exit_nodes: List) -> float:
        """Calculate confidence score for a detected circuit"""
        confidence = 0
        
        # Base confidence for having components
        if entry_nodes:
            confidence += 30
        if relay_nodes:
            confidence += 20
        if exit_nodes:
            confidence += 30
        
        # Bonus for proper 3-hop structure
        if entry_nodes and relay_nodes and exit_nodes:
            confidence += 20
        
        return min(confidence, 100)
    
    def _calculate_confidence_scores(self, circuits: List[Dict], timing_analysis: Dict) -> Dict:
        """Calculate overall confidence scores"""
        scores = {
            'overall_confidence': 0,
            'circuit_confidence': 0,
            'timing_confidence': 0,
            'node_matching_confidence': 0
        }
        
        if circuits:
            circuit_confidences = [c.get('confidence', 0) for c in circuits]
            scores['circuit_confidence'] = statistics.mean(circuit_confidences)
        
        # Timing confidence based on patterns
        if timing_analysis.get('burst_patterns'):
            scores['timing_confidence'] = min(len(timing_analysis['burst_patterns']) * 20, 100)
        
        # Node matching confidence
        total_nodes = len(self.tor_nodes['entry']) + len(self.tor_nodes['exit']) + len(self.tor_nodes['relay'])
        if total_nodes > 1000:  # Good node directory
            scores['node_matching_confidence'] = 90
        
        # Overall confidence
        scores['overall_confidence'] = statistics.mean([
            scores['circuit_confidence'],
            scores['timing_confidence'],
            scores['node_matching_confidence']
        ])
        
        return scores
    
    def _generate_statistics(self, tor_traffic: List[Dict], circuits: List[Dict]) -> Dict:
        """Generate comprehensive statistics"""
        stats = {
            'total_tor_packets': len(tor_traffic),
            'total_circuits': len(circuits),
            'unique_entry_nodes': set(),
            'unique_exit_nodes': set(),
            'unique_relay_nodes': set(),
            'port_distribution': Counter(),
            'protocol_distribution': Counter(),
            'packet_size_distribution': Counter(),
            'confidence_distribution': Counter(),
            'geographic_distribution': Counter()
        }
        
        for packet in tor_traffic:
            # Port distribution
            if packet.get('dst_port'):
                stats['port_distribution'][packet['dst_port']] += 1
            
            # Protocol distribution
            if packet.get('protocol'):
                stats['protocol_distribution'][packet['protocol']] += 1
            
            # Packet size distribution
            size_range = f"{(packet.get('size', 0) // 100) * 100}-{((packet.get('size', 0) // 100) + 1) * 100}"
            stats['packet_size_distribution'][size_range] += 1
            
            # Confidence distribution
            confidence = packet.get('tor_confidence', 0)
            if confidence >= 80:
                stats['confidence_distribution']['High (80-100%)'] += 1
            elif confidence >= 60:
                stats['confidence_distribution']['Medium (60-79%)'] += 1
            else:
                stats['confidence_distribution']['Low (30-59%)'] += 1
            
            # Node tracking
            src_ip = packet.get('src_ip', '')
            dst_ip = packet.get('dst_ip', '')
            
            if src_ip in self.tor_nodes['entry'] or dst_ip in self.tor_nodes['entry']:
                stats['unique_entry_nodes'].add(src_ip or dst_ip)
            if src_ip in self.tor_nodes['exit'] or dst_ip in self.tor_nodes['exit']:
                stats['unique_exit_nodes'].add(src_ip or dst_ip)
            if src_ip in self.tor_nodes['relay'] or dst_ip in self.tor_nodes['relay']:
                stats['unique_relay_nodes'].add(src_ip or dst_ip)
        
        # Convert sets to counts
        stats['unique_entry_nodes'] = len(stats['unique_entry_nodes'])
        stats['unique_exit_nodes'] = len(stats['unique_exit_nodes'])
        stats['unique_relay_nodes'] = len(stats['unique_relay_nodes'])
        
        return stats
    
    def get_results(self) -> Dict:
        """Get current correlation results"""
        with self.update_lock:
            return self.correlation_results.copy()
    
    def run_correlation(self, packets: List[Dict], fetch_nodes: bool = True) -> Dict:
        """Run complete TOR correlation analysis"""
        print("[TOR CORRELATION] Starting correlation analysis...")
        
        # Fetch TOR nodes if requested
        if fetch_nodes:
            self.fetch_tor_nodes()
        
        # Analyze packets
        results = self.analyze_packets(packets)
        
        print(f"[TOR CORRELATION] Analysis complete. Found {len(results['circuits'])} circuits, {len(results['connections'])} TOR connections")
        
        return results