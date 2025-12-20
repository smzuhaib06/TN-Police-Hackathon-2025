"""
Heuristic Correlation Engine for TOR Node Correlation
Uses statistical and time-based analysis to correlate entry/exit nodes
Current prototype implementation - ML-based scoring is roadmap feature
"""

import json
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from collections import defaultdict
import threading
import statistics


class TORHeuristicCorrelationEngine:
    """Heuristic engine to correlate TOR entry and exit nodes using time-based matching and statistical analysis"""
    
    def __init__(self):
        self.entry_nodes = []
        self.exit_nodes = []
        self.traffic_flows = defaultdict(list)
        self.correlations = []
        self.lock = threading.Lock()
        
    def extract_features(self, packet_flow: List[Dict]) -> np.ndarray:
        """Extract features from packet flow for ML analysis"""
        if not packet_flow:
            return np.array([])
        
        features = []
        
        # Feature 1: Average packet size
        sizes = [p.get('size', 0) for p in packet_flow]
        features.append(np.mean(sizes) if sizes else 0)
        
        # Feature 2: Packet count
        features.append(len(packet_flow))
        
        # Feature 3: Time duration (seconds)
        timestamps = [datetime.fromisoformat(p['timestamp']) for p in packet_flow if 'timestamp' in p]
        if len(timestamps) > 1:
            duration = (timestamps[-1] - timestamps[0]).total_seconds()
            features.append(duration)
        else:
            features.append(0)
        
        # Feature 4: Throughput (bytes/second)
        if features[2] > 0:
            throughput = sum(sizes) / features[2]
            features.append(throughput)
        else:
            features.append(0)
        
        # Feature 5: Packet timing variance
        if len(timestamps) > 1:
            time_gaps = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                        for i in range(len(timestamps)-1)]
            features.append(np.var(time_gaps) if time_gaps else 0)
        else:
            features.append(0)
        
        # Feature 6: Protocol distribution
        protocol_counts = defaultdict(int)
        for p in packet_flow:
            for proto in p.get('protocols', []):
                protocol_counts[proto] += 1
        features.append(len(protocol_counts))
        
        return np.array(features)
    
    def add_traffic_flow(self, flow_id: str, flow_data: List[Dict]):
        """Add a traffic flow for analysis"""
        with self.lock:
            self.traffic_flows[flow_id] = flow_data
    
    def identify_entry_exit_pairs(self, packets: List[Dict]) -> List[Dict]:
        """Identify entry and exit node pairs using timing correlation"""
        entry_exit_pairs = []
        
        # Group packets by direction and timing
        forward_flows = defaultdict(list)
        reverse_flows = defaultdict(list)
        
        for packet in packets:
            if 'src_ip' not in packet or 'dst_ip' not in packet:
                continue
            
            flow_key = f"{packet['src_ip']}:{packet.get('src_port', 0)}-{packet['dst_ip']}:{packet.get('dst_port', 0)}"
            forward_flows[flow_key].append(packet)
            
            # Reverse flow
            rev_key = f"{packet['dst_ip']}:{packet.get('dst_port', 0)}-{packet['src_ip']}:{packet.get('src_port', 0)}"
            reverse_flows[rev_key].append(packet)
        
        # Correlate flows based on timing and size patterns
        for flow_id, flow_packets in forward_flows.items():
            src_ip = flow_packets[0].get('src_ip')
            dst_ip = flow_packets[0].get('dst_ip')
            
            # Check for correlated reverse flow
            rev_key = f"{dst_ip}:{flow_packets[0].get('dst_port', 0)}-{src_ip}:{flow_packets[0].get('src_port', 0)}"
            if rev_key in reverse_flows:
                correlation_score = self.calculate_correlation_score(
                    flow_packets,
                    reverse_flows[rev_key]
                )
                
                if correlation_score > 0.5:  # Threshold
                    entry_exit_pairs.append({
                        'entry_ip': src_ip,
                        'exit_ip': dst_ip,
                        'confidence': correlation_score,
                        'flow_id': flow_id,
                        'packet_count': len(flow_packets),
                        'total_bytes': sum(p.get('size', 0) for p in flow_packets)
                    })
        
        return entry_exit_pairs
    
    def calculate_correlation_score(self, flow1: List[Dict], flow2: List[Dict]) -> float:
        """Calculate correlation score between two flows"""
        if not flow1 or not flow2:
            return 0.0
        
        # Extract timing information
        times1 = []
        times2 = []
        
        for packet in flow1:
            if 'timestamp' in packet:
                times1.append(datetime.fromisoformat(packet['timestamp']))
        
        for packet in flow2:
            if 'timestamp' in packet:
                times2.append(datetime.fromisoformat(packet['timestamp']))
        
        if not times1 or not times2:
            return 0.0
        
        # Check for temporal overlap
        min1, max1 = min(times1), max(times1)
        min2, max2 = min(times2), max(times2)
        
        overlap_start = max(min1, min2)
        overlap_end = min(max1, max2)
        
        if overlap_start > overlap_end:
            return 0.0
        
        # Calculate overlap percentage
        total_duration = (max(max1, max2) - min(min1, min2)).total_seconds()
        overlap_duration = (overlap_end - overlap_start).total_seconds()
        
        if total_duration == 0:
            return 0.0
        
        overlap_score = overlap_duration / total_duration
        
        # Size similarity heuristic
        sizes1 = [p.get('size', 0) for p in flow1]
        sizes2 = [p.get('size', 0) for p in flow2]
        
        if sizes1 and sizes2:
            avg_size_ratio = np.mean(sizes2) / np.mean(sizes1) if np.mean(sizes1) > 0 else 0
            size_score = 1.0 - abs(1.0 - avg_size_ratio) if avg_size_ratio > 0 else 0
            size_score = max(0, min(1, size_score))
        else:
            size_score = 0.5
        
        # Combined score
        combined_score = 0.6 * overlap_score + 0.4 * size_score
        
        return min(1.0, max(0.0, combined_score))
    
    def cluster_nodes(self, entry_exit_pairs: List[Dict]) -> Dict:
        """Group nodes by exit IP using heuristic similarity analysis"""
        if not entry_exit_pairs:
            return {}

        # Group by exit IP - heuristic approach: same exit IP = same cluster
        exit_ip_groups = defaultdict(list)
        for pair in entry_exit_pairs:
            exit_ip_groups[pair['exit_ip']].append(pair)

        # Sort groups by confidence for ranking
        clusters = []
        for exit_ip, pairs in exit_ip_groups.items():
            # Sort pairs within cluster by confidence
            sorted_pairs = sorted(pairs, key=lambda x: x['confidence'], reverse=True)
            clusters.append({
                'exit_ip': exit_ip,
                'pairs': sorted_pairs,
                'avg_confidence': np.mean([p['confidence'] for p in sorted_pairs]),
                'total_packets': sum(p['packet_count'] for p in sorted_pairs)
            })

        # Sort clusters by average confidence
        clusters.sort(key=lambda x: x['avg_confidence'], reverse=True)

        return {
            'clusters': [[c['exit_ip']] for c in clusters],  # List of IP lists for compatibility
            'cluster_details': clusters,  # Additional heuristic details
            'cluster_count': len(clusters)
        }
    
    def correlate_all(self, packets: List[Dict]) -> Dict:
        """Run complete correlation analysis"""
        with self.lock:
            entry_exit_pairs = self.identify_entry_exit_pairs(packets)
            clustering = self.cluster_nodes(entry_exit_pairs)
            
            return {
                'entry_exit_pairs': entry_exit_pairs,
                'clustering': clustering,
                'top_correlated_ips': sorted(
                    entry_exit_pairs,
                    key=lambda x: x['confidence'],
                    reverse=True
                )[:10],
                'analysis_time': datetime.now().isoformat(),
                'total_pairs': len(entry_exit_pairs)
            }
    
    def get_correlation_stats(self, correlation_result: Dict) -> Dict:
        """Get statistics from correlation analysis"""
        pairs = correlation_result.get('entry_exit_pairs', [])
        
        if not pairs:
            return {
                'average_confidence': 0,
                'high_confidence_count': 0,
                'total_correlations': 0
            }
        
        confidences = [p['confidence'] for p in pairs]
        
        return {
            'average_confidence': np.mean(confidences),
            'max_confidence': np.max(confidences),
            'min_confidence': np.min(confidences),
            'high_confidence_count': sum(1 for c in confidences if c > 0.7),
            'medium_confidence_count': sum(1 for c in confidences if 0.5 <= c <= 0.7),
            'total_correlations': len(pairs),
            'confidence_distribution': {
                'high': sum(1 for c in confidences if c > 0.7),
                'medium': sum(1 for c in confidences if 0.5 <= c <= 0.7),
                'low': sum(1 for c in confidences if c < 0.5)
            }
        }
