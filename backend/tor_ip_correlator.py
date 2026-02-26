#!/usr/bin/env python3
"""
TOR IP CORRELATOR - INTEGRATED FOR REAL-TIME ANALYSIS
====================================================
High-accuracy Tor traffic correlation optimized for live data analysis.
Integrates with the main app backend for real-time correlation.
"""

import numpy as np
from scipy import stats
from scipy.signal import correlate
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from datetime import datetime
import time
import threading
import logging

logger = logging.getLogger(__name__)

class TorFlowCorrelator:
    """Real-time Tor flow correlation engine"""
    
    def __init__(self):
        self.ingress_flows = defaultdict(lambda: {'timestamps': [], 'sizes': [], 'ports': set()})
        self.egress_flows = defaultdict(lambda: {'timestamps': [], 'sizes': [], 'ports': set()})
        self.correlations = []
        self.lock = threading.Lock()
        
    def add_packet(self, packet_data):
        """Add packet for real-time correlation"""
        with self.lock:
            src_ip = packet_data.get('src_ip')
            dst_ip = packet_data.get('dst_ip')
            
            # Handle timestamp conversion properly
            timestamp = packet_data.get('timestamp', time.time())
            if isinstance(timestamp, str):
                try:
                    # Parse ISO format timestamp
                    from datetime import datetime
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    timestamp = dt.timestamp()
                except:
                    timestamp = time.time()
            else:
                timestamp = float(timestamp)
                
            size = packet_data.get('size', 0)
            src_port = packet_data.get('src_port', 0)
            dst_port = packet_data.get('dst_port', 0)
            
            # Classify as ingress or egress based on IP patterns
            if self._is_local_ip(src_ip) and not self._is_local_ip(dst_ip):
                # Local to external = ingress (user -> entry node)
                flow_key = f"{src_ip}->{dst_ip}"
                self.ingress_flows[flow_key]['timestamps'].append(timestamp)
                self.ingress_flows[flow_key]['sizes'].append(size)
                self.ingress_flows[flow_key]['ports'].add(dst_port)
                
            elif not self._is_local_ip(src_ip) and not self._is_local_ip(dst_ip):
                # External to external = egress (exit node -> destination)
                flow_key = f"{src_ip}->{dst_ip}"
                self.egress_flows[flow_key]['timestamps'].append(timestamp)
                self.egress_flows[flow_key]['sizes'].append(size)
                self.egress_flows[flow_key]['ports'].add(dst_port)
    
    def _is_local_ip(self, ip):
        """Check if IP is local/private"""
        if not ip:
            return False
        return ip.startswith(('192.168.', '10.', '172.16.', '127.'))
    
    def extract_timing_features(self, flow_data):
        """Extract timing features optimized for Tor"""
        timestamps = np.array(flow_data['timestamps'])
        sizes = np.array(flow_data['sizes'])
        
        if len(timestamps) < 5:
            return {}
        
        timestamps = np.sort(timestamps)
        iat = np.diff(timestamps) * 1000  # milliseconds
        
        # Remove extreme outliers
        iat = iat[iat < 10000]
        if len(iat) < 3:
            return {}
        
        features = {
            'iat_raw': iat,
            'iat_log': np.log1p(iat),
            'iat_median': np.median(iat),
            'iat_std': np.std(iat),
            'burst_ratio': np.sum(iat < 50) / len(iat),
            'size_variance': np.var(sizes) if len(sizes) > 1 else 0,
            'duration': timestamps[-1] - timestamps[0],
            'packet_rate': len(timestamps) / max(timestamps[-1] - timestamps[0], 1)
        }
        
        # Normalize IAT for correlation
        if np.std(iat) > 0:
            features['iat_norm'] = (iat - np.median(iat)) / (np.percentile(iat, 75) - np.percentile(iat, 25) + 1e-6)
        else:
            features['iat_norm'] = iat
        
        return features
    
    def calculate_correlation(self, features1, features2):
        """Calculate Tor-optimized correlation score"""
        if not features1 or not features2:
            return 0.0
        
        iat1 = features1['iat_norm']
        iat2 = features2['iat_norm']
        
        if len(iat1) < 5 or len(iat2) < 5:
            return 0.0
        
        # Truncate to same length
        min_len = min(len(iat1), len(iat2), 200)
        iat1, iat2 = iat1[:min_len], iat2[:min_len]
        
        # Cross-correlation for time-shifted patterns
        cross_corr = correlate(iat1, iat2, mode='full')
        max_corr = np.max(np.abs(cross_corr)) / (np.linalg.norm(iat1) * np.linalg.norm(iat2) + 1e-10)
        
        # Statistical correlation
        try:
            pearson_r, p_val = stats.pearsonr(iat1, iat2)
            spearman_r, _ = stats.spearmanr(iat1, iat2)
        except:
            pearson_r = spearman_r = p_val = 0.0
        
        # Feature similarity
        burst_sim = 1 - abs(features1['burst_ratio'] - features2['burst_ratio'])
        rate_sim = 1 - abs(features1['packet_rate'] - features2['packet_rate']) / max(features1['packet_rate'], features2['packet_rate'], 1)
        
        # Combined score
        score = (
            max_corr * 0.4 +
            abs(pearson_r) * 0.25 +
            abs(spearman_r) * 0.15 +
            burst_sim * 0.1 +
            rate_sim * 0.1
        )
        
        # Boost if statistically significant
        if p_val < 0.05:
            score *= 1.2
        
        return min(score, 1.0)
    
    def check_timing_match(self, ingress_times, egress_times):
        """Check if timing patterns match Tor characteristics"""
        if not ingress_times or not egress_times:
            return False
        
        ing_start, ing_end = min(ingress_times), max(ingress_times)
        eg_start, eg_end = min(egress_times), max(egress_times)
        
        # Tor latency check
        latency = eg_start - ing_start
        if not (0.05 <= latency <= 3.0):
            return False
        
        # Overlap check
        overlap = min(ing_end, eg_end) - max(ing_start, eg_start)
        total_duration = max(ing_end, eg_end) - min(ing_start, eg_start)
        
        if total_duration > 0 and overlap / total_duration < 0.3:
            return False
        
        return True
    
    def run_correlation_analysis(self, min_packets=8, threshold=0.6):
        """Run real-time correlation analysis"""
        with self.lock:
            # Extract features for valid flows
            ingress_features = {}
            for flow, data in self.ingress_flows.items():
                if len(data['timestamps']) >= min_packets:
                    features = self.extract_timing_features(data)
                    if features:
                        ingress_features[flow] = features
            
            egress_features = {}
            for flow, data in self.egress_flows.items():
                if len(data['timestamps']) >= min_packets:
                    features = self.extract_timing_features(data)
                    if features:
                        egress_features[flow] = features
            
            if not ingress_features or not egress_features:
                return []
            
            # Correlate flows
            results = []
            for ing_flow, ing_features in ingress_features.items():
                for eg_flow, eg_features in egress_features.items():
                    # Quick timing check
                    if not self.check_timing_match(
                        self.ingress_flows[ing_flow]['timestamps'],
                        self.egress_flows[eg_flow]['timestamps']
                    ):
                        continue
                    
                    # Calculate correlation
                    score = self.calculate_correlation(ing_features, eg_features)
                    
                    if score >= threshold:
                        ing_src, ing_dst = ing_flow.split('->')
                        eg_src, eg_dst = eg_flow.split('->')
                        
                        result = {
                            'user_ip': ing_src,
                            'entry_node': ing_dst,
                            'exit_node': eg_src,
                            'destination': eg_dst,
                            'confidence': round(score, 4),
                            'ingress_packets': len(self.ingress_flows[ing_flow]['timestamps']),
                            'egress_packets': len(self.egress_flows[eg_flow]['timestamps']),
                            'latency': round(min(self.egress_flows[eg_flow]['timestamps']) - min(self.ingress_flows[ing_flow]['timestamps']), 3),
                            'timestamp': time.time()
                        }
                        results.append(result)
            
            # Sort by confidence
            results.sort(key=lambda x: x['confidence'], reverse=True)
            
            # Store results
            self.correlations.extend(results)
            
            # Keep only recent correlations (last 100)
            if len(self.correlations) > 100:
                self.correlations = self.correlations[-100:]
            
            return results
    
    def get_statistics(self):
        """Get correlation statistics"""
        with self.lock:
            return {
                'ingress_flows': len(self.ingress_flows),
                'egress_flows': len(self.egress_flows),
                'total_correlations': len(self.correlations),
                'high_confidence_correlations': len([c for c in self.correlations if c['confidence'] > 0.8]),
                'avg_confidence': np.mean([c['confidence'] for c in self.correlations]) if self.correlations else 0.0,
                'latest_correlations': self.correlations[-5:] if self.correlations else []
            }
    
    def clear_old_data(self, max_age_seconds=300):
        """Clear old flow data to prevent memory buildup"""
        with self.lock:
            current_time = time.time()
            
            # Clean ingress flows
            for flow_key in list(self.ingress_flows.keys()):
                timestamps = self.ingress_flows[flow_key]['timestamps']
                if timestamps:
                    # Convert timestamps to float if they're strings
                    try:
                        max_ts = max(float(t) if isinstance(t, (int, float)) else 
                                   datetime.fromisoformat(str(t).replace('Z', '+00:00')).timestamp() 
                                   if isinstance(t, str) else float(t) for t in timestamps)
                        if current_time - max_ts > max_age_seconds:
                            del self.ingress_flows[flow_key]
                    except (ValueError, TypeError, AttributeError):
                        # If conversion fails, delete the flow
                        del self.ingress_flows[flow_key]
            
            # Clean egress flows
            for flow_key in list(self.egress_flows.keys()):
                timestamps = self.egress_flows[flow_key]['timestamps']
                if timestamps:
                    try:
                        max_ts = max(float(t) if isinstance(t, (int, float)) else 
                                   datetime.fromisoformat(str(t).replace('Z', '+00:00')).timestamp() 
                                   if isinstance(t, str) else float(t) for t in timestamps)
                        if current_time - max_ts > max_age_seconds:
                            del self.egress_flows[flow_key]
                    except (ValueError, TypeError, AttributeError):
                        del self.egress_flows[flow_key]

# Global correlator instance
tor_correlator = TorFlowCorrelator()

def add_packet_for_tor_correlation(packet_data):
    """Add packet to Tor correlator"""
    tor_correlator.add_packet(packet_data)

def run_tor_correlation(min_packets=8, threshold=0.6):
    """Run Tor correlation analysis"""
    return tor_correlator.run_correlation_analysis(min_packets, threshold)

def get_tor_correlation_stats():
    """Get Tor correlation statistics"""
    return tor_correlator.get_statistics()

def cleanup_tor_correlator():
    """Clean up old correlation data"""
    tor_correlator.clear_old_data()

# Auto-cleanup thread
def start_cleanup_thread():
    """Start background cleanup thread"""
    def cleanup_worker():
        while True:
            time.sleep(60)  # Clean every minute
            cleanup_tor_correlator()
    
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()

# Start cleanup on import
start_cleanup_thread()