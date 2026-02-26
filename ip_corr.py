#!/usr/bin/env python3
"""
TOR TRAFFIC CORRELATOR - OPTIMIZED FOR REAL DATA
===============================================
Correlates Tor ingress/egress flows using advanced timing analysis.

Optimized for:
- Real Tor network latencies (100-500ms)
- Variable packet sizes and timing
- High-accuracy correlation with noise filtering
- Live traffic analysis
"""

import numpy as np
from scipy import stats
from scipy.signal import correlate
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

# =====================================================================
# PCAP PARSER - FLOW-BASED
# =====================================================================

def parse_pcap_flows(pcap_file: str, mode: str = 'ingress') -> Dict[str, Dict]:
    """
    Extract Tor flows with enhanced metadata for real traffic analysis.
    
    Returns:
        Dict mapping flow_key to {timestamps, sizes, directions}
    """
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError:
        print("ERROR: scapy not installed. Run: pip install scapy")
        return {}
    
    print(f"Reading {mode.upper()} PCAP: {pcap_file}")
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"ERROR: Failed to read PCAP: {e}")
        return {}
    
    flow_data = defaultdict(lambda: {'timestamps': [], 'sizes': [], 'ports': set()})
    
    for packet in packets:
        if not packet.haslayer(IP):
            continue
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = float(packet.time)
        size = len(packet)
        
        # Filter Tor-like traffic (common Tor ports)
        if packet.haslayer(TCP):
            port = packet[TCP].dport if mode == 'ingress' else packet[TCP].sport
            # Tor commonly uses 9001, 9030, 443, 80
            if port not in [80, 443, 9001, 9030, 8080]:
                continue
        
        flow_key = f"{src_ip}->{dst_ip}"
        flow_data[flow_key]['timestamps'].append(timestamp)
        flow_data[flow_key]['sizes'].append(size)
        if packet.haslayer(TCP):
            flow_data[flow_key]['ports'].add(packet[TCP].dport)
    
    print(f"  Found {len(flow_data)} Tor-like flows")
    return dict(flow_data)

# =====================================================================
# IAT EXTRACTION AND NORMALIZATION
# =====================================================================

def extract_timing_features(flow_data: Dict) -> Dict:
    """Extract comprehensive timing features for Tor correlation."""
    timestamps = np.array(flow_data['timestamps'])
    sizes = np.array(flow_data['sizes'])
    
    if len(timestamps) < 5:
        return {}
    
    timestamps = np.sort(timestamps)
    iat = np.diff(timestamps) * 1000  # milliseconds
    
    # Remove extreme outliers (>10 seconds likely network issues)
    iat = iat[iat < 10000]
    if len(iat) < 3:
        return {}
    
    # Tor-specific features
    features = {
        'iat_raw': iat,
        'iat_log': np.log1p(iat),  # Log transform for heavy-tailed distribution
        'iat_median': np.median(iat),
        'iat_std': np.std(iat),
        'burst_ratio': np.sum(iat < 50) / len(iat),  # Ratio of fast packets (<50ms)
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

# =====================================================================
# ADVANCED CORRELATION METHODS
# =====================================================================

def calculate_tor_correlation(features1: Dict, features2: Dict) -> float:
    """Calculate Tor-optimized correlation score."""
    if not features1 or not features2:
        return 0.0
    
    iat1 = features1['iat_norm']
    iat2 = features2['iat_norm']
    
    if len(iat1) < 5 or len(iat2) < 5:
        return 0.0
    
    # Truncate to same length
    min_len = min(len(iat1), len(iat2), 200)  # Limit for performance
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
    
    # Combined score optimized for Tor
    score = (
        max_corr * 0.4 +           # Cross-correlation (time shifts)
        abs(pearson_r) * 0.25 +    # Linear correlation
        abs(spearman_r) * 0.15 +   # Rank correlation
        burst_sim * 0.1 +          # Burst pattern similarity
        rate_sim * 0.1             # Rate similarity
    )
    
    # Boost if statistically significant
    if p_val < 0.05:
        score *= 1.2
    
    return min(score, 1.0)

def check_tor_timing_match(ingress_times: List[float], egress_times: List[float]) -> bool:
    """Check if timing patterns match Tor network characteristics."""
    if not ingress_times or not egress_times:
        return False
    
    ing_start, ing_end = min(ingress_times), max(ingress_times)
    eg_start, eg_end = min(egress_times), max(egress_times)
    
    # Tor latency: 100ms to 2 seconds typical
    latency = eg_start - ing_start
    if not (0.05 <= latency <= 3.0):  # 50ms to 3s range
        return False
    
    # Flows should overlap significantly
    overlap = min(ing_end, eg_end) - max(ing_start, eg_start)
    total_duration = max(ing_end, eg_end) - min(ing_start, eg_start)
    
    if total_duration > 0 and overlap / total_duration < 0.3:  # 30% overlap minimum
        return False
    
    return True

# =====================================================================
# FLOW CORRELATION ENGINE
# =====================================================================

def extract_ips_from_flow(flow_key: str) -> Tuple[str, str]:
    """Extract source and destination IPs from flow key."""
    parts = flow_key.split('->')
    if len(parts) == 2:
        return parts[0], parts[1]
    return "", ""

def correlate_tor_flows(
    ingress_flows: Dict[str, Dict],
    egress_flows: Dict[str, Dict],
    min_packets: int = 8,
    threshold: float = 0.6
) -> List[Dict]:
    """Correlate Tor flows with optimized real-world performance."""
    print(f"Analyzing {len(ingress_flows)} ingress and {len(egress_flows)} egress flows")
    
    # Extract features
    ingress_features = {}
    for flow, data in ingress_flows.items():
        if len(data['timestamps']) >= min_packets:
            features = extract_timing_features(data)
            if features:
                ingress_features[flow] = features
    
    egress_features = {}
    for flow, data in egress_flows.items():
        if len(data['timestamps']) >= min_packets:
            features = extract_timing_features(data)
            if features:
                egress_features[flow] = features
    
    print(f"Valid flows: {len(ingress_features)} ingress, {len(egress_features)} egress")
    
    if not ingress_features or not egress_features:
        return []
    
    results = []
    total = len(ingress_features) * len(egress_features)
    count = 0
    
    for ing_flow, ing_features in ingress_features.items():
        for eg_flow, eg_features in egress_features.items():
            count += 1
            if count % 100 == 0:
                print(f"Progress: {count}/{total}")
            
            # Quick timing check
            if not check_tor_timing_match(
                ingress_flows[ing_flow]['timestamps'],
                egress_flows[eg_flow]['timestamps']
            ):
                continue
            
            # Calculate correlation
            score = calculate_tor_correlation(ing_features, eg_features)
            
            if score >= threshold:
                ing_src, ing_dst = extract_ips_from_flow(ing_flow)
                eg_src, eg_dst = extract_ips_from_flow(eg_flow)
                
                results.append({
                    'user_ip': ing_src,
                    'entry_node': ing_dst,
                    'exit_node': eg_src,
                    'destination': eg_dst,
                    'confidence': round(score, 4),
                    'ingress_packets': len(ingress_flows[ing_flow]['timestamps']),
                    'egress_packets': len(egress_flows[eg_flow]['timestamps']),
                    'latency': round(min(egress_flows[eg_flow]['timestamps']) - min(ingress_flows[ing_flow]['timestamps']), 3)
                })
    
    results.sort(key=lambda x: x['confidence'], reverse=True)
    print(f"Found {len(results)} correlations above threshold {threshold}")
    return results

def print_results(results: List[Dict]):
    """Print Tor correlation results."""
    if not results:
        print("No correlations found. Try lowering threshold or min_packets.")
        return
    
    print(f"\n{'='*80}")
    print(f"TOR CORRELATION RESULTS - {len(results)} matches")
    print(f"{'='*80}")
    
    for i, r in enumerate(results[:10], 1):
        print(f"\n#{i} - Confidence: {r['confidence']:.3f}")
        print(f"  {r['user_ip']} → {r['entry_node']} → [TOR] → {r['exit_node']} → {r['destination']}")
        print(f"  Packets: {r['ingress_packets']} in, {r['egress_packets']} out | Latency: {r['latency']}s")
    
    if len(results) > 10:
        print(f"\n... and {len(results) - 10} more matches")
    print(f"{'='*80}")

def save_results_csv(results: List[Dict], output_file: str):
    """Save results to CSV."""
    import csv
    
    if not results:
        return
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    
    print(f"Results saved to {output_file}")



# =====================================================================
# MAIN FUNCTION
# =====================================================================

def analyze_tor_traffic(
    ingress_pcap: str,
    egress_pcap: str,
    output_csv: str = "tor_correlations.csv",
    min_packets: int = 8,
    threshold: float = 0.6
) -> List[Dict]:
    """Main Tor traffic correlation function."""
    print("TOR TRAFFIC CORRELATOR - Analyzing real network data")
    print("="*60)
    
    # Parse flows
    ingress_flows = parse_pcap_flows(ingress_pcap, 'ingress')
    egress_flows = parse_pcap_flows(egress_pcap, 'egress')
    
    if not ingress_flows or not egress_flows:
        print("No valid flows found")
        return []
    
    # Correlate
    results = correlate_tor_flows(ingress_flows, egress_flows, min_packets, threshold)
    
    # Output
    print_results(results)
    if results:
        save_results_csv(results, output_csv)
    
    return results

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python ip_corr.py <ingress.pcap> <egress.pcap> [output.csv] [min_packets] [threshold]")
        print("Example: python ip_corr.py ingress.pcap egress.pcap results.csv 8 0.6")
        sys.exit(1)
    
    ingress_file = sys.argv[1]
    egress_file = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else "tor_correlations.csv"
    min_packets = int(sys.argv[4]) if len(sys.argv) > 4 else 8
    threshold = float(sys.argv[5]) if len(sys.argv) > 5 else 0.6
    
    analyze_tor_traffic(ingress_file, egress_file, output_file, min_packets, threshold)
