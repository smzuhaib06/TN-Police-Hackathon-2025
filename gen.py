#!/usr/bin/env python3
"""
Generate test PCAP files with correlated traffic patterns
"""
from scapy.all import *
import random
import numpy as np

def generate_correlated_pcaps(output_ingress="test_ingress.pcap", 
                             output_egress="test_egress.pcap",
                             num_flows=3,
                             packets_per_flow=100):
    """
    Generate PCAP files with correlated timing patterns.
    """
    ingress_packets = []
    egress_packets = []
    
    # Define flows
    ingress_flows = [
        ("192.168.1.100", "45.141.215.100"),  # User -> Entry Node 1
        ("192.168.1.101", "199.249.230.77"),  # User -> Entry Node 2
        ("192.168.1.102", "185.220.101.45"),  # User -> Entry Node 3
    ]
    
    egress_flows = [
        ("185.220.101.45", "172.217.14.206"),  # Exit Node 1 -> Destination 1
        ("45.141.215.100", "93.184.216.34"),   # Exit Node 2 -> Destination 2
        ("199.249.230.77", "151.101.1.140"),   # Exit Node 3 -> Destination 3
    ]
    
    # Generate correlated traffic for each flow pair
    base_time = time.time()
    
    for i in range(num_flows):
        ingress_src, ingress_dst = ingress_flows[i]
        egress_src, egress_dst = egress_flows[i]
        
        # Generate timing pattern (could be bursty, periodic, etc.)
        if i == 0:
            # Bursty pattern
            intervals = np.concatenate([
                np.random.exponential(0.01, 30),  # Fast burst
                np.random.exponential(0.5, 20),   # Slow period
                np.random.exponential(0.01, 30),  # Fast burst
                np.random.exponential(0.3, 20)    # Medium period
            ])
        elif i == 1:
            # Periodic pattern
            intervals = np.concatenate([
                np.full(50, 0.1) + np.random.normal(0, 0.01, 50),
                np.full(50, 0.2) + np.random.normal(0, 0.02, 50)
            ])
        else:
            # Random pattern
            intervals = np.random.exponential(0.2, packets_per_flow)
        
        # Generate packets with correlated timing
        ingress_time = base_time + i * 10  # Offset each flow
        egress_time = ingress_time + 0.05  # 50ms Tor latency
        
        for interval in intervals[:packets_per_flow]:
            # Ingress packet
            pkt = IP(src=ingress_src, dst=ingress_dst)/TCP(sport=RandShort(), dport=9001)/Raw(RandString(size=random.randint(100, 1000)))
            pkt.time = ingress_time
            ingress_packets.append(pkt)
            
            # Corresponding egress packet (with slight jitter)
            jitter = random.uniform(-0.005, 0.005)  # ±5ms jitter
            pkt = IP(src=egress_src, dst=egress_dst)/TCP(sport=RandShort(), dport=443)/Raw(RandString(size=random.randint(100, 1000)))
            pkt.time = egress_time + jitter
            egress_packets.append(pkt)
            
            # Update times
            ingress_time += interval
            egress_time += interval
    
    # Add some noise packets (non-correlated traffic)
    for _ in range(50):
        # Random ingress noise
        pkt = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=RandShort(), dport=80)/Raw(RandString(size=100))
        pkt.time = base_time + random.uniform(0, 100)
        ingress_packets.append(pkt)
        
        # Random egress noise
        pkt = IP(src="20.0.0.1", dst="20.0.0.2")/TCP(sport=RandShort(), dport=443)/Raw(RandString(size=100))
        pkt.time = base_time + random.uniform(0, 100)
        egress_packets.append(pkt)
    
    # Sort by time and write
    ingress_packets.sort(key=lambda p: p.time)
    egress_packets.sort(key=lambda p: p.time)
    
    wrpcap(output_ingress, ingress_packets)
    wrpcap(output_egress, egress_packets)
    
    print(f"Generated {output_ingress} with {len(ingress_packets)} packets")
    print(f"Generated {output_egress} with {len(egress_packets)} packets")

if __name__ == "__main__":
    generate_correlated_pcaps()
