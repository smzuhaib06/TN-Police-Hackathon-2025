"""
Enhanced Real-time Packet Sniffer for TOR Unveil
Captures live network packets with TOR-specific analysis
"""

import os
import json
import threading
import time
from datetime import datetime
from collections import defaultdict
import socket
import struct
import requests

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
    from scapy.utils import PcapWriter
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class EnhancedPacketSniffer:
    def __init__(self, interface=None, packet_limit=5000):
        self.interface = interface
        self.packets = []
        self.tor_packets = []
        self.flows = defaultdict(int)
        self.is_running = False
        self.lock = threading.Lock()
        self.max_packets = packet_limit
        
        # TOR detection
        self.tor_ports = [9001, 9002, 9030, 9050, 9051, 443, 80, 8080, 8443]
        self.relay_ips = set()
        self.tor_circuits = {}
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'tor_packets': 0,
            'protocols': defaultdict(int),
            'start_time': None,
            'bytes_captured': 0
        }
        
        # PCAP storage
        self.pcap_dir = os.path.join(os.path.dirname(__file__), '..', 'pcap_storage')
        os.makedirs(self.pcap_dir, exist_ok=True)
        self.pcap_writer = None
        
        # Start relay IP refresh
        self._refresh_relay_ips()
        
    def _refresh_relay_ips(self):
        """Refresh TOR relay IPs from Onionoo"""
        try:
            response = requests.get('https://onionoo.torproject.org/summary?limit=2000', timeout=10)
            if response.status_code == 200:
                data = response.json()
                ips = set()
                for relay in data.get('relays', []):
                    for addr in relay.get('or_addresses', []):
                        ip = addr.split(':')[0].strip('[]')
                        if ip:
                            ips.add(ip)
                with self.lock:
                    self.relay_ips = ips
                print(f"SNIFFER: Loaded {len(ips)} TOR relay IPs")
        except Exception as e:
            print(f"SNIFFER: Failed to load relay IPs: {e}")
    
    def start_capture(self):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available - install with: pip install scapy")
        
        self.is_running = True
        self.stats['start_time'] = datetime.now()
        
        # Start PCAP writer
        timestamp = datetime.now().strftime('%Y%m%dT%H%M%SZ')
        pcap_file = os.path.join(self.pcap_dir, f'capture_{timestamp}.pcap')
        self.pcap_writer = PcapWriter(pcap_file, append=False, sync=True)
        
        def capture_thread():
            try:
                print(f"SNIFFER: Starting capture on interface: {self.interface or 'default'}")
                sniff(
                    prn=self._process_packet,
                    iface=self.interface,
                    store=False,
                    stop_filter=lambda x: not self.is_running or len(self.packets) >= self.max_packets
                )
            except PermissionError:
                error_msg = "ERROR: Administrator privileges required for packet capture. Please run as Administrator."
                print(f"SNIFFER: {error_msg}")
                self.stats['error'] = error_msg
                self.is_running = False
            except Exception as e:
                error_msg = f"Capture error: {e}"
                print(f"SNIFFER: {error_msg}")
                self.stats['error'] = error_msg
                self.is_running = False
        
        thread = threading.Thread(target=capture_thread, daemon=True)
        thread.start()
        return pcap_file
    
    def _process_packet(self, packet):
        """Process each captured packet"""
        try:
            with self.lock:
                # Write to PCAP
                if self.pcap_writer:
                    self.pcap_writer.write(packet)
                
                # Extract packet info
                packet_info = self._extract_packet_info(packet)
                if not packet_info:
                    return
                
                self.packets.append(packet_info)
                self.stats['total_packets'] += 1
                self.stats['bytes_captured'] += packet_info.get('size', 0)
                
                # Update protocol stats
                for proto in packet_info.get('protocols', []):
                    self.stats['protocols'][proto] += 1
                
                # Check for TOR traffic
                if self._is_tor_packet(packet_info):
                    self.tor_packets.append(packet_info)
                    self.stats['tor_packets'] += 1
                
                # Track flows
                flow_key = self._get_flow_key(packet_info)
                if flow_key:
                    self.flows[flow_key] += 1
                
        except Exception as e:
            print(f"SNIFFER: Packet processing error: {e}")
    
    def _extract_packet_info(self, packet):
        """Extract packet information"""
        try:
            info = {
                'timestamp': datetime.now().isoformat(),
                'size': len(packet),
                'protocols': []
            }
            
            if IP in packet:
                ip = packet[IP]
                info['src_ip'] = ip.src
                info['dst_ip'] = ip.dst
                info['ttl'] = ip.ttl
                info['protocols'].append('IP')
                
                if TCP in packet:
                    tcp = packet[TCP]
                    info['src_port'] = tcp.sport
                    info['dst_port'] = tcp.dport
                    info['tcp_flags'] = str(tcp.flags)
                    info['protocols'].append('TCP')
                    
                    # Check for TLS/SSL handshake
                    if Raw in packet and len(packet[Raw]) > 0:
                        payload = bytes(packet[Raw])
                        if payload.startswith(b'\x16\x03'):  # TLS handshake
                            info['tls_handshake'] = True
                            info['protocols'].append('TLS')
                
                elif UDP in packet:
                    udp = packet[UDP]
                    info['src_port'] = udp.sport
                    info['dst_port'] = udp.dport
                    info['protocols'].append('UDP')
                
                elif ICMP in packet:
                    icmp = packet[ICMP]
                    info['icmp_type'] = icmp.type
                    info['icmp_code'] = icmp.code
                    info['protocols'].append('ICMP')
            
            return info
        except Exception:
            return None
    
    def _is_tor_packet(self, packet_info):
        """Detect TOR traffic"""
        # Check ports
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        
        if src_port in self.tor_ports or dst_port in self.tor_ports:
            return True
        
        # Check IPs against known relays
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        
        if src_ip in self.relay_ips or dst_ip in self.relay_ips:
            return True
        
        # TLS on port 443 with specific patterns
        if dst_port == 443 and packet_info.get('tls_handshake'):
            return True
        
        return False
    
    def _get_flow_key(self, packet_info):
        """Generate flow key"""
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        
        if src_ip and dst_ip and src_port and dst_port:
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        return None
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_running = False
        if self.pcap_writer:
            self.pcap_writer.close()
            self.pcap_writer = None
    
    def get_statistics(self):
        """Get capture statistics"""
        with self.lock:
            runtime = 0
            if self.stats['start_time']:
                runtime = (datetime.now() - self.stats['start_time']).total_seconds()
            
            return {
                'total_packets': self.stats['total_packets'],
                'tor_packets': self.stats['tor_packets'],
                'tor_percentage': (self.stats['tor_packets'] / max(1, self.stats['total_packets'])) * 100,
                'bytes_captured': self.stats['bytes_captured'],
                'protocols': dict(self.stats['protocols']),
                'flows': len(self.flows),
                'runtime_seconds': runtime,
                'packets_per_second': self.stats['total_packets'] / max(1, runtime),
                'relay_ips_loaded': len(self.relay_ips),
                'error': self.stats.get('error')
            }
    
    def get_tor_packets(self, limit=100):
        """Get TOR packets"""
        with self.lock:
            return self.tor_packets[-limit:] if limit else self.tor_packets.copy()
    
    def get_flows(self, limit=50):
        """Get top flows"""
        with self.lock:
            sorted_flows = sorted(self.flows.items(), key=lambda x: x[1], reverse=True)
            return dict(sorted_flows[:limit])

# Global sniffer instance
sniffer = None

def start_sniffer(interface=None, packet_limit=5000):
    """Start the packet sniffer"""
    global sniffer
    if sniffer and sniffer.is_running:
        sniffer.stop_capture()
    
    sniffer = EnhancedPacketSniffer(interface=interface, packet_limit=packet_limit)
    pcap_file = sniffer.start_capture()
    return {
        'status': 'started',
        'interface': interface or 'default',
        'pcap_file': pcap_file,
        'packet_limit': packet_limit
    }

def stop_sniffer():
    """Stop the packet sniffer"""
    global sniffer
    if sniffer:
        sniffer.stop_capture()
        return {'status': 'stopped'}
    return {'status': 'not_running'}

def get_sniffer_stats():
    """Get sniffer statistics"""
    global sniffer
    if sniffer:
        return sniffer.get_statistics()
    return {'status': 'not_running'}

def get_tor_traffic(limit=100):
    """Get captured TOR traffic"""
    global sniffer
    if sniffer:
        return sniffer.get_tor_packets(limit=limit)
    return []

if __name__ == "__main__":
    # Test the sniffer
    print("Starting enhanced packet sniffer...")
    result = start_sniffer()
    print(f"Sniffer started: {result}")
    
    try:
        time.sleep(10)  # Capture for 10 seconds
        stats = get_sniffer_stats()
        print(f"Statistics: {json.dumps(stats, indent=2)}")
        
        tor_traffic = get_tor_traffic(limit=10)
        print(f"TOR packets captured: {len(tor_traffic)}")
        
    finally:
        stop_sniffer()
        print("Sniffer stopped")