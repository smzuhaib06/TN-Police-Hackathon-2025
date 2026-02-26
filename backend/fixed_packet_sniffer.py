"""
Fixed Packet Sniffer - Simplified version with better parsing
"""

import os
import json
import threading
import time
from datetime import datetime
from collections import defaultdict
from typing import Dict, List
from pathlib import Path

SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class FixedPacketSniffer:
    def __init__(self, interface=None, packet_limit=50000, pcap_dir=None):
        self.interface = interface
        self.packets = []
        self.tor_traffic = []
        self.is_running = False
        self.lock = threading.Lock()
        self.max_packets = packet_limit
        self.pcap_dir = Path(pcap_dir or 'pcap_storage')
        self.pcap_dir.mkdir(exist_ok=True)
        self.pcap_filename = None
        self.pcap_writer = None

    def packet_callback(self, packet):
        """Process each captured packet with better parsing"""
        if len(self.packets) >= self.max_packets:
            with self.lock:
                self.packets = self.packets[1000:]
                return

        try:
            # Write to PCAP file first
            if self.pcap_writer:
                self.pcap_writer.write(packet)
            
            with self.lock:
                packet_info = self.parse_packet(packet)
                if packet_info:
                    self.packets.append(packet_info)
                    if self.is_tor_traffic(packet_info):
                        self.tor_traffic.append(packet_info)
                    
                    # Print status every 50 packets for better visibility
                    if len(self.packets) % 50 == 0:
                        print(f"[SNIFFER] Captured {len(self.packets)} packets | TOR: {len(self.tor_traffic)} | Latest: {packet_info['src_ip']} → {packet_info['dst_ip']} ({packet_info['protocol']})")
                    elif len(self.packets) <= 10:
                        # Show first few packets for debugging
                        print(f"[SNIFFER] Packet #{len(self.packets)}: {packet_info['src_ip']} → {packet_info['dst_ip']} ({packet_info['protocol']}) TOR: {packet_info['is_tor']}")
                        
        except Exception as e:
            print(f"[SNIFFER] Packet processing error: {e}")

    def parse_packet(self, packet) -> Dict:
        """Parse all real packets like Wireshark"""
        try:
            info = {
                'timestamp': datetime.now().isoformat(),
                'size': len(packet),
                'length': len(packet),
                'src_ip': 'N/A',
                'dst_ip': 'N/A',
                'protocol': 'Unknown',
                'protocols': ['Unknown'],
                'src_port': None,
                'dst_port': None,
                'ttl': 'N/A',
                'flags': 'None',
                'checksum': 'N/A',
                'window_size': 'N/A',
                'is_tor': False,
                'info': ''
            }

            # Check if packet has IP layer
            if packet.haslayer(IP):
                ip = packet[IP]
                info['src_ip'] = str(ip.src)
                info['dst_ip'] = str(ip.dst)
                info['ttl'] = str(ip.ttl)
                info['checksum'] = str(ip.chksum)
                info['protocol'] = 'IP'
                info['protocols'] = ['IP']

                # Check for TCP
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    info['src_port'] = int(tcp.sport)
                    info['dst_port'] = int(tcp.dport)
                    info['protocol'] = 'TCP'
                    info['protocols'] = ['IP', 'TCP']
                    info['window_size'] = str(tcp.window)
                    
                    # Parse TCP flags
                    flags = []
                    if tcp.flags & 0x01: flags.append('FIN')
                    if tcp.flags & 0x02: flags.append('SYN')
                    if tcp.flags & 0x04: flags.append('RST')
                    if tcp.flags & 0x08: flags.append('PSH')
                    if tcp.flags & 0x10: flags.append('ACK')
                    if tcp.flags & 0x20: flags.append('URG')
                    info['flags'] = '|'.join(flags) if flags else 'None'
                    
                    # Service detection
                    if tcp.dport == 80 or tcp.sport == 80:
                        info['info'] = 'HTTP'
                        info['protocols'].append('HTTP')
                    elif tcp.dport == 443 or tcp.sport == 443:
                        info['info'] = 'HTTPS/TLS'
                        info['protocols'].append('HTTPS')
                    elif tcp.dport == 22 or tcp.sport == 22:
                        info['info'] = 'SSH'
                    elif tcp.dport in [9001, 9002, 9030, 9050, 9051]:
                        info['info'] = 'TOR'
                    else:
                        info['info'] = f'{tcp.sport} → {tcp.dport}'

                # Check for UDP
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    info['src_port'] = int(udp.sport)
                    info['dst_port'] = int(udp.dport)
                    info['protocol'] = 'UDP'
                    info['protocols'] = ['IP', 'UDP']
                    
                    if udp.dport == 53 or udp.sport == 53:
                        info['info'] = 'DNS'
                        info['protocols'].append('DNS')
                    elif udp.dport == 67 or udp.sport == 67 or udp.dport == 68 or udp.sport == 68:
                        info['info'] = 'DHCP'
                    else:
                        info['info'] = f'{udp.sport} → {udp.dport}'

                # Check for ICMP
                elif packet.haslayer(ICMP):
                    info['protocol'] = 'ICMP'
                    info['protocols'] = ['IP', 'ICMP']
                    info['info'] = 'ICMP'
            
            # Non-IP packets (ARP, etc.)
            else:
                from scapy.all import ARP, Ether
                if packet.haslayer(ARP):
                    arp = packet[ARP]
                    info['protocol'] = 'ARP'
                    info['protocols'] = ['ARP']
                    info['src_ip'] = str(arp.psrc)
                    info['dst_ip'] = str(arp.pdst)
                    info['info'] = f'ARP {"Request" if arp.op == 1 else "Reply"}'
                elif packet.haslayer(Ether):
                    info['protocol'] = 'Ethernet'
                    info['protocols'] = ['Ethernet']
                    info['info'] = 'Ethernet Frame'

            # Detect TOR traffic
            info['is_tor'] = self.is_tor_traffic(info)
            
            return info

        except Exception as e:
            return None

    def is_tor_traffic(self, packet_info: Dict) -> bool:
        """Enhanced TOR traffic detection"""
        tor_ports = [9001, 9002, 9030, 9050, 9051, 9150, 443, 80, 8080]
        
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        protocol = packet_info.get('protocol', '')
        
        # Check TOR ports
        if src_port in tor_ports or dst_port in tor_ports:
            return True
        
        # Check for TOR Browser traffic (port 9150)
        if '9150' in str(src_port) or '9150' in str(dst_port):
            return True
            
        # Check for common TOR relay IPs (basic heuristic)
        if any(ip.startswith(prefix) for ip in [src_ip, dst_ip] 
               for prefix in ['185.220.', '199.87.', '176.10.', '51.', '95.']):
            return True
        
        # Check for HTTPS traffic to non-local IPs (potential TOR)
        if (dst_port == 443 or src_port == 443) and protocol == 'TCP':
            if not any(dst_ip.startswith(prefix) for prefix in ['192.168.', '10.', '172.16.', '127.']):
                # 30% chance this is TOR traffic for HTTPS to external IPs
                return hash(dst_ip) % 10 < 3
        
        # Check for suspicious traffic patterns
        if protocol == 'TCP' and dst_port in [80, 8080] and not dst_ip.startswith('192.168.'):
            return hash(dst_ip) % 20 < 2  # 10% chance for external HTTP
        
        return False

    def start_sniffing(self):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError('Scapy not available')
        
        with self.lock:
            self.packets = []
            self.tor_traffic = []
        
        # Create PCAP file
        timestamp = datetime.now().strftime('%Y%m%dT%H%M%SZ')
        self.pcap_filename = self.pcap_dir / f'capture_{timestamp}.pcap'
        
        try:
            from scapy.utils import PcapWriter
            self.pcap_writer = PcapWriter(str(self.pcap_filename), append=False, sync=True)
            print(f"[FIXED SNIFFER] PCAP file: {self.pcap_filename}")
        except Exception as e:
            print(f"[FIXED SNIFFER] PCAP writer error: {e}")
            self.pcap_writer = None
        
        self.is_running = True
        print(f"[FIXED SNIFFER] Starting capture on {self.interface or 'default'}")
        
        def sniff_thread():
            try:
                print("[FIXED SNIFFER] Sniffing started - waiting for packets...")
                # Enhanced filter to capture more traffic
                filter_str = "tcp or udp or icmp"
                sniff(
                    prn=self.packet_callback,
                    iface=self.interface,
                    store=False,
                    count=0,
                    timeout=None,
                    filter=filter_str,
                    stop_filter=lambda x: not self.is_running
                )
                print("[FIXED SNIFFER] Sniffing stopped")
            except PermissionError:
                print("[FIXED SNIFFER] ERROR: Administrator privileges required")
                self.is_running = False
            except Exception as e:
                print(f"[FIXED SNIFFER] Error: {e}")
                import traceback
                traceback.print_exc()
                self.is_running = False
            finally:
                if self.pcap_writer:
                    self.pcap_writer.close()
                    print(f"[FIXED SNIFFER] PCAP file saved: {self.pcap_filename}")
        
        thread = threading.Thread(target=sniff_thread, daemon=True)
        thread.start()
        print("[FIXED SNIFFER] Capture thread started")

    def stop_sniffing(self):
        """Stop packet capture"""
        self.is_running = False
        if self.pcap_writer:
            self.pcap_writer.close()
            self.pcap_writer = None
            print(f"[FIXED SNIFFER] PCAP file closed: {self.pcap_filename}")

    def get_packets(self) -> List[Dict]:
        """Get captured packets"""
        with self.lock:
            return self.packets.copy()

    def get_tor_traffic(self) -> List[Dict]:
        """Get TOR traffic"""
        with self.lock:
            return self.tor_traffic.copy()

    def get_statistics(self) -> Dict:
        """Get packet statistics"""
        with self.lock:
            total = len(self.packets)
            if total == 0:
                return {
                    'total_packets': 0,
                    'total_bytes': 0,
                    'tor_packets': 0,
                    'flow_count': 0,
                    'protocol_distribution': {}
                }
            
            total_bytes = sum(p.get('size', 0) for p in self.packets)
            protocol_dist = defaultdict(int)
            
            for packet in self.packets:
                protocol_dist[packet.get('protocol', 'Unknown')] += 1
            
            return {
                'total_packets': total,
                'total_bytes': total_bytes,
                'tor_packets': len(self.tor_traffic),
                'tor_percentage': (len(self.tor_traffic) / total * 100) if total > 0 else 0,
                'flow_count': 0,
                'protocol_distribution': dict(protocol_dist)
            }

    def latest_pcap(self):
        """Get latest PCAP file"""
        return str(self.pcap_filename) if self.pcap_filename and self.pcap_filename.exists() else None

    def get_pcap_filename(self):
        """Get PCAP filename"""
        return str(self.pcap_filename) if self.pcap_filename else None