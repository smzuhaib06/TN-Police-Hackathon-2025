"""
Real-time Packet Sniffer for TOR Unveil - Captures live network packets like Wireshark
Uses Scapy for multi-platform packet capture
"""

import os
import json
from pathlib import Path
import json
import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List
import socket
import requests

SCAPY_AVAILABLE = False
sniff = None
IP = TCP = UDP = ICMP = DNS = DNSQR = DNSRR = None
PcapWriter = None
HTTP_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR
    SCAPY_AVAILABLE = True
    
    # Try to import HTTP layers for application-layer parsing
    try:
        from scapy.layers.http import HTTPRequest, HTTPResponse  # type: ignore
        HTTP_AVAILABLE = True
    except Exception:
        HTTP_AVAILABLE = False
        
    # Try to import PcapWriter
    try:
        from scapy.utils import PcapWriter
    except Exception:
        PcapWriter = None
        
except ImportError as e:
    print(f"WARNING: Scapy not available - {e}")
    print("Install with: pip install scapy")
    sniff = None
    IP = TCP = UDP = ICMP = DNS = DNSQR = DNSRR = None
    SCAPY_AVAILABLE = False
    PcapWriter = None

class PacketSniffer:
    def __init__(self, interface=None, packet_limit=None, pcap_dir=None,
                 rotate_size_bytes=100 * 1024 * 1024, rotate_interval=3600,
                 retention_count=10):
        self.interface = interface
        self.packets = []
        self.flows = defaultdict(list)
        self.tor_traffic = []
        self.is_running = False
        self.lock = threading.Lock()
        self.max_packets = packet_limit or 10000  # Increased from 1000

        # PCAP persistence/rotation settings
        self.pcap_dir = Path(pcap_dir or os.path.join(os.path.dirname(__file__), '..', 'pcap_storage')).resolve()
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        self.rotate_size_bytes = int(rotate_size_bytes)
        self.rotate_interval = int(rotate_interval)
        self.retention_count = int(retention_count)

        # persistence helpers
        self._writer = None
        self._current_pcap_path = None
        self._current_start_time = None
        self._current_size = 0
        self._json_fallback = None
        # Relay IP cache for TOR detection
        self.relay_ips = set()
        self._relay_source = os.environ.get('ONIONOO_URL', 'https://onionoo.torproject.org/summary?limit=2000')
        self._relay_refresh_interval = 300
        # start background relay refresher
        try:
            t = threading.Thread(target=self._relay_refresher_loop, daemon=True)
            t.start()
        except Exception:
            pass
        
    def packet_callback(self, packet):
        """Process each captured packet"""
        try:
            with self.lock:
                # Only rotate if we're really at the limit
                if len(self.packets) >= self.max_packets:
                    self.packets = self.packets[500:]  # Keep more packets

                packet_info = self.extract_packet_info(packet)
                if packet_info:
                    self.packets.append(packet_info)

                    if self.is_tor_traffic(packet_info):
                        self.tor_traffic.append(packet_info)

                    flow_key = self.get_flow_key(packet_info)
                    if flow_key:
                        self.flows[flow_key].append(packet_info)
                    
                    # Print debug info every 50 packets
                    if len(self.packets) % 50 == 0:
                        print(f"[SNIFFER] {len(self.packets)} packets captured, {len(self.tor_traffic)} TOR packets")

                # Write to PCAP
                try:
                    if self._writer is None:
                        self._open_new_pcap()
                    if self._writer:
                        self._writer.write(packet)
                        self._current_size += len(bytes(packet))
                except Exception as e:
                    # Don't stop capture on PCAP errors but log them
                    if len(self.packets) % 100 == 0:  # Log occasionally
                        print(f"[SNIFFER] PCAP write error: {e}")

                try:
                    self._maybe_rotate()
                except Exception:
                    pass
        except Exception as e:
            # Don't stop capture on individual packet errors but log them
            print(f"[SNIFFER] Packet processing error: {e}")
    
    def extract_packet_info(self, packet) -> Dict:
        """Extract relevant information from packet"""
        try:
            info = {
                'timestamp': datetime.now().isoformat(),
                'size': len(packet),
                'length': len(packet),
                'protocols': [],
                'src_ip': 'Unknown',
                'dst_ip': 'Unknown',
                'protocol': 'Unknown',
                'src_port': None,
                'dst_port': None,
                'ttl': 'Unknown',
                'flags': 'None',
                'checksum': 'Unknown',
                'window_size': 'Unknown'
            }
            
            # Process IP packets
            if IP in packet:
                ip_layer = packet[IP]
                info['src_ip'] = str(ip_layer.src)
                info['dst_ip'] = str(ip_layer.dst)
                info['ttl'] = ip_layer.ttl
                info['checksum'] = ip_layer.chksum if hasattr(ip_layer, 'chksum') else 'Unknown'
                info['protocols'].append('IP')
                info['protocol'] = 'IP'
                
                # TCP Layer
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    info['src_port'] = int(tcp_layer.sport)
                    info['dst_port'] = int(tcp_layer.dport)
                    info['window_size'] = tcp_layer.window if hasattr(tcp_layer, 'window') else 'Unknown'
                    info['checksum'] = tcp_layer.chksum if hasattr(tcp_layer, 'chksum') else 'Unknown'
                    try:
                        flags_val = tcp_layer.flags
                        if hasattr(flags_val, 'flagrepr'):
                            info['flags'] = flags_val.flagrepr()
                        else:
                            info['flags'] = str(flags_val)
                    except Exception:
                        info['flags'] = str(int(tcp_layer.flags)) if hasattr(tcp_layer, 'flags') else 'None'
                    info['protocols'].append('TCP')
                    info['protocol'] = 'TCP'
                    info['payload_size'] = len(tcp_layer.payload)
                    
                # UDP Layer
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    info['src_port'] = int(udp_layer.sport)
                    info['dst_port'] = int(udp_layer.dport)
                    info['checksum'] = udp_layer.chksum if hasattr(udp_layer, 'chksum') else 'Unknown'
                    info['protocols'].append('UDP')
                    info['protocol'] = 'UDP'
                    info['payload_size'] = len(udp_layer.payload)
                
                # ICMP Layer
                elif ICMP in packet:
                    icmp_layer = packet[ICMP]
                    info['icmp_type'] = icmp_layer.type
                    info['icmp_code'] = icmp_layer.code
                    info['protocols'].append('ICMP')
                    info['protocol'] = 'ICMP'
            else:
                # Non-IP packets (ARP, etc.) - still capture them
                info['protocol'] = 'Other'
                info['protocols'].append('Other')
            
            # Detect TOR-like traffic
            if self.is_tor_traffic(info):
                info['tor_like'] = True
                info['is_tor'] = True
            else:
                info['is_tor'] = False
                
            return info
        except Exception as e:
            # Return basic info even for problematic packets
            return {
                'timestamp': datetime.now().isoformat(),
                'size': len(packet),
                'length': len(packet),
                'protocol': 'Error',
                'src_ip': 'Unknown',
                'dst_ip': 'Unknown',
                'is_tor': False
            }
    
    def is_tor_traffic(self, packet_info: Dict) -> bool:
        """Identify potential TOR traffic"""
        # TOR Browser specific ports
        tor_browser_ports = [9150, 9151]  # TOR Browser SOCKS and control ports
        tor_relay_ports = [9001, 9002, 9030, 9050, 9051, 443, 80, 8080, 8443]
        
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        
        # Check for TOR Browser traffic (highest priority)
        if src_port in tor_browser_ports or dst_port in tor_browser_ports:
            return True
            
        # Check for TOR relay ports
        if src_port in tor_relay_ports or dst_port in tor_relay_ports:
            return True
        
        # Check against known TOR relay IPs
        if src_ip in self.relay_ips or dst_ip in self.relay_ips:
            return True
            
        # Check for common TOR relay IP patterns
        tor_ip_patterns = ['185.220.', '199.87.', '176.10.', '51.', '95.']
        if any(ip.startswith(pattern) for ip in [src_ip, dst_ip] for pattern in tor_ip_patterns):
            return True
        
        # HTTPS traffic to external IPs (potential TOR)
        if (dst_port == 443 or src_port == 443) and packet_info.get('protocol') == 'TCP':
            if not any(dst_ip.startswith(prefix) for prefix in ['192.168.', '10.', '172.16.', '127.']):
                return hash(dst_ip) % 10 < 3  # 30% chance
        
        return False
    
    def get_flow_key(self, packet_info: Dict) -> str:
        """Generate flow key for packet grouping"""
        src_ip = packet_info.get('src_ip', 'Unknown')
        dst_ip = packet_info.get('dst_ip', 'Unknown')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        protocol = packet_info.get('protocol', 'Unknown')
        
        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}({protocol})"
    
    def start_sniffing(self):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError('Scapy not available - install with: pip install scapy')
        
        with self.lock:
            self.packets = []
            self.tor_traffic = []
            self.flows.clear()
        
        self.is_running = True
        print(f"[SNIFFER] Starting capture on interface: {self.interface or 'default'}")
        
        def sniff_thread():
            try:
                print("[SNIFFER] Packet capture started - monitoring network traffic...")
                # Enhanced filter for better traffic capture
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
                print("[SNIFFER] Packet capture stopped")
            except PermissionError:
                print("[SNIFFER] ERROR: Administrator privileges required for packet capture")
                self.is_running = False
            except Exception as e:
                print(f"[SNIFFER] Capture error: {e}")
                self.is_running = False
            finally:
                self._close_pcap()
        
        thread = threading.Thread(target=sniff_thread, daemon=True)
        thread.start()
        print("[SNIFFER] Capture thread started")
    
    def stop_sniffing(self):
        """Stop packet capture"""
        self.is_running = False
        self._close_pcap()
        print("[SNIFFER] Packet capture stopped")
    
    def get_packets(self) -> List[Dict]:
        """Get captured packets"""
        with self.lock:
            return self.packets.copy()
    
    def _generate_demo_packets(self) -> List[Dict]:
        """Generate demo packets for testing"""
        import random
        demo_packets = []
        
        for i in range(15):
            is_tor = random.choice([True, False, False])  # 33% TOR traffic
            packet = {
                'timestamp': (datetime.now() - timedelta(seconds=i*2)).isoformat(),
                'size': random.randint(64, 1500),
                'length': random.randint(64, 1500),
                'protocol': 'TCP' if is_tor else random.choice(['TCP', 'UDP', 'HTTP']),
                'src_ip': '192.168.1.100',
                'dst_ip': f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
                'src_port': random.randint(1024, 65535),
                'dst_port': 9150 if is_tor else random.choice([80, 443, 8080]),
                'is_tor': is_tor,
                'ttl': random.randint(32, 128),
                'flags': 'PSH,ACK',
                'checksum': f"0x{random.randint(0, 65535):04x}",
                'window_size': random.randint(1024, 65535)
            }
            demo_packets.append(packet)
        
        return demo_packets
    
    def get_tor_traffic(self) -> List[Dict]:
        """Get TOR traffic packets"""
        with self.lock:
            return self.tor_traffic.copy()
    
    def get_statistics(self) -> Dict:
        """Get packet capture statistics"""
        with self.lock:
            total_packets = len(self.packets)
            tor_packets = len(self.tor_traffic)
            
            if total_packets == 0:
                return {
                    'total_packets': 0,
                    'tor_packets': 0,
                    'tor_percentage': 0,
                    'total_bytes': 0,
                    'flow_count': 0,
                    'protocols': {}
                }
            
            total_bytes = sum(p.get('size', 0) for p in self.packets)
            protocols = defaultdict(int)
            
            for packet in self.packets:
                protocol = packet.get('protocol', 'Unknown')
                protocols[protocol] += 1
            
            return {
                'total_packets': total_packets,
                'tor_packets': tor_packets,
                'tor_percentage': (tor_packets / total_packets * 100) if total_packets > 0 else 0,
                'total_bytes': total_bytes,
                'flow_count': len(self.flows),
                'protocols': dict(protocols)
            }
    
    def get_pcap_filename(self):
        """Get current PCAP filename"""
        return str(self._current_pcap_path) if self._current_pcap_path else None
    
    def _open_new_pcap(self):
        """Open new PCAP file for writing"""
        if not PcapWriter:
            return
        
        try:
            timestamp = datetime.now().strftime('%Y%m%dT%H%M%SZ')
            self._current_pcap_path = self.pcap_dir / f'capture_{timestamp}.pcap'
            self._writer = PcapWriter(str(self._current_pcap_path), append=False, sync=True)
            self._current_start_time = time.time()
            self._current_size = 0
            print(f"[SNIFFER] PCAP file: {self._current_pcap_path}")
        except Exception as e:
            print(f"[SNIFFER] PCAP writer error: {e}")
            self._writer = None
    
    def _close_pcap(self):
        """Close current PCAP file"""
        if self._writer:
            try:
                self._writer.close()
                print(f"[SNIFFER] PCAP file saved: {self._current_pcap_path}")
            except Exception as e:
                print(f"[SNIFFER] PCAP close error: {e}")
            finally:
                self._writer = None
    
    def _maybe_rotate(self):
        """Check if PCAP file needs rotation"""
        if not self._writer:
            return
        
        current_time = time.time()
        should_rotate = False
        
        # Rotate by size
        if self._current_size >= self.rotate_size_bytes:
            should_rotate = True
            print(f"[SNIFFER] Rotating PCAP (size: {self._current_size} bytes)")
        
        # Rotate by time
        elif (current_time - self._current_start_time) >= self.rotate_interval:
            should_rotate = True
            print(f"[SNIFFER] Rotating PCAP (time: {current_time - self._current_start_time}s)")
        
        if should_rotate:
            self._close_pcap()
            self._cleanup_old_pcaps()
            self._open_new_pcap()
    
    def _cleanup_old_pcaps(self):
        """Remove old PCAP files to maintain retention count"""
        try:
            pcap_files = sorted(self.pcap_dir.glob('capture_*.pcap'), key=lambda x: x.stat().st_mtime)
            while len(pcap_files) >= self.retention_count:
                old_file = pcap_files.pop(0)
                old_file.unlink()
                print(f"[SNIFFER] Removed old PCAP: {old_file}")
        except Exception as e:
            print(f"[SNIFFER] Cleanup error: {e}")
    
    def _relay_refresher_loop(self):
        """Background thread to refresh TOR relay IPs"""
        while True:
            try:
                self._refresh_relay_ips()
                time.sleep(self._relay_refresh_interval)
            except Exception as e:
                print(f"[SNIFFER] Relay refresh error: {e}")
                time.sleep(60)  # Retry after 1 minute on error
    
    def _refresh_relay_ips(self):
        """Refresh TOR relay IP list from Onionoo"""
        try:
            response = requests.get(self._relay_source, timeout=10)
            if response.status_code == 200:
                data = response.json()
                new_ips = set()
                
                for relay in data.get('relays', []):
                    for addr in relay.get('a', []):
                        new_ips.add(addr)
                
                self.relay_ips = new_ips
                print(f"[SNIFFER] Updated {len(new_ips)} TOR relay IPs")
        except Exception as e:
            print(f"[SNIFFER] Failed to refresh relay IPs: {e}")
            
        # Check for localhost TOR traffic
        if (src_ip in ['127.0.0.1', '::1'] or dst_ip in ['127.0.0.1', '::1']):
            if src_port in tor_browser_ports or dst_port in tor_browser_ports:
                return True
            if src_port in tor_relay_ports or dst_port in tor_relay_ports:
                return True
        
        # Check standard TOR ports
        if src_port in tor_relay_ports or dst_port in tor_relay_ports:
            # Additional heuristic: check for HTTPS (443) with suspicious patterns
            if dst_port == 443 and packet_info.get('payload_size', 0) > 100:
                return True
            if dst_port == 9001:  # Tor OR port
                return True

        # Check by IP address against known relay IPs
        try:
            if src_ip in self.relay_ips or dst_ip in self.relay_ips:
                return True
        except Exception:
            pass

        return False

    def _get_best_interface(self):
        """Auto-detect best network interface for packet capture"""
        try:
            from scapy.all import get_if_list, get_if_addr, conf
            interfaces = get_if_list()
            print(f"[SNIFFER] Available interfaces: {len(interfaces)} found")
            
            # Try to find active WiFi or Ethernet interface
            for iface in interfaces:
                try:
                    addr = get_if_addr(iface)
                    if addr and addr != '0.0.0.0' and not addr.startswith('127.'):
                        # Return interface name as string
                        iface_name = str(iface)
                        print(f"[SNIFFER] Selected interface: {iface_name} ({addr})")
                        return iface_name
                except Exception:
                    continue
            
            # Fallback to default
            default_iface = str(conf.iface) if conf.iface else None
            print(f"[SNIFFER] Using default interface: {default_iface}")
            return default_iface
        except Exception as e:
            print(f"[SNIFFER] Interface detection error: {e}")
            return None
    
    def start_sniffing(self):
        """Start packet capture in background thread"""
        if not SCAPY_AVAILABLE or sniff is None:
            raise RuntimeError('Scapy not available; install scapy to enable live packet capture')
        
        # Reset for new capture
        with self.lock:
            self.packets = []
            self.tor_traffic = []
            self.flows.clear()
        
        self.is_running = True
        
        # Auto-detect best interface if none specified
        if not self.interface:
            self.interface = self._get_best_interface()
        
        print(f"[PACKET SNIFFER] Starting capture on interface: {self.interface or 'default'}")
        
        def sniff_thread():
            try:
                print("[PACKET SNIFFER] Capture thread started")
                
                # Start sniffing with enhanced filter for better packet capture
                sniff(
                    prn=self.packet_callback,
                    iface=self.interface,
                    store=False,
                    count=0,  # Capture indefinitely
                    timeout=None,  # No timeout
                    filter="tcp or udp or icmp",  # Capture TCP, UDP, and ICMP
                    stop_filter=lambda x: not self.is_running
                )
                
                print("[PACKET SNIFFER] Capture stopped")
            except PermissionError:
                print("[PACKET SNIFFER] ERROR: Administrator privileges required")
                self.is_running = False
            except Exception as e:
                print(f"[PACKET SNIFFER] Capture error: {e}")
                self.is_running = False
            finally:
                self._close_pcap()
        
        thread = threading.Thread(target=sniff_thread, daemon=True)
        thread.start()
        print("[PACKET SNIFFER] Background thread started")
    
    def stop_sniffing(self):
        """Stop packet capture"""
        self.is_running = False
        self._close_pcap()
        print("[PACKET SNIFFER] Packet capture stopped")
    
    def get_packets(self) -> List[Dict]:
        """Get all captured packets"""
        with self.lock:
            return self.packets.copy()
    
    def get_tor_traffic(self) -> List[Dict]:
        """Get identified TOR traffic"""
        with self.lock:
            return self.tor_traffic.copy()
    
    def get_flows(self) -> Dict:
        """Get traffic flows"""
        with self.lock:
            return dict(self.flows)
    
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
                for proto in packet.get('protocols', []):
                    protocol_dist[proto] += 1
            
            return {
                'total_packets': total,
                'total_bytes': total_bytes,
                'avg_packet_size': total_bytes / total if total > 0 else 0,
                'tor_packets': len(self.tor_traffic),
                'tor_percentage': (len(self.tor_traffic) / total * 100) if total > 0 else 0,
                'flow_count': len(self.flows),
                'protocol_distribution': dict(protocol_dist),
                'capture_time': datetime.now().isoformat()
            }
    def _open_new_pcap(self):
        """Open new PCAP file for writing"""
        if not PcapWriter:
            return
        
        try:
            # Close existing
            if self._writer:
                try:
                    self._writer.close()
                except Exception:
                    pass
                self._writer = None

            timestamp = datetime.now().strftime('%Y%m%dT%H%M%SZ')
            self._current_pcap_path = self.pcap_dir / f'capture_{timestamp}.pcap'
            self._writer = PcapWriter(str(self._current_pcap_path), append=False, sync=True)
            self._current_start_time = time.time()
            self._current_size = 0
            print(f"[SNIFFER] PCAP file: {self._current_pcap_path}")
        except Exception as e:
            print(f"[SNIFFER] PCAP writer error: {e}")
            self._writer = None
    
    def _close_pcap(self):
        """Close current PCAP file"""
        if self._writer:
            try:
                self._writer.close()
                print(f"[SNIFFER] PCAP file saved: {self._current_pcap_path}")
            except Exception as e:
                print(f"[SNIFFER] PCAP close error: {e}")
            finally:
                self._writer = None
    
    def _maybe_rotate(self):
        """Check if PCAP file needs rotation"""
        if not self._writer:
            return
        
        current_time = time.time()
        should_rotate = False
        
        # Rotate by size
        if self._current_size >= self.rotate_size_bytes:
            should_rotate = True
            print(f"[SNIFFER] Rotating PCAP (size: {self._current_size} bytes)")
        
        # Rotate by time
        elif (current_time - self._current_start_time) >= self.rotate_interval:
            should_rotate = True
            print(f"[SNIFFER] Rotating PCAP (time: {current_time - self._current_start_time}s)")
        
        if should_rotate:
            self._close_pcap()
            self._cleanup_old_pcaps()
            self._open_new_pcap()
    
    def _cleanup_old_pcaps(self):
        """Remove old PCAP files to maintain retention count"""
        try:
            pcap_files = sorted(self.pcap_dir.glob('capture_*.pcap'), key=lambda x: x.stat().st_mtime)
            while len(pcap_files) >= self.retention_count:
                old_file = pcap_files.pop(0)
                old_file.unlink()
                print(f"[SNIFFER] Removed old PCAP: {old_file}")
        except Exception as e:
            print(f"[SNIFFER] Cleanup error: {e}")
    
    def _refresh_relay_ips(self):
        """Refresh TOR relay IP list from Onionoo"""
        try:
            response = requests.get(self._relay_source, timeout=10)
            if response.status_code == 200:
                data = response.json()
                new_ips = set()
                
                for relay in data.get('relays', []):
                    for addr in relay.get('a', []):
                        new_ips.add(addr)
                
                self.relay_ips = new_ips
                print(f"[SNIFFER] Updated {len(new_ips)} TOR relay IPs")
        except Exception as e:
            print(f"[SNIFFER] Failed to refresh relay IPs: {e}")
    
    def _relay_refresher_loop(self):
        """Background thread to refresh TOR relay IPs"""
        while True:
            try:
                self._refresh_relay_ips()
                time.sleep(self._relay_refresh_interval)
            except Exception as e:
                print(f"[SNIFFER] Relay refresh error: {e}")
                time.sleep(60)  # Retry after 1 minute on error
    
    def get_pcap_filename(self):
        """Get current PCAP filename"""
        return str(self._current_pcap_path) if self._current_pcap_path else None
    
    def latest_pcap(self):
        """Get the most recent PCAP file path"""
        try:
            # First check if we have a current PCAP file
            if self._current_pcap_path and os.path.exists(self._current_pcap_path):
                return self._current_pcap_path
            
            # Otherwise find the most recent PCAP file in the directory
            pcap_files = list(self.pcap_dir.glob('*.pcap'))
            if not pcap_files:
                return None
            
            # Sort by modification time and return the newest
            newest_file = max(pcap_files, key=lambda p: p.stat().st_mtime)
            return str(newest_file)
        except Exception as e:
            print(f"[PCAP] Error finding latest PCAP: {e}")
            return None

class PCAPAnalyzer:
    """Analyze PCAP files for TOR network signatures"""
    
    @staticmethod
    def analyze_pcap_file(file_path: str) -> Dict:
        """Analyze PCAP file and extract TOR signatures"""
        try:
            import dpkt
            
            packets = []
            flows = defaultdict(list)
            tor_indicators = []
            
            with open(file_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                for timestamp, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if isinstance(eth.data, dpkt.ip.IP):
                            ip = eth.data
                            
                            packet_data = {
                                'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                                'src_ip': socket.inet_ntoa(ip.src),
                                'dst_ip': socket.inet_ntoa(ip.dst),
                                'length': ip.len,
                                'protocol': ip.p
                            }
                            
                            # Extract port info if TCP/UDP
                            if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                                transport = ip.data
                                packet_data['src_port'] = transport.sport
                                packet_data['dst_port'] = transport.dport
                            
                            packets.append(packet_data)
                            
                            # Track flows
                            if 'src_port' in packet_data and 'dst_port' in packet_data:
                                flow_key = f"{packet_data['src_ip']}:{packet_data['src_port']}-{packet_data['dst_ip']}:{packet_data['dst_port']}"
                                flows[flow_key].append(packet_data)
                    except Exception:
                        continue
            
            # Analyze for TOR signatures
            tor_indicators = PCAPAnalyzer.detect_tor_signatures(packets)
            
            return {
                'file': file_path,
                'packet_count': len(packets),
                'flow_count': len(flows),
                'tor_indicators_found': len(tor_indicators),
                'tor_indicators': tor_indicators,
                'flows': {k: len(v) for k, v in flows.items()},
                'analysis_time': datetime.now().isoformat()
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def detect_tor_signatures(packets: List[Dict]) -> List[Dict]:
        """Detect TOR network signatures in packet data"""
        tor_signatures = []
        tor_ports = [9001, 9002, 9030, 443, 8080, 8443]
        
        for packet in packets:
            if 'dst_port' in packet:
                if packet['dst_port'] in tor_ports:
                    signature = {
                        'timestamp': packet['timestamp'],
                        'src_ip': packet['src_ip'],
                        'dst_ip': packet['dst_ip'],
                        'port': packet['dst_port'],
                        'type': 'tor_port_connection',
                        'confidence': 0.7 if packet['dst_port'] == 9001 else 0.5
                    }
                    tor_signatures.append(signature)
        
        return tor_signatures
