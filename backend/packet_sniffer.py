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
from datetime import datetime
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
        self.max_packets = packet_limit or 1000

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
        if len(self.packets) >= self.max_packets:
            # Rotate out old packets to keep memory manageable
            with self.lock:
                self.packets = self.packets[100:]  # Remove oldest 100 packets
                return

        try:
            with self.lock:
                packet_info = self.extract_packet_info(packet)
                if packet_info:
                    self.packets.append(packet_info)

                    # Check for TOR traffic
                    if self.is_tor_traffic(packet_info):
                        self.tor_traffic.append(packet_info)

                    # Track flows
                    flow_key = self.get_flow_key(packet_info)
                    if flow_key:
                        self.flows[flow_key].append(packet_info)
                    
                    # Print periodic status (every 100 packets)
                    if len(self.packets) % 100 == 0:
                        print(f"[PACKET SNIFFER] Captured {len(self.packets)} packets | TOR: {len(self.tor_traffic)} | Flows: {len(self.flows)}")

                    # Persist: try pcap via scapy's PcapWriter, else JSONL fallback
                    try:
                        if SCAPY_AVAILABLE and 'PcapWriter' in globals() and PcapWriter is not None:
                            if self._writer is None:
                                self._open_new_pcap()
                            try:
                                self._writer.write(packet)
                            except Exception:
                                # fallback write raw bytes
                                with open(self._current_pcap_path, 'ab') as f:
                                    f.write(bytes(packet))
                            try:
                                self._current_size = os.path.getsize(self._current_pcap_path)
                            except Exception:
                                self._current_size += len(bytes(packet))
                        else:
                            # JSON line
                            if self._json_fallback is None:
                                self._open_new_json()
                            self._json_fallback.write(json.dumps(packet_info, default=str) + '\n')
                            self._json_fallback.flush()
                            try:
                                self._current_size = os.path.getsize(self._current_pcap_path)
                            except Exception:
                                self._current_size += len(json.dumps(packet_info))
                    except Exception:
                        pass

                    # rotation
                    try:
                        self._maybe_rotate()
                    except Exception:
                        pass
        except Exception as e:
            print(f"[PACKET SNIFFER] Error processing packet: {e}")
    
    def extract_packet_info(self, packet) -> Dict:
        """Extract relevant information from packet"""
        try:
            info = {
                'timestamp': datetime.now().isoformat(),
                'size': len(packet),
                'protocols': []
            }
            
            # IP Layer
            if IP in packet:
                ip_layer = packet[IP]
                info['src_ip'] = ip_layer.src
                info['dst_ip'] = ip_layer.dst
                info['ttl'] = ip_layer.ttl
                info['protocols'].append('IP')
            else:
                # Handle non-IP packets
                info['protocols'].append('OTHER')
                info['raw_length'] = len(packet)
                return info
            
            # TCP Layer
            if TCP in packet:
                tcp_layer = packet[TCP]
                info['src_port'] = tcp_layer.sport
                info['dst_port'] = tcp_layer.dport
                # Convert scapy FlagValue to string for JSON serialization
                try:
                    info['flags'] = str(tcp_layer.flags)
                except Exception:
                    info['flags'] = int(tcp_layer.flags)
                info['protocols'].append('TCP')
                info['payload_size'] = len(tcp_layer.payload)
                
                # Try to detect HTTP (plain-text) using scapy HTTP layers or raw payload heuristic
                try:
                    if SCAPY_AVAILABLE:
                        try:
                            from scapy.layers.http import HTTPRequest, HTTPResponse  # type: ignore
                            http_layer = None
                            if packet.haslayer(HTTPRequest):
                                http_layer = packet[HTTPRequest]
                            elif packet.haslayer(HTTPResponse):
                                http_layer = packet[HTTPResponse]
                            if http_layer is not None:
                                h = {}
                                try:
                                    if hasattr(http_layer, 'Method'):
                                        h['method'] = (http_layer.Method.decode() if isinstance(http_layer.Method, bytes) else str(http_layer.Method))
                                except Exception:
                                    pass
                                try:
                                    if hasattr(http_layer, 'Host'):
                                        h['host'] = (http_layer.Host.decode() if isinstance(http_layer.Host, bytes) else str(http_layer.Host))
                                except Exception:
                                    pass
                                try:
                                    if hasattr(http_layer, 'Path'):
                                        h['path'] = (http_layer.Path.decode() if isinstance(http_layer.Path, bytes) else str(http_layer.Path))
                                except Exception:
                                    pass
                                if h:
                                    info['http'] = h
                        except Exception:
                            # Fallback: inspect raw TCP payload for HTTP methods
                            try:
                                raw = bytes(tcp_layer.payload)
                                if raw:
                                    for m in (b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS '):
                                        if raw.startswith(m):
                                            try:
                                                s = raw.split(b'\r\n\r\n', 1)[0].split(b'\r\n')
                                                first = s[0].decode(errors='ignore')
                                                parts = first.split(' ')
                                                h = {'method': parts[0] if parts else None}
                                                for line in s[1:]:
                                                    if line.lower().startswith(b'host:'):
                                                        try:
                                                            h['host'] = line.split(b':',1)[1].strip().decode(errors='ignore')
                                                        except Exception:
                                                            pass
                                                info['http'] = h
                                            except Exception:
                                                pass
                                            break
                            except Exception:
                                pass
                except Exception:
                    pass
            
            # UDP Layer
            elif UDP in packet:
                udp_layer = packet[UDP]
                info['src_port'] = udp_layer.sport
                info['dst_port'] = udp_layer.dport
                info['protocols'].append('UDP')
                info['payload_size'] = len(udp_layer.payload)
            
            # ICMP Layer
            elif ICMP in packet:
                icmp_layer = packet[ICMP]
                info['icmp_type'] = icmp_layer.type
                info['icmp_code'] = icmp_layer.code
                info['protocols'].append('ICMP')
            
            # Detect TOR-like traffic
            if self.is_tor_traffic(info):
                info['tor_like'] = True
                
            return info
        except Exception as e:
            # Return minimal packet info even on error
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'protocols': ['ERROR'],
                'size': len(packet) if packet else 0
            }
    
    def is_tor_traffic(self, packet_info: Dict) -> bool:
        """Identify potential TOR traffic"""
        tor_ports = [9001, 9002, 9030, 9050, 9051, 443, 80, 8080, 8443]
        
        if 'src_port' in packet_info and 'dst_port' in packet_info:
            if packet_info['dst_port'] in tor_ports or packet_info['src_port'] in tor_ports:
                # Additional heuristic: check for HTTPS (443) with suspicious patterns
                if packet_info['dst_port'] == 443 and packet_info.get('payload_size', 0) > 100:
                    return True
                if packet_info['dst_port'] == 9001:  # Tor OR port
                    return True

        # Check by IP address against known relay IPs
        try:
            src = packet_info.get('src_ip')
            dst = packet_info.get('dst_ip')
            if src in self.relay_ips or dst in self.relay_ips:
                return True
        except Exception:
            pass

        return False

    def _relay_refresher_loop(self):
        while True:
            try:
                self._refresh_relay_ips()
            except Exception:
                pass
            time.sleep(self._relay_refresh_interval)

    def _refresh_relay_ips(self):
        try:
            r = requests.get(self._relay_source, timeout=10)
            if r.status_code != 200:
                return
            j = r.json()
            ips = set()
            for relay in j.get('relays', []):
                for addr in relay.get('or_addresses', []):
                    ip = addr.split(':')[0].strip('[]')
                    if ip:
                        ips.add(ip)
                for addr in relay.get('exit_addresses', []):
                    ip = addr.split(':')[0].strip('[]')
                    if ip:
                        ips.add(ip)
            with self.lock:
                self.relay_ips = ips
        except Exception:
            pass
    
    def get_flow_key(self, packet_info: Dict) -> str:
        """Get flow key for flow tracking"""
        if 'src_ip' in packet_info and 'dst_ip' in packet_info:
            if 'src_port' in packet_info and 'dst_port' in packet_info:
                return f"{packet_info['src_ip']}:{packet_info['src_port']}-{packet_info['dst_ip']}:{packet_info['dst_port']}"
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
        print(f"[PACKET SNIFFER] Starting live capture on interface: {self.interface or 'default'}")
        print(f"[PACKET SNIFFER] Maximum packets: {self.max_packets}")
        print(f"[PACKET SNIFFER] PCAP storage: {self.pcap_dir}")
        
        def sniff_thread():
            try:
                print("[PACKET SNIFFER] Capture thread started - listening for packets...")
                
                # Start sniffing without filter for all traffic (like Wireshark)
                sniff(
                    prn=self.packet_callback,
                    iface=self.interface,
                    store=False,
                    stop_filter=lambda x: not self.is_running
                )
                
                print("[PACKET SNIFFER] Capture stopped")
            except PermissionError:
                error_msg = "[PACKET SNIFFER] ERROR: Root/Administrator privileges required for packet capture"
                print(error_msg)
                print("[PACKET SNIFFER] On Windows: Run as Administrator")
                print("[PACKET SNIFFER] On Linux: Run with sudo")
                with self.lock:
                    self.is_running = False
            except Exception as e:
                error_msg = f"[PACKET SNIFFER] Capture error: {e}"
                print(error_msg)
                import traceback
                traceback.print_exc()
                with self.lock:
                    self.is_running = False
        
        thread = threading.Thread(target=sniff_thread, daemon=True)
        thread.start()
        print("[PACKET SNIFFER] Background thread launched successfully")
    
    def stop_sniffing(self):
        """Stop packet capture"""
        self.is_running = False
        # Close PCAP writer
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None
        if self._json_fallback:
            try:
                self._json_fallback.close()
            except Exception:
                pass
            self._json_fallback = None
    
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
        # Close existing
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None

        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        filename = f'capture_{ts}.pcap'
        path = self.pcap_dir / filename
        # Use PcapWriter when possible
        try:
            if SCAPY_AVAILABLE and 'PcapWriter' in globals() and PcapWriter is not None:
                self._writer = PcapWriter(str(path), append=False, sync=True)
            else:
                self._writer = None
        except Exception:
            self._writer = None

        # for bookkeeping we still set path
        self._current_pcap_path = str(path)
        self._current_start_time = time.time()
        self._current_size = 0

    def _open_new_json(self):
        # Close existing JSON fallback
        if self._json_fallback:
            try:
                self._json_fallback.close()
            except Exception:
                pass
            self._json_fallback = None

        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        filename = f'capture_{ts}.jsonl'
        path = self.pcap_dir / filename
        self._current_pcap_path = str(path)
        self._json_fallback = open(self._current_pcap_path, 'a', encoding='utf8')
        self._current_start_time = time.time()
        self._current_size = 0

    def _maybe_rotate(self):
        try:
            now = time.time()
            if self._current_pcap_path is None:
                return
            # rotate by size
            if self.rotate_size_bytes and self._current_size >= self.rotate_size_bytes:
                if SCAPY_AVAILABLE and 'PcapWriter' in globals() and PcapWriter is not None:
                    self._open_new_pcap()
                else:
                    self._open_new_json()
                self._purge_old()
                return
            # rotate by interval
            if self.rotate_interval and (now - (self._current_start_time or now)) >= self.rotate_interval:
                if SCAPY_AVAILABLE and 'PcapWriter' in globals() and PcapWriter is not None:
                    self._open_new_pcap()
                else:
                    self._open_new_json()
                self._purge_old()
        except Exception:
            pass

    def _purge_old(self):
        try:
            files = sorted(self.pcap_dir.iterdir(), key=lambda p: p.stat().st_mtime)
            # keep newest retention_count
            if len(files) <= self.retention_count:
                return
            to_remove = files[0: len(files) - self.retention_count]
            for f in to_remove:
                try:
                    f.unlink()
                except Exception:
                    pass
        except Exception:
            pass

    def latest_pcap(self):
        try:
            files = sorted(self.pcap_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
            if not files:
                return None
            return str(files[0])
        except Exception:
            return None
    
    def get_pcap_filename(self):
        """Get current PCAP filename"""
        return self._current_pcap_path

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
