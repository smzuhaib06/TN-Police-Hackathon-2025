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
        
        # Start relay IP refresh in background (don't block initialization)
        threading.Thread(target=self._refresh_relay_ips, daemon=True).start()
        
    def _refresh_relay_ips(self):
        """Refresh TOR relay IPs from Onionoo"""
        try:
            print("SNIFFER: Loading TOR relay IPs...")
            response = requests.get('https://onionoo.torproject.org/summary?limit=2000', timeout=5)
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
            else:
                print(f"SNIFFER: Failed to load relay IPs - HTTP {response.status_code}")
        except Exception as e:
            print(f"SNIFFER: Failed to load relay IPs: {e}")
            # Continue without relay IPs - not critical for basic functionality
    
    def start_capture(self):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available - install with: pip install scapy")
        
        self.is_running = True
        self.stats['start_time'] = datetime.now()
        
        # Start PCAP writer with unique filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]  # Include milliseconds
        pcap_file = os.path.join(self.pcap_dir, f'capture_{timestamp}.pcap')
        self.pcap_file = pcap_file  # Store for later reference
        self.pcap_writer = PcapWriter(pcap_file, append=False, sync=True)
        
        def capture_thread():
            try:
                print(f"SNIFFER: Starting capture on interface: {self.interface or 'default'}")
                # Use conf.iface for Windows compatibility
                from scapy.config import conf
                from scapy.arch import get_if_list
                
                # Try to get a working interface
                if self.interface:
                    iface = self.interface
                else:
                    # Get list of available interfaces
                    interfaces = get_if_list()
                    # Filter out loopback and try to find a real network interface
                    real_interfaces = [i for i in interfaces if not i.startswith('lo') and 'Loopback' not in i]
                    iface = real_interfaces[0] if real_interfaces else conf.iface
                
                print(f"SNIFFER: Using interface: {iface}")
                print(f"SNIFFER: Available interfaces: {get_if_list()[:5]}")
                
                sniff(
                    prn=self._process_packet,
                    iface=iface,
                    store=False,
                    timeout=1,  # Add timeout to prevent hanging
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
                
                # Check for TOR traffic and set flag
                packet_info['is_tor'] = self._is_tor_packet(packet_info)
                
                self.packets.append(packet_info)
                self.stats['total_packets'] += 1
                self.stats['bytes_captured'] += packet_info.get('size', 0)
                
                # Update protocol stats
                for proto in packet_info.get('protocols', []):
                    self.stats['protocols'][proto] += 1
                
                # Store TOR packets separately
                if packet_info['is_tor']:
                    self.tor_packets.append(packet_info)
                    self.stats['tor_packets'] += 1
                
                # Track flows
                flow_key = self._get_flow_key(packet_info)
                if flow_key:
                    self.flows[flow_key] += 1
                
        except Exception as e:
            print(f"SNIFFER: Packet processing error: {e}")
    
    def _extract_packet_info(self, packet):
        """Extract comprehensive packet information"""
        try:
            info = {
                'timestamp': datetime.now().isoformat(),
                'size': len(packet),
                'length': len(packet),
                'protocols': [],
                'is_tor': False,
                'info': '',
                'flags': '',
                'ttl': '',
                'checksum': '',
                'window_size': '',
                'payload': ''
            }
            
            if IP in packet:
                ip = packet[IP]
                info['src_ip'] = ip.src
                info['dst_ip'] = ip.dst
                info['ttl'] = ip.ttl
                info['checksum'] = ip.chksum
                info['protocols'].append('IP')
                
                if TCP in packet:
                    tcp = packet[TCP]
                    info['src_port'] = tcp.sport
                    info['dst_port'] = tcp.dport
                    info['flags'] = str(tcp.flags)
                    info['window_size'] = tcp.window
                    info['protocols'].append('TCP')
                    
                    # Extract payload
                    if Raw in packet and len(packet[Raw]) > 0:
                        payload = bytes(packet[Raw])
                        info['payload'] = payload.decode('utf-8', errors='ignore')[:500]
                        payload_str = info['payload']
                        
                        # HTTP Detection
                        if any(method in payload_str[:50] for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ']):
                            info['http_method'] = payload_str.split()[0] if payload_str.split() else 'Unknown'
                            if len(payload_str.split()) > 1:
                                info['http_url'] = payload_str.split()[1]
                                info['info'] = f"HTTP {info['http_method']} {info['http_url']}"
                            info['protocols'].append('HTTP')
                            
                            # Extract Host header
                            if 'Host: ' in payload_str:
                                host_line = [line for line in payload_str.split('\n') if line.startswith('Host: ')]
                                if host_line:
                                    info['http_host'] = host_line[0].replace('Host: ', '').strip()
                        
                        # HTTP Response
                        elif payload_str.startswith('HTTP/'):
                            status_line = payload_str.split('\n')[0]
                            if len(status_line.split()) >= 2:
                                info['http_status'] = status_line.split()[1]
                                info['info'] = f"HTTP Response {info['http_status']}"
                            info['protocols'].append('HTTP')
                        
                        # HTTPS/TLS Detection
                        elif payload.startswith(b'\x16\x03'):
                            info['tls_handshake'] = True
                            info['protocols'].append('TLS')
                            info['info'] = 'TLS Handshake'
                            
                            # Extract SNI from TLS handshake
                            try:
                                if len(payload) > 50:
                                    sni_start = payload.find(b'\x00\x00') + 5
                                    if sni_start > 5 and sni_start < len(payload) - 10:
                                        sni_len = payload[sni_start]
                                        if sni_len > 0 and sni_start + sni_len < len(payload):
                                            sni = payload[sni_start+1:sni_start+1+sni_len].decode('utf-8', errors='ignore')
                                            if '.' in sni and len(sni) < 100:
                                                info['tls_sni'] = sni
                                                info['info'] = f'TLS to {sni}'
                            except:
                                pass
                    
                    # Service detection by port
                    if tcp.dport == 80 or tcp.sport == 80:
                        info['service'] = 'HTTP'
                    elif tcp.dport == 443 or tcp.sport == 443:
                        info['service'] = 'HTTPS'
                        if not info['info']:
                            info['info'] = 'HTTPS Connection'
                    elif tcp.dport == 22 or tcp.sport == 22:
                        info['service'] = 'SSH'
                        info['info'] = 'SSH Connection'
                    elif tcp.dport == 21 or tcp.sport == 21:
                        info['service'] = 'FTP'
                        info['info'] = 'FTP Connection'
                    elif tcp.dport == 25 or tcp.sport == 25:
                        info['service'] = 'SMTP'
                        info['info'] = 'SMTP Connection'
                
                elif UDP in packet:
                    udp = packet[UDP]
                    info['src_port'] = udp.sport
                    info['dst_port'] = udp.dport
                    info['protocols'].append('UDP')
                    
                    # DNS Detection
                    if udp.dport == 53 or udp.sport == 53:
                        info['service'] = 'DNS'
                        if DNS in packet:
                            dns = packet[DNS]
                            if dns.qr == 0 and dns.qd:  # Query
                                try:
                                    query_name = str(dns.qd.qname.decode())
                                    info['dns_query'] = query_name
                                    info['info'] = f'DNS Query: {query_name}'
                                except:
                                    info['dns_query'] = 'Unknown'
                                    info['info'] = 'DNS Query'
                            else:
                                info['info'] = 'DNS Response'
                            info['protocols'].append('DNS')
                
                elif ICMP in packet:
                    icmp = packet[ICMP]
                    info['icmp_type'] = icmp.type
                    info['icmp_code'] = icmp.code
                    info['protocols'].append('ICMP')
                    info['info'] = f'ICMP Type {icmp.type}'
            
            # Set default info if empty
            if not info['info'] and info['protocols']:
                info['info'] = ' + '.join(info['protocols'])
            
            return info
        except Exception as e:
            print(f"Packet extraction error: {e}")
            return None
    
    def _is_tor_packet(self, packet_info):
        """Enhanced TOR traffic detection"""
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
        
        # Check for TOR-related domains in SNI
        sni = packet_info.get('tls_sni', '')
        if sni and ('.onion' in sni or 'tor' in sni.lower()):
            return True
        
        # Check HTTP requests to TOR-related domains
        http_host = packet_info.get('http_host', '')
        if http_host and ('tor' in http_host.lower() or '.onion' in http_host):
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
        """Get comprehensive capture statistics"""
        with self.lock:
            runtime = 0
            if self.stats['start_time']:
                runtime = (datetime.now() - self.stats['start_time']).total_seconds()
            
            # Count different types of traffic safely
            try:
                http_count = sum(1 for p in self.packets if 'HTTP' in p.get('protocols', []))
                https_count = sum(1 for p in self.packets if 'TLS' in p.get('protocols', []))
                dns_count = sum(1 for p in self.packets if 'DNS' in p.get('protocols', []))
            except:
                http_count = https_count = dns_count = 0
            
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
                'http_requests': http_count,
                'https_connections': https_count,
                'dns_queries': dns_count,
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

def get_or_create_sniffer():
    """Get or create sniffer instance"""
    global sniffer
    if sniffer is None:
        sniffer = EnhancedPacketSniffer()
    return sniffer

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
        try:
            return sniffer.get_statistics()
        except Exception as e:
            print(f"Error getting stats: {e}")
            return {'total_packets': 0, 'tor_packets': 0, 'error': str(e)}
    return {'total_packets': 0, 'tor_packets': 0, 'status': 'not_running'}

def get_tor_traffic(limit=100):
    """Get captured TOR traffic"""
    global sniffer
    if sniffer:
        return sniffer.get_tor_packets(limit=limit)
    return []

def get_http_requests(limit=50):
    """Get captured HTTP requests"""
    global sniffer
    if sniffer:
        try:
            with sniffer.lock:
                http_packets = [p for p in sniffer.packets if 'HTTP' in p.get('protocols', [])]
                return http_packets[-limit:] if limit else http_packets
        except:
            return []
    return []

def get_all_packets(limit=50):
    """Get all captured packets"""
    global sniffer
    if not sniffer:
        return []
    
    try:
        # Don't use lock to avoid hanging
        packets = sniffer.packets[-limit:] if sniffer.packets else []
        return packets
    except:
        return []