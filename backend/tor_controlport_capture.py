"""
TOR ControlPort Packet Capture Integration
Captures packets specifically from TOR ControlPort connections
"""

import os
import json
import threading
import time
from datetime import datetime
from collections import defaultdict
import socket

try:
    from stem.control import Controller
    from stem import CircStatus, CircPurpose
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class TORControlPortCapture:
    def __init__(self, control_host='127.0.0.1', control_port=9051):
        self.control_host = control_host
        self.control_port = control_port
        self.controller = None
        self.is_capturing = False
        self.captured_packets = []
        self.circuit_events = []
        self.stream_events = []
        self.lock = threading.Lock()
        
        # TOR-specific data
        self.active_circuits = {}
        self.circuit_packets = defaultdict(list)
        self.relay_connections = {}
        
        # Statistics
        self.stats = {
            'control_packets': 0,
            'circuit_events': 0,
            'stream_events': 0,
            'relay_packets': 0,
            'start_time': None
        }
    
    def connect_controller(self):
        """Connect to TOR ControlPort"""
        if not STEM_AVAILABLE:
            raise RuntimeError("Stem library not available")
        
        try:
            self.controller = Controller.from_port(address=self.control_host, port=self.control_port)
            
            # Try different authentication methods
            authenticated = False
            
            # Try cookie authentication
            tor_paths = [
                'Z:\\Tor Browser\\Browser\\TorBrowser\\Data\\Tor',
                'C:\\Users\\LENOVO\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Data\\Tor'
            ]
            
            for tor_path in tor_paths:
                try:
                    cookie_path = os.path.join(tor_path, 'control_auth_cookie')
                    if os.path.exists(cookie_path):
                        with open(cookie_path, 'rb') as f:
                            cookie = f.read()
                        self.controller.authenticate(cookie)
                        authenticated = True
                        print(f"TOR: Authenticated with cookie from {cookie_path}")
                        break
                except Exception:
                    continue
            
            if not authenticated:
                try:
                    self.controller.authenticate()
                    authenticated = True
                    print("TOR: Authenticated automatically")
                except Exception as e:
                    print(f"TOR: Authentication failed: {e}")
                    return False
            
            if authenticated:
                # Enable event monitoring
                self.controller.add_event_listener(self._circuit_event, 'CIRC')
                self.controller.add_event_listener(self._stream_event, 'STREAM')
                print("TOR: ControlPort connected and event monitoring enabled")
                return True
            
        except Exception as e:
            print(f"TOR: ControlPort connection failed: {e}")
            return False
        
        return False
    
    def _circuit_event(self, event):
        """Handle circuit events from TOR"""
        with self.lock:
            circuit_info = {
                'timestamp': datetime.now().isoformat(),
                'circuit_id': event.id,
                'status': event.status.name,
                'path': [],
                'purpose': event.purpose.name if event.purpose else 'UNKNOWN'
            }
            
            # Extract path information
            if hasattr(event, 'path') and event.path:
                for hop in event.path:
                    circuit_info['path'].append({
                        'fingerprint': hop[0],
                        'nickname': hop[1] if len(hop) > 1 else 'Unknown'
                    })
            
            self.circuit_events.append(circuit_info)
            self.stats['circuit_events'] += 1
            
            # Track active circuits
            if event.status == CircStatus.BUILT:
                self.active_circuits[event.id] = circuit_info
            elif event.status in [CircStatus.CLOSED, CircStatus.FAILED]:
                self.active_circuits.pop(event.id, None)
            
            print(f"TOR: Circuit {event.id} {event.status.name} - {len(circuit_info['path'])} hops")
    
    def _stream_event(self, event):
        """Handle stream events from TOR"""
        with self.lock:
            stream_info = {
                'timestamp': datetime.now().isoformat(),
                'stream_id': event.id,
                'status': event.status.name,
                'circuit_id': getattr(event, 'circ_id', None),
                'target': getattr(event, 'target', None),
                'purpose': getattr(event, 'purpose', 'UNKNOWN')
            }
            
            self.stream_events.append(stream_info)
            self.stats['stream_events'] += 1
            
            print(f"TOR: Stream {event.id} {event.status.name} -> {stream_info['target']}")
    
    def start_packet_capture(self):
        """Start capturing packets on TOR-related ports"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available for packet capture")
        
        self.is_capturing = True
        self.stats['start_time'] = datetime.now()
        
        def capture_thread():
            try:
                # Capture packets on TOR ports
                filter_str = f"host {self.control_host} and (port {self.control_port} or port 9001 or port 9030 or port 443)"
                
                print(f"TOR: Starting packet capture with filter: {filter_str}")
                
                sniff(
                    filter=filter_str,
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda x: not self.is_capturing
                )
            except Exception as e:
                print(f"TOR: Packet capture error: {e}")
        
        thread = threading.Thread(target=capture_thread, daemon=True)
        thread.start()
    
    def _process_packet(self, packet):
        """Process captured packets"""
        try:
            with self.lock:
                if IP in packet and TCP in packet:
                    ip = packet[IP]
                    tcp = packet[TCP]
                    
                    packet_info = {
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': ip.src,
                        'dst_ip': ip.dst,
                        'src_port': tcp.sport,
                        'dst_port': tcp.dport,
                        'size': len(packet),
                        'flags': str(tcp.flags)
                    }
                    
                    # Identify packet type
                    if tcp.dport == self.control_port or tcp.sport == self.control_port:
                        packet_info['type'] = 'control_port'
                        self.stats['control_packets'] += 1
                        
                        # Try to parse ControlPort commands
                        if Raw in packet:
                            payload = bytes(packet[Raw])
                            if payload:
                                packet_info['control_command'] = self._parse_control_command(payload)
                    
                    elif tcp.dport in [9001, 9030] or tcp.sport in [9001, 9030]:
                        packet_info['type'] = 'relay_connection'
                        self.stats['relay_packets'] += 1
                        
                        # Track relay connections
                        relay_key = f"{ip.dst}:{tcp.dport}" if tcp.dport in [9001, 9030] else f"{ip.src}:{tcp.sport}"
                        if relay_key not in self.relay_connections:
                            self.relay_connections[relay_key] = []
                        self.relay_connections[relay_key].append(packet_info)
                    
                    elif tcp.dport == 443 or tcp.sport == 443:
                        packet_info['type'] = 'https_connection'
                        
                        # Check if this might be a TOR bridge
                        if self._is_potential_tor_bridge(ip.dst if tcp.dport == 443 else ip.src):
                            packet_info['potential_tor_bridge'] = True
                    
                    self.captured_packets.append(packet_info)
                    
                    # Correlate with active circuits
                    self._correlate_with_circuits(packet_info)
                    
        except Exception as e:
            print(f"TOR: Packet processing error: {e}")
    
    def _parse_control_command(self, payload):
        """Parse TOR ControlPort commands"""
        try:
            command_str = payload.decode('utf-8', errors='ignore')
            lines = command_str.strip().split('\n')
            
            if lines:
                first_line = lines[0].strip()
                if ' ' in first_line:
                    command = first_line.split(' ')[0]
                    return {
                        'command': command,
                        'full_line': first_line[:100]  # Truncate for safety
                    }
        except Exception:
            pass
        
        return None
    
    def _is_potential_tor_bridge(self, ip):
        """Check if IP might be a TOR bridge"""
        # Simple heuristic - could be enhanced with bridge lists
        return ip not in ['127.0.0.1', 'localhost']
    
    def _correlate_with_circuits(self, packet_info):
        """Correlate packet with active circuits"""
        if packet_info['type'] == 'relay_connection':
            relay_ip = packet_info['dst_ip'] if packet_info['dst_port'] in [9001, 9030] else packet_info['src_ip']
            
            # Find circuits using this relay
            for circuit_id, circuit in self.active_circuits.items():
                for hop in circuit['path']:
                    # This would need relay IP lookup - simplified for now
                    if hop['fingerprint']:  # Placeholder for IP correlation
                        self.circuit_packets[circuit_id].append(packet_info)
                        packet_info['associated_circuit'] = circuit_id
                        break
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.controller:
            try:
                self.controller.close()
            except Exception:
                pass
    
    def get_statistics(self):
        """Get capture statistics"""
        with self.lock:
            runtime = 0
            if self.stats['start_time']:
                runtime = (datetime.now() - self.stats['start_time']).total_seconds()
            
            return {
                'runtime_seconds': runtime,
                'total_packets': len(self.captured_packets),
                'control_packets': self.stats['control_packets'],
                'relay_packets': self.stats['relay_packets'],
                'circuit_events': self.stats['circuit_events'],
                'stream_events': self.stats['stream_events'],
                'active_circuits': len(self.active_circuits),
                'relay_connections': len(self.relay_connections),
                'packets_per_second': len(self.captured_packets) / max(1, runtime)
            }
    
    def get_circuit_data(self):
        """Get circuit data with packet correlation"""
        with self.lock:
            return {
                'active_circuits': dict(self.active_circuits),
                'circuit_events': self.circuit_events.copy(),
                'stream_events': self.stream_events.copy(),
                'circuit_packets': dict(self.circuit_packets)
            }
    
    def get_captured_packets(self, packet_type=None, limit=1000):
        """Get captured packets"""
        with self.lock:
            packets = self.captured_packets
            
            if packet_type:
                packets = [p for p in packets if p.get('type') == packet_type]
            
            return packets[-limit:] if limit else packets
    
    def export_capture_data(self):
        """Export all capture data"""
        return {
            'statistics': self.get_statistics(),
            'circuits': self.get_circuit_data(),
            'packets': self.get_captured_packets(),
            'relay_connections': dict(self.relay_connections),
            'export_time': datetime.now().isoformat()
        }

# Global capture instance
tor_capture = None

def start_tor_capture(control_host='127.0.0.1', control_port=9051):
    """Start TOR ControlPort capture"""
    global tor_capture
    
    if tor_capture and tor_capture.is_capturing:
        tor_capture.stop_capture()
    
    tor_capture = TORControlPortCapture(control_host, control_port)
    
    # Connect to ControlPort
    if not tor_capture.connect_controller():
        return {'status': 'error', 'message': 'Failed to connect to TOR ControlPort'}
    
    # Start packet capture
    try:
        tor_capture.start_packet_capture()
        return {
            'status': 'started',
            'control_host': control_host,
            'control_port': control_port,
            'message': 'TOR ControlPort capture started'
        }
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

def stop_tor_capture():
    """Stop TOR ControlPort capture"""
    global tor_capture
    if tor_capture:
        tor_capture.stop_capture()
        return {'status': 'stopped'}
    return {'status': 'not_running'}

def get_tor_capture_stats():
    """Get TOR capture statistics"""
    global tor_capture
    if tor_capture:
        return tor_capture.get_statistics()
    return {'status': 'not_running'}

def get_tor_circuits():
    """Get TOR circuit data"""
    global tor_capture
    if tor_capture:
        return tor_capture.get_circuit_data()
    return {'status': 'not_running'}

def export_tor_data():
    """Export all TOR capture data"""
    global tor_capture
    if tor_capture:
        return tor_capture.export_capture_data()
    return {'status': 'not_running'}

if __name__ == "__main__":
    # Test TOR capture
    print("Starting TOR ControlPort capture...")
    result = start_tor_capture()
    print(f"Start result: {result}")
    
    if result['status'] == 'started':
        try:
            time.sleep(30)  # Capture for 30 seconds
            
            stats = get_tor_capture_stats()
            print(f"Statistics: {json.dumps(stats, indent=2)}")
            
            circuits = get_tor_circuits()
            print(f"Circuits: {len(circuits.get('active_circuits', {}))}")
            
        finally:
            stop_tor_capture()
            print("TOR capture stopped")