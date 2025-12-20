#!/usr/bin/env python3
import json
import threading
import time
import sys
import os
import logging
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add backend directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))

try:
    from backend.packet_sniffer import PacketSniffer, SCAPY_AVAILABLE
    from backend.tor_correlation_engine import correlation_engine, add_packet_for_correlation, run_correlation, get_correlation_results
    from backend.pdf_report_generator import generate_pdf_report
except ImportError:
    try:
        from packet_sniffer import PacketSniffer, SCAPY_AVAILABLE
        from tor_correlation_engine import correlation_engine, add_packet_for_correlation, run_correlation, get_correlation_results
        from pdf_report_generator import generate_pdf_report
    except ImportError:
        print("[ERROR] Could not import required modules")
        PacketSniffer = None
        SCAPY_AVAILABLE = False
        correlation_engine = None
        generate_pdf_report = None

def safe_filename(filename):
    """Sanitize filename to prevent path traversal attacks"""
    # Remove any path separators and parent directory references
    filename = os.path.basename(filename)
    # Remove any remaining dangerous characters
    filename = filename.replace('..', '').replace('/', '').replace('\\', '')
    return filename
sniffer_instance = None
sniffer_lock = threading.Lock()
start_time = time.time()

def _safe_get_interfaces(timeout: float = 5.0):
    """Enumerate interfaces without hanging; fall back to socket/pcap defaults."""
    try:
        from scapy.all import get_if_list, conf  # type: ignore
        interfaces = []
        err = None

        def worker():
            nonlocal interfaces, err
            try:
                interfaces = get_if_list()
            except Exception as e:  # pragma: no cover - defensive
                err = e

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout)

        if t.is_alive():
            print(f"[SNIFFER] get_if_list timed out after {timeout}s; using fallback")
        if interfaces:
            return interfaces
        if err:
            print(f"[SNIFFER] get_if_list failed: {err}")

        # Fallback: socket.if_nameindex (fast, may miss virtual adapters)
        try:
            import socket
            return [name for _, name in socket.if_nameindex()]
        except Exception:
            pass

        # Last resort: scapy default interface
        try:
            return [conf.iface]
        except Exception:
            return []
    except Exception as e:
        print(f"[SNIFFER] Interface discovery error: {e}")
        return []


def get_best_interface():
    """Find the best network interface for packet capture with timeouts."""
    try:
        from scapy.all import get_if_addr, conf  # type: ignore
        interfaces = _safe_get_interfaces()
        print(f"[SNIFFER] Available interfaces: {interfaces}")

        for iface in interfaces:
            try:
                addr = get_if_addr(iface)
                if addr and addr != '0.0.0.0' and not addr.startswith('127.'):
                    print(f"[SNIFFER] Selected interface: {iface} ({addr})")
                    return iface
            except Exception:
                continue

        default = getattr(conf, 'iface', None)
        print(f"[SNIFFER] Using default interface: {default}")
        return default
    except Exception as e:
        print(f"[SNIFFER] Error selecting interface: {e}")
        return None

class Handler(BaseHTTPRequestHandler):
    def is_admin(self):
        """Check if running as administrator"""
        try:
            import os
            if os.name == 'nt':  # Windows
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except Exception as e:
            print(f"[ADMIN] Admin check error: {e}")
            return False
    
    def check_tor_connection(self):
        """Check if TOR is running and enabled"""
        sock = None
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                result = sock.connect_ex(('127.0.0.1', 9051))
                if result == 0:
                    auth_success = self._authenticate_tor(sock)
                    if auth_success:
                        sock.send(b'GETINFO network-status\r\n')
                        response = sock.recv(1024).decode()
                        return 'network-status=up' in response.lower()
                return False
        except Exception as e:
            logger.error(f"TOR connection check error: {e}")
            return False
    
    def _authenticate_tor(self, sock):
        """Helper method to authenticate with TOR"""
        try:
            # Try common TOR Browser installation paths
            possible_paths = [
                os.path.expanduser("~/Desktop/Tor Browser/Browser/TorBrowser/Data/Tor/control_auth_cookie"),
                os.path.expanduser("~/AppData/Roaming/tor/control_auth_cookie"),
                f"C:\\Users\\{os.getenv('USERNAME', '')}\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Data\\Tor\\control_auth_cookie",
                "/var/lib/tor/control_auth_cookie",
                "/usr/local/var/lib/tor/control_auth_cookie"
            ]
            
            for cookie_path in possible_paths:
                if os.path.exists(cookie_path):
                    try:
                        with open(cookie_path, 'rb') as f:
                            cookie = f.read()
                        cookie_hex = cookie.hex().upper()
                        sock.send(f'AUTHENTICATE {cookie_hex}\r\n'.encode())
                        auth_resp = sock.recv(1024)
                        if b'250 OK' in auth_resp:
                            return True
                    except (IOError, OSError) as e:
                        logger.warning(f"Cookie auth failed for {cookie_path}: {e}")
                        continue
            
            # Try empty authentication
            sock.send(b'AUTHENTICATE ""\r\n')
            auth_resp = sock.recv(1024)
            return b'250 OK' in auth_resp
            
        except Exception as e:
            logger.error(f"TOR authentication error: {e}")
            return False
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

    def do_GET(self):
        global sniffer_instance, sniffer_lock
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        if self.path == '/api/health':
            with sniffer_lock:
                is_active = sniffer_instance is not None and sniffer_instance.is_running
            data = {
                'status': 'healthy',
                'sniffer_available': SCAPY_AVAILABLE and PacketSniffer is not None,
                'sniffer_active': is_active,
                'sniffer_mode': 'real' if SCAPY_AVAILABLE else 'unavailable',
                'tor_connected': self.check_tor_connection(),
                'admin_required': not self.is_admin(),
                'is_admin': self.is_admin()
            }
        elif self.path == '/api/status':
            with sniffer_lock:
                if sniffer_instance:
                    stats = sniffer_instance.get_statistics()
                    packets = sniffer_instance.get_packets()
                    data = {
                        'packets_captured': stats.get('total_packets', 0),
                        'tor_packets': stats.get('tor_packets', 0),
                        'sniffer_active': sniffer_instance.is_running,
                        'total_bytes': stats.get('total_bytes', 0),
                        'flow_count': stats.get('flow_count', 0)
                    }
                else:
                    data = {
                        'packets_captured': 0,
                        'tor_packets': 0,
                        'sniffer_active': False
                    }
        elif self.path == '/api/packets':
            with sniffer_lock:
                if sniffer_instance:
                    packets = sniffer_instance.get_packets()
                    tor_packets = sniffer_instance.get_tor_traffic()
                    stats = sniffer_instance.get_statistics()
                    
                    # Add packets to correlation engine
                    if correlation_engine:
                        for packet in packets[-10:]:  # Last 10 packets
                            add_packet_for_correlation(packet)
                    
                    # Get last 20 packets for live view
                    recent_packets = packets[-20:] if len(packets) > 20 else packets
                    data = {
                        'packets': recent_packets,
                        'total_count': len(packets),
                        'tor_count': len(tor_packets),
                        'capture_rate': stats.get('total_packets', 0) / max(1, (time.time() - start_time)),
                        'protocol_distribution': stats.get('protocol_distribution', {})
                    }
                else:
                    data = {
                        'packets': [],
                        'total_count': 0,
                        'tor_count': 0,
                        'capture_rate': 0
                    }
        elif self.path == '/api/sniffer/start':
            with sniffer_lock:
                if sniffer_instance and sniffer_instance.is_running:
                    data = {
                        'status': 'already_running',
                        'active': True,
                        'message': 'Packet capture is already running'
                    }
                elif not SCAPY_AVAILABLE or PacketSniffer is None:
                    data = {
                        'status': 'error',
                        'active': False,
                        'message': 'Scapy not available. Install with: pip install scapy'
                    }
                elif not self.is_admin():
                    data = {
                        'status': 'error',
                        'active': False,
                        'message': 'Administrator/root privileges required for packet capture'
                    }
                else:
                    try:
                        interface = get_best_interface()
                        pcap_dir = Path(__file__).parent.parent / 'pcap_storage'
                        sniffer_instance = PacketSniffer(
                            interface=interface,
                            packet_limit=5000,
                            pcap_dir=str(pcap_dir)
                        )
                        sniffer_instance.start_sniffing()
                        print(f"[SNIFFER] Started on interface: {interface}")
                        data = {
                            'status': 'success',
                            'active': True,
                            'interface': interface,
                            'message': 'Live packet capture started'
                        }
                    except Exception as e:
                        print(f"[SNIFFER] Start error: {e}")
                        import traceback
                        traceback.print_exc()
                        sniffer_instance = None
                        data = {
                            'status': 'error',
                            'active': False,
                            'message': f'Failed to start: {str(e)}'
                        }
        elif self.path == '/api/sniffer/stop':
            with sniffer_lock:
                if sniffer_instance:
                    pcap_file = sniffer_instance.get_pcap_filename()
                    sniffer_instance.stop_sniffing()
                    print("[SNIFFER] Stopped")
                    data = {
                        'status': 'success', 
                        'active': False,
                        'pcap_file': pcap_file,
                        'message': f'Capture saved to {pcap_file}'
                    }
                else:
                    data = {'status': 'success', 'active': False, 'message': 'Sniffer was not running'}
        elif self.path == '/api/tor/connect':
            # Try to enable TOR network
            try:
                import socket
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3)
                    result = sock.connect_ex(('127.0.0.1', 9051))
                    if result == 0:
                        auth_success = self._authenticate_tor(sock)
                        if auth_success:
                            # Enable network
                            sock.send(b'SETCONF DisableNetwork=0\r\n')
                            enable_resp = sock.recv(1024)
                            
                            # Enable SOCKS proxy
                            sock.send(b'SETCONF SocksPort=9050\r\n')
                            socks_resp = sock.recv(1024)
                            
                            if b'250 OK' in enable_resp:
                                data = {'status': 'success', 'connected': True, 'message': 'TOR network and SOCKS proxy enabled'}
                            else:
                                data = {'status': 'failed', 'connected': False, 'message': 'Failed to enable TOR network'}
                        else:
                            data = {'status': 'failed', 'connected': False, 'message': 'TOR authentication failed'}
                    else:
                        data = {'status': 'failed', 'connected': False, 'message': 'TOR control port not accessible'}
            except Exception as e:
                logger.error(f"TOR connection error: {e}")
                data = {'status': 'failed', 'connected': False, 'message': f'TOR connection error: {str(e)}'}
        elif self.path == '/api/circuits':
            # Generate mock circuit data for visualization
            circuits = [
                {
                    'id': 'C1',
                    'status': 'BUILT',
                    'path': [
                        {'fingerprint': 'A1B2C3D4E5F6', 'nickname': 'GuardRelay1', 'country': 'US'},
                        {'fingerprint': 'F6E5D4C3B2A1', 'nickname': 'MiddleRelay1', 'country': 'DE'},
                        {'fingerprint': 'B2C3D4E5F6A1', 'nickname': 'ExitRelay1', 'country': 'NL'}
                    ]
                },
                {
                    'id': 'C2', 
                    'status': 'BUILT',
                    'path': [
                        {'fingerprint': 'C3D4E5F6A1B2', 'nickname': 'GuardRelay2', 'country': 'FR'},
                        {'fingerprint': 'D4E5F6A1B2C3', 'nickname': 'MiddleRelay2', 'country': 'SE'},
                        {'fingerprint': 'E5F6A1B2C3D4', 'nickname': 'ExitRelay2', 'country': 'CH'}
                    ]
                },
                {
                    'id': 'C3',
                    'status': 'BUILT', 
                    'path': [
                        {'fingerprint': 'F6A1B2C3D4E5', 'nickname': 'GuardRelay3', 'country': 'CA'},
                        {'fingerprint': 'A1B2C3D4E5F6', 'nickname': 'MiddleRelay3', 'country': 'NO'},
                        {'fingerprint': 'B2C3D4E5F6A1', 'nickname': 'ExitRelay3', 'country': 'AT'}
                    ]
                }
            ]
            data = {
                'circuits': circuits,
                'count': len(circuits),
                'tor_connected': self.check_tor_connection()
            }
        elif self.path == '/api/relays':
            # Generate mock relay data
            relays = [
                {'fingerprint': 'A1B2C3D4E5F6', 'nickname': 'GuardRelay1', 'country': 'US', 'bandwidth': '10 MB/s'},
                {'fingerprint': 'F6E5D4C3B2A1', 'nickname': 'MiddleRelay1', 'country': 'DE', 'bandwidth': '25 MB/s'},
                {'fingerprint': 'B2C3D4E5F6A1', 'nickname': 'ExitRelay1', 'country': 'NL', 'bandwidth': '15 MB/s'},
                {'fingerprint': 'C3D4E5F6A1B2', 'nickname': 'GuardRelay2', 'country': 'FR', 'bandwidth': '8 MB/s'},
                {'fingerprint': 'D4E5F6A1B2C3', 'nickname': 'MiddleRelay2', 'country': 'SE', 'bandwidth': '30 MB/s'}
            ]
            data = {
                'relays': relays,
                'count': len(relays),
                'tor_connected': self.check_tor_connection()
            }
        elif self.path.startswith('/api/download/'):
            # Download PCAP file with path traversal protection
            filename = safe_filename(self.path.split('/')[-1])
            pcap_dir = Path(__file__).parent.parent / 'pcap_storage'
            file_path = pcap_dir / filename
            
            # Ensure file is within pcap_storage directory
            if not str(file_path.resolve()).startswith(str(pcap_dir.resolve())):
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                data = {'error': 'Access denied'}
            elif file_path.exists() and file_path.suffix in ['.pcap', '.pcapng']:
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                try:
                    import shutil
                    with open(file_path, 'rb') as f:
                        shutil.copyfileobj(f, self.wfile)
                except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                    pass
                return
            else:
                self.send_response(404)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                data = {'error': 'File not found'}
        elif self.path == '/api/sniffer/export/pcap':
            # Export current capture as PCAP
            with sniffer_lock:
                if sniffer_instance:
                    # Get the latest PCAP file
                    pcap_file = sniffer_instance.latest_pcap()
                    if pcap_file and Path(pcap_file).exists():
                        filename = Path(pcap_file).name
                        # Add timestamp to make filename unique
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        unique_filename = f"tor_capture_{timestamp}.pcap"
                        
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/octet-stream')
                        self.send_header('Content-Disposition', f'attachment; filename="{unique_filename}"')
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.end_headers()
                        
                        try:
                            with open(pcap_file, 'rb') as f:
                                self.wfile.write(f.read())
                        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                            # Client disconnected
                            pass
                        return
                    else:
                        data = {'error': 'No PCAP file available'}
                else:
                    data = {'error': 'No active capture'}
        elif self.path == '/api/correlation/run':
            # Run correlation analysis
            if correlation_engine:
                try:
                    results = run_correlation()
                    data = {
                        'status': 'success',
                        'results': results
                    }
                except Exception as e:
                    data = {
                        'status': 'error',
                        'message': str(e)
                    }
            else:
                data = {
                    'status': 'error',
                    'message': 'Correlation engine not available'
                }
        elif self.path == '/api/correlation/results':
            # Get correlation results
            if correlation_engine:
                results = get_correlation_results()
                data = {
                    'status': 'success',
                    'results': results,
                    'has_results': results is not None
                }
            else:
                data = {
                    'status': 'error',
                    'message': 'Correlation engine not available'
                }
        elif self.path == '/api/correlation/stats':
            # Get correlation statistics
            try:
                from backend.tor_correlation_engine import get_correlation_stats
                stats = get_correlation_stats()
                data = {
                    'status': 'success',
                    'stats': stats
                }
            except Exception as e:
                data = {'status': 'error', 'message': str(e)}
        elif self.path == '/api/geo/locations':
            # Get all geo-located IPs
            try:
                from backend.tor_correlation_engine import get_geo_locations
                locations = get_geo_locations()
                data = {
                    'status': 'success',
                    'locations': locations
                }
            except Exception as e:
                data = {'status': 'error', 'message': str(e)}
        elif self.path == '/api/geo/user-location':
            # Get estimated user location
            try:
                from backend.tor_correlation_engine import get_user_location
                location = get_user_location()
                data = {
                    'status': 'success',
                    'user_location': location
                }
            except Exception as e:
                data = {'status': 'error', 'message': str(e)}
        elif self.path == '/api/pcap/list':
            # List available PCAP files
            pcap_dir = Path(__file__).parent.parent / 'pcap_storage'
            if pcap_dir.exists():
                files = []
                for f in pcap_dir.glob('*.pcap*'):
                    files.append({
                        'name': f.name,
                        'path': str(f),
                        'size': f.stat().st_size,
                        'modified': f.stat().st_mtime
                    })
                files.sort(key=lambda x: x['modified'], reverse=True)
                data = {'status': 'success', 'files': files}
            else:
                data = {'status': 'error', 'message': 'PCAP directory not found'}
        elif self.path == '/api/reports/list':
            # List available PDF reports
            reports_dir = Path(__file__).parent.parent / 'reports'
            if reports_dir.exists():
                files = []
                for f in reports_dir.glob('*.pdf'):
                    files.append({
                        'name': f.name,
                        'path': str(f),
                        'size': f.stat().st_size,
                        'modified': f.stat().st_mtime
                    })
                files.sort(key=lambda x: x['modified'], reverse=True)
                data = {'status': 'success', 'files': files}
            else:
                data = {'status': 'error', 'message': 'Reports directory not found'}
        elif self.path.startswith('/api/reports/download/'):
            # Download PDF report with path traversal protection
            filename = safe_filename(self.path.split('/')[-1])
            reports_dir = Path(__file__).parent.parent / 'reports'
            file_path = reports_dir / filename
            
            # Ensure file is within reports directory
            if not str(file_path.resolve()).startswith(str(reports_dir.resolve())):
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                data = {'error': 'Access denied'}
            elif file_path.exists() and file_path.suffix == '.pdf':
                self.send_response(200)
                self.send_header('Content-Type', 'application/pdf')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                try:
                    import shutil
                    with open(file_path, 'rb') as f:
                        shutil.copyfileobj(f, self.wfile)
                except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                    pass
                return
            else:
                self.send_response(404)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                data = {'error': 'Report not found'}
        else:
            data = {'error': 'Not found'}

        # Headers were already sent at the start of do_GET; only write body here
        try:
            self.wfile.write(json.dumps(data).encode())
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            # Client disconnected - ignore silently
            pass
        except Exception as e:
            print(f"[ERROR] Failed to send response: {e}")

    def do_POST(self):
        """Handle POST requests for file uploads and analysis"""
        global sniffer_instance, sniffer_lock
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        try:
            if self.path == '/api/pcap/upload':
                # Handle PCAP file upload
                content_type = self.headers.get('Content-Type', '')
                if 'multipart/form-data' in content_type:
                    import cgi
                    form = cgi.FieldStorage(
                        fp=self.rfile,
                        headers=self.headers,
                        environ={'REQUEST_METHOD': 'POST'}
                    )
                    
                    if 'file' in form:
                        file_item = form['file']
                        if file_item.filename:
                            # Save uploaded file
                            upload_dir = Path(__file__).parent.parent / 'pcap_storage'
                            upload_dir.mkdir(exist_ok=True)
                            
                            timestamp = datetime.now().strftime('%Y%m%dT%H%M%SZ')
                            filename = f"upload_{timestamp}_{Path(file_item.filename).name}"
                            file_path = upload_dir / filename
                            
                            # Validate file size (max 100MB)
                            file_data = file_item.file.read()
                            if len(file_data) > 100 * 1024 * 1024:
                                data = {'status': 'error', 'message': 'File too large (max 100MB)'}
                            elif not file_item.filename.lower().endswith(('.pcap', '.pcapng')):
                                data = {'status': 'error', 'message': 'Invalid file type (only .pcap/.pcapng allowed)'}
                            else:
                                with open(file_path, 'wb') as f:
                                    f.write(file_data)
                            
                            data = {
                                'status': 'success',
                                'message': 'File uploaded successfully',
                                'file_path': str(file_path),
                                'filename': filename
                            }
                        else:
                            data = {'status': 'error', 'message': 'No file provided'}
                    else:
                        data = {'status': 'error', 'message': 'No file in request'}
                else:
                    data = {'status': 'error', 'message': 'Invalid content type'}
                    
            elif self.path == '/api/correlation/analyze-pcap':
                # Analyze PCAP file offline
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length)
                request_data = json.loads(body.decode('utf-8'))
                
                pcap_path = request_data.get('pcap_path')
                if not pcap_path:
                    data = {'status': 'error', 'message': 'No PCAP path provided'}
                else:
                    # Analyze PCAP file
                    try:
                        from backend.tor_correlation_engine import analyze_pcap_offline
                        results = analyze_pcap_offline(pcap_path)
                        data = {
                            'status': 'success',
                            'results': results,
                            'message': f'Analyzed {results.get("pcap_packets", 0)} packets'
                        }
                    except Exception as e:
                        import traceback
                        traceback.print_exc()
                        data = {'status': 'error', 'message': str(e)}
                        
            elif self.path == '/api/geo/lookup':
                # Lookup IP geolocation
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length)
                request_data = json.loads(body.decode('utf-8'))
                
                ip_address = request_data.get('ip')
                if ip_address:
                    try:
                        from backend.tor_correlation_engine import correlation_engine
                        location = correlation_engine.geoip_service.lookup(ip_address)
                        data = {'status': 'success', 'location': location}
                    except Exception as e:
                        data = {'status': 'error', 'message': str(e)}
                else:
                    data = {'status': 'error', 'message': 'No IP address provided'}
            elif self.path == '/api/reports/generate-pdf':
                # Generate PDF report from correlation data
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length)
                request_data = json.loads(body.decode('utf-8'))
                
                correlation_data = request_data.get('correlation_data')
                filename = request_data.get('filename')
                
                if correlation_data and generate_pdf_report:
                    try:
                        result = generate_pdf_report(correlation_data, filename)
                        data = result
                    except Exception as e:
                        import traceback
                        traceback.print_exc()
                        data = {'status': 'error', 'message': str(e)}
                else:
                    data = {'status': 'error', 'message': 'No correlation data provided or PDF generator not available'}
            else:
                data = {'error': 'Not found'}
            
            self.wfile.write(json.dumps(data).encode())
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            error_data = {'status': 'error', 'message': str(e)}
            self.wfile.write(json.dumps(error_data).encode())

    def log_message(self, format, *args):
        # Log only errors, suppress normal HTTP logs
        if 'ERROR' in format % args:
            logger.error(format % args)

if __name__ == '__main__':
    print("Starting TOR Unveil Backend...")
    print(f"Scapy available: {SCAPY_AVAILABLE}")
    if not SCAPY_AVAILABLE:
        print("Install scapy for real packet capture: pip install scapy")
    print("Starting server on port 5000...")
    server = HTTPServer(('', 5000), Handler)
    print("Backend ready at http://localhost:5000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
        with sniffer_lock:
            if sniffer_instance:
                sniffer_instance.stop_sniffing()
        server.shutdown()
        server.server_close()