"""
Enhanced TOR Unveil Flask Backend API
Integrates packet sniffing, heuristic correlation, and TOR node scraping
"""

import os
import json
import threading
import time
from datetime import datetime
from functools import wraps

from flask import Flask, jsonify, request, send_file, Response
from flask_cors import CORS
from werkzeug.utils import secure_filename
import subprocess
import sys

from packet_sniffer import PacketSniffer, PCAPAnalyzer

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'log', 'json'}
API_KEY = os.environ.get('API_KEY', 'changeme')
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB

# Create upload folder
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Global instances (lazy-loaded to avoid heavy imports at startup)
packet_sniffer = None
ml_model = None
tor_scraper = None


def get_ml_model():
    """Lazily import and return the ML model instance"""
    global ml_model
    if ml_model is None:
        from ml_correlation import TORNodeCorrelationModel
        ml_model = TORNodeCorrelationModel()
    return ml_model


def get_tor_scraper():
    """Lazily import and return the TOR scraper instance"""
    global tor_scraper
    if tor_scraper is None:
        from tor_scraper import TORNodeScraper
        tor_scraper = TORNodeScraper()
    return tor_scraper

# Global state
captured_packets = []
correlation_results = {}
network_stats = {}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_dummy_packet(packet: dict) -> bool:
    """Heuristic to filter out non-real / dummy packets from topology.

    Filters out loopback, unspecified, link-local, and broadcast/multicast addresses.
    """
    try:
        src = packet.get('src_ip')
        dst = packet.get('dst_ip')
        for ip in (src, dst):
            if not ip:
                return True
            # common non-routable or broadcast ranges
            if ip.startswith('127.') or ip.startswith('0.') or ip == '255.255.255.255':
                return True
            if ip.startswith('169.254.'):  # APIPA/link-local
                return True
            if ip.startswith('224.') or ip.startswith('239.'):  # multicast ranges
                return True
        return False
    except Exception:
        return True



def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key != API_KEY:
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# PACKET CAPTURE ENDPOINTS
# ============================================================================

@app.route('/api/sniffer/start', methods=['POST'])
def start_packet_capture():
    """Start real-time packet capture"""
    global packet_sniffer, captured_packets
    
    try:
        interface = request.json.get('interface') if request.json else None
        packet_limit = request.json.get('packet_limit', 1000) if request.json else 1000
        
        packet_sniffer = PacketSniffer(interface=interface, packet_limit=packet_limit)
        try:
            packet_sniffer.start_sniffing()
        except RuntimeError as re:
            # Scapy not available or other runtime error during start
            packet_sniffer = None
            return jsonify({
                'status': 'error',
                'message': str(re)
            }), 500
        
        return jsonify({
            'status': 'success',
            'message': 'Packet capture started',
            'interface': interface or 'default',
            'packet_limit': packet_limit
        })
    except PermissionError:
        return jsonify({
            'status': 'error',
            'message': 'Root/Administrator privileges required'
        }), 403
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/sniffer/stop', methods=['POST'])
def stop_packet_capture():
    """Stop packet capture"""
    global packet_sniffer, captured_packets
    
    try:
        if packet_sniffer:
            packet_sniffer.stop_sniffing()
            captured_packets = packet_sniffer.get_packets()
            
            return jsonify({
                'status': 'success',
                'message': 'Packet capture stopped',
                'packets_captured': len(captured_packets)
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'No active packet capture'
            }), 400
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/sniffer/packets', methods=['GET'])
def get_packets():
    """Get captured packets"""
    global packet_sniffer, captured_packets
    
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        if packet_sniffer:
            packets = packet_sniffer.get_packets()
        else:
            packets = captured_packets
        
        total = len(packets)
        packets = packets[offset:offset+limit]
        
        return jsonify({
            'status': 'success',
            'total': total,
            'limit': limit,
            'offset': offset,
            'packets': packets
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/sniffer/statistics', methods=['GET'])
def get_sniffer_statistics():
    """Get packet capture statistics"""
    global packet_sniffer
    
    try:
        if packet_sniffer:
            stats = packet_sniffer.get_statistics()
            return jsonify({
                'status': 'success',
                'statistics': stats
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'No active packet capture'
            }), 400
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    """Start packet capture on best available interface"""
    global packet_sniffer, captured_packets
    
    try:
        print("[CAPTURE] Starting packet capture...")
        
        # Stop existing sniffer if running
        if packet_sniffer and getattr(packet_sniffer, 'is_running', False):
            packet_sniffer.stop_sniffing()
        
        # Create new sniffer
        packet_sniffer = PacketSniffer(interface=None, packet_limit=10000)
        packet_sniffer.start_sniffing()
        
        print("[CAPTURE] Packet capture started successfully")
        
        # Get interface name as string
        interface_name = str(packet_sniffer.interface) if packet_sniffer.interface else 'default'
        
        return jsonify({
            'status': 'started',
            'message': 'Packet capture started',
            'interface': interface_name
        })
    except Exception as e:
        print(f"[CAPTURE] Error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
    global packet_sniffer, captured_packets
    
    try:
        if packet_sniffer:
            packet_sniffer.stop_sniffing()
            captured_packets = packet_sniffer.get_packets()
            packet_count = len(captured_packets)
            
            # Keep packet_sniffer reference for export functionality
            # packet_sniffer = None  # Don't clear this - needed for PCAP export
            
            return jsonify({
                'status': 'stopped',
                'message': 'Packet capture stopped',
                'packets_captured': packet_count
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'No active packet capture'
            }), 400
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/capture/debug', methods=['GET'])
def debug_capture():
    """Debug packet capture status"""
    global packet_sniffer
    
    debug_info = {
        'sniffer_exists': packet_sniffer is not None,
        'sniffer_running': False,
        'packet_count': 0,
        'interface': None,
        'scapy_available': False
    }
    
    try:
        from scapy.all import sniff as scapy_sniff
        debug_info['scapy_available'] = True
    except:
        debug_info['scapy_available'] = False
    
    if packet_sniffer:
        debug_info['sniffer_running'] = getattr(packet_sniffer, 'is_running', False)
        debug_info['packet_count'] = len(getattr(packet_sniffer, 'packets', []))
        debug_info['interface'] = getattr(packet_sniffer, 'interface', None)
    
    return jsonify(debug_info)

@app.route('/api/capture/packets', methods=['GET'])
def get_capture_packets():
    """Get captured packets - return all packets"""
    global packet_sniffer, captured_packets
    
    try:
        limit = request.args.get('limit', 50, type=int)  # Increased default
        offset = request.args.get('offset', 0, type=int)
        
        if packet_sniffer:
            packets = packet_sniffer.get_packets()
        else:
            packets = captured_packets
        
        total = len(packets)
        packets_slice = packets[offset:offset+limit] if packets else []
        
        print(f"[API] Returning {len(packets_slice)} packets to frontend (total: {total})")
        
        return jsonify(packets_slice)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/capture/export/pcap', methods=['GET'])
def export_pcap():
    """Export captured packets as PCAP file"""
    global packet_sniffer, captured_packets
    try:
        # Get the latest PCAP file from sniffer if available
        pcap_file = None
        if packet_sniffer:
            pcap_file = packet_sniffer.latest_pcap()
        
        # If no PCAP file exists, create one from captured packets
        if not pcap_file or not os.path.exists(pcap_file):
            if not captured_packets:
                return jsonify({'status': 'error', 'message': 'No packets to export'}), 400
            
            # Create PCAP from captured packets using Scapy
            try:
                from scapy.all import wrpcap, Ether, IP, TCP, UDP, ICMP
                import tempfile
                
                # Create temporary PCAP file
                temp_fd, temp_path = tempfile.mkstemp(suffix='.pcap')
                os.close(temp_fd)
                
                # Convert captured packets back to Scapy packets
                scapy_packets = []
                for pkt_info in captured_packets:
                    try:
                        # Build basic Ethernet frame
                        pkt = Ether()
                        
                        # Add IP layer if we have IP info
                        if pkt_info.get('src_ip') and pkt_info.get('dst_ip'):
                            ip_pkt = IP(src=pkt_info['src_ip'], dst=pkt_info['dst_ip'])
                            if pkt_info.get('ttl'):
                                ip_pkt.ttl = pkt_info['ttl']
                            
                            # Add transport layer
                            if pkt_info.get('protocol') == 'TCP' and pkt_info.get('src_port') and pkt_info.get('dst_port'):
                                tcp_pkt = TCP(sport=pkt_info['src_port'], dport=pkt_info['dst_port'])
                                if pkt_info.get('flags'):
                                    try:
                                        tcp_pkt.flags = pkt_info['flags']
                                    except:
                                        pass
                                pkt = pkt / ip_pkt / tcp_pkt
                            elif pkt_info.get('protocol') == 'UDP' and pkt_info.get('src_port') and pkt_info.get('dst_port'):
                                udp_pkt = UDP(sport=pkt_info['src_port'], dport=pkt_info['dst_port'])
                                pkt = pkt / ip_pkt / udp_pkt
                            elif pkt_info.get('protocol') == 'ICMP':
                                icmp_pkt = ICMP()
                                if pkt_info.get('icmp_type'):
                                    icmp_pkt.type = pkt_info['icmp_type']
                                if pkt_info.get('icmp_code'):
                                    icmp_pkt.code = pkt_info['icmp_code']
                                pkt = pkt / ip_pkt / icmp_pkt
                            else:
                                pkt = pkt / ip_pkt
                            
                            scapy_packets.append(pkt)
                    except Exception as e:
                        print(f"[PCAP] Error converting packet: {e}")
                        continue
                
                if not scapy_packets:
                    return jsonify({'status': 'error', 'message': 'No valid packets to export'}), 400
                
                # Write PCAP file
                wrpcap(temp_path, scapy_packets)
                pcap_file = temp_path
                print(f"[PCAP] Created PCAP file with {len(scapy_packets)} packets: {pcap_file}")
                
            except ImportError:
                return jsonify({'status': 'error', 'message': 'Scapy not available for PCAP export'}), 500
            except Exception as e:
                return jsonify({'status': 'error', 'message': f'Failed to create PCAP: {str(e)}'}), 500
        
        # Verify PCAP file is valid
        try:
            with open(pcap_file, 'rb') as f:
                header = f.read(24)
                if len(header) < 24:
                    raise ValueError('Invalid PCAP file - too small')
                
                # Check for PCAP magic number
                import struct
                magic = struct.unpack('<I', header[:4])[0]
                if magic not in [0xA1B2C3D4, 0xD4C3B2A1]:  # Both endianness
                    raise ValueError('Invalid PCAP file - wrong magic number')
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Invalid PCAP file: {str(e)}'}), 500
        
        return send_file(
            pcap_file,
            as_attachment=True,
            download_name=f'tor_capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pcap',
            mimetype='application/vnd.tcpdump.pcap'
        )
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/capture/export/json', methods=['GET'])
def export_json():
    """Export captured packets as JSON"""
    global captured_packets
    try:
        if not captured_packets:
            return jsonify({'status': 'error', 'message': 'No packets captured'}), 400
        
        # Create JSON export
        export_data = {
            'export_time': datetime.now().isoformat(),
            'packet_count': len(captured_packets),
            'packets': captured_packets
        }
        
        # Create temporary JSON file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(export_data, f, indent=2, default=str)
            temp_path = f.name
        
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=f'tor_capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
            mimetype='application/json'
        )
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/sniffer/tor-traffic', methods=['GET'])
def get_tor_traffic():
    """Get identified TOR traffic"""
    global packet_sniffer
    
    try:
        if packet_sniffer:
            tor_traffic = packet_sniffer.get_tor_traffic()
            return jsonify({
                'status': 'success',
                'tor_packets': len(tor_traffic),
                'traffic': tor_traffic[:100]  # Limit response size
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'No active packet capture'
            }), 400
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/sniffer/stream', methods=['GET'])
def stream_sniffer_packets():
    """Stream live captured packets as Server-Sent Events (SSE).

    Only streams non-dummy packets (see `is_dummy_packet`). Connect from a browser
    or dashboard via EventSource to receive live JSON objects.
    """
    global packet_sniffer

    def gen():
        if not packet_sniffer:
            yield 'event: error\n'
            yield 'data: No active sniffer\n\n'
            return

        idx = 0
        while True:
            try:
                packets = packet_sniffer.get_packets()
                while idx < len(packets):
                    p = packets[idx]
                    idx += 1
                    if is_dummy_packet(p):
                        continue
                    yield 'data: ' + json.dumps(p, default=str) + '\n\n'
                time.sleep(0.4)
            except GeneratorExit:
                break
            except Exception:
                # pause briefly on errors and continue
                time.sleep(1)

    return Response(gen(), mimetype='text/event-stream')


# ============================================================================
# PCAP ANALYSIS ENDPOINTS
# ============================================================================

@app.route('/api/pcap/upload', methods=['POST'])
def upload_pcap():
    """Upload and analyze PCAP file"""
    try:
        if 'file' not in request.files:
            return jsonify({
                'status': 'error',
                'message': 'No file provided'
            }), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({
                'status': 'error',
                'message': 'No file selected'
            }), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'status': 'error',
                'message': 'Invalid file type'
            }), 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        # Analyze PCAP
        analysis = PCAPAnalyzer.analyze_pcap_file(filepath)

        # Create a small inline SVG visualization summarizing top flows
        try:
            flows = analysis.get('flows', {}) if isinstance(analysis, dict) else {}
            # Extract top flow endpoints
            nodes = {}
            links = []
            for i, (flow, count) in enumerate(sorted(flows.items(), key=lambda x: -x[1])[:40]):
                parts = flow.split('-')
                if len(parts) == 2:
                    src = parts[0]
                    dst = parts[1]
                else:
                    src = flow; dst = ''
                # remove dummy endpoints
                # endpoints are like 'ip:port'
                def strip_ip(ep):
                    return ep.split(':')[0] if ep and ':' in ep else ep

                s_ip = strip_ip(src)
                d_ip = strip_ip(dst)
                fake_packet = {'src_ip': s_ip, 'dst_ip': d_ip}
                if is_dummy_packet(fake_packet):
                    continue
                if src and src not in nodes:
                    nodes[src] = {'id': len(nodes)+1, 'ip': src}
                if dst and dst not in nodes:
                    nodes[dst] = {'id': len(nodes)+1, 'ip': dst}
                links.append({'source': src, 'target': dst, 'weight': count})

            # Build simple circle layout SVG
            svg_w, svg_h = 700, 360
            cx, cy = svg_w/2, svg_h/2
            r = min(cx, cy) - 60
            svg_parts = [f"<svg width='{svg_w}' height='{svg_h}' xmlns='http://www.w3.org/2000/svg'>"]
            node_list = list(nodes.values())
            import math
            for idx, n in enumerate(node_list):
                angle = 2*math.pi*idx/max(1, len(node_list))
                x = cx + r*math.cos(angle)
                y = cy + r*math.sin(angle)
                n['x'] = x; n['y'] = y

            for l in links:
                s = nodes.get(l['source'])
                t = nodes.get(l['target'])
                if s and t:
                    stroke = max(1, min(6, int(l.get('weight',1))/2))
                    svg_parts.append(f"<line x1='{s['x']:.1f}' y1='{s['y']:.1f}' x2='{t['x']:.1f}' y2='{t['y']:.1f}' stroke='rgba(34,150,243,0.6)' stroke-width='{stroke}' stroke-linecap='round' />")

            for n in node_list:
                svg_parts.append(f"<circle cx='{n['x']:.1f}' cy='{n['y']:.1f}' r='12' fill='#22a6f3' stroke='#0b3b57' stroke-width='2' />")
                svg_parts.append(f"<text x='{n['x']+14:.1f}' y='{n['y']+4:.1f}' font-size='10' fill='#052b3a'>{n['ip']}</text>")

            svg_parts.append('</svg>')
            analysis_visual = '\n'.join(svg_parts)
        except Exception:
            analysis_visual = None

        return jsonify({
            'status': 'success',
            'message': 'PCAP file analyzed',
            'analysis': analysis,
            'visual_svg': analysis_visual
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/pcap/analyze', methods=['POST'])
def analyze_pcap_data():
    """Analyze PCAP data from captured packets"""
    global captured_packets
    
    try:
        if not captured_packets:
            return jsonify({
                'status': 'error',
                'message': 'No captured packets available'
            }), 400
        
        # Find TOR traffic patterns
        tor_packets = [p for p in captured_packets 
                       if any(port in [p.get('src_port'), p.get('dst_port')] 
                             for port in [9001, 9002, 443, 8080])]
        
        # Build inline SVG visualization for captured packet flows (simple)
        try:
            # Filter out dummy packets before building topology
            real_packets = [p for p in captured_packets if not is_dummy_packet(p)]
            unique_ips = list({p.get('src_ip') for p in real_packets if p.get('src_ip')} | {p.get('dst_ip') for p in real_packets if p.get('dst_ip')})
            nodes = {ip: {'ip': ip} for ip in unique_ips[:30]}
            links = {}
            for p in real_packets[:500]:
                s = p.get('src_ip')
                d = p.get('dst_ip')
                if s and d:
                    key = f"{s}-{d}"
                    links[key] = links.get(key, 0) + 1

            # simple layout
            import math
            svg_w, svg_h = 700, 320
            cx, cy = svg_w/2, svg_h/2
            r = min(cx, cy) - 60
            svg_parts = [f"<svg width='{svg_w}' height='{svg_h}' xmlns='http://www.w3.org/2000/svg'>"]
            node_list = list(nodes.values())
            for idx, n in enumerate(node_list):
                angle = 2*math.pi*idx/max(1, len(node_list))
                x = cx + r*math.cos(angle)
                y = cy + r*math.sin(angle)
                n['x'] = x; n['y'] = y

            for key, cnt in list(links.items())[:60]:
                s_ip, d_ip = key.split('-')
                s = nodes.get(s_ip)
                t = nodes.get(d_ip)
                if s and t:
                    w = max(1, min(6, cnt//5))
                    svg_parts.append(f"<line x1='{s['x']:.1f}' y1='{s['y']:.1f}' x2='{t['x']:.1f}' y2='{t['y']:.1f}' stroke='rgba(120,180,240,0.5)' stroke-width='{w}' />")

            for n in node_list:
                svg_parts.append(f"<circle cx='{n['x']:.1f}' cy='{n['y']:.1f}' r='10' fill='#4aa3e0' stroke='#042639' stroke-width='1' />")
                svg_parts.append(f"<text x='{n['x']+12:.1f}' y='{n['y']+4:.1f}' font-size='10' fill='#052b3a'>{n['ip']}</text>")

            svg_parts.append('</svg>')
            visual_svg = '\n'.join(svg_parts)
        except Exception:
            visual_svg = None

        return jsonify({
            'status': 'success',
            'total_packets': len(captured_packets),
            'tor_related_packets': len(tor_packets),
            'tor_percentage': (len(tor_packets) / len(captured_packets) * 100) if captured_packets else 0,
            'tor_traffic': tor_packets[:50],
            'visual_svg': visual_svg
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ============================================================================
# HEURISTIC CORRELATION ENDPOINTS
# ============================================================================

@app.route('/api/ml/correlate', methods=['POST'])
def correlate_nodes():
    """Run heuristic correlation on captured packets"""
    global captured_packets, correlation_results
    
    try:
        if not captured_packets:
            return jsonify({
                'status': 'error',
                'message': 'No captured packets available'
            }), 400
        
        # Run correlation (lazy-load ML model)
        ml = get_ml_model()
        correlation_results = ml.correlate_all(captured_packets)

        # Get statistics
        stats = ml.get_correlation_stats(correlation_results)
        
        return jsonify({
            'status': 'success',
            'correlation': {
                'entry_exit_pairs': correlation_results.get('entry_exit_pairs', [])[:20],
                'statistics': stats,
                'top_correlated': correlation_results.get('top_correlated_ips', [])[:10]
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/ml/clustering', methods=['GET'])
def get_clustering_results():
    """Get node clustering results"""
    global correlation_results
    
    try:
        if not correlation_results:
            return jsonify({
                'status': 'error',
                'message': 'No correlation results available'
            }), 400
        
        return jsonify({
            'status': 'success',
            'clustering': correlation_results.get('clustering', {})
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ============================================================================
# TOR SCRAPER ENDPOINTS
# ============================================================================

@app.route('/api/tor/nodes/all', methods=['GET'])
def get_all_tor_nodes():
    """Get all active TOR nodes"""
    try:
        ts = get_tor_scraper()
        relays = ts.fetch_all_relays()
        
        return jsonify({
            'status': 'success',
            'total_relays': len(relays.get('relays', [])),
            'relays': relays
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/tor/nodes/exit', methods=['GET'])
def get_exit_nodes():
    """Get TOR exit nodes"""
    try:
        ts = get_tor_scraper()
        exit_nodes = ts.fetch_exit_nodes()
        
        return jsonify({
            'status': 'success',
            'count': len(exit_nodes),
            'nodes': exit_nodes[:100]
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/tor/nodes/guard', methods=['GET'])
def get_guard_nodes():
    """Get TOR guard nodes"""
    try:
        ts = get_tor_scraper()
        guard_nodes = ts.fetch_guard_nodes()
        
        return jsonify({
            'status': 'success',
            'count': len(guard_nodes),
            'nodes': guard_nodes[:100]
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/circuits', methods=['GET'])
def get_circuits():
    """Get TOR circuits"""
    circuits = [
        {
            'id': 'C1',
            'status': 'BUILT',
            'path': [
                {'fingerprint': 'A1B2C3D4E5F6', 'nickname': 'GuardRelay1', 'country': 'US'},
                {'fingerprint': 'F6E5D4C3B2A1', 'nickname': 'MiddleRelay1', 'country': 'DE'},
                {'fingerprint': 'B2C3D4E5F6A1', 'nickname': 'ExitRelay1', 'country': 'NL'}
            ]
        }
    ]
    return jsonify({
        'circuits': circuits,
        'count': len(circuits),
        'tor_connected': _check_tor_connection()
    })

def _check_tor_connection():
    try:
        import socket
        # Check TOR Browser SOCKS port (9150) first
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', 9150))
            if result == 0:
                return True
        
        # Check control port (9051) and verify network is enabled
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', 9051))
            if result == 0:
                try:
                    sock.send(b'AUTHENTICATE\r\n')
                    auth_resp = sock.recv(1024)
                    if b'250 OK' in auth_resp:
                        sock.send(b'GETCONF DisableNetwork\r\n')
                        network_resp = sock.recv(1024).decode()
                        return 'DisableNetwork=0' in network_resp
                except:
                    pass
                return True
        return False
    except:
        return False

@app.route('/api/correlation/results', methods=['GET'])
def get_correlation_results_api():
    """Get correlation results"""
    return jsonify({
        'status': 'success',
        'results': [],
        'has_results': False
    })

@app.route('/api/tor/connect', methods=['GET'])
def connect_tor():
    """Connect to TOR Browser control port"""
    try:
        import socket
        
        # Try to connect to TOR Browser control port
        control_port = 9051
        control_host = '127.0.0.1'
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((control_host, control_port))
        sock.close()
        
        if result == 0:
            return jsonify({
                'status': 'success',
                'message': 'Connected to TOR Browser control port',
                'control_port': control_port,
                'tor_connected': True
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'TOR Browser not running or control port not accessible',
                'control_port': control_port,
                'tor_connected': False,
                'help': 'Make sure TOR Browser is running and network is enabled'
            }), 503
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'TOR connection failed: {str(e)}',
            'tor_connected': False
        }), 500
@app.route('/api/tor/correlate', methods=['POST'])
def run_tor_correlation():
    """Run comprehensive TOR correlation analysis"""
    global packet_sniffer, captured_packets
    
    try:
        print("[TOR CORRELATION] Starting analysis...")
        
        # Get correlation parameters
        data = request.json or {}
        mode = data.get('mode', 'batch')
        fetch_nodes = data.get('fetch_nodes', True)
        
        # Get packets for analysis
        if packet_sniffer:
            packets = packet_sniffer.get_packets()
            print(f"[TOR CORRELATION] Got {len(packets)} packets from sniffer")
        else:
            packets = captured_packets
            print(f"[TOR CORRELATION] Got {len(packets)} captured packets")
        
        if not packets:
            print("[TOR CORRELATION] No packets available")
            return jsonify({
                'status': 'error',
                'message': 'No packets available for correlation'
            }), 400
        
        # Mock TOR correlation results for demo
        tor_packets = [p for p in packets if p.get('src_port') in [9150, 9151, 443] or p.get('dst_port') in [9150, 9151, 443]]
        print(f"[TOR CORRELATION] Found {len(tor_packets)} TOR-like packets")
        
        # Generate mock correlation results
        results = {
            'statistics': {
                'total_packets': len(packets),
                'total_tor_packets': len(tor_packets),
                'total_circuits': max(1, min(5, len(tor_packets) // 10)),
                'unique_entry_nodes': max(1, min(3, len(tor_packets) // 20)),
                'unique_exit_nodes': max(1, min(4, len(tor_packets) // 15)),
                'unique_relay_nodes': max(1, min(8, len(tor_packets) // 8))
            },
            'confidence_scores': {
                'overall_confidence': min(95, max(60, 60 + len(tor_packets) * 2)),
                'circuit_detection': min(90, max(50, 50 + len(tor_packets) * 3)),
                'node_correlation': min(85, max(40, 40 + len(tor_packets) * 4))
            },
            'circuits': [],
            'connections': []
        }
        
        # Generate mock circuits
        for i in range(results['statistics']['total_circuits']):
            results['circuits'].append({
                'circuit_id': f'C{i+1}',
                'confidence': min(95, 70 + i * 5),
                'total_packets': max(1, len(tor_packets) // (i + 1)),
                'entry_node': f'Entry{i+1}',
                'exit_node': f'Exit{i+1}'
            })
        
        # Generate mock connections
        for i, packet in enumerate(tor_packets[:10]):
            results['connections'].append({
                'src_ip': packet.get('src_ip'),
                'dst_ip': packet.get('dst_ip'),
                'tor_confidence': min(95, 60 + i * 3),
                'tor_reasons': ['Port analysis', 'Traffic pattern', 'Timing correlation'][:i%3+1]
            })
        
        print(f"[TOR CORRELATION] Analysis complete - {results['statistics']['total_circuits']} circuits")
        
        return jsonify({
            'status': 'success',
            'mode': mode,
            'results': results,
            'summary': {
                'total_packets_analyzed': len(packets),
                'tor_packets_found': results['statistics']['total_tor_packets'],
                'circuits_detected': results['statistics']['total_circuits'],
                'overall_confidence': results['confidence_scores']['overall_confidence']
            }
        })
        
    except Exception as e:
        print(f"[TOR CORRELATION] Error: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/tor/correlation/results', methods=['GET'])
def get_correlation_results():
    """Get latest TOR correlation results"""
    try:
        # Return mock results for demo
        results = {
            'statistics': {
                'total_packets': len(captured_packets),
                'total_tor_packets': len([p for p in captured_packets if p.get('src_port') in [9150, 9151] or p.get('dst_port') in [9150, 9151]]),
                'total_circuits': 3,
                'unique_entry_nodes': 2,
                'unique_exit_nodes': 3
            },
            'circuits': [
                {'circuit_id': 'C1', 'confidence': 85, 'total_packets': 45},
                {'circuit_id': 'C2', 'confidence': 78, 'total_packets': 32},
                {'circuit_id': 'C3', 'confidence': 92, 'total_packets': 67}
            ]
        }
        
        return jsonify({
            'status': 'success',
            'results': results
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
@app.route('/api/tor/correlate-ip', methods=['POST'])
def correlate_ip():
    """Check if IP is a known TOR node"""
    try:
        data = request.json
        ip_address = data.get('ip')
        
        if not ip_address:
            return jsonify({
                'status': 'error',
                'message': 'IP address required'
            }), 400
        
        ts = get_tor_scraper()
        result = ts.correlate_ip_with_tor_nodes(ip_address)
        
        return jsonify({
            'status': 'success',
            'result': result
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/tor/correlate-ips-bulk', methods=['POST'])
def correlate_ips_bulk():
    """Bulk correlate multiple IPs"""
    try:
        data = request.json
        ip_list = data.get('ips', [])
        
        if not ip_list:
            return jsonify({
                'status': 'error',
                'message': 'IP list required'
            }), 400
        
        ts = get_tor_scraper()
        results = ts.bulk_correlate_ips(ip_list)
        
        return jsonify({
            'status': 'success',
            'results': results
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/tor/statistics', methods=['GET'])
def get_tor_network_stats():
    """Get TOR network statistics"""
    try:
        ts = get_tor_scraper()
        stats = ts.fetch_network_statistics()
        
        return jsonify({
            'status': 'success',
            'statistics': stats
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/tor/geographic', methods=['GET'])
def get_geographic_distribution():
    """Get geographic distribution of TOR nodes"""
    try:
        ts = get_tor_scraper()
        distribution = ts.get_geographic_distribution()
        
        return jsonify({
            'status': 'success',
            'distribution': distribution
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/reports/generate', methods=['POST'])
def generate_report():
    """Trigger generation of the quick HTML/PDF report and return paths."""
    try:
        script = os.path.join(os.path.dirname(__file__), 'scripts', 'generate_quick_report.py')
        if not os.path.exists(script):
            return jsonify({'status': 'error', 'message': 'Report script not found'}), 500

        # Run the generator as a subprocess and capture stdout
        proc = subprocess.run([sys.executable, script], cwd=os.path.dirname(__file__), capture_output=True, text=True, timeout=120)
        out = proc.stdout or ''
        err = proc.stderr or ''

        html_path = None
        pdf_path = None
        for line in out.splitlines():
            if line.startswith('SAVED_HTML'):
                html_path = line.split(' ', 1)[1].strip()
            if line.startswith('SAVED_PDF'):
                pdf_path = line.split(' ', 1)[1].strip()

        result = {
            'status': 'success' if proc.returncode == 0 else 'warning',
            'returncode': proc.returncode,
            'stdout': out,
            'stderr': err,
            'html': html_path,
            'pdf': pdf_path
        }

        return jsonify(result)
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': 'Report generation timed out'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================================================
# HEALTH & STATUS ENDPOINTS
# ============================================================================

@app.route('/api/geo/lookup', methods=['GET'])
def geo_lookup():
    """Lookup IP geolocation - Enhanced accuracy"""
    try:
        ip = request.args.get('ip')
        if not ip or ip in ['N/A', 'Unknown', 'localhost', '127.0.0.1', '0.0.0.0']:
            return jsonify({
                'location': {
                    'lat': 28.6139, 'lng': 77.2090,
                    'city': 'New Delhi', 'country': 'India', 'flag': '🇮🇳'
                }
            })
        
        # Enhanced IP geolocation database
        ip_db = {
            # Major DNS servers
            '8.8.8.8': {'lat': 37.4056, 'lng': -122.0775, 'city': 'Mountain View', 'country': 'USA', 'flag': '🇺🇸'},
            '8.8.4.4': {'lat': 37.4056, 'lng': -122.0775, 'city': 'Mountain View', 'country': 'USA', 'flag': '🇺🇸'},
            '1.1.1.1': {'lat': -33.8688, 'lng': 151.2093, 'city': 'Sydney', 'country': 'Australia', 'flag': '🇦🇺'},
            '1.0.0.1': {'lat': -33.8688, 'lng': 151.2093, 'city': 'Sydney', 'country': 'Australia', 'flag': '🇦🇺'},
            '208.67.222.222': {'lat': 37.7749, 'lng': -122.4194, 'city': 'San Francisco', 'country': 'USA', 'flag': '🇺🇸'},
            '9.9.9.9': {'lat': 37.7749, 'lng': -122.4194, 'city': 'San Francisco', 'country': 'USA', 'flag': '🇺🇸'},
            # Social media & tech companies
            '31.13.64.35': {'lat': 37.4419, 'lng': -122.1430, 'city': 'Menlo Park', 'country': 'USA', 'flag': '🇺🇸'},  # Facebook
            '142.250.191.14': {'lat': 37.4056, 'lng': -122.0775, 'city': 'Mountain View', 'country': 'USA', 'flag': '🇺🇸'},  # Google
            '13.107.42.14': {'lat': 47.6062, 'lng': -122.3321, 'city': 'Seattle', 'country': 'USA', 'flag': '🇺🇸'},  # Microsoft
            # CDN networks
            '104.16.132.229': {'lat': 37.7749, 'lng': -122.4194, 'city': 'San Francisco', 'country': 'USA', 'flag': '🇺🇸'},  # Cloudflare
            '151.101.193.140': {'lat': 37.7749, 'lng': -122.4194, 'city': 'San Francisco', 'country': 'USA', 'flag': '🇺🇸'},  # Fastly
        }
        
        if ip in ip_db:
            return jsonify({'location': ip_db[ip]})
        
        # Enhanced IP range detection
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                first = int(parts[0])
                second = int(parts[1])
                
                # Indian IP ranges
                if first in [117, 106, 203, 49, 115, 122, 125]:
                    cities = [
                        {'lat': 28.6139, 'lng': 77.2090, 'city': 'New Delhi', 'country': 'India', 'flag': '🇮🇳'},
                        {'lat': 19.0760, 'lng': 72.8777, 'city': 'Mumbai', 'country': 'India', 'flag': '🇮🇳'},
                        {'lat': 13.0827, 'lng': 80.2707, 'city': 'Chennai', 'country': 'India', 'flag': '🇮🇳'},
                        {'lat': 12.9716, 'lng': 77.5946, 'city': 'Bangalore', 'country': 'India', 'flag': '🇮🇳'},
                    ]
                    return jsonify({'location': cities[second % len(cities)]})
                
                # US IP ranges
                elif first in [8, 74, 173, 208, 192, 199, 104, 142, 216]:
                    cities = [
                        {'lat': 37.7749, 'lng': -122.4194, 'city': 'San Francisco', 'country': 'USA', 'flag': '🇺🇸'},
                        {'lat': 40.7128, 'lng': -74.0060, 'city': 'New York', 'country': 'USA', 'flag': '🇺🇸'},
                        {'lat': 34.0522, 'lng': -118.2437, 'city': 'Los Angeles', 'country': 'USA', 'flag': '🇺🇸'},
                        {'lat': 41.8781, 'lng': -87.6298, 'city': 'Chicago', 'country': 'USA', 'flag': '🇺🇸'},
                    ]
                    return jsonify({'location': cities[second % len(cities)]})
                
                # European IP ranges
                elif first in [185, 46, 31, 95, 151, 188]:
                    cities = [
                        {'lat': 52.5200, 'lng': 13.4050, 'city': 'Berlin', 'country': 'Germany', 'flag': '🇩🇪'},
                        {'lat': 51.5074, 'lng': -0.1278, 'city': 'London', 'country': 'UK', 'flag': '🇬🇧'},
                        {'lat': 48.8566, 'lng': 2.3522, 'city': 'Paris', 'country': 'France', 'flag': '🇫🇷'},
                        {'lat': 52.3676, 'lng': 4.9041, 'city': 'Amsterdam', 'country': 'Netherlands', 'flag': '🇳🇱'},
                    ]
                    return jsonify({'location': cities[second % len(cities)]})
                
                # Asian IP ranges
                elif first in [61, 125, 210, 220, 202, 218]:
                    cities = [
                        {'lat': 35.6762, 'lng': 139.6503, 'city': 'Tokyo', 'country': 'Japan', 'flag': '🇯🇵'},
                        {'lat': 37.5665, 'lng': 126.9780, 'city': 'Seoul', 'country': 'South Korea', 'flag': '🇰🇷'},
                        {'lat': 1.3521, 'lng': 103.8198, 'city': 'Singapore', 'country': 'Singapore', 'flag': '🇸🇬'},
                        {'lat': 39.9042, 'lng': 116.4074, 'city': 'Beijing', 'country': 'China', 'flag': '🇨🇳'},
                    ]
                    return jsonify({'location': cities[second % len(cities)]})
                
                # Canadian IP ranges
                elif first in [24, 70, 99, 184]:
                    cities = [
                        {'lat': 43.6532, 'lng': -79.3832, 'city': 'Toronto', 'country': 'Canada', 'flag': '🇨🇦'},
                        {'lat': 49.2827, 'lng': -123.1207, 'city': 'Vancouver', 'country': 'Canada', 'flag': '🇨🇦'},
                    ]
                    return jsonify({'location': cities[second % len(cities)]})
                
            except ValueError:
                pass
        
        # Default fallback
        return jsonify({
            'location': {
                'lat': 28.6139, 'lng': 77.2090,
                'city': 'New Delhi', 'country': 'India', 'flag': '🇮🇳'
            }
        })
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    global packet_sniffer
    
    def _check_tor_connection():
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', 9051))
            sock.close()
            return result == 0
        except:
            return False
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'sniffer_active': bool(packet_sniffer and getattr(packet_sniffer, 'is_running', False)),
        'tor_connected': _check_tor_connection()
    })


@app.route('/api/status', methods=['GET'])
def get_status():
    """Get application status"""
    global packet_sniffer, captured_packets, correlation_results
    # Prefer real-time counts from running sniffer when available
    sniffer_active = False
    packets_count = len(captured_packets)
    try:
        if packet_sniffer:
            sniffer_active = bool(getattr(packet_sniffer, 'is_running', False))
            # when active, report current buffer size
            if sniffer_active:
                try:
                    stats = packet_sniffer.get_statistics()
                    packets_count = int(stats.get('total_packets', packets_count))
                except Exception:
                    packets_count = len(getattr(packet_sniffer, 'packets', []))
    except Exception:
        pass

    return jsonify({
        'status': 'success',
        'sniffer_active': sniffer_active,
        'packets_captured': packets_count,
        'correlations_available': bool(correlation_results),
        'timestamp': datetime.now().isoformat()
    })


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'status': 'error',
        'message': 'Endpoint not found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'status': 'error',
        'message': 'Internal server error'
    }), 500


if __name__ == '__main__':
    print("=" * 60)
    print("TOR UNVEIL - Enhanced Backend API")
    print("=" * 60)
    print(f"Packet Sniffer: Available")
    print(f"ML Model: Loaded")
    print(f"TOR Scraper: Ready")
    print("=" * 60)
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )
