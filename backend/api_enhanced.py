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


@app.route('/api/sniffer/export', methods=['GET'])
def export_latest_pcap():
    """Export the latest persisted PCAP/JSON capture file"""
    global packet_sniffer
    try:
        if not packet_sniffer:
            return jsonify({'status': 'error', 'message': 'No active packet sniffer'}), 400

        latest = None
        try:
            latest = packet_sniffer.latest_pcap()
        except Exception:
            latest = None

        if not latest:
            return jsonify({'status': 'error', 'message': 'No persisted PCAP available'}), 404

        # Send file, let Flask handle mime and streaming
        return send_file(latest, as_attachment=True)
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

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
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
