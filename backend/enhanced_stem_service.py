"""
Enhanced TOR Unveil Backend Service
Integrates all enhanced features: packet sniffer, PCAP analyzer, report generator, ControlPort capture
"""

import os
import json
import time
import threading
from datetime import datetime
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

# Import enhanced modules
try:
    from enhanced_packet_sniffer import start_sniffer, stop_sniffer, get_sniffer_stats, get_tor_traffic
    SNIFFER_AVAILABLE = True
except ImportError:
    SNIFFER_AVAILABLE = False

try:
    from enhanced_pcap_analyzer import analyze_pcap_file
    PCAP_ANALYZER_AVAILABLE = True
except ImportError:
    PCAP_ANALYZER_AVAILABLE = False

try:
    from enhanced_report_generator import generate_report
    REPORT_GENERATOR_AVAILABLE = True
except ImportError:
    REPORT_GENERATOR_AVAILABLE = False

try:
    from tor_controlport_capture import start_tor_capture, stop_tor_capture, get_tor_capture_stats, get_tor_circuits, export_tor_data
    TOR_CAPTURE_AVAILABLE = True
except ImportError:
    TOR_CAPTURE_AVAILABLE = False

# Original stem service imports
try:
    from stem.control import Controller
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False

import requests
from functools import wraps

# Configuration
API_KEY = os.environ.get('API_KEY', 'changeme')
BACKEND_PORT = int(os.environ.get('BACKEND_PORT', '5000'))
TOR_CONTROL_HOST = os.environ.get('TOR_CONTROL_HOST', '127.0.0.1')
TOR_CONTROL_PORT = int(os.environ.get('TOR_CONTROL_PORT', '9051'))
ONIONOO_URL = 'https://onionoo.torproject.org'

app = Flask(__name__)
CORS(app)

# Global state
backend_state = {
    'controller': None,
    'circuits': {},
    'sniffer_active': False,
    'tor_capture_active': False,
    'last_pcap_analysis': None,
    'system_stats': {
        'start_time': datetime.now(),
        'requests_handled': 0,
        'features_enabled': {
            'stem': STEM_AVAILABLE,
            'sniffer': SNIFFER_AVAILABLE,
            'pcap_analyzer': PCAP_ANALYZER_AVAILABLE,
            'report_generator': REPORT_GENERATOR_AVAILABLE,
            'tor_capture': TOR_CAPTURE_AVAILABLE
        }
    }
}

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-KEY')
        if not key or key != API_KEY:
            return jsonify({'error': 'API key required'}), 401
        backend_state['system_stats']['requests_handled'] += 1
        return f(*args, **kwargs)
    return decorated

# ==================== HEALTH & STATUS ====================

@app.route('/api/health')
def health():
    """Enhanced health check with feature status"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'controller': backend_state['controller'] is not None,
        'features': backend_state['system_stats']['features_enabled'],
        'active_services': {
            'packet_sniffer': backend_state['sniffer_active'],
            'tor_capture': backend_state['tor_capture_active']
        },
        'uptime_seconds': (datetime.now() - backend_state['system_stats']['start_time']).total_seconds(),
        'requests_handled': backend_state['system_stats']['requests_handled']
    })

@app.route('/api/status/detailed')
@require_api_key
def detailed_status():
    """Detailed system status"""
    status = {
        'backend': {
            'version': '2.0-enhanced',
            'start_time': backend_state['system_stats']['start_time'].isoformat(),
            'features': backend_state['system_stats']['features_enabled']
        },
        'tor_connection': {
            'connected': backend_state['controller'] is not None,
            'host': TOR_CONTROL_HOST,
            'port': TOR_CONTROL_PORT
        },
        'services': {}
    }
    
    # Sniffer status
    if SNIFFER_AVAILABLE:
        try:
            status['services']['packet_sniffer'] = get_sniffer_stats()
        except Exception as e:
            status['services']['packet_sniffer'] = {'error': str(e)}
    
    # TOR capture status
    if TOR_CAPTURE_AVAILABLE:
        try:
            status['services']['tor_capture'] = get_tor_capture_stats()
        except Exception as e:
            status['services']['tor_capture'] = {'error': str(e)}
    
    return jsonify(status)

# ==================== PACKET SNIFFER ENDPOINTS ====================

@app.route('/api/sniffer/start', methods=['POST'])
@require_api_key
def start_packet_sniffer():
    """Start enhanced packet sniffer"""
    if not SNIFFER_AVAILABLE:
        return jsonify({'error': 'Packet sniffer not available'}), 500
    
    try:
        data = request.json or {}
        interface = data.get('interface')
        packet_limit = data.get('packet_limit', 5000)
        
        result = start_sniffer(interface=interface, packet_limit=packet_limit)
        backend_state['sniffer_active'] = True
        
        return jsonify({
            'status': 'started',
            'result': result,
            'message': 'Enhanced packet sniffer started'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sniffer/stop', methods=['POST'])
@require_api_key
def stop_packet_sniffer():
    """Stop packet sniffer"""
    if not SNIFFER_AVAILABLE:
        return jsonify({'error': 'Packet sniffer not available'}), 500
    
    try:
        result = stop_sniffer()
        backend_state['sniffer_active'] = False
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sniffer/stats')
@require_api_key
def sniffer_statistics():
    """Get sniffer statistics"""
    if not SNIFFER_AVAILABLE:
        return jsonify({'error': 'Packet sniffer not available'}), 500
    
    try:
        stats = get_sniffer_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sniffer/tor-traffic')
@require_api_key
def sniffer_tor_traffic():
    """Get captured TOR traffic"""
    if not SNIFFER_AVAILABLE:
        return jsonify({'error': 'Packet sniffer not available'}), 500
    
    try:
        limit = request.args.get('limit', 100, type=int)
        traffic = get_tor_traffic(limit=limit)
        return jsonify({
            'tor_packets': traffic,
            'count': len(traffic)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== TOR CONTROLPORT CAPTURE ====================

@app.route('/api/tor-capture/start', methods=['POST'])
@require_api_key
def start_tor_controlport_capture():
    """Start TOR ControlPort capture"""
    if not TOR_CAPTURE_AVAILABLE:
        return jsonify({'error': 'TOR capture not available'}), 500
    
    try:
        data = request.json or {}
        host = data.get('host', TOR_CONTROL_HOST)
        port = data.get('port', TOR_CONTROL_PORT)
        
        result = start_tor_capture(control_host=host, control_port=port)
        if result['status'] == 'started':
            backend_state['tor_capture_active'] = True
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tor-capture/stop', methods=['POST'])
@require_api_key
def stop_tor_controlport_capture():
    """Stop TOR ControlPort capture"""
    if not TOR_CAPTURE_AVAILABLE:
        return jsonify({'error': 'TOR capture not available'}), 500
    
    try:
        result = stop_tor_capture()
        backend_state['tor_capture_active'] = False
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tor-capture/circuits')
@require_api_key
def tor_capture_circuits():
    """Get TOR circuits from capture"""
    if not TOR_CAPTURE_AVAILABLE:
        return jsonify({'error': 'TOR capture not available'}), 500
    
    try:
        circuits = get_tor_circuits()
        return jsonify(circuits)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tor-capture/export')
@require_api_key
def export_tor_capture_data():
    """Export all TOR capture data"""
    if not TOR_CAPTURE_AVAILABLE:
        return jsonify({'error': 'TOR capture not available'}), 500
    
    try:
        data = export_tor_data()
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== ENHANCED PCAP ANALYSIS ====================

@app.route('/api/pcap/analyze-enhanced', methods=['POST'])
@require_api_key
def enhanced_pcap_analysis():
    """Enhanced PCAP analysis with TOR detection"""
    if not PCAP_ANALYZER_AVAILABLE:
        return jsonify({'error': 'Enhanced PCAP analyzer not available'}), 500
    
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Save uploaded file
        upload_dir = os.path.join(os.path.dirname(__file__), 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        
        filepath = os.path.join(upload_dir, file.filename)
        file.save(filepath)
        
        # Analyze with enhanced analyzer
        analysis = analyze_pcap_file(filepath)
        backend_state['last_pcap_analysis'] = analysis
        
        return jsonify({
            'status': 'success',
            'analysis': analysis,
            'filename': file.filename
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== ENHANCED REPORT GENERATION ====================

@app.route('/api/reports/generate-enhanced', methods=['POST'])
@require_api_key
def generate_enhanced_report():
    """Generate enhanced forensic report"""
    if not REPORT_GENERATOR_AVAILABLE:
        return jsonify({'error': 'Enhanced report generator not available'}), 500
    
    try:
        # Collect all available data
        report_data = {
            'circuits': list(backend_state['circuits'].values()),
            'pcap_analysis': backend_state['last_pcap_analysis'],
            'correlations': []
        }
        
        # Add sniffer data if available
        if SNIFFER_AVAILABLE:
            try:
                report_data['sniffer_stats'] = get_sniffer_stats()
            except Exception:
                pass
        
        # Add TOR capture data if available
        if TOR_CAPTURE_AVAILABLE:
            try:
                report_data['tor_capture'] = get_tor_circuits()
            except Exception:
                pass
        
        # Generate comprehensive report
        result = generate_report(report_data)
        
        return jsonify({
            'status': 'success',
            'report_id': result['report_id'],
            'reports': result['reports'],
            'summary': result['summary']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== ORIGINAL ENDPOINTS (ENHANCED) ====================

@app.route('/api/circuits')
@require_api_key
def api_circuits():
    """Get circuits (enhanced with capture data)"""
    circuits = list(backend_state['circuits'].values())
    
    # Add TOR capture circuit data if available
    if TOR_CAPTURE_AVAILABLE:
        try:
            capture_circuits = get_tor_circuits()
            if 'active_circuits' in capture_circuits:
                for circuit_id, circuit_data in capture_circuits['active_circuits'].items():
                    # Merge with existing or add new
                    found = False
                    for existing in circuits:
                        if existing.get('id') == circuit_id:
                            existing.update(circuit_data)
                            found = True
                            break
                    if not found:
                        circuits.append(circuit_data)
        except Exception:
            pass
    
    return jsonify({
        'circuits': circuits,
        'count': len(circuits),
        'enhanced': True
    })

@app.route('/api/relays')
@require_api_key
def api_relays():
    """Get relay data from Onionoo"""
    try:
        response = requests.get(f"{ONIONOO_URL}/summary?limit=2000", timeout=15)
        if response.status_code == 200:
            data = response.json()
            # Enhance with local analysis if available
            if SNIFFER_AVAILABLE:
                try:
                    stats = get_sniffer_stats()
                    data['local_analysis'] = {
                        'tor_packets_detected': stats.get('tor_packets', 0),
                        'relay_ips_loaded': stats.get('relay_ips_loaded', 0)
                    }
                except Exception:
                    pass
            return jsonify(data)
        else:
            return jsonify({'error': f'Onionoo returned {response.status_code}'}), 502
    except Exception as e:
        return jsonify({'error': str(e)}), 502

# ==================== SYSTEM CONTROL ====================

@app.route('/api/system/start-all', methods=['POST'])
@require_api_key
def start_all_services():
    """Start all available services"""
    results = {}
    
    # Start packet sniffer
    if SNIFFER_AVAILABLE:
        try:
            result = start_sniffer(packet_limit=5000)
            results['sniffer'] = result
            backend_state['sniffer_active'] = True
        except Exception as e:
            results['sniffer'] = {'error': str(e)}
    
    # Start TOR capture
    if TOR_CAPTURE_AVAILABLE:
        try:
            result = start_tor_capture()
            results['tor_capture'] = result
            if result['status'] == 'started':
                backend_state['tor_capture_active'] = True
        except Exception as e:
            results['tor_capture'] = {'error': str(e)}
    
    return jsonify({
        'status': 'completed',
        'services': results,
        'message': 'All available services started'
    })

@app.route('/api/system/stop-all', methods=['POST'])
@require_api_key
def stop_all_services():
    """Stop all services"""
    results = {}
    
    # Stop sniffer
    if SNIFFER_AVAILABLE:
        try:
            results['sniffer'] = stop_sniffer()
            backend_state['sniffer_active'] = False
        except Exception as e:
            results['sniffer'] = {'error': str(e)}
    
    # Stop TOR capture
    if TOR_CAPTURE_AVAILABLE:
        try:
            results['tor_capture'] = stop_tor_capture()
            backend_state['tor_capture_active'] = False
        except Exception as e:
            results['tor_capture'] = {'error': str(e)}
    
    return jsonify({
        'status': 'completed',
        'services': results,
        'message': 'All services stopped'
    })

# ==================== INITIALIZATION ====================

def initialize_backend():
    """Initialize backend services"""
    print("TOR Unveil Enhanced Backend v2.0")
    print("=" * 50)
    
    # Check feature availability
    features = backend_state['system_stats']['features_enabled']
    print(f"Stem (TOR Control): {'✓' if features['stem'] else '✗'}")
    print(f"Packet Sniffer: {'✓' if features['sniffer'] else '✗'}")
    print(f"PCAP Analyzer: {'✓' if features['pcap_analyzer'] else '✗'}")
    print(f"Report Generator: {'✓' if features['report_generator'] else '✗'}")
    print(f"TOR Capture: {'✓' if features['tor_capture'] else '✗'}")
    print()
    
    # Try to connect to TOR ControlPort
    if STEM_AVAILABLE:
        try:
            controller = Controller.from_port(address=TOR_CONTROL_HOST, port=TOR_CONTROL_PORT)
            
            # Try authentication
            tor_paths = [
                'Z:\\Tor Browser\\Browser\\TorBrowser\\Data\\Tor',
                'C:\\Users\\LENOVO\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Data\\Tor'
            ]
            
            authenticated = False
            for tor_path in tor_paths:
                try:
                    cookie_path = os.path.join(tor_path, 'control_auth_cookie')
                    if os.path.exists(cookie_path):
                        with open(cookie_path, 'rb') as f:
                            cookie = f.read()
                        controller.authenticate(cookie)
                        authenticated = True
                        print(f"TOR: Connected via {cookie_path}")
                        break
                except Exception:
                    continue
            
            if not authenticated:
                try:
                    controller.authenticate()
                    authenticated = True
                    print("TOR: Connected with auto-authentication")
                except Exception:
                    pass
            
            if authenticated:
                backend_state['controller'] = controller
                print("TOR: ControlPort ready")
            else:
                print("TOR: ControlPort connection failed")
                
        except Exception as e:
            print(f"TOR: Connection error - {e}")
    
    print(f"\nStarting server on port {BACKEND_PORT}...")
    print(f"API Key: {API_KEY}")
    print("=" * 50)

if __name__ == "__main__":
    initialize_backend()
    app.run(host='0.0.0.0', port=BACKEND_PORT, debug=False)