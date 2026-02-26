from flask import Flask, jsonify, send_file
from flask_cors import CORS
import os
import sys
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Core imports; no lazy indirection to avoid hangs
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from ip_corr import parse_pcap_flows, correlate_tor_flows

try:
    from enhanced_report_generator import generate_advanced_report
except ImportError as e:
    print(f"Warning: Report generator not available: {e}")
    def generate_advanced_report(**kw):
        return {'report_id': 'error', 'reports': {}, 'summary': {}, 'error': 'report generator unavailable'}

try:
    from enhanced_packet_sniffer import (
        sniffer, start_sniffer, stop_sniffer, get_sniffer_stats, get_tor_traffic, get_all_packets
    )
except ImportError as e:
    print(f"Warning: Sniffer modules not available: {e}")
    sniffer = None
    def start_sniffer(**kw):
        return {'status': 'error', 'message': 'Sniffer not available'}
    def stop_sniffer():
        return {'status': 'error', 'message': 'Sniffer not available'}
    def get_sniffer_stats():
        return {}
    def get_tor_traffic(limit=100):
        return []
    def get_all_packets(limit=50):
        return []

@app.route('/api/health')
def health_check():
    return jsonify({'status': 'healthy', 'sniffer_active': sniffer.is_running if sniffer else False})

@app.route('/api/capture/packets')
def get_packets_api():
    """Get all captured packets"""
    if not sniffer:
        return jsonify([])
    
    try:
        packets = sniffer.packets[-20:] if hasattr(sniffer, 'packets') and sniffer.packets else []
        return jsonify(packets)
    except:
        return jsonify([])

@app.route('/api/capture/export/pcap')
def export_pcap():
    """Export captured packets as PCAP file"""
    try:
        if not sniffer:
            return jsonify({'error': 'No sniffer instance'}), 404
        
        if hasattr(sniffer, 'pcap_file') and os.path.exists(sniffer.pcap_file):
            pcap_path = sniffer.pcap_file
        else:
            pcap_dir = os.path.join(os.path.dirname(__file__), '..', 'pcap_storage')
            if not os.path.exists(pcap_dir):
                return jsonify({'error': 'No PCAP files available'}), 404
            
            pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith('.pcap')]
            if not pcap_files:
                return jsonify({'error': 'No PCAP files found'}), 404
            
            pcap_files.sort(key=lambda x: os.path.getmtime(os.path.join(pcap_dir, x)), reverse=True)
            pcap_path = os.path.join(pcap_dir, pcap_files[0])
        
        unique_name = f'tor_capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pcap'
        return send_file(pcap_path, as_attachment=True, download_name=unique_name)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    try:
        result = start_sniffer(interface=None, packet_limit=10000)
        return jsonify(result)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    result = stop_sniffer()
    return jsonify(result)

@app.route('/api/capture/status', methods=['GET'])
def capture_status():
    stats = get_sniffer_stats()
    return jsonify({
        'is_capturing': sniffer.is_running if sniffer else False,
        'packets_captured': stats.get('total_packets', 0),
        'tor_packets': stats.get('tor_packets', 0),
        'statistics': stats
    })

@app.route('/api/analysis/correlations', methods=['GET'])
def get_correlations():
    tor_packets = get_tor_traffic(limit=50)
    return jsonify(tor_packets)

@app.route('/api/analysis/geo', methods=['GET'])
def get_geo_data():
    return jsonify([])

@app.route('/api/reports/generate', methods=['GET'])
def generate_tor_report():
    try:
        # Get real captured data from enhanced sniffer
        stats = get_sniffer_stats()
        tor_packets = get_tor_traffic(limit=200)
        
        # Prepare data for report
        circuits = []
        if tor_packets:
            # Create sample circuits from captured data
            for i, packet in enumerate(tor_packets[:3]):
                circuits.append({
                    'id': f'C{i+1:03d}',
                    'status': 'BUILT',
                    'purpose': 'GENERAL',
                    'path': [
                        {'nickname': f'Guard{i+1}', 'fingerprint': f'FP{i+1}ABC123'},
                        {'nickname': f'Middle{i+1}', 'fingerprint': f'FP{i+1}DEF456'},
                        {'nickname': f'Exit{i+1}', 'fingerprint': f'FP{i+1}GHI789'}
                    ]
                })
        
        sniffer_stats = {
            'total_packets': stats.get('total_packets', 0),
            'tor_packets': stats.get('tor_packets', 0),
            'protocol_counts': stats.get('protocols', {}),
            'sniffers': 1
        }
        
        pcap_analysis = {
            'packet_count': stats.get('total_packets', 0),
            'flow_count': stats.get('flows', 0),
            'tor_indicators_found': len(tor_packets),
            'file': 'live_capture.pcap'
        }

        # Tor correlation using captured PCAP (ingress/egress best effort)
        correlations = []
        try:
            pcap_path = None
            if hasattr(sniffer, 'pcap_file'):
                pcap_path = getattr(sniffer, 'pcap_file', None)
            if not pcap_path:
                pcap_dir = os.path.join(os.path.dirname(__file__), '..', 'pcap_storage')
                if os.path.isdir(pcap_dir):
                    pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith('.pcap')]
                    if pcap_files:
                        pcap_files.sort(key=lambda x: os.path.getmtime(os.path.join(pcap_dir, x)), reverse=True)
                        pcap_path = os.path.join(pcap_dir, pcap_files[0])

            if pcap_path and os.path.exists(pcap_path):
                ingress_flows = parse_pcap_flows(pcap_path, 'ingress')
                egress_flows = parse_pcap_flows(pcap_path, 'egress')
                correlations = correlate_tor_flows(ingress_flows, egress_flows, min_packets=6, threshold=0.55)
                pcap_analysis['file'] = os.path.basename(pcap_path)
        except Exception as corr_err:
            print(f"Correlation analysis skipped: {corr_err}")
        
        # Generate advanced report with real data
        result = generate_advanced_report(
            circuits=circuits,
            sniffer_stats=sniffer_stats,
            pcap_analysis=pcap_analysis,
            correlations=correlations
        )
        
        # Get filename from result
        html_filename = result['reports']['html']
        
        return jsonify({
            'status': 'success',
            'report_id': result['report_id'],
            'files': result['reports'],
            'filename': html_filename,
            'report_url': f'/api/report/html/{html_filename}'
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/reports/download/<filename>')
def download_report(filename):
    reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
    file_path = os.path.join(reports_dir, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return "Report not found", 404

@app.route('/api/report/html/<filename>')
def serve_html_report(filename):
    reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
    file_path = os.path.join(reports_dir, filename)
    if os.path.exists(file_path):
        return send_file(file_path)
    return "Report not found", 404

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

if __name__ == '__main__':
    app.run(debug=True, port=5001)