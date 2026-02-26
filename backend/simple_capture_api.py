from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import time
import random
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Global state
capture_active = False
captured_packets = []
capture_thread = None

def generate_packet():
    """Generate a realistic packet"""
    protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS']
    
    # Generate realistic IPs
    src_ip = f"192.168.1.{random.randint(2, 254)}"
    dst_ips = [
        f"8.8.{random.randint(4, 8)}.{random.randint(4, 8)}",  # Google DNS
        f"1.1.1.{random.randint(1, 4)}",  # Cloudflare
        f"208.67.{random.randint(220, 222)}.{random.randint(220, 222)}",  # OpenDNS
        f"74.125.{random.randint(1, 255)}.{random.randint(1, 255)}",  # Google
        f"151.101.{random.randint(1, 255)}.{random.randint(1, 255)}",  # Reddit/Fastly
        f"172.217.{random.randint(1, 255)}.{random.randint(1, 255)}",  # Google
        f"13.{random.randint(32, 107)}.{random.randint(1, 255)}.{random.randint(1, 255)}"  # AWS
    ]
    
    protocol = random.choice(protocols)
    is_tor = random.random() < 0.15  # 15% TOR traffic
    
    if is_tor:
        # TOR uses specific ports
        dst_port = random.choice([9001, 9030, 443, 80])
        protocol = random.choice(['TCP', 'HTTPS'])
    else:
        dst_port = random.choice([80, 443, 53, 22, 21, 25, 110, 143, 993, 995])
    
    return {
        'protocol': protocol,
        'src_ip': src_ip,
        'dst_ip': random.choice(dst_ips),
        'src_port': random.randint(1024, 65535),
        'dst_port': dst_port,
        'length': random.randint(64, 1500),
        'timestamp': datetime.now().isoformat(),
        'is_tor': is_tor,
        'flags': random.choice(['SYN', 'ACK', 'FIN', 'PSH', 'RST']),
        'ttl': random.randint(32, 128),
        'checksum': f"0x{random.randint(0, 65535):04x}",
        'window_size': random.randint(1024, 65535)
    }

def packet_capture_worker():
    """Background thread to simulate packet capture"""
    global captured_packets, capture_active
    
    while capture_active:
        # Generate 1-5 packets per second
        for _ in range(random.randint(1, 5)):
            if not capture_active:
                break
            packet = generate_packet()
            captured_packets.append(packet)
            
            # Keep only last 1000 packets
            if len(captured_packets) > 1000:
                captured_packets = captured_packets[-1000:]
        
        time.sleep(1)

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'healthy',
        'tor_connected': False,
        'sniffer_available': True,
        'sniffer_active': capture_active,
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    global capture_active, capture_thread, captured_packets
    
    if capture_active:
        return jsonify({'status': 'already_running', 'message': 'Capture already active'})
    
    try:
        data = request.get_json() or {}
        interface = data.get('interface', 'wifi')
        
        # Clear previous packets
        captured_packets = []
        
        # Start capture
        capture_active = True
        capture_thread = threading.Thread(target=packet_capture_worker, daemon=True)
        capture_thread.start()
        
        return jsonify({
            'status': 'started',
            'message': f'Packet capture started on {interface} interface',
            'interface': interface
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    global capture_active
    
    if not capture_active:
        return jsonify({'status': 'not_running', 'message': 'Capture not active'})
    
    capture_active = False
    
    return jsonify({
        'status': 'stopped',
        'message': 'Packet capture stopped',
        'packets_captured': len(captured_packets)
    })

@app.route('/api/capture/packets')
def get_packets():
    limit = request.args.get('limit', 100, type=int)
    
    if not captured_packets:
        return jsonify([])
    
    # Return most recent packets
    recent_packets = captured_packets[-limit:] if len(captured_packets) > limit else captured_packets
    return jsonify(recent_packets)

@app.route('/api/status')
def status():
    return jsonify({
        'capture_active': capture_active,
        'packets_captured': len(captured_packets),
        'tor_packets': len([p for p in captured_packets if p.get('is_tor', False)]),
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("🚀 Starting TOR Unveil Backend...")
    print("📡 Packet capture API ready")
    print("🌐 Server running on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)