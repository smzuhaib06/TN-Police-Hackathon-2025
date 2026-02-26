#!/usr/bin/env python3
"""
Test script to verify packet capture functionality
"""

import requests
import time
import json

def test_backend_connection():
    """Test if backend is running"""
    try:
        response = requests.get('http://localhost:5001/api/health', timeout=5)
        print(f"✓ Backend health check: {response.status_code}")
        data = response.json()
        print(f"  - Scapy available: {data.get('sniffer_available', False)}")
        print(f"  - Admin privileges: {not data.get('admin_required', True)}")
        return True
    except Exception as e:
        print(f"✗ Backend connection failed: {e}")
        return False

def test_packet_capture():
    """Test packet capture functionality"""
    try:
        # Start capture
        print("\n--- Starting Packet Capture ---")
        response = requests.post('http://localhost:5001/api/capture/start', timeout=10)
        data = response.json()
        print(f"Start capture response: {data}")
        
        if data.get('status') != 'started':
            print(f"✗ Failed to start capture: {data.get('message', 'Unknown error')}")
            return False
        
        print("✓ Capture started successfully")
        
        # Wait for packets
        print("\n--- Waiting for packets (10 seconds) ---")
        for i in range(10):
            time.sleep(1)
            try:
                debug_response = requests.get('http://localhost:5001/api/debug/sniffer', timeout=5)
                debug_data = debug_response.json()
                packet_count = debug_data.get('total_packets', 0)
                print(f"  Second {i+1}: {packet_count} packets captured")
                
                if packet_count > 0:
                    print("✓ Packets are being captured!")
                    break
            except Exception as e:
                print(f"  Debug check failed: {e}")
        
        # Check final status
        print("\n--- Final Status Check ---")
        debug_response = requests.get('http://localhost:5001/api/debug/sniffer', timeout=5)
        debug_data = debug_response.json()
        
        print(f"Total packets: {debug_data.get('total_packets', 0)}")
        print(f"TOR packets: {debug_data.get('tor_packets', 0)}")
        print(f"Sniffer active: {debug_data.get('sniffer_active', False)}")
        
        # Test packet retrieval
        print("\n--- Testing Packet Retrieval ---")
        packets_response = requests.get('http://localhost:5001/api/capture/packets', timeout=5)
        packets_data = packets_response.json()
        
        if isinstance(packets_data, list):
            print(f"✓ Retrieved {len(packets_data)} packets as array")
            if len(packets_data) > 0:
                sample_packet = packets_data[0]
                print(f"Sample packet: {sample_packet.get('src_ip', 'N/A')} → {sample_packet.get('dst_ip', 'N/A')} ({sample_packet.get('protocol', 'N/A')})")
        else:
            print(f"✗ Unexpected packet data format: {type(packets_data)}")
        
        # Stop capture
        print("\n--- Stopping Capture ---")
        stop_response = requests.post('http://localhost:5001/api/capture/stop', timeout=5)
        stop_data = stop_response.json()
        print(f"Stop response: {stop_data}")
        
        return True
        
    except Exception as e:
        print(f"✗ Packet capture test failed: {e}")
        return False

def main():
    print("=== TOR Unveil Packet Capture Test ===")
    
    if not test_backend_connection():
        return
    
    if not test_packet_capture():
        return
    
    print("\n✓ All tests completed!")

if __name__ == '__main__':
    main()