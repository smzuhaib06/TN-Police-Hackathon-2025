import sys
sys.path.append('.')
from enhanced_packet_sniffer import sniffer

if sniffer:
    print(f"Total packets in sniffer: {len(sniffer.packets)}")
    if sniffer.packets:
        print(f"Sample packet: {sniffer.packets[0]}")
else:
    print("No sniffer instance")