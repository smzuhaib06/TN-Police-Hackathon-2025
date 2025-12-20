import time
import json
import sys
import os
import argparse

def main():
    parser = argparse.ArgumentParser(description='Run live PacketSniffer for a short period')
    parser.add_argument('--duration', '-d', type=int, default=10, help='Capture duration in seconds')
    parser.add_argument('--interface', '-i', default=None, help='Interface to capture on')
    parser.add_argument('--packet_limit', type=int, default=1000, help='Maximum packets to capture')
    parser.add_argument('--bpf', default=None, help='BPF filter string (passed to scapy.sniff)')
    args = parser.parse_args()

    try:
        # Ensure local backend folder is importable
        sys.path.insert(0, os.path.join(os.getcwd(), 'backend'))
        from packet_sniffer import PacketSniffer

        duration = args.duration
        interface = args.interface
        packet_limit = args.packet_limit
        bpf = args.bpf

        print('INITIALIZING_SNIFFER')
        ps = PacketSniffer(interface=interface, packet_limit=packet_limit)

        if bpf:
            # Use scapy's sniff with BPF filter and direct callback into PacketSniffer
            try:
                import scapy.all as scapy
                print(f'STARTING_SNIFF with BPF="{bpf}" interface={interface} duration={duration}s')
                scapy.sniff(prn=ps.packet_callback, iface=interface, filter=bpf, timeout=duration, store=False)
                print('BPF_SNIFF_COMPLETE')
            except Exception as e:
                print('ERROR starting BPF sniff:', e)
        else:
            print(f'STARTING_SNIFF interface={interface} duration={duration}s')
            ps.start_sniffing()
            for i in range(duration):
                print(f'SNIFFING... {i+1}/{duration}s')
                time.sleep(1)
            print('STOPPING_SNIFF')
            ps.stop_sniffing()

        # allow any in-flight processing
        time.sleep(1)

        stats = ps.get_statistics()
        packets = ps.get_packets()
        tor_packets = ps.get_tor_traffic()
        latest = ps.latest_pcap()

        result = {
            'status': 'completed',
            'stats': stats,
            'captured_count': len(packets),
            'sample_packets': packets[:10],
            'tor_packets_count': len(tor_packets),
            'latest_pcap': latest
        }

        print('RESULT_JSON_START')
        print(json.dumps(result, default=str, indent=2))
        print('RESULT_JSON_END')

    except Exception as e:
        print('ERROR', str(e))

if __name__ == '__main__':
    main()
