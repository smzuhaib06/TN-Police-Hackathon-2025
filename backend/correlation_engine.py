"""
Correlation Engine (time-based, heuristic) for TOR Unveil

Provides functions to parse PCAP bytes and correlate packet events with live Tor circuits
using Onionoo relay OR addresses and simple time-window matching.
"""
from datetime import datetime
import time
from io import BytesIO
from typing import List, Dict, Any
import dpkt
import socket

# Avoid circular import at module import time; import backend controller lazily in functions


def _inet_to_str(inet: bytes) -> str:
    try:
        if len(inet) == 4:
            return socket.inet_ntop(socket.AF_INET, inet)
        elif len(inet) == 16:
            return socket.inet_ntop(socket.AF_INET6, inet)
    except Exception:
        try:
            return '.'.join(str(b) for b in inet)
        except Exception:
            return repr(inet)


def parse_pcap_bytes(data: bytes) -> List[Dict[str, Any]]:
    packets = []
    try:
        pcap = dpkt.pcap.Reader(BytesIO(data))
    except Exception:
        return packets

    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            pkt = {
                'ts': float(ts),
                'timestamp_iso': datetime.utcfromtimestamp(ts).isoformat() + 'Z',
                'src_ip': _inet_to_str(ip.src),
                'dst_ip': _inet_to_str(ip.dst),
                'proto': int(ip.p),
            }
            payload = ip.data
            if isinstance(payload, dpkt.tcp.TCP):
                pkt['src_port'] = getattr(payload, 'sport', 0)
                pkt['dst_port'] = getattr(payload, 'dport', 0)
            elif isinstance(payload, dpkt.udp.UDP):
                pkt['src_port'] = getattr(payload, 'sport', 0)
                pkt['dst_port'] = getattr(payload, 'dport', 0)
            packets.append(pkt)
        except Exception:
            continue
    return packets


def correlate_pcap_with_circuits(pcap_bytes: bytes, window_seconds: int = 10) -> Dict[str, Any]:
    """Perform time-based and IP-based correlation between PCAP packets and Tor circuits.

    Returns a report with matched flows, candidate entry/exit mappings, and confidence scores.
    """
    packets = parse_pcap_bytes(pcap_bytes)
    # import backend controller lazily to avoid circular import
    try:
        from .stem_service import backend as tor_backend
    except Exception:
        # fallback: try top-level import
        import backend as tor_backend
    circuits = tor_backend.get_circuits()

    # Build relay IP map for quick lookup: fp -> [ips]
    relay_ip_map = {}
    for c in circuits:
        for hop in c.get('path', []):
            fp = hop.get('fingerprint')
            if not fp:
                continue
            relay = tor_backend.onionoo_relay(fp)
            if relay and 'or_addresses' in relay:
                ips = [a.split(':')[0] for a in relay.get('or_addresses', []) if a]
                relay_ip_map[fp.upper()] = ips

    matches = []
    entry_counts = {}
    exit_counts = {}

    for pkt in packets:
        ts = pkt['ts']
        src = pkt.get('src_ip')
        dst = pkt.get('dst_ip')
        dst_port = pkt.get('dst_port')

        for c in circuits:
            circ_id = c.get('id')
            created = float(c.get('created_at', time.time()))
            # temporal proximity: packet within window of circuit snapshot creation
            time_ok = abs(ts - created) <= window_seconds

            for hop in c.get('path', []):
                fp = hop.get('fingerprint')
                if not fp:
                    continue
                ips = relay_ip_map.get(fp.upper(), [])
                ip_match = False
                if ips:
                    if any(ip == src or ip == dst for ip in ips):
                        ip_match = True

                # port heuristic: common tor OR ports
                tor_ports = {9001, 9002, 9030, 9050, 9051, 443}
                port_match = dst_port in tor_ports if dst_port else False

                if ip_match or port_match:
                    confidence = 0.2
                    if ip_match:
                        confidence += 0.5
                    if time_ok:
                        confidence += 0.25

                    matches.append({
                        'packet': pkt,
                        'circuit_id': circ_id,
                        'relay_fp': fp,
                        'relay_ips': ips,
                        'ip_match': ip_match,
                        'port_match': port_match,
                        'time_proximity': time_ok,
                        'confidence': min(confidence, 1.0)
                    })

                    # aggregate counts
                    entry = c.get('entry')
                    exit = c.get('exit')
                    if entry:
                        entry_counts[entry] = entry_counts.get(entry, 0) + 1
                    if exit:
                        exit_counts[exit] = exit_counts.get(exit, 0) + 1

    # build candidate list with normalized confidence
    candidate_entries = []
    total_entry = sum(entry_counts.values()) or 1
    for e, cnt in entry_counts.items():
        candidate_entries.append({'entry': e, 'count': cnt, 'score': cnt / total_entry})

    candidate_exits = []
    total_exit = sum(exit_counts.values()) or 1
    for e, cnt in exit_counts.items():
        candidate_exits.append({'exit': e, 'count': cnt, 'score': cnt / total_exit})

    # sort by score
    candidate_entries.sort(key=lambda x: x['score'], reverse=True)
    candidate_exits.sort(key=lambda x: x['score'], reverse=True)

    report = {
        'packet_count': len(packets),
        'circuit_snapshot_count': len(circuits),
        'matches': matches,
        'candidate_entries': candidate_entries,
        'candidate_exits': candidate_exits,
        'generated_at': datetime.utcnow().isoformat() + 'Z'
    }

    return report
