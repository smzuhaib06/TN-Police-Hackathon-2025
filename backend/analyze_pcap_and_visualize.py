import os
import sys
import json
import math

sys.path.insert(0, os.path.join(os.getcwd(), 'backend'))
from packet_sniffer import PCAPAnalyzer

def build_svg_from_flows(flows, outpath='pcap_analysis.svg'):
    # flows is mapping flow_key -> count
    nodes = {}
    links = []
    for i, (flow, count) in enumerate(sorted(flows.items(), key=lambda x: -x[1])[:40]):
        parts = flow.split('-')
        if len(parts) == 2:
            src = parts[0]
            dst = parts[1]
        else:
            src = flow; dst = ''
        if src and src not in nodes:
            nodes[src] = {'id': len(nodes)+1, 'ip': src}
        if dst and dst not in nodes:
            nodes[dst] = {'id': len(nodes)+1, 'ip': dst}
        links.append({'source': src, 'target': dst, 'weight': count})

    svg_w, svg_h = 900, 480
    cx, cy = svg_w/2, svg_h/2
    r = min(cx, cy) - 80
    svg_parts = [f"<svg width='{svg_w}' height='{svg_h}' xmlns='http://www.w3.org/2000/svg'>"]
    node_list = list(nodes.values())
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
    svg = '\n'.join(svg_parts)
    with open(outpath, 'w', encoding='utf8') as f:
        f.write(svg)
    return outpath


def analyze(file_path):
    print('ANALYZE_START', file_path)
    result = PCAPAnalyzer.analyze_pcap_file(file_path)
    print('ANALYZE_RESULT_SUMMARY')
    summary = {
        'file': result.get('file'),
        'packet_count': result.get('packet_count'),
        'flow_count': result.get('flow_count'),
        'tor_indicators_found': result.get('tor_indicators_found')
    }
    print(json.dumps(summary, indent=2))

    flows = result.get('flows', {}) if isinstance(result, dict) else {}
    if flows:
        svg_path = build_svg_from_flows(flows, outpath=os.path.join(os.getcwd(), 'pcap_analysis.svg'))
        print('SVG_SAVED', svg_path)
    else:
        print('NO_FLOWS_TO_VISUALIZE')

    # Save full analysis JSON
    outjson = os.path.join(os.getcwd(), 'pcap_analysis.json')
    with open(outjson, 'w', encoding='utf8') as f:
        json.dump(result, f, default=str, indent=2)
    print('ANALYZE_END', outjson)

if __name__ == '__main__':
    # find latest pcap in pcap_storage
    pcap_dir = os.path.join(os.getcwd(), 'pcap_storage')
    files = []
    try:
        files = [os.path.join(pcap_dir, f) for f in os.listdir(pcap_dir) if f.lower().endswith('.pcap') or f.lower().endswith('.pcapng')]
        files = sorted(files, key=lambda p: os.path.getmtime(p), reverse=True)
    except Exception as e:
        print('PCAP_DIR_ERROR', e)
    if not files:
        print('NO_PCAP_FOUND')
        sys.exit(1)
    latest = files[0]
    analyze(latest)
