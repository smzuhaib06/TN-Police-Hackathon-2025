import requests, os, json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape

base = 'http://localhost:5000'


def fetch_data():
    try:
        corr = requests.post(base + '/api/ml/correlate', json={'mode': 'live'}, timeout=30).json()
    except Exception:
        corr = {'status': 'error', 'message': 'Correlation fetch failed', 'correlation': {}}
    try:
        pk = requests.get(base + '/api/sniffer/packets?limit=500', timeout=30).json()
    except Exception:
        pk = {'status': 'error', 'message': 'Packets fetch failed', 'packets': []}
    try:
        tor = requests.get(base + '/api/tor/statistics', timeout=30).json()
    except Exception:
        tor = {'status': 'error', 'statistics': {}}
    return corr, pk, tor


def build_html_report(corr, pk, tor_stats):
    # Use server-side template for the same look as report preview
    env = Environment(
        loader=FileSystemLoader(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'templates'))),
        autoescape=select_autoescape(['html', 'xml'])
    )

    template = env.get_template('forensic_report.html')

    # Prepare context
    packets = pk.get('packets', []) if isinstance(pk, dict) else []
    corr_summary = corr.get('correlation', {}) if isinstance(corr, dict) else {}
    pairs = corr_summary.get('entry_exit_pairs', []) if corr_summary else []

    # Map pairs into template-friendly correlations
    correlations = []
    for p in pairs:
        correlations.append({
            'entry': p.get('entry_ip'),
            'exit': p.get('exit_ip'),
            'confidence': float(p.get('confidence', 0))
        })

    # Simple relays list from tor_stats if available — do NOT inject placeholder relays
    relays = []
    try:
        stats = tor_stats.get('statistics', {}) if isinstance(tor_stats, dict) else {}
        # Only use relays if authoritative data is present
        if isinstance(stats.get('relays'), list) and len(stats.get('relays')) > 0:
            relays = stats.get('relays')
    except Exception:
        relays = []

    # Basic circuits placeholder and bandwidth/latency arrays
    circuits = []
    bandwidths = []
    latencies = []
    # Aggregate some simple stats from packets
    if packets:
        # group bytes per source
        bytes_by_src = {}
        for pkt in packets:
            src = pkt.get('src_ip') or 'unknown'
            bytes_by_src[src] = bytes_by_src.get(src, 0) + (pkt.get('size') or 0)
        bandwidths = list(bytes_by_src.values())[:20]
        latencies = [max(1, ((pkt.get('ttl') or 64) % 100)) for pkt in packets[:20]]

    context = {
        'summary': 'TOR Network Investigation Report',
        'details': 'Forensic Analysis of Suspicious Network Activity',
        'alerts': [],
        'correlated': correlations,
        'circuits': circuits,
        'relays': relays,
        'correlations': correlations,
        'bandwidth_latency': {'bandwidths': bandwidths, 'latencies': latencies},
        'timeline_data': [],
        'relay_points': []
    }

    return template.render(**context)

if __name__ == '__main__':
    corr, pk, tor = fetch_data()
    report_html = build_html_report(corr, pk, tor)
    # Determine reports dir relative to this script
    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'reports'))
    os.makedirs(reports_dir, exist_ok=True)
    path = os.path.join(reports_dir, 'quick-correlation-report.html')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(report_html)
    print('SAVED_HTML', path)

    # Create PDF from generated HTML using best available tool
    pdf_path = os.path.join(reports_dir, 'quick-correlation-report.pdf')
    created = False

    # 1) Try pdfkit (wkhtmltopdf wrapper)
    try:
        import pdfkit
        try:
            pdfkit.from_file(path, pdf_path)
            if os.path.exists(pdf_path):
                print('SAVED_PDF', pdf_path)
                created = True
        except Exception:
            created = False
    except Exception:
        created = False

    # 2) Try WeasyPrint
    if not created:
        try:
            from weasyprint import HTML
            HTML(filename=path).write_pdf(pdf_path)
            if os.path.exists(pdf_path):
                print('SAVED_PDF', pdf_path)
                created = True
        except Exception:
            created = False

    # 3) Try wkhtmltopdf CLI directly
    if not created:
        try:
            rc = os.system(f'"wkhtmltopdf" "{path}" "{pdf_path}"')
            if rc == 0 and os.path.exists(pdf_path):
                print('SAVED_PDF', pdf_path)
                created = True
        except Exception:
            created = False

    if not created:
        print('PDF_NOT_CREATED', 'Install wkhtmltopdf, pdfkit or weasyprint for PDF generation')
