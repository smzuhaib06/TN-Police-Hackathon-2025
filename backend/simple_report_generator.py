"""
Simple Working Report Generator
"""

import os
import time
from datetime import datetime

def generate_simple_report(circuits=None, sniffer_stats=None, pcap_analysis=None):
    """Generate a simple working report"""
    
    # Create reports directory
    reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate report ID and timestamp
    timestamp = int(time.time())
    report_id = f"TOR-{timestamp}"
    
    # Prepare data with defaults
    circuits = circuits or []
    stats = sniffer_stats or {'total_packets': 0, 'tor_packets': 0, 'protocol_counts': {}}
    analysis = pcap_analysis or {'packet_count': 0, 'flow_count': 0}
    
    # Generate HTML content
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TOR Unveil Report - {report_id}</title>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Times New Roman', serif; 
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); 
            color: #222; 
            line-height: 1.8;
        }}
        .container {{ 
            max-width: 1200px; 
            margin: 30px auto; 
            background: white; 
            border-radius: 12px; 
            box-shadow: 0 8px 32px rgba(0,0,0,0.1); 
            padding: 48px;
        }}
        .header {{
            border-bottom: 4px solid #2a3a5e;
            margin-bottom: 32px;
            padding-bottom: 24px;
            text-align: center;
        }}
        h1 {{ 
            color: #2a3a5e; 
            font-size: 2.5em; 
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        .section {{ 
            margin-bottom: 32px; 
        }}
        .section-title {{ 
            color: #2a3a5e; 
            font-size: 1.6em;
            border-bottom: 3px solid #1aaf5d;
            padding-bottom: 12px;
            margin-bottom: 16px;
        }}
        table {{ 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 24px;
        }}
        th {{ 
            background: linear-gradient(135deg, #2a3a5e 0%, #3d5a80 100%); 
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: bold;
        }}
        td {{ 
            border: 1px solid #ddd; 
            padding: 10px;
            background: #fafafa;
        }}
        .summary-box {{
            background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 24px;
            border-left: 5px solid #1aaf5d;
        }}
        .btn {{ 
            background: #2a3a5e; 
            color: white; 
            border: none; 
            padding: 10px 20px; 
            border-radius: 6px; 
            cursor: pointer; 
            margin: 8px 8px 8px 0;
        }}
        .btn:hover {{ background: #1aaf5d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>TOR UNVEIL</h1>
            <div class="subtitle">Forensic Analysis & Correlation Report</div>
            <p><strong>Report ID:</strong> {report_id}</p>
            <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        
        <div class="section">
            <div class="section-title">Executive Summary</div>
            <div class="summary-box">
                <p><strong>Analysis Complete:</strong> Successfully analyzed network traffic and TOR circuits.</p>
                <p><strong>Total Packets:</strong> {stats.get('total_packets', 0):,}</p>
                <p><strong>TOR Packets:</strong> {stats.get('tor_packets', 0):,}</p>
                <p><strong>Active Circuits:</strong> {len(circuits)}</p>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">Network Statistics</div>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Total Packets Captured</td><td>{stats.get('total_packets', 0):,}</td></tr>
                <tr><td>TOR Traffic Detected</td><td>{stats.get('tor_packets', 0):,}</td></tr>
                <tr><td>Network Flows</td><td>{analysis.get('flow_count', 0):,}</td></tr>
                <tr><td>Analysis Timestamp</td><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <div class="section-title">Circuit Analysis</div>
            <table>
                <tr><th>Circuit ID</th><th>Status</th><th>Path Length</th><th>Purpose</th></tr>
                {"".join(f'<tr><td>{c.get("id", "N/A")}</td><td>{c.get("status", "UNKNOWN")}</td><td>{len(c.get("path", []))}</td><td>{c.get("purpose", "GENERAL")}</td></tr>' for c in circuits[:10])}
            </table>
            {f"<p>Showing {min(len(circuits), 10)} of {len(circuits)} circuits.</p>" if circuits else "<p>No active circuits detected.</p>"}
        </div>
        
        <div class="section">
            <div class="section-title">Protocol Distribution</div>
            <table>
                <tr><th>Protocol</th><th>Packet Count</th></tr>
                {"".join(f'<tr><td>{proto}</td><td>{count:,}</td></tr>' for proto, count in stats.get('protocol_counts', {}).items())}
            </table>
        </div>
        
        <div style="text-align: center; margin-top: 40px;">
            <button class="btn" onclick="window.print()">🖨️ Print Report</button>
            <button class="btn" onclick="window.close()">✕ Close</button>
        </div>
        
        <div style="margin-top: 50px; border-top: 1px solid #ccc; padding-top: 20px; text-align: center; font-size: 12px; color: #666;">
            <p><strong>TOR Unveil Forensic Analysis System v2.1</strong></p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Report ID: {report_id}</p>
        </div>
    </div>
</body>
</html>"""
    
    # Write HTML file
    html_filename = f"{report_id}.html"
    html_path = os.path.join(reports_dir, html_filename)
    
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return {
        'report_id': report_id,
        'reports': {
            'html': html_path
        },
        'summary': f'Generated report with {stats.get("total_packets", 0)} packets analyzed'
    }