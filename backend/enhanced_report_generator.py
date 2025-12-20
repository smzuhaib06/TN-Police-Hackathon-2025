"""
Enhanced Report Generator for TOR Unveil
Generates comprehensive forensic reports with visualizations
"""

import os
import json
import uuid
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import base64

class EnhancedReportGenerator:
    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
        os.makedirs(self.reports_dir, exist_ok=True)
        
        self.env = Environment(loader=FileSystemLoader(self.template_dir))
    
    def generate_comprehensive_report(self, data):
        """Generate comprehensive forensic report"""
        report_id = f"TOR-{int(datetime.now().timestamp())}-{str(uuid.uuid4())[:8]}"
        
        report_data = {
            'report_id': report_id,
            'generated_at': datetime.now().isoformat(),
            'analyst': 'TOR Unveil System',
            'case_number': f"CASE-{report_id}",
            'summary': self._generate_executive_summary(data),
            'circuits': data.get('circuits', []),
            'pcap_analysis': data.get('pcap_analysis', {}),
            'sniffer_stats': data.get('sniffer_stats', {}),
            'correlations': data.get('correlations', []),
            'tor_indicators': self._extract_tor_indicators(data),
            'network_topology': self._analyze_network_topology(data),
            'timeline': self._create_timeline(data),
            'recommendations': self._generate_recommendations(data)
        }
        
        # Generate different report formats
        reports = {}
        
        # HTML Report
        html_report = self._generate_html_report(report_data)
        html_path = os.path.join(self.reports_dir, f"{report_id}.html")
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_report)
        reports['html'] = html_path
        
        # JSON Report
        json_path = os.path.join(self.reports_dir, f"{report_id}.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        reports['json'] = json_path
        
        # Executive Summary
        exec_summary = self._generate_executive_summary_doc(report_data)
        exec_path = os.path.join(self.reports_dir, f"{report_id}_executive.html")
        with open(exec_path, 'w', encoding='utf-8') as f:
            f.write(exec_summary)
        reports['executive'] = exec_path
        
        return {
            'report_id': report_id,
            'reports': reports,
            'summary': report_data['summary']
        }
    
    def _generate_executive_summary(self, data):
        """Generate executive summary"""
        circuits = data.get('circuits', [])
        pcap = data.get('pcap_analysis', {})
        sniffer = data.get('sniffer_stats', {})
        
        return {
            'total_circuits': len(circuits),
            'active_relays': len(set(hop['fingerprint'] for c in circuits for hop in c.get('path', []))),
            'packets_analyzed': pcap.get('total_packets', 0) + sniffer.get('total_packets', 0),
            'tor_traffic_detected': pcap.get('tor_packets', 0) + sniffer.get('tor_packets', 0),
            'confidence_level': self._calculate_confidence(data),
            'risk_assessment': self._assess_risk(data)
        }
    
    def _extract_tor_indicators(self, data):
        """Extract TOR indicators from analysis"""
        indicators = []
        
        # From PCAP analysis
        pcap = data.get('pcap_analysis', {})
        if 'tor_circuits' in pcap:
            for circuit in pcap['tor_circuits']:
                indicators.append({
                    'type': 'circuit_detected',
                    'timestamp': circuit.get('timestamp'),
                    'confidence': circuit.get('confidence', 0),
                    'details': f"Guard: {circuit.get('guard_relays', [])}, Exit: {circuit.get('exit_relays', [])}"
                })
        
        # From live circuits
        circuits = data.get('circuits', [])
        for circuit in circuits:
            if circuit.get('status') == 'BUILT':
                indicators.append({
                    'type': 'active_circuit',
                    'timestamp': datetime.now().isoformat(),
                    'confidence': 1.0,
                    'details': f"Circuit {circuit['id']}: {len(circuit.get('path', []))} hops"
                })
        
        return indicators
    
    def _analyze_network_topology(self, data):
        """Analyze network topology"""
        topology = {
            'nodes': [],
            'edges': [],
            'clusters': []
        }
        
        # Add relay nodes from circuits
        circuits = data.get('circuits', [])
        relay_map = {}
        
        for circuit in circuits:
            for i, hop in enumerate(circuit.get('path', [])):
                fp = hop['fingerprint']
                if fp not in relay_map:
                    relay_map[fp] = {
                        'id': fp[:16],
                        'nickname': hop.get('nickname', 'Unknown'),
                        'type': 'guard' if i == 0 else 'exit' if i == len(circuit['path'])-1 else 'middle',
                        'circuits': []
                    }
                relay_map[fp]['circuits'].append(circuit['id'])
        
        topology['nodes'] = list(relay_map.values())
        
        # Add edges between consecutive hops
        for circuit in circuits:
            path = circuit.get('path', [])
            for i in range(len(path) - 1):
                topology['edges'].append({
                    'source': path[i]['fingerprint'][:16],
                    'target': path[i+1]['fingerprint'][:16],
                    'circuit': circuit['id']
                })
        
        return topology
    
    def _create_timeline(self, data):
        """Create timeline of events"""
        events = []
        
        # Circuit events
        circuits = data.get('circuits', [])
        for circuit in circuits:
            events.append({
                'timestamp': circuit.get('created_at', datetime.now().timestamp()),
                'type': 'circuit_created',
                'description': f"Circuit {circuit['id']} created with {len(circuit.get('path', []))} hops",
                'severity': 'info'
            })
        
        # PCAP events
        pcap = data.get('pcap_analysis', {})
        if 'tor_circuits' in pcap:
            for circuit in pcap['tor_circuits']:
                events.append({
                    'timestamp': circuit.get('timestamp'),
                    'type': 'tor_traffic_detected',
                    'description': f"TOR circuit detected (confidence: {circuit.get('confidence', 0):.2f})",
                    'severity': 'warning' if circuit.get('confidence', 0) > 0.7 else 'info'
                })
        
        # Sort by timestamp
        events.sort(key=lambda x: x['timestamp'])
        return events
    
    def _generate_recommendations(self, data):
        """Generate investigation recommendations"""
        recommendations = []
        
        circuits = data.get('circuits', [])
        pcap = data.get('pcap_analysis', {})
        
        if len(circuits) > 0:
            recommendations.append({
                'priority': 'high',
                'category': 'circuit_analysis',
                'title': 'Monitor Active Circuits',
                'description': f'Found {len(circuits)} active TOR circuits. Monitor for suspicious activity patterns.',
                'actions': [
                    'Log all circuit creation/destruction events',
                    'Monitor bandwidth usage patterns',
                    'Correlate with known threat indicators'
                ]
            })
        
        if pcap.get('tor_packets', 0) > 0:
            recommendations.append({
                'priority': 'medium',
                'category': 'traffic_analysis',
                'title': 'Analyze TOR Traffic Patterns',
                'description': f'Detected {pcap.get("tor_packets", 0)} TOR-related packets in network traffic.',
                'actions': [
                    'Perform deep packet inspection on encrypted flows',
                    'Correlate timing patterns with circuit events',
                    'Identify potential data exfiltration'
                ]
            })
        
        if pcap.get('tor_relays_contacted', 0) > 10:
            recommendations.append({
                'priority': 'high',
                'category': 'relay_analysis',
                'title': 'Investigate Relay Connections',
                'description': f'System contacted {pcap.get("tor_relays_contacted", 0)} different TOR relays.',
                'actions': [
                    'Check relay reputation and flags',
                    'Monitor for malicious exit nodes',
                    'Implement relay blocking if necessary'
                ]
            })
        
        return recommendations
    
    def _calculate_confidence(self, data):
        """Calculate overall confidence level"""
        confidence_factors = []
        
        # Circuit data confidence
        circuits = data.get('circuits', [])
        if circuits:
            confidence_factors.append(0.8)  # High confidence for live circuits
        
        # PCAP analysis confidence
        pcap = data.get('pcap_analysis', {})
        if pcap.get('tor_packets', 0) > 0:
            tor_percentage = pcap.get('tor_percentage', 0)
            confidence_factors.append(min(tor_percentage / 100, 0.9))
        
        # Sniffer data confidence
        sniffer = data.get('sniffer_stats', {})
        if sniffer.get('tor_packets', 0) > 0:
            confidence_factors.append(0.7)
        
        return sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.0
    
    def _assess_risk(self, data):
        """Assess risk level"""
        risk_score = 0
        
        circuits = data.get('circuits', [])
        pcap = data.get('pcap_analysis', {})
        
        # Active circuits increase risk
        risk_score += len(circuits) * 10
        
        # TOR traffic increases risk
        risk_score += pcap.get('tor_packets', 0) * 0.1
        
        # Multiple relay contacts increase risk
        risk_score += pcap.get('tor_relays_contacted', 0) * 5
        
        if risk_score < 50:
            return 'low'
        elif risk_score < 150:
            return 'medium'
        else:
            return 'high'
    
    def _generate_html_report(self, data):
        """Generate HTML report"""
        template = """
<!DOCTYPE html>
<html>
<head>
    <title>TOR Unveil Forensic Report - {{ report_id }}</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { border-bottom: 3px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; page-break-inside: avoid; }
        .risk-high { color: #dc3545; font-weight: bold; }
        .risk-medium { color: #ffc107; font-weight: bold; }
        .risk-low { color: #28a745; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        .timeline { border-left: 3px solid #007bff; padding-left: 20px; }
        .timeline-item { margin-bottom: 15px; }
        .recommendation { background: #f8f9fa; border-left: 4px solid #007bff; padding: 15px; margin: 10px 0; }
        .priority-high { border-left-color: #dc3545; }
        .priority-medium { border-left-color: #ffc107; }
        .priority-low { border-left-color: #28a745; }
    </style>
</head>
<body>
    <div class="header">
        <h1>TOR UNVEIL - Forensic Analysis Report</h1>
        <p><strong>Report ID:</strong> {{ report_id }}</p>
        <p><strong>Generated:</strong> {{ generated_at }}</p>
        <p><strong>Analyst:</strong> {{ analyst }}</p>
        <p><strong>Case Number:</strong> {{ case_number }}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Circuits Analyzed</td><td>{{ summary.total_circuits }}</td></tr>
            <tr><td>Active Relays Identified</td><td>{{ summary.active_relays }}</td></tr>
            <tr><td>Packets Analyzed</td><td>{{ summary.packets_analyzed }}</td></tr>
            <tr><td>TOR Traffic Detected</td><td>{{ summary.tor_traffic_detected }}</td></tr>
            <tr><td>Confidence Level</td><td>{{ "%.1f%%" | format(summary.confidence_level * 100) }}</td></tr>
            <tr><td>Risk Assessment</td><td><span class="risk-{{ summary.risk_assessment }}">{{ summary.risk_assessment.upper() }}</span></td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>TOR Indicators</h2>
        <table>
            <tr><th>Type</th><th>Timestamp</th><th>Confidence</th><th>Details</th></tr>
            {% for indicator in tor_indicators %}
            <tr>
                <td>{{ indicator.type }}</td>
                <td>{{ indicator.timestamp }}</td>
                <td>{{ "%.2f" | format(indicator.confidence) }}</td>
                <td>{{ indicator.details }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    
    <div class="section">
        <h2>Circuit Analysis</h2>
        <p>Analyzed {{ circuits|length }} active circuits:</p>
        <table>
            <tr><th>Circuit ID</th><th>Status</th><th>Path Length</th><th>Purpose</th></tr>
            {% for circuit in circuits[:20] %}
            <tr>
                <td>{{ circuit.id }}</td>
                <td>{{ circuit.status }}</td>
                <td>{{ circuit.path|length }}</td>
                <td>{{ circuit.purpose }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    
    <div class="section">
        <h2>Network Topology</h2>
        <p><strong>Nodes:</strong> {{ network_topology.nodes|length }}</p>
        <p><strong>Edges:</strong> {{ network_topology.edges|length }}</p>
        <p><strong>Guard Nodes:</strong> {{ network_topology.nodes|selectattr("type", "equalto", "guard")|list|length }}</p>
        <p><strong>Exit Nodes:</strong> {{ network_topology.nodes|selectattr("type", "equalto", "exit")|list|length }}</p>
    </div>
    
    <div class="section">
        <h2>Timeline of Events</h2>
        <div class="timeline">
            {% for event in timeline[:20] %}
            <div class="timeline-item">
                <strong>{{ event.timestamp }}</strong> - {{ event.description }}
                <span class="risk-{{ event.severity }}">[{{ event.severity.upper() }}]</span>
            </div>
            {% endfor %}
        </div>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        {% for rec in recommendations %}
        <div class="recommendation priority-{{ rec.priority }}">
            <h4>{{ rec.title }} <span class="risk-{{ rec.priority }}">[{{ rec.priority.upper() }}]</span></h4>
            <p>{{ rec.description }}</p>
            <ul>
                {% for action in rec.actions %}
                <li>{{ action }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endfor %}
    </div>
    
    <footer style="margin-top: 50px; border-top: 1px solid #ccc; padding-top: 20px; font-size: 12px; color: #666;">
        <p><strong>Generated by:</strong> TOR Unveil v2.0 Enhanced</p>
        <p><strong>Report ID:</strong> {{ report_id }}</p>
        <p><strong>Timestamp:</strong> {{ generated_at }}</p>
    </footer>
</body>
</html>
        """
        
        from jinja2 import Template
        template_obj = Template(template)
        return template_obj.render(**data)
    
    def _generate_executive_summary_doc(self, data):
        """Generate executive summary document"""
        template = """
<!DOCTYPE html>
<html>
<head>
    <title>Executive Summary - {{ report_id }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { text-align: center; margin-bottom: 40px; }
        .summary-box { background: #f8f9fa; border: 1px solid #dee2e6; padding: 20px; margin: 20px 0; }
        .risk-high { color: #dc3545; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }
    </style>
</head>
<body>
    <div class="header">
        <h1>EXECUTIVE SUMMARY</h1>
        <h2>TOR Network Analysis</h2>
        <p>Case: {{ case_number }} | {{ generated_at }}</p>
    </div>
    
    <div class="summary-box">
        <h3>Key Findings</h3>
        <ul>
            <li><strong>{{ summary.total_circuits }}</strong> active TOR circuits identified</li>
            <li><strong>{{ summary.packets_analyzed }}</strong> network packets analyzed</li>
            <li><strong>{{ summary.tor_traffic_detected }}</strong> TOR-related packets detected</li>
            <li>Risk Level: <span class="risk-{{ summary.risk_assessment }}"><strong>{{ summary.risk_assessment.upper() }}</strong></span></li>
        </ul>
    </div>
    
    <div class="summary-box">
        <h3>Immediate Actions Required</h3>
        {% for rec in recommendations[:3] %}
        <p><strong>{{ rec.title }}:</strong> {{ rec.description }}</p>
        {% endfor %}
    </div>
    
    <div class="summary-box">
        <h3>Technical Summary</h3>
        <p>Analysis confidence: {{ "%.1f%%" | format(summary.confidence_level * 100) }}</p>
        <p>Active relay nodes: {{ summary.active_relays }}</p>
        <p>TOR indicators found: {{ tor_indicators|length }}</p>
    </div>
</body>
</html>
        """
        
        from jinja2 import Template
        template_obj = Template(template)
        return template_obj.render(**data)

def generate_report(data):
    """Generate comprehensive report - main entry point"""
    generator = EnhancedReportGenerator()
    return generator.generate_comprehensive_report(data)

if __name__ == "__main__":
    # Test report generation
    test_data = {
        'circuits': [
            {'id': 1, 'status': 'BUILT', 'path': [{'fingerprint': 'ABC123', 'nickname': 'Guard1'}]},
            {'id': 2, 'status': 'BUILT', 'path': [{'fingerprint': 'DEF456', 'nickname': 'Guard2'}]}
        ],
        'pcap_analysis': {
            'total_packets': 1000,
            'tor_packets': 150,
            'tor_percentage': 15.0,
            'tor_relays_contacted': 5
        },
        'sniffer_stats': {
            'total_packets': 500,
            'tor_packets': 75
        }
    }
    
    result = generate_report(test_data)
    print(f"Generated report: {result['report_id']}")
    print(f"Files: {result['reports']}")