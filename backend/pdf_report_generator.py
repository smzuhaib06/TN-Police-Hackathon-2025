#!/usr/bin/env python3
"""
TOR Unveil - PDF Report Generator
Comprehensive correlation reports with risk assessment
"""

import json
import os
from datetime import datetime
from pathlib import Path

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("[WARNING] reportlab not available, PDF generation disabled")


class PDFReportGenerator:
    """Generate comprehensive PDF reports for correlation analysis"""
    
    def __init__(self):
        self.report_dir = Path(__file__).parent.parent / 'reports'
        self.report_dir.mkdir(exist_ok=True)
        
    def generate_report(self, correlation_data, output_filename=None):
        """Generate PDF report from correlation data"""
        if not REPORTLAB_AVAILABLE:
            return {
                'status': 'error',
                'message': 'reportlab not installed. Run: pip install reportlab'
            }
        
        try:
            # Generate filename
            if not output_filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_filename = f"correlation_report_{timestamp}.pdf"
            
            output_path = self.report_dir / output_filename
            
            # Create PDF document
            doc = SimpleDocTemplate(
                str(output_path),
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build story (content)
            story = []
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#00d4ff'),
                spaceAfter=30,
                alignment=TA_CENTER
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#ff6b6b'),
                spaceAfter=12,
                spaceBefore=12
            )
            
            # Title Page
            story.append(Spacer(1, 2*inch))
            story.append(Paragraph("TOR UNVEIL", title_style))
            story.append(Paragraph("Correlation Analysis Report", styles['Heading2']))
            story.append(Spacer(1, 0.5*inch))
            story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph("⚠️ CONFIDENTIAL - LAW ENFORCEMENT USE ONLY", styles['Normal']))
            story.append(PageBreak())
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", heading_style))
            story.append(Spacer(1, 12))
            
            overall_confidence = correlation_data.get('overall_confidence', 0)
            strength = correlation_data.get('correlation_strength', 'UNKNOWN')
            deanon_success = correlation_data.get('deanonymization_success', False)
            
            summary_data = [
                ["Overall Confidence:", f"{overall_confidence*100:.1f}%"],
                ["Correlation Strength:", strength],
                ["Deanonymization:", "SUCCESSFUL" if deanon_success else "UNSUCCESSFUL"],
                ["Analysis Mode:", correlation_data.get('mode', 'unknown').upper()],
                ["Timestamp:", correlation_data.get('timestamp', 'N/A')]
            ]
            
            summary_table = Table(summary_data, colWidths=[2.5*inch, 3*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1e293b')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 12),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#00d4ff'))
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 20))
            
            # Risk Assessment
            story.append(Paragraph("Risk Assessment", heading_style))
            risk_level = self._calculate_risk_level(overall_confidence)
            risk_color = colors.green if risk_level == "LOW" else colors.orange if risk_level == "MEDIUM" else colors.red
            
            risk_para = Paragraph(
                f"<font color='{risk_color.hexval()}' size='14'><b>RISK LEVEL: {risk_level}</b></font>",
                styles['Normal']
            )
            story.append(risk_para)
            story.append(Spacer(1, 20))
            
            # Algorithm Results
            story.append(Paragraph("Correlation Analysis Results", heading_style))
            story.append(Spacer(1, 12))
            
            # Timing Correlation
            timing_data = correlation_data.get('timing_correlation', {})
            story.append(Paragraph("<b>1. Timing Correlation Analysis</b>", styles['Normal']))
            timing_info = [
                ["Confidence:", f"{timing_data.get('confidence', 0)*100:.1f}%"],
                ["Correlation Coefficient:", f"{timing_data.get('correlation', 0):.3f}"],
                ["Average Delay:", f"{timing_data.get('delay', 0):.2f}s"],
                ["Entry Packets:", str(timing_data.get('entry_packets', 0))],
                ["Exit Packets:", str(timing_data.get('exit_packets', 0))]
            ]
            timing_table = Table(timing_info, colWidths=[2*inch, 3.5*inch])
            timing_table.setStyle(self._get_table_style())
            story.append(timing_table)
            story.append(Spacer(1, 15))
            
            # Traffic Analysis
            traffic_data = correlation_data.get('traffic_analysis', {})
            story.append(Paragraph("<b>2. Traffic Analysis</b>", styles['Normal']))
            traffic_info = [
                ["Confidence:", f"{traffic_data.get('avg_confidence', 0)*100:.1f}%"],
                ["Total Flows:", str(traffic_data.get('total_flows', 0))],
                ["Analyzed Flows:", str(len(traffic_data.get('flows', [])))]
            ]
            traffic_table = Table(traffic_info, colWidths=[2*inch, 3.5*inch])
            traffic_table.setStyle(self._get_table_style())
            story.append(traffic_table)
            story.append(Spacer(1, 15))
            
            # Website Fingerprinting
            fingerprint_data = correlation_data.get('website_fingerprinting', {})
            story.append(Paragraph("<b>3. Website Fingerprinting</b>", styles['Normal']))
            websites = fingerprint_data.get('websites', [])
            if websites:
                website_info = [["Website", "Confidence", "Method"]]
                for site in websites[:5]:  # Top 5
                    website_info.append([
                        site.get('website', 'unknown'),
                        f"{site.get('confidence', 0)*100:.1f}%",
                        site.get('method', 'unknown')
                    ])
                website_table = Table(website_info, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
                website_table.setStyle(self._get_table_style_with_header())
                story.append(website_table)
            else:
                story.append(Paragraph("No websites identified", styles['Normal']))
            story.append(Spacer(1, 15))
            
            # Geo-Location Data
            if 'user_location' in correlation_data and correlation_data['user_location']:
                story.append(PageBreak())
                story.append(Paragraph("Geo-Location Analysis", heading_style))
                story.append(Spacer(1, 12))
                
                user_loc = correlation_data['user_location']
                est_loc = user_loc.get('estimated_location', {})
                
                geo_info = [
                    ["Estimated City:", est_loc.get('city', 'Unknown')],
                    ["Country:", est_loc.get('country', 'Unknown')],
                    ["Latitude:", f"{est_loc.get('latitude', 0):.4f}"],
                    ["Longitude:", f"{est_loc.get('longitude', 0):.4f}"],
                    ["Confidence:", f"{user_loc.get('confidence', 0)*100:.1f}%"],
                    ["Method:", user_loc.get('method', 'unknown')]
                ]
                geo_table = Table(geo_info, colWidths=[2*inch, 3.5*inch])
                geo_table.setStyle(self._get_table_style())
                story.append(geo_table)
            
            # Recommendations
            story.append(PageBreak())
            story.append(Paragraph("Recommendations", heading_style))
            story.append(Spacer(1, 12))
            
            recommendations = self._generate_recommendations(correlation_data)
            for i, rec in enumerate(recommendations, 1):
                story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
                story.append(Spacer(1, 8))
            
            # Legal Disclaimer
            story.append(PageBreak())
            story.append(Paragraph("Legal Disclaimer", heading_style))
            disclaimer_text = """
            This report contains analysis of TOR network traffic for law enforcement and 
            authorized research purposes only. The techniques described and data collected 
            must comply with all applicable laws and regulations. Unauthorized monitoring 
            or deanonymization of network traffic may violate computer fraud, privacy, 
            and telecommunications laws. This report is confidential and should be handled 
            according to your organization's information security policies.
            
            The correlation analysis provides probabilistic estimates and should not be 
            considered definitive proof of user identity or location. All findings should 
            be corroborated with additional evidence and verified through established 
            legal procedures before being used in any legal proceedings.
            """
            story.append(Paragraph(disclaimer_text, styles['Normal']))
            
            # Build PDF
            doc.build(story)
            
            return {
                'status': 'success',
                'file_path': str(output_path),
                'filename': output_filename,
                'message': f'Report generated successfully'
            }
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def _get_table_style(self):
        """Standard table style"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#334155'))
        ])
    
    def _get_table_style_with_header(self):
        """Table style with header row"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#334155'))
        ])
    
    def _calculate_risk_level(self, confidence):
        """Calculate risk level based on confidence"""
        if confidence > 0.7:
            return "HIGH"
        elif confidence > 0.4:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommendations(self, correlation_data):
        """Generate actionable recommendations"""
        recommendations = []
        confidence = correlation_data.get('overall_confidence', 0)
        
        if confidence > 0.7:
            recommendations.append(
                "HIGH CONFIDENCE: Strong correlation detected. Consider initiating formal investigation "
                "with legal authorization. Corroborate findings with additional surveillance methods."
            )
        elif confidence > 0.4:
            recommendations.append(
                "MEDIUM CONFIDENCE: Moderate correlation detected. Recommend extended monitoring period "
                "to increase confidence. Consider combining with other intelligence sources."
            )
        else:
            recommendations.append(
                "LOW CONFIDENCE: Weak correlation detected. Insufficient data for actionable intelligence. "
                "Recommend longer capture period or alternative investigation methods."
            )
        
        if correlation_data.get('timing_correlation', {}).get('confidence', 0) > 0.6:
            recommendations.append(
                "Strong timing correlation suggests entry-exit node relationship. Focus on temporal "
                "traffic analysis and packet timing fingerprints."
            )
        
        if correlation_data.get('website_fingerprinting', {}).get('avg_confidence', 0) > 0.5:
            recommendations.append(
                "Website fingerprinting shows promising results. Target user's browsing patterns "
                "match known website signatures. Cross-reference with web server logs if available."
            )
        
        if correlation_data.get('user_location'):
            recommendations.append(
                "User location estimated from entry node analysis. Verify with ISP records and "
                "physical surveillance if legally authorized."
            )
        
        recommendations.append(
            "Maintain audit trail of all analysis activities. Document chain of custody for any "
            "evidence collected. Ensure compliance with applicable privacy and surveillance laws."
        )
        
        return recommendations


# Global instance
pdf_generator = PDFReportGenerator()

def generate_pdf_report(correlation_data, filename=None):
    """Generate PDF report from correlation data"""
    return pdf_generator.generate_report(correlation_data, filename)


if __name__ == "__main__":
    # Test report generation
    test_data = {
        'timestamp': datetime.now().isoformat(),
        'overall_confidence': 0.75,
        'correlation_strength': 'HIGH',
        'deanonymization_success': True,
        'mode': 'live_capture',
        'timing_correlation': {
            'confidence': 0.82,
            'correlation': 0.91,
            'delay': 0.45,
            'entry_packets': 1245,
            'exit_packets': 1189
        },
        'traffic_analysis': {
            'avg_confidence': 0.68,
            'total_flows': 47,
            'flows': []
        },
        'website_fingerprinting': {
            'avg_confidence': 0.71,
            'websites': [
                {'website': 'google.com', 'confidence': 0.89, 'method': 'ml_random_forest'},
                {'website': 'facebook.com', 'confidence': 0.65, 'method': 'ml_random_forest'}
            ]
        },
        'user_location': {
            'estimated_location': {
                'city': 'Chennai',
                'country': 'India',
                'latitude': 13.0827,
                'longitude': 80.2707
            },
            'confidence': 0.68,
            'method': 'entry_node_correlation'
        }
    }
    
    result = generate_pdf_report(test_data)
    print(json.dumps(result, indent=2))
