/**
 * Dynamic Real-Time Report Generator for TOR Unveil
 * Features:
 * - Real-time data updates
 * - Multiple export formats (HTML, PDF, JSON, CSV)
 * - Live circuit monitoring
 * - Auto-refresh capabilities
 * - Print-friendly formatting
 */

class DynamicReportGenerator {
    constructor() {
        this.apiBase = 'http://localhost:5000/api';
        this.apiKey = 'changeme';
        this.reportData = null;
        this.updateInterval = null;
        this.isRealTime = false;
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.loadInitialData();
    }
    
    setupEventListeners() {
        // Generate report button
        document.getElementById('generateReportBtn')?.addEventListener('click', () => 
            this.generateReport()
        );
        
        // Real-time toggle
        document.getElementById('realtimeToggle')?.addEventListener('change', (e) => 
            this.toggleRealTime(e.target.checked)
        );
        
        // Export buttons
        document.getElementById('exportHTML')?.addEventListener('click', () => 
            this.exportReport('html')
        );
        document.getElementById('exportPDF')?.addEventListener('click', () => 
            this.exportReport('pdf')
        );
        document.getElementById('exportJSON')?.addEventListener('click', () => 
            this.exportReport('json')
        );
        document.getElementById('exportCSV')?.addEventListener('click', () => 
            this.exportReport('csv')
        );
        
        // Print button
        document.getElementById('printReport')?.addEventListener('click', () => 
            this.printReport()
        );
        
        // Refresh button
        document.getElementById('refreshReport')?.addEventListener('click', () => 
            this.refreshReportData()
        );
    }
    
    async loadInitialData() {
        try {
            await this.refreshReportData();
        } catch (error) {
            console.error('Failed to load initial report data:', error);
        }
    }
    
    async refreshReportData() {
        try {
            this.showLoading('Loading report data...');
            
            // Fetch all necessary data
            const [circuits, snifferStats, analysis] = await Promise.all([
                this.fetchCircuits(),
                this.fetchSnifferStats(),
                this.fetchLastAnalysis()
            ]);
            
            this.reportData = {
                circuits: circuits,
                snifferStats: snifferStats,
                analysis: analysis,
                timestamp: new Date().toISOString(),
                reportId: `TOR-${Date.now()}`
            };
            
            this.hideLoading();
            this.renderReport();
            
        } catch (error) {
            this.hideLoading();
            this.showNotification('Failed to refresh report data', 'error');
            console.error('Refresh error:', error);
        }
    }
    
    async fetchCircuits() {
        try {
            const response = await fetch(`${this.apiBase}/circuits`, {
                headers: { 'X-API-KEY': this.apiKey }
            });
            const data = await response.json();
            return data.circuits || [];
        } catch (error) {
            console.error('Failed to fetch circuits:', error);
            return [];
        }
    }
    
    async fetchSnifferStats() {
        try {
            const response = await fetch(`${this.apiBase}/sniffer/statistics`, {
                headers: { 'X-API-KEY': this.apiKey }
            });
            return await response.json();
        } catch (error) {
            console.error('Failed to fetch sniffer stats:', error);
            return {
                total_packets: 0,
                tor_packets: 0,
                protocol_counts: {}
            };
        }
    }
    
    async fetchLastAnalysis() {
        try {
            const response = await fetch(`${this.apiBase}/analysis/last`, {
                headers: { 'X-API-KEY': this.apiKey }
            });
            const data = await response.json();
            return data.pcap_analysis || {};
        } catch (error) {
            console.error('Failed to fetch last analysis:', error);
            return {};
        }
    }
    
    renderReport() {
        if (!this.reportData) return;
        
        const reportContainer = document.getElementById('reportContent');
        if (!reportContainer) return;
        
        const html = this.generateReportHTML(this.reportData);
        reportContainer.innerHTML = html;
        
        // Update statistics in sidebar
        this.updateStats();
    }
    
    generateReportHTML(data) {
        const circuits = data.circuits || [];
        const stats = data.snifferStats || {};
        const analysis = data.analysis || {};
        
        return `
            <div class="report-container">
                <div class="report-header">
                    <h1 class="text-3xl font-bold text-cyber-blue mb-4">TOR UNVEIL - Forensic Analysis Report</h1>
                    <div class="grid grid-cols-2 gap-4 mb-6">
                        <div>
                            <p class="text-gray-400">Report ID:</p>
                            <p class="font-mono text-white">${data.reportId}</p>
                        </div>
                        <div>
                            <p class="text-gray-400">Generated:</p>
                            <p class="font-mono text-white">${new Date(data.timestamp).toLocaleString()}</p>
                        </div>
                    </div>
                </div>
                
                <div class="report-section">
                    <h2 class="text-2xl font-bold text-matrix-green mb-4">Executive Summary</h2>
                    <div class="grid grid-cols-3 gap-4">
                        <div class="stat-card">
                            <div class="stat-label">Active Circuits</div>
                            <div class="stat-value">${circuits.length}</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-label">Packets Captured</div>
                            <div class="stat-value">${(stats.total_packets || 0).toLocaleString()}</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-label">TOR Packets</div>
                            <div class="stat-value">${(stats.tor_packets || 0).toLocaleString()}</div>
                        </div>
                    </div>
                </div>
                
                <div class="report-section">
                    <h2 class="text-2xl font-bold text-matrix-green mb-4">Circuit Analysis</h2>
                    <div class="overflow-x-auto">
                        <table class="report-table w-full">
                            <thead>
                                <tr>
                                    <th>Circuit ID</th>
                                    <th>Status</th>
                                    <th>Path Length</th>
                                    <th>Entry Node</th>
                                    <th>Exit Node</th>
                                    <th>Purpose</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${circuits.slice(0, 20).map(circuit => `
                                    <tr>
                                        <td>${circuit.id}</td>
                                        <td><span class="status-badge status-${circuit.status.toLowerCase()}">${circuit.status}</span></td>
                                        <td>${circuit.path ? circuit.path.length : 0} hops</td>
                                        <td>${circuit.path && circuit.path[0] ? circuit.path[0].nickname : 'N/A'}</td>
                                        <td>${circuit.path && circuit.path[circuit.path.length - 1] ? circuit.path[circuit.path.length - 1].nickname : 'N/A'}</td>
                                        <td>${circuit.purpose || 'GENERAL'}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="report-section">
                    <h2 class="text-2xl font-bold text-matrix-green mb-4">Network Statistics</h2>
                    <div class="grid grid-cols-2 gap-6">
                        <div>
                            <h3 class="text-lg font-bold mb-3">Protocol Distribution</h3>
                            <div class="protocol-list">
                                ${Object.entries(stats.protocol_counts || {}).map(([protocol, count]) => `
                                    <div class="protocol-item">
                                        <span class="protocol-name">${protocol}</span>
                                        <span class="protocol-count">${count.toLocaleString()}</span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                        <div>
                            <h3 class="text-lg font-bold mb-3">TOR Analysis</h3>
                            <div class="analysis-metrics">
                                <div class="metric">
                                    <span class="metric-label">TOR Percentage:</span>
                                    <span class="metric-value">${this.calculateTorPercentage(stats)}%</span>
                                </div>
                                <div class="metric">
                                    <span class="metric-label">Unique Flows:</span>
                                    <span class="metric-value">${analysis.flow_count || 0}</span>
                                </div>
                                <div class="metric">
                                    <span class="metric-label">TOR Indicators:</span>
                                    <span class="metric-value">${analysis.tor_indicators_found || 0}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="report-section">
                    <h2 class="text-2xl font-bold text-matrix-green mb-4">Circuit Topology</h2>
                    <div class="circuit-topology">
                        ${this.renderCircuitTopology(circuits)}
                    </div>
                </div>
                
                <div class="report-section">
                    <h2 class="text-2xl font-bold text-matrix-green mb-4">Recommendations</h2>
                    <div class="recommendations-list">
                        ${this.generateRecommendations(data).map(rec => `
                            <div class="recommendation-item priority-${rec.priority}">
                                <h4 class="recommendation-title">${rec.title}</h4>
                                <p class="recommendation-desc">${rec.description}</p>
                            </div>
                        `).join('')}
                    </div>
                </div>
                
                <div class="report-footer">
                    <p class="text-sm text-gray-400">
                        Generated by TOR Unveil v2.0 | 
                        Last Updated: ${new Date(data.timestamp).toLocaleString()} |
                        ${this.isRealTime ? '<span class="text-matrix-green">● LIVE</span>' : ''}
                    </p>
                </div>
            </div>
        `;
    }
    
    renderCircuitTopology(circuits) {
        if (circuits.length === 0) {
            return '<p class="text-gray-400">No active circuits to display</p>';
        }
        
        return circuits.slice(0, 5).map(circuit => {
            const path = circuit.path || [];
            return `
                <div class="circuit-path">
                    <div class="circuit-id">Circuit ${circuit.id}</div>
                    <div class="path-nodes">
                        ${path.map((hop, index) => `
                            <div class="path-node">
                                <div class="node-type">${this.getNodeType(index, path.length)}</div>
                                <div class="node-nickname">${hop.nickname || 'Unknown'}</div>
                                <div class="node-fingerprint">${hop.fingerprint ? hop.fingerprint.substring(0, 16) + '...' : 'N/A'}</div>
                            </div>
                            ${index < path.length - 1 ? '<div class="path-arrow">→</div>' : ''}
                        `).join('')}
                    </div>
                </div>
            `;
        }).join('');
    }
    
    getNodeType(index, pathLength) {
        if (index === 0) return 'Guard';
        if (index === pathLength - 1) return 'Exit';
        return 'Middle';
    }
    
    calculateTorPercentage(stats) {
        const total = stats.total_packets || 0;
        const tor = stats.tor_packets || 0;
        if (total === 0) return '0.00';
        return ((tor / total) * 100).toFixed(2);
    }
    
    generateRecommendations(data) {
        const recommendations = [];
        const circuits = data.circuits || [];
        const stats = data.snifferStats || {};
        
        if (circuits.length > 5) {
            recommendations.push({
                priority: 'high',
                title: 'Multiple Active Circuits Detected',
                description: `Found ${circuits.length} active TOR circuits. Monitor for suspicious activity patterns and unusual traffic volumes.`
            });
        }
        
        if (stats.tor_packets > 1000) {
            recommendations.push({
                priority: 'medium',
                title: 'Significant TOR Traffic Volume',
                description: `Detected ${stats.tor_packets} TOR packets. Analyze timing patterns and correlate with known threat indicators.`
            });
        }
        
        recommendations.push({
            priority: 'medium',
            title: 'Continue Monitoring',
            description: 'Maintain continuous packet capture and circuit monitoring for comprehensive analysis.'
        });
        
        return recommendations;
    }
    
    toggleRealTime(enabled) {
        this.isRealTime = enabled;
        
        if (enabled) {
            // Start auto-refresh every 5 seconds
            this.updateInterval = setInterval(() => {
                this.refreshReportData();
            }, 5000);
            this.showNotification('Real-time updates enabled', 'success');
        } else {
            // Stop auto-refresh
            if (this.updateInterval) {
                clearInterval(this.updateInterval);
                this.updateInterval = null;
            }
            this.showNotification('Real-time updates disabled', 'info');
        }
    }
    
    async generateReport() {
        try {
            this.showLoading('Generating comprehensive report...');
            
            const response = await fetch(`${this.apiBase}/report/generate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-KEY': this.apiKey
                },
                body: JSON.stringify({
                    template: 'forensic',
                    include_charts: true
                })
            });
            
            const result = await response.json();
            
            this.hideLoading();
            
            if (result.status === 'success') {
                this.showNotification(`Report generated: ${result.report_id}`, 'success');
                
                // Open report in new window
                if (result.report_url) {
                    window.open(result.report_url, '_blank');
                }
            } else {
                this.showNotification('Report generation failed', 'error');
            }
            
        } catch (error) {
            this.hideLoading();
            this.showNotification('Failed to generate report', 'error');
            console.error('Report generation error:', error);
        }
    }
    
    async exportReport(format) {
        try {
            this.showLoading(`Exporting report as ${format.toUpperCase()}...`);
            
            switch (format) {
                case 'html':
                    await this.exportHTML();
                    break;
                case 'pdf':
                    await this.exportPDF();
                    break;
                case 'json':
                    await this.exportJSON();
                    break;
                case 'csv':
                    await this.exportCSV();
                    break;
            }
            
            this.hideLoading();
            this.showNotification(`Report exported as ${format.toUpperCase()}`, 'success');
            
        } catch (error) {
            this.hideLoading();
            this.showNotification(`Export failed: ${error.message}`, 'error');
            console.error('Export error:', error);
        }
    }
    
    async exportHTML() {
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>TOR Unveil Report - ${this.reportData.reportId}</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; background: #fff; color: #333; }
                    .report-header { border-bottom: 3px solid #4a90e2; padding-bottom: 20px; margin-bottom: 30px; }
                    .report-section { margin-bottom: 30px; page-break-inside: avoid; }
                    table { width: 100%; border-collapse: collapse; }
                    th, td { padding: 12px; text-align: left; border: 1px solid #ddd; }
                    th { background: #f0f0f0; font-weight: bold; }
                    .stat-card { padding: 15px; background: #f8f9fa; border-radius: 8px; text-align: center; }
                    .stat-value { font-size: 24px; font-weight: bold; color: #4a90e2; }
                </style>
            </head>
            <body>
                ${this.generateReportHTML(this.reportData)}
            </body>
            </html>
        `;
        
        const blob = new Blob([html], { type: 'text/html' });
        this.downloadFile(blob, `tor-report-${Date.now()}.html`);
    }
    
    async exportPDF() {
        // Using jsPDF library (make sure it's loaded)
        if (typeof window.jspdf === 'undefined') {
            throw new Error('jsPDF library not loaded');
        }
        
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        // Add content to PDF
        doc.setFontSize(20);
        doc.text('TOR Unveil - Forensic Report', 20, 20);
        
        doc.setFontSize(12);
        doc.text(`Report ID: ${this.reportData.reportId}`, 20, 35);
        doc.text(`Generated: ${new Date(this.reportData.timestamp).toLocaleString()}`, 20, 45);
        
        // Add summary stats
        doc.setFontSize(16);
        doc.text('Executive Summary', 20, 60);
        
        doc.setFontSize(12);
        doc.text(`Active Circuits: ${this.reportData.circuits.length}`, 20, 75);
        doc.text(`Packets Captured: ${this.reportData.snifferStats.total_packets || 0}`, 20, 85);
        doc.text(`TOR Packets: ${this.reportData.snifferStats.tor_packets || 0}`, 20, 95);
        
        // Save PDF
        doc.save(`tor-report-${Date.now()}.pdf`);
    }
    
    async exportJSON() {
        const json = JSON.stringify(this.reportData, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        this.downloadFile(blob, `tor-report-${Date.now()}.json`);
    }
    
    async exportCSV() {
        const circuits = this.reportData.circuits || [];
        
        let csv = 'Circuit ID,Status,Path Length,Entry Node,Exit Node,Purpose\n';
        circuits.forEach(circuit => {
            const path = circuit.path || [];
            csv += `${circuit.id},${circuit.status},${path.length},`;
            csv += `${path[0] ? path[0].nickname : 'N/A'},`;
            csv += `${path[path.length - 1] ? path[path.length - 1].nickname : 'N/A'},`;
            csv += `${circuit.purpose || 'GENERAL'}\n`;
        });
        
        const blob = new Blob([csv], { type: 'text/csv' });
        this.downloadFile(blob, `tor-circuits-${Date.now()}.csv`);
    }
    
    downloadFile(blob, filename) {
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }
    
    printReport() {
        window.print();
    }
    
    updateStats() {
        if (!this.reportData) return;
        
        document.getElementById('liveCircuitCount')?.textContent = this.reportData.circuits.length;
        document.getElementById('livePacketCount')?.textContent = 
            (this.reportData.snifferStats.total_packets || 0).toLocaleString();
        document.getElementById('liveTorPacketCount')?.textContent = 
            (this.reportData.snifferStats.tor_packets || 0).toLocaleString();
        document.getElementById('lastUpdateTime')?.textContent = 
            new Date(this.reportData.timestamp).toLocaleTimeString();
    }
    
    showLoading(message) {
        const overlay = document.createElement('div');
        overlay.id = 'loadingOverlay';
        overlay.className = 'loading-overlay';
        overlay.innerHTML = `
            <div class="loading-spinner"></div>
            <div class="loading-text">${message}</div>
        `;
        document.body.appendChild(overlay);
    }
    
    hideLoading() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.remove();
        }
    }
    
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            background: ${type === 'success' ? '#00ff88' : type === 'error' ? '#ff6b6b' : '#00d4ff'};
            color: #1a1a1a;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            z-index: 10000;
            font-weight: bold;
            animation: slideIn 0.3s ease-out;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-out';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dynamicReportGenerator = new DynamicReportGenerator();
    console.log('Dynamic Report Generator initialized');
});
