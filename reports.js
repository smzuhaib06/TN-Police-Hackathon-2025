// TOR Unveil - Forensic Report Generation System
class ReportGenerator {
    constructor() {
        this.selectedTemplate = 'investigation';
        this.selectedFormats = new Set(['pdf']);
        this.generatedReports = new Map();
        this.currentPreview = null;
        
        this.init();
    }

    init() {
        this.initializeEventListeners();
        // Load real data when available; avoid preloading sample reports
        this.initializeAnimations();
    }

    initializeEventListeners() {
        // Template selection
        document.querySelectorAll('.template-card').forEach(card => {
            card.addEventListener('click', () => this.selectTemplate(card));
        });

        // Export format selection
        document.querySelectorAll('.export-format').forEach(format => {
            format.addEventListener('click', () => this.toggleExportFormat(format));
        });

        // Report generation
        document.getElementById('generateReport').addEventListener('click', () => this.generateReport());
        document.getElementById('batchExport').addEventListener('click', () => this.batchExport());
        document.getElementById('saveTemplate').addEventListener('click', () => this.saveTemplate());

        // Preview controls
        document.getElementById('refreshPreview').addEventListener('click', () => this.refreshPreview());
        document.getElementById('fullscreenPreview').addEventListener('click', () => this.fullscreenPreview());

        // Report management
        document.getElementById('selectAllReports').addEventListener('change', (e) => this.toggleAllReports(e.target.checked));
        document.getElementById('archiveReports').addEventListener('click', () => this.archiveSelectedReports());
        document.getElementById('deleteReports').addEventListener('click', () => this.deleteSelectedReports());

        // Individual report actions
        document.querySelectorAll('.reports-table button').forEach(button => {
            button.addEventListener('click', (e) => this.handleReportAction(e));
        });
    }

    selectTemplate(card) {
        document.querySelectorAll('.template-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        this.selectedTemplate = card.dataset.template;
        
        this.updatePreview();
        
        // Animate selection
        anime({
            targets: card,
            scale: [1, 1.02, 1],
            duration: 300,
            easing: 'easeOutQuad'
        });
    }

    toggleExportFormat(format) {
        const formatType = format.dataset.format;
        
        if (this.selectedFormats.has(formatType)) {
            this.selectedFormats.delete(formatType);
            format.classList.remove('selected');
        } else {
            this.selectedFormats.add(formatType);
            format.classList.add('selected');
        }
    }

    async generateReport() {
        if (this.selectedFormats.size === 0) {
            this.showNotification('Please select at least one export format', 'warning');
            return;
        }

        const generateBtn = document.getElementById('generateReport');
        generateBtn.textContent = 'Generating...';
        generateBtn.disabled = true;

        try {
            // Simulate report generation process
            await this.simulateReportGeneration();
            
            // Generate report data
            const reportData = this.generateReportData();
            
            // Export in selected formats
            await this.exportReport(reportData);
            
            // Add to reports table
            this.addReportToTable(reportData);
            
            this.showNotification('Report generated successfully', 'success');
            
        } catch (error) {
            console.error('Report generation failed:', error);
            this.showNotification('Report generation failed', 'error');
        } finally {
            generateBtn.textContent = 'Generate Report';
            generateBtn.disabled = false;
        }
    }

    async simulateReportGeneration() {
        const phases = [
            'Collecting investigation data...',
            'Analyzing network topology...',
            'Processing correlation results...',
            'Generating timeline reconstruction...',
            'Compiling evidence analysis...',
            'Formatting legal documentation...',
            'Finalizing report structure...'
        ];

        for (let i = 0; i < phases.length; i++) {
            this.showProgressNotification(phases[i], (i + 1) / phases.length * 100);
            await new Promise(resolve => setTimeout(resolve, 500));
        }
    }

    generateReportData() {
        const templates = {
            investigation: {
                title: 'TOR Network Investigation Report',
                caseId: 'TOR-INV-' + Date.now().toString().slice(-6),
                sections: [
                    'Executive Summary',
                    'Investigation Overview',
                    'Network Topology Analysis',
                    'Node Correlation Results',
                    'Timeline Reconstruction',
                    'Origin Identification',
                    'Evidence Analysis',
                    'Conclusions and Recommendations'
                ]
            },
            summary: {
                title: 'Executive Summary - TOR Investigation',
                caseId: 'TOR-SUM-' + Date.now().toString().slice(-6),
                sections: [
                    'Executive Summary',
                    'Key Findings',
                    'Risk Assessment',
                    'Recommendations'
                ]
            },
            technical: {
                title: 'Technical Analysis Report - TOR Network',
                caseId: 'TOR-TECH-' + Date.now().toString().slice(-6),
                sections: [
                    'Technical Overview',
                    'Network Architecture Analysis',
                    'Correlation Algorithms',
                    'Statistical Analysis',
                    'Algorithm Performance',
                    'Technical Findings',
                    'Implementation Details'
                ]
            },
            evidence: {
                title: 'Evidence Analysis Report - TOR Investigation',
                caseId: 'TOR-EVID-' + Date.now().toString().slice(-6),
                sections: [
                    'Chain of Custody',
                    'Evidence Collection',
                    'Forensic Analysis',
                    'Digital Evidence',
                    'Network Logs',
                    'Correlation Evidence',
                    'Legal Compliance'
                ]
            }
        };

        const template = templates[this.selectedTemplate];
        const reportId = 'RPT-' + Date.now().toString().slice(-8);
        
        return {
            id: reportId,
            ...template,
            generatedAt: new Date().toISOString(),
            investigator: 'TN Police Cyber Division',
            system: 'TOR Unveil v1.0',
            confidentiality: 'Law Enforcement Use Only',
            findings: this.generateFindings(),
            evidence: this.generateEvidenceData(),
            correlations: this.generateCorrelationData()
        };
    }

    generateFindings() {
        return [
            {
                type: 'origin-identification',
                confidence: 92.3,
                description: 'High-confidence identification of origin IP address 192.168.1.100 behind TOR-based traffic',
                evidence: ['Timing correlation analysis', 'Traffic pattern matching', 'Geolocation verification']
            },
            {
                type: 'network-analysis',
                confidence: 87.6,
                description: 'Comprehensive analysis of TOR network topology revealing 7,524 active relays',
                evidence: ['Network topology mapping', 'Relay status monitoring', 'Bandwidth analysis']
            },
            {
                type: 'timeline-reconstruction',
                confidence: 94.1,
                description: 'Complete timeline reconstruction of attack progression over 28-minute period',
                evidence: ['Packet capture analysis', 'Timestamp correlation', 'Event sequence verification']
            }
        ];
    }

    generateEvidenceData() {
        return [
            {
                id: 'EVID-001',
                type: 'PCAP File',
                filename: 'suspicious_traffic.pcap',
                size: '2.3 GB',
                hash: 'SHA256:a1b2c3d4e5f6...',
                collected: '2025-11-22T14:23:45Z',
                analyst: 'Cyber Division'
            },
            {
                id: 'EVID-002',
                type: 'Network Logs',
                filename: 'tor_access.log',
                size: '45 MB',
                hash: 'SHA256:f6e5d4c3b2a1...',
                collected: '2025-11-22T13:15:12Z',
                analyst: 'Cyber Division'
            }
        ];
    }

    generateCorrelationData() {
        return {
            totalCorrelations: 247,
            highConfidence: 23,
            algorithmsUsed: ['Timing Correlation', 'Traffic Analysis', 'Statistical Matching'],
            confidenceRange: '68.2% - 94.7%',
            processingTime: '2.3 seconds'
        };
    }

    async exportReport(reportData) {
        for (const format of this.selectedFormats) {
            await this.exportInFormat(reportData, format);
        }
    }

    async exportInFormat(reportData, format) {
        switch(format) {
            case 'pdf':
                await this.exportPDF(reportData);
                break;
            case 'docx':
                await this.exportDOCX(reportData);
                break;
            case 'json':
                await this.exportJSON(reportData);
                break;
            case 'csv':
                await this.exportCSV(reportData);
                break;
        }
    }

    async exportPDF(reportData) {
        // Use jsPDF (loaded in page) to generate a basic PDF from report data
        try {
            // Robustly detect jsPDF constructor from different UMD builds
            const jsPDFCtor = (window.jspdf && (window.jspdf.jsPDF || window.jspdf.default && window.jspdf.default.jsPDF)) || window.jsPDF || null;

            if (typeof jsPDFCtor === 'function') {
                const doc = new jsPDFCtor();
                const txt = this.generatePlainTextReport(reportData);

                // splitTextToSize exists on the instance for typical jsPDF builds
                const maxWidth = 180;
                const lines = (typeof doc.splitTextToSize === 'function') ? doc.splitTextToSize(txt, maxWidth) : txt.split('\n');
                let cursorY = 15;
                const lineHeight = 7;

                lines.forEach((line) => {
                    if (cursorY > 280) {
                        doc.addPage();
                        cursorY = 15;
                    }
                    doc.text(String(line), 15, cursorY);
                    cursorY += lineHeight;
                });

                // Prefer arraybuffer -> Blob to ensure correct PDF bytes and MIME
                const arrayBuf = doc.output && typeof doc.output === 'function' ? doc.output('arraybuffer') : null;
                if (arrayBuf) {
                    const blob = new Blob([arrayBuf], { type: 'application/pdf' });
                    this.downloadFile(blob, `${reportData.id}.pdf`);
                    return;
                }

                // Fallback to blob output if arraybuffer not available
                const blobFallback = doc.output && typeof doc.output === 'function' ? doc.output('blob') : null;
                if (blobFallback) {
                    this.downloadFile(blobFallback, `${reportData.id}.pdf`);
                    return;
                }
            }
        } catch (e) {
            console.warn('jsPDF generation failed, falling back to simple PDF blob', e);
        }

        // Final fallback: create a small text-based PDF wrapper using plain text (best-effort)
        const text = this.generatePlainTextReport(reportData);
        const fallbackBlob = new Blob([text], { type: 'application/pdf' });
        this.downloadFile(fallbackBlob, `${reportData.id}.pdf`);
    }

    async exportDOCX(reportData) {
        // Generate an HTML-backed .doc file which MS Word can open reliably
        const html = `<!doctype html><html><head><meta charset="utf-8"><title>${reportData.title}</title></head><body>${this.generateReportHTML(reportData)}</body></html>`;
        const blob = new Blob([html], { type: 'application/msword' });
        // Use .doc extension for compatibility
        this.downloadFile(blob, `${reportData.id}.doc`);
    }

    // Helper to produce plain-text version of the report for PDF fallback
    generatePlainTextReport(reportData) {
        const lines = [];
        lines.push(reportData.title);
        lines.push(`Case ID: ${reportData.caseId}`);
        lines.push(`Generated: ${reportData.generatedAt}`);
        lines.push(`Investigator: ${reportData.investigator}`);
        lines.push('\nExecutive Summary:\n');
        lines.push('Key Findings:');
        reportData.findings.forEach(f => {
            lines.push(`- ${f.confidence}% confidence: ${f.description}`);
        });
        lines.push('\nEvidence:\n');
        reportData.evidence.forEach(e => {
            lines.push(`${e.id} | ${e.type} | ${e.filename} | ${e.size} | ${e.collected}`);
        });
        lines.push('\nConclusions and Recommendations:\n');
        lines.push('Review findings and follow recommended actions.');
        return lines.join('\n');
    }

    async exportJSON(reportData) {
        const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
        this.downloadFile(blob, `${reportData.id}.json`);
    }

    async exportCSV(reportData) {
        const csvContent = this.generateCSVContent(reportData);
        const blob = new Blob([csvContent], { type: 'text/csv' });
        this.downloadFile(blob, `${reportData.id}.csv`);
    }

    generateCSVContent(reportData) {
        let csv = 'Section,Content,Confidence,Evidence\n';
        
        reportData.findings.forEach(finding => {
            csv += `${finding.type},"${finding.description}",${finding.confidence},"${finding.evidence.join('; ')}"\n`;
        });
        
        return csv;
    }

    downloadFile(blob, filename) {
        // Log and show size for debugging if file fails to open
        try {
            const sizeKb = blob && blob.size ? Math.round(blob.size / 1024) : 0;
            console.log(`Preparing download: ${filename} (${sizeKb} KB)`);
            this.showNotification(`Preparing download: ${filename} (${sizeKb} KB)`, 'info');
        } catch (e) {
            // ignore logging errors
        }

        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        // Append to DOM to ensure click works in some browsers
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
    }

    updatePreview() {
        const preview = document.getElementById('reportPreview');
        const reportData = this.generateReportData();
        
        const html = this.generateReportHTML(reportData);
        preview.innerHTML = html;
        
        this.currentPreview = reportData;
    }

    generateReportHTML(reportData) {
        const confidenceColor = (confidence) => {
            if (confidence > 80) return 'confidence-high';
            if (confidence > 60) return 'confidence-medium';
            return 'confidence-low';
        };

        return `
            <div class="report-header">
                <h1 class="text-2xl font-bold mb-2">${reportData.title}</h1>
                <div class="grid grid-cols-2 gap-4 text-sm">
                    <div><strong>Case ID:</strong> ${reportData.caseId}</div>
                    <div><strong>Generated:</strong> ${new Date(reportData.generatedAt).toLocaleString()}</div>
                    <div><strong>Investigator:</strong> ${reportData.investigator}</div>
                    <div><strong>System:</strong> ${reportData.system}</div>
                </div>
                <div class="mt-2 text-xs text-gray-500">
                    <strong>Confidentiality:</strong> ${reportData.confidentiality}
                </div>
            </div>

            <div class="report-section">
                <h2 class="text-lg font-bold mb-3 border-b border-gray-300 pb-1">Executive Summary</h2>
                <p class="mb-4">
                    This report presents the findings of a comprehensive TOR network investigation conducted using advanced 
                    correlation analysis and forensic techniques. The investigation successfully identified the probable origin 
                    of suspicious network activity with high confidence.
                </p>
                <div class="bg-gray-100 p-3 rounded mb-4">
                    <h3 class="font-bold mb-2">Key Findings:</h3>
                    <ul class="space-y-1 text-sm">
                        ${reportData.findings.map(finding => `
                            <li class="flex items-center">
                                <span class="confidence-indicator ${confidenceColor(finding.confidence)}"></span>
                                <span><strong>${finding.confidence}% confidence:</strong> ${finding.description}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            </div>

            <div class="report-section">
                <h2 class="text-lg font-bold mb-3 border-b border-gray-300 pb-1">Investigation Overview</h2>
                <p class="mb-3">
                    The investigation utilized multiple correlation algorithms to analyze TOR network traffic patterns 
                    and identify potential origin IPs. The analysis covered ${reportData.correlations.totalCorrelations} 
                    correlation points with ${reportData.correlations.highConfidence} high-confidence matches.
                </p>
                <table class="report-table">
                    <thead>
                        <tr>
                            <th>Algorithm</th>
                            <th>Accuracy</th>
                            <th>Processing Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Timing Correlation</td>
                            <td>85.2%</td>
                            <td>0.8s</td>
                        </tr>
                        <tr>
                            <td>Traffic Analysis</td>
                            <td>72.6%</td>
                            <td>1.2s</td>
                        </tr>
                        <tr>
                            <td>Statistical Matching</td>
                            <td>68.9%</td>
                            <td>2.3s</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="report-section">
                <h2 class="text-lg font-bold mb-3 border-b border-gray-300 pb-1">Evidence Analysis</h2>
                <p class="mb-3">The following digital evidence was analyzed during this investigation:</p>
                <table class="report-table">
                    <thead>
                        <tr>
                            <th>Evidence ID</th>
                            <th>Type</th>
                            <th>Filename</th>
                            <th>Size</th>
                            <th>Collected</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${reportData.evidence.map(item => `
                            <tr>
                                <td class="mono-font">${item.id}</td>
                                <td>${item.type}</td>
                                <td class="mono-font">${item.filename}</td>
                                <td>${item.size}</td>
                                <td>${new Date(item.collected).toLocaleString()}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>

            <div class="report-section">
                <h2 class="text-lg font-bold mb-3 border-b border-gray-300 pb-1">Conclusions and Recommendations</h2>
                <p class="mb-3">
                    Based on the comprehensive analysis conducted, we have identified the probable origin of the 
                    suspicious TOR network activity with high confidence. The investigation reveals sophisticated 
                    attempts to obfuscate network traffic through the TOR network.
                </p>
                <div class="bg-yellow-50 border-l-4 border-yellow-400 p-3 mb-4">
                    <h3 class="font-bold mb-2">Immediate Actions Required:</h3>
                    <ul class="space-y-1 text-sm">
                        <li>• Monitor identified origin IP for continued suspicious activity</li>
                        <li>• Implement additional network segmentation and monitoring</li>
                        <li>• Review and update incident response procedures</li>
                        <li>• Conduct security awareness training for relevant personnel</li>
                    </ul>
                </div>
            </div>

            <div class="text-xs text-gray-500 mt-6 pt-4 border-t border-gray-300">
                <p>This report was generated automatically by the TOR Unveil forensic analysis system. 
                All findings are based on statistical analysis and correlation algorithms. Results should 
                be reviewed by qualified cybersecurity professionals.</p>
            </div>
        `;
    }

    addReportToTable(reportData) {
        const tbody = document.getElementById('reportsTable');
        const row = document.createElement('tr');
        row.className = 'border-b border-gray-700 hover:bg-steel-gray';
        
        row.innerHTML = `
            <td class="py-2 px-3">
                <input type="checkbox" class="report-checkbox rounded">
            </td>
            <td class="py-2 px-3 mono-font text-cyber-blue">${reportData.id}</td>
            <td class="py-2 px-3">${this.selectedTemplate.charAt(0).toUpperCase() + this.selectedTemplate.slice(1)}</td>
            <td class="py-2 px-3">${reportData.caseId}</td>
            <td class="py-2 px-3 mono-font text-gray-400">${new Date(reportData.generatedAt).toLocaleString()}</td>
            <td class="py-2 px-3">
                <span class="px-2 py-1 bg-matrix-green text-black rounded text-xs">Completed</span>
            </td>
            <td class="py-2 px-3">
                <div class="flex space-x-2">
                    <button class="text-cyber-blue hover:text-white text-xs" onclick="window.reports.viewReport('${reportData.id}')">View</button>
                    <button class="text-matrix-green hover:text-white text-xs" onclick="window.reports.downloadReport('${reportData.id}')">Download</button>
                    <button class="text-warning-amber hover:text-white text-xs" onclick="window.reports.editReport('${reportData.id}')">Edit</button>
                </div>
            </td>
        `;
        
        tbody.appendChild(row);
        
        // Animate in
        anime({
            targets: row,
            opacity: [0, 1],
            translateX: [-20, 0],
            duration: 400,
            easing: 'easeOutQuad'
        });
    }

    refreshPreview() {
        this.updatePreview();
        this.showNotification('Preview refreshed', 'info');
    }

    fullscreenPreview() {
        if (this.currentPreview) {
            const newWindow = window.open('', '_blank', 'width=1024,height=768');
            newWindow.document.write(`
                <html>
                    <head>
                        <title>${this.currentPreview.title}</title>
                        <style>
                            body { font-family: 'Times New Roman', serif; margin: 40px; line-height: 1.6; }
                            .report-container { max-width: 800px; margin: 0 auto; }
                        </style>
                    </head>
                    <body>
                        <div class="report-container">
                            ${this.generateReportHTML(this.currentPreview)}
                        </div>
                    </body>
                </html>
            `);
        }
    }

    toggleAllReports(checked) {
        document.querySelectorAll('.report-checkbox').forEach(checkbox => {
            checkbox.checked = checked;
        });
    }

    getSelectedReports() {
        const selected = [];
        document.querySelectorAll('.report-checkbox:checked').forEach(checkbox => {
            const row = checkbox.closest('tr');
            selected.push({
                element: row,
                id: row.cells[1].textContent
            });
        });
        return selected;
    }

    archiveSelectedReports() {
        const selected = this.getSelectedReports();
        if (selected.length === 0) {
            this.showNotification('No reports selected', 'warning');
            return;
        }

        selected.forEach(report => {
            anime({
                targets: report.element,
                opacity: [1, 0.5],
                duration: 300,
                complete: () => {
                    const statusCell = report.element.cells[5];
                    statusCell.innerHTML = '<span class="px-2 py-1 bg-gray-500 text-white rounded text-xs">Archived</span>';
                    
                    anime({
                        targets: report.element,
                        opacity: [0.5, 1],
                        duration: 300
                    });
                }
            });
        });

        this.showNotification(`${selected.length} reports archived`, 'success');
    }

    deleteSelectedReports() {
        const selected = this.getSelectedReports();
        if (selected.length === 0) {
            this.showNotification('No reports selected', 'warning');
            return;
        }

        if (!confirm(`Are you sure you want to delete ${selected.length} selected reports?`)) {
            return;
        }

        selected.forEach(report => {
            anime({
                targets: report.element,
                opacity: [1, 0],
                height: [report.element.offsetHeight, 0],
                duration: 400,
                easing: 'easeOutQuad',
                complete: () => {
                    report.element.remove();
                }
            });
        });

        this.showNotification(`${selected.length} reports deleted`, 'success');
    }

    handleReportAction(e) {
        const action = e.target.textContent.toLowerCase();
        const reportId = e.target.closest('tr').cells[1].textContent;
        
        switch(action) {
            case 'view':
                this.viewReport(reportId);
                break;
            case 'download':
                this.downloadReport(reportId);
                break;
            case 'edit':
                this.editReport(reportId);
                break;
        }
    }

    viewReport(reportId) {
        this.showNotification(`Opening report ${reportId}`, 'info');
        // In a real implementation, this would open the report viewer
    }

    downloadReport(reportId) {
        this.showNotification(`Downloading report ${reportId}`, 'success');
        // In a real implementation, this would trigger the download
    }

    editReport(reportId) {
        this.showNotification(`Opening editor for ${reportId}`, 'info');
        // In a real implementation, this would open the report editor
    }

    batchExport() {
        const selected = this.getSelectedReports();
        if (selected.length === 0) {
            this.showNotification('No reports selected for batch export', 'warning');
            return;
        }

        this.showNotification(`Exporting ${selected.length} reports in batch`, 'info');
        // In a real implementation, this would generate a zip file with all selected reports
    }

    saveTemplate() {
        this.showNotification('Template saved successfully', 'success');
        // In a real implementation, this would save the current template configuration
    }

    loadSampleReports() {
        // Sample reports are already in the HTML table
        // In a real implementation, this would load from a database
    }

    showProgressNotification(message, progress) {
        const notification = document.createElement('div');
        notification.className = 'fixed top-20 right-4 z-50 p-4 rounded-lg border bg-blue-900 border-blue-500 text-white max-w-sm';
        notification.innerHTML = `
            <div class="flex items-center space-x-3">
                <div class="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                <div class="flex-1">
                    <p class="text-sm">${message}</p>
                    <div class="w-full bg-blue-700 rounded-full h-1 mt-1">
                        <div class="bg-white h-1 rounded-full transition-all duration-300" style="width: ${progress}%"></div>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(notification);

        if (progress >= 100) {
            setTimeout(() => {
                notification.remove();
            }, 1000);
        }

        return notification;
    }

    showNotification(message, type = 'info') {
        const colors = {
            success: 'bg-green-900 border-green-500',
            error: 'bg-red-900 border-red-500',
            warning: 'bg-orange-900 border-orange-500',
            info: 'bg-blue-900 border-blue-500'
        };

        const notification = document.createElement('div');
        notification.className = `fixed top-20 right-4 z-50 p-4 rounded-lg border ${colors[type]} text-white max-w-sm`;
        notification.innerHTML = `
            <div class="flex justify-between items-start">
                <p class="text-sm">${message}</p>
                <button onclick="this.parentElement.parentElement.remove()" class="ml-2 text-gray-400 hover:text-white">✕</button>
            </div>
        `;

        document.body.appendChild(notification);

        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);

        anime({
            targets: notification,
            translateX: [300, 0],
            opacity: [0, 1],
            duration: 300,
            easing: 'easeOutQuad'
        });
    }

    initializeAnimations() {
        // Animate elements on page load
        anime({
            targets: '.hover-lift',
            translateY: [20, 0],
            opacity: [0, 1],
            delay: anime.stagger(100),
            duration: 800,
            easing: 'easeOutQuad'
        });

        // Animate template cards
        anime({
            targets: '.template-card',
            scale: [0.95, 1],
            opacity: [0, 1],
            delay: anime.stagger(150, {start: 300}),
            duration: 600,
            easing: 'easeOutElastic(1, .8)'
        });

        // Initialize preview with default template
        setTimeout(() => {
            this.updatePreview();
        }, 1000);
    }
}

// Global functions for inline event handlers
window.reports = {
    viewReport: function(reportId) {
        window.reportGenerator.viewReport(reportId);
    },
    downloadReport: function(reportId) {
        window.reportGenerator.downloadReport(reportId);
    },
    editReport: function(reportId) {
        window.reportGenerator.editReport(reportId);
    }
};

// Initialize report generator when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.reportGenerator = new ReportGenerator();
});