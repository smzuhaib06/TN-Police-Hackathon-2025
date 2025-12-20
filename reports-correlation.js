// Reports Correlation Integration
class ReportsCorrelation {
    constructor() {
        this.correlationData = null;
        this.reportHistory = [];
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadReportHistory();
    }

    setupEventListeners() {
        // Generate report button
        const generateBtn = document.getElementById('generateReport');
        if (generateBtn) {
            generateBtn.addEventListener('click', () => this.generateCorrelationReport());
        }

        // Export buttons
        const exportPdfBtn = document.getElementById('exportPdf');
        const exportJsonBtn = document.getElementById('exportJson');
        
        if (exportPdfBtn) {
            exportPdfBtn.addEventListener('click', () => this.exportReport('pdf'));
        }
        if (exportJsonBtn) {
            exportJsonBtn.addEventListener('click', () => this.exportReport('json'));
        }
    }

    async generateCorrelationReport() {
        try {
            // First run correlation analysis
            const correlationResponse = await fetch('http://localhost:5000/api/correlation/run');
            const correlationData = await correlationResponse.json();
            
            if (correlationData.status === 'success') {
                this.correlationData = correlationData.results;
                
                // Generate comprehensive report
                const report = this.createCorrelationReport();
                this.displayReport(report);
                this.addToReportHistory(report);
                
                this.showNotification('Correlation report generated successfully', 'success');
            } else {
                this.showNotification(`Failed to generate report: ${correlationData.message}`, 'error');
            }
        } catch (error) {
            console.error('Report generation error:', error);
            this.showNotification('Failed to generate correlation report', 'error');
        }
    }

    createCorrelationReport() {
        if (!this.correlationData) return null;

        const results = this.correlationData;
        const timestamp = new Date().toISOString();
        
        return {
            id: `report_${Date.now()}`,
            timestamp: timestamp,
            title: 'TOR Correlation Analysis Report',
            summary: {
                overall_confidence: results.overall_confidence,
                correlation_strength: results.correlation_strength,
                analysis_time: results.timestamp,
                total_algorithms: 3
            },
            timing_correlation: {
                confidence: results.timing_correlation.confidence,
                correlation_coefficient: results.timing_correlation.correlation,
                network_delay: results.timing_correlation.delay,
                entry_packets: results.timing_correlation.entry_packets,
                exit_packets: results.timing_correlation.exit_packets,
                assessment: this.assessTimingCorrelation(results.timing_correlation)
            },
            traffic_analysis: {
                avg_confidence: results.traffic_analysis.avg_confidence,
                total_flows: results.traffic_analysis.total_flows,
                analyzed_flows: results.traffic_analysis.flows.length,
                flow_details: results.traffic_analysis.flows.slice(0, 5), // Top 5 flows
                assessment: this.assessTrafficAnalysis(results.traffic_analysis)
            },
            website_fingerprinting: {
                avg_confidence: results.website_fingerprinting.avg_confidence,
                total_fingerprints: results.website_fingerprinting.total_fingerprints,
                detected_websites: results.website_fingerprinting.website_counts,
                top_websites: Object.entries(results.website_fingerprinting.website_counts || {})
                    .sort(([,a], [,b]) => b - a)
                    .slice(0, 5),
                assessment: this.assessWebsiteFingerprinting(results.website_fingerprinting)
            },
            circuit_correlations: {
                total_correlations: results.circuit_correlations.total_correlations,
                high_confidence_pairs: results.circuit_correlations.circuit_pairs.filter(p => p.correlation.confidence > 0.7).length,
                circuit_pairs: results.circuit_correlations.circuit_pairs.slice(0, 5), // Top 5 pairs
                assessment: this.assessCircuitCorrelations(results.circuit_correlations)
            },
            recommendations: this.generateRecommendations(results),
            risk_assessment: this.assessRisk(results)
        };
    }

    assessTimingCorrelation(timing) {
        if (timing.confidence > 0.8) {
            return {
                level: 'HIGH',
                description: 'Strong timing correlation detected. High probability of successful de-anonymization.',
                color: 'text-red-400'
            };
        } else if (timing.confidence > 0.5) {
            return {
                level: 'MEDIUM',
                description: 'Moderate timing correlation. Possible de-anonymization with additional evidence.',
                color: 'text-yellow-400'
            };
        } else {
            return {
                level: 'LOW',
                description: 'Weak timing correlation. Insufficient for reliable de-anonymization.',
                color: 'text-green-400'
            };
        }
    }

    assessTrafficAnalysis(traffic) {
        if (traffic.avg_confidence > 0.7 && traffic.total_flows > 10) {
            return {
                level: 'HIGH',
                description: 'Strong traffic patterns identified across multiple flows.',
                color: 'text-red-400'
            };
        } else if (traffic.avg_confidence > 0.4) {
            return {
                level: 'MEDIUM', 
                description: 'Moderate traffic correlation detected.',
                color: 'text-yellow-400'
            };
        } else {
            return {
                level: 'LOW',
                description: 'Limited traffic correlation evidence.',
                color: 'text-green-400'
            };
        }
    }

    assessWebsiteFingerprinting(websites) {
        if (websites.avg_confidence > 0.6 && websites.total_fingerprints > 5) {
            return {
                level: 'HIGH',
                description: 'Multiple websites successfully fingerprinted with high confidence.',
                color: 'text-red-400'
            };
        } else if (websites.total_fingerprints > 0) {
            return {
                level: 'MEDIUM',
                description: 'Some website fingerprinting successful.',
                color: 'text-yellow-400'
            };
        } else {
            return {
                level: 'LOW',
                description: 'No reliable website fingerprints detected.',
                color: 'text-green-400'
            };
        }
    }

    assessCircuitCorrelations(circuits) {
        const highConfidence = circuits.circuit_pairs.filter(p => p.correlation.confidence > 0.7).length;
        
        if (highConfidence > 2) {
            return {
                level: 'HIGH',
                description: 'Multiple high-confidence circuit correlations detected.',
                color: 'text-red-400'
            };
        } else if (circuits.total_correlations > 0) {
            return {
                level: 'MEDIUM',
                description: 'Some circuit correlations identified.',
                color: 'text-yellow-400'
            };
        } else {
            return {
                level: 'LOW',
                description: 'No significant circuit correlations found.',
                color: 'text-green-400'
            };
        }
    }

    generateRecommendations(results) {
        const recommendations = [];
        
        if (results.overall_confidence > 0.7) {
            recommendations.push({
                priority: 'HIGH',
                action: 'Immediate Investigation',
                description: 'High correlation confidence suggests successful de-anonymization. Proceed with targeted investigation.',
                color: 'text-red-400'
            });
        }
        
        if (results.timing_correlation.confidence > 0.6) {
            recommendations.push({
                priority: 'MEDIUM',
                action: 'Timing Analysis',
                description: 'Strong timing patterns detected. Consider extended monitoring for pattern confirmation.',
                color: 'text-yellow-400'
            });
        }
        
        if (Object.keys(results.website_fingerprinting.website_counts || {}).length > 0) {
            recommendations.push({
                priority: 'MEDIUM',
                action: 'Website Investigation',
                description: 'Specific websites identified. Cross-reference with investigation targets.',
                color: 'text-yellow-400'
            });
        }
        
        if (results.circuit_correlations.total_correlations === 0) {
            recommendations.push({
                priority: 'LOW',
                action: 'Extended Monitoring',
                description: 'No circuit correlations found. Consider longer monitoring period.',
                color: 'text-green-400'
            });
        }
        
        return recommendations;
    }

    assessRisk(results) {
        const riskScore = (
            results.overall_confidence * 0.4 +
            results.timing_correlation.confidence * 0.3 +
            results.traffic_analysis.avg_confidence * 0.2 +
            results.website_fingerprinting.avg_confidence * 0.1
        );
        
        if (riskScore > 0.7) {
            return {
                level: 'CRITICAL',
                score: Math.round(riskScore * 100),
                description: 'High risk of successful de-anonymization. Immediate action recommended.',
                color: 'text-red-400'
            };
        } else if (riskScore > 0.4) {
            return {
                level: 'MODERATE',
                score: Math.round(riskScore * 100),
                description: 'Moderate de-anonymization risk. Continue monitoring.',
                color: 'text-yellow-400'
            };
        } else {
            return {
                level: 'LOW',
                score: Math.round(riskScore * 100),
                description: 'Low de-anonymization risk. Standard monitoring sufficient.',
                color: 'text-green-400'
            };
        }
    }

    displayReport(report) {
        if (!report) return;

        // Update report summary
        this.updateReportSummary(report);
        
        // Update detailed sections
        this.updateTimingSection(report.timing_correlation);
        this.updateTrafficSection(report.traffic_analysis);
        this.updateWebsiteSection(report.website_fingerprinting);
        this.updateCircuitSection(report.circuit_correlations);
        this.updateRecommendations(report.recommendations);
        this.updateRiskAssessment(report.risk_assessment);
    }

    updateReportSummary(report) {
        const elements = {
            'reportTitle': report.title,
            'reportTimestamp': new Date(report.timestamp).toLocaleString(),
            'overallConfidence': `${(report.summary.overall_confidence * 100).toFixed(1)}%`,
            'correlationStrength': report.summary.correlation_strength,
            'algorithmsUsed': report.summary.total_algorithms
        };

        Object.entries(elements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) element.textContent = value;
        });
    }

    updateTimingSection(timing) {
        const container = document.getElementById('timingDetails');
        if (!container) return;

        container.innerHTML = `
            <div class="grid grid-cols-2 gap-4 text-sm mb-3">
                <div><strong>Confidence:</strong> <span class="${timing.assessment.color}">${(timing.confidence * 100).toFixed(1)}%</span></div>
                <div><strong>Correlation:</strong> <span class="text-matrix-green">${timing.correlation_coefficient.toFixed(3)}</span></div>
                <div><strong>Network Delay:</strong> <span class="text-yellow-400">${timing.network_delay.toFixed(2)}s</span></div>
                <div><strong>Entry Packets:</strong> <span class="text-cyan-400">${timing.entry_packets}</span></div>
            </div>
            <div class="bg-gray-800 rounded p-3">
                <div class="font-medium ${timing.assessment.color} mb-1">${timing.assessment.level} Risk</div>
                <div class="text-sm text-gray-300">${timing.assessment.description}</div>
            </div>
        `;
    }

    updateTrafficSection(traffic) {
        const container = document.getElementById('trafficDetails');
        if (!container) return;

        container.innerHTML = `
            <div class="grid grid-cols-2 gap-4 text-sm mb-3">
                <div><strong>Avg Confidence:</strong> <span class="${traffic.assessment.color}">${(traffic.avg_confidence * 100).toFixed(1)}%</span></div>
                <div><strong>Total Flows:</strong> <span class="text-matrix-green">${traffic.total_flows}</span></div>
                <div><strong>Analyzed:</strong> <span class="text-yellow-400">${traffic.analyzed_flows}</span></div>
                <div><strong>Assessment:</strong> <span class="${traffic.assessment.color}">${traffic.assessment.level}</span></div>
            </div>
            <div class="bg-gray-800 rounded p-3">
                <div class="text-sm text-gray-300">${traffic.assessment.description}</div>
            </div>
        `;
    }

    updateWebsiteSection(websites) {
        const container = document.getElementById('websiteDetails');
        if (!container) return;

        const websiteList = websites.top_websites.map(([site, count]) => 
            `<div class="flex justify-between"><span>${site}</span><span>${count} visits</span></div>`
        ).join('');

        container.innerHTML = `
            <div class="grid grid-cols-2 gap-4 text-sm mb-3">
                <div><strong>Confidence:</strong> <span class="${websites.assessment.color}">${(websites.avg_confidence * 100).toFixed(1)}%</span></div>
                <div><strong>Total Sites:</strong> <span class="text-matrix-green">${websites.total_fingerprints}</span></div>
            </div>
            <div class="bg-gray-800 rounded p-3 mb-3">
                <div class="text-sm text-gray-300">${websites.assessment.description}</div>
            </div>
            <div class="space-y-1 text-sm">
                ${websiteList || '<div class="text-gray-400">No websites detected</div>'}
            </div>
        `;
    }

    updateCircuitSection(circuits) {
        const container = document.getElementById('circuitDetails');
        if (!container) return;

        const pairsList = circuits.circuit_pairs.map((pair, index) => 
            `<div class="text-xs bg-gray-800 rounded p-2">
                <div class="font-medium">Pair ${index + 1}: ${(pair.correlation.confidence * 100).toFixed(1)}%</div>
                <div class="text-gray-400">${pair.flow1.split('-')[0]} ↔ ${pair.flow2.split('-')[0]}</div>
            </div>`
        ).join('');

        container.innerHTML = `
            <div class="grid grid-cols-2 gap-4 text-sm mb-3">
                <div><strong>Total Correlations:</strong> <span class="text-matrix-green">${circuits.total_correlations}</span></div>
                <div><strong>High Confidence:</strong> <span class="${circuits.assessment.color}">${circuits.high_confidence_pairs}</span></div>
            </div>
            <div class="bg-gray-800 rounded p-3 mb-3">
                <div class="text-sm text-gray-300">${circuits.assessment.description}</div>
            </div>
            <div class="space-y-2">
                ${pairsList || '<div class="text-gray-400 text-sm">No circuit correlations found</div>'}
            </div>
        `;
    }

    updateRecommendations(recommendations) {
        const container = document.getElementById('recommendationsList');
        if (!container) return;

        container.innerHTML = recommendations.map(rec => `
            <div class="bg-gray-800 rounded p-3">
                <div class="flex justify-between items-start mb-2">
                    <div class="font-medium ${rec.color}">${rec.action}</div>
                    <div class="text-xs px-2 py-1 rounded ${rec.color} bg-opacity-20">${rec.priority}</div>
                </div>
                <div class="text-sm text-gray-300">${rec.description}</div>
            </div>
        `).join('');
    }

    updateRiskAssessment(risk) {
        const container = document.getElementById('riskAssessment');
        if (!container) return;

        container.innerHTML = `
            <div class="text-center mb-4">
                <div class="text-3xl font-bold ${risk.color} mb-2">${risk.score}%</div>
                <div class="text-lg font-medium ${risk.color}">${risk.level} RISK</div>
            </div>
            <div class="bg-gray-800 rounded p-4">
                <div class="text-sm text-gray-300">${risk.description}</div>
            </div>
        `;
    }

    addToReportHistory(report) {
        this.reportHistory.unshift(report);
        if (this.reportHistory.length > 10) {
            this.reportHistory = this.reportHistory.slice(0, 10);
        }
        this.updateReportHistory();
    }

    updateReportHistory() {
        const container = document.getElementById('reportHistory');
        if (!container) return;

        container.innerHTML = this.reportHistory.map(report => `
            <div class="bg-steel-gray rounded p-3 cursor-pointer hover:bg-gray-600 transition-colors" onclick="window.reportsCorrelation.loadReport('${report.id}')">
                <div class="flex justify-between items-start">
                    <div>
                        <div class="font-medium text-cyber-blue text-sm">${report.title}</div>
                        <div class="text-xs text-gray-400">${new Date(report.timestamp).toLocaleString()}</div>
                    </div>
                    <div class="text-xs ${report.risk_assessment.color}">${report.risk_assessment.level}</div>
                </div>
            </div>
        `).join('');
    }

    loadReport(reportId) {
        const report = this.reportHistory.find(r => r.id === reportId);
        if (report) {
            this.displayReport(report);
        }
    }

    loadReportHistory() {
        // Load from localStorage if available
        const saved = localStorage.getItem('tor_reports');
        if (saved) {
            try {
                this.reportHistory = JSON.parse(saved);
                this.updateReportHistory();
            } catch (e) {
                console.error('Failed to load report history:', e);
            }
        }
    }

    saveReportHistory() {
        try {
            localStorage.setItem('tor_reports', JSON.stringify(this.reportHistory));
        } catch (e) {
            console.error('Failed to save report history:', e);
        }
    }

    exportReport(format) {
        if (!this.correlationData) {
            this.showNotification('No report data to export', 'error');
            return;
        }

        const report = this.createCorrelationReport();
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        
        if (format === 'json') {
            const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
            this.downloadFile(blob, `tor_correlation_report_${timestamp}.json`);
        } else if (format === 'pdf') {
            // For PDF, we'll create a formatted text version
            const textReport = this.formatReportAsText(report);
            const blob = new Blob([textReport], { type: 'text/plain' });
            this.downloadFile(blob, `tor_correlation_report_${timestamp}.txt`);
        }
    }

    formatReportAsText(report) {
        return `
TOR CORRELATION ANALYSIS REPORT
===============================

Generated: ${new Date(report.timestamp).toLocaleString()}
Overall Confidence: ${(report.summary.overall_confidence * 100).toFixed(1)}%
Correlation Strength: ${report.summary.correlation_strength}

TIMING CORRELATION
------------------
Confidence: ${(report.timing_correlation.confidence * 100).toFixed(1)}%
Correlation Coefficient: ${report.timing_correlation.correlation_coefficient.toFixed(3)}
Network Delay: ${report.timing_correlation.network_delay.toFixed(2)}s
Assessment: ${report.timing_correlation.assessment.level} - ${report.timing_correlation.assessment.description}

TRAFFIC ANALYSIS
----------------
Average Confidence: ${(report.traffic_analysis.avg_confidence * 100).toFixed(1)}%
Total Flows: ${report.traffic_analysis.total_flows}
Analyzed Flows: ${report.traffic_analysis.analyzed_flows}
Assessment: ${report.traffic_analysis.assessment.level} - ${report.traffic_analysis.assessment.description}

WEBSITE FINGERPRINTING
----------------------
Average Confidence: ${(report.website_fingerprinting.avg_confidence * 100).toFixed(1)}%
Total Fingerprints: ${report.website_fingerprinting.total_fingerprints}
Top Websites: ${report.website_fingerprinting.top_websites.map(([site, count]) => `${site} (${count} visits)`).join(', ')}
Assessment: ${report.website_fingerprinting.assessment.level} - ${report.website_fingerprinting.assessment.description}

CIRCUIT CORRELATIONS
-------------------
Total Correlations: ${report.circuit_correlations.total_correlations}
High Confidence Pairs: ${report.circuit_correlations.high_confidence_pairs}
Assessment: ${report.circuit_correlations.assessment.level} - ${report.circuit_correlations.assessment.description}

RISK ASSESSMENT
---------------
Risk Level: ${report.risk_assessment.level}
Risk Score: ${report.risk_assessment.score}%
Description: ${report.risk_assessment.description}

RECOMMENDATIONS
---------------
${report.recommendations.map(rec => `${rec.priority}: ${rec.action} - ${rec.description}`).join('\n')}
        `.trim();
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
        
        this.showNotification(`Report exported as ${filename}`, 'success');
    }

    showNotification(message, type = 'info') {
        console.log(`${type.toUpperCase()}: ${message}`);
        
        const notification = document.createElement('div');
        notification.className = `fixed top-20 right-4 z-50 p-4 rounded-lg border max-w-sm ${
            type === 'success' ? 'bg-green-900 border-green-500 text-green-200' :
            type === 'error' ? 'bg-red-900 border-red-500 text-red-200' :
            'bg-blue-900 border-blue-500 text-blue-200'
        }`;
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
        }, 4000);
    }
}

// Initialize reports correlation
document.addEventListener('DOMContentLoaded', function() {
    window.reportsCorrelation = new ReportsCorrelation();
    console.log('Reports Correlation initialized');
});