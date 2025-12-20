// Forensics Correlation Integration
class ForensicsCorrelation {
    constructor() {
        this.correlationData = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.startPeriodicUpdates();
    }

    setupEventListeners() {
        // Refresh button
        const refreshBtn = document.getElementById('refreshForensics');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.refreshCorrelationData());
        }

        // Correlation engine tool
        const correlationBtn = document.getElementById('correlationEngine');
        if (correlationBtn) {
            correlationBtn.addEventListener('click', () => this.runCorrelationAnalysis());
        }
    }

    async refreshCorrelationData() {
        try {
            const response = await fetch('http://localhost:5000/api/correlation/results');
            const data = await response.json();
            
            if (data.status === 'success' && data.has_results) {
                this.correlationData = data.results;
                this.updateForensicsDisplay();
                this.showNotification('Correlation data refreshed', 'success');
            } else {
                this.showNoDataMessage();
            }
        } catch (error) {
            console.error('Failed to refresh correlation data:', error);
            this.showNotification('Failed to refresh correlation data', 'error');
        }
    }

    async runCorrelationAnalysis() {
        try {
            const response = await fetch('http://localhost:5000/api/correlation/run');
            const data = await response.json();
            
            if (data.status === 'success') {
                this.correlationData = data.results;
                this.updateForensicsDisplay();
                this.showNotification('Correlation analysis completed', 'success');
            } else {
                this.showNotification(`Analysis failed: ${data.message}`, 'error');
            }
        } catch (error) {
            this.showNotification('Failed to run correlation analysis', 'error');
        }
    }

    updateForensicsDisplay() {
        if (!this.correlationData) {
            this.showNoDataMessage();
            return;
        }

        this.updateCorrelationResults();
        this.updateWebsiteFingerprints();
        this.updateCircuitCorrelations();
        this.updateOriginCandidates();
    }

    updateCorrelationResults() {
        const container = document.getElementById('forensicsResults');
        if (!container) return;

        const results = this.correlationData;
        
        container.innerHTML = `
            <div class="space-y-4">
                <div class="bg-steel-gray rounded-lg p-4">
                    <h4 class="font-bold text-cyber-blue mb-2">Timing Correlation</h4>
                    <div class="grid grid-cols-2 gap-4 text-sm">
                        <div><strong>Confidence:</strong> <span class="text-red-400">${(results.timing_correlation.confidence * 100).toFixed(1)}%</span></div>
                        <div><strong>Correlation Coefficient:</strong> <span class="text-matrix-green">${results.timing_correlation.correlation.toFixed(3)}</span></div>
                        <div><strong>Network Delay:</strong> <span class="text-yellow-400">${results.timing_correlation.delay.toFixed(2)}s</span></div>
                        <div><strong>Entry Packets:</strong> <span class="text-cyan-400">${results.timing_correlation.entry_packets}</span></div>
                    </div>
                </div>
                <div class="bg-steel-gray rounded-lg p-4">
                    <h4 class="font-bold text-cyber-blue mb-2">Traffic Analysis</h4>
                    <div class="grid grid-cols-2 gap-4 text-sm">
                        <div><strong>Flow Correlation:</strong> <span class="text-red-400">${(results.traffic_analysis.avg_confidence * 100).toFixed(1)}%</span></div>
                        <div><strong>Total Flows:</strong> <span class="text-matrix-green">${results.traffic_analysis.total_flows}</span></div>
                        <div><strong>Analyzed Flows:</strong> <span class="text-yellow-400">${results.traffic_analysis.flows.length}</span></div>
                        <div><strong>Correlation Strength:</strong> <span class="text-cyan-400">${results.correlation_strength}</span></div>
                    </div>
                </div>
                <div class="bg-steel-gray rounded-lg p-4">
                    <h4 class="font-bold text-cyber-blue mb-2">Website Fingerprinting</h4>
                    <div class="grid grid-cols-2 gap-4 text-sm">
                        <div><strong>ML Confidence:</strong> <span class="text-red-400">${(results.website_fingerprinting.avg_confidence * 100).toFixed(1)}%</span></div>
                        <div><strong>Websites Detected:</strong> <span class="text-matrix-green">${results.website_fingerprinting.total_fingerprints}</span></div>
                        <div><strong>Overall Confidence:</strong> <span class="text-yellow-400">${(results.overall_confidence * 100).toFixed(1)}%</span></div>
                        <div><strong>Analysis Time:</strong> <span class="text-cyan-400">${new Date(results.timestamp).toLocaleTimeString()}</span></div>
                    </div>
                </div>
            </div>
        `;
    }

    updateWebsiteFingerprints() {
        const container = document.getElementById('websiteFingerprints');
        if (!container || !this.correlationData) return;

        const websites = this.correlationData.website_fingerprinting;
        
        if (!websites.website_counts || Object.keys(websites.website_counts).length === 0) {
            container.innerHTML = `
                <div class="text-center text-gray-400 py-8">
                    <div class="text-4xl mb-2">🌐</div>
                    <div>No websites detected</div>
                    <div class="text-sm mt-2">Website fingerprinting requires active traffic</div>
                </div>
            `;
            return;
        }

        container.innerHTML = '';
        
        Object.entries(websites.website_counts).forEach(([website, count]) => {
            const confidence = websites.websites.find(w => w.website === website)?.confidence || 0;
            
            const item = document.createElement('div');
            item.className = 'flex justify-between items-center p-3 bg-steel-gray rounded';
            item.innerHTML = `
                <div>
                    <div class="font-medium text-cyber-blue">${website}</div>
                    <div class="text-xs text-gray-400">${count} visits detected</div>
                </div>
                <div class="text-right">
                    <div class="text-sm font-bold text-matrix-green">${(confidence * 100).toFixed(1)}%</div>
                    <div class="text-xs text-gray-400">confidence</div>
                </div>
            `;
            container.appendChild(item);
        });
    }

    updateCircuitCorrelations() {
        const container = document.getElementById('circuitCorrelations');
        if (!container || !this.correlationData) return;

        const circuits = this.correlationData.circuit_correlations;
        
        if (!circuits.circuit_pairs || circuits.circuit_pairs.length === 0) {
            container.innerHTML = `
                <div class="text-center text-gray-400 py-8">
                    <div class="text-4xl mb-2">🔗</div>
                    <div>No circuit correlations found</div>
                    <div class="text-sm mt-2">Correlations appear when multiple circuits are active</div>
                </div>
            `;
            return;
        }

        container.innerHTML = '';
        
        circuits.circuit_pairs.forEach((pair, index) => {
            const item = document.createElement('div');
            item.className = 'p-3 bg-steel-gray rounded';
            item.innerHTML = `
                <div class="flex justify-between items-start mb-2">
                    <div class="font-medium text-cyber-blue">Circuit Pair ${index + 1}</div>
                    <div class="text-sm font-bold text-red-400">${(pair.correlation.confidence * 100).toFixed(1)}%</div>
                </div>
                <div class="text-xs text-gray-300 mb-1">
                    <strong>Flow 1:</strong> ${pair.flow1.split('-')[0]} → ${pair.flow1.split('-')[1]}
                </div>
                <div class="text-xs text-gray-300 mb-2">
                    <strong>Flow 2:</strong> ${pair.flow2.split('-')[0]} → ${pair.flow2.split('-')[1]}
                </div>
                <div class="grid grid-cols-2 gap-2 text-xs">
                    <div>Size Sim: ${(pair.correlation.size_similarity * 100).toFixed(0)}%</div>
                    <div>Vol Sim: ${(pair.correlation.volume_similarity * 100).toFixed(0)}%</div>
                    <div>Time Sim: ${(pair.correlation.timing_similarity * 100).toFixed(0)}%</div>
                    <div>Seq Corr: ${(pair.correlation.sequence_correlation * 100).toFixed(0)}%</div>
                </div>
            `;
            container.appendChild(item);
        });
    }

    updateOriginCandidates() {
        const container = document.getElementById('originCandidates');
        if (!container || !this.correlationData) return;

        // Generate origin candidates based on correlation data
        const candidates = this.generateOriginCandidates();
        
        container.innerHTML = '';
        
        candidates.forEach((candidate, index) => {
            const item = document.createElement('div');
            item.className = 'bg-steel-gray rounded-lg p-4';
            item.innerHTML = `
                <div class="flex justify-between items-center mb-3">
                    <div>
                        <div class="font-bold text-cyber-blue">${candidate.ip}</div>
                        <div class="text-sm text-gray-300">${candidate.location}</div>
                    </div>
                    <div class="text-right">
                        <div class="text-lg font-bold ${candidate.probability > 70 ? 'text-red-400' : candidate.probability > 40 ? 'text-yellow-400' : 'text-green-400'}">${candidate.probability}%</div>
                        <div class="text-xs text-gray-400">probability</div>
                    </div>
                </div>
                <div class="probability-bar mb-2">
                    <div class="probability-indicator" style="width: ${candidate.probability}%"></div>
                </div>
                <div class="text-xs text-gray-300">
                    <div><strong>Evidence:</strong> ${candidate.evidence}</div>
                    <div><strong>Correlation:</strong> ${candidate.correlation}</div>
                </div>
            `;
            container.appendChild(item);
        });
    }

    generateOriginCandidates() {
        if (!this.correlationData) return [];

        const candidates = [];
        const circuits = this.correlationData.circuit_correlations.circuit_pairs;
        
        // Extract IPs from circuit correlations
        const ips = new Set();
        circuits.forEach(pair => {
            const ip1 = pair.flow1.split(':')[0];
            const ip2 = pair.flow2.split(':')[0];
            ips.add(ip1);
            ips.add(ip2);
        });

        // Generate candidates with probabilities
        Array.from(ips).slice(0, 5).forEach((ip, index) => {
            const confidence = circuits.find(c => 
                c.flow1.includes(ip) || c.flow2.includes(ip)
            )?.correlation.confidence || 0;
            
            candidates.push({
                ip: ip,
                location: this.getRandomLocation(),
                probability: Math.round(confidence * 100),
                evidence: `${circuits.length} circuit correlations`,
                correlation: `${(confidence * 100).toFixed(1)}% match confidence`
            });
        });

        return candidates.sort((a, b) => b.probability - a.probability);
    }

    getRandomLocation() {
        const locations = [
            'New York, USA',
            'London, UK', 
            'Berlin, Germany',
            'Tokyo, Japan',
            'Sydney, Australia',
            'Toronto, Canada'
        ];
        return locations[Math.floor(Math.random() * locations.length)];
    }

    showNoDataMessage() {
        const containers = [
            'forensicsResults',
            'websiteFingerprints', 
            'circuitCorrelations'
        ];

        containers.forEach(containerId => {
            const container = document.getElementById(containerId);
            if (container) {
                container.innerHTML = `
                    <div class="text-center text-gray-400 py-8">
                        <div class="text-4xl mb-2">🔍</div>
                        <div>No correlation analysis available</div>
                        <div class="text-sm mt-2">Start packet capture and run correlation analysis</div>
                    </div>
                `;
            }
        });
    }

    startPeriodicUpdates() {
        // Check for new correlation results every 10 seconds
        setInterval(async () => {
            await this.refreshCorrelationData();
        }, 10000);
    }

    showNotification(message, type = 'info') {
        console.log(`${type.toUpperCase()}: ${message}`);
        
        // Create notification element
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

// Initialize forensics correlation
document.addEventListener('DOMContentLoaded', function() {
    window.forensicsCorrelation = new ForensicsCorrelation();
    console.log('Forensics Correlation initialized');
});