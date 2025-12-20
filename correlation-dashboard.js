// Real-time Correlation Dashboard
class CorrelationDashboard {
    constructor() {
        this.correlationData = null;
        this.isRunning = false;
        this.updateInterval = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.startPeriodicUpdates();
    }

    setupEventListeners() {
        // Run correlation analysis button
        const runBtn = document.getElementById('runCorrelation');
        if (runBtn) {
            runBtn.addEventListener('click', () => this.runCorrelationAnalysis());
        }

        // Auto-correlation toggle
        const autoBtn = document.getElementById('autoCorrelation');
        if (autoBtn) {
            autoBtn.addEventListener('change', (e) => {
                if (e.target.checked) {
                    this.startAutoCorrelation();
                } else {
                    this.stopAutoCorrelation();
                }
            });
        }
    }

    async runCorrelationAnalysis() {
        try {
            const response = await fetch('http://localhost:5000/api/correlation/run');
            const data = await response.json();
            
            if (data.status === 'success') {
                this.correlationData = data.results;
                this.updateDashboard();
                this.updateTopology();
                this.updateGeoMap();
                this.showNotification('Correlation analysis completed', 'success');
            } else {
                this.showNotification(`Correlation failed: ${data.message}`, 'error');
            }
        } catch (error) {
            this.showNotification('Failed to run correlation analysis', 'error');
            console.error('Correlation error:', error);
        }
    }

    async getCorrelationResults() {
        try {
            const response = await fetch('http://localhost:5000/api/correlation/results');
            const data = await response.json();
            
            if (data.status === 'success' && data.has_results) {
                this.correlationData = data.results;
                return true;
            }
            return false;
        } catch (error) {
            console.error('Failed to get correlation results:', error);
            return false;
        }
    }

    updateDashboard() {
        if (!this.correlationData) return;

        const results = this.correlationData;
        
        // Update correlation metrics
        this.updateElement('timingConfidence', (results.timing_correlation.confidence * 100).toFixed(1) + '%');
        this.updateElement('trafficConfidence', (results.traffic_analysis.avg_confidence * 100).toFixed(1) + '%');
        this.updateElement('fingerprintConfidence', (results.website_fingerprinting.avg_confidence * 100).toFixed(1) + '%');
        this.updateElement('overallConfidence', (results.overall_confidence * 100).toFixed(1) + '%');
        this.updateElement('correlationStrength', results.correlation_strength);

        // Update timing correlation details
        const timing = results.timing_correlation;
        this.updateElement('correlationCoeff', timing.correlation.toFixed(3));
        this.updateElement('networkDelay', timing.delay.toFixed(2) + 's');
        this.updateElement('entryPackets', timing.entry_packets);
        this.updateElement('exitPackets', timing.exit_packets);

        // Update traffic analysis
        const traffic = results.traffic_analysis;
        this.updateElement('totalFlows', traffic.total_flows);
        this.updateElement('analyzedFlows', traffic.flows.length);

        // Update website fingerprinting
        const websites = results.website_fingerprinting;
        this.updateElement('identifiedWebsites', websites.total_fingerprints);
        this.updateWebsiteList(websites.website_counts);

        // Update circuit correlations
        const circuits = results.circuit_correlations;
        this.updateElement('circuitPairs', circuits.total_correlations);
        this.updateCircuitList(circuits.circuit_pairs);

        // Update status indicators
        this.updateStatusIndicators(results);
    }

    updateElement(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    }

    updateWebsiteList(websiteCounts) {
        const container = document.getElementById('websiteList');
        if (!container) return;

        container.innerHTML = '';
        
        Object.entries(websiteCounts).forEach(([website, count]) => {
            const item = document.createElement('div');
            item.className = 'flex justify-between items-center py-1 px-2 bg-gray-700 rounded text-sm';
            item.innerHTML = `
                <span class="text-cyan-400">${website}</span>
                <span class="text-gray-300">${count} visits</span>
            `;
            container.appendChild(item);
        });
    }

    updateCircuitList(circuitPairs) {
        const container = document.getElementById('circuitList');
        if (!container) return;

        container.innerHTML = '';
        
        circuitPairs.forEach((pair, index) => {
            const item = document.createElement('div');
            item.className = 'py-2 px-3 bg-gray-700 rounded text-xs';
            item.innerHTML = `
                <div class="text-cyan-400 font-bold">Circuit ${index + 1}</div>
                <div class="text-gray-300">${pair.flow1.split('-')[0]} ↔ ${pair.flow2.split('-')[0]}</div>
                <div class="text-green-400">Confidence: ${(pair.correlation.confidence * 100).toFixed(1)}%</div>
            `;
            container.appendChild(item);
        });
    }

    updateStatusIndicators(results) {
        // Update correlation strength indicator
        const strengthEl = document.getElementById('correlationStrength');
        if (strengthEl) {
            strengthEl.className = `font-bold ${
                results.correlation_strength === 'HIGH' ? 'text-red-400' :
                results.correlation_strength === 'MEDIUM' ? 'text-yellow-400' : 'text-green-400'
            }`;
        }

        // Update confidence bars
        this.updateConfidenceBar('timingBar', results.timing_correlation.confidence);
        this.updateConfidenceBar('trafficBar', results.traffic_analysis.avg_confidence);
        this.updateConfidenceBar('fingerprintBar', results.website_fingerprinting.avg_confidence);
        this.updateConfidenceBar('overallBar', results.overall_confidence);
    }

    updateConfidenceBar(id, confidence) {
        const bar = document.getElementById(id);
        if (bar) {
            const percentage = confidence * 100;
            bar.style.width = percentage + '%';
            bar.className = `h-2 rounded transition-all duration-500 ${
                percentage > 70 ? 'bg-red-500' :
                percentage > 40 ? 'bg-yellow-500' : 'bg-green-500'
            }`;
        }
    }

    updateTopology() {
        if (!this.correlationData || !window.torUnveil?.topology) return;

        const results = this.correlationData;
        const topology = window.torUnveil.topology;

        // Highlight correlated nodes
        if (results.circuit_correlations.circuit_pairs.length > 0) {
            const correlatedNodes = [];
            
            results.circuit_correlations.circuit_pairs.forEach(pair => {
                const flow1IP = pair.flow1.split(':')[0];
                const flow2IP = pair.flow2.split(':')[0];
                correlatedNodes.push(flow1IP, flow2IP);
            });

            // Update topology visualization with correlation data
            if (topology.chart) {
                const option = topology.chart.getOption();
                const nodes = option.series[0].data;
                
                nodes.forEach(node => {
                    if (correlatedNodes.includes(node.ip)) {
                        node.itemStyle = {
                            ...node.itemStyle,
                            borderColor: '#ff2d2d',
                            borderWidth: 4,
                            shadowColor: 'rgba(255, 45, 45, 0.8)',
                            shadowBlur: 25
                        };
                    }
                });

                topology.chart.setOption({
                    series: [{ data: nodes }]
                });
            }
        }
    }

    updateGeoMap() {
        if (!this.correlationData) return;

        // Update world map with correlation data
        const mapContainer = document.getElementById('worldMap');
        if (mapContainer && window.echarts) {
            this.initGeoMap();
        }
    }

    initGeoMap() {
        const mapDom = document.getElementById('worldMap');
        if (!mapDom) return;

        // Use Earth3D map instead of ECharts
        mapDom.innerHTML = `
            <iframe 
                src="https://earth3dmap.com/" 
                width="100%" 
                height="100%" 
                frameborder="0" 
                style="border-radius: 8px; background: #1a1a1a;"
                allowfullscreen>
            </iframe>
        `;
    }

    getRandomCoordinates() {
        // Generate random coordinates for demonstration
        const locations = [
            [-74.0059, 40.7128], // New York
            [2.3522, 48.8566],   // Paris
            [139.6917, 35.6895], // Tokyo
            [-0.1276, 51.5074],  // London
            [13.4050, 52.5200],  // Berlin
            [-122.4194, 37.7749] // San Francisco
        ];
        return locations[Math.floor(Math.random() * locations.length)];
    }

    startAutoCorrelation() {
        this.isRunning = true;
        this.updateInterval = setInterval(() => {
            this.runCorrelationAnalysis();
        }, 10000); // Run every 10 seconds
    }

    stopAutoCorrelation() {
        this.isRunning = false;
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
            this.updateInterval = null;
        }
    }

    startPeriodicUpdates() {
        // Check for new results every 5 seconds
        setInterval(async () => {
            if (!this.isRunning) {
                const hasResults = await this.getCorrelationResults();
                if (hasResults) {
                    this.updateDashboard();
                    this.updateTopology();
                    this.updateGeoMap();
                }
            }
        }, 5000);
    }

    showNotification(message, type = 'info') {
        // Use existing notification system from main dashboard
        if (window.showNotification) {
            window.showNotification(message, type);
        } else {
            console.log(`${type.toUpperCase()}: ${message}`);
        }
    }
}

// Initialize correlation dashboard
document.addEventListener('DOMContentLoaded', function() {
    window.correlationDashboard = new CorrelationDashboard();
    console.log('Correlation Dashboard initialized');
});