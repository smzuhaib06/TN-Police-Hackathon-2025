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
            // Wait for backend to be ready
            await this.waitForBackend();
            
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

    async waitForBackend(maxRetries = 5) {
        for (let i = 0; i < maxRetries; i++) {
            try {
                const response = await fetch('http://localhost:5000/api/health');
                if (response.ok) {
                    return true;
                }
            } catch (error) {
                // Backend not ready yet
            }
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
        throw new Error('Backend not available');
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
        const mapContainer = document.getElementById('worldMap');
        if (!mapContainer) return;

        // Wait for SVG to be loaded
        if (!window.worldMapLoader || !window.worldMapLoader.isLoaded()) {
            setTimeout(() => this.initGeoMap(), 500);
            return;
        }

        // Get the loaded SVG element
        const svgElement = mapContainer.querySelector('svg');
        if (!svgElement) return;

        // Clear existing pins
        const pinsContainer = svgElement.querySelector('#geo-pins');
        if (pinsContainer) {
            pinsContainer.innerHTML = '';
        }

        // Add geo pins for correlation data
        if (this.correlationData && this.correlationData.circuit_correlations.circuit_pairs.length > 0) {
            this.addGeoPins(svgElement, this.correlationData.circuit_correlations.circuit_pairs);
        }
    }

    addGeoPins(svgElement, circuitPairs) {
        const pinsContainer = svgElement.querySelector('#geo-pins');
        if (!pinsContainer) return;

        // Sample coordinates for demonstration (in SVG coordinate system)
        const locations = {
            'US': { x: 400, y: 300, name: 'United States' },
            'DE': { x: 1377, y: 280, name: 'Germany' },
            'JP': { x: 2200, y: 350, name: 'Japan' },
            'GB': { x: 1320, y: 250, name: 'United Kingdom' },
            'FR': { x: 1350, y: 300, name: 'France' },
            'RU': { x: 1600, y: 200, name: 'Russia' },
            'CN': { x: 2000, y: 350, name: 'China' },
            'BR': { x: 700, y: 700, name: 'Brazil' },
            'AU': { x: 2300, y: 900, name: 'Australia' },
            'CA': { x: 350, y: 200, name: 'Canada' }
        };

        circuitPairs.forEach((pair, index) => {
            // Extract country codes from IP addresses (simplified)
            const countries = Object.keys(locations);
            const sourceCountry = countries[index % countries.length];
            const destCountry = countries[(index + 1) % countries.length];

            const sourceLocation = locations[sourceCountry];
            const destLocation = locations[destCountry];

            // Add connection line
            const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('x1', sourceLocation.x);
            line.setAttribute('y1', sourceLocation.y);
            line.setAttribute('x2', destLocation.x);
            line.setAttribute('y2', destLocation.y);
            line.setAttribute('stroke', '#ff2d2d');
            line.setAttribute('stroke-width', '2');
            line.setAttribute('stroke-dasharray', '5,5');
            line.setAttribute('opacity', '0.7');
            line.innerHTML = `<animate attributeName="stroke-dashoffset" values="0;10" dur="1s" repeatCount="indefinite"/>`;
            pinsContainer.appendChild(line);

            // Add source pin
            const sourcePin = this.createGeoPin(sourceLocation.x, sourceLocation.y, sourceLocation.name, pair.correlation.confidence);
            pinsContainer.appendChild(sourcePin);

            // Add destination pin
            const destPin = this.createGeoPin(destLocation.x, destLocation.y, destLocation.name, pair.correlation.confidence);
            pinsContainer.appendChild(destPin);
        });
    }

    createGeoPin(x, y, location, confidence) {
        const pin = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        pin.setAttribute('class', 'geo-pin-group');
        pin.setAttribute('transform', `translate(${x}, ${y})`);

        // Pin circle
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('r', '8');
        circle.setAttribute('class', 'geo-pin');
        circle.setAttribute('fill', confidence > 0.7 ? '#ff2d2d' : confidence > 0.4 ? '#ffa500' : '#00ff88');
        
        // Pulse animation
        const pulseCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        pulseCircle.setAttribute('r', '8');
        pulseCircle.setAttribute('fill', 'none');
        pulseCircle.setAttribute('stroke', '#ffffff');
        pulseCircle.setAttribute('stroke-width', '2');
        pulseCircle.setAttribute('opacity', '0');
        pulseCircle.innerHTML = `
            <animate attributeName="r" values="8;20;8" dur="2s" repeatCount="indefinite"/>
            <animate attributeName="opacity" values="0.8;0;0.8" dur="2s" repeatCount="indefinite"/>
        `;

        // Tooltip
        const tooltip = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        tooltip.setAttribute('x', '12');
        tooltip.setAttribute('y', '5');
        tooltip.setAttribute('fill', '#ffffff');
        tooltip.setAttribute('font-size', '12');
        tooltip.setAttribute('font-family', 'monospace');
        tooltip.setAttribute('opacity', '0');
        tooltip.textContent = `${location} (${(confidence * 100).toFixed(1)}%)`;

        pin.appendChild(pulseCircle);
        pin.appendChild(circle);
        pin.appendChild(tooltip);

        // Hover events
        pin.addEventListener('mouseenter', () => {
            tooltip.setAttribute('opacity', '1');
            circle.setAttribute('r', '12');
        });
        
        pin.addEventListener('mouseleave', () => {
            tooltip.setAttribute('opacity', '0');
            circle.setAttribute('r', '8');
        });

        return pin;
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
        // Delay initial check to allow backend to start
        setTimeout(() => {
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
        }, 3000);
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