// Live Data Manager - Connects Topology and Geo with Real TOR Data
class LiveDataManager {
    constructor() {
        this.apiBase = 'http://localhost:5001/api';
        this.nodes = new Map();
        this.circuits = new Map();
        this.selectedNode = null;
        this.updateInterval = null;
        this.init();
    }

    async init() {
        await this.fetchLiveData();
        this.startRealTimeUpdates();
        this.setupEventListeners();
    }

    async fetchLiveData() {
        try {
            // Fetch real TOR relays
            const relaysResponse = await fetch(`${this.apiBase}/relays`, {
                headers: { 'X-API-KEY': 'changeme' }
            });
            const relaysData = await relaysResponse.json();
            
            // Fetch active circuits
            const circuitsResponse = await fetch(`${this.apiBase}/circuits`, {
                headers: { 'X-API-KEY': 'changeme' }
            });
            const circuitsData = await circuitsResponse.json();

            this.processRelaysData(relaysData);
            this.processCircuitsData(circuitsData);
            
        } catch (error) {
            console.warn('Using fallback data:', error);
            this.generateFallbackData();
        }
    }

    processRelaysData(data) {
        if (data.relays) {
            data.relays.slice(0, 100).forEach(relay => {
                const node = {
                    id: relay.fingerprint,
                    name: relay.nickname || 'Unknown',
                    ip: relay.or_addresses?.[0]?.split(':')[0] || 'Unknown',
                    country: relay.country || 'Unknown',
                    type: this.determineNodeType(relay.flags),
                    bandwidth: relay.observed_bandwidth || 0,
                    lat: this.getCountryCoords(relay.country)?.lat || 0,
                    lon: this.getCountryCoords(relay.country)?.lon || 0,
                    flags: relay.flags || [],
                    uptime: relay.uptime || 0
                };
                this.nodes.set(node.id, node);
            });
        }
    }

    processCircuitsData(data) {
        if (data.circuits) {
            Object.entries(data.circuits).forEach(([id, circuit]) => {
                this.circuits.set(id, {
                    id,
                    path: circuit.path || [],
                    status: circuit.status || 'UNKNOWN',
                    purpose: circuit.purpose || 'GENERAL'
                });
            });
        }
    }

    determineNodeType(flags) {
        if (!flags) return 'guard';
        if (flags.includes('Guard')) return 'guard';
        if (flags.includes('Exit')) return 'exit';
        if (flags.includes('HSDir')) return 'hsdir';
        return 'guard';
    }

    getCountryCoords(countryCode) {
        const coords = {
            'US': { lat: 39.0, lon: -98.0 },
            'DE': { lat: 51.0, lon: 9.0 },
            'NL': { lat: 52.0, lon: 5.0 },
            'FR': { lat: 46.0, lon: 2.0 },
            'GB': { lat: 54.0, lon: -4.0 },
            'CA': { lat: 56.0, lon: -106.0 },
            'SE': { lat: 60.0, lon: 18.0 },
            'CH': { lat: 47.0, lon: 8.0 },
            'RU': { lat: 61.0, lon: 105.0 },
            'JP': { lat: 36.0, lon: 138.0 },
            'AU': { lat: -27.0, lon: 133.0 },
            'IN': { lat: 20.0, lon: 77.0 },
            'SG': { lat: 1.0, lon: 104.0 },
            'BR': { lat: -14.0, lon: -51.0 }
        };
        return coords[countryCode] || { lat: 0, lon: 0 };
    }

    generateFallbackData() {
        const countries = ['US', 'DE', 'NL', 'FR', 'GB', 'CA', 'SE', 'CH', 'RU', 'JP'];
        const types = ['guard', 'middle', 'exit'];
        
        for (let i = 0; i < 50; i++) {
            const country = countries[Math.floor(Math.random() * countries.length)];
            const coords = this.getCountryCoords(country);
            const type = types[Math.floor(Math.random() * types.length)];
            
            const node = {
                id: `node_${i}`,
                name: `${type}_${country}_${i}`,
                ip: this.generateRandomIP(),
                country,
                type,
                bandwidth: Math.floor(Math.random() * 1000000),
                lat: coords.lat + (Math.random() - 0.5) * 10,
                lon: coords.lon + (Math.random() - 0.5) * 10,
                flags: [type === 'guard' ? 'Guard' : type === 'exit' ? 'Exit' : 'Stable'],
                uptime: Math.floor(Math.random() * 86400)
            };
            this.nodes.set(node.id, node);
        }
    }

    generateRandomIP() {
        return Array.from({length: 4}, () => Math.floor(Math.random() * 256)).join('.');
    }

    startRealTimeUpdates() {
        this.updateInterval = setInterval(() => {
            this.fetchLiveData();
            this.updateVisualizations();
        }, 10000); // Update every 10 seconds
    }

    updateVisualizations() {
        this.updateTopology();
        this.updateGeoVisualization();
    }

    updateTopology() {
        if (!window.torUnveil?.topologyChart) return;

        const nodes = Array.from(this.nodes.values()).map(node => ({
            id: node.id,
            name: node.name,
            category: this.getNodeCategory(node.type),
            ip: node.ip,
            country: node.country,
            bandwidth: `${Math.floor(node.bandwidth / 1000)} KB/s`,
            symbolSize: Math.min(Math.max(node.bandwidth / 50000 + 15, 10), 40),
            itemStyle: {
                color: this.getNodeColor(node.type)
            }
        }));

        const links = this.generateTopologyLinks(nodes);

        window.torUnveil.topologyChart.setOption({
            series: [{
                data: nodes,
                links: links
            }]
        });
    }

    updateGeoVisualization() {
        if (!window.torVisualization) return;

        // Update the geo visualization with real node data
        const geoNodes = Array.from(this.nodes.values()).map(node => ({
            id: node.id,
            x: this.lonToPercent(node.lon),
            y: this.latToPercent(node.lat),
            label: node.country,
            type: node.type,
            ip: node.ip,
            name: node.name,
            bandwidth: node.bandwidth
        }));

        window.torVisualization.nodes = geoNodes;
        window.torVisualization.createVisualization();
    }

    lonToPercent(lon) {
        return ((lon + 180) / 360) * 100;
    }

    latToPercent(lat) {
        return ((90 - lat) / 180) * 100;
    }

    getNodeCategory(type) {
        const categories = {
            'guard': 'Guard Node',
            'exit': 'Exit Node',
            'hsdir': 'Bridge Node'
        };
        return categories[type] || 'Guard Node';
    }

    getNodeColor(type) {
        const colors = {
            'guard': '#00d4ff',
            'middle': '#a855f7',
            'exit': '#ff6b6b',
            'hsdir': '#ff8c00'
        };
        return colors[type] || '#a855f7';
    }

    generateTopologyLinks(nodes) {
        const links = [];
        const guardNodes = nodes.filter(n => n.category === 'Guard Node');
        const exitNodes = nodes.filter(n => n.category === 'Exit Node');
        const bridgeNodes = nodes.filter(n => n.category === 'Bridge Node');

        // Create direct circuit paths: Guard -> Exit
        for (let i = 0; i < Math.min(20, guardNodes.length); i++) {
            const guard = guardNodes[i];
            const exit = exitNodes[Math.floor(Math.random() * exitNodes.length)];

            if (guard && exit) {
                links.push({ source: guard.id, target: exit.id });
            }
        }

        // Connect bridges to guards
        bridgeNodes.forEach(bridge => {
            const guard = guardNodes[Math.floor(Math.random() * guardNodes.length)];
            if (guard) {
                links.push({ source: bridge.id, target: guard.id });
            }
        });

        return links;
    }

    setupEventListeners() {
        // Listen for topology node clicks
        if (window.torUnveil?.topologyChart) {
            window.torUnveil.topologyChart.off('click');
            window.torUnveil.topologyChart.on('click', (params) => {
                if (params.dataType === 'node') {
                    this.selectNode(params.data.id);
                }
            });
        }
    }

    selectNode(nodeId) {
        this.selectedNode = nodeId;
        const node = this.nodes.get(nodeId);
        
        if (node) {
            // Highlight in topology
            this.highlightTopologyNode(nodeId);
            
            // Focus on geo location
            this.focusGeoLocation(node);
            
            // Show node details
            this.showNodeDetails(node);
        }
    }

    highlightTopologyNode(nodeId) {
        if (!window.torUnveil?.topologyChart) return;

        window.torUnveil.topologyChart.dispatchAction({
            type: 'highlight',
            seriesIndex: 0,
            dataIndex: nodeId
        });
    }

    focusGeoLocation(node) {
        if (!window.torVisualization) return;

        // Find and highlight the corresponding geo node
        const geoNode = window.torVisualization.nodes.find(n => n.id === node.id);
        if (geoNode) {
            // Add visual highlight to the geo node
            const nodeElement = document.querySelector(`[data-node-id="${node.id}"]`);
            if (nodeElement) {
                nodeElement.classList.add('highlighted');
                nodeElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }
    }

    showNodeDetails(node) {
        // Remove existing details
        const existing = document.getElementById('nodeDetails');
        if (existing) existing.remove();

        // Create details panel
        const details = document.createElement('div');
        details.id = 'nodeDetails';
        details.className = 'fixed top-20 left-4 z-50 glass-panel rounded-lg p-4 max-w-sm';
        details.innerHTML = `
            <div class="flex justify-between items-center mb-3">
                <h3 class="cyber-font text-sm font-bold text-cyber-blue">Node Details</h3>
                <button onclick="this.parentElement.parentElement.remove()" class="text-gray-400 hover:text-white">✕</button>
            </div>
            <div class="space-y-2 text-xs mono-font">
                <div><strong>Name:</strong> ${node.name}</div>
                <div><strong>Type:</strong> ${node.type}</div>
                <div><strong>IP:</strong> ${node.ip}</div>
                <div><strong>Country:</strong> ${node.country}</div>
                <div><strong>Bandwidth:</strong> ${Math.floor(node.bandwidth / 1000)} KB/s</div>
                <div><strong>Flags:</strong> ${node.flags.join(', ')}</div>
                <div><strong>Uptime:</strong> ${Math.floor(node.uptime / 3600)}h</div>
            </div>
        `;
        document.body.appendChild(details);

        // Auto-remove after 10 seconds
        setTimeout(() => {
            if (details.parentElement) details.remove();
        }, 10000);
    }

    destroy() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }
    }
}

// Export for global access
window.LiveDataManager = LiveDataManager;