// Clean Network Topology Visualization for TOR Unveil
class NetworkTopology {
    constructor() {
        this.apiBase = 'http://localhost:5000/api';
        this.nodes = [];
        this.links = [];
        this.allNodes = [];
        this.allLinks = [];
        this.chart = null;
        this.activeFilters = new Set(['Guard', 'Middle', 'Exit']);
        this.init();
    }

    init() {
        this.initializeChart();
        this.setupFilters();
        this.loadData();
        setInterval(() => this.loadData(), 8000);
    }

    initializeChart() {
        const chartDom = document.getElementById('networkTopology');
        if (!chartDom) return;

        this.chart = echarts.init(chartDom);
        
        const option = {
            backgroundColor: 'transparent',
            tooltip: {
                trigger: 'item',
                backgroundColor: 'rgba(45, 55, 72, 0.95)',
                borderColor: '#00d4ff',
                textStyle: { color: '#e2e8f0' },
                formatter: (params) => {
                    if (params.dataType === 'node') {
                        const node = params.data;
                        return `
                            <div style="font-family: 'JetBrains Mono', monospace; font-size: 12px;">
                                <div style="color: #00d4ff; font-weight: bold; margin-bottom: 8px;">${node.name}</div>
                                <div><strong>Type:</strong> ${node.nodeType}</div>
                                <div><strong>Country:</strong> ${node.country || 'Unknown'}</div>
                                <div><strong>Circuits:</strong> ${node.circuits || 0}</div>
                                <div><strong>Status:</strong> <span style="color: #00ff88;">${node.status || 'Active'}</span></div>
                            </div>
                        `;
                    } else {
                        return `
                            <div style="font-family: 'JetBrains Mono', monospace; font-size: 12px;">
                                <strong>Circuit Connection</strong><br/>
                                ${params.data.source} → ${params.data.target}
                            </div>
                        `;
                    }
                }
            },
            series: [{
                name: 'TOR Network',
                type: 'graph',
                layout: 'force',
                animation: true,
                animationDuration: 1500,
                force: {
                    repulsion: 800,
                    gravity: 0.03,
                    edgeLength: [120, 200],
                    layoutAnimation: true,
                    friction: 0.6
                },
                draggable: true,
                roam: true,
                focusNodeAdjacency: true,
                nodeScaleRatio: 0.8,
                categories: [
                    { 
                        name: 'Guard', 
                        itemStyle: { 
                            color: '#3b82f6',
                            shadowBlur: 15,
                            shadowColor: 'rgba(59, 130, 246, 0.6)',
                            borderColor: '#1e40af',
                            borderWidth: 2
                        }
                    },
                    { 
                        name: 'Middle', 
                        itemStyle: { 
                            color: '#10b981',
                            shadowBlur: 15,
                            shadowColor: 'rgba(16, 185, 129, 0.6)',
                            borderColor: '#047857',
                            borderWidth: 2
                        }
                    },
                    { 
                        name: 'Exit', 
                        itemStyle: { 
                            color: '#f59e0b',
                            shadowBlur: 15,
                            shadowColor: 'rgba(245, 158, 11, 0.6)',
                            borderColor: '#d97706',
                            borderWidth: 2
                        }
                    }
                ],
                label: {
                    show: false
                },
                lineStyle: {
                    color: 'rgba(0, 212, 255, 0.4)',
                    width: 2,
                    curveness: 0.2,
                    opacity: 0.7
                },
                emphasis: {
                    focus: 'adjacency',
                    lineStyle: {
                        width: 4,
                        opacity: 1,
                        color: '#00ff88'
                    },
                    itemStyle: {
                        shadowBlur: 25
                    }
                },
                data: [],
                links: []
            }]
        };

        this.chart.setOption(option);
        
        window.addEventListener('resize', () => {
            if (this.chart) {
                this.chart.resize();
            }
        });
    }

    setupFilters() {
        const filterButtons = document.querySelectorAll('.filter-btn');
        filterButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                const nodeType = btn.dataset.type;
                
                if (this.activeFilters.has(nodeType)) {
                    this.activeFilters.delete(nodeType);
                    btn.classList.remove('active');
                    btn.style.opacity = '0.5';
                } else {
                    this.activeFilters.add(nodeType);
                    btn.classList.add('active');
                    btn.style.opacity = '1';
                }
                
                this.applyFilters();
            });
        });
    }

    applyFilters() {
        // Filter nodes based on active filters
        this.nodes = this.allNodes.filter(node => 
            this.activeFilters.has(node.nodeType)
        );
        
        // Filter links to only show connections between visible nodes
        const visibleNodeIds = new Set(this.nodes.map(n => n.id));
        this.links = this.allLinks.filter(link => 
            visibleNodeIds.has(link.source) && visibleNodeIds.has(link.target)
        );
        
        this.updateChart();
    }

    async loadData() {
        try {
            const headers = { 'X-API-Key': 'changeme' };
            const resp = await fetch(`${this.apiBase}/circuits`, { headers });
            
            if (resp.ok) {
                const text = await resp.text();
                let circuitsData;
                try {
                    circuitsData = JSON.parse(text);
                } catch (e) {
                    const i = Math.min(...[text.indexOf('{'), text.indexOf('[')].filter(x => x >= 0));
                    if (isFinite(i)) {
                        circuitsData = JSON.parse(text.slice(i));
                    } else {
                        throw e;
                    }
                }
                this.processData(circuitsData);
            } else {
                this.generateSimulatedData();
            }
            
            this.applyFilters();
        } catch (error) {
            console.warn('Using simulated data:', error);
            this.generateSimulatedData();
            this.applyFilters();
        }
    }

    processData(circuitsData) {
        const nodeMap = new Map();
        const linkSet = new Set();
        
        const circuits = circuitsData.circuits || [];
        
        circuits.forEach(circuit => {
            const path = circuit.path || [];
            
            path.forEach((hop, index) => {
                const nodeId = hop.fingerprint || `node_${index}_${circuit.id}`;
                
                let nodeType = 'Middle';
                if (index === 0) nodeType = 'Guard';
                if (index === path.length - 1) nodeType = 'Exit';
                
                if (!nodeMap.has(nodeId)) {
                    nodeMap.set(nodeId, {
                        id: nodeId,
                        name: hop.nickname || `${nodeType}_${nodeId.substring(0, 6)}`,
                        nodeType: nodeType,
                        category: this.getNodeCategory(nodeType),
                        symbolSize: this.getNodeSize(nodeType),
                        country: this.getRandomCountry(),
                        circuits: 1,
                        status: 'Active'
                    });
                } else {
                    const node = nodeMap.get(nodeId);
                    node.circuits = (node.circuits || 0) + 1;
                    node.symbolSize = this.getNodeSize(nodeType, node.circuits);
                }
            });
            
            for (let i = 0; i < path.length - 1; i++) {
                const sourceId = path[i].fingerprint || `node_${i}_${circuit.id}`;
                const targetId = path[i + 1].fingerprint || `node_${i + 1}_${circuit.id}`;
                const linkId = `${sourceId}-${targetId}`;
                
                if (!linkSet.has(linkId)) {
                    linkSet.add(linkId);
                    this.allLinks.push({
                        source: sourceId,
                        target: targetId,
                        circuit: circuit.id
                    });
                }
            }
        });
        
        this.allNodes = Array.from(nodeMap.values());
    }

    generateSimulatedData() {
        this.allNodes = [];
        this.allLinks = [];
        
        const nodeTypes = [
            { type: 'Guard', count: 12 },
            { type: 'Middle', count: 18 },
            { type: 'Exit', count: 8 }
        ];
        
        let nodeId = 0;
        
        nodeTypes.forEach(nodeTypeInfo => {
            for (let i = 0; i < nodeTypeInfo.count; i++) {
                const id = `node_${nodeId++}`;
                this.allNodes.push({
                    id: id,
                    name: `${nodeTypeInfo.type}_${i + 1}`,
                    nodeType: nodeTypeInfo.type,
                    category: this.getNodeCategory(nodeTypeInfo.type),
                    symbolSize: this.getNodeSize(nodeTypeInfo.type),
                    country: this.getRandomCountry(),
                    circuits: Math.floor(Math.random() * 8) + 1,
                    status: Math.random() < 0.95 ? 'Active' : 'Degraded'
                });
            }
        });
        
        const guardNodes = this.allNodes.filter(n => n.nodeType === 'Guard');
        const middleNodes = this.allNodes.filter(n => n.nodeType === 'Middle');
        const exitNodes = this.allNodes.filter(n => n.nodeType === 'Exit');
        
        for (let i = 0; i < 20; i++) {
            const guard = guardNodes[Math.floor(Math.random() * guardNodes.length)];
            const middle = middleNodes[Math.floor(Math.random() * middleNodes.length)];
            const exit = exitNodes[Math.floor(Math.random() * exitNodes.length)];
            
            this.allLinks.push(
                { source: guard.id, target: middle.id, circuit: `circuit_${i}_1` },
                { source: middle.id, target: exit.id, circuit: `circuit_${i}_2` }
            );
        }
    }

    getRandomCountry() {
        const countries = ['US', 'DE', 'NL', 'FR', 'UK', 'CA', 'SE', 'CH', 'JP', 'AU'];
        return countries[Math.floor(Math.random() * countries.length)];
    }

    getNodeCategory(nodeType) {
        switch (nodeType) {
            case 'Guard': return 0;
            case 'Exit': return 2;
            default: return 1;
        }
    }

    getNodeSize(nodeType, circuitCount = 1) {
        const baseSizes = {
            'Guard': 25,
            'Middle': 20,
            'Exit': 30
        };
        const baseSize = baseSizes[nodeType] || 20;
        return Math.min(baseSize + Math.log(circuitCount) * 3, 45);
    }

    updateChart() {
        if (!this.chart) return;
        
        this.chart.setOption({
            series: [{
                data: this.nodes,
                links: this.links
            }]
        });
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Check if we're on the topology page
    if (document.getElementById('networkTopology')) {
        window.networkTopology = new NetworkTopology();
        console.log('Network Topology Visualization initialized');
    }
});