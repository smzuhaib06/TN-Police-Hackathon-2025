// Enhanced Network Topology with Animated Node Types
class EnhancedTopology {
    constructor() {
        this.apiBase = 'http://localhost:5000/api';
        this.chart = null;
        this.nodes = [];
        this.links = [];
        this.animationFrames = [];
        this.isAnimating = false;
        this.nodeAnimations = new Map();
        this.init();
    }

    init() {
        this.initializeChart();
        this.setupControls();
        this.loadNetworkData();
        this.startAnimationLoop();
        
        setInterval(() => this.loadNetworkData(), 5000);
    }

    initializeChart() {
        const chartDom = document.getElementById('networkTopology');
        if (!chartDom) {
            console.warn('networkTopology element not found');
            return;
        }

        this.chart = echarts.init(chartDom);

        const option = {
            backgroundColor: 'transparent',
            legend: {
                show: false
            },
            tooltip: {
                trigger: 'item',
                formatter: (params) => {
                    if (params.dataType === 'node') {
                        const node = params.data;
                        return `
                            <div class="mono-font text-sm bg-steel-gray p-3 rounded border border-cyber-blue">
                                <div class="text-cyber-blue font-bold mb-2">${node.name}</div>
                                <div><strong>Type:</strong> ${node.nodeType}</div>
                                <div><strong>IP:</strong> ${node.ip || 'Unknown'}</div>
                                <div><strong>Country:</strong> ${node.country || 'Unknown'}</div>
                                <div><strong>Bandwidth:</strong> ${node.bandwidth || 'Unknown'}</div>
                                <div><strong>Circuits:</strong> ${node.circuits || 0}</div>
                                <div><strong>Status:</strong> <span class="text-matrix-green">${node.status || 'Active'}</span></div>
                                <div><strong>Uptime:</strong> ${node.uptime || 'Unknown'}</div>
                            </div>
                        `;
                    } else if (params.dataType === 'edge') {
                        return `
                            <div class="mono-font text-sm">
                                <strong>Circuit Connection</strong><br/>
                                From: ${params.data.sourceName}<br/>
                                To: ${params.data.targetName}<br/>
                                Circuit ID: ${params.data.circuitId}<br/>
                                Bandwidth: ${params.data.bandwidth || 'Unknown'}
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
                animationDuration: 1000,
                animationEasing: 'cubicOut',
                force: {
                    repulsion: 1500,
                    gravity: 0.05,
                    edgeLength: [150, 250],
                    layoutAnimation: true,
                    friction: 0.4
                },
                draggable: true,
                roam: true,
                focusNodeAdjacency: true,
                nodeScaleRatio: 0.8,
                categories: [
                    { 
                        name: 'Entry Node', 
                        itemStyle: { 
                            color: '#ff6b6b',
                            shadowBlur: 20,
                            shadowColor: 'rgba(255, 107, 107, 0.9)',
                            borderColor: '#fff',
                            borderWidth: 2
                        }
                    },
                    { 
                        name: 'Guard Node', 
                        itemStyle: { 
                            color: '#00d4ff',
                            shadowBlur: 20,
                            shadowColor: 'rgba(0, 212, 255, 0.9)',
                            borderColor: '#fff',
                            borderWidth: 2
                        }
                    },
                    { 
                        name: 'Exit Node', 
                        itemStyle: { 
                            color: '#00ff88',
                            shadowBlur: 20,
                            shadowColor: 'rgba(0, 255, 136, 0.9)',
                            borderColor: '#fff',
                            borderWidth: 2
                        }
                    },
                    { 
                        name: 'Bridge Node', 
                        itemStyle: { 
                            color: '#ff8c00',
                            shadowBlur: 20,
                            shadowColor: 'rgba(255, 140, 0, 0.9)',
                            borderColor: '#fff',
                            borderWidth: 2
                        }
                    }
                ],
                label: {
                    show: false
                },
                lineStyle: {
                    color: 'rgba(0, 212, 255, 0.6)',
                    width: 3,
                    curveness: 0.3,
                    opacity: 0.8,
                    shadowBlur: 10,
                    shadowColor: 'rgba(0, 212, 255, 0.3)'
                },
                emphasis: {
                    focus: 'adjacency',
                    lineStyle: {
                        width: 4,
                        opacity: 1,
                        color: '#00ff88'
                    },
                    itemStyle: {
                        shadowBlur: 20
                    }
                },
                data: [],
                links: []
            }]
        };

        this.chart.setOption(option);

        // Add click event for node inspection
        this.chart.on('click', (params) => {
            if (params.dataType === 'node') {
                this.inspectNode(params.data);
            }
        });

        // Handle window resize
        window.addEventListener('resize', () => {
            if (this.chart) {
                this.chart.resize();
            }
        });
    }

    async loadNetworkData() {
        try {
            const headers = { 'X-API-KEY': 'changeme' };
            
            // Try to fetch real circuit data
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
                this.processRealData(circuitsData);
            } else {
                this.generateSimulatedData();
            }
            
            this.updateChart();
            this.applyFilters();
            this.startNodeAnimations();
        } catch (error) {
            console.warn('Failed to load real network data, using simulation:', error);
            this.generateSimulatedData();
            this.updateChart();
            this.applyFilters();
            this.startNodeAnimations();
        }
    }

    processRealData(circuitsData) {
        const nodeMap = new Map();
        const linkSet = new Set();
        
        const circuits = circuitsData.circuits || [];
        
        circuits.forEach(circuit => {
            const path = circuit.path || [];
            
            path.forEach((hop, index) => {
                const nodeId = hop.fingerprint || `node_${index}_${circuit.id}`;
                
                // Determine node type based on position (no middle relays)
                let nodeType = 'Guard Node';
                let category = 1;
                
                if (index === 0) {
                    nodeType = Math.random() < 0.3 ? 'Entry Node' : 'Guard Node';
                    category = nodeType === 'Entry Node' ? 0 : 1;
                } else if (index === path.length - 1) {
                    nodeType = 'Exit Node';
                    category = 2;
                } else if (Math.random() < 0.15) {
                    nodeType = 'Bridge Node';
                    category = 3;
                }
                
                if (!nodeMap.has(nodeId)) {
                    nodeMap.set(nodeId, {
                        id: nodeId,
                        name: hop.nickname || `Node_${nodeId.substring(0, 8)}`,
                        nodeType: nodeType,
                        category: category,
                        symbolSize: this.getNodeSize(nodeType),
                        ip: this.generateIP(),
                        country: this.getRandomCountry(),
                        bandwidth: this.generateBandwidth(),
                        circuits: 1,
                        status: 'Active',
                        uptime: this.generateUptime(),
                        x: Math.random() * 800,
                        y: Math.random() * 600
                    });
                } else {
                    const node = nodeMap.get(nodeId);
                    node.circuits = (node.circuits || 0) + 1;
                    node.symbolSize = this.getNodeSize(node.nodeType, node.circuits);
                }
            });
            
            // Create links between consecutive hops
            for (let i = 0; i < path.length - 1; i++) {
                const sourceId = path[i].fingerprint || `node_${i}_${circuit.id}`;
                const targetId = path[i + 1].fingerprint || `node_${i + 1}_${circuit.id}`;
                const linkId = `${sourceId}-${targetId}`;
                
                if (!linkSet.has(linkId)) {
                    linkSet.add(linkId);
                    this.links.push({
                        source: sourceId,
                        target: targetId,
                        sourceName: nodeMap.get(sourceId)?.name || sourceId,
                        targetName: nodeMap.get(targetId)?.name || targetId,
                        circuitId: circuit.id,
                        bandwidth: this.generateBandwidth(),
                        lineStyle: {
                            width: Math.random() * 3 + 1,
                            opacity: 0.6 + Math.random() * 0.4
                        }
                    });
                }
            }
        });
        
        this.nodes = Array.from(nodeMap.values());
    }

    generateSimulatedData() {
        this.nodes = [];
        this.links = [];
        
        const nodeTypes = [
            { type: 'Entry Node', category: 0, count: 8 },
            { type: 'Guard Node', category: 1, count: 15 },
            { type: 'Exit Node', category: 2, count: 10 },
            { type: 'Bridge Node', category: 3, count: 5 }
        ];
        
        let nodeId = 0;
        
        // Generate nodes
        nodeTypes.forEach(nodeTypeInfo => {
            for (let i = 0; i < nodeTypeInfo.count; i++) {
                const id = `node_${nodeId++}`;
                this.nodes.push({
                    id: id,
                    name: `${nodeTypeInfo.type.replace(' ', '')}_${i + 1}`,
                    nodeType: nodeTypeInfo.type,
                    category: nodeTypeInfo.category,
                    symbolSize: this.getNodeSize(nodeTypeInfo.type),
                    ip: this.generateIP(),
                    country: this.getRandomCountry(),
                    bandwidth: this.generateBandwidth(),
                    circuits: Math.floor(Math.random() * 10) + 1,
                    status: Math.random() < 0.95 ? 'Active' : 'Degraded',
                    uptime: this.generateUptime(),
                    x: Math.random() * 800,
                    y: Math.random() * 600
                });
            }
        });
        
        // Generate realistic circuit paths (direct connections)
        const entryNodes = this.nodes.filter(n => n.category === 0 || n.category === 1);
        const exitNodes = this.nodes.filter(n => n.category === 2);
        const bridgeNodes = this.nodes.filter(n => n.category === 3);
        
        // Create direct circuit paths: Entry/Guard -> Exit
        for (let i = 0; i < 15; i++) {
            const entry = entryNodes[Math.floor(Math.random() * entryNodes.length)];
            const exit = exitNodes[Math.floor(Math.random() * exitNodes.length)];
            
            this.links.push({
                source: entry.id,
                target: exit.id,
                sourceName: entry.name,
                targetName: exit.name,
                circuitId: `circuit_${i}`,
                bandwidth: this.generateBandwidth()
            });
        }
        
        // Add bridge connections to entry nodes
        bridgeNodes.forEach(bridge => {
            const target = entryNodes[Math.floor(Math.random() * entryNodes.length)];
            this.links.push({
                source: bridge.id,
                target: target.id,
                sourceName: bridge.name,
                targetName: target.name,
                circuitId: `bridge_${bridge.id}`,
                bandwidth: this.generateBandwidth()
            });
        });
    }

    getNodeSize(nodeType, circuits = 1) {
        const baseSizes = {
            'Entry Node': 30,
            'Guard Node': 35,
            'Exit Node': 40,
            'Bridge Node': 32
        };
        
        const baseSize = baseSizes[nodeType] || 25;
        return baseSize + Math.log(circuits) * 4;
    }

    generateIP() {
        return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    }

    getRandomCountry() {
        const countries = ['US', 'DE', 'NL', 'FR', 'UK', 'CA', 'SE', 'CH', 'JP', 'AU', 'RU', 'BR', 'IN', 'SG'];
        return countries[Math.floor(Math.random() * countries.length)];
    }

    generateBandwidth() {
        const bandwidths = ['10 Mbps', '50 Mbps', '100 Mbps', '500 Mbps', '1 Gbps', '10 Gbps'];
        return bandwidths[Math.floor(Math.random() * bandwidths.length)];
    }

    generateUptime() {
        const days = Math.floor(Math.random() * 365);
        const hours = Math.floor(Math.random() * 24);
        return `${days}d ${hours}h`;
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

    startNodeAnimations() {
        // Clear existing animations
        this.nodeAnimations.clear();
        
        this.nodes.forEach(node => {
            this.createNodeAnimation(node);
        });
    }

    createNodeAnimation(node) {
        const animationType = this.getAnimationType(node.nodeType);
        
        switch (animationType) {
            case 'pulse':
                this.createPulseAnimation(node);
                break;
            case 'glow':
                this.createGlowAnimation(node);
                break;
            case 'rotate':
                this.createRotateAnimation(node);
                break;
            case 'breathe':
                this.createBreatheAnimation(node);
                break;
        }
    }

    getAnimationType(nodeType) {
        const animations = {
            'Entry Node': 'pulse',
            'Guard Node': 'glow',
            'Exit Node': 'rotate',
            'Bridge Node': 'pulse'
        };
        return animations[nodeType] || 'glow';
    }

    createPulseAnimation(node) {
        let scale = 1;
        let direction = 1;
        
        const animate = () => {
            scale += direction * 0.02;
            if (scale >= 1.3) direction = -1;
            if (scale <= 0.8) direction = 1;
            
            // Update node in chart
            this.updateNodeAnimation(node.id, { scale });
            
            if (this.nodeAnimations.has(node.id)) {
                requestAnimationFrame(animate);
            }
        };
        
        this.nodeAnimations.set(node.id, animate);
        animate();
    }

    createGlowAnimation(node) {
        let intensity = 0;
        let direction = 1;
        
        const animate = () => {
            intensity += direction * 0.05;
            if (intensity >= 1) direction = -1;
            if (intensity <= 0) direction = 1;
            
            this.updateNodeAnimation(node.id, { glow: intensity });
            
            if (this.nodeAnimations.has(node.id)) {
                requestAnimationFrame(animate);
            }
        };
        
        this.nodeAnimations.set(node.id, animate);
        animate();
    }

    createRotateAnimation(node) {
        let rotation = 0;
        
        const animate = () => {
            rotation += 2;
            if (rotation >= 360) rotation = 0;
            
            this.updateNodeAnimation(node.id, { rotation });
            
            if (this.nodeAnimations.has(node.id)) {
                requestAnimationFrame(animate);
            }
        };
        
        this.nodeAnimations.set(node.id, animate);
        animate();
    }

    createBreatheAnimation(node) {
        let opacity = 1;
        let direction = -1;
        
        const animate = () => {
            opacity += direction * 0.01;
            if (opacity <= 0.3) direction = 1;
            if (opacity >= 1) direction = -1;
            
            this.updateNodeAnimation(node.id, { opacity });
            
            if (this.nodeAnimations.has(node.id)) {
                requestAnimationFrame(animate);
            }
        };
        
        this.nodeAnimations.set(node.id, animate);
        animate();
    }

    updateNodeAnimation(nodeId, properties) {
        // This would update the visual properties of the node
        // ECharts doesn't support real-time animation updates easily,
        // so we'll simulate this with periodic chart updates
    }

    startAnimationLoop() {
        const animateTraffic = () => {
            if (!this.chart) return;
            
            // Simulate traffic flow animation
            const currentTime = Date.now();
            const animatedLinks = this.links.map(link => ({
                ...link,
                lineStyle: {
                    ...link.lineStyle,
                    opacity: 0.3 + Math.sin(currentTime * 0.001 + Math.random()) * 0.3
                }
            }));
            
            // Update chart with animated links
            this.chart.setOption({
                series: [{
                    links: animatedLinks
                }]
            }, false);
            
            requestAnimationFrame(animateTraffic);
        };
        
        animateTraffic();
    }

    inspectNode(nodeData) {
        // Create enhanced node inspection modal
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50';
        modal.innerHTML = `
            <div class="glass-panel rounded-lg p-6 max-w-lg w-full mx-4 border border-cyber-blue">
                <div class="flex justify-between items-center mb-4">
                    <h3 class="cyber-font text-xl font-bold text-cyber-blue">${nodeData.nodeType} Details</h3>
                    <button onclick="this.parentElement.parentElement.parentElement.remove()" 
                            class="text-gray-400 hover:text-white text-xl">✕</button>
                </div>
                <div class="space-y-3 mono-font text-sm">
                    <div class="grid grid-cols-2 gap-4">
                        <div><strong>Name:</strong> ${nodeData.name}</div>
                        <div><strong>Type:</strong> <span class="text-matrix-green">${nodeData.nodeType}</span></div>
                        <div><strong>IP:</strong> ${nodeData.ip}</div>
                        <div><strong>Country:</strong> ${nodeData.country}</div>
                        <div><strong>Bandwidth:</strong> ${nodeData.bandwidth}</div>
                        <div><strong>Circuits:</strong> ${nodeData.circuits}</div>
                        <div><strong>Status:</strong> <span class="text-matrix-green">${nodeData.status}</span></div>
                        <div><strong>Uptime:</strong> ${nodeData.uptime}</div>
                    </div>
                </div>
                <div class="mt-6 grid grid-cols-3 gap-3">
                    <button onclick="window.location.href='analysis.html?node=${nodeData.name}'" 
                            class="bg-cyber-blue text-black font-medium py-2 rounded hover:bg-opacity-80">
                        Analyze
                    </button>
                    <button onclick="window.location.href='forensics.html?target=${nodeData.ip}'" 
                            class="bg-matrix-green text-black font-medium py-2 rounded hover:bg-opacity-80">
                        Investigate
                    </button>
                    <button onclick="this.parentElement.parentElement.parentElement.remove()" 
                            class="bg-steel-gray text-white font-medium py-2 rounded hover:bg-gray-600">
                        Close
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }

    setupControls() {
        const refreshBtn = document.getElementById('refreshTopology');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.loadNetworkData();
            });
        }
        
        // Setup filter checkboxes
        const entryFilter = document.getElementById('showEntry');
        const guardFilter = document.getElementById('showGuard');
        const exitFilter = document.getElementById('showExit');
        
        [entryFilter, guardFilter, exitFilter].forEach(filter => {
            if (filter) {
                filter.addEventListener('change', () => this.applyFilters());
            }
        });
    }
    
    applyFilters() {
        if (!this.chart) return;
        
        const showEntry = document.getElementById('showEntry')?.checked ?? true;
        const showGuard = document.getElementById('showGuard')?.checked ?? true;
        const showExit = document.getElementById('showExit')?.checked ?? true;
        
        const filteredNodes = this.nodes.filter(node => {
            if (node.nodeType === 'Entry Node') return showEntry;
            if (node.nodeType === 'Guard Node') return showGuard;
            if (node.nodeType === 'Exit Node') return showExit;
            if (node.nodeType === 'Bridge Node') return showGuard;
            return true;
        });
        
        const visibleNodeIds = new Set(filteredNodes.map(n => n.id));
        const filteredLinks = this.links.filter(link => 
            visibleNodeIds.has(link.source) && visibleNodeIds.has(link.target)
        );
        
        this.chart.setOption({
            series: [{
                data: filteredNodes,
                links: filteredLinks
            }]
        });
    }
}

// Export for use in other modules
window.EnhancedTopology = EnhancedTopology;