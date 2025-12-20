// React-based TOR Network Geo Positioning Component
class TorGeoVisualization {
    constructor() {
        this.apiBase = 'http://localhost:5001/api';
        this.container = null;
        this.circuit = [];
        this.isBuilding = false;
        this.activeHop = -1;
        this.packetOffsets = [0, 20, 40, 60, 80];
        this.animationFrameId = null;
        this.init();
    }

    init() {
        this.initializeContainer();
        this.startTorNetworkSimulation();
        this.setupEventListeners();
    }

    initializeContainer() {
        const mapContainer = document.getElementById('worldMap');
        if (!mapContainer) return;

        // Clear existing content
        mapContainer.innerHTML = '';
        
        // Create React-like component structure
        this.container = document.createElement('div');
        this.container.className = 'relative w-full h-full bg-[#020202] overflow-hidden';
        
        // Add background image
        const bgDiv = document.createElement('div');
        bgDiv.className = 'absolute inset-0 z-0 scale-110 pointer-events-none';
        bgDiv.style.cssText = `
            background-image: url('https://images.unsplash.com/photo-1526778548025-fa2f459cd5c1?q=80&w=2400&auto=format&fit=crop');
            background-size: cover;
            background-position: center;
            filter: grayscale(0.9) contrast(1.6) brightness(0.3);
        `;
        this.container.appendChild(bgDiv);

        // Add overlay effects
        const overlay1 = document.createElement('div');
        overlay1.className = 'absolute inset-0 z-10 pointer-events-none';
        overlay1.style.cssText = `
            background: radial-gradient(circle at center, transparent 0%, black 90%);
            opacity: 0.8;
        `;
        this.container.appendChild(overlay1);

        const scanline = document.createElement('div');
        scanline.className = 'absolute inset-0 z-10 pointer-events-none scanline';
        scanline.style.cssText = `
            background: linear-gradient(to bottom, transparent 0%, rgba(34, 211, 238, 0.05) 50%, transparent 100%);
            background-size: 100% 200px;
            animation: scanlineMove 15s linear infinite;
            opacity: 0.3;
        `;
        this.container.appendChild(scanline);

        // Create SVG for network visualization
        this.createSVGLayer();
        
        // Add control overlay
        this.createControlOverlay();
        
        // Add CSS animations
        this.addCustomStyles();
        
        mapContainer.appendChild(this.container);
    }

    createSVGLayer() {
        const svgContainer = document.createElement('div');
        svgContainer.className = 'absolute inset-0 z-20 flex items-center justify-center pointer-events-none';
        
        this.svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        this.svg.setAttribute('viewBox', '0 0 900 450');
        this.svg.setAttribute('class', 'w-full h-full max-h-[90vh]');
        
        // Add SVG definitions
        const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
        
        // Ultra glow filter
        const filter = document.createElementNS('http://www.w3.org/2000/svg', 'filter');
        filter.setAttribute('id', 'ultra-glow');
        filter.setAttribute('x', '-50%');
        filter.setAttribute('y', '-50%');
        filter.setAttribute('width', '200%');
        filter.setAttribute('height', '200%');
        
        const blur = document.createElementNS('http://www.w3.org/2000/svg', 'feGaussianBlur');
        blur.setAttribute('stdDeviation', '5');
        blur.setAttribute('result', 'blur');
        filter.appendChild(blur);
        
        const composite = document.createElementNS('http://www.w3.org/2000/svg', 'feComposite');
        composite.setAttribute('in', 'SourceGraphic');
        composite.setAttribute('in2', 'blur');
        composite.setAttribute('operator', 'over');
        filter.appendChild(composite);
        
        defs.appendChild(filter);
        
        // Circuit line gradient
        const gradient = document.createElementNS('http://www.w3.org/2000/svg', 'linearGradient');
        gradient.setAttribute('id', 'circuitLine');
        gradient.setAttribute('x1', '0%');
        gradient.setAttribute('y1', '0%');
        gradient.setAttribute('x2', '100%');
        gradient.setAttribute('y2', '0%');
        
        const stop1 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
        stop1.setAttribute('offset', '0%');
        stop1.setAttribute('stop-color', '#22d3ee');
        stop1.setAttribute('stop-opacity', '0.8');
        gradient.appendChild(stop1);
        
        const stop2 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
        stop2.setAttribute('offset', '100%');
        stop2.setAttribute('stop-color', '#10b981');
        stop2.setAttribute('stop-opacity', '0.8');
        gradient.appendChild(stop2);
        
        defs.appendChild(gradient);
        this.svg.appendChild(defs);
        
        svgContainer.appendChild(this.svg);
        this.container.appendChild(svgContainer);
    }

    createControlOverlay() {
        const controlDiv = document.createElement('div');
        controlDiv.className = 'absolute bottom-10 right-10 z-30 flex items-center gap-6';
        
        const statusDiv = document.createElement('div');
        statusDiv.className = 'flex flex-col items-end mr-4';
        statusDiv.innerHTML = `
            <span class="text-[10px] text-cyan-500 font-black tracking-[0.3em] uppercase opacity-60">Status</span>
            <span id="torNetworkStatus" class="text-xs text-white font-bold tracking-widest uppercase">
                ${this.isBuilding ? 'Syncing_Nodes...' : 'Circuit_Encrypted'}
            </span>
        `;
        controlDiv.appendChild(statusDiv);
        
        const button = document.createElement('button');
        button.className = 'relative w-14 h-14 flex items-center justify-center rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 hover:text-cyan-300 transition-all active:scale-90 disabled:opacity-30 group';
        button.title = 'Renew Identity';
        button.onclick = () => this.buildCircuit();
        
        const pingDiv = document.createElement('div');
        pingDiv.className = 'absolute inset-0 rounded-full border border-cyan-500/20 animate-ping opacity-20';
        button.appendChild(pingDiv);
        
        const icon = document.createElement('div');
        icon.innerHTML = '⟳';
        icon.className = `text-2xl ${this.isBuilding ? 'animate-spin' : 'group-hover:rotate-180 transition-transform duration-500'}`;
        button.appendChild(icon);
        
        controlDiv.appendChild(button);
        this.container.appendChild(controlDiv);
    }

    addCustomStyles() {
        if (document.getElementById('tor-geo-styles')) return;
        
        const style = document.createElement('style');
        style.id = 'tor-geo-styles';
        style.textContent = `
            @keyframes dash { to { stroke-dashoffset: -1000; } }
            @keyframes scanlineMove {
                from { transform: translateY(-100%); }
                to { transform: translateY(100%); }
            }
            .tor-node-pulse {
                animation: torNodePulse 2s ease-in-out infinite;
            }
            @keyframes torNodePulse {
                0%, 100% { opacity: 0.7; transform: scale(1); }
                50% { opacity: 1; transform: scale(1.1); }
            }
        `;
        document.head.appendChild(style);
    }

    async buildCircuit() {
        this.isBuilding = true;
        this.circuit = [];
        this.activeHop = -1;
        
        // Update status
        const statusEl = document.getElementById('torNetworkStatus');
        if (statusEl) statusEl.textContent = 'Syncing_Nodes...';
        
        // Clear existing SVG content
        while (this.svg.children.length > 1) {
            this.svg.removeChild(this.svg.lastChild);
        }
        
        // TOR nodes based on real geo locations
        const torNodes = [
            { name: 'US-East', coords: { x: 205, y: 142 }, type: 'guard', country: 'United States' },
            { name: 'Central-EU', coords: { x: 458, y: 112 }, type: 'guard', country: 'Germany' },
            { name: 'Tokyo-JP', coords: { x: 782, y: 158 }, type: 'middle', country: 'Japan' },
            { name: 'Sao-Paulo-BR', coords: { x: 292, y: 318 }, type: 'middle', country: 'Brazil' },
            { name: 'Sydney-AU', coords: { x: 765, y: 355 }, type: 'middle', country: 'Australia' },
            { name: 'Reykjavik-IS', coords: { x: 412, y: 82 }, type: 'exit', country: 'Iceland' },
            { name: 'Singapore-SG', coords: { x: 705, y: 268 }, type: 'exit', country: 'Singapore' },
            { name: 'Amsterdam-NL', coords: { x: 448, y: 102 }, type: 'exit', country: 'Netherlands' },
            { name: 'Zurich-CH', coords: { x: 455, y: 118 }, type: 'exit', country: 'Switzerland' }
        ];
        
        const destinations = [
            { name: 'target.service', coords: { x: 810, y: 185 }, type: 'destination' },
            { name: 'secure.vault', coords: { x: 465, y: 128 }, type: 'destination' },
            { name: 'onion.node', coords: { x: 200, y: 125 }, type: 'destination' },
            { name: 'hidden.core', coords: { x: 625, y: 255 }, type: 'destination' }
        ];
        
        // Shuffle and select nodes for realistic TOR circuit
        const shuffled = [...torNodes].sort(() => 0.5 - Math.random());
        const dest = destinations[Math.floor(Math.random() * destinations.length)];
        
        // Build circuit: Guard -> Middle -> Exit -> Destination
        const guardNodes = shuffled.filter(n => n.type === 'guard');
        const middleNodes = shuffled.filter(n => n.type === 'middle');
        const exitNodes = shuffled.filter(n => n.type === 'exit');
        
        const newCircuit = [
            guardNodes[0],
            middleNodes[0],
            exitNodes[0],
            dest
        ];
        
        // Add user node
        const userNode = { coords: { x: 175, y: 155 }, name: 'User', type: 'user' };
        this.createUserNode(userNode);
        
        // Build circuit step by step
        for (let i = 0; i < newCircuit.length; i++) {
            this.activeHop = i;
            await new Promise(r => setTimeout(r, 1000));
            this.circuit.push(newCircuit[i]);
            this.createNode(newCircuit[i], i);
            
            if (i > 0 || this.circuit.length === 1) {
                this.createConnection(i === 0 ? userNode : this.circuit[i-1], newCircuit[i]);
            }
        }
        
        this.isBuilding = false;
        this.activeHop = 100;
        
        if (statusEl) statusEl.textContent = 'Circuit_Encrypted';
        
        // Start packet animation
        this.startPacketAnimation();
    }

    createUserNode(node) {
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('transform', `translate(${node.coords.x-10}, ${node.coords.y-10})`);
        
        // Outer square
        const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
        rect.setAttribute('width', '20');
        rect.setAttribute('height', '20');
        rect.setAttribute('fill', 'none');
        rect.setAttribute('stroke', '#22d3ee');
        rect.setAttribute('stroke-width', '1');
        rect.setAttribute('opacity', '0.5');
        g.appendChild(rect);
        
        // Center dot
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', '10');
        circle.setAttribute('cy', '10');
        circle.setAttribute('r', '2');
        circle.setAttribute('fill', '#22d3ee');
        g.appendChild(circle);
        
        // Pulse ring
        const pulseRing = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        pulseRing.setAttribute('cx', '10');
        pulseRing.setAttribute('cy', '10');
        pulseRing.setAttribute('r', '10');
        pulseRing.setAttribute('fill', 'none');
        pulseRing.setAttribute('stroke', '#22d3ee');
        pulseRing.setAttribute('stroke-width', '0.5');
        
        const animateR = document.createElementNS('http://www.w3.org/2000/svg', 'animate');
        animateR.setAttribute('attributeName', 'r');
        animateR.setAttribute('from', '2');
        animateR.setAttribute('to', '20');
        animateR.setAttribute('dur', '2s');
        animateR.setAttribute('repeatCount', 'indefinite');
        pulseRing.appendChild(animateR);
        
        const animateOpacity = document.createElementNS('http://www.w3.org/2000/svg', 'animate');
        animateOpacity.setAttribute('attributeName', 'opacity');
        animateOpacity.setAttribute('from', '0.8');
        animateOpacity.setAttribute('to', '0');
        animateOpacity.setAttribute('dur', '2s');
        animateOpacity.setAttribute('repeatCount', 'indefinite');
        pulseRing.appendChild(animateOpacity);
        
        g.appendChild(pulseRing);
        this.svg.appendChild(g);
    }

    createNode(node, index) {
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('transform', `translate(${node.coords.x-15}, ${node.coords.y-15})`);
        g.setAttribute('class', 'animate-in fade-in zoom-in duration-500');
        
        // Outer reticle
        const reticle = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        reticle.setAttribute('d', 'M 5 0 L 0 0 L 0 5 M 25 0 L 30 0 L 30 5 M 0 25 L 0 30 L 5 30 M 25 30 L 30 30 L 30 25');
        reticle.setAttribute('fill', 'none');
        reticle.setAttribute('stroke', node.type === 'destination' ? '#ef4444' : '#22d3ee');
        reticle.setAttribute('stroke-width', '1');
        reticle.setAttribute('opacity', '0.8');
        
        const rotateAnim = document.createElementNS('http://www.w3.org/2000/svg', 'animateTransform');
        rotateAnim.setAttribute('attributeName', 'transform');
        rotateAnim.setAttribute('type', 'rotate');
        rotateAnim.setAttribute('from', '0 15 15');
        rotateAnim.setAttribute('to', '90 15 15');
        rotateAnim.setAttribute('dur', '3s');
        rotateAnim.setAttribute('repeatCount', 'indefinite');
        reticle.appendChild(rotateAnim);
        
        g.appendChild(reticle);
        
        // Core node
        const core = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        core.setAttribute('cx', '15');
        core.setAttribute('cy', '15');
        core.setAttribute('r', '5');
        
        let color = '#f59e0b'; // Default amber
        if (node.type === 'destination') color = '#ef4444';
        else if (node.type === 'exit') color = '#10b981';
        else if (node.type === 'guard') color = '#22d3ee';
        
        core.setAttribute('fill', color);
        core.setAttribute('class', 'shadow-lg');
        g.appendChild(core);
        
        // Ping ripple
        const pingRipple = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        pingRipple.setAttribute('cx', '15');
        pingRipple.setAttribute('cy', '15');
        pingRipple.setAttribute('r', '5');
        pingRipple.setAttribute('fill', 'none');
        pingRipple.setAttribute('stroke', 'white');
        pingRipple.setAttribute('stroke-width', '0.5');
        
        const pingAnimR = document.createElementNS('http://www.w3.org/2000/svg', 'animate');
        pingAnimR.setAttribute('attributeName', 'r');
        pingAnimR.setAttribute('from', '5');
        pingAnimR.setAttribute('to', '35');
        pingAnimR.setAttribute('dur', '1.5s');
        pingAnimR.setAttribute('repeatCount', 'indefinite');
        pingRipple.appendChild(pingAnimR);
        
        const pingAnimOpacity = document.createElementNS('http://www.w3.org/2000/svg', 'animate');
        pingAnimOpacity.setAttribute('attributeName', 'opacity');
        pingAnimOpacity.setAttribute('from', '0.6');
        pingAnimOpacity.setAttribute('to', '0');
        pingAnimOpacity.setAttribute('dur', '1.5s');
        pingAnimOpacity.setAttribute('repeatCount', 'indefinite');
        pingRipple.appendChild(pingAnimOpacity);
        
        g.appendChild(pingRipple);
        
        // Data ripple
        const dataRipple = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        dataRipple.setAttribute('cx', '15');
        dataRipple.setAttribute('cy', '15');
        dataRipple.setAttribute('r', '5');
        dataRipple.setAttribute('fill', 'none');
        dataRipple.setAttribute('stroke', node.type === 'destination' ? '#ef4444' : '#22d3ee');
        dataRipple.setAttribute('stroke-width', '1');
        
        const dataAnimR = document.createElementNS('http://www.w3.org/2000/svg', 'animate');
        dataAnimR.setAttribute('attributeName', 'r');
        dataAnimR.setAttribute('from', '5');
        dataAnimR.setAttribute('to', '20');
        dataAnimR.setAttribute('dur', '3s');
        dataAnimR.setAttribute('repeatCount', 'indefinite');
        dataAnimR.setAttribute('begin', '0.5s');
        dataRipple.appendChild(dataAnimR);
        
        const dataAnimOpacity = document.createElementNS('http://www.w3.org/2000/svg', 'animate');
        dataAnimOpacity.setAttribute('attributeName', 'opacity');
        dataAnimOpacity.setAttribute('from', '0.4');
        dataAnimOpacity.setAttribute('to', '0');
        dataAnimOpacity.setAttribute('dur', '3s');
        dataAnimOpacity.setAttribute('repeatCount', 'indefinite');
        dataAnimOpacity.setAttribute('begin', '0.5s');
        dataRipple.appendChild(dataAnimOpacity);
        
        g.appendChild(dataRipple);
        this.svg.appendChild(g);
    }

    createConnection(fromNode, toNode) {
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('filter', 'url(#ultra-glow)');
        
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', `M ${fromNode.coords.x},${fromNode.coords.y} L ${toNode.coords.x},${toNode.coords.y}`);
        path.setAttribute('fill', 'none');
        path.setAttribute('stroke', 'url(#circuitLine)');
        path.setAttribute('stroke-width', '1.5');
        path.setAttribute('stroke-dasharray', '4 6');
        path.setAttribute('class', 'animate-[dash_60s_linear_infinite] opacity-40');
        
        g.appendChild(path);
        this.svg.appendChild(g);
    }

    startPacketAnimation() {
        if (this.circuit.length === 0) return;
        
        const userNode = { coords: { x: 175, y: 155 } };
        const pathData = `M ${userNode.coords.x},${userNode.coords.y} ${this.circuit.map(c => `L ${c.coords.x},${c.coords.y}`).join(' ')}`;
        
        // Create animated packets
        for (let i = 0; i < 5; i++) {
            setTimeout(() => {
                const packet = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                packet.setAttribute('r', '2');
                packet.setAttribute('fill', '#fff');
                packet.setAttribute('class', 'shadow-[0_0_15px_#fff]');
                
                const animateMotion = document.createElementNS('http://www.w3.org/2000/svg', 'animateMotion');
                animateMotion.setAttribute('path', pathData);
                animateMotion.setAttribute('dur', '2.5s');
                animateMotion.setAttribute('repeatCount', 'indefinite');
                animateMotion.setAttribute('begin', `${i * 0.5}s`);
                
                packet.appendChild(animateMotion);
                this.svg.appendChild(packet);
            }, i * 500);
        }
    }

    async startTorNetworkSimulation() {
        // Auto-build circuit on initialization
        setTimeout(() => {
            this.buildCircuit();
        }, 1000);
        
        // Periodic circuit renewal
        setInterval(() => {
            if (!this.isBuilding) {
                this.buildCircuit();
            }
        }, 30000); // Renew every 30 seconds
    }

    setupEventListeners() {
        // Add controls for the geo positioning
        const controlsContainer = document.getElementById('geoControls');
        if (controlsContainer) {
            controlsContainer.innerHTML = `
                <div class="flex space-x-2 mb-4">
                    <button id="renewCircuit" class="px-3 py-1 bg-cyber-blue text-black text-xs rounded hover:bg-opacity-80">Renew Circuit</button>
                    <button id="toggleAnimation" class="px-3 py-1 bg-matrix-green text-black text-xs rounded hover:bg-opacity-80">Toggle Animation</button>
                    <button id="exportCircuit" class="px-3 py-1 bg-warning-amber text-black text-xs rounded hover:bg-opacity-80">Export Data</button>
                </div>
                <div class="text-xs text-gray-400 mb-2">
                    <div class="grid grid-cols-3 gap-1">
                        <button onclick="window.torGeoVisualization?.buildCircuit()" class="bg-matrix-green text-black py-1 rounded text-xs hover:bg-opacity-80">New Circuit</button>
                        <button onclick="window.torGeoVisualization?.showCircuitInfo()" class="bg-cyber-blue text-black py-1 rounded text-xs hover:bg-opacity-80">Circuit Info</button>
                        <button onclick="window.torGeoVisualization?.analyzeLatency()" class="bg-warning-amber text-black py-1 rounded text-xs hover:bg-opacity-80">Analyze</button>
                    </div>
                </div>
            `;

            document.getElementById('renewCircuit')?.addEventListener('click', () => {
                this.buildCircuit();
            });
        }
    }

    showCircuitInfo() {
        if (this.circuit.length === 0) {
            this.showNotification('No active circuit', 'info');
            return;
        }
        
        const info = this.circuit.map((node, i) => {
            const types = ['Guard', 'Middle', 'Exit', 'Destination'];
            return `${types[i] || 'Node'}: ${node.name} (${node.country || 'Unknown'})`;
        }).join('\n');
        
        this.showNotification(`Active Circuit:\n${info}`, 'info');
    }

    analyzeLatency() {
        const latencies = this.circuit.map(() => Math.floor(Math.random() * 200) + 50);
        const total = latencies.reduce((sum, lat) => sum + lat, 0);
        
        this.showNotification(`Circuit Latency Analysis:\nTotal: ${total}ms\nAverage: ${Math.floor(total / latencies.length)}ms`, 'info');
    }

    showNotification(message, type = 'info') {
        const colors = {
            success: 'bg-green-900 border-green-500 text-green-200',
            error: 'bg-red-900 border-red-500 text-red-200',
            warning: 'bg-orange-900 border-orange-500 text-orange-200',
            info: 'bg-blue-900 border-blue-500 text-blue-200'
        };
        
        const notification = document.createElement('div');
        notification.className = `fixed top-24 right-4 z-50 p-3 rounded bg-warning-amber text-black text-xs max-w-xs whitespace-pre-line`;
        notification.innerHTML = `<strong>TOR Network:</strong> ${message}`;
        document.body.appendChild(notification);
        setTimeout(() => notification.remove(), 4000);
    }
}

// Export for use in other modules
window.TorGeoVisualization = TorGeoVisualization;
window.GeoPositioning = TorGeoVisualization; // Backward compatibility