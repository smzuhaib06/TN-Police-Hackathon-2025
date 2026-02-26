// TOR Unveil - Main Application Logic
class TORUnveil {
    constructor() {
        this.networkData = null;
        this.topologyChart = null;
        this.currentTime = new Date();
        this.isRealTimeActive = true;
        
        this.init();
    }

    init() {
        this.initializeTypedText();
        this.initializeNetworkTopology();
        this.initializeEventListeners();
        this.initializeBackendIntegration();
        this.startRealTimeUpdates();
        this.initializeAnimations();
    }

    initializeTypedText() {
        const statusMessages = [
            "Monitoring TOR Network Topology...",
            "Analyzing Relay Connections...",
            "Tracking Suspicious Activity Patterns...",
            "Correlating Entry-Exit Node Data...",
            "Generating Forensic Intelligence..."
        ];
        const typedTarget = document.querySelector('#typed-status');
        if (typeof Typed !== 'undefined' && typedTarget) {
            new Typed('#typed-status', {
                strings: statusMessages,
                typeSpeed: 50,
                backSpeed: 30,
                backDelay: 2000,
                loop: true,
                showCursor: false
            });
        }
    }

    initializeNetworkTopology() {
        const chartDom = document.getElementById('networkTopology');

        // If a live topology script is running, skip demo initialization
        if (window.__liveTopologyPresent__) return;

        this.topologyChart = echarts.init(chartDom);

        // Generate realistic TOR network data and render demo topology
        this.generateNetworkData();

        const option = {
            backgroundColor: 'transparent',
            tooltip: {
                trigger: 'item',
                formatter: function(params) {
                    if (params.dataType === 'node') {
                        return `
                            <div class="mono-font text-sm">
                                <strong>${params.data.name}</strong><br/>
                                Type: ${params.data.category}<br/>
                                IP: ${params.data.ip}<br/>
                                Bandwidth: ${params.data.bandwidth}<br/>
                                Country: ${params.data.country}
                            </div>
                        `;
                    } else {
                        return `Connection: ${params.data.source} → ${params.data.target}`;
                    }
                }
            },
            legend: {
                data: ['Guard Node', 'Middle Relay', 'Exit Node', 'Bridge Node'],
                textStyle: { color: '#e2e8f0' },
                top: 10,
                left: 10
            },
            series: [{
                type: 'graph',
                layout: 'force',
                animation: true,
                roam: true,
                focusNodeAdjacency: true,
                force: {
                    repulsion: 1000,
                    gravity: 0.1,
                    edgeLength: 150,
                    layoutAnimation: true
                },
                data: this.networkData.nodes,
                links: this.networkData.links,
                categories: [
                    { name: 'Guard Node', itemStyle: { color: '#00d4ff' } },
                    { name: 'Middle Relay', itemStyle: { color: '#4a90e2' } },
                    { name: 'Exit Node', itemStyle: { color: '#00ff88' } },
                    { name: 'Bridge Node', itemStyle: { color: '#ff8c00' } }
                ],
                itemStyle: {
                    borderColor: '#fff',
                    borderWidth: 1,
                    shadowBlur: 10,
                    shadowColor: 'rgba(0, 212, 255, 0.5)'
                },
                lineStyle: {
                    color: 'rgba(0, 212, 255, 0.6)',
                    width: 2,
                    curveness: 0.1,
                    opacity: 0.8
                },
                emphasis: {
                    focus: 'adjacency',
                    lineStyle: {
                        width: 4,
                        opacity: 1
                    }
                },
                symbolSize: (value, params) => {
                    const baseSize = 20;
                    const bandwidth = params.data.bandwidth || '0';
                    const size = parseInt(bandwidth) / 10 + baseSize;
                    return Math.min(Math.max(size, 10), 50);
                }
            }]
        };

        this.topologyChart.setOption(option);

        // Node click events are now handled by LiveDataManager

        // Handle window resize
        window.addEventListener('resize', () => {
            this.topologyChart.resize();
        });
    }

    generateNetworkData() {
        const nodes = [];
        const links = [];
        const nodeTypes = ['Guard Node', 'Middle Relay', 'Exit Node', 'Bridge Node'];
        const countries = ['US', 'DE', 'NL', 'FR', 'UK', 'CA', 'SE', 'CH'];
        
        // Generate realistic node data
        for (let i = 0; i < 150; i++) {
            const nodeType = nodeTypes[Math.floor(Math.random() * nodeTypes.length)];
            const country = countries[Math.floor(Math.random() * countries.length)];
            const bandwidth = Math.floor(Math.random() * 1000) + 10;
            
            nodes.push({
                id: i,
                name: `${nodeType.replace(' ', '')}_${i}`,
                category: nodeType,
                ip: this.generateRandomIP(),
                country: country,
                bandwidth: bandwidth + ' Mbps',
                symbolSize: Math.min(Math.max(bandwidth / 10 + 20, 10), 50)
            });
        }

        // Generate realistic connections
        const guardNodes = nodes.filter(n => n.category === 'Guard Node');
        const middleNodes = nodes.filter(n => n.category === 'Middle Relay');
        const exitNodes = nodes.filter(n => n.category === 'Exit Node');

        // Create circuit paths: Guard -> Middle -> Exit
        for (let i = 0; i < 75; i++) {
            const guard = guardNodes[Math.floor(Math.random() * guardNodes.length)];
            const middle = middleNodes[Math.floor(Math.random() * middleNodes.length)];
            const exit = exitNodes[Math.floor(Math.random() * exitNodes.length)];
            
            links.push(
                { source: guard.id, target: middle.id },
                { source: middle.id, target: exit.id }
            );
        }

        // Add some random connections for complexity
        for (let i = 0; i < 50; i++) {
            const source = nodes[Math.floor(Math.random() * nodes.length)];
            const target = nodes[Math.floor(Math.random() * nodes.length)];
            
            if (source.id !== target.id) {
                links.push({ source: source.id, target: target.id });
            }
        }

        this.networkData = { nodes, links };
    }

    generateRandomIP() {
        return Array.from({length: 4}, () => Math.floor(Math.random() * 256)).join('.');
    }

    inspectNode(nodeData) {
        // Create node inspection modal
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
        modal.innerHTML = `
            <div class="glass-panel rounded-lg p-6 max-w-md w-full mx-4">
                <div class="flex justify-between items-center mb-4">
                    <h3 class="cyber-font text-lg font-bold text-cyber-blue">Node Details</h3>
                    <button onclick="this.parentElement.parentElement.parentElement.remove()" 
                            class="text-gray-400 hover:text-white">✕</button>
                </div>
                <div class="space-y-3 mono-font text-sm">
                    <div><strong>Name:</strong> ${nodeData.name}</div>
                    <div><strong>Type:</strong> ${nodeData.category}</div>
                    <div><strong>IP Address:</strong> ${nodeData.ip}</div>
                    <div><strong>Country:</strong> ${nodeData.country}</div>
                    <div><strong>Bandwidth:</strong> ${nodeData.bandwidth}</div>
                    <div><strong>Status:</strong> <span class="text-matrix-green">Active</span></div>
                </div>
                <div class="mt-6 flex space-x-3">
                    <button onclick="window.location.href='analysis.html?node=${nodeData.name}'" 
                            class="flex-1 bg-cyber-blue text-black font-medium py-2 rounded hover:bg-opacity-80">
                        Analyze Node
                    </button>
                    <button onclick="window.location.href='forensics.html?target=${nodeData.ip}'" 
                            class="flex-1 bg-matrix-green text-black font-medium py-2 rounded hover:bg-opacity-80">
                        Investigate
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }

    initializeEventListeners() {
        // Node filter checkboxes (check if they exist before adding listeners)
        const showEntry = document.getElementById('showEntry');
        const showGuard = document.getElementById('showGuard');
        const showExit = document.getElementById('showExit');
        
        if (showEntry) showEntry.addEventListener('change', () => this.updateTopology());
        if (showGuard) showGuard.addEventListener('change', () => this.updateTopology());
        if (showExit) showExit.addEventListener('change', () => this.updateTopology());

        // Topology controls
        const refreshTopology = document.getElementById('refreshTopology');
        if (refreshTopology) refreshTopology.addEventListener('click', () => this.refreshNetwork());
        
        document.getElementById('refreshCorrelation')?.addEventListener('click', () => this.refreshCorrelationVisualization());
        document.getElementById('zoomIn')?.addEventListener('click', () => this.topologyChart.dispatchAction({ type: 'scale', scale: 1.2 }));
        document.getElementById('zoomOut')?.addEventListener('click', () => this.topologyChart.dispatchAction({ type: 'scale', scale: 0.8 }));
        document.getElementById('resetView')?.addEventListener('click', () => this.topologyChart.dispatchAction({ type: 'restore' }));

        // Timeline scrubber
        const timelineScrubber = document.getElementById('timelineScrubber');
        if (timelineScrubber) {
            timelineScrubber.addEventListener('input', (e) => {
                const value = e.target.value;
                this.updateTimeline(value);
            });
        }
    }

    updateTopology() {
        const guardChecked = document.getElementById('guardNodes').checked;
        const middleChecked = document.getElementById('middleNodes').checked;
        const exitChecked = document.getElementById('exitNodes').checked;
        const bridgeChecked = document.getElementById('bridgeNodes').checked;

        const filteredNodes = this.networkData.nodes.filter(node => {
            switch(node.category) {
                case 'Guard Node': return guardChecked;
                case 'Middle Relay': return middleChecked;
                case 'Exit Node': return exitChecked;
                case 'Bridge Node': return bridgeChecked;
                default: return true;
            }
        });

        const filteredNodeIds = new Set(filteredNodes.map(n => n.id));
        const filteredLinks = this.networkData.links.filter(link => 
            filteredNodeIds.has(link.source) && filteredNodeIds.has(link.target)
        );

        this.topologyChart.setOption({
            series: [{
                data: filteredNodes,
                links: filteredLinks
            }]
        });
    }

    refreshNetwork() {
        // Simulate network refresh
        const refreshBtn = document.getElementById('refreshTopology');
        refreshBtn.textContent = 'Refreshing...';
        refreshBtn.disabled = true;

        setTimeout(() => {
            this.generateNetworkData();
            this.topologyChart.setOption({
                series: [{
                    data: this.networkData.nodes,
                    links: this.networkData.links
                }]
            });
            
            refreshBtn.textContent = 'Refresh Network';
            refreshBtn.disabled = false;
            
            // Show success notification
            this.showNotification('Network topology updated successfully', 'success');
        }, 2000);
    }

    refreshCorrelationVisualization() {
        // Refresh the TOR correlation attack visualization
        const refreshBtn = document.getElementById('refreshCorrelation');
        if (refreshBtn) {
            refreshBtn.textContent = '⟳';
            refreshBtn.disabled = true;
        }

        setTimeout(() => {
            // Reinitialize the TOR visualization
            if (window.torVisualization) {
                window.torVisualization.createVisualization();
                window.torVisualization.startAnimation();
            } else if (window.TorVisualization) {
                window.torVisualization = new TorVisualization();
            }
            
            if (refreshBtn) {
                refreshBtn.textContent = '🔄';
                refreshBtn.disabled = false;
            }
            
            // Show success notification
            this.showNotification('TOR correlation analysis refreshed', 'warning');
        }, 1500);
    }

    updateTimeline(value) {
        const timeOffset = (100 - value) * 24 * 60 * 60 * 1000; // Up to 24 hours back
        const newTime = new Date(Date.now() - timeOffset);
        
        document.getElementById('currentTime').textContent = newTime.toISOString().replace('T', ' ').slice(0, -5) + ' UTC';
        
        // Update network visualization based on timeline
        this.updateNetworkForTime(newTime);
    }

    updateNetworkForTime(time) {
        // Simulate network changes over time
        const hour = time.getHours();
        const activityFactor = Math.sin((hour / 24) * Math.PI * 2) * 0.5 + 0.5; // 0-1 based on time of day
        
        // Update node sizes based on activity
        const updatedNodes = this.networkData.nodes.map(node => {
            const baseSize = parseInt(node.bandwidth) / 10 + 20;
            const timeSize = baseSize * (0.7 + activityFactor * 0.6);
            return {
                ...node,
                symbolSize: Math.min(Math.max(timeSize, 10), 50)
            };
        });

        this.topologyChart.setOption({
            series: [{
                data: updatedNodes
            }]
        });
    }

    startRealTimeUpdates() {
        setInterval(() => {
            // If live topology is present, avoid running demo stat simulation
            if (window.__liveTopologyPresent__) return;

            // push demo stats periodically
            this.updateLiveStats();
            this.updateAlerts();
        }, 5000); // Update every 5 seconds
    }

    updateLiveStats() {
        // Simulate real-time statistics updates
        const stats = {
            bandwidth: (Math.random() * 200 + 700).toFixed(0) + ' Gbps',
            circuits: (Math.random() * 2000 + 12000).toFixed(0),
            users: (Math.random() * 0.5 + 5.0).toFixed(1) + 'M'
        };

        // Update stats display with animation
        const bandwidthEl = document.querySelector('.mono-font.text-matrix-green');
        const circuitsEl = document.querySelector('.mono-font.text-cyber-blue');
        const usersEl = document.querySelector('.mono-font.text-white');

        if (bandwidthEl) bandwidthEl.textContent = stats.bandwidth;
        if (circuitsEl) circuitsEl.textContent = stats.circuits;
        if (usersEl) usersEl.textContent = stats.users;
    }

    updateAlerts() {
        // Simulate new alerts
        if (Math.random() < 0.3) { // 30% chance of new alert
            const alertTypes = [
                { type: 'suspicious', color: 'critical-red', text: 'Unusual traffic pattern detected' },
                { type: 'correlation', color: 'warning-amber', text: 'Potential correlation attack' },
                { type: 'newnode', color: 'cyber-blue', text: 'New high-bandwidth relay joined' }
            ];

            const alert = alertTypes[Math.floor(Math.random() * alertTypes.length)];
            this.showNotification(alert.text, alert.type);
        }
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

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);

        // Animate in
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

        // Animate status indicators
        anime({
            targets: '.status-indicator',
            scale: [0, 1],
            delay: anime.stagger(200, {start: 500}),
            duration: 600,
            easing: 'easeOutElastic(1, .8)'
        });
    }

    /* Backend integration for local Stem service */
    initializeBackendIntegration() {
        // Detect backend URL dynamically
        // Try localhost:5000 first (standard backend port), then detect from window.location
        const detectBackendUrl = () => {
            if (window.BACKEND_BASE) return window.BACKEND_BASE;
            // Try standard backend port
            return `http://${window.location.hostname}:5001`;
        };
        this.backendBase = detectBackendUrl();

        // Create a small debug panel in the right sidebar Quick Actions area
        const quickActions = document.querySelector('.glass-panel .space-y-3');
        if (!quickActions) return;

        const panel = document.createElement('div');
        panel.className = 'glass-panel rounded-lg p-4 mt-4';
        panel.innerHTML = `
            <h4 class="cyber-font text-sm font-bold text-cyber-blue mb-2">Backend Control Panel</h4>
            <div class="text-xs text-gray-400 mb-3">Enhanced TOR Unveil v2.0</div>
            <div class="space-y-2">
                <div><button id="beHealthBtn" class="w-full bg-steel-gray text-white py-1 rounded text-xs">Health Check</button></div>
                <div><button id="beCircuitsBtn" class="w-full bg-steel-gray text-white py-1 rounded text-xs">Get Circuits</button></div>
                <div><button id="beRelaysBtn" class="w-full bg-steel-gray text-white py-1 rounded text-xs">Get Relays (2000+)</button></div>
                <div class="flex space-x-2">
                    <input id="beExitInput" class="w-full bg-gray-700 text-sm px-2 py-1 rounded" placeholder="Exit fingerprint" />
                    <button id="beTraceBtn" class="bg-cyber-blue text-black px-3 py-1 rounded text-xs">Trace</button>
                </div>
                <div class="grid grid-cols-2 gap-2">
                    <button id="beSniffStart" class="bg-matrix-green text-black py-1 rounded text-xs">Start Sniffer</button>
                    <button id="beSniffStop" class="bg-warning-amber text-black py-1 rounded text-xs">Stop Sniffer</button>
                </div>
                <div class="grid grid-cols-2 gap-2 mt-1">
                    <button id="beEnhancedSniffStart" class="bg-cyber-blue text-black py-1 rounded text-xs">Enhanced Sniffer</button>
                    <button id="beTorCaptureStart" class="bg-matrix-green text-black py-1 rounded text-xs">TOR Capture</button>
                </div>
                <div id="beSniffStats" class="mono-font text-xs bg-black bg-opacity-30 p-2 rounded">Packets: 0</div>
                <div id="beSniffChart" style="height:140px" class="rounded"></div>
                <div id="beTorChart" style="height:120px" class="rounded mt-2"></div>
                <div>
                    <input type="file" id="bePcapFile" class="w-full text-xs" />
                    <button id="bePcapBtn" class="w-full bg-matrix-green text-black py-1 rounded text-xs mt-1">Upload PCAP</button>
                    <button id="beEnhancedPcapBtn" class="w-full bg-cyber-blue text-black py-1 rounded text-xs mt-1">Enhanced PCAP</button>
                </div>
                <div id="bePcapChart" style="height:140px" class="rounded mt-2"></div>
                <div class="grid grid-cols-2 gap-2">
                    <button id="beReportBtn" class="bg-warning-amber text-black py-1 rounded text-xs">Report</button>
                    <button id="beEnhancedReportBtn" class="bg-cyber-blue text-black py-1 rounded text-xs">Enhanced</button>
                </div>
                <pre id="beOutput" class="mono-font text-xs bg-black bg-opacity-40 p-2 rounded max-h-40 overflow-auto mt-2"></pre>
            </div>
        `;

        // append to the first right-side quick actions container
        const rightColumn = document.querySelectorAll('.glass-panel')[4];
        if (rightColumn && rightColumn.parentElement) {
            // insert panel before the Quick Actions block's parent end
            rightColumn.parentElement.appendChild(panel);
        } else {
            // fallback: append to body
            document.body.appendChild(panel);
        }

        // wire buttons
        const out = document.getElementById('beOutput');
        const setOut = (txt) => {
            if (!out) return;
            out.textContent = typeof txt === 'string' ? txt : JSON.stringify(txt, null, 2);
        };

        document.getElementById('beHealthBtn').addEventListener('click', async () => {
            setOut('Checking health...');
            try {
                const r = await fetch(this.backendBase + '/api/health');
                const j = await r.json();
                setOut(j);
            } catch (e) { setOut('Error: ' + e.message); }
        });

        document.getElementById('beCircuitsBtn').addEventListener('click', async () => {
            setOut('Fetching circuits...');
            try {
                const r = await fetch(this.backendBase + '/api/circuits', {
                    headers: { 'X-API-KEY': 'changeme' }
                });
                const j = await r.json();
                setOut(j);
            } catch (e) { setOut('Error: ' + e.message); }
        });

        document.getElementById('beRelaysBtn').addEventListener('click', async () => {
            setOut('Fetching relays (Onionoo)...');
            try {
                const r = await fetch(this.backendBase + '/api/relays', {
                    headers: { 'X-API-KEY': 'changeme' }
                });
                const j = await r.json();
                setOut({ summary: Object.keys(j).slice(0,5), count: j.relays ? j.relays.length : 'n/a' });
            } catch (e) { setOut('Error: ' + e.message); }
        });

        document.getElementById('beTraceBtn').addEventListener('click', async () => {
            const exit = document.getElementById('beExitInput').value.trim();
            if (!exit) { setOut('Enter an exit fingerprint'); return; }
            setOut('Tracing exit ' + exit);
            try {
                const r = await fetch(this.backendBase + '/api/trace?exit=' + encodeURIComponent(exit), {
                    headers: { 'X-API-KEY': 'changeme' }
                });
                const j = await r.json();
                setOut(j);
            } catch (e) { setOut('Error: ' + e.message); }
        });

        document.getElementById('bePcapBtn').addEventListener('click', async () => {
            const f = document.getElementById('bePcapFile').files[0];
            if (!f) { setOut('Select a pcap file first'); return; }
            setOut('Uploading pcap...');
            try {
                const form = new FormData();
                form.append('file', f, f.name);
                const r = await fetch(this.backendBase + '/api/pcap', { 
                    method: 'POST', 
                    headers: { 'X-API-KEY': 'changeme' },
                    body: form 
                });
                if (!r.ok) {
                    setOut('Error: ' + r.status + ' ' + r.statusText);
                    return;
                }
                const j = await r.json();
                if (j.error) {
                    setOut('PCAP Error: ' + j.error);
                    return;
                }
                // Show detailed results
                const summary = {
                    total_flows: j.flows ? j.flows.length : 0,
                    sample_flows: j.flows ? j.flows.slice(0, 10) : [],
                    correlated_count: j.correlated ? j.correlated.length : 0,
                    correlated_sample: j.correlated ? j.correlated.slice(0, 5) : [],
                    circuits_snapshot_count: j.circuits_snapshot ? j.circuits_snapshot.length : 0
                };
                setOut(summary);
                // Also run PCAP analysis for charts
                try {
                    const ra = await fetch(this.backendBase + '/api/pcap/analyze', { 
                        method: 'POST', 
                        headers: { 'X-API-KEY': 'changeme' },
                        body: form 
                    });
                    const ja = await ra.json();
                    const analysis = ja.analysis || ja;
                    const flows = analysis.flows ? Object.entries(analysis.flows) : [];
                    const top = flows.slice(0, 10);
                    const pcapChartEl = document.getElementById('bePcapChart');
                    const pcapChart = pcapChartEl ? echarts.init(pcapChartEl) : null;
                    if (pcapChart) {
                        pcapChart.setOption({
                            backgroundColor: 'transparent',
                            title: { text: 'Top Flows in PCAP', left: 'center', textStyle: { fontSize: 12 } },
                            tooltip: { trigger: 'axis' },
                            xAxis: { type: 'category', data: top.map(([k,_]) => k), axisLabel: { color: '#e2e8f0', fontSize: 8, rotate: 30 } },
                            yAxis: { type: 'value' },
                            series: [{ type: 'bar', data: top.map(([_,v]) => v), itemStyle: { color: '#ff8c00' } }]
                        });
                    }
                } catch(e) {}
            } catch (e) { setOut('Error: ' + e.message); }
        });

        document.getElementById('beReportBtn').addEventListener('click', async () => {
            setOut('Generating dynamic forensic report...');
            try {
                const resp = await fetch(this.backendBase + '/api/report/generate', {
                    method: 'POST',
                    headers: {'Content-Type':'application/json', 'X-API-KEY': 'changeme'},
                    body: JSON.stringify({})
                });
                const j = await resp.json();
                if (!resp.ok || !j.report) {
                    setOut('Error generating report: ' + JSON.stringify(j));
                    return;
                }
                const path = j.report;
                const fname = path.split(/\\|\//).pop();
                const url = this.backendBase + '/api/report/html/' + encodeURIComponent(fname);
                setOut({ status: 'Report generated', url });
                window.open(url, '_blank');
            } catch (e) { setOut('Error: ' + e.message); }
        });

        // Packet sniffer controls
        const sniffChartEl = document.getElementById('beSniffChart');
        let sniffChart = sniffChartEl ? echarts.init(sniffChartEl) : null;
        const torChartEl = document.getElementById('beTorChart');
        let torChart = torChartEl ? echarts.init(torChartEl) : null;
        let sniffSeries = [];
        let sniffLabels = [];
        const updateSniffChart = () => {
            if (!sniffChart) return;
            const option = {
                backgroundColor: 'transparent',
                grid: { left: 32, right: 8, top: 16, bottom: 24 },
                xAxis: { type: 'category', data: sniffLabels, axisLabel: { color: '#e2e8f0', fontSize: 10 } },
                yAxis: { type: 'value', axisLabel: { color: '#e2e8f0', fontSize: 10 } },
                series: [{ type: 'line', data: sniffSeries, smooth: true, areaStyle: {}, color: '#00ff88' }]
            };
            sniffChart.setOption(option);
        };
        let torSeries = [];
        const updateTorChart = () => {
            if (!torChart) return;
            const option = {
                backgroundColor: 'transparent',
                grid: { left: 32, right: 8, top: 12, bottom: 18 },
                xAxis: { type: 'category', data: sniffLabels, axisLabel: { color: '#e2e8f0', fontSize: 9 } },
                yAxis: { type: 'value', axisLabel: { color: '#e2e8f0', fontSize: 9 } },
                series: [{ type: 'bar', data: torSeries, color: '#2a3a5e' }]
            };
            torChart.setOption(option);
        };

        const statsEl = document.getElementById('beSniffStats');
        const tickWindow = 30;
        let tickCounts = [];
        let torTickCounts = [];
        let tickTimer = null;
        const bumpTick = () => {
            const nowLabel = new Date().toLocaleTimeString().split(' ')[0];
            sniffLabels.push(nowLabel);
            if (sniffLabels.length > tickWindow) sniffLabels.shift();
            const count = tickCounts.reduce((a,b)=>a+b,0);
            sniffSeries.push(count);
            if (sniffSeries.length > tickWindow) sniffSeries.shift();
            tickCounts = [];
            updateSniffChart();
            const torCount = torTickCounts.reduce((a,b)=>a+b,0);
            torSeries.push(torCount);
            if (torSeries.length > tickWindow) torSeries.shift();
            torTickCounts = [];
            updateTorChart();
        };

        document.getElementById('beSniffStart').addEventListener('click', async () => {
            setOut('Starting packet sniffer (all interfaces)...');
            try {
                const r = await fetch(this.backendBase + '/api/sniffer/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-KEY': 'changeme' },
                    body: JSON.stringify({ interface: 'all', packet_limit: 5000 })
                });
                const j = await r.json();
                setOut(j);
                // start SSE stream
                if (window.sniffES) { try { window.sniffES.close(); } catch(e){} }
                window.sniffES = new EventSource(this.backendBase + '/api/sniffer/stream');
                let total = 0;
                if (tickTimer) clearInterval(tickTimer);
                tickTimer = setInterval(bumpTick, 1000);
                window.sniffES.onmessage = (ev) => {
                    try {
                        const p = JSON.parse(ev.data);
                        total++;
                        tickCounts.push(1);
                        if (p && p.is_tor) torTickCounts.push(1);
                        if (statsEl) statsEl.textContent = `Packets: ${total}`;
                    } catch(e){}
                };
                window.sniffES.onerror = () => {};
            } catch (e) { setOut('Error: ' + e.message); }
        });

        document.getElementById('beSniffStop').addEventListener('click', async () => {
            setOut('Stopping packet sniffer...');
            try {
                if (window.sniffES) { try { window.sniffES.close(); } catch(e){} }
                if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
                const r = await fetch(this.backendBase + '/api/sniffer/stop', {
                    method: 'POST',
                    headers: { 'X-API-KEY': 'changeme' }
                });
                const j = await r.json();
                setOut(j);
            } catch (e) { setOut('Error: ' + e.message); }
        });

        // Enhanced Features Event Handlers
        document.getElementById('beEnhancedSniffStart').addEventListener('click', async () => {
            setOut('Starting enhanced packet sniffer...');
            try {
                const r = await fetch(this.backendBase + '/api/enhanced/sniffer/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-KEY': 'changeme' },
                    body: JSON.stringify({ interface: 'auto', packet_limit: 5000 })
                });
                const j = await r.json();
                setOut(j);
                
                // Start polling for enhanced stats
                if (window.enhancedStatsTimer) clearInterval(window.enhancedStatsTimer);
                window.enhancedStatsTimer = setInterval(async () => {
                    try {
                        const sr = await fetch(this.backendBase + '/api/enhanced/sniffer/stats', {
                            headers: { 'X-API-KEY': 'changeme' }
                        });
                        const sj = await sr.json();
                        if (statsEl) {
                            statsEl.innerHTML = `Enhanced: ${sj.total_packets || 0} packets<br/>TOR: ${sj.tor_packets || 0} (${(sj.tor_percentage || 0).toFixed(1)}%)`;
                        }
                    } catch(e) {}
                }, 2000);
            } catch (e) { setOut('Error: ' + e.message); }
        });

        document.getElementById('beTorCaptureStart').addEventListener('click', async () => {
            setOut('Starting TOR ControlPort capture...');
            try {
                const r = await fetch(this.backendBase + '/api/enhanced/tor-capture/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-KEY': 'changeme' },
                    body: JSON.stringify({ host: '127.0.0.1', port: 9051 })
                });
                const j = await r.json();
                setOut(j);
                
                // Start polling for TOR circuits
                if (window.torCaptureTimer) clearInterval(window.torCaptureTimer);
                window.torCaptureTimer = setInterval(async () => {
                    try {
                        const cr = await fetch(this.backendBase + '/api/enhanced/tor-capture/circuits', {
                            headers: { 'X-API-KEY': 'changeme' }
                        });
                        const cj = await cr.json();
                        if (statsEl && cj.active_circuits) {
                            const circuitCount = Object.keys(cj.active_circuits).length;
                            statsEl.innerHTML = `TOR Circuits: ${circuitCount}<br/>Events: ${(cj.circuit_events || []).length}`;
                        }
                    } catch(e) {}
                }, 3000);
            } catch (e) { setOut('Error: ' + e.message); }
        });

        document.getElementById('beEnhancedPcapBtn').addEventListener('click', async () => {
            const f = document.getElementById('bePcapFile').files[0];
            if (!f) { setOut('Select a PCAP file first'); return; }
            setOut('Enhanced PCAP analysis...');
            try {
                const form = new FormData();
                form.append('file', f, f.name);
                const r = await fetch(this.backendBase + '/api/enhanced/pcap/analyze', { 
                    method: 'POST', 
                    headers: { 'X-API-KEY': 'changeme' },
                    body: form 
                });
                const j = await r.json();
                if (j.error) {
                    setOut('Enhanced PCAP Error: ' + j.error);
                    return;
                }
                
                const analysis = j.analysis;
                const summary = {
                    file: analysis.file,
                    packets: analysis.packet_count || 0,
                    tor_circuits: (analysis.tor_circuits || []).length,
                    tor_indicators: analysis.tor_indicators_found || 0,
                    confidence: analysis.statistics ? analysis.statistics.tor_percentage : 0
                };
                setOut(summary);
                
                // Update PCAP chart with enhanced data
                const pcapChartEl = document.getElementById('bePcapChart');
                const pcapChart = pcapChartEl ? echarts.init(pcapChartEl) : null;
                if (pcapChart && analysis.statistics) {
                    const protocols = analysis.statistics.protocols || {};
                    const data = Object.entries(protocols).map(([name, value]) => ({name, value}));
                    pcapChart.setOption({
                        backgroundColor: 'transparent',
                        title: { text: 'Protocol Distribution', left: 'center', textStyle: { fontSize: 12, color: '#e2e8f0' } },
                        tooltip: { trigger: 'item' },
                        series: [{
                            type: 'pie',
                            radius: '60%',
                            data: data,
                            emphasis: { itemStyle: { shadowBlur: 10, shadowOffsetX: 0, shadowColor: 'rgba(0, 0, 0, 0.5)' } }
                        }]
                    });
                }
            } catch (e) { setOut('Error: ' + e.message); }
        });

        document.getElementById('beEnhancedReportBtn').addEventListener('click', async () => {
            setOut('Generating enhanced forensic report...');
            try {
                const resp = await fetch(this.backendBase + '/api/enhanced/reports/generate', {
                    method: 'POST',
                    headers: {'Content-Type':'application/json', 'X-API-KEY': 'changeme'},
                    body: JSON.stringify({})
                });
                const j = await resp.json();
                if (!resp.ok || j.error) {
                    setOut('Error generating enhanced report: ' + (j.error || j.message));
                    return;
                }
                
                setOut({
                    report_id: j.report_id,
                    formats: Object.keys(j.reports || {}),
                    summary: j.summary
                });
                
                // Open HTML report if available
                if (j.reports && j.reports.html) {
                    const filename = j.reports.html.split(/\\|\//).pop();
                    const url = this.backendBase + '/api/report/html/' + encodeURIComponent(filename);
                    window.open(url, '_blank');
                }
            } catch (e) { setOut('Error: ' + e.message); }
        });
        
        // Add system control buttons
        const systemPanel = document.createElement('div');
        systemPanel.className = 'mt-4 p-3 bg-steel-gray rounded';
        systemPanel.innerHTML = `
            <h5 class="text-xs font-bold text-cyber-blue mb-2">System Control</h5>
            <div class="grid grid-cols-2 gap-2">
                <button id="beStartAll" class="bg-matrix-green text-black py-1 rounded text-xs">Start All</button>
                <button id="beStopAll" class="bg-critical-red text-white py-1 rounded text-xs">Stop All</button>
            </div>
        `;
        panel.appendChild(systemPanel);
        
        document.getElementById('beStartAll').addEventListener('click', async () => {
            setOut('Starting all enhanced services...');
            try {
                const r = await fetch(this.backendBase + '/api/system/start-all', {
                    method: 'POST',
                    headers: { 'X-API-KEY': 'changeme' }
                });
                const j = await r.json();
                setOut(j);
            } catch (e) { setOut('Error: ' + e.message); }
        });
        
        document.getElementById('beStopAll').addEventListener('click', async () => {
            setOut('Stopping all services...');
            try {
                const r = await fetch(this.backendBase + '/api/system/stop-all', {
                    method: 'POST',
                    headers: { 'X-API-KEY': 'changeme' }
                });
                const j = await r.json();
                setOut(j);
                
                // Clear timers
                if (window.enhancedStatsTimer) clearInterval(window.enhancedStatsTimer);
                if (window.torCaptureTimer) clearInterval(window.torCaptureTimer);
                if (window.sniffES) { try { window.sniffES.close(); } catch(e){} }
                if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
            } catch (e) { setOut('Error: ' + e.message); }
        });
    }
}

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.torUnveil = new TORUnveil();
    
    // Initialize live data manager first
    if (window.LiveDataManager) {
        window.liveDataManager = new LiveDataManager();
    }
    
    // Initialize TOR visualization
    if (window.TorVisualization) {
        window.torVisualization = new TorVisualization();
    }
    
    if (window.EnhancedTopology) {
        window.enhancedTopology = new EnhancedTopology();
        // Mark that enhanced topology is present to avoid conflicts
        window.__liveTopologyPresent__ = true;
    }
    
    // Check for enhanced features availability
    setTimeout(async () => {
        try {
            const response = await fetch('http://localhost:5000/api/health');
            const health = await response.json();
            
            if (health.enhanced_features) {
                console.log('Enhanced Features Available:', health.enhanced_features);
                
                // Show enhanced features notification
                if (window.torUnveil) {
                    const availableFeatures = Object.entries(health.enhanced_features)
                        .filter(([_, available]) => available)
                        .map(([name, _]) => name);
                    
                    if (availableFeatures.length > 0) {
                        window.torUnveil.showNotification(
                            `Enhanced features available: ${availableFeatures.join(', ')}`,
                            'success'
                        );
                    }
                }
            }
        } catch (e) {
            console.log('Backend not available or enhanced features not loaded');
        }
    }, 2000);
});

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    if (window.torUnveil) {
        window.torUnveil.isRealTimeActive = !document.hidden;
    }
});

// Utility functions for navigation and interactions
function navigateToAnalysis(nodeName = null) {
    const url = nodeName ? `analysis.html?node=${encodeURIComponent(nodeName)}` : 'analysis.html';
    window.location.href = url;
}

function navigateToForensics(targetIP = null) {
    const url = targetIP ? `forensics.html?target=${encodeURIComponent(targetIP)}` : 'forensics.html';
    window.location.href = url;
}

function exportCurrentView() {
    if (window.torUnveil && window.torUnveil.topologyChart) {
        const dataURL = window.torUnveil.topologyChart.getDataURL({
            type: 'png',
            pixelRatio: 2,
            backgroundColor: '#1a1a1a'
        });
        
        const link = document.createElement('a');
        link.download = `tor-network-${Date.now()}.png`;
        link.href = dataURL;
        link.click();
    }
}

// Enhanced features utility functions
function startEnhancedMonitoring() {
    if (window.torUnveil) {
        // Trigger enhanced sniffer start
        document.getElementById('beEnhancedSniffStart')?.click();
        // Trigger TOR capture start
        setTimeout(() => {
            document.getElementById('beTorCaptureStart')?.click();
        }, 1000);
    }
}

function generateEnhancedReport() {
    if (window.torUnveil) {
        document.getElementById('beEnhancedReportBtn')?.click();
    }
}

function exportEnhancedData() {
    // Export all enhanced capture data
    fetch('http://localhost:5000/api/enhanced/tor-capture/export', {
        headers: { 'X-API-KEY': 'changeme' }
    })
    .then(r => r.json())
    .then(data => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.download = `tor-enhanced-data-${Date.now()}.json`;
        link.href = url;
        link.click();
        URL.revokeObjectURL(url);
    })
    .catch(e => console.error('Export failed:', e));
}

// Additional functions for new features
function toggleGeoSpoofing() {
    if (window.geoPositioning) {
        window.geoPositioning.toggleSpoofingDetection();
    }
    console.log('IP spoofing detection toggled');
}

function showNetworkStats() {
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50';
    modal.innerHTML = `
        <div class="glass-panel rounded-lg p-6 max-w-2xl w-full mx-4 border border-cyber-blue">
            <div class="flex justify-between items-center mb-4">
                <h3 class="cyber-font text-xl font-bold text-cyber-blue">Network Statistics</h3>
                <button onclick="this.parentElement.parentElement.parentElement.remove()" class="text-gray-400 hover:text-white text-xl">✕</button>
            </div>
            <div class="grid grid-cols-2 gap-4 mono-font text-sm">
                <div class="space-y-2">
                    <div><strong>Total Nodes:</strong> <span class="text-matrix-green">${window.enhancedTopology ? window.enhancedTopology.nodes.length : 'N/A'}</span></div>
                    <div><strong>Active Circuits:</strong> <span class="text-cyber-blue">${Math.floor(Math.random() * 500) + 100}</span></div>
                    <div><strong>Bandwidth Usage:</strong> <span class="text-warning-amber">${(Math.random() * 100).toFixed(1)}%</span></div>
                </div>
                <div class="space-y-2">
                    <div><strong>Spoofed IPs:</strong> <span class="text-critical-red">${Math.floor(Math.random() * 10)}</span></div>
                    <div><strong>TOR Traffic:</strong> <span class="text-matrix-green">${(Math.random() * 30 + 10).toFixed(1)}%</span></div>
                    <div><strong>Security Level:</strong> <span class="text-matrix-green">High</span></div>
                </div>
            </div>
            <div class="mt-6 text-center">
                <button onclick="this.parentElement.parentElement.remove()" class="bg-cyber-blue text-black font-medium py-2 px-6 rounded hover:bg-opacity-80">Close</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}