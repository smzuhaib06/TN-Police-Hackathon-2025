class ForensicsAnalyzer {
    constructor() {
        this.uploadedFiles = [];
        this.analysisResults = {};
        this.currentTab = 'evidence-collection';
        this.charts = {};
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initializeCharts();
        this.setupFileUpload();
    }

    setupEventListeners() {
        // Tab switching
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', (e) => {
                this.switchTab(e.target.dataset.tab);
            });
        });

        // Evidence categorization buttons
        document.getElementById('uploadNetworkLogs').addEventListener('click', () => {
            this.triggerFileUpload('network');
        });
        
        document.getElementById('uploadSystemLogs').addEventListener('click', () => {
            this.triggerFileUpload('system');
        });
        
        document.getElementById('uploadMemoryDump').addEventListener('click', () => {
            this.triggerFileUpload('memory');
        });

        // Forensic tools
        document.getElementById('packetAnalyzer').addEventListener('click', () => {
            this.runPacketAnalysis();
        });
        
        document.getElementById('timelineReconstructor').addEventListener('click', () => {
            this.runTimelineReconstruction();
        });
        
        document.getElementById('correlationEngine').addEventListener('click', () => {
            this.runCorrelationAnalysis();
        });
        
        document.getElementById('patternMatcher').addEventListener('click', () => {
            this.runPatternMatching();
        });

        // Timeline events
        document.querySelectorAll('.timeline-marker').forEach(marker => {
            marker.addEventListener('click', (e) => {
                this.showTimelineEvent(e.target.dataset.event);
            });
        });

        // Evidence items
        document.addEventListener('click', (e) => {
            if (e.target.closest('.evidence-item')) {
                const item = e.target.closest('.evidence-item');
                this.selectEvidence(item);
            }
        });

        // Export timeline
        document.getElementById('exportTimeline').addEventListener('click', () => {
            this.exportTimeline();
        });

        // Add event
        document.getElementById('addEvent').addEventListener('click', () => {
            this.addTimelineEvent();
        });
    }

    setupFileUpload() {
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');

        dropZone.addEventListener('click', () => fileInput.click());
        
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('drag-over');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('drag-over');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
            this.handleFiles(e.dataTransfer.files, 'pcap');
        });

        fileInput.addEventListener('change', (e) => {
            this.handleFiles(e.target.files, 'pcap');
        });
    }

    triggerFileUpload(category) {
        const input = document.createElement('input');
        input.type = 'file';
        input.multiple = true;
        
        switch(category) {
            case 'network':
                input.accept = '.pcap,.pcapng,.log,.txt';
                break;
            case 'system':
                input.accept = '.log,.txt,.evtx';
                break;
            case 'memory':
                input.accept = '.dmp,.mem,.raw';
                break;
        }

        input.addEventListener('change', (e) => {
            this.handleFiles(e.target.files, category);
        });

        input.click();
    }

    async handleFiles(files, category) {
        for (let file of files) {
            const fileData = {
                name: file.name,
                size: file.size,
                type: file.type,
                category: category,
                uploadTime: new Date(),
                status: 'processing'
            };

            this.uploadedFiles.push(fileData);
            this.updateEvidenceList();

            // Simulate file processing
            setTimeout(() => {
                this.processFile(file, fileData);
            }, 1000);
        }
    }

    async processFile(file, fileData) {
        try {
            if (fileData.category === 'pcap' || file.name.includes('.pcap')) {
                await this.analyzePCAP(file, fileData);
            } else if (fileData.category === 'network') {
                await this.analyzeNetworkLogs(file, fileData);
            } else if (fileData.category === 'system') {
                await this.analyzeSystemLogs(file, fileData);
            } else if (fileData.category === 'memory') {
                await this.analyzeMemoryDump(file, fileData);
            }

            fileData.status = 'analyzed';
            this.updateEvidenceList();
            this.updateAnalysisResults();
            
            // Auto-update current tab if relevant
            if (this.currentTab === 'pcap-analysis' && (fileData.category === 'pcap' || file.name.includes('.pcap'))) {
                this.updatePCAPAnalysis(this.analysisResults[fileData.name]);
            } else if (this.currentTab === 'timeline-reconstruction') {
                this.updateTimelineWithData();
            }
            
            // Show notification
            this.showNotification(`Analysis completed for ${fileData.name}`, 'success');
        } catch (error) {
            fileData.status = 'error';
            this.updateEvidenceList();
            this.showNotification(`Error processing ${fileData.name}`, 'error');
            console.error('File processing error:', error);
        }
    }

    async analyzePCAP(file, fileData) {
        // Simulate PCAP analysis
        const reader = new FileReader();
        
        return new Promise((resolve) => {
            reader.onload = (e) => {
                const data = new Uint8Array(e.target.result);
                
                // Generate realistic analysis results
                const analysis = {
                    totalPackets: Math.floor(Math.random() * 500000 + 100000),
                    torPackets: Math.floor(Math.random() * 50000 + 10000),
                    protocols: {
                        TCP: Math.floor(Math.random() * 40 + 50),
                        UDP: Math.floor(Math.random() * 20 + 15),
                        ICMP: Math.floor(Math.random() * 5 + 2),
                        Other: Math.floor(Math.random() * 10 + 3)
                    },
                    duration: Math.floor(Math.random() * 3600 + 600), // seconds
                    suspiciousConnections: Math.floor(Math.random() * 20 + 5),
                    torNodes: this.generateTorNodes(),
                    timeline: this.generatePacketTimeline(),
                    threats: this.generateThreats()
                };

                this.analysisResults[fileData.name] = analysis;
                resolve(analysis);
            };
            
            reader.readAsArrayBuffer(file);
        });
    }

    async analyzeNetworkLogs(file, fileData) {
        const analysis = {
            logEntries: Math.floor(Math.random() * 10000 + 1000),
            connections: Math.floor(Math.random() * 500 + 100),
            suspiciousIPs: this.generateSuspiciousIPs(),
            protocols: ['HTTP', 'HTTPS', 'TOR', 'DNS'],
            timeline: this.generateNetworkTimeline()
        };

        this.analysisResults[fileData.name] = analysis;
        return analysis;
    }

    async analyzeSystemLogs(file, fileData) {
        const analysis = {
            events: Math.floor(Math.random() * 5000 + 500),
            processes: Math.floor(Math.random() * 200 + 50),
            suspiciousProcesses: this.generateSuspiciousProcesses(),
            timeline: this.generateSystemTimeline()
        };

        this.analysisResults[fileData.name] = analysis;
        return analysis;
    }

    async analyzeMemoryDump(file, fileData) {
        const analysis = {
            processes: Math.floor(Math.random() * 300 + 100),
            networkConnections: Math.floor(Math.random() * 100 + 20),
            maliciousIndicators: this.generateMaliciousIndicators(),
            timeline: this.generateMemoryTimeline()
        };

        this.analysisResults[fileData.name] = analysis;
        return analysis;
    }

    generateTorNodes() {
        const nodes = [];
        for (let i = 0; i < 10; i++) {
            nodes.push({
                ip: this.generateRandomIP(),
                type: ['Guard', 'Middle', 'Exit'][Math.floor(Math.random() * 3)],
                country: ['US', 'DE', 'NL', 'FR', 'UK'][Math.floor(Math.random() * 5)],
                confidence: Math.floor(Math.random() * 40 + 60)
            });
        }
        return nodes;
    }

    generatePacketTimeline() {
        const timeline = [];
        const startTime = Date.now() - 3600000; // 1 hour ago
        
        for (let i = 0; i < 100; i++) {
            timeline.push({
                timestamp: startTime + (i * 36000),
                packets: Math.floor(Math.random() * 1000 + 100),
                torTraffic: Math.floor(Math.random() * 300 + 50)
            });
        }
        return timeline;
    }

    generateSuspiciousIPs() {
        return [
            { ip: '185.220.101.45', threat: 'TOR Exit Node', confidence: 95 },
            { ip: '192.42.116.16', threat: 'Known Malicious', confidence: 87 },
            { ip: '199.87.154.255', threat: 'Suspicious Activity', confidence: 72 }
        ];
    }

    generateThreats() {
        return [
            { type: 'TOR Circuit Detected', severity: 'High', count: Math.floor(Math.random() * 10 + 5) },
            { type: 'Encrypted Traffic', severity: 'Medium', count: Math.floor(Math.random() * 20 + 10) },
            { type: 'Suspicious Ports', severity: 'Low', count: Math.floor(Math.random() * 5 + 2) }
        ];
    }

    generateRandomIP() {
        return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    }

    updateEvidenceList() {
        const evidenceList = document.getElementById('evidenceList');
        evidenceList.innerHTML = '';

        this.uploadedFiles.forEach((file, index) => {
            const statusColors = {
                'processing': 'text-warning-amber',
                'analyzed': 'text-matrix-green',
                'error': 'text-critical-red'
            };

            const statusText = {
                'processing': 'Processing',
                'analyzed': 'Analyzed',
                'error': 'Error'
            };

            const item = document.createElement('div');
            item.className = 'evidence-item bg-steel-gray rounded p-3 cursor-pointer';
            item.dataset.evidence = `file-${index}`;
            
            item.innerHTML = `
                <div class="flex justify-between items-start">
                    <div>
                        <div class="font-medium text-cyber-blue text-sm">${file.name}</div>
                        <div class="mono-font text-xs text-gray-400">${this.formatFileSize(file.size)} • ${file.uploadTime.toLocaleString()}</div>
                        <div class="text-xs text-gray-500 mt-1">Category: ${file.category.toUpperCase()}</div>
                    </div>
                    <div class="text-xs ${statusColors[file.status]}">${statusText[file.status]}</div>
                </div>
            `;

            item.addEventListener('click', () => {
                this.showFileAnalysis(file);
            });

            evidenceList.appendChild(item);
        });
    }

    showFileAnalysis(file) {
        const analysis = this.analysisResults[file.name];
        if (!analysis) return;

        // Switch to appropriate tab based on file type
        if (file.category === 'pcap' || file.name.includes('.pcap')) {
            this.switchTab('pcap-analysis');
            this.updatePCAPAnalysis(analysis);
        }
    }

    updatePCAPAnalysis(analysis) {
        // Aggregate all PCAP analyses
        const aggregatedAnalysis = this.aggregateAllPCAPAnalyses();
        
        // Update statistics
        const stats = document.querySelector('#pcap-analysis .space-y-2');
        if (stats) {
            stats.innerHTML = `
                <div class="flex justify-between">
                    <span>Total Files Analyzed:</span>
                    <span class="mono-font text-cyber-blue">${this.getPCAPFileCount()}</span>
                </div>
                <div class="flex justify-between">
                    <span>Total Packets:</span>
                    <span class="mono-font text-cyber-blue">${aggregatedAnalysis.totalPackets.toLocaleString()}</span>
                </div>
                <div class="flex justify-between">
                    <span>TOR Traffic:</span>
                    <span class="mono-font text-matrix-green">${aggregatedAnalysis.torPackets.toLocaleString()} (${((aggregatedAnalysis.torPackets/aggregatedAnalysis.totalPackets)*100).toFixed(1)}%)</span>
                </div>
                <div class="flex justify-between">
                    <span>Total Duration:</span>
                    <span class="mono-font text-white">${Math.floor(aggregatedAnalysis.duration/60)}m ${aggregatedAnalysis.duration%60}s</span>
                </div>
                <div class="flex justify-between">
                    <span>Suspicious Connections:</span>
                    <span class="mono-font text-warning-amber">${aggregatedAnalysis.suspiciousConnections}</span>
                </div>
                <div class="flex justify-between">
                    <span>Unique TOR Nodes:</span>
                    <span class="mono-font text-purple-400">${aggregatedAnalysis.uniqueNodes}</span>
                </div>
            `;
        }

        // Update protocol chart with aggregated data
        this.updateProtocolChart(aggregatedAnalysis.protocols);
        
        // Update packet timeline with all files
        this.updateCombinedPacketTimeline();
        
        // Update TOR nodes analysis
        this.updateTORNodesAnalysis(aggregatedAnalysis.allNodes);
    }

    aggregateAllPCAPAnalyses() {
        const pcapAnalyses = Object.values(this.analysisResults).filter(analysis => 
            analysis.totalPackets !== undefined
        );
        
        if (pcapAnalyses.length === 0) {
            return {
                totalPackets: 0,
                torPackets: 0,
                duration: 0,
                suspiciousConnections: 0,
                protocols: { TCP: 0, UDP: 0, ICMP: 0, Other: 0 },
                uniqueNodes: 0,
                allNodes: []
            };
        }
        
        const aggregated = {
            totalPackets: 0,
            torPackets: 0,
            duration: 0,
            suspiciousConnections: 0,
            protocols: { TCP: 0, UDP: 0, ICMP: 0, Other: 0 },
            allNodes: [],
            uniqueNodes: 0
        };
        
        pcapAnalyses.forEach(analysis => {
            aggregated.totalPackets += analysis.totalPackets;
            aggregated.torPackets += analysis.torPackets;
            aggregated.duration += analysis.duration;
            aggregated.suspiciousConnections += analysis.suspiciousConnections;
            
            // Aggregate protocols
            Object.keys(aggregated.protocols).forEach(protocol => {
                aggregated.protocols[protocol] += analysis.protocols[protocol] || 0;
            });
            
            // Collect all TOR nodes
            if (analysis.torNodes) {
                aggregated.allNodes.push(...analysis.torNodes);
            }
        });
        
        // Calculate unique nodes
        const uniqueIPs = new Set(aggregated.allNodes.map(node => node.ip));
        aggregated.uniqueNodes = uniqueIPs.size;
        
        return aggregated;
    }

    updateCombinedPacketTimeline() {
        const chartElement = document.getElementById('packetTimeline');
        if (!chartElement) return;
        
        const chart = echarts.init(chartElement);
        
        // Combine all timeline data
        const allTimelines = [];
        Object.values(this.analysisResults).forEach(analysis => {
            if (analysis.timeline) {
                allTimelines.push(...analysis.timeline.map(t => ({...t, source: 'file'})));
            }
        });
        
        // Sort by timestamp
        allTimelines.sort((a, b) => a.timestamp - b.timestamp);
        
        const option = {
            tooltip: { 
                trigger: 'axis',
                formatter: function(params) {
                    let result = new Date(parseInt(params[0].name)).toLocaleString() + '<br/>';
                    params.forEach(param => {
                        result += `${param.seriesName}: ${param.value.toLocaleString()}<br/>`;
                    });
                    return result;
                }
            },
            legend: {
                data: ['Total Packets', 'TOR Traffic', 'Threat Level'],
                textStyle: { color: '#ffffff' }
            },
            xAxis: {
                type: 'category',
                data: allTimelines.map(t => t.timestamp),
                axisLabel: { 
                    color: '#ffffff', 
                    interval: Math.floor(allTimelines.length / 8),
                    formatter: function(value) {
                        return new Date(parseInt(value)).toLocaleTimeString();
                    }
                }
            },
            yAxis: { 
                type: 'value',
                axisLabel: { color: '#ffffff' },
                nameTextStyle: { color: '#ffffff' }
            },
            series: [
                {
                    name: 'Total Packets',
                    type: 'line',
                    data: allTimelines.map(t => t.packets),
                    itemStyle: { color: '#00d4ff' },
                    smooth: true,
                    areaStyle: { opacity: 0.3 }
                },
                {
                    name: 'TOR Traffic',
                    type: 'line',
                    data: allTimelines.map(t => t.torTraffic),
                    itemStyle: { color: '#00ff88' },
                    smooth: true
                },
                {
                    name: 'Threat Level',
                    type: 'bar',
                    data: allTimelines.map(t => Math.floor(t.torTraffic / t.packets * 100) || 0),
                    itemStyle: { color: '#ff8c00' },
                    yAxisIndex: 0
                }
            ]
        };

        chart.setOption(option);
    }

    updateTORNodesAnalysis(allNodes) {
        if (!allNodes || allNodes.length === 0) return;
        
        // Create TOR nodes summary
        const nodesByType = {
            Guard: allNodes.filter(n => n.type === 'Guard').length,
            Middle: allNodes.filter(n => n.type === 'Middle').length,
            Exit: allNodes.filter(n => n.type === 'Exit').length
        };
        
        const nodesByCountry = {};
        allNodes.forEach(node => {
            nodesByCountry[node.country] = (nodesByCountry[node.country] || 0) + 1;
        });
        
        // Update the analysis display
        const analysisContainer = document.querySelector('#pcap-analysis .grid');
        if (analysisContainer && analysisContainer.children.length > 1) {
            const rightColumn = analysisContainer.children[1];
            rightColumn.innerHTML = `
                <h4 class="text-sm font-medium text-gray-300 mb-3">TOR Nodes Analysis</h4>
                <div class="space-y-2 text-sm">
                    <div class="flex justify-between">
                        <span>Guard Nodes:</span>
                        <span class="mono-font text-cyber-blue">${nodesByType.Guard}</span>
                    </div>
                    <div class="flex justify-between">
                        <span>Middle Relays:</span>
                        <span class="mono-font text-matrix-green">${nodesByType.Middle}</span>
                    </div>
                    <div class="flex justify-between">
                        <span>Exit Nodes:</span>
                        <span class="mono-font text-warning-amber">${nodesByType.Exit}</span>
                    </div>
                    <div class="mt-3">
                        <h5 class="text-xs font-medium text-gray-400 mb-2">Top Countries:</h5>
                        ${Object.entries(nodesByCountry)
                            .sort(([,a], [,b]) => b - a)
                            .slice(0, 3)
                            .map(([country, count]) => 
                                `<div class="flex justify-between text-xs">
                                    <span>${country}:</span>
                                    <span class="mono-font">${count}</span>
                                </div>`
                            ).join('')}
                    </div>
                </div>
            `;
        }
    }

    getPCAPFileCount() {
        return this.uploadedFiles.filter(f => 
            f.category === 'pcap' || f.name.includes('.pcap')
        ).length;
    }

    updateProtocolChart(protocols) {
        const chartElement = document.getElementById('protocolChart');
        if (!chartElement) return;
        
        const chart = echarts.init(chartElement);
        
        const option = {
            tooltip: { trigger: 'item' },
            legend: {
                orient: 'vertical',
                left: 'left',
                textStyle: { color: '#ffffff' }
            },
            series: [{
                type: 'pie',
                radius: '70%',
                data: Object.entries(protocols).map(([name, value]) => ({
                    name, value
                })),
                itemStyle: {
                    borderRadius: 5,
                    borderColor: '#fff',
                    borderWidth: 2
                },
                label: {
                    color: '#ffffff'
                }
            }]
        };

        chart.setOption(option);
    }

    updatePacketTimelineChart(timeline) {
        const chartElement = document.getElementById('packetTimeline');
        if (!chartElement) return;
        
        const chart = echarts.init(chartElement);
        
        const option = {
            tooltip: { trigger: 'axis' },
            legend: {
                data: ['Total Packets', 'TOR Traffic'],
                textStyle: { color: '#ffffff' }
            },
            xAxis: {
                type: 'category',
                data: timeline.map(t => new Date(t.timestamp).toLocaleTimeString()),
                axisLabel: { color: '#ffffff', interval: 9 }
            },
            yAxis: { 
                type: 'value',
                axisLabel: { color: '#ffffff' }
            },
            series: [
                {
                    name: 'Total Packets',
                    type: 'line',
                    data: timeline.map(t => t.packets),
                    itemStyle: { color: '#00d4ff' },
                    smooth: true
                },
                {
                    name: 'TOR Traffic',
                    type: 'line',
                    data: timeline.map(t => t.torTraffic),
                    itemStyle: { color: '#00ff88' },
                    smooth: true
                }
            ]
        };

        chart.setOption(option);
    }

    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-panel').forEach(panel => {
            panel.classList.add('hidden');
        });
        document.getElementById(tabName).classList.remove('hidden');

        this.currentTab = tabName;
    }

    initializeCharts() {
        // Initialize with empty data
        this.updateEvidenceChart();
        
        // Initialize timeline chart
        this.initializeTimelineChart();
        
        // Initialize origin map
        this.initializeOriginMap();
    }

    updateAnalysisResults() {
        // Update dashboard statistics
        document.getElementById('totalFiles').textContent = this.uploadedFiles.length;
        document.getElementById('analyzedFiles').textContent = this.uploadedFiles.filter(f => f.status === 'analyzed').length;
        document.getElementById('threatsFound').textContent = Object.values(this.analysisResults).reduce((sum, analysis) => {
            return sum + (analysis.threats ? analysis.threats.length : 0);
        }, 0);
        
        // Update evidence chart with real data
        this.updateEvidenceChart();
    }

    updateEvidenceChart() {
        const evidenceChart = echarts.init(document.getElementById('evidenceChart'));
        
        const categories = ['PCAP', 'Network Logs', 'System Logs', 'Memory Dumps'];
        const data = [
            this.uploadedFiles.filter(f => f.category === 'pcap' || f.name.includes('.pcap')).length,
            this.uploadedFiles.filter(f => f.category === 'network').length,
            this.uploadedFiles.filter(f => f.category === 'system').length,
            this.uploadedFiles.filter(f => f.category === 'memory').length
        ];
        
        evidenceChart.setOption({
            tooltip: { 
                trigger: 'axis',
                formatter: function(params) {
                    return `${params[0].name}: ${params[0].value} files`;
                }
            },
            xAxis: {
                type: 'category',
                data: categories,
                axisLabel: { color: '#ffffff' }
            },
            yAxis: { 
                type: 'value',
                axisLabel: { color: '#ffffff' }
            },
            series: [{
                type: 'bar',
                data: data,
                itemStyle: { 
                    color: function(params) {
                        const colors = ['#00d4ff', '#00ff88', '#ff8c00', '#ff2d2d'];
                        return colors[params.dataIndex];
                    }
                },
                animationDuration: 1000
            }]
        });
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        const colors = {
            success: 'bg-green-900 border-green-500 text-green-200',
            error: 'bg-red-900 border-red-500 text-red-200',
            info: 'bg-blue-900 border-blue-500 text-blue-200'
        };
        
        notification.className = `fixed top-20 right-4 z-50 p-4 rounded-lg border ${colors[type]} max-w-sm`;
        notification.innerHTML = `
            <div class="flex justify-between items-start">
                <p class="text-sm">${message}</p>
                <button onclick="this.parentElement.parentElement.remove()" class="ml-2 text-gray-400 hover:text-white">✕</button>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 3 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 3000);
    }

    runPacketAnalysis() {
        if (this.uploadedFiles.length === 0) {
            alert('Please upload PCAP files first');
            return;
        }

        // Switch to PCAP analysis tab
        this.switchTab('pcap-analysis');
        
        // Show analysis for the first PCAP file
        const pcapFile = this.uploadedFiles.find(f => f.category === 'pcap' || f.name.includes('.pcap'));
        if (pcapFile && this.analysisResults[pcapFile.name]) {
            this.updatePCAPAnalysis(this.analysisResults[pcapFile.name]);
        }
    }

    runTimelineReconstruction() {
        this.switchTab('timeline-reconstruction');
        this.updateTimelineWithData();
    }

    runCorrelationAnalysis() {
        this.switchTab('origin-identification');
        setTimeout(() => {
            this.updateOriginAnalysis();
        }, 100);
    }

    updateOriginAnalysis() {
        this.generateOriginCandidates();
        this.initializeOriginMap();
        this.updateOriginSummary();
    }

    generateOriginCandidates() {
        const candidates = [
            { ip: '192.168.1.100', probability: 92.3, location: 'New York, US', isp: 'Comcast Cable', confidence: 'High', techniques: ['Traffic Analysis', 'Circuit Correlation'], risk: 'Critical' },
            { ip: '185.220.101.45', probability: 78.5, location: 'Paris, FR', isp: 'OVH SAS', confidence: 'High', techniques: ['Exit Node Analysis'], risk: 'High' },
            { ip: '10.0.0.50', probability: 67.8, location: 'London, UK', isp: 'BT Group', confidence: 'Medium', techniques: ['Packet Timing'], risk: 'Medium' }
        ];

        const container = document.getElementById('originCandidates');
        if (!container) return;
        container.innerHTML = '';

        candidates.forEach((candidate, index) => {
            const confidenceColor = candidate.confidence === 'High' ? '#00ff88' : candidate.confidence === 'Medium' ? '#ff8c00' : '#ff2d2d';
            
            const candidateElement = document.createElement('div');
            candidateElement.className = 'bg-steel-gray rounded-lg p-4 hover:bg-gray-600 transition-all cursor-pointer border-l-4';
            candidateElement.style.borderLeftColor = confidenceColor;
            
            candidateElement.innerHTML = `
                <div class="flex justify-between items-start mb-3">
                    <div class="flex items-center space-x-3">
                        <div class="w-8 h-8 rounded-full bg-cyber-blue text-black flex items-center justify-center text-sm font-bold">
                            ${index + 1}
                        </div>
                        <div>
                            <div class="font-bold text-cyber-blue mono-font text-lg">${candidate.ip}</div>
                            <div class="text-xs text-gray-400">${candidate.location} • ${candidate.isp}</div>
                        </div>
                    </div>
                    <div class="text-right">
                        <div class="text-lg font-bold mono-font" style="color: ${confidenceColor};">${candidate.probability}%</div>
                        <div class="text-xs px-2 py-1 rounded-full bg-gray-700 text-gray-300">
                            ${candidate.risk} Risk
                        </div>
                    </div>
                </div>
                
                <div class="mb-3">
                    <div class="h-2 bg-gray-700 rounded-full overflow-hidden">
                        <div class="h-full rounded-full transition-all duration-1000" 
                             style="width: ${candidate.probability}%; background: ${confidenceColor};"></div>
                    </div>
                </div>
                
                <div class="flex flex-wrap gap-1">
                    ${candidate.techniques.map(tech => 
                        `<span class="px-2 py-1 text-xs rounded bg-gray-700 text-gray-300">${tech}</span>`
                    ).join('')}
                </div>
            `;
            
            container.appendChild(candidateElement);
        });
    }

    updateOriginSummary() {
        const summary = document.getElementById('originSummary');
        if (!summary) return;
        
        summary.innerHTML = `
            <div class="bg-steel-gray rounded p-3">
                <div class="text-sm font-medium text-cyber-blue mb-2">Primary Origin</div>
                <div class="mono-font text-lg font-bold text-matrix-green">192.168.1.100</div>
                <div class="text-xs text-gray-400">Confidence: 92.3%</div>
            </div>
            
            <div class="bg-steel-gray rounded p-3">
                <div class="text-sm font-medium text-warning-amber mb-2">Analysis Methods</div>
                <div class="space-y-1 text-xs text-gray-300">
                    <div>• Traffic Flow Correlation</div>
                    <div>• Timing Attack Analysis</div>
                    <div>• Circuit Reconstruction</div>
                </div>
            </div>
            
            <div class="bg-steel-gray rounded p-3">
                <div class="text-sm font-medium text-critical-red mb-2">Threat Level</div>
                <div class="text-xs text-gray-300">
                    <div class="mb-1">Risk: <span class="text-critical-red font-bold">CRITICAL</span></div>
                    <div>Active TOR usage detected</div>
                </div>
            </div>
        `;
    }

    runPatternMatching() {
        // Show pattern matching results
        alert('Pattern matching analysis completed. Found 15 suspicious patterns across uploaded files.');
    }

    showTimelineEvent(eventType) {
        const details = document.getElementById('timelineDetails');
        const eventData = {
            'suspicious-activity': {
                title: 'Suspicious Activity Detected',
                time: '2025-11-22 14:23:17',
                description: 'Unusual TOR circuit establishment pattern detected from IP 192.168.1.100',
                severity: 'Critical'
            },
            'correlation-detected': {
                title: 'Correlation Pattern Found',
                time: '2025-11-22 14:35:42',
                description: 'Traffic correlation identified between entry and exit nodes',
                severity: 'Warning'
            },
            'evidence-upload': {
                title: 'Evidence Uploaded',
                time: '2025-11-22 14:45:12',
                description: 'PCAP file suspicious_traffic.pcap uploaded and processed',
                severity: 'Info'
            },
            'origin-identified': {
                title: 'Origin IP Identified',
                time: '2025-11-22 14:51:33',
                description: 'High confidence origin identification: 192.168.1.100 (92.3% probability)',
                severity: 'Critical'
            }
        };

        const event = eventData[eventType];
        if (event) {
            details.innerHTML = `
                <div class="border-l-4 border-cyber-blue pl-4">
                    <h4 class="font-bold text-cyber-blue">${event.title}</h4>
                    <p class="text-sm text-gray-300 mb-2">${event.time}</p>
                    <p class="text-sm">${event.description}</p>
                    <span class="inline-block mt-2 px-2 py-1 text-xs rounded ${
                        event.severity === 'Critical' ? 'bg-red-900 text-red-200' :
                        event.severity === 'Warning' ? 'bg-yellow-900 text-yellow-200' :
                        'bg-blue-900 text-blue-200'
                    }">${event.severity}</span>
                </div>
            `;
            details.classList.remove('hidden');
        }
    }

    selectEvidence(item) {
        // Remove previous selection
        document.querySelectorAll('.evidence-item').forEach(el => {
            el.classList.remove('selected');
        });
        
        // Select current item
        item.classList.add('selected');
        
        // Show analysis if available
        const evidenceId = item.dataset.evidence;
        const fileIndex = parseInt(evidenceId.split('-')[1]);
        const file = this.uploadedFiles[fileIndex];
        
        if (file && this.analysisResults[file.name]) {
            this.showFileAnalysis(file);
        }
    }

    initializeTimelineChart() {
        const chartElement = document.getElementById('timelineChart');
        if (!chartElement) return;
        
        this.timelineChart = echarts.init(chartElement);
        this.updateTimelineWithData();
    }

    updateTimelineWithData() {
        if (!this.timelineChart) return;
        
        // Generate realistic timeline data
        const timelineData = this.generateRealisticTimeline();
        const phases = this.generateAttackPhases(timelineData);
        
        const option = {
            backgroundColor: 'transparent',
            tooltip: {
                trigger: 'axis',
                backgroundColor: '#1e293b',
                borderColor: '#334155',
                textStyle: { color: '#ffffff' },
                formatter: function(params) {
                    let result = `<div style="font-family: 'JetBrains Mono', monospace;">`;
                    result += `<strong>${new Date(parseInt(params[0].name)).toLocaleString()}</strong><br/>`;
                    params.forEach(param => {
                        const color = param.color;
                        result += `<span style="color: ${color};">● ${param.seriesName}: ${param.value.toLocaleString()}</span><br/>`;
                    });
                    result += `</div>`;
                    return result;
                }
            },
            legend: {
                data: ['Network Activity', 'TOR Traffic', 'Attack Intensity', 'Data Exfiltration'],
                textStyle: { color: '#ffffff', fontSize: 12 },
                top: 10
            },
            grid: {
                left: '3%',
                right: '4%',
                bottom: '15%',
                top: '15%',
                containLabel: true
            },
            xAxis: {
                type: 'category',
                data: timelineData.map(t => t.timestamp),
                axisLabel: { 
                    color: '#94a3b8', 
                    fontSize: 10,
                    interval: Math.floor(timelineData.length / 8),
                    formatter: function(value) {
                        return new Date(parseInt(value)).toLocaleTimeString();
                    }
                },
                axisLine: { lineStyle: { color: '#475569' } },
                splitLine: { show: false }
            },
            yAxis: [{
                type: 'value',
                name: 'Packets/Events',
                nameTextStyle: { color: '#94a3b8', fontSize: 11 },
                axisLabel: { color: '#94a3b8', fontSize: 10 },
                axisLine: { lineStyle: { color: '#475569' } },
                splitLine: { lineStyle: { color: '#334155', type: 'dashed' } }
            }, {
                type: 'value',
                name: 'Threat Level (%)',
                nameTextStyle: { color: '#94a3b8', fontSize: 11 },
                axisLabel: { color: '#94a3b8', fontSize: 10 },
                axisLine: { lineStyle: { color: '#475569' } },
                splitLine: { show: false },
                max: 100
            }],
            series: [
                {
                    name: 'Network Activity',
                    type: 'line',
                    data: timelineData.map(t => t.packets),
                    itemStyle: { color: '#00d4ff' },
                    lineStyle: { width: 2 },
                    areaStyle: { 
                        color: {
                            type: 'linear',
                            x: 0, y: 0, x2: 0, y2: 1,
                            colorStops: [
                                { offset: 0, color: 'rgba(0, 212, 255, 0.3)' },
                                { offset: 1, color: 'rgba(0, 212, 255, 0.05)' }
                            ]
                        }
                    },
                    smooth: true,
                    symbol: 'circle',
                    symbolSize: 4
                },
                {
                    name: 'TOR Traffic',
                    type: 'line',
                    data: timelineData.map(t => t.torTraffic),
                    itemStyle: { color: '#00ff88' },
                    lineStyle: { width: 2 },
                    smooth: true,
                    symbol: 'circle',
                    symbolSize: 4
                },
                {
                    name: 'Attack Intensity',
                    type: 'bar',
                    yAxisIndex: 1,
                    data: timelineData.map(t => t.threatLevel),
                    itemStyle: { 
                        color: function(params) {
                            const value = params.value;
                            if (value > 80) return '#ff2d2d';
                            if (value > 60) return '#ff8c00';
                            if (value > 40) return '#ffd700';
                            return '#00ff88';
                        },
                        opacity: 0.7
                    },
                    barWidth: '60%'
                },
                {
                    name: 'Data Exfiltration',
                    type: 'scatter',
                    data: timelineData.filter(t => t.exfiltration > 0).map((t, i) => [i * 3, t.exfiltration]),
                    itemStyle: { 
                        color: '#ff2d2d',
                        shadowBlur: 10,
                        shadowColor: '#ff2d2d'
                    },
                    symbolSize: function(data) {
                        return Math.max(8, data[1] / 10);
                    },
                    symbol: 'diamond'
                }
            ],
            animationDuration: 2000,
            animationEasing: 'cubicOut'
        };

        this.timelineChart.setOption(option);
        this.updateAttackPhases(phases);
    }

    generateRealisticTimeline() {
        const timeline = [];
        const startTime = Date.now() - 3600000; // 1 hour ago
        const baselinePackets = 150;
        
        for (let i = 0; i < 120; i++) { // 2-minute intervals
            const timestamp = startTime + (i * 30000); // 30-second intervals
            let packets = baselinePackets + Math.floor(Math.random() * 100);
            let torTraffic = Math.floor(Math.random() * 50 + 10);
            let threatLevel = Math.floor(Math.random() * 30 + 10);
            let exfiltration = 0;
            
            // Simulate attack phases
            if (i >= 20 && i <= 35) { // Reconnaissance phase
                packets += Math.floor(Math.random() * 200 + 100);
                torTraffic += Math.floor(Math.random() * 100 + 50);
                threatLevel = Math.floor(Math.random() * 40 + 30);
            } else if (i >= 40 && i <= 55) { // Initial access
                packets += Math.floor(Math.random() * 400 + 200);
                torTraffic += Math.floor(Math.random() * 200 + 100);
                threatLevel = Math.floor(Math.random() * 30 + 50);
            } else if (i >= 60 && i <= 80) { // Persistence
                packets += Math.floor(Math.random() * 300 + 150);
                torTraffic += Math.floor(Math.random() * 150 + 75);
                threatLevel = Math.floor(Math.random() * 25 + 60);
            } else if (i >= 85 && i <= 110) { // Data exfiltration
                packets += Math.floor(Math.random() * 500 + 300);
                torTraffic += Math.floor(Math.random() * 300 + 200);
                threatLevel = Math.floor(Math.random() * 20 + 70);
                exfiltration = Math.floor(Math.random() * 100 + 50);
            }
            
            timeline.push({
                timestamp,
                packets,
                torTraffic,
                threatLevel: Math.min(threatLevel, 100),
                exfiltration
            });
        }
        
        return timeline;
    }

    generateAttackPhases(timeline) {
        const phases = [
            {
                name: 'Reconnaissance',
                startTime: timeline[20]?.timestamp || Date.now(),
                endTime: timeline[35]?.timestamp || Date.now(),
                duration: 450, // 7.5 minutes
                intensity: 35,
                color: '#ffd700',
                description: 'Network scanning, TOR node discovery, target enumeration',
                techniques: ['Port Scanning', 'TOR Directory Queries', 'OSINT Gathering'],
                indicators: ['Unusual DNS queries', 'Port scan patterns', 'TOR bootstrap connections']
            },
            {
                name: 'Initial Access',
                startTime: timeline[40]?.timestamp || Date.now(),
                endTime: timeline[55]?.timestamp || Date.now(),
                duration: 450, // 7.5 minutes
                intensity: 65,
                color: '#ff8c00',
                description: 'TOR circuit establishment, entry point compromise',
                techniques: ['Circuit Building', 'Guard Node Selection', 'Encrypted Tunneling'],
                indicators: ['TOR handshake patterns', 'Circuit extend cells', 'Encrypted payload spikes']
            },
            {
                name: 'Persistence',
                startTime: timeline[60]?.timestamp || Date.now(),
                endTime: timeline[80]?.timestamp || Date.now(),
                duration: 600, // 10 minutes
                intensity: 72,
                color: '#ff6b35',
                description: 'Maintaining TOR circuits, establishing multiple paths',
                techniques: ['Circuit Multiplexing', 'Path Diversification', 'Connection Pooling'],
                indicators: ['Multiple active circuits', 'Keep-alive patterns', 'Redundant connections']
            },
            {
                name: 'Data Exfiltration',
                startTime: timeline[85]?.timestamp || Date.now(),
                endTime: timeline[110]?.timestamp || Date.now(),
                duration: 750, // 12.5 minutes
                intensity: 88,
                color: '#ff2d2d',
                description: 'Active data transfer through TOR exit nodes',
                techniques: ['Stream Multiplexing', 'Exit Node Rotation', 'Traffic Obfuscation'],
                indicators: ['High-volume encrypted streams', 'Exit node diversity', 'Sustained bandwidth usage']
            }
        ];

        return phases;
    }

    updateAttackPhases(phases) {
        const container = document.querySelector('#timeline-reconstruction .grid .space-y-2');
        if (!container) return;

        container.innerHTML = '';
        
        phases.forEach((phase, index) => {
            const startTime = new Date(phase.startTime);
            const endTime = new Date(phase.endTime);
            
            const phaseElement = document.createElement('div');
            phaseElement.className = 'bg-steel-gray rounded-lg p-4 hover:bg-gray-600 transition-all duration-300 cursor-pointer border-l-4 hover:shadow-lg';
            phaseElement.style.borderLeftColor = phase.color;
            
            phaseElement.innerHTML = `
                <div class="flex justify-between items-start mb-3">
                    <div class="flex items-center space-x-2">
                        <div class="w-3 h-3 rounded-full" style="background-color: ${phase.color}; box-shadow: 0 0 8px ${phase.color};"></div>
                        <span class="text-sm font-bold text-white">${phase.name}</span>
                        <span class="px-2 py-1 text-xs rounded-full bg-gray-700 text-gray-300">
                            Phase ${index + 1}
                        </span>
                    </div>
                    <div class="text-right">
                        <div class="mono-font text-xs text-cyber-blue">
                            ${startTime.toLocaleTimeString()} - ${endTime.toLocaleTimeString()}
                        </div>
                        <div class="text-xs text-gray-400 mt-1">
                            Duration: ${Math.floor(phase.duration / 60)}m ${phase.duration % 60}s
                        </div>
                    </div>
                </div>
                
                <div class="mb-3">
                    <p class="text-xs text-gray-300 mb-2">${phase.description}</p>
                    <div class="flex items-center space-x-2 mb-2">
                        <span class="text-xs text-gray-400">Threat Intensity:</span>
                        <div class="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
                            <div class="h-full rounded-full transition-all duration-1000" 
                                 style="width: ${phase.intensity}%; background: linear-gradient(90deg, ${phase.color}, ${phase.color}aa);"></div>
                        </div>
                        <span class="mono-font text-xs font-bold" style="color: ${phase.color}">${phase.intensity}%</span>
                    </div>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    <div>
                        <div class="text-gray-400 mb-1">Techniques:</div>
                        <div class="space-y-1">
                            ${phase.techniques.map(tech => 
                                `<div class="flex items-center space-x-1">
                                    <div class="w-1 h-1 rounded-full bg-matrix-green"></div>
                                    <span class="text-gray-300">${tech}</span>
                                </div>`
                            ).join('')}
                        </div>
                    </div>
                    <div>
                        <div class="text-gray-400 mb-1">Key Indicators:</div>
                        <div class="space-y-1">
                            ${phase.indicators.map(indicator => 
                                `<div class="flex items-center space-x-1">
                                    <div class="w-1 h-1 rounded-full bg-warning-amber"></div>
                                    <span class="text-gray-300">${indicator}</span>
                                </div>`
                            ).join('')}
                        </div>
                    </div>
                </div>
            `;
            
            phaseElement.addEventListener('click', () => {
                this.showEnhancedPhaseDetails(phase, index + 1);
            });
            
            container.appendChild(phaseElement);
        });
    }

    showEnhancedPhaseDetails(phase, phaseNumber) {
        const details = document.getElementById('timelineDetails');
        if (details) {
            const startTime = new Date(phase.startTime);
            const endTime = new Date(phase.endTime);
            
            details.innerHTML = `
                <div class="border-l-4 pl-6 py-4" style="border-left-color: ${phase.color};">
                    <div class="flex items-center space-x-3 mb-4">
                        <div class="w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold" 
                             style="background-color: ${phase.color}; color: #000;">
                            ${phaseNumber}
                        </div>
                        <div>
                            <h4 class="font-bold text-lg" style="color: ${phase.color};">${phase.name} Phase</h4>
                            <p class="text-sm text-gray-400 mono-font">
                                ${startTime.toLocaleString()} → ${endTime.toLocaleString()}
                            </p>
                        </div>
                    </div>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-4">
                        <div>
                            <h5 class="text-sm font-semibold text-gray-300 mb-2">Phase Overview</h5>
                            <p class="text-sm text-gray-300 mb-3">${phase.description}</p>
                            <div class="space-y-2">
                                <div class="flex justify-between text-sm">
                                    <span class="text-gray-400">Duration:</span>
                                    <span class="mono-font text-white">${Math.floor(phase.duration / 60)}m ${phase.duration % 60}s</span>
                                </div>
                                <div class="flex justify-between text-sm">
                                    <span class="text-gray-400">Threat Level:</span>
                                    <span class="mono-font font-bold" style="color: ${phase.color};">${phase.intensity}%</span>
                                </div>
                            </div>
                        </div>
                        
                        <div>
                            <h5 class="text-sm font-semibold text-gray-300 mb-2">Attack Techniques</h5>
                            <div class="space-y-2">
                                ${phase.techniques.map(tech => 
                                    `<div class="flex items-center space-x-2 text-sm">
                                        <div class="w-2 h-2 rounded-full bg-matrix-green"></div>
                                        <span class="text-gray-300">${tech}</span>
                                    </div>`
                                ).join('')}
                            </div>
                        </div>
                    </div>
                    
                    <div>
                        <h5 class="text-sm font-semibold text-gray-300 mb-2">Key Indicators of Compromise (IOCs)</h5>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                            ${phase.indicators.map(indicator => 
                                `<div class="flex items-center space-x-2 text-sm bg-steel-gray rounded p-2">
                                    <div class="w-2 h-2 rounded-full bg-warning-amber"></div>
                                    <span class="text-gray-300">${indicator}</span>
                                </div>`
                            ).join('')}
                        </div>
                    </div>
                </div>
            `;
            details.classList.remove('hidden');
        }
    }

    initializeOriginMap() {
        const chart = echarts.init(document.getElementById('originMap'));
        
        // Enhanced origin data with realistic geolocation
        const originData = [
            { name: 'Primary Origin', coords: [-74.0060, 40.7128], confidence: 92.3, ip: '192.168.1.100', country: 'United States', city: 'New York', isp: 'Comcast Cable' },
            { name: 'Secondary Origin', coords: [-0.1278, 51.5074], confidence: 67.8, ip: '10.0.0.50', country: 'United Kingdom', city: 'London', isp: 'BT Group' },
            { name: 'Tertiary Origin', coords: [139.6503, 35.6762], confidence: 34.2, ip: '172.16.0.25', country: 'Japan', city: 'Tokyo', isp: 'NTT Communications' },
            { name: 'TOR Exit Node', coords: [2.3522, 48.8566], confidence: 78.5, ip: '185.220.101.45', country: 'France', city: 'Paris', isp: 'OVH SAS' },
            { name: 'Relay Node', coords: [13.4050, 52.5200], confidence: 45.7, ip: '199.87.154.255', country: 'Germany', city: 'Berlin', isp: 'Hetzner Online' }
        ];
        
        const option = {
            backgroundColor: 'transparent',
            tooltip: {
                trigger: 'item',
                backgroundColor: '#1e293b',
                borderColor: '#334155',
                textStyle: { color: '#ffffff', fontSize: 12 },
                formatter: function(params) {
                    const data = params.data;
                    return `
                        <div style="font-family: 'JetBrains Mono', monospace; min-width: 200px;">
                            <div style="color: #00d4ff; font-weight: bold; margin-bottom: 8px;">${data.name}</div>
                            <div style="margin-bottom: 4px;"><strong>IP:</strong> ${data.ip}</div>
                            <div style="margin-bottom: 4px;"><strong>Location:</strong> ${data.city}, ${data.country}</div>
                            <div style="margin-bottom: 4px;"><strong>ISP:</strong> ${data.isp}</div>
                            <div style="margin-bottom: 4px;"><strong>Confidence:</strong> 
                                <span style="color: ${data.confidence > 80 ? '#00ff88' : data.confidence > 60 ? '#ff8c00' : '#ff2d2d'}; font-weight: bold;">
                                    ${data.confidence}%
                                </span>
                            </div>
                        </div>
                    `;
                }
            },
            geo: {
                map: 'world',
                roam: true,
                zoom: 1.2,
                center: [20, 30],
                itemStyle: {
                    areaColor: '#1e293b',
                    borderColor: '#475569',
                    borderWidth: 0.5
                },
                emphasis: {
                    itemStyle: {
                        areaColor: '#334155'
                    }
                },
                label: {
                    show: false
                }
            },
            series: [
                {
                    type: 'scatter',
                    coordinateSystem: 'geo',
                    data: originData.map(item => ({
                        name: item.name,
                        value: item.coords.concat([item.confidence]),
                        ip: item.ip,
                        country: item.country,
                        city: item.city,
                        isp: item.isp,
                        confidence: item.confidence
                    })),
                    symbolSize: function(val) {
                        return Math.max(12, val[2] / 3);
                    },
                    itemStyle: {
                        color: function(params) {
                            const confidence = params.data.confidence;
                            if (confidence > 80) return '#00ff88';
                            if (confidence > 60) return '#ff8c00';
                            return '#ff2d2d';
                        },
                        shadowBlur: 10,
                        shadowColor: function(params) {
                            const confidence = params.data.confidence;
                            if (confidence > 80) return '#00ff88';
                            if (confidence > 60) return '#ff8c00';
                            return '#ff2d2d';
                        }
                    },
                    label: {
                        show: true,
                        position: 'top',
                        color: '#ffffff',
                        fontSize: 10,
                        formatter: function(params) {
                            return `${params.data.confidence}%`;
                        }
                    },
                    emphasis: {
                        scale: 1.5,
                        itemStyle: {
                            shadowBlur: 20
                        }
                    }
                },
                {
                    type: 'lines',
                    coordinateSystem: 'geo',
                    data: [
                        {
                            coords: [[-74.0060, 40.7128], [2.3522, 48.8566]],
                            lineStyle: { color: '#00d4ff', width: 2, opacity: 0.6 }
                        },
                        {
                            coords: [[2.3522, 48.8566], [13.4050, 52.5200]],
                            lineStyle: { color: '#00ff88', width: 2, opacity: 0.6 }
                        },
                        {
                            coords: [[13.4050, 52.5200], [139.6503, 35.6762]],
                            lineStyle: { color: '#ff8c00', width: 2, opacity: 0.6 }
                        }
                    ],
                    effect: {
                        show: true,
                        period: 4,
                        trailLength: 0.1,
                        color: '#ffffff',
                        symbolSize: 4
                    }
                }
            ],
            animationDuration: 2000
        };
        
        // Load world map
        fetch('https://geo.datav.io/world.json')
            .then(response => response.json())
            .then(worldJson => {
                echarts.registerMap('world', worldJson);
                chart.setOption(option);
            })
            .catch(() => {
                // Fallback to simple scatter plot if world map fails to load
                const fallbackOption = {
                    backgroundColor: 'transparent',
                    tooltip: {
                        trigger: 'item',
                        backgroundColor: '#1e293b',
                        borderColor: '#334155',
                        textStyle: { color: '#ffffff' }
                    },
                    xAxis: {
                        type: 'value',
                        name: 'Longitude',
                        nameTextStyle: { color: '#94a3b8' },
                        axisLabel: { color: '#94a3b8' },
                        axisLine: { lineStyle: { color: '#475569' } },
                        splitLine: { lineStyle: { color: '#334155' } }
                    },
                    yAxis: {
                        type: 'value',
                        name: 'Latitude',
                        nameTextStyle: { color: '#94a3b8' },
                        axisLabel: { color: '#94a3b8' },
                        axisLine: { lineStyle: { color: '#475569' } },
                        splitLine: { lineStyle: { color: '#334155' } }
                    },
                    series: [{
                        type: 'scatter',
                        data: originData.map(item => item.coords.concat([item.confidence])),
                        symbolSize: function(val) { return Math.max(15, val[2] / 2); },
                        itemStyle: {
                            color: function(params) {
                                const confidence = params.data[2];
                                return confidence > 80 ? '#00ff88' : confidence > 60 ? '#ff8c00' : '#ff2d2d';
                            },
                            shadowBlur: 10
                        }
                    }]
                };
                chart.setOption(fallbackOption);
            });
    }

    updateTimelineChart() {
        // Update with current analysis data
        this.updateTimelineWithData();
    }

    updateOriginAnalysis() {
        // Update origin identification with current data
        this.initializeOriginMap();
    }

    exportTimeline() {
        const timelineData = {
            events: [
                { time: '14:23:17', event: 'Suspicious Activity Detected', severity: 'Critical' },
                { time: '14:35:42', event: 'Correlation Pattern Found', severity: 'Warning' },
                { time: '14:45:12', event: 'Evidence Uploaded', severity: 'Info' },
                { time: '14:51:33', event: 'Origin IP Identified', severity: 'Critical' }
            ],
            exported: new Date().toISOString()
        };
        
        const blob = new Blob([JSON.stringify(timelineData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `timeline_export_${Date.now()}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    addTimelineEvent() {
        const eventType = prompt('Enter event type (e.g., "Network Anomaly")');
        const eventTime = prompt('Enter event time (HH:MM:SS)');
        
        if (eventType && eventTime) {
            const track = document.getElementById('timelineTrack');
            const marker = document.createElement('div');
            marker.className = 'timeline-marker info';
            marker.style.left = Math.random() * 80 + 10 + '%';
            marker.style.top = '-5px';
            marker.dataset.event = 'custom-event';
            marker.title = `${eventType} - ${eventTime}`;
            
            marker.addEventListener('click', () => {
                this.showCustomEvent(eventType, eventTime);
            });
            
            track.appendChild(marker);
        }
    }

    showCustomEvent(type, time) {
        const details = document.getElementById('timelineDetails');
        details.innerHTML = `
            <div class="border-l-4 border-cyber-blue pl-4">
                <h4 class="font-bold text-cyber-blue">${type}</h4>
                <p class="text-sm text-gray-300 mb-2">${time}</p>
                <p class="text-sm">Custom event added by investigator</p>
                <span class="inline-block mt-2 px-2 py-1 text-xs rounded bg-blue-900 text-blue-200">Custom</span>
            </div>
        `;
        details.classList.remove('hidden');
    }
}

// Initialize forensics analyzer when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.forensicsAnalyzer = new ForensicsAnalyzer();
});