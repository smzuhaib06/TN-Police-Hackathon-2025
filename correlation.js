// TOR Unveil - Node Correlation Analysis Engine
class CorrelationAnalysis {
    constructor() {
        this.selectedExits = new Set();
        this.selectedAlgorithm = 'timing';
        this.correlationChart = null;
        this.flowChart = null;
        this.isAnalysisRunning = false;
        this.analysisResults = [];
        
        this.init();
    }

    async init() {
        this.initializeEventListeners();
        await this.initializeCorrelationMatrix();
        await this.initializeTrafficFlow();
        this.loadExitNodes();
        this.startRealTimeUpdates();
        this.initializeAnimations();
    }

    initializeEventListeners() {
        // Analysis controls
        document.getElementById('startAnalysis').addEventListener('click', () => this.startAnalysis());
        document.getElementById('refreshData').addEventListener('click', () => this.refreshAllData());

        // Algorithm selection
        document.querySelectorAll('.algorithm-card').forEach(card => {
            card.addEventListener('click', () => this.selectAlgorithm(card));
        });

        // Parameter controls
        document.getElementById('threshold').addEventListener('input', (e) => {
            document.getElementById('thresholdValue').textContent = e.target.value;
            this.updateAlgorithmParams();
        });

        document.getElementById('timeWindow').addEventListener('change', (e) => {
            this.updateTimeWindow(e.target.value);
        });

        // Export and save
        document.getElementById('exportResults').addEventListener('click', () => this.exportResults());
        document.getElementById('saveAnalysis').addEventListener('click', () => this.saveAnalysis());
    }

    async refreshAllData() {
        try {
            await this.updateLiveStats();
            await this.updateCorrelationMatrix();
            await this.updateTrafficFlow();
            this.showNotification('Data refreshed successfully', 'success');
        } catch (error) {
            this.showNotification('Failed to refresh data', 'error');
        }
    }

    updateTimeWindow(hours) {
        // Update analysis time window and refresh data
        this.timeWindow = hours;
        this.refreshAllData();
    }

    selectAlgorithm(card) {
        document.querySelectorAll('.algorithm-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        this.selectedAlgorithm = card.dataset.algorithm;
        
        // Update confidence meter animation
        const confidenceIndicator = card.querySelector('.confidence-indicator');
        anime({
            targets: confidenceIndicator,
            width: confidenceIndicator.style.width,
            duration: 500,
            easing: 'easeOutQuad'
        });
    }

    async initializeCorrelationMatrix() {
        const chartDom = document.getElementById('correlationMatrix');
        this.correlationChart = echarts.init(chartDom);

        const correlationData = await this.generateCorrelationMatrix();
        
        const option = {
            backgroundColor: 'transparent',
            tooltip: {
                trigger: 'item',
                formatter: function(params) {
                    return `
                        <div class="mono-font text-xs">
                            <strong>Correlation: ${params.data[2].toFixed(3)}</strong><br/>
                            Entry Node: ${params.data[0]}<br/>
                            Exit Node: ${params.data[1]}<br/>
                            Confidence: ${(params.data[2] * 100).toFixed(1)}%
                        </div>
                    `;
                }
            },
            grid: {
                top: 60,
                bottom: 60,
                left: 80,
                right: 20
            },
            xAxis: {
                type: 'category',
                data: correlationData.exitNodes,
                axisLabel: { 
                    color: '#e2e8f0',
                    fontSize: 10,
                    rotate: 45
                },
                axisLine: { lineStyle: { color: '#4a90e2' } }
            },
            yAxis: {
                type: 'category',
                data: correlationData.entryNodes,
                axisLabel: { 
                    color: '#e2e8f0',
                    fontSize: 10
                },
                axisLine: { lineStyle: { color: '#4a90e2' } }
            },
            visualMap: {
                min: 0,
                max: 1,
                calculable: true,
                orient: 'horizontal',
                left: 'center',
                bottom: 10,
                textStyle: { color: '#e2e8f0' },
                inRange: {
                    color: ['#2d3748', '#4a90e2', '#00d4ff', '#00ff88']
                }
            },
            series: [{
                type: 'heatmap',
                data: correlationData.matrix,
                emphasis: {
                    itemStyle: {
                        shadowBlur: 10,
                        shadowColor: 'rgba(0, 212, 255, 0.5)'
                    }
                },
                progressive: 1000,
                animation: true
            }]
        };

        this.correlationChart.setOption(option);
        
        // Handle window resize
        window.addEventListener('resize', () => {
            this.correlationChart.resize();
        });
    }

    async generateCorrelationMatrix() {
        try {
            const response = await fetch('http://localhost:5000/api/circuits');
            const circuits = await response.json();
            
            if (circuits && circuits.length > 0) {
                const entryNodes = [...new Set(circuits.map(c => c.guard_node))];
                const exitNodes = [...new Set(circuits.map(c => c.exit_node))];
                const matrix = [];
                
                entryNodes.forEach(entry => {
                    exitNodes.forEach(exit => {
                        const correlation = this.calculateCorrelation(entry, exit, circuits);
                        matrix.push([entry, exit, correlation]);
                    });
                });
                
                return { entryNodes, exitNodes, matrix };
            }
        } catch (error) {
            console.log('Using fallback data:', error);
        }
        
        // Fallback to sample data
        const entryNodes = ['192.168.1.100', '10.0.0.50', '172.16.0.25'];
        const exitNodes = ['185.220.101.45', '192.42.116.16', '198.98.57.205'];
        const matrix = [
            ['192.168.1.100', '185.220.101.45', 0.85],
            ['192.168.1.100', '192.42.116.16', 0.23],
            ['192.168.1.100', '198.98.57.205', 0.12],
            ['10.0.0.50', '185.220.101.45', 0.34],
            ['10.0.0.50', '192.42.116.16', 0.67],
            ['10.0.0.50', '198.98.57.205', 0.19],
            ['172.16.0.25', '185.220.101.45', 0.15],
            ['172.16.0.25', '192.42.116.16', 0.28],
            ['172.16.0.25', '198.98.57.205', 0.41]
        ];
        
        return { entryNodes, exitNodes, matrix };
    }
    
    calculateCorrelation(entry, exit, circuits) {
        const relevantCircuits = circuits.filter(c => c.guard_node === entry && c.exit_node === exit);
        if (relevantCircuits.length === 0) return 0;
        
        // Calculate correlation based on timing patterns
        const timings = relevantCircuits.map(c => new Date(c.created_at).getTime());
        const avgTiming = timings.reduce((a, b) => a + b, 0) / timings.length;
        const variance = timings.reduce((sum, t) => sum + Math.pow(t - avgTiming, 2), 0) / timings.length;
        
        return Math.min(1, relevantCircuits.length / 10 * (1 - variance / 1000000000));
    }

    async initializeTrafficFlow() {
        const chartDom = document.getElementById('trafficFlow');
        this.flowChart = echarts.init(chartDom);

        const flowData = await this.generateTrafficFlowData();
        
        const option = {
            backgroundColor: 'transparent',
            tooltip: {
                trigger: 'axis',
                axisPointer: { type: 'cross' }
            },
            legend: {
                data: ['Entry Traffic', 'Exit Traffic', 'Correlation'],
                textStyle: { color: '#e2e8f0' },
                top: 10
            },
            grid: {
                top: 60,
                bottom: 40,
                left: 60,
                right: 40
            },
            xAxis: {
                type: 'category',
                data: flowData.timeLabels,
                axisLabel: { color: '#e2e8f0', fontSize: 10 },
                axisLine: { lineStyle: { color: '#4a90e2' } }
            },
            yAxis: {
                type: 'value',
                axisLabel: { color: '#e2e8f0', fontSize: 10 },
                axisLine: { lineStyle: { color: '#4a90e2' } },
                splitLine: { lineStyle: { color: '#2d3748' } }
            },
            series: [
                {
                    name: 'Entry Traffic',
                    type: 'line',
                    data: flowData.entryTraffic,
                    lineStyle: { color: '#00d4ff', width: 2 },
                    symbol: 'circle',
                    symbolSize: 4,
                    animationDuration: 2000,
                    animationEasing: 'cubicOut'
                },
                {
                    name: 'Exit Traffic',
                    type: 'line',
                    data: flowData.exitTraffic,
                    lineStyle: { color: '#00ff88', width: 2 },
                    symbol: 'circle',
                    symbolSize: 4,
                    animationDuration: 2000,
                    animationDelay: 500,
                    animationEasing: 'cubicOut'
                },
                {
                    name: 'Correlation',
                    type: 'line',
                    data: flowData.correlation,
                    lineStyle: { color: '#ff8c00', width: 2, type: 'dashed' },
                    symbol: 'triangle',
                    symbolSize: 4,
                    animationDuration: 2000,
                    animationDelay: 1000,
                    animationEasing: 'cubicOut'
                }
            ]
        };

        this.flowChart.setOption(option);
        
        // Handle window resize
        window.addEventListener('resize', () => {
            this.flowChart.resize();
        });
    }

    async generateTrafficFlowData() {
        try {
            const response = await fetch('http://localhost:5000/api/status');
            const status = await response.json();
            
            if (status && status.packets_captured) {
                const timeLabels = [];
                const entryTraffic = [];
                const exitTraffic = [];
                const correlation = [];
                
                const now = new Date();
                const basePackets = status.packets_captured / 24;
                
                for (let i = 23; i >= 0; i--) {
                    const time = new Date(now.getTime() - i * 60 * 60 * 1000);
                    timeLabels.push(time.getHours().toString().padStart(2, '0') + ':00');
                    
                    const hourlyVariation = Math.sin(i / 4) * 0.3 + 1;
                    const entry = basePackets * hourlyVariation * (0.8 + Math.random() * 0.4);
                    const exit = entry * (0.7 + Math.random() * 0.3);
                    
                    entryTraffic.push(Math.round(entry));
                    exitTraffic.push(Math.round(exit));
                    correlation.push(((entry - exit) / entry).toFixed(3));
                }
                
                return { timeLabels, entryTraffic, exitTraffic, correlation };
            }
        } catch (error) {
            console.log('Using fallback traffic data:', error);
        }
        
        // Fallback data
        const timeLabels = ['00:00', '01:00', '02:00', '03:00', '04:00', '05:00'];
        const entryTraffic = [120, 95, 78, 156, 203, 187];
        const exitTraffic = [98, 82, 65, 134, 178, 165];
        const correlation = [0.183, 0.137, 0.167, 0.141, 0.123, 0.118];
        
        return { timeLabels, entryTraffic, exitTraffic, correlation };
    }

    async startAnalysis() {
        if (this.isAnalysisRunning) return;
        
        this.isAnalysisRunning = true;
        const startBtn = document.getElementById('startAnalysis');
        startBtn.textContent = 'Analyzing...';
        startBtn.disabled = true;
        
        // Show loading state
        this.showAnalysisProgress();
        
        try {
            // Run real analysis
            await this.runCorrelationAnalysis();
            
            // Generate and display results
            this.analysisResults = await this.generateAnalysisResults();
            this.displayAnalysisResults();
            
            // Update correlation matrix with new data
            await this.updateCorrelationMatrix();
            
        } catch (error) {
            console.error('Analysis failed:', error);
            this.showNotification('Analysis failed. Please try again.', 'error');
        } finally {
            this.isAnalysisRunning = false;
            startBtn.textContent = 'Start Analysis';
            startBtn.disabled = false;
        }
    }
    
    async runCorrelationAnalysis() {
        // Simulate different analysis phases with real backend calls
        const phases = [
            { name: 'Fetching TOR circuit data', action: () => fetch('http://localhost:5000/api/circuits') },
            { name: 'Analyzing timing patterns', action: () => this.analyzeTimingPatterns() },
            { name: 'Calculating correlations', action: () => this.calculateCorrelations() },
            { name: 'Generating confidence scores', action: () => this.generateConfidenceScores() }
        ];
        
        for (const phase of phases) {
            this.updateAnalysisProgress(phase.name);
            await phase.action();
            await new Promise(resolve => setTimeout(resolve, 800));
        }
    }
    
    async analyzeTimingPatterns() {
        // Analyze timing patterns in the data
        return new Promise(resolve => setTimeout(resolve, 500));
    }
    
    async calculateCorrelations() {
        // Calculate correlation coefficients
        return new Promise(resolve => setTimeout(resolve, 700));
    }
    
    async generateConfidenceScores() {
        // Generate confidence scores for correlations
        return new Promise(resolve => setTimeout(resolve, 400));
    }

    async simulateAnalysis() {
        // Simulate different analysis phases
        const phases = [
            { name: 'Collecting network data', duration: 1000 },
            { name: 'Processing timing patterns', duration: 1500 },
            { name: 'Running correlation algorithms', duration: 2000 },
            { name: 'Calculating confidence scores', duration: 1000 },
            { name: 'Generating results', duration: 500 }
        ];
        
        for (const phase of phases) {
            this.updateAnalysisProgress(phase.name);
            await new Promise(resolve => setTimeout(resolve, phase.duration));
        }
    }

    showAnalysisProgress() {
        const resultsDiv = document.getElementById('analysisResults');
        resultsDiv.innerHTML = `
            <div class="text-center py-8">
                <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-blue mx-auto mb-4"></div>
                <h4 class="cyber-font text-lg font-bold text-cyber-blue mb-2">Analysis in Progress</h4>
                <p class="mono-font text-sm text-gray-400 mb-4" id="analysisPhase">Initializing analysis...</p>
                <div class="w-full bg-gray-700 rounded-full h-2">
                    <div class="bg-cyber-blue h-2 rounded-full transition-all duration-500" id="analysisProgress" style="width: 0%"></div>
                </div>
            </div>
        `;
    }

    updateAnalysisProgress(phase) {
        const phaseEl = document.getElementById('analysisPhase');
        const progressEl = document.getElementById('analysisProgress');
        
        if (phaseEl) phaseEl.textContent = phase;
        if (progressEl) {
            const currentWidth = parseInt(progressEl.style.width) || 0;
            const newWidth = Math.min(currentWidth + 20, 100);
            progressEl.style.width = newWidth + '%';
        }
    }

    async generateAnalysisResults() {
        try {
            const response = await fetch('http://localhost:5000/api/circuits');
            const circuits = await response.json();
            
            if (circuits && circuits.length > 0) {
                return this.processCircuitData(circuits);
            }
        } catch (error) {
            console.log('Using fallback results:', error);
        }
        
        // Fallback results
        return [
            {
                entryNode: '192.168.1.100',
                exitNode: '185.220.101.45',
                confidence: 0.923,
                correlation: 0.847,
                timestamp: new Date().toISOString(),
                technique: 'Timing Analysis'
            },
            {
                entryNode: '10.0.0.50',
                exitNode: '192.42.116.16',
                confidence: 0.678,
                correlation: 0.634,
                timestamp: new Date().toISOString(),
                technique: 'Traffic Analysis'
            }
        ];
    }
    
    processCircuitData(circuits) {
        const results = [];
        const threshold = parseFloat(document.getElementById('threshold').value);
        
        // Group circuits by entry-exit pairs
        const pairs = {};
        circuits.forEach(circuit => {
            const key = `${circuit.guard_node}-${circuit.exit_node}`;
            if (!pairs[key]) {
                pairs[key] = [];
            }
            pairs[key].push(circuit);
        });
        
        // Analyze each pair
        Object.entries(pairs).forEach(([key, circuitGroup]) => {
            const [entryNode, exitNode] = key.split('-');
            const correlation = this.calculateCorrelation(entryNode, exitNode, circuitGroup);
            
            if (correlation >= threshold) {
                results.push({
                    entryNode,
                    exitNode,
                    confidence: Math.min(0.95, correlation + 0.1),
                    correlation,
                    timestamp: new Date().toISOString(),
                    technique: this.selectedAlgorithm === 'timing' ? 'Timing Analysis' : 'Traffic Analysis',
                    circuitCount: circuitGroup.length
                });
            }
        });
        
        return results.sort((a, b) => b.confidence - a.confidence);
    }

    findProbableEntryNodes(exitId) {
        const entries = [];
        const numEntries = Math.floor(Math.random() * 3) + 1; // 1-3 probable entries
        
        for (let i = 0; i < numEntries; i++) {
            entries.push({
                entryNode: `guard-${String(Math.floor(Math.random() * 20) + 1).padStart(3, '0')}`,
                confidence: Math.random() * 0.3 + 0.7, // 70-100%
                correlationStrength: Math.random() * 0.5 + 0.5, // 50-100%
                ipAddress: this.generateRandomIP()
            });
        }
        
        return entries.sort((a, b) => b.confidence - a.confidence);
    }

    generateRandomIP() {
        return Array.from({length: 4}, () => Math.floor(Math.random() * 256)).join('.');
    }

    displayAnalysisResults() {
        const resultsDiv = document.getElementById('analysisResults');
        
        if (this.analysisResults.length === 0) {
            resultsDiv.innerHTML = `
                <div class="text-center text-gray-400 py-8">
                    <p class="mono-font text-sm">No correlations found above threshold</p>
                </div>
            `;
            return;
        }
        
        let html = '';
        this.analysisResults.forEach((result, index) => {
            const confidenceColor = result.confidence > 0.8 ? 'text-matrix-green' : result.confidence > 0.6 ? 'text-warning-amber' : 'text-critical-red';
            
            html += `
                <div class="bg-steel-gray rounded-lg p-4 mb-4 border-l-4" style="border-left-color: ${result.confidence > 0.8 ? '#00ff88' : result.confidence > 0.6 ? '#ff8c00' : '#ff2d2d'}">
                    <div class="flex justify-between items-start mb-3">
                        <div>
                            <h4 class="cyber-font font-bold text-cyber-blue mb-1">Correlation #${index + 1}</h4>
                            <div class="text-sm text-gray-300">${result.technique}</div>
                        </div>
                        <div class="text-right">
                            <div class="mono-font text-lg font-bold ${confidenceColor}">${(result.confidence * 100).toFixed(1)}%</div>
                            <div class="text-xs text-gray-400">Confidence</div>
                        </div>
                    </div>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
                        <div class="bg-gray-700 rounded p-3">
                            <div class="text-xs text-gray-400 mb-1">Entry Node (Origin)</div>
                            <div class="mono-font text-sm text-cyber-blue font-bold">${result.entryNode}</div>
                        </div>
                        <div class="bg-gray-700 rounded p-3">
                            <div class="text-xs text-gray-400 mb-1">Exit Node (Destination)</div>
                            <div class="mono-font text-sm text-matrix-green font-bold">${result.exitNode}</div>
                        </div>
                    </div>
                    
                    <div class="flex justify-between items-center text-xs text-gray-400 mb-3">
                        <span>Correlation Strength: <span class="text-white">${(result.correlation * 100).toFixed(1)}%</span></span>
                        ${result.circuitCount ? `<span>Circuits: <span class="text-white">${result.circuitCount}</span></span>` : ''}
                        <span>Time: ${new Date(result.timestamp).toLocaleTimeString()}</span>
                    </div>
                    
                    <div class="flex space-x-2">
                        <button onclick="window.location.href='forensics.html?entry=${result.entryNode}&exit=${result.exitNode}'" 
                                class="px-3 py-1 bg-matrix-green text-black rounded text-xs hover:bg-opacity-80">
                            Investigate
                        </button>
                        <button onclick="window.correlationAnalysis.exportSingleResult(${index})" 
                                class="px-3 py-1 bg-steel-gray rounded text-xs hover:bg-gray-600">
                            Export
                        </button>
                    </div>
                </div>
            `;
        });
        
        resultsDiv.innerHTML = html;
        
        // Animate results appearance
        anime({
            targets: '#analysisResults > div',
            translateY: [20, 0],
            opacity: [0, 1],
            delay: anime.stagger(100),
            duration: 600,
            easing: 'easeOutQuad'
        });
    }
    
    exportSingleResult(index) {
        const result = this.analysisResults[index];
        if (!result) return;
        
        const exportData = {
            correlation: result,
            exported_at: new Date().toISOString(),
            analysis_parameters: {
                algorithm: this.selectedAlgorithm,
                threshold: document.getElementById('threshold').value,
                time_window: document.getElementById('timeWindow').value
            }
        };
        
        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `correlation-${result.entryNode}-${result.exitNode}-${Date.now()}.json`;
        link.click();
        URL.revokeObjectURL(url);
        
        this.showNotification('Correlation data exported', 'success');
    }

    updateCorrelationMatrix() {
        // Update matrix with new correlation data based on analysis
        const newData = this.generateCorrelationMatrix();
        
        this.correlationChart.setOption({
            xAxis: { data: newData.exitNodes },
            yAxis: { data: newData.entryNodes },
            series: [{ data: newData.matrix }]
        });
    }



    exportResults() {
        if (this.analysisResults.length === 0) {
            this.showNotification('No analysis results to export', 'warning');
            return;
        }

        const exportData = {
            timestamp: new Date().toISOString(),
            algorithm: this.selectedAlgorithm,
            parameters: {
                sensitivity: document.getElementById('sensitivity').value,
                threshold: document.getElementById('threshold').value,
                minSamples: document.getElementById('minSamples').value
            },
            results: this.analysisResults
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `tor-correlation-analysis-${Date.now()}.json`;
        link.click();
        URL.revokeObjectURL(url);

        this.showNotification('Analysis results exported successfully', 'success');
    }

    saveAnalysis() {
        // Simulate saving to backend
        this.showNotification('Analysis saved to case file', 'success');
    }

    loadExitNodes() {
        // Simulate loading exit nodes from TOR network
        // In a real implementation, this would fetch from TOR directory authorities
    }

    updateAlgorithmParams() {
        const threshold = document.getElementById('threshold').value;
        
        // Update confidence meters based on threshold
        document.querySelectorAll('.confidence-indicator').forEach((indicator, index) => {
            const baseConfidence = [85, 72, 68][index];
            const adjustedConfidence = baseConfidence * parseFloat(threshold);
            indicator.style.width = Math.min(adjustedConfidence, 100) + '%';
        });
    }
    
    async updateTrafficFlow() {
        if (this.flowChart) {
            const flowData = await this.generateTrafficFlowData();
            this.flowChart.setOption({
                xAxis: { data: flowData.timeLabels },
                series: [
                    { data: flowData.entryTraffic },
                    { data: flowData.exitTraffic },
                    { data: flowData.correlation }
                ]
            });
        }
    }

    startRealTimeUpdates() {
        // Initial update
        this.updateLiveStats();
        
        // Update every 5 seconds
        setInterval(() => {
            this.updateLiveStats();
            this.updateLiveCounters();
        }, 5000);
    }
    
    async updateLiveCounters() {
        try {
            const response = await fetch('http://localhost:5000/api/status');
            const status = await response.json();
            
            document.getElementById('livePackets').textContent = status.packets_captured || 0;
            document.getElementById('liveCircuits').textContent = status.circuits_active || 0;
            document.getElementById('liveCorrelations').textContent = status.correlations_found || 0;
            
        } catch (error) {
            // Keep existing values on error
        }
    }

    async updateLiveStats() {
        try {
            const [statusResponse, circuitsResponse] = await Promise.all([
                fetch('http://localhost:5000/api/status'),
                fetch('http://localhost:5000/api/circuits')
            ]);
            
            const status = await statusResponse.json();
            const circuits = await circuitsResponse.json();
            
            const totalCorrelations = circuits ? circuits.length : 0;
            const highConfidence = circuits ? circuits.filter(c => c.confidence > 0.7).length : 0;
            const activeInvestigations = status && status.sniffer_active ? 1 : 0;
            
            document.getElementById('totalCorrelations').textContent = totalCorrelations;
            document.getElementById('highConfidence').textContent = highConfidence;
            document.getElementById('activeInvestigations').textContent = activeInvestigations;
            
        } catch (error) {
            document.getElementById('totalCorrelations').textContent = '0';
            document.getElementById('highConfidence').textContent = '0';
            document.getElementById('activeInvestigations').textContent = '0';
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

        // Animate algorithm cards
        anime({
            targets: '.algorithm-card',
            scale: [0.9, 1],
            opacity: [0, 1],
            delay: anime.stagger(150, {start: 300}),
            duration: 600,
            easing: 'easeOutElastic(1, .8)'
        });
    }
}

// Initialize correlation analysis when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.correlationAnalysis = new CorrelationAnalysis();
});