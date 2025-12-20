/**
 * PCAP Visualizer for TOR Unveil
 * Features:
 * - Protocol distribution pie chart
 * - TOR vs Non-TOR traffic visualization
 * - Flow analysis charts
 * - Interactive filtering
 * - Real-time updates
 */

class PCAPVisualizer {
    constructor() {
        this.apiBase = 'http://localhost:5000/api';
        this.apiKey = 'changeme';
        this.charts = {};
        this.currentAnalysis = null;
        
        this.init();
    }
    
    init() {
        this.initCharts();
        this.setupEventListeners();
    }
    
    initCharts() {
        // Protocol Distribution Pie Chart
        const protocolContainer = document.getElementById('protocolPieChart');
        if (protocolContainer) {
            this.charts.protocol = echarts.init(protocolContainer);
        }
        
        // TOR Traffic Pie Chart
        const torContainer = document.getElementById('torTrafficPieChart');
        if (torContainer) {
            this.charts.torTraffic = echarts.init(torContainer);
        }
        
        // Flow Analysis Bar Chart
        const flowContainer = document.getElementById('flowAnalysisChart');
        if (flowContainer) {
            this.charts.flowAnalysis = echarts.init(flowContainer);
        }
        
        // TOR Node Type Distribution
        const nodeTypeContainer = document.getElementById('nodeTypePieChart');
        if (nodeTypeContainer) {
            this.charts.nodeType = echarts.init(nodeTypeContainer);
        }
    }
    
    setupEventListeners() {
        // File upload
        const uploadButton = document.getElementById('uploadPCAPButton');
        const fileInput = document.getElementById('pcapFileInput');
        
        if (uploadButton && fileInput) {
            uploadButton.addEventListener('click', () => fileInput.click());
            fileInput.addEventListener('change', (e) => this.handleFileUpload(e));
        }
        
        // Drag and drop
        const dropZone = document.getElementById('pcapDropZone');
        if (dropZone) {
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
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    this.analyzePCAP(files[0]);
                }
            });
        }
        
        // Export chart buttons
        document.getElementById('exportProtocolChart')?.addEventListener('click', () => 
            this.exportChart(this.charts.protocol, 'protocol-distribution.png')
        );
        
        document.getElementById('exportTorChart')?.addEventListener('click', () => 
            this.exportChart(this.charts.torTraffic, 'tor-traffic.png')
        );
    }
    
    async handleFileUpload(event) {
        const file = event.target.files[0];
        if (file) {
            await this.analyzePCAP(file);
        }
    }
    
    async analyzePCAP(file) {
        try {
            this.showLoading('Analyzing PCAP file...');
            
            const formData = new FormData();
            formData.append('file', file);
            
            const response = await fetch(`${this.apiBase}/pcap/analyze`, {
                method: 'POST',
                headers: {
                    'X-API-KEY': this.apiKey
                },
                body: formData
            });
            
            if (!response.ok) {
                throw new Error(`Analysis failed: ${response.statusText}`);
            }
            
            const result = await response.json();
            this.currentAnalysis = result.analysis;
            
            this.hideLoading();
            this.renderAnalysis(this.currentAnalysis);
            this.showNotification('PCAP analysis completed successfully', 'success');
            
        } catch (error) {
            this.hideLoading();
            this.showNotification(`Analysis failed: ${error.message}`, 'error');
            console.error('PCAP analysis error:', error);
        }
    }
    
    renderAnalysis(analysis) {
        if (!analysis) return;
        
        // Render protocol distribution
        this.renderProtocolDistribution(analysis);
        
        // Render TOR traffic breakdown
        this.renderTorTrafficBreakdown(analysis);
        
        // Render flow analysis
        this.renderFlowAnalysis(analysis);
        
        // Render TOR node types
        this.renderNodeTypeDistribution(analysis);
        
        // Update summary statistics
        this.updateSummaryStats(analysis);
    }
    
    renderProtocolDistribution(analysis) {
        if (!this.charts.protocol) return;
        
        const protocols = analysis.protocol_distribution || analysis.protocols || {};
        const data = Object.entries(protocols).map(([name, value]) => ({
            name: name,
            value: value
        }));
        
        const option = {
            title: {
                text: 'Protocol Distribution',
                left: 'center',
                textStyle: {
                    color: '#e6eef8',
                    fontSize: 16
                }
            },
            tooltip: {
                trigger: 'item',
                formatter: '{b}: {c} packets ({d}%)'
            },
            legend: {
                orient: 'vertical',
                right: 10,
                top: 'middle',
                textStyle: { color: '#e6eef8' }
            },
            series: [{
                type: 'pie',
                radius: ['40%', '70%'],
                avoidLabelOverlap: true,
                itemStyle: {
                    borderRadius: 10,
                    borderColor: '#1a1a1a',
                    borderWidth: 2
                },
                label: {
                    show: true,
                    formatter: '{b}\n{d}%',
                    color: '#e6eef8'
                },
                emphasis: {
                    label: {
                        show: true,
                        fontSize: 14,
                        fontWeight: 'bold'
                    },
                    itemStyle: {
                        shadowBlur: 10,
                        shadowOffsetX: 0,
                        shadowColor: 'rgba(0, 0, 0, 0.5)'
                    }
                },
                data: data,
                color: ['#4a90e2', '#00d4ff', '#00ff88', '#ffd700', '#ff6b6b', '#9b59b6']
            }]
        };
        
        this.charts.protocol.setOption(option);
    }
    
    renderTorTrafficBreakdown(analysis) {
        if (!this.charts.torTraffic) return;
        
        const totalPackets = analysis.packet_count || analysis.processed_packets || 0;
        const torPackets = analysis.tor_indicators_found || 0;
        const nonTorPackets = totalPackets - torPackets;
        
        const option = {
            title: {
                text: 'TOR vs Non-TOR Traffic',
                left: 'center',
                textStyle: {
                    color: '#e6eef8',
                    fontSize: 16
                }
            },
            tooltip: {
                trigger: 'item',
                formatter: '{b}: {c} packets ({d}%)'
            },
            legend: {
                orient: 'horizontal',
                bottom: 10,
                textStyle: { color: '#e6eef8' }
            },
            series: [{
                type: 'pie',
                radius: '70%',
                center: ['50%', '50%'],
                data: [
                    { 
                        value: torPackets, 
                        name: 'TOR Traffic',
                        itemStyle: { color: '#ff6b6b' }
                    },
                    { 
                        value: nonTorPackets, 
                        name: 'Non-TOR Traffic',
                        itemStyle: { color: '#4a90e2' }
                    }
                ],
                emphasis: {
                    itemStyle: {
                        shadowBlur: 10,
                        shadowOffsetX: 0,
                        shadowColor: 'rgba(0, 0, 0, 0.5)'
                    }
                },
                label: {
                    formatter: '{b}\n{c} packets\n({d}%)',
                    color: '#e6eef8'
                }
            }]
        };
        
        this.charts.torTraffic.setOption(option);
    }
    
    renderFlowAnalysis(analysis) {
        if (!this.charts.flowAnalysis) return;
        
        const flows = analysis.flows || {};
        const topFlows = Object.entries(flows)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);
        
        const flowNames = topFlows.map(([name]) => name.substring(0, 30) + '...');
        const flowCounts = topFlows.map(([, count]) => count);
        
        const option = {
            title: {
                text: 'Top 10 Network Flows',
                left: 'center',
                textStyle: {
                    color: '#e6eef8',
                    fontSize: 16
                }
            },
            tooltip: {
                trigger: 'axis',
                axisPointer: {
                    type: 'shadow'
                }
            },
            grid: {
                left: '3%',
                right: '4%',
                bottom: '3%',
                containLabel: true
            },
            xAxis: {
                type: 'value',
                axisLabel: { color: '#e6eef8' },
                splitLine: { lineStyle: { color: '#333' } }
            },
            yAxis: {
                type: 'category',
                data: flowNames,
                axisLabel: { 
                    color: '#e6eef8',
                    fontSize: 10
                }
            },
            series: [{
                name: 'Packet Count',
                type: 'bar',
                data: flowCounts,
                itemStyle: {
                    color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
                        { offset: 0, color: '#4a90e2' },
                        { offset: 1, color: '#00d4ff' }
                    ]),
                    borderRadius: [0, 5, 5, 0]
                },
                label: {
                    show: true,
                    position: 'right',
                    color: '#e6eef8'
                }
            }]
        };
        
        this.charts.flowAnalysis.setOption(option);
    }
    
    renderNodeTypeDistribution(analysis) {
        if (!this.charts.nodeType) return;
        
        // Extract TOR node type information from indicators
        const indicators = analysis.tor_indicators || [];
        const nodeTypes = {
            'Guard': 0,
            'Middle': 0,
            'Exit': 0,
            'Bridge': 0,
            'Unknown': 0
        };
        
        indicators.forEach(indicator => {
            const type = indicator.relay_type || indicator.type || 'Unknown';
            const normalized = type.charAt(0).toUpperCase() + type.slice(1).toLowerCase();
            if (nodeTypes.hasOwnProperty(normalized)) {
                nodeTypes[normalized]++;
            } else {
                nodeTypes['Unknown']++;
            }
        });
        
        const data = Object.entries(nodeTypes)
            .filter(([, value]) => value > 0)
            .map(([name, value]) => ({ name, value }));
        
        const option = {
            title: {
                text: 'TOR Node Type Distribution',
                left: 'center',
                textStyle: {
                    color: '#e6eef8',
                    fontSize: 16
                }
            },
            tooltip: {
                trigger: 'item',
                formatter: '{b}: {c} connections ({d}%)'
            },
            legend: {
                orient: 'horizontal',
                bottom: 10,
                textStyle: { color: '#e6eef8' }
            },
            series: [{
                type: 'pie',
                radius: ['30%', '60%'],
                data: data,
                color: ['#00ff88', '#4a90e2', '#ff6b6b', '#ffd700', '#999999'],
                emphasis: {
                    itemStyle: {
                        shadowBlur: 10,
                        shadowOffsetX: 0,
                        shadowColor: 'rgba(0, 0, 0, 0.5)'
                    }
                },
                label: {
                    formatter: '{b}\n{d}%',
                    color: '#e6eef8'
                }
            }]
        };
        
        this.charts.nodeType.setOption(option);
    }
    
    updateSummaryStats(analysis) {
        document.getElementById('totalPacketsAnalyzed')?.textContent = 
            (analysis.packet_count || analysis.processed_packets || 0).toLocaleString();
        
        document.getElementById('torPacketsFound')?.textContent = 
            (analysis.tor_indicators_found || 0).toLocaleString();
        
        document.getElementById('uniqueFlows')?.textContent = 
            (analysis.flow_count || 0).toLocaleString();
        
        document.getElementById('fileSize')?.textContent = 
            this.formatBytes(analysis.file_size || 0);
        
        const torPercentage = analysis.packet_count > 0 
            ? ((analysis.tor_indicators_found / analysis.packet_count) * 100).toFixed(2)
            : 0;
        document.getElementById('torPercentage')?.textContent = `${torPercentage}%`;
    }
    
    exportChart(chart, filename) {
        if (!chart) return;
        
        const url = chart.getDataURL({
            type: 'png',
            pixelRatio: 2,
            backgroundColor: '#1a1a1a'
        });
        
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        link.click();
        
        this.showNotification(`Chart exported as ${filename}`, 'success');
    }
    
    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    }
    
    showLoading(message) {
        Object.values(this.charts).forEach(chart => {
            if (chart) {
                chart.showLoading('default', {
                    text: message,
                    color: '#00d4ff',
                    textColor: '#e6eef8',
                    maskColor: 'rgba(26, 26, 26, 0.8)'
                });
            }
        });
    }
    
    hideLoading() {
        Object.values(this.charts).forEach(chart => {
            if (chart) {
                chart.hideLoading();
            }
        });
    }
    
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            background: ${type === 'success' ? '#00ff88' : type === 'error' ? '#ff6b6b' : '#00d4ff'};
            color: #1a1a1a;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            z-index: 10000;
            font-weight: bold;
            animation: slideIn 0.3s ease-out;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-out';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.pcapVisualizer = new PCAPVisualizer();
    console.log('PCAP Visualizer initialized');
});
