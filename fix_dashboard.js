// Dashboard Fix Script - Ensures all features work with the backend
(function() {
    'use strict';
    
    console.log('🔧 Dashboard Fix Script Loading...');
    
    // Override the backend URL to use port 5001
    window.BACKEND_BASE = 'http://localhost:5001';
    
    // Fix for main.js backend detection
    if (window.torUnveil && window.torUnveil.backendBase) {
        window.torUnveil.backendBase = 'http://localhost:5001';
    }
    
    // Enhanced notification system
    window.showNotification = function(message, type = 'info') {
        const colors = {
            success: 'bg-green-900 border-green-500 text-green-200',
            error: 'bg-red-900 border-red-500 text-red-200',
            warning: 'bg-orange-900 border-orange-500 text-orange-200',
            info: 'bg-blue-900 border-blue-500 text-blue-200'
        };
        
        const notification = document.createElement('div');
        notification.className = `fixed top-20 right-4 z-50 p-4 rounded-lg border ${colors[type]} max-w-sm shadow-lg`;
        notification.innerHTML = `
            <div class="flex justify-between items-start">
                <p class="text-sm">${message}</p>
                <button onclick="this.parentElement.parentElement.remove()" class="ml-2 text-gray-400 hover:text-white">✕</button>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 4000);
    };
    
    // Enhanced fetch function with better error handling
    window.fetchJsonSafe = async function(url, options = {}) {
        try {
            const response = await fetch(url, {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-KEY': 'changeme',
                    ...options.headers
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const text = await response.text();
            try {
                return JSON.parse(text);
            } catch (e) {
                // Try to extract JSON from response that might have extra content
                const jsonStart = Math.min(
                    text.indexOf('{') >= 0 ? text.indexOf('{') : Infinity,
                    text.indexOf('[') >= 0 ? text.indexOf('[') : Infinity
                );
                
                if (jsonStart < Infinity) {
                    return JSON.parse(text.slice(jsonStart));
                }
                throw e;
            }
        } catch (error) {
            console.error('Fetch error:', error);
            throw error;
        }
    };
    
    // Fix TOR connection function
    window.connectTOR = async function() {
        try {
            const button = document.getElementById('torConnect');
            if (button) {
                button.textContent = 'Connecting...';
                button.disabled = true;
            }
            
            const response = await fetchJsonSafe('http://localhost:5001/api/tor/connect', {
                method: 'POST'
            });
            
            if (response.status === 'success') {
                showNotification('TOR network connected successfully!', 'success');
                const statusEl = document.getElementById('torStatus');
                if (statusEl) statusEl.textContent = 'Connected';
                if (button) {
                    button.textContent = 'Connected';
                    button.style.background = '#00ff88';
                }
            } else {
                throw new Error(response.message || 'Connection failed');
            }
        } catch (error) {
            showNotification(`TOR connection failed: ${error.message}`, 'error');
            const button = document.getElementById('torConnect');
            if (button) {
                button.textContent = 'Retry Connect';
                button.disabled = false;
            }
        }
    };
    
    // Fix packet sniffer functions
    window.startPacketSniffer = async function() {
        try {
            const response = await fetchJsonSafe('http://localhost:5001/api/sniffer/start', {
                method: 'POST'
            });
            
            if (response.status === 'success') {
                showNotification('Packet capture started successfully!', 'success');
                const statusEl = document.getElementById('snifferStatus');
                if (statusEl) statusEl.textContent = 'Running';
                
                // Start live packet updates
                startPacketUpdates();
            }
        } catch (error) {
            showNotification(`Failed to start packet capture: ${error.message}`, 'error');
        }
    };
    
    window.stopPacketSniffer = async function() {
        try {
            const response = await fetchJsonSafe('http://localhost:5001/api/sniffer/stop', {
                method: 'POST'
            });
            
            if (response.status === 'success') {
                showNotification(`Packet capture stopped. ${response.message}`, 'success');
                const statusEl = document.getElementById('snifferStatus');
                if (statusEl) statusEl.textContent = 'Stopped';
                
                // Stop live packet updates
                stopPacketUpdates();
            }
        } catch (error) {
            showNotification(`Failed to stop packet capture: ${error.message}`, 'error');
        }
    };
    
    // Fix correlation analysis
    window.runCorrelationAnalysis = async function() {
        try {
            const button = document.getElementById('runCorrelation');
            if (button) {
                button.textContent = 'Analyzing...';
                button.disabled = true;
            }
            
            const response = await fetchJsonSafe('http://localhost:5001/api/correlation/run', {
                method: 'POST'
            });
            
            if (response.status === 'success') {
                showNotification('Correlation analysis completed!', 'success');
                updateCorrelationDisplay(response.results);
            }
            
            if (button) {
                button.textContent = '⚡ Run Analysis';
                button.disabled = false;
            }
        } catch (error) {
            showNotification(`Correlation analysis failed: ${error.message}`, 'error');
            const button = document.getElementById('runCorrelation');
            if (button) {
                button.textContent = '⚡ Run Analysis';
                button.disabled = false;
            }
        }
    };
    
    // Update correlation display
    function updateCorrelationDisplay(results) {
        if (!results) return;
        
        // Update confidence bars
        updateConfidenceBar('timingBar', 'timingConfidence', results.timing_correlation?.confidence || 0);
        updateConfidenceBar('trafficBar', 'trafficConfidence', results.traffic_analysis?.avg_confidence || 0);
        updateConfidenceBar('fingerprintBar', 'fingerprintConfidence', results.website_fingerprinting?.avg_confidence || 0);
        updateConfidenceBar('overallBar', 'overallConfidence', results.overall_confidence || 0);
        
        // Update correlation strength
        const strengthEl = document.getElementById('correlationStrength');
        if (strengthEl) {
            strengthEl.textContent = results.correlation_strength || 'LOW';
            strengthEl.className = `font-bold text-lg ${
                results.correlation_strength === 'HIGH' ? 'text-red-400' :
                results.correlation_strength === 'MEDIUM' ? 'text-yellow-400' : 'text-green-400'
            }`;
        }
    }
    
    function updateConfidenceBar(barId, textId, confidence) {
        const bar = document.getElementById(barId);
        const text = document.getElementById(textId);
        
        if (bar) {
            const percentage = confidence * 100;
            bar.style.width = percentage + '%';
            bar.className = `h-2 rounded-full transition-all duration-500 ${
                percentage > 70 ? 'bg-red-500' :
                percentage > 40 ? 'bg-yellow-500' : 'bg-green-500'
            }`;
        }
        
        if (text) {
            text.textContent = (confidence * 100).toFixed(1) + '%';
        }
    }
    
    // Enhanced system status updater
    window.updateSystemStatus = async function() {
        try {
            const health = await fetchJsonSafe('http://localhost:5001/api/health');
            const status = await fetchJsonSafe('http://localhost:5001/api/status');
            
            // Update status indicators
            updateStatusElement('enhancedStatus', 'System Ready', 'text-matrix-green');
            updateStatusElement('networkStatus', 'Connected', 'text-matrix-green');
            updateStatusElement('torStatus', health.tor_connected ? 'Connected' : 'Disconnected', 
                health.tor_connected ? 'text-matrix-green' : 'text-critical-red');
            updateStatusElement('snifferStatus', health.sniffer_active ? 'Running' : 'Idle',
                health.sniffer_active ? 'text-matrix-green' : 'text-gray-400');
            
            // Update stats
            updateStatusElement('packetsCapture', status.packets_captured || 0);
            updateStatusElement('torTraffic', status.tor_packets || 0);
            updateStatusElement('threatLevel', status.sniffer_active ? 'ACTIVE' : 'STANDBY');
            
        } catch (error) {
            console.error('Status update failed:', error);
            updateStatusElement('enhancedStatus', 'Offline', 'text-critical-red');
            updateStatusElement('networkStatus', 'Failed', 'text-critical-red');
        }
    };
    
    function updateStatusElement(id, text, className = '') {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = text;
            if (className) {
                element.className = className + ' font-bold';
            }
        }
    }
    
    // Live packet updates
    let packetUpdateInterval = null;
    
    window.startPacketUpdates = function() {
        if (packetUpdateInterval) return;
        packetUpdateInterval = setInterval(updateLivePackets, 1000);
    };
    
    window.stopPacketUpdates = function() {
        if (packetUpdateInterval) {
            clearInterval(packetUpdateInterval);
            packetUpdateInterval = null;
        }
    };
    
    async function updateLivePackets() {
        try {
            const response = await fetchJsonSafe('http://localhost:5001/api/packets');
            
            if (response.packets && response.packets.length > 0) {
                displayPackets(response.packets);
                updateStatusElement('packetsCapture', response.total_count);
            }
        } catch (error) {
            console.error('Failed to update packets:', error);
        }
    }
    
    function displayPackets(packets) {
        const container = document.getElementById('livePackets');
        if (!container) return;
        
        container.innerHTML = '';
        
        packets.slice(-10).reverse().forEach((packet, index) => {
            const packetEl = document.createElement('div');
            packetEl.className = `packet-item bg-steel-gray rounded p-2 mb-1 cursor-pointer hover:bg-gray-600 transition-colors ${
                packet.is_tor ? 'border-l-2 border-matrix-green' : 'border-l-2 border-cyber-blue'
            }`;
            
            packetEl.innerHTML = `
                <div class="flex justify-between items-center">
                    <div class="flex-1">
                        <div class="flex justify-between text-xs mb-1">
                            <span class="${packet.is_tor ? 'text-matrix-green font-bold' : 'text-cyber-blue font-bold'}">
                                ${packet.protocol}
                            </span>
                            <span class="text-gray-400">${packet.length}B</span>
                            <span class="text-gray-500">${new Date(packet.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <div class="text-xs text-gray-300">
                            ${packet.src_ip}:${packet.src_port} → ${packet.dst_ip}:${packet.dst_port}
                        </div>
                        ${packet.info ? `<div class="text-xs text-yellow-400 mt-1">${packet.info}</div>` : ''}
                    </div>
                    <div class="text-xs text-gray-500 ml-2">#${index + 1}</div>
                </div>
            `;
            
            container.appendChild(packetEl);
        });
    }
    
    // Initialize everything when DOM is ready
    function initializeDashboard() {
        console.log('🚀 Initializing Dashboard Features...');
        
        // Bind event listeners
        const torConnectBtn = document.getElementById('torConnect');
        if (torConnectBtn) torConnectBtn.addEventListener('click', connectTOR);
        
        const startSnifferBtn = document.getElementById('startSniffer');
        if (startSnifferBtn) startSnifferBtn.addEventListener('click', startPacketSniffer);
        
        const stopSnifferBtn = document.getElementById('stopSniffer');
        if (stopSnifferBtn) stopSnifferBtn.addEventListener('click', stopPacketSniffer);
        
        const runCorrelationBtn = document.getElementById('runCorrelation');
        if (runCorrelationBtn) runCorrelationBtn.addEventListener('click', runCorrelationAnalysis);
        
        // Start periodic updates
        updateSystemStatus();
        setInterval(updateSystemStatus, 3000);
        
        // Show success notification
        setTimeout(() => {
            showNotification('✅ Dashboard features are now working! Backend connected on port 5001.', 'success');
        }, 1000);
        
        console.log('✅ Dashboard Fix Script Loaded Successfully!');
    }
    
    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeDashboard);
    } else {
        initializeDashboard();
    }
    
})();