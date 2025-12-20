// Real-time stats updater for enhanced UI
function updateEnhancedStats() {
    const stats = {
        activeCircuits: Math.floor(Math.random() * 50) + 200,
        guardNodes: Math.floor(Math.random() * 200) + 1800,
        middleRelays: Math.floor(Math.random() * 500) + 4500,
        exitNodes: Math.floor(Math.random() * 100) + 1200,
        totalBandwidth: Math.floor(Math.random() * 200) + 800,
        countriesCount: Math.floor(Math.random() * 10) + 85,
        packetsPerSec: (Math.random() * 5 + 10).toFixed(1),
        threatLevel: Math.random() < 0.1 ? 'HIGH' : (Math.random() < 0.3 ? 'MEDIUM' : 'LOW')
    };

    // Update elements if they exist
    const updates = {
        'activeCircuits': stats.activeCircuits,
        'guardNodes': stats.guardNodes.toLocaleString(),
        'middleRelays': stats.middleRelays.toLocaleString(),
        'exitNodes': stats.exitNodes.toLocaleString(),
        'totalBandwidth': stats.totalBandwidth + ' Gbps',
        'countriesCount': stats.countriesCount,
        'packetsCapture': stats.packetsPerSec + 'K',
        'threatLevel': stats.threatLevel
    };

    Object.entries(updates).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
            
            // Update threat level color
            if (id === 'threatLevel') {
                element.className = element.className.replace(/text-\w+-\w+/, 
                    stats.threatLevel === 'HIGH' ? 'text-critical-red' : 
                    stats.threatLevel === 'MEDIUM' ? 'text-warning-amber' : 'text-matrix-green'
                );
            }
        }
    });
}

// Start updating stats every 3 seconds
setInterval(updateEnhancedStats, 3000);

// Initial update
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(updateEnhancedStats, 1000);
});