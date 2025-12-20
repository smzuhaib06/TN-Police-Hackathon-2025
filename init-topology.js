// Initialize Enhanced Topology
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('networkTopology')) {
        window.torUnveil = window.torUnveil || {};
        window.torUnveil.topology = new EnhancedTopology();
        console.log('Enhanced Topology initialized');
    }
});