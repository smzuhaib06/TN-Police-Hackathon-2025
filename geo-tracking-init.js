// Geo Tracking Initialization Script
document.addEventListener('DOMContentLoaded', function() {
    // Add event listener for geo tracking button
    const geoTrackingBtn = document.getElementById('startGeoTracking');
    if (geoTrackingBtn) {
        geoTrackingBtn.addEventListener('click', function() {
            if (window.geoPositioning) {
                window.geoPositioning.simulateIPData();
                this.textContent = 'Geo Tracking Active';
                this.disabled = true;
                this.classList.remove('bg-matrix-green');
                this.classList.add('bg-warning-amber');
            }
        });
    }
    
    // Initialize components after a short delay to ensure DOM is ready
    setTimeout(() => {
        // Initialize TOR geo visualization if available
        if (window.TorGeoVisualization && !window.torGeoVisualization) {
            window.torGeoVisualization = new TorGeoVisualization();
            window.geoPositioning = window.torGeoVisualization; // Backward compatibility
            console.log('TOR Geo Visualization initialized');
        }
        
        // Initialize enhanced topology if available
        if (window.EnhancedTopology && !window.enhancedTopology) {
            window.enhancedTopology = new EnhancedTopology();
            window.__liveTopologyPresent__ = true;
            console.log('Enhanced Topology initialized');
        }
    }, 1000);
});