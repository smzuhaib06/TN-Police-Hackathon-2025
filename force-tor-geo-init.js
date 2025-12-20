// Force refresh and initialize new TOR Geo Visualization
(function() {
    'use strict';
    
    // Wait for DOM to be ready
    function initTorGeoVisualization() {
        // Clear any existing geo positioning instances
        if (window.geoPositioning) {
            try {
                if (window.geoPositioning.worldChart) {
                    window.geoPositioning.worldChart.dispose();
                }
            } catch (e) {}
        }
        
        // Clear the worldMap container completely
        const worldMapEl = document.getElementById('worldMap');
        if (worldMapEl) {
            worldMapEl.innerHTML = '';
            worldMapEl.style.cssText = '';
        }
        
        // Initialize new TOR Geo Visualization
        if (window.TorGeoVisualization) {
            console.log('Initializing new TOR Geo Visualization...');
            window.torGeoVisualization = new TorGeoVisualization();
            window.geoPositioning = window.torGeoVisualization; // Backward compatibility
            
            // Show notification
            setTimeout(() => {
                if (window.torUnveil && window.torUnveil.showNotification) {
                    window.torUnveil.showNotification('TOR Network Visualization Updated', 'success');
                }
            }, 2000);
        } else {
            console.error('TorGeoVisualization class not found');
        }
    }
    
    // Initialize immediately if DOM is ready, otherwise wait
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTorGeoVisualization);
    } else {
        // DOM is already ready
        setTimeout(initTorGeoVisualization, 100);
    }
    
    // Also initialize after a delay to ensure all scripts are loaded
    setTimeout(initTorGeoVisualization, 1500);
})();