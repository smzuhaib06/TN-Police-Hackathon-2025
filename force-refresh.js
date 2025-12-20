// Force browser cache refresh
(function() {
    // Add timestamp to force refresh
    const timestamp = Date.now();
    
    // Update page title to show refresh
    document.title = `TOR Unveil - Enhanced UI (${timestamp})`;
    
    // Force reload stylesheets
    const links = document.querySelectorAll('link[rel="stylesheet"]');
    links.forEach(link => {
        const href = link.href;
        link.href = href + (href.includes('?') ? '&' : '?') + 't=' + timestamp;
    });
    
    // Add visual indicator that changes are applied
    const indicator = document.createElement('div');
    indicator.style.cssText = `
        position: fixed;
        top: 10px;
        right: 10px;
        background: #00ff88;
        color: #000;
        padding: 8px 16px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: bold;
        z-index: 9999;
        animation: fadeInOut 3s ease-in-out;
    `;
    indicator.textContent = '✓ UI Enhanced';
    
    // Add fade animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes fadeInOut {
            0% { opacity: 0; transform: translateY(-20px); }
            20% { opacity: 1; transform: translateY(0); }
            80% { opacity: 1; transform: translateY(0); }
            100% { opacity: 0; transform: translateY(-20px); }
        }
    `;
    document.head.appendChild(style);
    document.body.appendChild(indicator);
    
    // Remove indicator after animation
    setTimeout(() => {
        if (indicator.parentNode) {
            indicator.remove();
        }
    }, 3000);
})();