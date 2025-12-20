// Backend configuration
const BACKEND_CONFIG = {
    host: 'localhost',
    port: 5001,  // Using 5001 temporarily while main backend has issues
    baseUrl: function() {
        return `http://${this.host}:${this.port}`;
    }
};

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = BACKEND_CONFIG;
} else {
    window.BACKEND_CONFIG = BACKEND_CONFIG;
}