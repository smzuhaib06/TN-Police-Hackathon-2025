// Backend Status Checker
class BackendChecker {
    constructor() {
        this.backendUrl = 'http://localhost:5000';
        this.checkInterval = null;
        this.isOnline = false;
        this.init();
    }

    init() {
        this.checkStatus();
        this.startPeriodicCheck();
        this.showStatusIndicator();
    }

    async checkStatus() {
        try {
            const response = await fetch(`${this.backendUrl}/api/health`, { 
                method: 'GET',
                timeout: 3000 
            });
            
            if (response.ok) {
                this.isOnline = true;
                this.updateStatusIndicator('online');
                console.log('✅ Backend is online');
            } else {
                this.isOnline = false;
                this.updateStatusIndicator('error');
                console.log('❌ Backend returned error:', response.status);
            }
        } catch (error) {
            this.isOnline = false;
            this.updateStatusIndicator('offline');
            console.log('❌ Backend is offline:', error.message);
        }
    }

    startPeriodicCheck() {
        this.checkInterval = setInterval(() => {
            this.checkStatus();
        }, 5000);
    }

    showStatusIndicator() {
        const indicator = document.createElement('div');
        indicator.id = 'backend-status';
        indicator.className = 'fixed top-4 right-4 z-50 px-3 py-2 rounded-lg text-sm font-bold';
        indicator.innerHTML = 'Checking backend...';
        document.body.appendChild(indicator);
    }

    updateStatusIndicator(status) {
        const indicator = document.getElementById('backend-status');
        if (!indicator) return;

        switch (status) {
            case 'online':
                indicator.className = 'fixed top-4 right-4 z-50 px-3 py-2 rounded-lg text-sm font-bold bg-green-900 border border-green-500 text-green-200';
                indicator.innerHTML = '✅ Backend Online';
                break;
            case 'offline':
                indicator.className = 'fixed top-4 right-4 z-50 px-3 py-2 rounded-lg text-sm font-bold bg-red-900 border border-red-500 text-red-200';
                indicator.innerHTML = '❌ Backend Offline - Start backend/working_backend.py';
                break;
            case 'error':
                indicator.className = 'fixed top-4 right-4 z-50 px-3 py-2 rounded-lg text-sm font-bold bg-orange-900 border border-orange-500 text-orange-200';
                indicator.innerHTML = '⚠️ Backend Error';
                break;
        }
    }

    stop() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
        }
    }
}

// Auto-start backend checker
document.addEventListener('DOMContentLoaded', () => {
    window.backendChecker = new BackendChecker();
});