/**
 * NIDS API Client
 * Handles all API communication with the backend
 */

const api = (() => {
    let baseUrl = localStorage.getItem('apiUrl') || `${window.location.origin}`;
    return {
        baseUrl,
        
        setBaseUrl(url) {
            baseUrl = url;
            localStorage.setItem('apiUrl', url);
            this.baseUrl = url;
        },
        
        async getStats() {
            const response = await fetch(`${baseUrl}/api/stats`);
            if (!response.ok) throw new Error(`API error: ${response.status}`);
            return response.json();
        },
        
        async getAlerts(limit = 50) {
            const response = await fetch(`${baseUrl}/api/alerts?limit=${limit}`);
            if (!response.ok) throw new Error(`API error: ${response.status}`);
            return response.json();
        },
        
        async getAlertDetails(alertId) {
            const response = await fetch(`${baseUrl}/api/alerts/${alertId}`);
            if (!response.ok) throw new Error(`API error: ${response.status}`);
            return response.json();
        },
        
        async acknowledgeAlert(alertId) {
            const response = await fetch(`${baseUrl}/api/alerts/${alertId}/acknowledge`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            if (!response.ok) throw new Error(`API error: ${response.status}`);
            return response.json();
        },
        
        async resolveAlert(alertId, resolution) {
            const response = await fetch(`${baseUrl}/api/alerts/${alertId}/resolve`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ resolution })
            });
            if (!response.ok) throw new Error(`API error: ${response.status}`);
            return response.json();
        },
        
        async getConfig() {
            const response = await fetch(`${baseUrl}/api/config`);
            if (!response.ok) throw new Error(`API error: ${response.status}`);
            return response.json();
        },
        
        async updateConfig(newConfig) {
            const response = await fetch(`${baseUrl}/api/config`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newConfig)
            });
            if (!response.ok) throw new Error(`API error: ${response.status}`);
            return response.json();
        },
        
        async startMonitoring() {
            const response = await fetch(`${baseUrl}/api/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            if (!response.ok) throw new Error(`API error: ${response.status}`);
            return response.json();
        },
        
        async stopMonitoring() {
            const response = await fetch(`${baseUrl}/api/stop`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            if (!response.ok) throw new Error(`API error: ${response.status}`);
            return response.json();
        }
    };
})();
