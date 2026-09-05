/**
 * NIDS API Client
 * Handles all API communication with the backend.
 * Falls back to local simulation when the backend is unavailable.
 */

const api = (() => {
    let baseUrl = localStorage.getItem('apiUrl') || `${window.location.origin}`;
    const obj = {
        baseUrl,

        setBaseUrl(url) {
            const nextUrl = String(url || '').trim();
            if (!nextUrl) return;
            baseUrl = nextUrl.replace(/\/$/, '');
            try {
                localStorage.setItem('apiUrl', baseUrl);
            } catch (error) {
                console.warn('[NIDS] API URL could not be saved in browser storage');
            }
            this.baseUrl = baseUrl;
        },

        async _fetch(path, options) {
            try {
                const response = await fetch(`${baseUrl}${path}`, options);
                if (!response.ok) throw new Error(`API error: ${response.status}`);
                return await response.json();
            } catch (err) {
                console.warn(`[NIDS] Backend unreachable for ${path}, using local mode`);
                throw err;
            }
        },

        async getStats() {
            return this._fetch('/api/stats');
        },

        async getAlerts(limit = 50) {
            return this._fetch(`/api/alerts?limit=${limit}`);
        },

        async getAlertDetails(alertId) {
            return this._fetch(`/api/alerts/${alertId}`);
        },

        async acknowledgeAlert(alertId) {
            return this._fetch(`/api/alerts/${alertId}/acknowledge`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            });
        },

        async resolveAlert(alertId, resolution) {
            return this._fetch(`/api/alerts/${alertId}/resolve`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ resolution }),
            });
        },

        async getConfig() {
            return this._fetch('/api/config');
        },

        async updateConfig(newConfig) {
            return this._fetch('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newConfig),
            });
        },

        async startMonitoring() {
            return this._fetch('/api/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            });
        },

        async stopMonitoring() {
            return this._fetch('/api/stop', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            });
        },
    };
    return obj;
})();

window.api = api;
