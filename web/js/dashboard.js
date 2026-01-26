/**
 * NIDS Dashboard Logic
 * Handles real-time updates, charts, and UI interactions
 */

document.addEventListener('DOMContentLoaded', () => {
    // Initialize Dashboard
    const dashboard = new NIDSDashboard();
    dashboard.init();
});

class NIDSDashboard {
    constructor() {
        this.trafficChart = null;
        this.threatChart = null;
        this.updateInterval = 5000; // 5 seconds
        this.maxDataPoints = 20;
        this.trafficData = {
            labels: [],
            datasets: [{
                label: 'Network Traffic (Packets/s)',
                data: [],
                borderColor: '#0d6efd',
                tension: 0.4,
                fill: true,
                backgroundColor: 'rgba(13, 110, 253, 0.1)'
            }]
        };
    }

    async init() {
        this.initCharts();
        this.setupEventListeners();
        this.startDataPoller();
        await this.loadInitialData();
    }

    initCharts() {
        const trafficCtx = document.getElementById('trafficChart').getContext('2d');
        this.trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: this.trafficData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true },
                    x: { display: false }
                },
                plugins: {
                    legend: { display: false }
                },
                animation: { duration: 0 }
            }
        });

        const threatCtx = document.getElementById('threatChart').getContext('2d');
        this.threatChart = new Chart(threatCtx, {
            type: 'doughnut',
            data: {
                labels: ['Normal', 'Suspicious', 'Malicious'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#198754', '#ffc107', '#dc3545']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
    }

    setupEventListeners() {
        // Refresh button
        document.getElementById('refreshBtn')?.addEventListener('click', () => {
            this.loadInitialData();
        });

        // Search alerts
        document.getElementById('alertSearch')?.addEventListener('input', (e) => {
            this.filterAlerts(e.target.value);
        });
    }

    async loadInitialData() {
        try {
            const stats = await api.getStats();
            this.updateStatsUI(stats);
            
            const alerts = await api.getAlerts();
            this.updateAlertsTable(alerts);
        } catch (error) {
            console.error('Failed to load initial dashboard data:', error);
        }
    }

    startDataPoller() {
        setInterval(async () => {
            try {
                const stats = await api.getStats();
                this.updateCharts(stats);
                this.updateStatsUI(stats);
            } catch (error) {
                console.error('Polling error:', error);
            }
        }, this.updateInterval);
    }

    updateCharts(stats) {
        // Update Traffic Chart
        const timestamp = new Date().toLocaleTimeString();
        this.trafficData.labels.push(timestamp);
        this.trafficData.datasets[0].data.push(stats.packets_per_second || 0);

        if (this.trafficData.labels.length > this.maxDataPoints) {
            this.trafficData.labels.shift();
            this.trafficData.datasets[0].data.shift();
        }
        this.trafficChart.update();

        // Update Threat Chart
        this.threatChart.data.datasets[0].data = [
            stats.normal_count || 0,
            stats.suspicious_count || 0,
            stats.malicious_count || 0
        ];
        this.threatChart.update();
    }

    updateStatsUI(stats) {
        document.getElementById('active-threats').textContent = stats.active_threats || 0;
        document.getElementById('system-status').textContent = stats.status || 'Healthy';
        document.getElementById('total-packets').textContent = stats.total_packets || 0;
    }

    updateAlertsTable(alerts) {
        const tbody = document.getElementById('alertTableBody');
        if (!tbody) return;

        tbody.innerHTML = alerts.map(alert => `
            <tr class="${alert.severity === 'high' ? 'table-danger' : alert.severity === 'medium' ? 'table-warning' : ''}">
                <td>${new Date(alert.timestamp).toLocaleString()}</td>
                <td><span class="badge bg-${this.getSeverityColor(alert.severity)}">${alert.type}</span></td>
                <td>${alert.source_ip}</td>
                <td>${alert.message}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="viewAlert('${alert.id}')">View</button>
                </td>
            </tr>
        `).join('');
    }

    getSeverityColor(severity) {
        switch (severity) {
            case 'high': return 'danger';
            case 'medium': return 'warning';
            case 'low': return 'info';
            default: return 'secondary';
        }
    }

    filterAlerts(query) {
        // Filter logic for the UI
        console.log('Filtering alerts for:', query);
    }
}

// Global helper for alert actions
window.viewAlert = async (id) => {
    try {
        const alert = await api.getAlertDetails(id);
        console.log('Alert Details:', alert);
        // Modal logic would go here
    } catch (error) {
        alert('Failed to fetch alert details');
    }
};

// Setup event listeners for start/stop monitoring buttons
document.addEventListener('DOMContentLoaded', () => {
    const startBtn = document.getElementById('startBtn');
    const stopBtn = document.getElementById('stopBtn');
    
    if (startBtn) {
        startBtn.onclick = async () => {
            try {
                startBtn.disabled = true;
                startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';
                const response = await api.startMonitoring();
                console.log('Monitoring started:', response);
                startBtn.style.display = 'none';
                stopBtn.style.display = 'inline-block';
                alert('NIDS monitoring started successfully!');
            } catch (error) {
                console.error('Failed to start monitoring:', error);
                alert('Failed to start monitoring: ' + error.message);
                startBtn.disabled = false;
                startBtn.innerHTML = '<i class="fas fa-play"></i> Start Monitoring';
            }
        };
    }
    
    if (stopBtn) {
        stopBtn.onclick = async () => {
            try {
                stopBtn.disabled = true;
                stopBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Stopping...';
                const response = await api.stopMonitoring();
                console.log('Monitoring stopped:', response);
                startBtn.style.display = 'inline-block';
                stopBtn.style.display = 'none';
                alert('NIDS monitoring stopped successfully!');
            } catch (error) {
                console.error('Failed to stop monitoring:', error);
                alert('Failed to stop monitoring: ' + error.message);
                stopBtn.disabled = false;
                stopBtn.innerHTML = '<i class="fas fa-stop"></i> Stop Monitoring';
            }
        };
    }
});
