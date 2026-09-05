/**
 * NIDS Dashboard — Full functional logic with live simulation
 */

const THREAT_TYPES = [
  { type: 'Port Scan', severity: 'medium' },
  { type: 'SYN Flood', severity: 'critical' },
  { type: 'SSH Brute Force', severity: 'high' },
  { type: 'SQL Injection', severity: 'high' },
  { type: 'DNS Tunneling', severity: 'medium' },
  { type: 'DDoS Attack', severity: 'critical' },
  { type: 'XSS Attempt', severity: 'medium' },
  { type: 'Malware C2 Beacon', severity: 'critical' },
  { type: 'Data Exfiltration', severity: 'high' },
  { type: 'ICMP Flood', severity: 'low' },
  { type: 'Banner Grabbing', severity: 'low' },
  { type: 'Command Injection', severity: 'high' },
];

const RANDOM_IPS = [
  '192.168.1.100', '10.0.0.52', '172.16.0.88', '45.227.34.12',
  '91.214.124.6', '188.131.18.77', '203.0.113.45', '198.51.100.23',
  '51.158.144.221', '212.129.7.98', '89.248.162.140', '193.27.228.52',
];

const LOCAL_IPS = ['10.0.0.5', '10.0.0.12', '192.168.1.1', '172.16.0.1'];
const STORAGE_KEY = 'nids-dashboard-state';

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomIp() {
  return `${Math.floor(Math.random() * 223 + 1)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254 + 1)}`;
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const icons = { success: 'fa-check-circle', error: 'fa-exclamation-circle', info: 'fa-info-circle' };
  const toast = document.createElement('div');
  toast.className = `toast-msg ${type}`;
  toast.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i> ${message}`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('fade-out');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function readStoredState() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
  } catch (error) {
    return null;
  }
}

function writeStoredState(value) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(value));
    return true;
  } catch (error) {
    showToast('Browser storage is unavailable', 'error');
    return false;
  }
}

function generateAlert() {
  const threat = randomItem(THREAT_TYPES);
  const isExternal = Math.random() > 0.3;
  const src = isExternal ? randomIp() : randomItem(LOCAL_IPS);
  const dst = randomItem(LOCAL_IPS);
  return {
    id: `ALR-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
    timestamp: new Date().toISOString(),
    type: threat.type,
    severity: threat.severity,
    source_ip: src,
    destination_ip: dst,
    status: 'open',
    acknowledged: false,
    resolved: false,
  };
}

class NIDSDashboard {
  constructor() {
    this.threatChart = null;
    this.alertChart = null;
    this.protocolChart = null;
    this.updateInterval = 3000;
    this.maxDataPoints = 30;
    this.isMonitoring = false;
    this.alerts = [];
    this.stats = {
      total_packets: 0,
      normal_count: 0,
      suspicious_count: 0,
      malicious_count: 0,
      active_threats: 0,
      packets_per_second: 0,
    };
    this.protocolData = { TCP: 0, UDP: 0, ICMP: 0 };
    this.threatSources = {};
    this.currentFilter = 'all';
    this.detailAlertId = null;
    this.threatData = {
      labels: [],
      datasets: [{
        label: 'Packets/s',
        data: [],
        borderColor: '#00d4ff',
        tension: 0.35,
        fill: true,
        backgroundColor: 'rgba(0, 212, 255, 0.08)',
        pointRadius: 0,
        borderWidth: 2,
      }],
    };
  }

  async init() {
    this.initCharts();
    this.setupEventListeners();
    this.restoreState();
    this.updateUI();
    this.renderAlerts();
    this.renderTopThreats();
  }

  restoreState() {
    try {
      const saved = readStoredState();
      if (!saved) return;
      this.alerts = Array.isArray(saved.alerts) ? saved.alerts : [];
      this.stats = { ...this.stats, ...(saved.stats || {}) };
      this.protocolData = { ...this.protocolData, ...(saved.protocolData || {}) };
      this.threatSources = saved.threatSources || {};
      const settings = saved.settings || {};
      const apiUrlInput = document.getElementById('apiUrl');
      if (apiUrlInput && typeof settings.apiUrl === 'string' && settings.apiUrl.trim()) apiUrlInput.value = settings.apiUrl;
      const interval = Number(settings.refreshInterval);
      if (Number.isFinite(interval) && interval >= 1) {
        this.updateInterval = interval * 1000;
        const intervalInput = document.getElementById('refreshInterval');
        if (intervalInput) intervalInput.value = interval;
      }
      const limitInput = document.getElementById('alertsLimit');
      if (limitInput && Number.isFinite(Number(settings.alertsLimit))) limitInput.value = settings.alertsLimit;
      const autoRefresh = document.getElementById('autoRefresh');
      if (autoRefresh && typeof settings.autoRefresh === 'boolean') autoRefresh.checked = settings.autoRefresh;
    } catch (error) {
      console.warn('[NIDS] Saved dashboard state could not be restored');
    }
  }

  persistState() {
    const settings = {
      refreshInterval: Math.max(1, Number(document.getElementById('refreshInterval')?.value || 3)),
      alertsLimit: Math.max(1, Number(document.getElementById('alertsLimit')?.value || 20)),
      autoRefresh: Boolean(document.getElementById('autoRefresh')?.checked),
    };
    return writeStoredState({
      alerts: this.alerts,
      stats: this.stats,
      protocolData: this.protocolData,
      threatSources: this.threatSources,
      settings: {
        ...settings,
        apiUrl: document.getElementById('apiUrl')?.value?.trim() || '',
      },
    });
  }

  initCharts() {
    const threatEl = document.getElementById('threatChart');
    if (threatEl) {
      this.threatChart = new Chart(threatEl.getContext('2d'), {
        type: 'line',
        data: this.threatData,
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: { beginAtZero: true, grid: { color: 'rgba(30, 41, 59, 0.5)' }, ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } } },
            x: { grid: { display: false }, ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 }, maxTicksLimit: 6 } },
          },
          plugins: { legend: { display: false } },
          animation: { duration: 0 },
        },
      });
    }

    const alertEl = document.getElementById('alertChart');
    if (alertEl) {
      this.alertChart = new Chart(alertEl.getContext('2d'), {
        type: 'doughnut',
        data: {
          labels: ['Normal', 'Suspicious', 'Malicious'],
          datasets: [{
            data: [0, 0, 0],
            backgroundColor: ['#00e676', '#ffb547', '#ff3b5c'],
            borderColor: '#151c2c',
            borderWidth: 3,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '65%',
          plugins: {
            legend: { position: 'bottom', labels: { color: '#94a3b8', font: { family: 'Space Grotesk', size: 11 }, padding: 12 } },
          },
        },
      });
    }

    const protoEl = document.getElementById('protocolChart');
    if (protoEl) {
      this.protocolChart = new Chart(protoEl.getContext('2d'), {
        type: 'bar',
        data: {
          labels: ['TCP', 'UDP', 'ICMP'],
          datasets: [{
            label: 'Packets',
            data: [0, 0, 0],
            backgroundColor: ['#00d4ff', '#00e676', '#ffb547'],
            borderRadius: 6,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            y: { beginAtZero: true, grid: { color: 'rgba(30, 41, 59, 0.5)' }, ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } } },
            x: { grid: { display: false }, ticks: { color: '#94a3b8', font: { family: 'Space Grotesk', size: 11 } } },
          },
        },
      });
    }
  }

  setupEventListeners() {
    document.getElementById('refreshBtn')?.addEventListener('click', () => {
      this.renderAlerts();
      showToast('Alerts refreshed', 'info');
    });

    document.getElementById('clearAlertsBtn')?.addEventListener('click', () => {
      this.alerts = [];
      this.threatSources = {};
      this.stats.active_threats = 0;
      this.persistState();
      this.renderAlerts();
      this.renderTopThreats();
      this.updateUI();
      showToast('All alerts cleared', 'success');
    });

    document.getElementById('saveSettings')?.addEventListener('click', () => {
      const url = document.getElementById('apiUrl')?.value?.trim();
      const interval = parseInt(document.getElementById('refreshInterval')?.value || '3', 10);
      if (url && window.api) window.api.setBaseUrl(url);
      if (interval > 0) this.updateInterval = interval * 1000;
      const saved = this.persistState();
      if (saved) showToast('Settings saved successfully', 'success');
      if (this.isMonitoring) {
        this.stopSimulation();
        if (document.getElementById('autoRefresh')?.checked !== false) this.startSimulation();
      }
      const settingsModal = document.getElementById('settingsModal');
      if (settingsModal) bootstrap.Modal.getOrCreateInstance(settingsModal).hide();
    });

    document.querySelectorAll('.chip').forEach(chip => {
      chip.addEventListener('click', () => {
        document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        this.currentFilter = chip.dataset.filter;
        this.renderAlerts();
      });
    });

    document.getElementById('ackBtn')?.addEventListener('click', () => {
      if (!this.detailAlertId) return;
      const alert = this.alerts.find(a => a.id === this.detailAlertId);
      if (alert) {
        alert.status = 'acknowledged';
        alert.acknowledged = true;
        this.stats.active_threats = this.alerts.filter(item => item.status === 'open').length;
        this.persistState();
        this.renderAlerts();
        const detailModal = document.getElementById('alertDetailModal');
        if (detailModal) bootstrap.Modal.getOrCreateInstance(detailModal).hide();
        showToast(`Alert ${alert.status}`, 'success');
      }
    });

    document.getElementById('resolveBtn')?.addEventListener('click', () => {
      if (!this.detailAlertId) return;
      const alert = this.alerts.find(a => a.id === this.detailAlertId);
      if (alert) {
        alert.status = 'resolved';
        alert.resolved = true;
        this.stats.active_threats = this.alerts.filter(item => item.status === 'open').length;
        this.persistState();
        this.renderAlerts();
        const detailModal = document.getElementById('alertDetailModal');
        if (detailModal) bootstrap.Modal.getOrCreateInstance(detailModal).hide();
        showToast(`Alert ${alert.status}`, 'success');
      }
    });

    const startBtn = document.getElementById('startBtn');
    const stopBtn = document.getElementById('stopBtn');

    startBtn?.addEventListener('click', () => this.startMonitoring());
    stopBtn?.addEventListener('click', () => this.stopMonitoring());
  }

  startMonitoring() {
    this.isMonitoring = true;
    document.getElementById('startBtn').style.display = 'none';
    document.getElementById('stopBtn').style.display = 'inline-flex';
    document.getElementById('statusDot').className = 'status-dot online';
    document.getElementById('statusText').textContent = 'Monitoring';
    this.persistState();
    this.startSimulation();
  }

  stopMonitoring() {
    this.isMonitoring = false;
    document.getElementById('startBtn').style.display = 'inline-flex';
    document.getElementById('stopBtn').style.display = 'none';
    document.getElementById('statusDot').className = 'status-dot offline';
    document.getElementById('statusText').textContent = 'Standby';
    this.persistState();
    this.stopSimulation();
  }

  startSimulation() {
    this.stopSimulation();
    this.simTimer = setInterval(() => this.tick(), this.updateInterval);
    this.tick();
  }

  stopSimulation() {
    if (this.simTimer) {
      clearInterval(this.simTimer);
      this.simTimer = null;
    }
  }

  tick() {
    const pps = Math.floor(Math.random() * 800 + 200);
    this.stats.packets_per_second = pps;
    this.stats.total_packets += pps * (this.updateInterval / 1000);

    const normal = Math.floor(pps * 0.92);
    const suspicious = Math.floor(pps * 0.06);
    const malicious = Math.floor(pps * 0.02);
    this.stats.normal_count += normal;
    this.stats.suspicious_count += suspicious;
    this.stats.malicious_count += malicious;

    const protocols = ['TCP', 'UDP', 'ICMP'];
    protocols.forEach(p => {
      this.protocolData[p] += Math.floor(pps * (p === 'TCP' ? 0.7 : p === 'UDP' ? 0.25 : 0.05));
    });

    if (Math.random() > 0.4) {
      const alert = generateAlert();
      this.alerts.unshift(alert);
      if (this.alerts.length > 100) this.alerts.pop();
      this.stats.active_threats = this.alerts.filter(a => a.status === 'open').length;
      this.threatSources[alert.source_ip] = (this.threatSources[alert.source_ip] || 0) + 1;
    }

    this.updateCharts();
    this.updateUI();
    this.renderAlerts();
    this.renderTopThreats();
    this.persistState();
  }

  updateCharts() {
    const ts = new Date().toLocaleTimeString();
    this.threatData.labels.push(ts);
    this.threatData.datasets[0].data.push(this.stats.packets_per_second);
    if (this.threatData.labels.length > this.maxDataPoints) {
      this.threatData.labels.shift();
      this.threatData.datasets[0].data.shift();
    }
    this.threatChart?.update('none');

    if (this.alertChart) {
      this.alertChart.data.datasets[0].data = [
        this.stats.normal_count,
        this.stats.suspicious_count,
        this.stats.malicious_count,
      ];
      this.alertChart.update('none');
    }

    if (this.protocolChart) {
      this.protocolChart.data.datasets[0].data = [
        this.protocolData.TCP,
        this.protocolData.UDP,
        this.protocolData.ICMP,
      ];
      this.protocolChart.update('none');
    }
  }

  updateUI() {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('threatsCount', this.stats.active_threats.toLocaleString());
    set('criticalCount', this.stats.malicious_count.toLocaleString());
    set('packetsCount', this.stats.total_packets.toLocaleString());
    const total = this.stats.normal_count + this.stats.suspicious_count + this.stats.malicious_count;
    if (total > 0) {
      const rate = ((this.stats.normal_count / total) * 100).toFixed(1);
      set('detectionRate', `${rate}%`);
    }
  }

  renderAlerts() {
    const tbody = document.getElementById('alertsTable');
    if (!tbody) return;

    let filtered = this.alerts;
    if (this.currentFilter !== 'all') {
      filtered = this.alerts.filter(a => a.severity === this.currentFilter);
    }

    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No alerts match this filter</td></tr>';
      return;
    }

    const limit = parseInt(document.getElementById('alertsLimit')?.value || '20', 10);
    const shown = filtered.slice(0, limit);

    tbody.innerHTML = shown.map(alert => `
      <tr class="slide-in" onclick="window.viewAlert('${alert.id}')">
        <td class="mono">${new Date(alert.timestamp).toLocaleTimeString()}</td>
        <td>${alert.type}</td>
        <td class="mono">${alert.source_ip}</td>
        <td class="mono">${alert.destination_ip}</td>
        <td><span class="sev-badge ${alert.severity}">${alert.severity}</span></td>
        <td><span class="status-badge ${alert.status}">${alert.status}</span></td>
        <td><button class="btn-ghost btn-sm" onclick="event.stopPropagation(); window.viewAlert('${alert.id}')">View</button></td>
      </tr>
    `).join('');
  }

  renderTopThreats() {
    const container = document.getElementById('topThreats');
    if (!container) return;

    const sorted = Object.entries(this.threatSources)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);

    if (sorted.length === 0) {
      container.innerHTML = '<div class="empty-state">No threat data yet</div>';
      return;
    }

    const max = sorted[0][1];
    const colors = { critical: '#ff3b5c', high: '#ffb547', medium: '#5b9eff', low: '#00e676' };

    container.innerHTML = sorted.map(([ip, count]) => {
      const pct = (count / max) * 100;
      const alert = this.alerts.find(a => a.source_ip === ip);
      const color = alert ? colors[alert.severity] || '#5b9eff' : '#5b9eff';
      return `
        <div class="threat-source">
          <div class="threat-source-left">
            <div>
              <div class="threat-source-ip">${ip}</div>
              <div class="threat-source-count">${count} alert${count > 1 ? 's' : ''}</div>
            </div>
          </div>
          <div class="threat-bar">
            <div class="threat-bar-fill" style="width:${pct}%;background:${color}"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  showDetail(alert) {
    this.detailAlertId = alert.id;
    const body = document.getElementById('alertDetailBody');
    if (!body) return;

    const rows = [
      ['Alert ID', alert.id],
      ['Timestamp', new Date(alert.timestamp).toLocaleString()],
      ['Threat Type', alert.type],
      ['Severity', alert.severity.toUpperCase()],
      ['Source IP', alert.source_ip],
      ['Destination', alert.destination_ip],
      ['Status', alert.status],
      ['Acknowledged', alert.acknowledged ? 'Yes' : 'No'],
      ['Resolved', alert.resolved ? 'Yes' : 'No'],
    ];

    body.innerHTML = rows.map(([label, value]) => `
      <div class="detail-row">
        <span class="detail-label">${label}</span>
        <span class="detail-value">${value}</span>
      </div>
    `).join('');

    const modal = bootstrap.Modal.getOrCreateInstance(document.getElementById('alertDetailModal'));
    modal.show();
  }
}

const dashboard = new NIDSDashboard();

window.viewAlert = (id) => {
  const alert = dashboard.alerts.find(a => a.id === id);
  if (alert) dashboard.showDetail(alert);
};

document.addEventListener('DOMContentLoaded', () => {
  dashboard.init();
});
