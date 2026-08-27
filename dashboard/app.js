class EnclaveWatchDashboard {
    constructor() {
        this.alerts = [];
        this.filters = {
            types: new Set(['ddos', 'c2', 'dns', 'malware', 'scan', 'exfil']),
            confidence: 0,
            timeRange: 'all' // 5m, 15m, 1h, 6h, 24h, all
        };
        this.systemStatus = {
            eventsPerSec: 0,
            uptime: 0,
            totalAlerts: 0,
            chainVerified: true
        };
        
        this.threatColors = {
            'ddos': '#ef4444',
            'c2_beacon': '#a855f7',
            'dns_tunnel': '#06b6d4',
            'encrypted_malware': '#f97316',
            'port_scan': '#eab308',
            'exfiltration': '#ec4899'
        };

        // Map UI short names ↔ API full names
        this.uiToApi = {
            'ddos': 'ddos', 'c2': 'c2_beacon', 'dns': 'dns_tunnel',
            'malware': 'encrypted_malware', 'scan': 'port_scan', 'exfil': 'exfiltration'
        };
        this.apiToUi = Object.fromEntries(Object.entries(this.uiToApi).map(([k,v]) => [v, k]));

        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectDelay = 30000;
        
        // Canvas history for sparklines (keyed by API names)
        this.sparklineData = {
            'ddos': Array(60).fill(0),
            'c2_beacon': Array(60).fill(0),
            'dns_tunnel': Array(60).fill(0),
            'encrypted_malware': Array(60).fill(0),
            'port_scan': Array(60).fill(0),
            'exfiltration': Array(60).fill(0)
        };
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.startClock();
        this.renderThreatStats();
        this.connectWebSocket();
        this.fetchInitialAlerts();
        
        // Simulating sparkline updates every 2 seconds for demo
        setInterval(() => this.updateSparklines(), 2000);
    }

    bindEvents() {
        // Filters
        document.querySelectorAll('#threat-type-filters input').forEach(cb => {
            cb.addEventListener('change', (e) => {
                if (e.target.checked) this.filters.types.add(e.target.value);
                else this.filters.types.delete(e.target.value);
                this.debouncedApplyFilters();
            });
        });

        const confSlider = document.getElementById('confidence-slider');
        const confValue = document.getElementById('confidence-value');
        confSlider.addEventListener('input', (e) => {
            confValue.textContent = e.target.value + '%';
            this.filters.confidence = parseInt(e.target.value);
            this.debouncedApplyFilters();
        });

        document.getElementById('time-range-select').addEventListener('change', (e) => {
            this.filters.timeRange = e.target.value;
            this.debouncedApplyFilters();
        });

        // Actions
        document.getElementById('btn-generate-attack').addEventListener('click', () => {
            const type = document.getElementById('attack-type-select').value;
            this.generateAttack(type);
        });

        document.getElementById('btn-run-all-attacks').addEventListener('click', () => {
            this.generateAttack('all');
        });

        document.getElementById('btn-retro-hunt').addEventListener('click', () => {
            const type = document.getElementById('ioc-type-select').value;
            const value = document.getElementById('ioc-value-input').value;
            if (value) this.runRetroHunt(type, value);
        });

        document.getElementById('btn-clear-feed').addEventListener('click', () => {
            document.getElementById('alert-feed').innerHTML = '';
            this.alerts = [];
        });

        document.getElementById('btn-verify-chain').addEventListener('click', () => {
            this.verifyChain();
        });
    }

    startClock() {
        const timeEl = document.getElementById('current-time');
        const uptimeEl = document.getElementById('system-uptime');
        const startTime = Date.now();

        setInterval(() => {
            const now = new Date();
            timeEl.textContent = now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
            
            const diff = Math.floor((Date.now() - startTime) / 1000);
            const h = String(Math.floor(diff / 3600)).padStart(2, '0');
            const m = String(Math.floor((diff % 3600) / 60)).padStart(2, '0');
            const s = String(diff % 60).padStart(2, '0');
            uptimeEl.textContent = `${h}:${m}:${s}`;
        }, 1000);
    }

    connectWebSocket() {
        const wsUrl = `ws://${window.location.hostname}:8000/ws/alerts`;
        try {
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                console.log('WebSocket Connected');
                this.updateWsStatus(true);
                this.reconnectAttempts = 0;
            };

            this.ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleWsMessage(data);
                } catch (e) {
                    console.error('Error parsing WS message:', e);
                }
            };

            this.ws.onclose = () => {
                this.updateWsStatus(false);
                this.scheduleReconnect();
            };

            this.ws.onerror = (err) => {
                console.error('WebSocket error:', err);
                this.ws.close();
            };
        } catch (e) {
            console.error('Failed to create WebSocket:', e);
            this.updateWsStatus(false);
            this.scheduleReconnect();
        }
    }

    scheduleReconnect() {
        const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), this.maxReconnectDelay);
        this.reconnectAttempts++;
        setTimeout(() => this.connectWebSocket(), delay);
    }

    updateWsStatus(connected) {
        const ind = document.getElementById('ws-status-indicator');
        const txt = document.getElementById('ws-status-text');
        if (connected) {
            ind.className = 'indicator green';
            txt.textContent = 'Connected';
        } else {
            ind.className = 'indicator red';
            txt.textContent = 'Disconnected';
        }
    }

    handleWsMessage(msg) {
        switch(msg.type) {
            case 'alert':
                this.addAlert(msg.data);
                break;
            case 'status':
                this.updateSystemStatus(msg.data);
                break;
            case 'chain_status':
                this.updateChainStatus(msg.data);
                break;
        }
    }

    addAlert(alert) {
        this.alerts.unshift(alert);
        // keep max 1000
        if (this.alerts.length > 1000) this.alerts.pop();
        
        this.systemStatus.totalAlerts++;
        document.getElementById('total-alerts').textContent = this.systemStatus.totalAlerts;

        // Sparkline data update
        if (this.sparklineData[alert.threat_type]) {
            this.sparklineData[alert.threat_type][59]++;
        }

        if (this.shouldShowAlert(alert)) {
            const feed = document.getElementById('alert-feed');
            const card = this.renderAlertCard(alert);
            feed.prepend(card);
            
            // Limit DOM nodes
            while (feed.children.length > 100) {
                feed.removeChild(feed.lastChild);
            }
        }
        
        this.updateThreatCounts();
    }

    async fetchInitialAlerts() {
        try {
            const res = await fetch('/api/alerts');
            if (res.ok) {
                const alerts = await res.json();
                // API returns DB rows — may have raw_json field to parse
                alerts.forEach(a => {
                    if (a.raw_json && typeof a.raw_json === 'string') {
                        try { Object.assign(a, JSON.parse(a.raw_json)); } catch {}
                    }
                    this.addAlert(a);
                });
            }
        } catch (e) {
            console.log('API not reachable, starting empty');
        }
    }

    renderAlertCard(alert) {
        const template = document.getElementById('alert-card-template');
        const clone = template.content.cloneNode(true);
        const card = clone.querySelector('.alert-card');
        
        const alertId = alert.alert_id || alert.id || '';
        card.dataset.id = alertId;
        
        const stripe = card.querySelector('.color-stripe');
        stripe.style.backgroundColor = this.threatColors[alert.threat_type] || '#64748b';

        const badge = card.querySelector('.threat-badge');
        // Display human-readable threat type
        const displayType = (alert.threat_type || '').replace(/_/g, ' ').toUpperCase();
        badge.textContent = displayType;
        badge.style.backgroundColor = (this.threatColors[alert.threat_type] || '#64748b') + '33';
        badge.style.color = this.threatColors[alert.threat_type] || '#94a3b8';

        const gauge = card.querySelector('.confidence-gauge');
        const confPct = Math.round((alert.confidence || 0) * 100);
        const confColor = confPct > 80 ? 'var(--danger)' : (confPct > 50 ? 'var(--warning)' : 'var(--success)');
        gauge.style.setProperty('--gauge-percent', `${confPct}%`);
        gauge.style.setProperty('--gauge-color', confColor);
        gauge.dataset.value = confPct;
        gauge.textContent = confPct + '%';

        card.querySelector('.timestamp').textContent = this.formatTimestamp(alert.timestamp);
        card.querySelector('.alert-title').textContent = this.escapeHtml(alert.title || 'Alert');
        card.querySelector('.alert-desc').textContent = this.escapeHtml(alert.description || '');
        
        // Handle source/dest from arrays
        const srcIp = (alert.source_ips && alert.source_ips[0]) || '—';
        const dstIp = (alert.dest_ips && alert.dest_ips[0]) || '—';
        const dstPort = (alert.dest_ports && alert.dest_ports[0]) || '*';
        card.querySelector('.src').textContent = srcIp;
        card.querySelector('.dst').textContent = `${dstIp}:${dstPort}`;

        // Retro-hunt badge
        if (alert.is_retrohunt) {
            card.querySelector('.retro-badge').classList.remove('hidden');
        }

        // Collapsed count badge
        if (alert.is_collapsed && alert.collapsed_count > 1) {
            const countBadge = card.querySelector('.count-badge');
            countBadge.textContent = `×${alert.collapsed_count}`;
            countBadge.classList.remove('hidden');
        }

        const evToggle = card.querySelector('.evidence-toggle');
        const evPanel = card.querySelector('.evidence-panel');
        const evContent = card.querySelector('.evidence-content');
        
        evToggle.addEventListener('click', () => {
            evPanel.classList.toggle('hidden');
            if (!evPanel.classList.contains('hidden') && !evContent.textContent) {
                evContent.textContent = JSON.stringify(alert.evidence || {}, null, 2);
            }
            evToggle.textContent = evPanel.classList.contains('hidden') ? 'View Evidence ▾' : 'Hide Evidence ▴';
        });

        // Actions
        card.querySelector('.btn-tp').addEventListener('click', () => this.submitFeedback(alertId, 'true_positive'));
        card.querySelector('.btn-fp').addEventListener('click', () => this.submitFeedback(alertId, 'false_positive'));
        card.querySelector('.btn-dl').addEventListener('click', () => this.downloadEvidence(alertId));

        return card;
    }

    shouldShowAlert(alert) {
        // Map API threat type to UI short name for filter matching
        const uiType = this.apiToUi[alert.threat_type] || alert.threat_type;
        if (!this.filters.types.has(uiType)) return false;
        if ((alert.confidence || 0) * 100 < this.filters.confidence) return false;
        
        if (this.filters.timeRange !== 'all') {
            const ts = alert.timestamp;
            const alertTime = typeof ts === 'number' ? (ts < 1e12 ? ts * 1000 : ts) : new Date(ts).getTime();
            const now = Date.now();
            const diffMins = (now - alertTime) / 60000;
            
            switch(this.filters.timeRange) {
                case '5m': if (diffMins > 5) return false; break;
                case '15m': if (diffMins > 15) return false; break;
                case '1h': if (diffMins > 60) return false; break;
                case '6h': if (diffMins > 360) return false; break;
                case '24h': if (diffMins > 1440) return false; break;
            }
        }
        return true;
    }

    debouncedApplyFilters() {
        if (this.filterTimeout) clearTimeout(this.filterTimeout);
        this.filterTimeout = setTimeout(() => {
            const feed = document.getElementById('alert-feed');
            feed.innerHTML = '';
            
            // Apply to up to last 100 matching
            let count = 0;
            for (let i = 0; i < this.alerts.length; i++) {
                if (count >= 100) break;
                const a = this.alerts[i];
                if (this.shouldShowAlert(a)) {
                    feed.appendChild(this.renderAlertCard(a));
                    count++;
                }
            }
        }, 300);
    }

    // Stats and Updates
    renderThreatStats() {
        const container = document.getElementById('threat-stats');
        container.innerHTML = '';
        
        const displayNames = {
            'ddos': 'DDoS', 'c2_beacon': 'C2 BEACON', 'dns_tunnel': 'DNS TUNNEL',
            'encrypted_malware': 'ENC MALWARE', 'port_scan': 'PORT SCAN', 'exfiltration': 'EXFIL'
        };
        
        Object.keys(this.threatColors).forEach(type => {
            const row = document.createElement('div');
            row.className = 'stat-row';
            
            const label = document.createElement('div');
            label.className = 'stat-label';
            const dotColor = this.threatColors[type] || '#64748b';
            label.innerHTML = `<span class="dot" style="background:${dotColor};box-shadow:0 0 6px ${dotColor}80"></span> ${displayNames[type] || type.toUpperCase()}`;
            
            const rightWrap = document.createElement('div');
            rightWrap.style.display = 'flex';
            rightWrap.style.alignItems = 'center';
            rightWrap.style.gap = '12px';

            const canvas = document.createElement('canvas');
            canvas.className = 'sparkline-canvas';
            canvas.width = 100;
            canvas.height = 20;
            canvas.id = `sparkline-${type}`;

            const value = document.createElement('div');
            value.className = 'stat-value';
            value.id = `stat-count-${type}`;
            value.textContent = '0';

            rightWrap.appendChild(canvas);
            rightWrap.appendChild(value);
            
            row.appendChild(label);
            row.appendChild(rightWrap);
            container.appendChild(row);
        });
    }

    updateThreatCounts() {
        const counts = {};
        Object.keys(this.threatColors).forEach(t => counts[t] = 0);
        this.alerts.forEach(a => {
            if (counts[a.threat_type] !== undefined) counts[a.threat_type]++;
        });
        
        Object.keys(counts).forEach(type => {
            const el = document.getElementById(`stat-count-${type}`);
            if (el) el.textContent = counts[type];
        });
    }

    updateSparklines() {
        Object.keys(this.sparklineData).forEach(type => {
            const data = this.sparklineData[type];
            // Shift left
            data.shift();
            // Current value is 0 (will be incremented by new alerts)
            data.push(0);

            const canvas = document.getElementById(`sparkline-${type}`);
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            const max = Math.max(...data, 5); // min ceiling of 5
            const stepX = canvas.width / (data.length - 1);
            
            ctx.beginPath();
            ctx.moveTo(0, canvas.height - (data[0]/max * canvas.height));
            
            for (let i = 1; i < data.length; i++) {
                const x = i * stepX;
                const y = canvas.height - (data[i]/max * canvas.height);
                ctx.lineTo(x, y);
            }
            
            ctx.strokeStyle = this.threatColors[type];
            ctx.lineWidth = 1.5;
            ctx.stroke();
        });
    }

    updateSystemStatus(status) {
        if (status.eps !== undefined) {
            document.getElementById('events-per-sec').textContent = status.eps;
        }
    }

    updateChainStatus(status) {
        document.getElementById('chain-length').textContent = status.length || 0;
        if (status.last_hash) {
            document.getElementById('chain-last-hash').textContent = this.truncateHash(status.last_hash);
        }
        
        const ind = document.getElementById('chain-status-indicator');
        const ver = document.getElementById('chain-verify-status');
        
        if (status.valid) {
            ind.className = 'indicator green';
            ver.className = 'value badge success';
            ver.textContent = 'Verified';
        } else {
            ind.className = 'indicator red';
            ver.className = 'value badge danger';
            ver.textContent = 'Broken!';
        }
    }

    // APIs
    async generateAttack(type) {
        const apiType = this.uiToApi[type] || type;
        try {
            await fetch(`/api/generate/${apiType}`, { method: 'POST' });
        } catch (e) {
            console.error('Failed to generate attack', e);
        }
    }

    async runRetroHunt(type, value) {
        const btn = document.getElementById('btn-retro-hunt');
        btn.textContent = 'Hunting...';
        btn.disabled = true;
        try {
            await fetch('/api/retrohunt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type, value })
            });
        } catch (e) {
            console.error('Retro hunt failed', e);
        } finally {
            btn.textContent = 'Hunt';
            btn.disabled = false;
        }
    }

    async submitFeedback(alertId, verdict) {
        try {
            await fetch('/api/feedback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ alert_id: alertId, verdict })
            });
            alert(`Marked ${verdict}`);
        } catch (e) {
            console.error('Feedback failed', e);
        }
    }

    async downloadEvidence(alertId) {
        window.open(`/api/evidence/${alertId}`, '_blank');
    }

    async verifyChain() {
        try {
            const res = await fetch('/api/chain/verify');
            const data = await res.json();
            this.updateChainStatus(data);
        } catch (e) {
            console.error('Chain verify failed', e);
        }
    }

    // Utils
    escapeHtml(unsafe) {
        if (!unsafe) return '';
        return unsafe
            .toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    truncateHash(hash, len=12) {
        if (!hash) return '';
        return hash.substring(0, len) + '...';
    }

    formatTimestamp(ts) {
        // Handle Unix epoch (seconds) or ISO string
        let date;
        if (typeof ts === 'number') {
            // Unix epoch in seconds — convert to ms
            date = new Date(ts < 1e12 ? ts * 1000 : ts);
        } else {
            date = new Date(ts);
        }
        const now = new Date();
        const diffMs = now - date;
        const diffSec = Math.floor(Math.abs(diffMs) / 1000);
        
        if (diffSec < 60) return 'Just now';
        if (diffSec < 3600) return `${Math.floor(diffSec/60)}m ago`;
        if (diffSec < 86400) return `${Math.floor(diffSec/3600)}h ago`;
        return date.toLocaleString();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new EnclaveWatchDashboard();
});
