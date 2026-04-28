// ============================================
// AEGIS Dashboard — Real-time Frontend Logic
// Socket.IO + DOM updates
// ============================================

const socket = io();

// ── Clock ─────────────────────────────────────
function updateClock() {
    const now = new Date();
    const el = document.getElementById('clock');
    if (el) {
        el.textContent = now.toLocaleTimeString('en-GB', { hour12: false });
    }
}
setInterval(updateClock, 1000);
updateClock();

// ── Load initial state ────────────────────────
fetch('/api/state')
    .then(r => r.json())
    .then(data => {
        updateStats(data.stats);
        updateScannerTable(data.active_scanners);
        data.alerts.forEach(alert => addAlertToFeed(alert, false));
        data.honeypot_events.forEach(evt => addHoneypotEvent(evt, false));
    });

// ── Socket.IO listeners ──────────────────────

socket.on('new_alert', (alert) => {
    addAlertToFeed(alert, true);
});

socket.on('state_update', (data) => {
    updateStats(data.stats);
    updateScannerTable(data.active_scanners);
});

socket.on('honeypot_event', (event) => {
    addHoneypotEvent(event, true);
});

socket.on('ip_blocked', (data) => {
    // Update button state in scanner table
    const btn = document.querySelector(`[data-block-ip="${data.ip}"]`);
    if (btn) {
        btn.textContent = 'BLOCKED';
        btn.disabled = true;
        btn.classList.add('btn--blocked-active');
    }
});

// ── Update Functions ─────────────────────────

function updateStats(stats) {
    animateValue('stat-alerts', stats.total_alerts);
    animateValue('stat-threats', stats.active_threats);
    animateValue('stat-blocked', stats.blocked_count);
    animateValue('stat-honeypot', stats.honeypot_hits);
}

function animateValue(elementId, newValue) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const current = parseInt(el.textContent) || 0;
    if (current !== newValue) {
        el.textContent = newValue;
        el.style.transform = 'scale(1.2)';
        el.style.transition = 'transform 0.3s';
        setTimeout(() => { el.style.transform = 'scale(1)'; }, 300);
    }
}

function addAlertToFeed(alert, animate) {
    const feed = document.getElementById('alert-feed');

    // Remove empty state
    const empty = feed.querySelector('.empty-state');
    if (empty) empty.remove();

    const div = document.createElement('div');
    div.className = `alert-item alert-item--${alert.severity.toLowerCase()}`;
    if (!animate) div.style.animation = 'none';

    const honeypotBadge = alert.honeypot_flag
        ? '<span class="badge badge--honeypot">🍯 HONEYPOT</span>'
        : '';

    div.innerHTML = `
        <div style="flex:1">
            <div style="display:flex;align-items:center;gap:8px">
                <span class="alert-item__ip">${alert.src_ip}</span>
                <span class="badge badge--${alert.severity.toLowerCase()}">${alert.severity}</span>
                ${honeypotBadge}
            </div>
            <div class="alert-item__meta">
                ${alert.scan_type} scan &middot; ${formatTime(alert.timestamp)}
            </div>
        </div>
        <div class="alert-item__confidence" style="color: ${getConfidenceColor(alert.confidence)}">
            ${(alert.confidence * 100).toFixed(1)}%
        </div>
    `;

    feed.insertBefore(div, feed.firstChild);

    // Keep max 50 items
    while (feed.children.length > 50) {
        feed.removeChild(feed.lastChild);
    }
}

function updateScannerTable(scanners) {
    const tbody = document.getElementById('scanner-tbody');
    const entries = Object.entries(scanners);

    if (entries.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No active scanners</td></tr>';
        return;
    }

    tbody.innerHTML = entries.map(([ip, info]) => `
        <tr>
            <td style="color: var(--accent-cyan); font-weight: 600;">${ip}</td>
            <td>${info.scan_type}</td>
            <td style="color: ${getConfidenceColor(info.confidence)}">${(info.confidence * 100).toFixed(1)}%</td>
            <td>${info.alert_count}</td>
            <td>${info.honeypot_hit
                ? '<span class="badge badge--honeypot">🍯 YES</span>'
                : '<span style="color:var(--text-muted)">—</span>'
            }</td>
            <td>
                <button class="btn btn--block" data-block-ip="${ip}"
                    onclick="blockIP('${ip}')">BLOCK</button>
            </td>
        </tr>
    `).join('');
}

function addHoneypotEvent(event, animate) {
    const feed = document.getElementById('honeypot-feed');

    const empty = feed.querySelector('.empty-state');
    if (empty) empty.remove();

    const div = document.createElement('div');
    div.className = 'honeypot-item';
    if (!animate) div.style.animation = 'none';

    const cmds = event.commands && event.commands.length > 0
        ? event.commands.slice(0, 3).map(c => `<code>${c}</code>`).join(', ')
        : 'connection only';

    const creds = event.credentials && event.credentials.length > 0
        ? event.credentials.slice(0, 2).join(', ')
        : '';

    div.innerHTML = `
        <div class="honeypot-item__header">
            <span class="honeypot-item__ip">${event.src_ip}</span>
            <span class="honeypot-item__service">${event.service}</span>
        </div>
        <div class="honeypot-item__detail">
            Commands: ${cmds}
            ${creds ? '<br>Credentials: ' + creds : ''}
        </div>
    `;

    feed.insertBefore(div, feed.firstChild);

    while (feed.children.length > 30) {
        feed.removeChild(feed.lastChild);
    }
}

// ── Actions ──────────────────────────────────

function blockIP(ip) {
    fetch('/api/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    });
}

// ── Helpers ──────────────────────────────────

function getConfidenceColor(conf) {
    if (conf >= 0.90) return 'var(--accent-red)';
    if (conf >= 0.75) return 'var(--accent-orange)';
    if (conf >= 0.60) return 'var(--accent-blue)';
    return 'var(--accent-green)';
}

function formatTime(iso) {
    try {
        const d = new Date(iso);
        return d.toLocaleTimeString('en-GB', { hour12: false });
    } catch {
        return iso;
    }
}
