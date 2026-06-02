/* ===========================================
   AEGIS Dashboard v2 — Frontend Logic
   D3.js Heatmap + Socket.IO + Micro-interactions
   =========================================== */

// ── State ────────────────────────────────────
const state = {
  alerts: [],
  scanners: {},
  honeypotEvents: [],
  selectedScanner: null,
  startTime: Date.now(),
  heatmapData: {},  // { "ip::portRange": count }
};

const PORT_RANGES = ['0-100', '100-500', '500-1K', '1K-5K', '5K-10K', '10K-65K'];
const PORT_RANGE_BOUNDS = [[0,100],[100,500],[500,1000],[1000,5000],[5000,10000],[10000,65535]];

// ── Socket.IO ────────────────────────────────
const socket = io();

socket.on('connect', () => {
  document.getElementById('conn-dot').className = 'status-dot status-dot--active';
  document.getElementById('conn-label').textContent = 'CONNECTED';
});

socket.on('disconnect', () => {
  document.getElementById('conn-dot').className = 'status-dot status-dot--disconnected';
  document.getElementById('conn-label').textContent = 'DISCONNECTED';
});

socket.on('new_alert', (data) => {
  clearSkeletons('alert-feed');
  state.alerts.unshift(data);
  if (state.alerts.length > 50) state.alerts.pop();
  renderAlert(data);
  updateScannerFromAlert(data);
  updateHeatmapFromAlert(data);
  updateStats();
});

socket.on('honeypot_event', (data) => {
  state.honeypotEvents.unshift(data);
  updateStats();
});

socket.on('state_update', (data) => {
  if (data.scanners) {
    state.scanners = data.scanners;
    renderScannersTable();
    rebuildHeatmap();
    updateStats();
  }
});

// ── Clock ────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent =
    now.toLocaleTimeString('en-GB', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ── Uptime ───────────────────────────────────
function updateUptime() {
  const mins = Math.floor((Date.now() - state.startTime) / 60000);
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  document.getElementById('v-uptime').textContent = h > 0 ? `${h}h ${m}m` : `${m}m`;
}
setInterval(updateUptime, 30000);
updateUptime();

// ── Stats ────────────────────────────────────
function updateStats() {
  animateValue('v-alerts', state.alerts.length);
  const scannerKeys = Object.keys(state.scanners);
  const activeCount = scannerKeys.filter(k => !state.scanners[k].blocked).length;
  animateValue('v-threats', activeCount);
  const blockedCount = scannerKeys.filter(k => state.scanners[k].blocked).length;
  animateValue('v-blocked', blockedCount);
  animateValue('v-honeypot', state.honeypotEvents.length);

  if (state.alerts.length > 0) {
    const avg = state.alerts.reduce((s, a) => s + (a.confidence || 0), 0) / state.alerts.length;
    document.getElementById('v-confidence').textContent = (avg * 100).toFixed(0) + '%';
  }

  document.getElementById('scanner-count').textContent = scannerKeys.length;
}

function animateValue(id, newVal) {
  const el = document.getElementById(id);
  const current = parseInt(el.textContent) || 0;
  if (current !== newVal) {
    el.textContent = newVal;
    el.style.transform = 'scale(1.15)';
    setTimeout(() => { el.style.transform = 'scale(1)'; }, 200);
  }
}

// ── Skeleton Clearing ────────────────────────
function clearSkeletons(containerId) {
  const container = document.getElementById(containerId);
  const skeletons = container.querySelectorAll('.skeleton');
  skeletons.forEach(s => s.remove());
}

// ── Alert Rendering ──────────────────────────
function renderAlert(alert) {
  const feed = document.getElementById('alert-feed');

  const severity = getSeverity(alert.confidence);
  const time = new Date(alert.timestamp || Date.now()).toLocaleTimeString('en-GB', { hour12: false });
  const conf = ((alert.confidence || 0) * 100).toFixed(0);
  const confColor = severity === 'critical' ? 'var(--red)' :
                    severity === 'high' ? 'var(--amber)' :
                    severity === 'medium' ? 'var(--blue)' : 'var(--green)';

  const div = document.createElement('div');
  div.className = `alert-item alert-item--${severity}`;
  div.innerHTML = `
    <div>
      <div class="alert-item__ip">${escapeHtml(alert.src_ip || 'Unknown')}</div>
      <div class="alert-item__meta">
        ${time} · ${escapeHtml(alert.scan_type || 'scan')}
        ${alert.honeypot_flag ? ' · <span class="badge badge--honeypot">Honeypot</span>' : ''}
      </div>
    </div>
    <div class="alert-item__right">
      <div class="alert-item__confidence" style="color:${confColor}">${conf}%</div>
      <div class="confidence-bar">
        <div class="confidence-bar__fill" style="width:${conf}%;background:${confColor}"></div>
      </div>
    </div>
  `;
  feed.prepend(div);

  // Keep max 50 DOM elements
  while (feed.children.length > 50) feed.lastChild.remove();
}

function getSeverity(confidence) {
  if (confidence >= 0.9) return 'critical';
  if (confidence >= 0.7) return 'high';
  if (confidence >= 0.4) return 'medium';
  return 'low';
}

// ── Scanner Table ────────────────────────────
function updateScannerFromAlert(alert) {
  const ip = alert.src_ip;
  if (!ip) return;
  if (!state.scanners[ip]) {
    state.scanners[ip] = {
      scan_type: alert.scan_type || 'Unknown',
      confidence: alert.confidence || 0,
      alert_count: 0,
      honeypot: alert.honeypot_flag || false,
      blocked: false,
      first_seen: alert.timestamp || new Date().toISOString(),
      last_seen: alert.timestamp || new Date().toISOString(),
      ports_probed: [],
      events: []
    };
  }
  const s = state.scanners[ip];
  s.alert_count = (s.alert_count || 0) + 1;
  s.confidence = Math.max(s.confidence, alert.confidence || 0);
  s.last_seen = alert.timestamp || new Date().toISOString();
  if (alert.honeypot_flag) s.honeypot = true;
  if (alert.dst_port && !s.ports_probed.includes(alert.dst_port)) {
    s.ports_probed.push(alert.dst_port);
  }
  s.events.push({
    time: alert.timestamp || new Date().toISOString(),
    type: 'alert',
    detail: `${alert.scan_type} detected (${((alert.confidence||0)*100).toFixed(0)}%)`
  });

  renderScannersTable();
}

function renderScannersTable() {
  const tbody = document.getElementById('scanner-tbody');
  tbody.innerHTML = '';

  const entries = Object.entries(state.scanners).sort((a, b) => b[1].confidence - a[1].confidence);

  entries.forEach(([ip, s]) => {
    const conf = ((s.confidence || 0) * 100).toFixed(0);
    const severity = getSeverity(s.confidence);
    const confColor = severity === 'critical' ? 'var(--red)' :
                      severity === 'high' ? 'var(--amber)' :
                      severity === 'medium' ? 'var(--blue)' : 'var(--green)';

    const tr = document.createElement('tr');
    if (state.selectedScanner === ip) tr.classList.add('selected');
    tr.innerHTML = `
      <td style="color:var(--cyan)">${escapeHtml(ip)}</td>
      <td><span class="badge badge--scan">${escapeHtml(s.scan_type || '—')}</span></td>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          <div class="confidence-bar" style="width:50px">
            <div class="confidence-bar__fill" style="width:${conf}%;background:${confColor}"></div>
          </div>
          <span style="color:${confColor};font-size:10px">${conf}%</span>
        </div>
      </td>
      <td>${s.alert_count || 0}</td>
      <td>${s.honeypot ? '<span class="badge badge--honeypot">HP</span>' : '—'}</td>
      <td>
        ${s.blocked
          ? '<span class="badge badge--blocked">Blocked</span>'
          : `<button class="btn btn--block" onclick="blockScanner('${escapeHtml(ip)}',event)" aria-label="Block ${escapeHtml(ip)}">Block</button>`
        }
      </td>
    `;
    tr.addEventListener('click', (e) => {
      if (e.target.tagName === 'BUTTON') return;
      selectScanner(ip);
    });
    tbody.appendChild(tr);
  });
}

function blockScanner(ip, event) {
  event.stopPropagation();
  socket.emit('block_ip', { ip: ip });
  if (state.scanners[ip]) {
    state.scanners[ip].blocked = true;
    state.scanners[ip].events.push({
      time: new Date().toISOString(),
      type: 'block',
      detail: 'IP blocked by operator'
    });
  }
  renderScannersTable();
  updateStats();
  if (state.selectedScanner === ip) renderProfile(ip);
}

// ── Threat Intelligence Profile ──────────────
function selectScanner(ip) {
  state.selectedScanner = ip;
  renderScannersTable();
  renderProfile(ip);
}

function renderProfile(ip) {
  const s = state.scanners[ip];
  if (!s) return;

  document.getElementById('profile-empty').style.display = 'none';
  const container = document.getElementById('profile-content');
  container.style.display = 'block';

  const severity = getSeverity(s.confidence);
  const conf = ((s.confidence || 0) * 100).toFixed(0);
  const statusBadge = s.blocked
    ? '<span class="badge badge--blocked">BLOCKED</span>'
    : '<span class="badge badge--critical">ACTIVE</span>';

  let portsStr = (s.ports_probed || []).slice(0, 10).join(', ');
  if ((s.ports_probed || []).length > 10) portsStr += ` (+${s.ports_probed.length - 10} more)`;

  let timelineHtml = '';
  const events = (s.events || []).slice(-8).reverse();
  events.forEach(evt => {
    const t = new Date(evt.time).toLocaleTimeString('en-GB', { hour12: false });
    const cls = evt.type === 'block' ? 'timeline__item--danger' :
                evt.type === 'honeypot' ? 'timeline__item--warning' : '';
    timelineHtml += `
      <div class="timeline__item ${cls}">
        <span class="timeline__time">${t}</span>
        <span class="timeline__text">${escapeHtml(evt.detail)}</span>
      </div>`;
  });

  container.innerHTML = `
    <div class="profile__header">
      <div class="profile__avatar">
        <svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
      </div>
      <div>
        <div class="profile__name">${escapeHtml(ip)}</div>
        <div class="profile__subtitle">${escapeHtml(s.scan_type || 'Unknown Scan Type')} ${statusBadge}</div>
      </div>
    </div>
    <div class="profile__grid">
      <div class="profile__field">
        <div class="profile__field-label">Confidence</div>
        <div class="profile__field-value" style="color:${severity==='critical'?'var(--red)':severity==='high'?'var(--amber)':'var(--cyan)'}">${conf}%</div>
      </div>
      <div class="profile__field">
        <div class="profile__field-label">Alert Count</div>
        <div class="profile__field-value">${s.alert_count || 0}</div>
      </div>
      <div class="profile__field">
        <div class="profile__field-label">First Seen</div>
        <div class="profile__field-value">${s.first_seen ? new Date(s.first_seen).toLocaleTimeString('en-GB') : '—'}</div>
      </div>
      <div class="profile__field">
        <div class="profile__field-label">Last Seen</div>
        <div class="profile__field-value">${s.last_seen ? new Date(s.last_seen).toLocaleTimeString('en-GB') : '—'}</div>
      </div>
      <div class="profile__field" style="grid-column:span 2">
        <div class="profile__field-label">Ports Probed</div>
        <div class="profile__field-value">${portsStr || '—'}</div>
      </div>
    </div>
    ${s.honeypot ? `<div style="margin-bottom:12px"><span class="badge badge--honeypot">Honeypot Interaction Detected</span></div>` : ''}
    <div style="font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:var(--text-muted);margin-bottom:8px">Activity Timeline</div>
    <div class="timeline">${timelineHtml || '<div class="empty-state" style="height:60px"><span>No events yet</span></div>'}</div>
  `;
}

// ── Heatmap (D3.js) ──────────────────────────
function updateHeatmapFromAlert(alert) {
  if (!alert.src_ip || !alert.dst_port) return;
  const port = parseInt(alert.dst_port);
  const range = getPortRange(port);
  const key = `${alert.src_ip}::${range}`;
  state.heatmapData[key] = (state.heatmapData[key] || 0) + 1;
  drawHeatmap();
}

function getPortRange(port) {
  for (let i = 0; i < PORT_RANGE_BOUNDS.length; i++) {
    if (port >= PORT_RANGE_BOUNDS[i][0] && port < PORT_RANGE_BOUNDS[i][1]) return PORT_RANGES[i];
  }
  return PORT_RANGES[5];
}

function rebuildHeatmap() {
  state.heatmapData = {};
  Object.entries(state.scanners).forEach(([ip, s]) => {
    (s.ports_probed || []).forEach(p => {
      const range = getPortRange(parseInt(p));
      const key = `${ip}::${range}`;
      state.heatmapData[key] = (state.heatmapData[key] || 0) + 1;
    });
  });
  drawHeatmap();
}

function drawHeatmap() {
  const container = document.getElementById('heatmap-container');
  const rect = container.getBoundingClientRect();
  const width = rect.width || 400;
  const height = rect.height || 250;
  const margin = { top: 24, right: 10, bottom: 30, left: 100 };
  const innerW = width - margin.left - margin.right;
  const innerH = height - margin.top - margin.bottom;

  // Get unique IPs
  const ips = [...new Set(Object.keys(state.heatmapData).map(k => k.split('::')[0]))];
  if (ips.length === 0) {
    container.innerHTML = '<div class="empty-state" style="height:100%"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg><span>Heatmap populates with scan data</span></div>';
    return;
  }

  // Clear and rebuild SVG
  d3.select('#heatmap-container').selectAll('*').remove();
  const svg = d3.select('#heatmap-container')
    .append('svg')
    .attr('width', width)
    .attr('height', height)
    .attr('role', 'img')
    .attr('aria-label', 'Port scan heatmap showing probe intensity by source IP and port range');

  const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

  // Scales
  const xScale = d3.scaleBand().domain(PORT_RANGES).range([0, innerW]).padding(0.06);
  const yScale = d3.scaleBand().domain(ips).range([0, innerH]).padding(0.06);

  const maxVal = d3.max(Object.values(state.heatmapData)) || 1;
  const colorScale = d3.scaleSequential()
    .domain([0, maxVal])
    .interpolator(t => d3.interpolateRgb('#0f1730', '#00e5ff')(t));

  // Axes
  g.append('g')
    .attr('transform', `translate(0,${innerH})`)
    .call(d3.axisBottom(xScale).tickSize(0))
    .selectAll('text')
    .style('fill', '#4d5f82').style('font-size', '9px').style('font-family', 'Fira Code');

  g.append('g')
    .call(d3.axisLeft(yScale).tickSize(0))
    .selectAll('text')
    .style('fill', '#00e5ff').style('font-size', '10px').style('font-family', 'Fira Code');

  // Remove axis lines
  g.selectAll('.domain').remove();

  // Tooltip reference
  const tooltip = d3.select('#heatmap-tooltip');

  // Build data array
  const cells = [];
  ips.forEach(ip => {
    PORT_RANGES.forEach(pr => {
      const key = `${ip}::${pr}`;
      cells.push({ ip, range: pr, value: state.heatmapData[key] || 0 });
    });
  });

  // Draw cells
  g.selectAll('rect.cell')
    .data(cells)
    .join('rect')
    .attr('class', 'cell')
    .attr('x', d => xScale(d.range))
    .attr('y', d => yScale(d.ip))
    .attr('width', xScale.bandwidth())
    .attr('height', yScale.bandwidth())
    .attr('rx', 2)
    .attr('fill', d => d.value > 0 ? colorScale(d.value) : '#0a0e1a')
    .attr('stroke', d => d.value > 0 ? 'rgba(0,229,255,.15)' : 'none')
    .attr('stroke-width', 0.5)
    .style('cursor', d => d.value > 0 ? 'pointer' : 'default')
    .on('mouseover', function (event, d) {
      if (d.value === 0) return;
      d3.select(this).attr('stroke', '#00e5ff').attr('stroke-width', 1.5);
      tooltip
        .style('visibility', 'visible')
        .html(`<strong>${d.ip}</strong><br>Ports: ${d.range}<br>Probes: ${d.value}`);
    })
    .on('mousemove', function (event) {
      tooltip
        .style('top', (event.pageY - 40) + 'px')
        .style('left', (event.pageX + 12) + 'px');
    })
    .on('mouseout', function (event, d) {
      d3.select(this)
        .attr('stroke', d.value > 0 ? 'rgba(0,229,255,.15)' : 'none')
        .attr('stroke-width', 0.5);
      tooltip.style('visibility', 'hidden');
    })
    .on('click', function (event, d) {
      if (d.value > 0) selectScanner(d.ip);
    });
}

// Redraw on resize
const resizeObserver = new ResizeObserver(() => { drawHeatmap(); });
window.addEventListener('DOMContentLoaded', () => {
  const hc = document.getElementById('heatmap-container');
  if (hc) resizeObserver.observe(hc);
  drawHeatmap();
});

// ── Utility ──────────────────────────────────
function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
