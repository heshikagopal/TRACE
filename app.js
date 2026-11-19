/**
 * CONTRACT WATCH — Harbor & Finch Freight Defense System
 * Lead Frontend & Detection Engine Client Architecture
 */

(function () {
  'use strict';

  // Global State
  const state = {
    events: null,
    contracts: null,
    metrics: null,
    activeView: 'timeline', // 'timeline' | 'graph'
    isPlaying: false,
    speed: 1,
    progress: 1.0, // Start at 100% to display full reconstructed chain
    playbackTimer: null,
    selectedEvent: null,
    selectedContract: null,
    theme: localStorage.getItem('cw_theme') || 'dark',
    graph: {
      zoom: 1.0,
      showLayers: true
    },
    gate: {
      step: 1, // 0: 3 Sep, 1: 5 Sep (Locked), 2: 8 Sep (Cutoff)
      checks: { check1: true, check2: false, check3: false },
      isRolledBack: false
    },
    mutator: {
      sourceIp: '10.20.4.77',
      clientVer: '3.4.1',
      apiKey: 'key-tb-07',
      timeWindow: '12:10',
      targetField: 'bank_account',
      approvalRef: 'null'
    }
  };

  // Timeline Boundaries: 2026-08-01 to 2026-09-08
  const T_START = new Date('2026-08-01T00:00:00Z').getTime();
  const T_END = new Date('2026-09-08T12:00:00Z').getTime();
  const T_TOTAL_SPAN = T_END - T_START;

  function formatUtcDate(dateObj) {
    if (!dateObj) return 'N/A';
    const d = new Date(dateObj);
    return d.toUTCString().replace('GMT', 'UTC');
  }

  function getProgressForTime(isoStr) {
    const t = new Date(isoStr).getTime();
    return Math.max(0, Math.min(1, (t - T_START) / T_TOTAL_SPAN));
  }

  function getTimeForProgress(p) {
    return new Date(T_START + p * T_TOTAL_SPAN);
  }

  // --- INITIALIZATION ---
  async function init() {
    applyTheme(state.theme);
    setupEventListeners();

    try {
      const [eventsRes, contractsRes, metricsRes] = await Promise.all([
        fetch('events.json').then(r => r.json()),
        fetch('contracts.json').then(r => r.json()),
        fetch('metrics.json').then(r => r.json())
      ]);

      state.events = eventsRes;
      state.contracts = contractsRes.contracts;
      state.metrics = metricsRes;

      renderBoard();
      renderGraph();
      renderMetrics();
      evaluateMutator();
      updateGateDisplay();
      updateRadarBlip();
      setupWaveChartInteraction();
    } catch (err) {
      console.error('Failed to load local JSON evidence:', err);
    }
  }

  // --- THEME MANAGEMENT ---
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    state.theme = theme;
    localStorage.setItem('cw_theme', theme);
    const themeBtn = document.getElementById('btn-theme-toggle');
    if (themeBtn) {
      themeBtn.innerHTML = theme === 'dark' ? '☀️ Light' : '🌙 Dark';
    }
  }

  function toggleTheme() {
    applyTheme(state.theme === 'dark' ? 'light' : 'dark');
  }

  // --- RENDERING: SHIPPING LANES & CORRIDORS ---
  function renderBoard() {
    if (!state.events) return;

    const lanesContainer = document.getElementById('lanes-container');
    if (!lanesContainer) return;
    lanesContainer.innerHTML = '';

    const currentTimestamp = getTimeForProgress(state.progress);
    const timeDisplay = document.getElementById('replay-timestamp-val');
    if (timeDisplay) {
      timeDisplay.textContent = formatUtcDate(currentTimestamp);
    }

    state.events.lanes.forEach(lane => {
      const laneEl = document.createElement('div');
      laneEl.className = 'shipping-lane';
      laneEl.dataset.laneId = lane.id;

      // Header card (clickable for contract inspector)
      const headerEl = document.createElement('div');
      headerEl.className = 'lane-header-card';
      headerEl.title = 'Click to inspect behavioral contract';
      headerEl.innerHTML = `
        <div class="lane-credential-id">
          <span>${lane.credential}</span>
          <span style="font-size:0.9rem;">📜</span>
        </div>
        <div class="lane-name">${lane.name}</div>
        <div class="lane-target-system">${lane.target_system}</div>
        <div class="lane-inspect-hint"><span>🔍 Inspect Contract</span></div>
      `;
      headerEl.addEventListener('click', () => openContractInspector(lane.credential));

      // Contract corridor
      const corridorEl = document.createElement('div');
      corridorEl.className = 'contract-corridor';
      corridorEl.innerHTML = `
        <span class="corridor-boundary-label">CONTRACT CORRIDOR: ALLOWED ENVELOPE</span>
      `;

      // Baseline sampled calm dots
      const sampleCount = 14;
      for (let i = 0; i < sampleCount; i++) {
        const dot = document.createElement('div');
        dot.className = 'baseline-dot';
        const pctX = 4 + (i / (sampleCount - 1)) * 92;
        const pctY = 50 + Math.sin(i * 1.5) * 18;
        dot.style.left = `${pctX}%`;
        dot.style.top = `${pctY}%`;
        dot.title = `Sampled baseline traffic (synthetic corridor) for ${lane.credential}`;
        corridorEl.appendChild(dot);
      }

      // Render Breaches in this lane
      const laneBreaches = state.events.breaches.filter(b => b.lane_id === lane.id);
      laneBreaches.forEach(breach => {
        const breachProgress = getProgressForTime(breach.timestamp_utc);
        if (breachProgress <= state.progress) {
          const marker = document.createElement('div');
          marker.className = 'event-marker';
          marker.dataset.eventId = breach.id;
          marker.style.left = `${breachProgress * 94 + 3}%`;
          marker.style.top = '50%';

          marker.innerHTML = `
            <div class="marker-beacon breach">
              <span>!</span>
              <div class="sonar-ripple"></div>
            </div>
            <div class="marker-label-tag">${breach.id} · ${breach.source_ip}</div>
          `;
          marker.addEventListener('click', (e) => {
            e.stopPropagation();
            openEvidenceDrilldown(breach);
          });
          corridorEl.appendChild(marker);
        }
      });

      // Render Set-Aside Events in this lane
      const laneSetAsides = state.events.set_aside_ordinary.filter(s => s.lane_id === lane.id);
      laneSetAsides.forEach(sa => {
        const saProgress = getProgressForTime(sa.timestamp_utc);
        if (saProgress <= state.progress) {
          const marker = document.createElement('div');
          marker.className = 'event-marker';
          marker.dataset.eventId = sa.id;
          marker.style.left = `${saProgress * 94 + 3}%`;
          marker.style.top = '50%';

          marker.innerHTML = `
            <div class="marker-beacon setaside" title="Set aside as ordinary">
              <span>✓</span>
            </div>
            <div class="marker-label-tag" style="color:var(--status-setaside);">${sa.id} (Ordinary)</div>
          `;
          marker.addEventListener('click', (e) => {
            e.stopPropagation();
            openEvidenceDrilldown(sa, true);
          });
          corridorEl.appendChild(marker);
        }
      });

      laneEl.appendChild(headerEl);
      laneEl.appendChild(corridorEl);
      lanesContainer.appendChild(laneEl);
    });

    renderCausalChain();
  }

  // --- SVG CAUSAL CHAIN RENDERING ---
  function renderCausalChain() {
    const svgEl = document.getElementById('causal-chain-svg');
    if (!svgEl || !state.events) return;
    svgEl.innerHTML = '';

    // Collect positions of visible breach markers
    const visibleBreaches = state.events.breaches
      .filter(b => getProgressForTime(b.timestamp_utc) <= state.progress)
      .sort((a, b) => new Date(a.timestamp_utc) - new Date(b.timestamp_utc));

    if (visibleBreaches.length < 2) return;

    const boardRect = document.getElementById('shipping-lanes-board').getBoundingClientRect();
    const points = [];

    visibleBreaches.forEach(b => {
      const markerEl = document.querySelector(`.event-marker[data-event-id="${b.id}"]`);
      if (markerEl) {
        const rect = markerEl.getBoundingClientRect();
        const x = rect.left + rect.width / 2 - boardRect.left;
        const y = rect.top + rect.height / 2 - boardRect.top;
        points.push({ x, y, id: b.id });
      }
    });

    if (points.length < 2) return;

    let d = `M ${points[0].x} ${points[0].y}`;
    for (let i = 1; i < points.length; i++) {
      const prev = points[i - 1];
      const curr = points[i];
      const cx1 = prev.x + (curr.x - prev.x) * 0.5;
      const cy1 = prev.y;
      const cx2 = prev.x + (curr.x - prev.x) * 0.5;
      const cy2 = curr.y;
      d += ` C ${cx1} ${cy1}, ${cx2} ${cy2}, ${curr.x} ${curr.y}`;
    }

    const pathEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    pathEl.setAttribute('d', d);
    pathEl.setAttribute('class', 'causal-chain-path');
    svgEl.appendChild(pathEl);
  }

  // --- TACTICAL BREACH GRAPH VIEW (IMAGE 3 ENHANCEMENT) ---
  function renderGraph() {
    const graphSvg = document.getElementById('graph-canvas-svg');
    if (!graphSvg || !state.events) return;
    graphSvg.innerHTML = '';

    const width = 1000;
    const height = 500;
    graphSvg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
    graphSvg.setAttribute('preserveAspectRatio', 'xMidYMid meet');

    // Create defs with glow filters and gradients
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    defs.innerHTML = `
      <filter id="tgGlowCyan" x="-30%" y="-30%" width="160%" height="160%">
        <feGaussianBlur stdDeviation="5" result="blur" />
        <feComposite in="SourceGraphic" in2="blur" operator="over" />
      </filter>
      <filter id="tgGlowRed" x="-30%" y="-30%" width="160%" height="160%">
        <feGaussianBlur stdDeviation="6" result="blur" />
        <feComposite in="SourceGraphic" in2="blur" operator="over" />
      </filter>
      <filter id="tgGlowAmber" x="-30%" y="-30%" width="160%" height="160%">
        <feGaussianBlur stdDeviation="5" result="blur" />
        <feComposite in="SourceGraphic" in2="blur" operator="over" />
      </filter>
      <linearGradient id="tgCyanSpineGrad" x1="0%" y1="100%" x2="0%" y2="0%">
        <stop offset="0%" stop-color="#22C55E" stop-opacity="0.9" />
        <stop offset="60%" stop-color="#22C55E" stop-opacity="0.9" />
        <stop offset="100%" stop-color="#22C55E" stop-opacity="0.9" />
      </linearGradient>
    `;
    graphSvg.appendChild(defs);

    // Root viewport group for zoom & pan
    const zoom = state.graph ? state.graph.zoom : 1.0;
    const gViewport = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    gViewport.setAttribute('id', 'graph-viewport');
    gViewport.setAttribute('transform', 'translate(' + ((width * (1 - zoom)) / 2) + ', ' + ((height * (1 - zoom)) / 2) + ') scale(' + zoom + ')');
    graphSvg.appendChild(gViewport);

    // Background Constellation Nodes & Mesh Lines (matching Image 3 starry mesh)
    const bgMeshGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    bgMeshGroup.setAttribute('opacity', state.graph && state.graph.showLayers ? '0.35' : '0.1');

    const meshPoints = [
      { x: 140, y: 380 }, { x: 220, y: 440 }, { x: 340, y: 400 },
      { x: 180, y: 280 }, { x: 300, y: 320 }, { x: 420, y: 350 },
      { x: 260, y: 160 }, { x: 380, y: 220 }, { x: 460, y: 270 },
      { x: 580, y: 380 }, { x: 670, y: 410 }, { x: 780, y: 360 },
      { x: 630, y: 280 }, { x: 740, y: 300 }, { x: 860, y: 320 },
      { x: 690, y: 160 }, { x: 800, y: 140 }, { x: 890, y: 200 }
    ];

    // Constellation lines
    for (let i = 0; i < meshPoints.length - 1; i++) {
      const p1 = meshPoints[i];
      const p2 = meshPoints[i + 1];
      const dist = Math.hypot(p2.x - p1.x, p2.y - p1.y);
      if (dist < 160) {
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', p1.x);
        line.setAttribute('y1', p1.y);
        line.setAttribute('x2', p2.x);
        line.setAttribute('y2', p2.y);
        line.setAttribute('stroke', '#334155');
        line.setAttribute('stroke-width', '1');
        line.setAttribute('stroke-dasharray', '2 3');
        bgMeshGroup.appendChild(line);
      }
    }

    // Constellation faint dots
    meshPoints.forEach(p => {
      const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      c.setAttribute('cx', p.x);
      c.setAttribute('cy', p.y);
      c.setAttribute('r', '2.5');
      c.setAttribute('fill', '#475569');
      bgMeshGroup.appendChild(c);
    });
    gViewport.appendChild(bgMeshGroup);

    // Primary Tactical Lateral Spine Path (Image 3 glowing cyan pathway)
    const spineD = 'M 510 420 L 510 330 C 510 290, 550 280, 550 240 C 550 190, 470 180, 470 140 C 470 100, 510 80, 520 75';
    
    // Spine Aura Glow
    const spineAura = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    spineAura.setAttribute('d', spineD);
    spineAura.setAttribute('fill', 'none');
    spineAura.setAttribute('stroke', '#22C55E');
    spineAura.setAttribute('stroke-width', '8');
    spineAura.setAttribute('opacity', '0.35');
    spineAura.setAttribute('filter', 'url(#tgGlowCyan)');
    gViewport.appendChild(spineAura);

    // Spine Core Line
    const spineCore = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    spineCore.setAttribute('d', spineD);
    spineCore.setAttribute('fill', 'none');
    spineCore.setAttribute('stroke', 'url(#tgCyanSpineGrad)');
    spineCore.setAttribute('stroke-width', '3.5');
    spineCore.setAttribute('filter', 'url(#tgGlowCyan)');
    gViewport.appendChild(spineCore);

    // Flowing Energy Pulse on Spine
    const spinePulse = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    spinePulse.setAttribute('d', spineD);
    spinePulse.setAttribute('fill', 'none');
    spinePulse.setAttribute('stroke', '#FFFFFF');
    spinePulse.setAttribute('stroke-width', '2');
    spinePulse.setAttribute('stroke-dasharray', '8 16');
    spinePulse.setAttribute('opacity', '0.75');
    gViewport.appendChild(spinePulse);

    // Red dashed branch to Command Server (185.220.101.8)
    const cmdBranch = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    cmdBranch.setAttribute('x1', '520');
    cmdBranch.setAttribute('y1', '75');
    cmdBranch.setAttribute('x2', '650');
    cmdBranch.setAttribute('y2', '55');
    cmdBranch.setAttribute('stroke', '#22C55E');
    cmdBranch.setAttribute('stroke-width', '2');
    cmdBranch.setAttribute('stroke-dasharray', '4 4');
    gViewport.appendChild(cmdBranch);

    // Orange dashed branch to Exfiltration (High Severity)
    const exfilBranch = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    exfilBranch.setAttribute('d', 'M 550 240 C 640 220, 720 180, 810 190');
    exfilBranch.setAttribute('fill', 'none');
    exfilBranch.setAttribute('stroke', '#F59E0B');
    exfilBranch.setAttribute('stroke-width', '2');
    exfilBranch.setAttribute('stroke-dasharray', '4 4');
    gViewport.appendChild(exfilBranch);

    // Coordinates for Case Breaches & Strategic Tactical Nodes
    const tacticalNodes = [
      { id: 'BR-01', x: 200, y: 220, label: 'Finance-Laptop-17', ip: '198.18.7.41', role: 'Initial Recon', type: 'host' },
      { id: 'BR-02', x: 320, y: 280, label: 'Support Sync Node', ip: 'tb-sync-svc', role: 'Bulk Export', type: 'host' },
      { id: 'BR-03', x: 400, y: 210, label: 'Ticket Vault', ip: 'bvk-7f3a', role: 'Credential Leak', type: 'host' },
      { id: 'BR-04', x: 380, y: 350, label: 'BlueVault Storage', ip: '10.20.4.12', role: 'S3 Extraction', type: 'host' },
      { id: 'BR-05', x: 470, y: 140, label: 'tb-build-02 Pivot', ip: '10.20.4.77', role: 'Build Host Pivot', type: 'spine' },
      { id: 'BR-06', x: 535, y: 190, label: 'DC-East-01 Ingress', ip: '10.0.0.5', role: 'Off-Hours Recon', type: 'spine' },
      { id: 'BR-07', x: 550, y: 240, label: 'LedgerOne Core', ip: '10.20.4.77', role: 'Account Tamper', type: 'spine' },
      { id: 'BR-08', x: 810, y: 190, label: 'Exfiltration Point', ip: '****9083', role: 'Disbursement Gate', type: 'exfil' }
    ];

    // Spine Waypoint Nodes (Image 3 cyan glowing circles along spine)
    const waypoints = [
      { x: 510, y: 375, r: 6 },
      { x: 510, y: 330, r: 7 },
      { x: 535, y: 285, r: 6 },
      { x: 550, y: 240, r: 9 },
      { x: 530, y: 185, r: 7 },
      { x: 470, y: 140, r: 9 },
      { x: 455, y: 100, r: 7 },
      { x: 520, y: 75, r: 8 }
    ];

    waypoints.forEach(wp => {
      const circ = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circ.setAttribute('cx', wp.x);
      circ.setAttribute('cy', wp.y);
      circ.setAttribute('r', wp.r);
      circ.setAttribute('fill', '#22C55E');
      circ.setAttribute('filter', 'url(#tgGlowCyan)');
      gViewport.appendChild(circ);
    });

    // 1. Protected Endpoint (Bottom node with Double Ring & Halo, Image 3)
    const peGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    peGroup.setAttribute('class', 'graph-node');
    peGroup.style.cursor = 'pointer';
    peGroup.innerHTML = `
      <!-- Outer cyan halo -->
      <circle cx="510" cy="420" r="28" fill="rgba(34, 197, 94, 0.12)" stroke="#22C55E" stroke-width="2" filter="url(#tgGlowCyan)">
        <animate attributeName="r" values="26;30;26" dur="3s" repeatCount="indefinite" />
      </circle>
      <!-- Inner core circle -->
      <circle cx="510" cy="420" r="18" fill="#060F08" stroke="#22C55E" stroke-width="2" />
      <!-- Shield / Check icon -->
      <text x="510" y="425" fill="#22C55E" font-size="13" font-weight="700" text-anchor="middle">🛡️</text>
      <!-- Label -->
      <text x="548" y="418" fill="#FFFFFF" font-size="12px" font-weight="700" font-family="'Inter', sans-serif">Protected Endpoint</text>
      <text x="548" y="433" fill="#22C55E" font-size="10px" font-family="'JetBrains Mono', monospace">10.0.3.25 (ERP Gateway)</text>
    `;
    peGroup.addEventListener('click', () => {
      if (state.events && state.events.breaches && state.events.breaches[7]) {
        openEvidenceDrilldown(state.events.breaches[7]);
      }
    });
    gViewport.appendChild(peGroup);

    // 2. Command Server (Top Right node with Red Skull, Image 3)
    const csGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    csGroup.setAttribute('class', 'graph-node');
    csGroup.style.cursor = 'pointer';
    csGroup.innerHTML = `
      <!-- Red glowing aura -->
      <circle cx="650" cy="55" r="22" fill="#06140A" stroke="#22C55E" stroke-width="2.5" filter="url(#tgGlowRed)">
        <animate attributeName="r" values="20;25;20" dur="2s" repeatCount="indefinite" />
      </circle>
      <!-- Skull icon -->
      <text x="650" y="61" fill="#22C55E" font-size="13" text-anchor="middle">💀</text>
      <!-- Labels -->
      <text x="682" y="52" fill="#22C55E" font-size="12px" font-weight="700" font-family="'Inter', sans-serif">Command Server</text>
      <text x="682" y="67" fill="#86EFAC" font-size="10px" font-family="'JetBrains Mono', monospace">185.220.101.8 (C2 Pivot)</text>
    `;
    csGroup.addEventListener('click', () => {
      if (state.events) {
        const br5 = state.events.breaches.find(b => b.id === 'BR-05') || state.events.breaches[0];
        openEvidenceDrilldown(br5);
      }
    });
    gViewport.appendChild(csGroup);

    // 3. Exfiltration Target (Amber Crosshair node, Image 3)
    const exGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    exGroup.setAttribute('class', 'graph-node');
    exGroup.style.cursor = 'pointer';
    exGroup.innerHTML = `
      <!-- Amber glowing aura -->
      <circle cx="810" cy="190" r="22" fill="#231707" stroke="#F59E0B" stroke-width="2.5" filter="url(#tgGlowAmber)">
        <animate attributeName="r" values="20;24;20" dur="2.2s" repeatCount="indefinite" />
      </circle>
      <!-- Crosshair icon -->
      <text x="810" y="196" fill="#F59E0B" font-size="13" text-anchor="middle">🎯</text>
      <!-- Labels -->
      <text x="842" y="186" fill="#F59E0B" font-size="12px" font-weight="700" font-family="'Inter', sans-serif">Exfiltration Target</text>
      <text x="842" y="201" fill="#FDE68A" font-size="10px" font-family="'JetBrains Mono', monospace">High Severity (****9083)</text>
    `;
    exGroup.addEventListener('click', () => {
      if (state.events) {
        const br7 = state.events.breaches.find(b => b.id === 'BR-07') || state.events.breaches[0];
        openEvidenceDrilldown(br7);
      }
    });
    gViewport.appendChild(exGroup);

    // 4. Render Breach Nodes (BR-01 through BR-08)
    const breaches = state.events.breaches;
    tacticalNodes.forEach((node, idx) => {
      const breachData = breaches.find(b => b.id === node.id) || breaches[idx % breaches.length];
      if (!breachData) return;

      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('class', 'graph-node');
      g.style.cursor = 'pointer';
      g.addEventListener('click', () => openEvidenceDrilldown(breachData));

      const isCritical = breachData.severity === 'CRITICAL';
      const nodeColor = isCritical ? '#22C55E' : (node.type === 'spine' ? '#22C55E' : '#F59E0B');

      // Outer border circle
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', node.x);
      circle.setAttribute('cy', node.y);
      circle.setAttribute('r', '16');
      circle.setAttribute('fill', '#09100B');
      circle.setAttribute('stroke', nodeColor);
      circle.setAttribute('stroke-width', '2.5');
      if (isCritical) {
        circle.setAttribute('filter', 'url(#tgGlowRed)');
      }
      g.appendChild(circle);

      // Node ID
      const textId = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      textId.setAttribute('x', node.x);
      textId.setAttribute('y', node.y + 4);
      textId.setAttribute('fill', '#FFFFFF');
      textId.setAttribute('font-size', '10px');
      textId.setAttribute('font-weight', '800');
      textId.setAttribute('font-family', "'JetBrains Mono', monospace");
      textId.setAttribute('text-anchor', 'middle');
      textId.textContent = node.id;
      g.appendChild(textId);

      // Labels below/beside node if showLayers is true
      if (state.graph && state.graph.showLayers) {
        const textLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        textLabel.setAttribute('x', node.x);
        textLabel.setAttribute('y', node.y + 28);
        textLabel.setAttribute('fill', '#E2E8F0');
        textLabel.setAttribute('font-size', '9.5px');
        textLabel.setAttribute('font-weight', '600');
        textLabel.setAttribute('font-family', "'Inter', sans-serif");
        textLabel.setAttribute('text-anchor', 'middle');
        textLabel.textContent = node.label;
        g.appendChild(textLabel);

        const textSub = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        textSub.setAttribute('x', node.x);
        textSub.setAttribute('y', node.y + 39);
        textSub.setAttribute('fill', '#94A3B8');
        textSub.setAttribute('font-size', '8.5px');
        textSub.setAttribute('font-family', "'JetBrains Mono', monospace");
        textSub.setAttribute('text-anchor', 'middle');
        textSub.textContent = node.ip;
        g.appendChild(textSub);
      }

      gViewport.appendChild(g);
    });
  }

  // --- EVIDENCE DRILL-DOWN DRAWER ---
  function openEvidenceDrilldown(eventItem, isSetAside = false) {
    state.selectedEvent = eventItem;
    const drawer = document.getElementById('slide-drawer');
    const backdrop = document.getElementById('drawer-backdrop');
    const titleEl = document.getElementById('drawer-title');
    const subtitleEl = document.getElementById('drawer-subtitle');
    const contentEl = document.getElementById('drawer-body');

    if (!drawer || !contentEl) return;

    titleEl.textContent = `${eventItem.id}: ${eventItem.title}`;
    subtitleEl.textContent = `${formatUtcDate(eventItem.timestamp_utc)} | ${eventItem.source_ip || 'Internal Host'}`;

    let html = `
      <div class="drilldown-section">
        <div class="drilldown-title">Forensic Summary (What Happened)</div>
        <div style="font-size:0.88rem; color:var(--text-primary); line-height:1.5;">${eventItem.what_happened}</div>
      </div>
    `;

    if (!isSetAside && eventItem.contract_rule_broken) {
      const r = eventItem.contract_rule_broken;
      html += `
        <div class="drilldown-section">
          <div class="drilldown-title">Contract Rule Broken (${r.rule_id})</div>
          <div style="font-size:0.8rem; font-weight:700; color:var(--status-breach); margin-bottom:8px;">${r.rule_name}</div>
          <div class="side-by-side-grid">
            <div class="clause-card expected">
              <b style="color:var(--status-setaside);">EXPECTED CONTRACT SPEC:</b>
              <div style="margin-top:4px;">${r.expected}</div>
            </div>
            <div class="clause-card observed">
              <b style="color:var(--status-breach);">OBSERVED ANOMALY:</b>
              <div style="margin-top:4px;">${r.observed}</div>
            </div>
          </div>
        </div>
      `;
    } else if (isSetAside && eventItem.rule_evaluated) {
      html += `
        <div class="drilldown-section">
          <div class="drilldown-title">Rule Evaluated & Acceptable Threshold</div>
          <div class="clause-card expected">
            <b>EVALUATED RULE:</b> ${eventItem.rule_evaluated}
          </div>
        </div>
      `;
    }

    // Supporting Evidence citations
    if (eventItem.evidence_ids) {
      html += `
        <div class="drilldown-section">
          <div class="drilldown-title">Supporting Case Evidence Files</div>
          <div class="tag-pills-row">
            ${eventItem.evidence_ids.map(eid => `<span class="evidence-tag">${eid}</span>`).join('')}
          </div>
        </div>
      `;
    }

    // Ordinary explanation considered
    if (!isSetAside) {
      html += `
        <div class="drilldown-section">
          <div class="drilldown-title">Ordinary Explanation Evaluated & Why Rejected</div>
          <div style="background-color:var(--bg-surface-elevated); padding:10px 12px; border-radius:6px; font-size:0.82rem; margin-bottom:6px;">
            <b>Hypothesis Considered:</b> ${eventItem.ordinary_explanation_considered}
          </div>
          <div style="background-color:rgba(34, 197, 94, 0.08); border-left:3px solid var(--status-breach); padding:10px 12px; border-radius:4px; font-size:0.82rem; color:#86EFAC;">
            <b>Forensic Rejection Rationale:</b> ${eventItem.why_rejected}
          </div>
        </div>
      `;
    } else {
      html += `
        <div class="drilldown-section">
          <div class="drilldown-title">Why Set Aside as Ordinary Baseline</div>
          <div style="background-color:rgba(16, 185, 129, 0.08); border-left:3px solid var(--status-setaside); padding:10px 12px; border-radius:4px; font-size:0.82rem; color:#6EE7B7;">
            <b>Acceptance Rationale:</b> ${eventItem.why_accepted}
          </div>
        </div>
      `;
    }

    // What would change our mind
    if (eventItem.what_would_change_our_mind) {
      html += `
        <div class="drilldown-section">
          <div class="drilldown-title">Falsification Criteria (What Would Change Our Mind)</div>
          <div style="background-color:var(--bg-surface-elevated); border:1px solid var(--border-subtle); padding:10px 12px; border-radius:6px; font-size:0.82rem; color:var(--text-secondary);">
            ⚖️ ${eventItem.what_would_change_our_mind}
          </div>
        </div>
      `;
    }

    contentEl.innerHTML = html;
    drawer.classList.add('open');
    if (backdrop) backdrop.classList.add('open');
  }

  // --- CONTRACT INSPECTOR DRAWER ---
  function openContractInspector(credentialId) {
    if (!state.contracts) return;
    const contract = state.contracts[credentialId];
    if (!contract) return;

    state.selectedContract = contract;
    const drawer = document.getElementById('slide-drawer');
    const backdrop = document.getElementById('drawer-backdrop');
    const titleEl = document.getElementById('drawer-title');
    const subtitleEl = document.getElementById('drawer-subtitle');
    const contentEl = document.getElementById('drawer-body');

    if (!drawer || !contentEl) return;

    titleEl.textContent = `Behavioral Contract: ${contract.credential_id}`;
    subtitleEl.textContent = `${contract.credential_name} | Target: ${contract.system}`;

    let html = `
      <div class="drilldown-section">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <span class="drilldown-title">Contract Health Score</span>
          <span style="font-weight:700; color:${contract.contract_score < 30 ? 'var(--status-breach)' : 'var(--status-warning)'};">
            ${contract.contract_score} / 100 (${contract.risk_rating})
          </span>
        </div>
        <div style="font-size:0.78rem; color:var(--text-secondary);">
          Contract specifies allowable networks, client versions, scheduled time windows, endpoints, and approval tokens. Observed telemetry is overlaid below.
        </div>
      </div>
    `;

    Object.keys(contract.clauses).forEach(clauseKey => {
      const c = contract.clauses[clauseKey];
      const isBad = c.status.includes('VIOLATION') || c.status.includes('BREACH') || c.status.includes('COMPROMISED');
      html += `
        <div class="drilldown-section">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
            <span style="font-size:0.75rem; font-weight:700; color:var(--text-primary);">${c.label}</span>
            <span style="font-size:0.7rem; font-weight:700; color:${isBad ? 'var(--status-breach)' : 'var(--status-setaside)'};">
              [${c.status}]
            </span>
          </div>
          <div class="side-by-side-grid">
            <div class="clause-card expected">
              <b style="color:var(--status-setaside);">ALLOWED SPEC:</b>
              <div style="margin-top:2px;">${c.contract_spec}</div>
            </div>
            <div class="clause-card observed">
              <b style="color:var(--status-breach);">OBSERVED OVERLAY:</b>
              <div style="margin-top:2px;">${c.observed_anomaly}</div>
            </div>
          </div>
        </div>
      `;
    });

    contentEl.innerHTML = html;
    drawer.classList.add('open');
    if (backdrop) backdrop.classList.add('open');
  }

  function closeDrawer() {
    const drawer = document.getElementById('slide-drawer');
    const backdrop = document.getElementById('drawer-backdrop');
    if (drawer) drawer.classList.remove('open');
    if (backdrop) backdrop.classList.remove('open');
  }

  // --- REPLAY PLAYBACK CONTROLLER ---
  function playReplay() {
    if (state.isPlaying) return;
    state.isPlaying = true;
    updatePlayPauseButton();

    if (state.progress >= 1.0) {
      state.progress = 0.0;
    }

    const stepInterval = 100;
    state.playbackTimer = setInterval(() => {
      state.progress += (0.005 * state.speed);
      if (state.progress >= 1.0) {
        state.progress = 1.0;
        pauseReplay();
      }
      updateScrubber();
      renderBoard();
    }, stepInterval);
  }

  function pauseReplay() {
    state.isPlaying = false;
    if (state.playbackTimer) {
      clearInterval(state.playbackTimer);
      state.playbackTimer = null;
    }
    updatePlayPauseButton();
  }

  function updatePlayPauseButton() {
    const btn = document.getElementById('btn-play-pause');
    if (btn) {
      btn.innerHTML = state.isPlaying ? '⏸' : '▶';
      btn.setAttribute('aria-label', state.isPlaying ? 'Pause replay' : 'Play replay');
    }
  }

  function updateScrubber() {
    const progressEl = document.getElementById('scrubber-progress');
    if (progressEl) {
      progressEl.style.width = `${state.progress * 100}%`;
    }
    updateRadarBlip();
  }

  function updateRadarBlip() {
    const threatBlip = document.getElementById('radar-threat-blip');
    if (!threatBlip) return;

    if (state.gate.isRolledBack) {
      threatBlip.innerHTML = `
        <circle cx="0" cy="0" r="6" fill="#10B981" filter="url(#radar-glow)" />
        <circle cx="0" cy="0" r="12" fill="none" stroke="#10B981" stroke-width="1.5" />
        <text x="8" y="4" fill="#10B981" font-size="9" font-family="'JetBrains Mono', monospace" font-weight="700">ROLLED BACK: ****1142</text>
      `;
      return;
    }

    if (state.progress >= 0.85) {
      threatBlip.innerHTML = `
        <circle cx="0" cy="0" r="7" fill="#22C55E" filter="url(#radar-glow)" />
        <circle cx="0" cy="0" r="14" fill="none" stroke="#22C55E" stroke-width="2">
          <animate attributeName="r" values="7;18;7" dur="1s" repeatCount="indefinite" />
        </circle>
        <text x="8" y="4" fill="#22C55E" font-size="9" font-family="'JetBrains Mono', monospace" font-weight="700">TAMPERING: coastal_pkg ****9083</text>
      `;
    } else if (state.progress >= 0.5) {
      threatBlip.innerHTML = `
        <circle cx="0" cy="0" r="6" fill="#F59E0B" filter="url(#radar-glow)" />
        <circle cx="0" cy="0" r="12" fill="none" stroke="#F59E0B" stroke-width="1.5">
          <animate attributeName="r" values="6;14;6" dur="1.5s" repeatCount="indefinite" />
        </circle>
        <text x="8" y="4" fill="#F59E0B" font-size="9" font-family="'JetBrains Mono', monospace" font-weight="700">PIVOT: 10.20.4.77</text>
      `;
    } else {
      threatBlip.innerHTML = `
        <circle cx="0" cy="0" r="5" fill="#22C55E" filter="url(#radar-glow)" />
        <circle cx="0" cy="0" r="10" fill="none" stroke="#22C55E" stroke-width="1" />
        <text x="8" y="4" fill="#94A3B8" font-size="9" font-family="'JetBrains Mono', monospace">CORRIDOR RECON</text>
      `;
    }
  }

  function setupWaveChartInteraction() {
    const container = document.getElementById('wave-chart-container');
    if (!container) return;

    container.addEventListener('mousemove', (e) => {
      const rect = container.getBoundingClientRect();
      const x = Math.max(10, Math.min(590, ((e.clientX - rect.left) / rect.width) * 600));
      const y = 140 - Math.sin((x / 600) * Math.PI * 3.5) * 55;
      const count = Math.round(20 + Math.abs(Math.sin(x / 50)) * 85);

      const scrubber = container.querySelector('g[transform^="translate"]');
      if (scrubber) {
        scrubber.setAttribute('transform', `translate(${x}, ${Math.max(40, Math.min(145, y))})`);
        const text = scrubber.querySelector('text');
        if (text) {
          text.textContent = `${count}k`;
        }
      }
    });
  }

  // --- PAYMENT-RUN GATE SIMULATOR ---
  function updateGateDisplay() {
    const box = document.getElementById('gate-decision-box');
    const badge = document.getElementById('gate-status-badge');
    const rollbackBtn = document.getElementById('btn-rollback');

    if (!box || !badge) return;

    const hudGatePill = document.getElementById('hud-gate-pill');
    const hudValCrew = document.getElementById('hud-val-crew');

    if (state.gate.isRolledBack) {
      badge.className = 'gate-badge-released';
      badge.innerHTML = '🛡️ ROLLED BACK & PROTECTED';
      box.className = 'gate-decision-box safe';
      box.innerHTML = `
        <div style="font-weight:700; color:var(--status-setaside); margin-bottom:4px;">DECISION: ROLLBACK RESTORED VERIFIED MASTER ACCOUNT</div>
        <div>Vendor V-0412 bank routing reverted to verified HDFC account <code>****1142</code>. $284,500 monthly payment disbursement released safely under dual approval.</div>
      `;
      if (rollbackBtn) {
        rollbackBtn.className = 'rollback-btn restored';
        rollbackBtn.innerHTML = '✅ Rollback Complete — Account ****1142 Active';
      }
      if (hudGatePill) {
        hudGatePill.className = 'kpi-trend-pill positive';
        hudGatePill.textContent = 'SECURED';
      }
      if (hudValCrew) {
        hudValCrew.textContent = 'SECURED ****1142';
      }
      updateRadarBlip();
      return;
    }

    if (hudGatePill) {
      hudGatePill.className = 'kpi-trend-pill negative';
      hudGatePill.textContent = state.gate.step === 0 ? 'FLAGGED' : 'GATE LOCKED';
    }
    if (hudValCrew) {
      hudValCrew.textContent = state.gate.step === 0 ? '1 FLAGGED' : '6 ACTIVE';
    }

    if (state.gate.step === 0) {
      badge.className = 'gate-badge-locked';
      badge.innerHTML = '⚠️ UNVERIFIED CHANGE DETECTED';
      box.className = 'gate-decision-box held';
      box.innerHTML = `
        <div style="font-weight:700; color:var(--status-breach); margin-bottom:4px;">DECISION: INTERCEPTED AT 3 SEP CHANGE INTAKE</div>
        <div>API change submitted with approval_ref: null altering Coastal Packaging bank details to <code>****9083</code>. Flagged for mandatory review.</div>
      `;
    } else if (state.gate.step === 1) {
      badge.className = 'gate-badge-locked';
      badge.innerHTML = '⛔ PADLOCK GATE: HELD FROM PAYMENT RUN';
      box.className = 'gate-decision-box held';
      box.innerHTML = `
        <div style="font-weight:700; color:var(--status-breach); margin-bottom:4px;">DECISION: DISBURSEMENT FROZEN FOR V-0412</div>
        <div>Target Coastal Packaging held. 42 ordinary vendor payments released normally. Callback verification checklist required prior to payment cutoff.</div>
      `;
    } else {
      badge.className = 'gate-badge-locked';
      badge.innerHTML = '🔒 DISBURSEMENT EXCLUDED FROM RUN';
      box.className = 'gate-decision-box held';
      box.innerHTML = `
        <div style="font-weight:700; color:var(--status-breach); margin-bottom:4px;">DECISION: 8 SEP PAYMENT RUN EXCLUSION APPLIED</div>
        <div>Cutoff reached without valid dual-control approval. Disbursement held to prevent financial loss. User may execute immediate rollback below.</div>
      `;
    }
  }

  function setGateStep(stepIndex) {
    state.gate.step = stepIndex;
    document.querySelectorAll('.step-node').forEach((node, idx) => {
      node.classList.toggle('active', idx === stepIndex);
    });
    updateGateDisplay();
  }

  function toggleGateCheck(checkKey) {
    state.gate.checks[checkKey] = !state.gate.checks[checkKey];
    const itemEl = document.querySelector(`.check-item[data-check="${checkKey}"]`);
    if (itemEl) {
      itemEl.classList.toggle('checked', state.gate.checks[checkKey]);
      const box = itemEl.querySelector('.check-box');
      if (box) box.textContent = state.gate.checks[checkKey] ? '✓' : '';
    }
  }

  function executeRollback() {
    state.gate.isRolledBack = true;
    updateGateDisplay();
  }

  // --- ATTACK MUTATOR DEMO ---
  function evaluateMutator() {
    const m = state.mutator;
    const isIpViolated = m.sourceIp !== '10.20.4.12';
    const isVerViolated = m.clientVer !== '4.2.0';
    const isTimeViolated = m.timeWindow !== '01:30';
    const isGateViolated = m.approvalRef === 'null';
    const isFieldViolated = m.targetField === 'bank_account';

    // IOC Blocklist check: only catches known IP 198.18.7.77
    const iocFired = (m.sourceIp === '198.18.7.77');

    const matrixEl = document.getElementById('mutator-matrix');
    if (!matrixEl) return;

    matrixEl.innerHTML = `
      <div class="detector-row">
        <span>RULE-IP-BOUNDARY (Private Network Pool)</span>
        <span class="${isIpViolated ? 'detector-badge-fired' : 'detector-badge-missed'}">
          ${isIpViolated ? '🚨 FIRED' : 'MISSED'}
        </span>
      </div>
      <div class="detector-row">
        <span>RULE-CLIENT-VER (SDK Minimum Version)</span>
        <span class="${isVerViolated ? 'detector-badge-fired' : 'detector-badge-missed'}">
          ${isVerViolated ? '🚨 FIRED' : 'MISSED'}
        </span>
      </div>
      <div class="detector-row">
        <span>RULE-TIME-WINDOW (01:00–02:00 UTC Corridor)</span>
        <span class="${isTimeViolated ? 'detector-badge-fired' : 'detector-badge-missed'}">
          ${isTimeViolated ? '🚨 FIRED' : 'MISSED'}
        </span>
      </div>
      <div class="detector-row">
        <span>RULE-APPROVAL-GATE (Dual-Control Requirement)</span>
        <span class="${isGateViolated ? 'detector-badge-fired' : 'detector-badge-missed'}">
          ${isGateViolated ? '🚨 FIRED' : 'MISSED'}
        </span>
      </div>
      <div class="detector-row" style="border-top:1px dashed var(--border-subtle); padding-top:8px;">
        <span>Traditional IOC IP-Blocklist Baseline</span>
        <span class="${iocFired ? 'detector-badge-fired' : 'detector-badge-missed'}">
          ${iocFired ? '🚨 FIRED' : 'MISSED (Bypassed)'}
        </span>
      </div>
    `;
  }

  // --- METRICS RENDERING ---
  function renderMetrics() {
    if (!state.metrics) return;
    const cw = state.metrics.comparison_scoreboard.contract_watch;
    const ioc = state.metrics.comparison_scoreboard.traditional_ioc_blocklist;

    const cwStats = document.getElementById('cw-stats-container');
    const iocStats = document.getElementById('ioc-stats-container');

    if (cwStats) {
      cwStats.innerHTML = `
        <div class="stat-box">
          <div class="stat-val" style="color:var(--status-setaside);">${cw.breaches_detected}/${cw.total_breaches}</div>
          <div class="stat-lbl">Breaches Detected</div>
        </div>
        <div class="stat-box">
          <div class="stat-val" style="color:var(--lane-ledgerone);">${cw.false_alarms}</div>
          <div class="stat-lbl">False Alarms</div>
        </div>
        <div class="stat-box">
          <div class="stat-val" style="color:var(--status-setaside);">${cw.set_aside_correctly}</div>
          <div class="stat-lbl">Set Aside Correctly</div>
        </div>
        <div class="stat-box">
          <div class="stat-val">${(cw.f1_score * 100).toFixed(0)}%</div>
          <div class="stat-lbl">F1-Score</div>
        </div>
      `;
    }

    if (iocStats) {
      iocStats.innerHTML = `
        <div class="stat-box">
          <div class="stat-val" style="color:var(--status-breach);">${ioc.breaches_detected}/${ioc.total_breaches}</div>
          <div class="stat-lbl">Breaches Detected</div>
        </div>
        <div class="stat-box">
          <div class="stat-val" style="color:var(--status-breach);">${ioc.false_alarms}</div>
          <div class="stat-lbl">False Alarms (Staff Blocked)</div>
        </div>
        <div class="stat-box">
          <div class="stat-val" style="color:var(--status-breach);">${ioc.missed_breaches}</div>
          <div class="stat-lbl">Missed Breaches</div>
        </div>
        <div class="stat-box">
          <div class="stat-val">${(ioc.f1_score * 100).toFixed(0)}%</div>
          <div class="stat-lbl">F1-Score</div>
        </div>
      `;
    }
  }

  // --- EVENT LISTENERS & KEYBOARD NAV ---
  function setupEventListeners() {
    // Theme toggle
    document.getElementById('btn-theme-toggle')?.addEventListener('click', toggleTheme);

    // View toggle buttons
    const btnTimeline = document.getElementById('btn-view-timeline');
    const btnGraph = document.getElementById('btn-view-graph');
    btnTimeline?.addEventListener('click', () => switchView('timeline'));
    btnGraph?.addEventListener('click', () => switchView('graph'));

    // Playback buttons
    document.getElementById('btn-play-pause')?.addEventListener('click', () => {
      state.isPlaying ? pauseReplay() : playReplay();
    });

    document.getElementById('btn-step-back')?.addEventListener('click', () => {
      pauseReplay();
      state.progress = Math.max(0, state.progress - 0.05);
      updateScrubber();
      renderBoard();
    });

    document.getElementById('btn-step-fwd')?.addEventListener('click', () => {
      pauseReplay();
      state.progress = Math.min(1, state.progress + 0.05);
      updateScrubber();
      renderBoard();
    });

    document.getElementById('btn-rewind')?.addEventListener('click', () => {
      pauseReplay();
      state.progress = 0;
      updateScrubber();
      renderBoard();
    });

    document.getElementById('speed-select')?.addEventListener('change', (e) => {
      state.speed = parseFloat(e.target.value);
    });

    // Scrubber click
    document.getElementById('scrubber-track')?.addEventListener('click', (e) => {
      const rect = e.currentTarget.getBoundingClientRect();
      const clickX = e.clientX - rect.left;
      state.progress = Math.max(0, Math.min(1, clickX / rect.width));
      updateScrubber();
      renderBoard();
    });

    // Drawer close
    document.getElementById('drawer-close-btn')?.addEventListener('click', closeDrawer);
    document.getElementById('drawer-backdrop')?.addEventListener('click', closeDrawer);

    // Gate interactions
    document.querySelectorAll('.step-node').forEach((node, idx) => {
      node.addEventListener('click', () => setGateStep(idx));
    });

    document.querySelectorAll('.check-item').forEach(item => {
      item.addEventListener('click', () => {
        const key = item.dataset.check;
        toggleGateCheck(key);
      });
    });

    document.getElementById('btn-rollback')?.addEventListener('click', executeRollback);

    // Cyber Action buttons (Images 1 & 2)
    const lockGateAction = () => {
      setGateStep(1);
      const gateBadge = document.getElementById('gate-status-badge');
      if (gateBadge) {
        gateBadge.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    };

    document.getElementById('hero-btn-lockdown')?.addEventListener('click', lockGateAction);
    document.getElementById('btn-radar-dock')?.addEventListener('click', lockGateAction);

    const togglePlaybackAction = () => {
      state.isPlaying ? pauseReplay() : playReplay();
    };

    document.getElementById('hero-btn-launch-replay')?.addEventListener('click', togglePlaybackAction);
    document.getElementById('btn-radar-launch')?.addEventListener('click', togglePlaybackAction);

    document.getElementById('hero-btn-view-matrix')?.addEventListener('click', () => {
      switchView('graph');
    });

    document.getElementById('btn-export-intel')?.addEventListener('click', () => {
      alert("CONTRACT WATCH INTEL BRIEFING EXPORT:\n\nCase: CR-26-047 (Harbor & Finch Freight)\nKey Findings:\n- Former employee account access (Rohan Menon) via Okta SSO\n- HelpDeskr bulk customer statement export overage\n- Shared storage S3 key leakage in ticket thread\n- Build host pivot (10.20.4.77) attempting unapproved bank routing alteration\n- 8 Sep payment-run padlock held disbursement; rollback to verified account ****1142 completed.");
    });

    // Tactical Graph Controls (Image 3)
    document.getElementById('btn-graph-zoom-in')?.addEventListener('click', () => {
      state.graph.zoom = Math.min(2.0, state.graph.zoom + 0.15);
      renderGraph();
    });

    document.getElementById('btn-graph-zoom-out')?.addEventListener('click', () => {
      state.graph.zoom = Math.max(0.65, state.graph.zoom - 0.15);
      renderGraph();
    });

    document.getElementById('btn-graph-reset')?.addEventListener('click', () => {
      state.graph.zoom = 1.0;
      renderGraph();
    });

    document.getElementById('btn-graph-layers')?.addEventListener('click', () => {
      state.graph.showLayers = !state.graph.showLayers;
      renderGraph();
    });

    document.getElementById('btn-graph-reticle')?.addEventListener('click', () => {
      state.graph.zoom = 1.4;
      renderGraph();
      const exfilBreach = state.events && state.events.breaches ? state.events.breaches.find(b => b.id === 'BR-07') : null;
      if (exfilBreach) {
        openEvidenceDrilldown(exfilBreach);
      }
    });

    // Mutator input changes
    ['mut-ip', 'mut-ver', 'mut-key', 'mut-time', 'mut-field', 'mut-app'].forEach(id => {
      document.getElementById(id)?.addEventListener('change', (e) => {
        const propMap = {
          'mut-ip': 'sourceIp',
          'mut-ver': 'clientVer',
          'mut-key': 'apiKey',
          'mut-time': 'timeWindow',
          'mut-field': 'targetField',
          'mut-app': 'approvalRef'
        };
        state.mutator[propMap[id]] = e.target.value;
        evaluateMutator();
      });
    });

    // Keyboard Shortcuts
    window.addEventListener('keydown', (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;

      if (e.code === 'Space') {
        e.preventDefault();
        state.isPlaying ? pauseReplay() : playReplay();
      } else if (e.code === 'ArrowRight') {
        e.preventDefault();
        pauseReplay();
        state.progress = Math.min(1, state.progress + 0.05);
        updateScrubber();
        renderBoard();
      } else if (e.code === 'ArrowLeft') {
        e.preventDefault();
        pauseReplay();
        state.progress = Math.max(0, state.progress - 0.05);
        updateScrubber();
        renderBoard();
      } else if (e.key === 'g' || e.key === 'G') {
        switchView(state.activeView === 'timeline' ? 'graph' : 'timeline');
      } else if (e.key === 't' || e.key === 'T') {
        toggleTheme();
      } else if (e.code === 'Escape') {
        closeDrawer();
      }
    });

    // Window resize handler for causal chain line adjustments
    window.addEventListener('resize', () => {
      if (state.activeView === 'timeline') {
        renderCausalChain();
      }
    });
  }

  function switchView(viewName) {
    state.activeView = viewName;
    const timelineEl = document.getElementById('lanes-view-wrapper');
    const graphEl = document.getElementById('graph-view-wrapper');
    const btnTimeline = document.getElementById('btn-view-timeline');
    const btnGraph = document.getElementById('btn-view-graph');

    if (viewName === 'timeline') {
      timelineEl.style.display = 'flex';
      graphEl.classList.remove('active');
      btnTimeline.classList.add('active');
      btnGraph.classList.remove('active');
      renderCausalChain();
    } else {
      timelineEl.style.display = 'none';
      graphEl.classList.add('active');
      btnGraph.classList.add('active');
      btnTimeline.classList.remove('active');
      renderGraph();
    }
  }

  // Run on DOM load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
