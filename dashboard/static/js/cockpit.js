/**
 * RedTeam Harness — Cockpit Dashboard v2.0
 * Real-time WebSocket: streaming, plan, autonomous, token tracking, reports
 */

// ═══════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════
let socket = null;
let sessionId = null;
let toolCount = 0;
let stepCount = 0;
let commandLog = [];
let findings = [];
let currentCategory = 'all';
let streamingMessage = null;
let autonomousEnabled = false;
let tacticalSuggestions = [];
let tacticalExecuting = new Set();

// ═══════════════════════════════════════════════════════════════
// Initialize
// ═══════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
    initSocket();
    loadTools();
    loadQuickCommands();
    loadAttackChains();
    loadWorkflows();
    populateGraphSelect();
    loadAttackGraphSources();
    loadAttackMatrixSources();
    loadStatus();
    loadSessions();
    loadSafety();
    initInput();
    initTabs();
    initAutonomousToggle();
    loadCampaignSelectOptions();
    loadCompareSelects();
    initCtrlTooltips();
});

// ═══════════════════════════════════════════════════════════════
// WebSocket
// ═══════════════════════════════════════════════════════════════

// v5.5: SocketIO reconnection resilience — buffer missed campaign events
// during a disconnect and replay them on reconnect so a dropped WebSocket
// never leaves the C2 view stale. Buffers the last N events per channel.
const CAMPAIGN_EVENT_BUFFER = new Map(); // eventName -> [payload, ...]
const MAX_BUFFERED_EVENTS = 200;
let socketDisconnectedAt = null;

function bufferCampaignEvent(eventName, data) {
    if (!CAMPAIGN_EVENT_BUFFER.has(eventName)) CAMPAIGN_EVENT_BUFFER.set(eventName, []);
    const q = CAMPAIGN_EVENT_BUFFER.get(eventName);
    q.push(data);
    if (q.length > MAX_BUFFERED_EVENTS) q.shift();
}

function replayBufferedEvents() {
    for (const [eventName, q] of CAMPAIGN_EVENT_BUFFER.entries()) {
        if (!q.length) continue;
        console.log(`Replaying ${q.length} buffered ${eventName} event(s) after reconnect`);
        for (const payload of q) {
            try {
                if (eventName === 'multi_target_progress') handleMultiTargetProgress(payload);
                else if (eventName === 'campaign_target_update') handleCampaignTargetUpdate(payload);
                else if (eventName === 'campaign_update') handleCampaignUpdate(payload);
                else if (eventName === 'campaign_complete') handleCampaignComplete(payload);
                else if (eventName === 'parallel_complete') renderParallelResult(payload);
            } catch (e) { console.error('Replay failed for', eventName, e); }
        }
    }
    CAMPAIGN_EVENT_BUFFER.clear();
    // Always force a full refresh after replay — catches anything missed
    if (currentCampaignId) debouncedCampaignRefresh();
}

function handleMultiTargetProgress(data) {
    if (currentCampaignId && data.campaign_id === currentCampaignId) {
        debouncedCampaignRefresh();
    }
    if (data.phase === 'complete') {
        const icon = data.status === 'complete' ? '✅' : (data.status === 'failed' || data.status === 'error') ? '❌' : '⚠️';
        addSystemMessage(`${icon} Target ${escapeHtml(data.target)} ${data.status} — ${data.completed || 0}/${data.total || 0} targets done`);
    } else if (data.phase === 'started') {
        addSystemMessage(`🚀 Target ${escapeHtml(data.target)} started (${data.completed || 0}/${data.total || 0})`);
    }
}

function handleCampaignTargetUpdate(data) {
    if (data.campaign_id === currentCampaignId) debouncedCampaignRefresh();
}

function handleCampaignUpdate(data) {
    if (data.campaign_id === currentCampaignId) debouncedCampaignRefresh();
}

function handleCampaignComplete(data) {
    if (data.campaign_id === currentCampaignId) {
        refreshCampaignData();
        addSystemMessage(`📡 Campaign ${data.status}: ${data.error || 'all targets processed'}`);
        if (campaignPollTimer) { clearInterval(campaignPollTimer); campaignPollTimer = null; }
    }
}

function initSocket() {
    socket = io();

    socket.on('connect', () => {
        console.log('Connected to RedTeam Harness v2');
        updateLLMStatus(true);
        // v5.5: replay anything buffered while we were disconnected
        if (socketDisconnectedAt) {
            replayBufferedEvents();
            socketDisconnectedAt = null;
        }
    });

    socket.on('disconnect', () => {
        updateLLMStatus(false);
        socketDisconnectedAt = Date.now();
    });

    socket.on('status', (data) => {
        updateStatusIndicators(data);
        updateTokenUsage(data.token_usage);
    });

    // ── Tool events ──
    socket.on('tool_start', (data) => {
        addToolMessage(data.tool, data.args, 'running');
    });

    socket.on('tool_complete', (data) => {
        toolCount++;
        updateMeta();
        updateToolResult(data);
        appendLiveOutput(data);
        addCommandToLog(data);
    });

    // ── LLM streaming ──
    socket.on('llm_thinking', () => showThinking(true));

    socket.on('llm_chunk', (data) => {
        if (!streamingMessage) {
            streamingMessage = addAssistantMessageStream();
        }
        appendToStreamingMessage(data.content);
    });

    socket.on('llm_response', (data) => {
        showThinking(false);
        finalizeStreamingMessage();
    });

    // ── Plan & Report ──
    socket.on('plan_generated', (data) => {
        showPlan(data.plan);
    });

    socket.on('report_generated', (data) => {
        showReport(data.report);
    });

    // ── Task lifecycle ──
    socket.on('task_complete', (data) => {
        showThinking(false);
        finalizeStreamingMessage();
        handleTaskComplete(data);
        updateTokenUsage(data.token_usage);
    });

    socket.on('tool_result', (data) => {
        toolCount++;
        updateMeta();
        appendLiveOutput(data);
    });

    socket.on('error', (data) => {
        showThinking(false);
        addSystemMessage(`❌ Error: ${data.message}`);
    });

    socket.on('autonomous_changed', (data) => {
        autonomousEnabled = data.enabled;
        updateAutonomousToggleUI();
    });

    // ── Workflow events ──
    socket.on('workflow_start', (data) => {
        addSystemMessage(`🚀 Workflow started: ${data.workflow?.name || 'unknown'} (task: ${data.task_id})`);
    });

    socket.on('workflow_complete', (data) => {
        const status = (data.status || 'unknown').toUpperCase();
        addSystemMessage(`🏁 Workflow complete: ${status} — ${data.completed_steps}/${data.total_steps} steps`);
        if (data.chain_values && Object.keys(data.chain_values).length) {
            const chainText = Object.entries(data.chain_values)
                .map(([k, v]) => `• ${k} = ${String(v).slice(0, 60)}`).join('\n');
            addSystemMessage(`🔗 Exploit chain values:\n${chainText}`);
        }
        if (data.status === 'complete') {
            addSystemMessage(`✅ Full workflow completed — output at: ${data.root}`);
        }
    });

    socket.on('workflow_result', (data) => {
        handleWorkflowResult(data);
    });

    socket.on('workflow_multi_result', (data) => {
        handleMultiWorkflowResult(data);
    });

    socket.on('workflow_generated', (data) => {
        handleWorkflowGenerated(data);
    });

    // ── Mission Control (autonomous kill chain) ──
    socket.on('autonomous_mission_control', (data) => {
        renderMissionControl(data);
    });

    socket.on('autonomous_retry_escalation', (data) => {
        loadMissionControl();  // refresh from server for full retry history
    });

    // ── Campaign events (v5.5: buffered during disconnect + replayed) ──
    socket.on('campaign_target_update', (data) => {
        if (socketDisconnectedAt) { bufferCampaignEvent('campaign_target_update', data); return; }
        handleCampaignTargetUpdate(data);
    });

    socket.on('campaign_update', (data) => {
        if (socketDisconnectedAt) { bufferCampaignEvent('campaign_update', data); return; }
        handleCampaignUpdate(data);
    });

    // ── Multi-target scheduler: live per-target progress ──
    socket.on('multi_target_progress', (data) => {
        if (socketDisconnectedAt) { bufferCampaignEvent('multi_target_progress', data); return; }
        handleMultiTargetProgress(data);
    });

    socket.on('parallel_complete', (data) => {
        if (socketDisconnectedAt) { bufferCampaignEvent('parallel_complete', data); return; }
        renderParallelResult(data);
    });
    socket.on('campaign_complete', (data) => {
        if (socketDisconnectedAt) { bufferCampaignEvent('campaign_complete', data); return; }
        handleCampaignComplete(data);
    });

    // ── Tactical suggestions (live feed) ──
    socket.on('tactical_suggestions', (data) => {
        handleTacticalSuggestions(data);
    });

    socket.on('tactical_result', (data) => {
        handleTacticalResult(data);
    });
}

// ═══════════════════════════════════════════════════════════════
// Streaming Message Support
// ═══════════════════════════════════════════════════════════════
function addAssistantMessageStream() {
    const container = document.getElementById('chat-messages');
    const msg = document.createElement('div');
    msg.className = 'message assistant streaming';
    msg.innerHTML = '<div class="msg-content" id="stream-content"></div>';
    container.appendChild(msg);
    scrollToBottom();
    return msg;
}

function appendToStreamingMessage(chunk) {
    const el = document.getElementById('stream-content');
    if (el) {
        el.innerHTML += formatMarkdown(chunk);
        scrollToBottom();
    }
}

function finalizeStreamingMessage() {
    if (streamingMessage) {
        streamingMessage.classList.remove('streaming');
        streamingMessage = null;
    }
}

// ═══════════════════════════════════════════════════════════════
// Status & Indicators
// ═══════════════════════════════════════════════════════════════
function updateStatusIndicators(data) {
    const llmDot = document.getElementById('llm-status');
    const llmLabel = document.getElementById('llm-label');
    const toolsDot = document.getElementById('tools-status');
    const toolsLabel = document.getElementById('tools-label');

    if (data.llm_connected) {
        llmDot.className = 'status-dot green';
        llmLabel.textContent = 'LLM: Connected';
    } else {
        llmDot.className = 'status-dot';
        llmLabel.textContent = 'LLM: Disconnected';
    }

    toolsLabel.textContent = `Tools: ${data.tools_available}/${data.tools_total}`;
}

function updateLLMStatus(connected) {
    const dot = document.getElementById('llm-status');
    const label = document.getElementById('llm-label');
    dot.className = connected ? 'status-dot green' : 'status-dot';
    label.textContent = connected ? 'LLM: Connected' : 'LLM: Disconnected';
}

function updateTokenUsage(usage) {
    if (!usage) return;
    const bar = document.getElementById('token-bar-fill');
    const label = document.getElementById('token-bar-label');
    if (bar && usage.total_tokens) {
        const max = 65536;
        const pct = Math.min(100, (usage.total_tokens / max) * 100);
        bar.style.width = pct + '%';
        bar.className = pct > 80 ? 'token-bar-fill warn' : 'token-bar-fill';
        label.textContent = `${(usage.total_tokens/1000).toFixed(1)}k / 65k tokens`;
    }
}

async function loadStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        updateStatusIndicators(data);
        updateTokenUsage(data.token_usage);
        if (data.session) {
            sessionId = data.session;
            document.getElementById('session-id').textContent = sessionId;
            document.getElementById('meta-session').textContent = sessionId;
        }
    } catch (e) {
        console.error('Status load failed:', e);
    }
}

function updateMeta() {
    document.getElementById('meta-steps').textContent = stepCount;
    document.getElementById('meta-tools-run').textContent = toolCount;
}

// ═══════════════════════════════════════════════════════════════
// Autonomous Mode
// ═══════════════════════════════════════════════════════════════
function initAutonomousToggle() {
    const toggle = document.getElementById('autonomous-toggle');
    if (toggle) {
        toggle.addEventListener('change', () => {
            autonomousEnabled = toggle.checked;
            socket.emit('set_autonomous', { enabled: autonomousEnabled });
        });
    }
}

function updateAutonomousToggleUI() {
    const toggle = document.getElementById('autonomous-toggle');
    if (toggle) {
        toggle.checked = autonomousEnabled;
    }
}

// ═══════════════════════════════════════════════════════════════
// Chat
// ═══════════════════════════════════════════════════════════════
function initInput() {
    const input = document.getElementById('chat-input');
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });
}

function sendMessage() {
    const input = document.getElementById('chat-input');
    const prompt = input.value.trim();
    if (!prompt) return;

    addUserMessage(prompt);
    input.value = '';
    showThinking(true);
    stepCount++;
    streamingMessage = null;

    socket.emit('send_task', { prompt, session_id: sessionId });
}

function sendQuickPrompt(prompt) {
    document.getElementById('chat-input').value = prompt;
    sendMessage();
}

function addUserMessage(text) {
    const container = document.getElementById('chat-messages');
    const msg = document.createElement('div');
    msg.className = 'message user';
    msg.innerHTML = `<div class="msg-content">${escapeHtml(text)}</div>`;
    container.appendChild(msg);
    scrollToBottom();
}

function addAssistantMessage(text) {
    const container = document.getElementById('chat-messages');
    const msg = document.createElement('div');
    msg.className = 'message assistant';
    msg.innerHTML = `<div class="msg-content">${formatMarkdown(text)}</div>`;
    container.appendChild(msg);
    scrollToBottom();
}

function addSystemMessage(text) {
    const container = document.getElementById('chat-messages');
    const msg = document.createElement('div');
    msg.className = 'message system';
    msg.innerHTML = `<div class="msg-content">${text}</div>`;
    container.appendChild(msg);
    scrollToBottom();
}

function addToolMessage(tool, args, status) {
    const container = document.getElementById('chat-messages');
    const msg = document.createElement('div');
    msg.className = 'message tool';
    const statusColor = status === 'running' ? 'var(--accent-yellow)' : 'var(--accent-green)';
    msg.innerHTML = `
        <div class="tool-header">
            <span class="tool-badge">${escapeHtml(tool)}</span>
            <span class="tool-status" style="color:${statusColor}">${status === 'running' ? '⏳ Running...' : '✓ Complete'}</span>
        </div>
        <pre>${escapeHtml(JSON.stringify(args, null, 2))}</pre>
    `;
    msg.id = `tool-msg-${tool}-${Date.now()}`;
    container.appendChild(msg);
    scrollToBottom();
    return msg.id;
}

function updateToolResult(data) {
    const messages = document.querySelectorAll('.message.tool');
    const last = messages[messages.length - 1];
    if (last) {
        const statusEl = last.querySelector('.tool-status');
        if (statusEl) {
            const success = data.result?.status === 'success' || data.result?.exit_code === 0;
            statusEl.textContent = success ? '✓ Complete' : `✗ Failed (${data.result?.exit_code ?? '?'})`;
            statusEl.style.color = success ? 'var(--accent-green)' : 'var(--accent-red)';
        }
    }
}

function handleTaskComplete(data) {
    // Client-side tactical evaluation from task results
    if (data.findings && data.findings.length) {
        evaluateTacticsFromFindings(data.findings);
    }
    const steps = data.steps || [];
    for (const step of steps) {
        if (step.llm_response && !streamingMessage) {
            addAssistantMessage(step.llm_response);
        }
        if (step.results) {
            for (const r of step.results) {
                if (r.status === 'blocked') {
                    addSystemMessage(`⚠️ Tool ${r.tool} blocked: ${r.reason}`);
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Plan & Report panels
// ═══════════════════════════════════════════════════════════════
function showPlan(plan) {
    const el = document.getElementById('plan-content');
    if (!el) return;
    if (!plan || plan.length === 0) {
        el.innerHTML = '<p class="muted">No plan generated.</p>';
        return;
    }
    el.innerHTML = plan.map(s => `
        <div class="plan-step">
            <span class="plan-step-num">${s.step || '?'}</span>
            <div>
                <strong>${escapeHtml(s.tool || '?')}</strong>
                <div class="plan-step-desc">${escapeHtml(s.description || '')}</div>
                ${s.target ? `<code>${escapeHtml(s.target)}</code>` : ''}
            </div>
        </div>
    `).join('');
}

function showReport(report) {
    const el = document.getElementById('report-content');
    if (!el) return;
    if (!report) {
        el.innerHTML = '<p class="muted">No report generated.</p>';
        return;
    }
    el.innerHTML = formatMarkdown(report);
    // Switch to report tab
    showResultsTab('report');
}

function scrollToBottom() {
    const container = document.getElementById('chat-messages');
    container.scrollTop = container.scrollHeight;
}

// ═══════════════════════════════════════════════════════════════
// Vector Memory / RAG Panel
// ═══════════════════════════════════════════════════════════════
async function loadMemoryPanel() {
    try {
        const statsEl = document.getElementById('memory-stats');
        if (statsEl) statsEl.innerHTML = '<p class="muted">Loading memory...</p>';
        const [statsRes, targetsRes] = await Promise.all([
            fetch('/api/memory/stats'),
            fetch('/api/memory/targets')
        ]);
        const stats = await statsRes.json();
        const targets = await targetsRes.json();
        renderMemoryStats(stats);
        renderMemoryTargets(targets);
    } catch (e) {
        console.error('Memory load failed:', e);
    }
}

function renderMemoryStats(stats) {
    const el = document.getElementById('memory-stats');
    if (!el) return;
    const sevCounts = stats.severity_counts || {};
    el.innerHTML = `
        <div class="memory-stat-grid">
            <div class="memory-stat"><span class="ms-val">${stats.total_findings || 0}</span><span class="ms-label">Total Findings</span></div>
            <div class="memory-stat"><span class="ms-val">${stats.unique_sessions || 0}</span><span class="ms-label">Sessions</span></div>
            <div class="memory-stat"><span class="ms-val">${stats.vocab_size || 0}</span><span class="ms-label">Vocab Size</span></div>
            <div class="memory-stat"><span class="ms-val">${stats.fitted ? '✅' : '❌'}</span><span class="ms-label">Index Ready</span></div>
        </div>
        <div class="memory-severity-bar">
            <span class="sev sev-critical" title="Critical">🔴 ${sevCounts.critical || 0}</span>
            <span class="sev sev-high" title="High">🟠 ${sevCounts.high || 0}</span>
            <span class="sev sev-medium" title="Medium">🟡 ${sevCounts.medium || 0}</span>
            <span class="sev sev-low" title="Low">🔵 ${sevCounts.low || 0}</span>
            <span class="sev sev-info" title="Info">⚪ ${sevCounts.info || 0}</span>
        </div>
    `;
}

function renderMemoryTargets(targets) {
    const el = document.getElementById('memory-targets');
    if (!el) return;
    if (!targets || targets.length === 0) {
        el.innerHTML = '<p class="muted">No targets stored yet.</p>';
        return;
    }
    el.innerHTML = '<h4>🎯 Stored Targets</h4>' + targets.map(t => {
        const sevBars = Object.entries(t.severities || {}).map(([s, c]) => 
            `<span class="sev-dot sev-${s}" title="${s}: ${c}">${c}</span>`).join(' ');
        return `<div class="memory-target-row" data-target="${escapeHtml(t.target)}" onclick="memoryQueryTarget(this.dataset.target)">
            <span class="mt-name">${escapeHtml(t.target)}</span>
            <span class="mt-count">${t.count} findings</span>
            <span class="mt-sevs">${sevBars}</span>
        </div>`;
    }).join('');
}

async function memorySearch() {
    const input = document.getElementById('memory-search-input');
    const query = input.value.trim();
    if (!query) return;
    try {
        const res = await fetch('/api/memory/query', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({query, top_k: 15})
        });
        const data = await res.json();
        renderMemoryResults(data.results || [], `Search: "${query}"`);
    } catch (e) {
        console.error('Memory search failed:', e);
    }
}

async function memoryQueryTarget(target) {
    try {
        const res = await fetch(`/api/memory/target/${encodeURIComponent(target)}`);
        const data = await res.json();
        renderMemoryResults(data.findings || [], `Target: ${target}`);
    } catch (e) {
        console.error('Memory target query failed:', e);
    }
}

function renderMemoryResults(results, title) {
    const el = document.getElementById('memory-results');
    if (!el) return;
    if (!results || results.length === 0) {
        el.innerHTML = `<p class="muted">No results for: ${escapeHtml(title)}</p>`;
        return;
    }
    el.innerHTML = `<h4>🔍 ${escapeHtml(title)} (${results.length} results)</h4>` + results.map(f => {
        const sev = f.severity || 'info';
        const sim = f.similarity ? ` (sim: ${f.similarity})` : '';
        const match = f.match_type ? ` [${f.match_type}]` : '';
        return `<div class="memory-finding sev-border-${sev}">
            <div class="mf-header"><span class="sev-badge sev-${sev}">${sev.toUpperCase()}</span> ${escapeHtml(f.title || 'Unknown')}${sim}${match}</div>
            <div class="mf-meta">Tool: ${escapeHtml(f.source_tool || '?')} | Session: ${escapeHtml(f.session_id || '?')}</div>
            ${f.evidence ? `<div class="mf-evidence">${escapeHtml(f.evidence)}</div>` : ''}
        </div>`;
    }).join('');
}

async function memoryExport() {
    try {
        const res = await fetch('/api/memory/export');
        if (!res.ok) throw new Error(`Export failed: ${res.statusText}`);
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = 'redteam_memory_export.zip';
        document.body.appendChild(a); a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (e) {
        alert('Export failed: ' + e.message);
    }
}

async function memoryImport() {
    const fileInput = document.getElementById('memory-import-file');
    const file = fileInput.files[0];
    if (!file) { alert('Select a .zip file to import'); return; }
    const formData = new FormData();
    formData.append('file', file);
    try {
        const res = await fetch('/api/memory/import', {method: 'POST', body: formData});
        const data = await res.json();
        if (data.error) { alert('Import failed: ' + data.error); return; }
        addSystemMessage(`📥 Memory imported: ${data.imported} files, ${data.stats?.total_findings || 0} findings`);
        loadMemoryPanel();
    } catch (e) {
        alert('Import failed: ' + e.message);
    }
}

async function memoryReset() {
    if (!confirm('⚠️ This will permanently delete ALL stored vector memory. Continue?')) return;
    try {
        await fetch('/api/memory/reset', {method: 'POST'});
        addSystemMessage('🗑️ Vector memory cleared');
        loadMemoryPanel();
    } catch (e) {
        alert('Reset failed: ' + e.message);
    }
}

// ═══════════════════════════════════════════════════════════════
// Offline Knowledge Base (v5.6) — CVE / ATT&CK / exploits / remediation
// ═══════════════════════════════════════════════════════════════
async function loadKBPanel() {
    try {
        const el = document.getElementById('kb-stats');
        if (el) el.innerHTML = '<p class="muted">Loading offline database...</p>';
        const res = await fetch('/api/kb/stats');
        const stats = await res.json();
        renderKBStats(stats);
    } catch (e) {
        const el = document.getElementById('kb-stats');
        if (el) el.innerHTML = '<p class="muted">Offline database unavailable.</p>';
        console.error('KB load failed:', e);
    }
}

function renderKBStats(stats) {
    const el = document.getElementById('kb-stats');
    if (!el) return;
    el.innerHTML = `
        <div class="memory-stat-grid">
            <div class="memory-stat"><span class="ms-val">${stats.cves || 0}</span><span class="ms-label">CVEs</span></div>
            <div class="memory-stat"><span class="ms-val">${stats.techniques || 0}</span><span class="ms-label">ATT&CK</span></div>
            <div class="memory-stat"><span class="ms-val">${stats.signatures || 0}</span><span class="ms-label">Signatures</span></div>
            <div class="memory-stat"><span class="ms-val">${stats.playbooks || 0}</span><span class="ms-label">Playbooks</span></div>
            <div class="memory-stat"><span class="ms-val">${stats.vocab_size || 0}</span><span class="ms-label">Index Terms</span></div>
        </div>
        <p class="kb-note">💾 Fully embedded — zero network calls. The LLM grounds exploit suggestions & remediation in this verified dataset during air-gapped engagements.</p>
    `;
}

async function kbSearch() {
    const input = document.getElementById('kb-search-input');
    const query = input.value.trim();
    if (!query) return;
    try {
        const res = await fetch('/api/kb/search', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({query, top_k: 12})
        });
        const data = await res.json();
        renderKBResults(data.results || [], `Search: "${query}"`);
    } catch (e) {
        console.error('KB search failed:', e);
    }
}

async function kbLookupCVE() {
    const input = document.getElementById('kb-cve-input');
    const cveId = input.value.trim().toUpperCase();
    if (!cveId) return;
    try {
        const res = await fetch(`/api/kb/cve/${encodeURIComponent(cveId)}`);
        const data = await res.json();
        if (data.error || res.status === 404) {
            renderKBResults([], `CVE ${cveId}: ${data.error || 'not found'}`);
            return;
        }
        renderKBCVEDetail(data);
    } catch (e) {
        console.error('KB CVE lookup failed:', e);
    }
}

async function kbLookupTech() {
    const input = document.getElementById('kb-tech-input');
    const techId = input.value.trim().toUpperCase();
    if (!techId) return;
    try {
        const res = await fetch(`/api/kb/technique/${encodeURIComponent(techId)}`);
        const data = await res.json();
        if (data.error || res.status === 404) {
            renderKBResults([], `ATT&CK ${techId}: ${data.error || 'not found'}`);
            return;
        }
        renderKBResults([{
            _kb_type: 'technique', id: data.id, title: data.name,
            description: data.description,
            tactics: data.tactics ? data.tactics.join(', ') : ''
        }], `ATT&CK ${techId}`);
    } catch (e) {
        console.error('KB technique lookup failed:', e);
    }
}

async function kbGroundClipboard() {
    const text = (document.getElementById('kb-search-input').value || '').trim();
    if (!text) {
        // fall back to the last live output if search box is empty
        const live = document.getElementById('live-output');
        if (live && live.textContent.trim().length > 30) {
            const t = live.textContent.trim();
            document.getElementById('kb-search-input').value = t.slice(0, 400);
            return kbGroundClipboard();
        }
        alert('Paste or type tool output text first (or run a scan so Live Output has content).');
        return;
    }
    try {
        const res = await fetch('/api/kb/ground', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text})
        });
        const data = await res.json();
        const sigs = (data.signatures || []).map(s =>
            `<div class="kb-sig"><span class="sev-badge sev-${s.severity || 'info'}">${(s.severity || 'info').toUpperCase()}</span> <strong>${escapeHtml(s.signature)}</strong> — ${escapeHtml(s.description || '')}${s.cve ? ` <a class="kb-link" onclick="kbGroundCVE('${s.cve}')">${escapeHtml(s.cve)}</a>` : ''}</div>`
        ).join('');
        const related = (data.related || []).slice(0, 4).map(r =>
            `<div class="kb-entry"><span class="kb-type-badge">${escapeHtml(r.type)}</span> <strong>${escapeHtml(r.id)}</strong> — ${escapeHtml(r.title)}</div>`
        ).join('');
        renderKBResults([], `🛡️ Signature match on provided text (${(data.signatures || []).length} hits)` + (sigs ? `<div class="kb-sig-list">${sigs}</div>` : '<p class="muted">No signature matches.</p>') + (related ? `<h4>Related entries</h4>${related}` : ''));
    } catch (e) {
        console.error('KB ground failed:', e);
    }
}

async function kbGroundCVE(cveId) {
    document.getElementById('kb-cve-input').value = cveId;
    await kbLookupCVE();
}

function renderKBCVEDetail(cve) {
    const el = document.getElementById('kb-results');
    if (!el) return;
    const cvss = cve.cvss != null ? `CVSS ${cve.cvss}` : 'CVSS n/a';
    const techs = (cve.techniques || []).map(t =>
        `<span class="kb-entry-pill">${escapeHtml(t)}</span>`).join('');
    el.innerHTML = `
        <div class="kb-cve-detail">
            <div class="mf-header"><span class="sev-badge sev-${cve.severity || 'info'}">${(cve.severity || 'INFO').toUpperCase()}</span> <strong>${escapeHtml(cve.id)}</strong> <span class="kb-cvss">${cvss}</span></div>
            <div class="mf-meta">${escapeHtml(cve.published || '')}${cve.references ? ` | ${cve.references.length} references` : ''}</div>
            <div class="mf-evidence">${escapeHtml(cve.description || '')}</div>
            ${techs ? `<div class="kb-tech-row">${techs}</div>` : ''}
            ${cve.remediation && cve.remediation.playbook ? `<div class="kb-remediation"><strong>🛡️ Remediation</strong><br>${escapeHtml(cve.remediation.playbook)}</div>` : ''}
        </div>
    `;
}

function renderKBResults(entries, title) {
    const el = document.getElementById('kb-results');
    if (!el) return;
    if (!entries || entries.length === 0) {
        el.innerHTML = `<p class="muted">${escapeHtml(title)}</p>`;
        return;
    }
    el.innerHTML = `<h4>${escapeHtml(title)} (${entries.length} results)</h4>` + entries.map(r => {
        const type = r._kb_type || r.type || 'entry';
        const score = r.score != null ? `<span class="kb-score">${(r.score * 100).toFixed(0)}%</span>` : '';
        return `<div class="kb-entry">
            <span class="kb-type-badge">${escapeHtml(type)}</span>
            <strong>${escapeHtml(r.id || r.name || '')}</strong>${score}
            <div class="mf-meta">${escapeHtml(r.title || r.name || r.cve_id || '')}</div>
            <div class="mf-evidence">${escapeHtml((r.description || r.summary || '').slice(0, 300))}</div>
        </div>`;
    }).join('');
}

function showThinking(show) {
    const indicator = document.getElementById('thinking-indicator');
    const sendBtn = document.getElementById('send-btn');
    if (show) {
        indicator.classList.remove('hidden');
        sendBtn.disabled = true;
    } else {
        indicator.classList.add('hidden');
        sendBtn.disabled = false;
    }
}

// ═══════════════════════════════════════════════════════════════
// Tools Panel
// ═══════════════════════════════════════════════════════════════
async function loadTools() {
    try {
        const res = await fetch('/api/tools');
        const data = await res.json();
        renderTools(data);
    } catch (e) {
        console.error('Tools load failed:', e);
    }
}

function renderTools(toolsByCategory) {
    const list = document.getElementById('tool-list');
    list.innerHTML = '';

    for (const [category, tools] of Object.entries(toolsByCategory)) {
        for (const tool of tools) {
            if (currentCategory !== 'all' && tool.category !== currentCategory) continue;
            const item = document.createElement('div');
            item.className = `tool-item ${tool.installed ? 'installed' : 'missing'}`;
            item.innerHTML = `
                <div>
                    <div class="tool-name">${escapeHtml(tool.name)}</div>
                    <div class="tool-category">${escapeHtml(tool.category)} ${tool.installed ? '✓' : '✗'}</div>
                </div>
            `;
            item.onclick = () => showToolDialog(tool);
            list.appendChild(item);
        }
    }
}

async function loadQuickCommands() {
    try {
        const res = await fetch('/api/tools/quick-commands');
        const commands = await res.json();
        const list = document.getElementById('quick-commands-list');
        list.innerHTML = '';
        for (const cmd of commands.slice(0, 12)) {
            const btn = document.createElement('button');
            btn.className = 'quick-cmd';
            btn.innerHTML = `<span class="cmd-name">${escapeHtml(cmd.name)}</span><span class="cmd-desc">${escapeHtml(cmd.description)}</span>`;
            btn.onclick = () => {
                if (cmd.note) {
                    addSystemMessage(`ℹ️ ${escapeHtml(cmd.note)}`);
                } else {
                    const argsJson = JSON.stringify(cmd.args_template).replace(/TARGET/g, '192.168.1.1');
                    sendQuickPrompt(`Execute tool "${escapeHtml(cmd.tool)}" with args: ${argsJson}`);
                }
            };
            list.appendChild(btn);
        }
    } catch (e) {
        console.error('Quick commands load failed:', e);
    }
}

async function loadAttackChains() {
    try {
        const res = await fetch('/api/tools/attack-chains');
        const chains = await res.json();
        const list = document.getElementById('attack-chains-list');
        list.innerHTML = '';
        for (const chain of chains) {
            const el = document.createElement('div');
            el.className = 'attack-chain';
            el.innerHTML = `
                <div class="chain-name">${escapeHtml(chain.name)}</div>
                <div class="chain-desc">${escapeHtml(chain.description)}</div>
            `;
            el.onclick = () => {
                sendQuickPrompt(`Run attack chain "${escapeHtml(chain.name)}": ${escapeHtml(chain.description)}`);
            };
            list.appendChild(el);
        }
    } catch (e) {
        console.error('Attack chains load failed:', e);
    }
}

function showToolDialog(tool) {
    const prompt = `Execute tool "${escapeHtml(tool.name)}" against target. Describe the target and parameters.`;
    document.getElementById('chat-input').value = prompt;
    document.getElementById('chat-input').focus();
}

function initTabs() {
    document.querySelectorAll('.tool-tabs .tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tool-tabs .tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            currentCategory = tab.dataset.category;
            loadTools();
        });
    });
}

// ═══════════════════════════════════════════════════════════════
// Workflows (v3.0)
// ═══════════════════════════════════════════════════════════════
async function loadWorkflows() {
    try {
        const res = await fetch('/api/workflows');
        const workflows = await res.json();
        const list = document.getElementById('workflows-list');
        if (workflows.length === 0) {
            list.innerHTML = '<p class="muted">No workflow templates found.</p>';
            return;
        }
        list.innerHTML = workflows.map(w => `
            <div class="attack-chain">
                <div class="chain-name">${escapeHtml(w.name)}</div>
                <div class="chain-desc">${escapeHtml(w.category)} · ${w.steps_count} steps ${w.cutting_edge ? '· 🔥 Cutting-edge' : ''}</div>
            </div>
        `).join('');

        // Populate modal select
        const select = document.getElementById('wf-select');
        if (select) {
            select.innerHTML = '<option value="">Select a workflow...</option>' +
                workflows.map(w => `<option value="${escapeHtml(w.name)}">${escapeHtml(w.name)}</option>`).join('');
        }
    } catch (e) {
        console.error('Workflows load failed:', e);
    }
}

function openWorkflowModal() {
    document.getElementById('workflow-modal').classList.remove('hidden');
    document.getElementById('wf-select').addEventListener('change', onWorkflowSelect);
}

function closeWorkflowModal() {
    document.getElementById('workflow-modal').classList.add('hidden');
}

async function onWorkflowSelect() {
    const name = document.getElementById('wf-select').value;
    const runBtn = document.getElementById('wf-run-btn');
    if (!name) {
        document.getElementById('wf-details').classList.add('hidden');
        runBtn.disabled = true;
        return;
    }
    // Fetch the summary to show details + build variable inputs
    const res = await fetch('/api/workflows');
    const workflows = await res.json();
    const wf = workflows.find(w => w.name === name);
    if (!wf) return;

    const details = document.getElementById('wf-details');
    details.classList.remove('hidden');
    details.innerHTML = `
        <div class="wf-desc">${escapeHtml(wf.description)}</div>
        <div class="wf-steps">Steps: ${wf.steps.map(s => escapeHtml(s)).join(' → ')}</div>
        ${wf.cutting_edge ? '<div class="wf-badge">🔥 Cutting-edge attack</div>' : ''}
    `;

    // Build variable inputs
    const varsBox = document.getElementById('wf-vars');
    if (wf.variables && wf.variables.length) {
        varsBox.innerHTML = wf.variables.map(v => `
            <div class="wf-var-row">
                <label class="modal-label" for="wf-var-${escapeHtml(v)}">${escapeHtml(v)}</label>
                <input class="modal-input" id="wf-var-${escapeHtml(v)}" placeholder="${escapeHtml(v)}" data-var="${escapeHtml(v)}">
            </div>
        `).join('');
    } else {
        varsBox.innerHTML = '<input class="modal-input" id="wf-var-target" placeholder="target" data-var="target">';
    }
    runBtn.disabled = false;
}

async function runWorkflowFromModal() {
    const name = document.getElementById('wf-select').value;
    if (!name) return;

    // Collect variables
    const variables = {};
    document.querySelectorAll('#wf-vars input[data-var]').forEach(inp => {
        if (inp.value.trim()) variables[inp.dataset.var] = inp.value.trim();
    });
    // Add target from chat if not provided
    if (!variables.target) variables.target = '192.168.1.1';

    // Multi-target mode: comma-separated targets → concurrent execution
    const targetsField = document.getElementById('wf-targets');
    const targets = (targetsField?.value || '').split(',').map(t => t.trim()).filter(Boolean);

    closeWorkflowModal();
    if (targets.length > 1) {
        addSystemMessage(`🚀 Launching multi-target workflow: ${escapeHtml(name)} against ${targets.length} targets (concurrent)`);
        socket.emit('run_multi_workflow', { workflow: name, targets, variables });
    } else {
        if (targets.length === 1) variables.target = targets[0];
        addSystemMessage(`🚀 Launching workflow: ${escapeHtml(name)}`);
        socket.emit('run_workflow', { workflow: name, variables });
    }
}

async function generateWorkflowFromModal() {
    const objective = document.getElementById('wf-objective').value.trim();
    if (!objective) return;
    const btn = document.getElementById('wf-gen-btn');
    const resultBox = document.getElementById('wf-gen-result');
    btn.disabled = true;
    btn.textContent = '🧠 Generating...';
    resultBox.classList.remove('hidden');
    resultBox.innerHTML = '<p class="muted">Asking the local LLM to design a workflow...</p>';
    try {
        const res = await fetch('/api/workflows/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ objective }),
        });
        const data = await res.json();
        if (data.error) {
            resultBox.innerHTML = `<p class="muted">❌ ${escapeHtml(data.error)}</p>`;
            if (data.validation_errors) {
                resultBox.innerHTML += `<div class="wf-steps">${data.validation_errors.map(e => escapeHtml(e)).join('<br>')}</div>`;
            }
        } else {
            resultBox.innerHTML = `
                <div class="wf-desc"><b>${escapeHtml(data.name)}</b> — ${escapeHtml(data.description || '')}</div>
                <div class="wf-steps">Steps: ${(data.steps || []).map(s => escapeHtml(s)).join(' → ')}</div>
                <div class="wf-badge">✨ Generated by LLM · saved as template</div>
            `;
            // Refresh workflow list + select the new template
            await loadWorkflows();
            const select = document.getElementById('wf-select');
            if (select) select.value = data.name;
            onWorkflowSelect();
            document.getElementById('wf-run-btn').disabled = false;
        }
    } catch (e) {
        resultBox.innerHTML = `<p class="muted">❌ Generation failed: ${escapeHtml(e.message)}</p>`;
    } finally {
        btn.disabled = false;
        btn.textContent = '✨ Generate with LLM';
    }
}

function handleWorkflowGenerated(data) {
    // WebSocket path: the payload is a GENERATION summary (name, steps =
    // list of names), NOT a workflow result — handle it as such.
    if (data.error) {
        addSystemMessage(`❌ Generation failed: ${escapeHtml(data.error)}`);
        if (data.validation_errors) {
            addSystemMessage(data.validation_errors.map(e => `⚠️ ${escapeHtml(e)}`).join('<br>'));
        }
        return;
    }
    addSystemMessage(`✨ Generated workflow: ${escapeHtml(data.name)} — ${(data.steps || []).length} steps`);
    loadWorkflows();
}

function handleWorkflowResult(data) {
    if (data.error) {
        addSystemMessage(`❌ Workflow error: ${escapeHtml(data.error)}`);
        return;
    }
    const status = (data.status || 'unknown').toUpperCase();
    addSystemMessage(`🏁 Workflow finished: ${status} (${data.completed_steps || 0}/${data.total_steps || 0} steps)`);
    if (data.steps) {
        for (const s of data.steps) {
            const icon = s.status === 'success' ? '✅' : (s.gate_failed ? '⛔' : '⚠️');
            addSystemMessage(`${icon} ${escapeHtml(s.step)} — ${s.status} (attempts=${s.attempts})`);
        }
    }
    // Phase 7: correlate findings into attack paths + remediation
    if (data.findings && data.findings.length) {
        renderFindings(data.findings);
        correlateFindings(data.findings);
        evaluateTacticsFromFindings(data.findings);
    }
}

function handleMultiWorkflowResult(data) {
    if (data.error) {
        addSystemMessage(`❌ Multi-target error: ${escapeHtml(data.error)}`);
        return;
    }
    const status = (data.status || 'unknown').toUpperCase();
    addSystemMessage(`🏁 Multi-target workflow finished: ${status} — ${(data.targets || []).length} targets`);
    if (data.per_target) {
        for (const [target, r] of Object.entries(data.per_target)) {
            const icon = (r.status === 'complete' || r.status === 'partial') ? '✅' : '❌';
            addSystemMessage(`${icon} ${escapeHtml(target)} — ${r.status} (${r.steps_count}/${r.total_steps} steps)${r.error ? ' — ' + escapeHtml(r.error) : ''}`);
        }
    }
    if (data.pooled_findings && data.pooled_findings.length) {
        renderFindings(data.pooled_findings);
        correlateFindings(data.pooled_findings);
        evaluateTacticsFromFindings(data.pooled_findings);
    }
}

async function correlateFindings(findings) {
    try {
        const res = await fetch('/api/correlate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ findings }),
        });
        const data = await res.json();
        if (data.paths && data.paths.length) {
            renderAttackPaths(data.paths);
        }
    } catch (e) {
        console.error('Correlation failed:', e);
    }
}

function renderFindings(findings) {
    const el = document.getElementById('findings-list');
    if (!el) return;
    el.innerHTML = findings.slice(0, 50).map(f => `
        <div class="plan-step">
            <span class="plan-step-num sev-${escapeHtml(f.severity || 'info')}">${escapeHtml((f.severity || 'info').slice(0, 1).toUpperCase())}</span>
            <div>
                <strong>${escapeHtml(f.title || '')}</strong>
                ${f.target ? `<span class="muted"> · ${escapeHtml(f.target)}</span>` : ''}
                <div class="plan-step-desc">${escapeHtml(f.evidence || '')}</div>
                <code>${escapeHtml(f.source_tool || '')}</code>
            </div>
        </div>
    `).join('');
}

function renderAttackPaths(paths) {
    const el = document.getElementById('findings-list');
    if (!el) return;
    const pathHtml = paths.map(p => `
        <div class="attack-path">
            <div class="attack-path-head">
                <span class="plan-step-num sev-${escapeHtml(p.severity || 'medium')}">${escapeHtml((p.severity || 'medium').toUpperCase())}</span>
                <strong>${escapeHtml(p.title)}</strong>
                <span class="muted">score ${p.score || '?'}</span>
            </div>
            <div class="plan-step-desc">${(p.remediation || []).map(r => `• ${escapeHtml(r)}`).join('<br>')}</div>
        </div>
    `).join('');
    el.innerHTML = `<div class="path-header">🔗 Correlated Attack Paths</div>${pathHtml}${el.innerHTML}`;
}

// ═══════════════════════════════════════════════════════════════
// Tactical Suggestions Feed (Live)
// ═══════════════════════════════════════════════════════════════

const TACTICAL_COLORS = {
    'recon': 'var(--accent-cyan)',
    'vuln': 'var(--accent-orange)',
    'web': 'var(--accent-green)',
    'password': 'var(--accent-yellow)',
    'exploit': 'var(--accent-red)',
    'postex': 'var(--accent-purple)',
};

const TACTICAL_ICONS = {
    'nikto_scan': '🌐', 'hydra_brute': '🔓', 'enum4linux': '📁',
    'sqlmap_scan': '💉', 'gobuster': '📂', 'wpscan': '🔫',
    'hashcat_crack': '🔑', 'impacket_tools': '🦾',
    'msfvenom_payload': '💥', 'nuclei': '🔍', 'crackmapexec_exec': '🧩',
    'bloodhound_analyze': '🦇', 'socat': '🔌', 'curl_request': '📡',
};

function handleTacticalSuggestions(data) {
    const suggestions = data.suggestions || [];
    if (!suggestions.length) return;

    // Track previous count for new-suggestion notification
    const prevCount = tacticalSuggestions.length;

    // Dedup: merge new suggestions with existing, keep highest confidence
    for (const s of suggestions) {
        const key = s.tool + ':' + JSON.stringify(s.args);
        const existing = tacticalSuggestions.find(e => e.tool + ':' + JSON.stringify(e.args) === key);
        if (!existing) {
            tacticalSuggestions.push(s);
        } else if (s.confidence > existing.confidence) {
            Object.assign(existing, s);
        }
    }

    // Sort by confidence descending
    tacticalSuggestions.sort((a, b) => b.confidence - a.confidence);

    // Update tab badge count
    updateTacticsBadge();

    // Add system message notification for new suggestions only
    const newCount = tacticalSuggestions.length - prevCount;
    if (newCount > 0) {
        const newAutoCount = suggestions.filter(s => s.auto_run).length;
        addSystemMessage(`🎯 Tactical engine: ${newCount} new suggestion${newCount > 1 ? 's' : ''}` +
            (newAutoCount > 0 ? ` (${newAutoCount} auto-run)` : ''));
    }

    // Render the full tactical feed
    renderTacticalFeed();
}

function evaluateTacticsFromFindings(findings) {
    // Client-side: send findings to server for tactical evaluation
    if (findings && findings.length) {
        const context = sessionId ? { host: sessionId } : {};
        fetch('/api/tactics/suggest', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ findings, context }),
        })
        .then(res => res.json())
        .then(data => {
            if (data.suggestions && data.suggestions.length) {
                handleTacticalSuggestions({ suggestions: data.suggestions });
            }
        })
        .catch(e => console.error('Tactical evaluation failed:', e));
    }
}

function updateTacticsBadge() {
    const tabs = document.querySelectorAll('.results-tabs .tab');
    for (const t of tabs) {
        if (t.textContent.includes('Tactics')) {
            t.textContent = tacticalSuggestions.length > 0
                ? `🎯 Tactics (${tacticalSuggestions.length})`
                : '🎯 Tactics';
            break;
        }
    }
}

function renderTacticalFeed() {
    const el = document.getElementById('tactics-feed');
    if (!el) return;

    updateTacticsBadge();

    if (!tacticalSuggestions.length) {
        el.innerHTML = '<p class="muted">No tactical suggestions yet. Run a scan or workflow to see AI-powered next actions here.</p>';
        return;
    }

    el.innerHTML = tacticalSuggestions.map((s, i) => {
        const confPct = Math.round(s.confidence * 100);
        const confColor = s.auto_run ? 'var(--accent-green)' :
                          s.confidence >= 0.5 ? 'var(--accent-yellow)' : 'var(--accent-cyan)';
        const icon = TACTICAL_ICONS[s.tool] || '⚔️';
        const toolColor = TACTICAL_COLORS[s.tool.split('_')[0]] || 'var(--accent-cyan)';

        return `
            <div class="tactical-card ${s.auto_run ? 'auto-run' : ''}" id="tac-${i}">
                <div class="tactical-header">
                    <div class="tactical-tool">
                        <span class="tactical-icon">${icon}</span>
                        <span class="tactical-tool-name" style="color:${toolColor}">${escapeHtml(s.tool)}</span>
                        ${s.auto_run ? '<span class="tactical-badge auto">⚡ AUTO</span>' : '<span class="tactical-badge suggest">💡 SUGGEST</span>'}
                    </div>
                    <div class="tactical-confidence">
                        <div class="conf-bar">
                            <div class="conf-fill" style="width:${confPct}%;background:${confColor}"></div>
                        </div>
                        <span class="conf-label" style="color:${confColor}">${confPct}%</span>
                    </div>
                </div>
                <div class="tactical-reasoning">${escapeHtml(s.reasoning)}</div>
                <div class="tactical-triggered">Triggered by: <code>${escapeHtml(s.triggered_by)}</code></div>
                <div class="tactical-args">
                    <code>${escapeHtml(JSON.stringify(s.args))}</code>
                </div>
                <div class="tactical-actions">
                    <button class="tactical-btn execute" onclick="executeTactical(${i})">
                        ▶ Execute Now
                    </button>
                    <button class="tactical-btn dismiss" onclick="dismissTactical(${i})">
                        ✕ Dismiss
                    </button>
                </div>
            </div>
        `;
    }).join('');
}

function executeTactical(index) {
    const s = tacticalSuggestions[index];
    if (!s) return;

    // Prevent double-execution
    const execKey = s.tool + ':' + JSON.stringify(s.args);
    if (tacticalExecuting.has(execKey)) return;
    tacticalExecuting.add(execKey);

    const card = document.getElementById(`tac-${index}`);
    if (card) {
        card.classList.add('executing');
        const btn = card.querySelector('.tactical-btn.execute');
        if (btn) {
            btn.disabled = true;
            btn.textContent = '⏳ Running...';
        }
    }

    addSystemMessage(`🎯 Executing tactical action: ${s.tool} — ${escapeHtml(s.reasoning)}`);
    socket.emit('execute_tactical', {
        tool: s.tool,
        args: s.args,
        session_id: sessionId,
    });
}

function dismissTactical(index) {
    tacticalSuggestions.splice(index, 1);
    renderTacticalFeed();
}

function handleTacticalResult(data) {
    const result = data.result || {};
    if (data.error) {
        addSystemMessage(`❌ Tactical failed: ${escapeHtml(data.error)}`);
        renderTacticalFeed();
        return;
    }
    const success = result.status === 'success' || result.exit_code === 0;
    const icon = success ? '✅' : '❌';

    addSystemMessage(`${icon} Tactical execution: ${data.tool} — ${success ? 'completed' : 'failed (exit ' + (result.exit_code ?? '?') + ')'}`);

    // If the tactical action produced output, show it
    if (result.summary || result.stdout) {
        const output = result.summary || (result.stdout ? result.stdout.slice(0, 500) : 'No output');
        addAssistantMessage(`**${data.tool} output:**\n\n${output}`);
    }

    // Remove the executed suggestion from the feed
    const idx = tacticalSuggestions.findIndex(s => s.tool === data.tool);
    if (idx >= 0) {
        tacticalSuggestions.splice(idx, 1);
    }
    // Clear executing guard
    tacticalExecuting.delete(data.tool + ':' + JSON.stringify(data.args || {}));
    renderTacticalFeed();
}

// ═══════════════════════════════════════════════════════════════
// Workflow Chain Graph (Phase 4)
// ═══════════════════════════════════════════════════════════════
async function populateGraphSelect() {
    try {
        const res = await fetch('/api/workflows');
        const workflows = await res.json();
        const sel = document.getElementById('graph-wf-select');
        if (!sel) return;
        sel.innerHTML = '<option value="">Select workflow to visualize...</option>' +
            workflows.map(w => `<option value="${escapeHtml(w.name)}">${escapeHtml(w.name)}</option>`).join('');
    } catch (e) {
        console.error('Graph select load failed:', e);
    }
}

let currentGraphTaskId = null;
let currentGraphData = null;

async function renderWorkflowGraph() {
    const sel = document.getElementById('graph-wf-select');
    const name = sel ? sel.value : '';
    const content = document.getElementById('graph-content');
    if (!name) {
        content.innerHTML = '<p class="muted">Pick a workflow to see its attack chain graph.</p>';
        return;
    }
    content.innerHTML = '<p class="muted">Rendering chain graph...</p>';
    try {
        let url = `/api/workflows/graph/${encodeURIComponent(name)}`;
        if (currentGraphTaskId) url += `?task_id=${encodeURIComponent(currentGraphTaskId)}`;
        const res = await fetch(url);
        const graph = await res.json();
        if (graph.error) {
            content.innerHTML = `<p class="muted">${escapeHtml(graph.error)}</p>`;
            return;
        }
        currentGraphData = graph;
        // Also load task list for this workflow to show as selector
        await loadGraphTaskList(name);
        content.innerHTML = drawChainGraph(graph);
    } catch (e) {
        content.innerHTML = `<p class="muted">Graph load failed: ${escapeHtml(e.message)}</p>`;
    }
}

async function loadGraphTaskList(workflowName) {
    try {
        const res = await fetch(`/api/workflows/${encodeURIComponent(workflowName)}/status`);
        const data = await res.json();
        const tasks = data.tasks || [];
        const taskSel = document.getElementById('graph-task-select');
        if (!taskSel) return;
        if (tasks.length === 0) {
            taskSel.innerHTML = '<option value="">No completed runs</option>';
            return;
        }
        taskSel.innerHTML = '<option value="">Template view (no state)</option>' +
            tasks.map(t => `<option value="${escapeHtml(t.task_id)}" ${t.task_id === currentGraphTaskId ? 'selected' : ''}>${escapeHtml(t.task_id)} — ${escapeHtml(t.status || 'unknown')}</option>`).join('');
    } catch (e) { /* silent */ }
}

function onGraphTaskChange() {
    const sel = document.getElementById('graph-task-select');
    currentGraphTaskId = sel && sel.value ? sel.value : null;
    renderWorkflowGraph();
}

function drawChainGraph(graph) {
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];
    if (!nodes.length) return '<p class="muted">No steps in this workflow.</p>';

    // Build id → index map
    const idIdx = {};
    nodes.forEach((n, i) => idIdx[n.id] = i);

    // Collect chain value labels for edges
    const chainLabels = {};
    edges.filter(e => e.kind === 'chain').forEach(e => {
        const fromNode = nodes.find(n => n.id === e.from);
        if (fromNode && fromNode.deps) {
            // Find extract vars that flow from 'from' to 'to'
            // We'll label the edge with the variable name
            chainLabels[e.from + '→' + e.to] = e.chain_var || '';
        }
    });

    // Column layout: sequential flow left→right; chain edges may pull right
    const COLS = nodes.length;
    const NODE_W = 200, NODE_H = 72, GX = 70, GY = 110;
    const W = COLS * (NODE_W + GX) + GX;
    const H = 2 * (NODE_H + GY) + 60;

    const colors = {
        pending: '#5b6b7a', success: '#22c55e', failed: '#ef4444',
        blocked: '#ef4444', running: '#f59e0b', not_started: '#5b6b7a',
    };
    const statusIcons = {
        success: '✅', failed: '❌', blocked: '🚫', running: '⏳', pending: '⏸️',
    };

    // Position: try to place nodes with chain deps on the same row
    const pos = {};
    const rowOf = {};
    nodes.forEach((n, i) => {
        rowOf[n.id] = 0;
    });
    // Chain deps pull target up to dep's row
    edges.forEach(e => {
        if (e.kind === 'chain' && idIdx[e.to] !== undefined && idIdx[e.from] !== undefined) {
            rowOf[e.to] = Math.max(rowOf[e.to], rowOf[e.from]);
        }
    });
    nodes.forEach((n, i) => {
        pos[n.id] = { x: GX + i * (NODE_W + GX), y: 40 + rowOf[n.id] * (NODE_H + GY) };
    });

    let svg = `<svg viewBox="0 0 ${W} ${Math.max(H, 220)}" class="chain-svg" xmlns="http://www.w3.org/2000/svg">`;
    svg += `<defs>
        <marker id="arrow-seq" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#7c8a99"/></marker>
        <marker id="arrow-chain" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M0,0 L10,5 L0,10 Z" fill="#00ff88"/></marker>
        <filter id="glow-green"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
        <filter id="glow-red"><feGaussianBlur stdDeviation="2" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    </defs>`;

    // Draw edges first (behind nodes)
    for (const e of edges) {
        const a = pos[e.from], b = pos[e.to];
        if (!a || !b) continue;
        const isChain = e.kind === 'chain';
        const x1 = a.x + NODE_W / 2, y1 = a.y + NODE_H / 2;
        const x2 = b.x + NODE_W / 2, y2 = b.y + NODE_H / 2;
        const stroke = isChain ? '#00ff88' : '#7c8a99';
        const dash = isChain ? '8,5' : 'none';
        const marker = isChain ? 'url(#arrow-chain)' : 'url(#arrow-seq)';
        const sw = isChain ? 2.5 : 1.5;
        const filter = isChain ? 'filter="url(#glow-green)"' : '';
        const curve = isChain
            ? `M ${x1} ${y1} C ${x1 + 60} ${y1}, ${x2 - 60} ${y2}, ${x2} ${y2}`
            : `M ${x1} ${y1} L ${x2} ${y2}`;
        svg += `<path d="${curve}" fill="none" stroke="${stroke}" stroke-width="${sw}" stroke-dasharray="${dash}" marker-end="${marker}" ${filter}>
            <title>${isChain ? '🔗 Exploit chain: extracted data flows' : '➡️ Sequential step'} ${escapeXml(e.from)} → ${escapeXml(e.to)}</title></path>`;
        // Chain value label on the edge
        if (isChain) {
            const mx = (x1 + x2) / 2, my = (y1 + y2) / 2 - 12;
            const label = e.chain_var || '';
            if (label) {
                svg += `<rect x="${mx - 30}" y="${my - 10}" width="60" height="16" rx="4" fill="#0d1620" stroke="#00ff88" stroke-width="0.5" opacity="0.9"/>
                <text x="${mx}" y="${my + 2}" text-anchor="middle" fill="#00ff88" font-size="9" font-family="DejaVu Sans Mono, monospace">${escapeXml(label.slice(0, 14))}</text>`;
            }
        }
    }

    // Draw nodes
    for (const n of nodes) {
        const p = pos[n.id];
        const fill = colors[n.status] || colors.pending;
        const gate = n.gate ? '⛔ ' : '';
        const icon = statusIcons[n.status] || '❓';
        const isClickable = currentGraphTaskId && (n.status === 'success' || n.status === 'failed');
        const clickAttr = isClickable ? `onclick="showGraphNodeDetail('${escapeXml(n.id)}')" style="cursor:pointer"` : '';
        const hoverFilter = n.status === 'failed' ? 'filter="url(#glow-red)"' : '';
        svg += `<g ${clickAttr}>
            <rect x="${p.x}" y="${p.y}" width="${NODE_W}" height="${NODE_H}" rx="10"
                  fill="#0d1620" stroke="${fill}" stroke-width="2" ${hoverFilter}/>
            <text x="${p.x + 12}" y="${p.y + 22}" fill="${fill}" font-size="13" font-weight="bold">${n.index}. ${gate}${escapeXml(n.tool)}</text>
            <text x="${p.x + 12}" y="${p.y + 40}" fill="#94a3b8" font-size="10" font-family="DejaVu Sans Mono, monospace">${escapeXml(n.id)}</text>
            <text x="${p.x + 12}" y="${p.y + 56}" fill="${fill}" font-size="10">${icon} ${escapeXml(String(n.status).toUpperCase())}</text>
            ${n.gate ? `<text x="${p.x + NODE_W - 12}" y="${p.y + 22}" fill="#f59e0b" font-size="12" text-anchor="end">GATE</text>` : ''}
            <title>${escapeXml(n.description || n.id)}${isClickable ? '\n\nClick to view sandbox output' : ''}</title>
        </g>`;
    }

    svg += '</svg>';

    // Legend + summary
    const fs = graph.findings_summary || {};
    const summary = Object.keys(fs).filter(k => fs[k] > 0)
        .map(k => `<span class="legend-item sev-${k}">${k}: ${fs[k]}</span>`).join('');
    return `<div class="graph-wrap">
        <div class="graph-status">Status: <b>${escapeHtml(graph.status || 'not_started')}</b> · Findings: ${summary || 'none yet'}${currentGraphTaskId ? ' · <span class="graph-task-label">Task: ' + escapeHtml(currentGraphTaskId) + '</span>' : ''}</div>
        ${svg}
        <div class="graph-legend">
            <span class="legend-item"><span class="dot seq"></span> Sequential</span>
            <span class="legend-item"><span class="dot chain"></span> Exploit chain (data flow)</span>
            <span class="legend-item"><span class="dot pend"></span> Pending</span>
            <span class="legend-item"><span class="dot succ"></span> Success</span>
            <span class="legend-item"><span class="dot fail"></span> Failed</span>
            <span class="legend-item"><span class="dot gate"></span> ⛔ Gate step</span>
            ${currentGraphTaskId ? '<span class="legend-item"><span class="dot clickable"></span> Click node for sandbox output</span>' : ''}
        </div>
        <div id="graph-node-detail"></div>
    </div>`;
}

async function showGraphNodeDetail(stepName) {
    const detailEl = document.getElementById('graph-node-detail');
    if (!detailEl || !currentGraphTaskId) return;
    detailEl.innerHTML = '<div class="graph-detail-loading">⏳ Loading sandbox output for ' + escapeHtml(stepName) + '...</div>';
    try {
        const res = await fetch(`/api/workflows/${encodeURIComponent(currentGraphTaskId)}/sandbox/${encodeURIComponent(stepName)}`);
        const data = await res.json();
        if (data.error) {
            detailEl.innerHTML = `<div class="graph-detail-error">❌ ${escapeHtml(data.error)}</div>`;
            return;
        }
        let html = `<div class="graph-detail-panel">
            <div class="graph-detail-header">
                <h4>📋 ${escapeHtml(stepName)} — Sandbox Output</h4>
                <button class="btn-icon" onclick="document.getElementById('graph-node-detail').innerHTML=''">✕</button>
            </div>`;
        if (data.stdout) {
            html += `<div class="graph-detail-section">
                <div class="graph-detail-label">STDOUT (${data.stdout_size} bytes)</div>
                <pre class="graph-detail-pre">${escapeHtml(data.stdout)}</pre>
            </div>`;
        }
        if (data.stderr) {
            html += `<div class="graph-detail-section">
                <div class="graph-detail-label">STDERR (${data.stderr_size} bytes)</div>
                <pre class="graph-detail-pre stderr">${escapeHtml(data.stderr)}</pre>
            </div>`;
        }
        if (data.log_excerpt) {
            html += `<div class="graph-detail-section">
                <div class="graph-detail-label">WORKFLOW LOG (related lines)</div>
                <pre class="graph-detail-pre log">${escapeHtml(data.log_excerpt)}</pre>
            </div>`;
        }
        if (!data.stdout && !data.stderr && !data.log_excerpt) {
            html += '<div class="graph-detail-section muted">No sandbox output found for this step.</div>';
        }
        html += '</div>';
        detailEl.innerHTML = html;
        detailEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (e) {
        detailEl.innerHTML = `<div class="graph-detail-error">❌ Failed to load: ${escapeHtml(e.message)}</div>`;
    }
}

function escapeXml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

// ═══════════════════════════════════════════════════════════════
// Correlation Attack Graph (v5.3) — force-directed SVG visualizer
// ═══════════════════════════════════════════════════════════════
let attackGraphData = null;
let attackGraphSource = null;      // 'task' | 'campaign'
let attackGraphView = { scale: 1, tx: 0, ty: 0, dirty: false };
let attackGraphLayoutCache = null; // {nodes, edges, pos, W, H} for minimap reset

const ATTACK_SEV_COLORS = {
    critical: '#ef4444', high: '#f97316', medium: '#f59e0b',
    low: '#84cc16', info: '#64748b', unknown: '#94a3b8',
};

async function loadAttackGraphSources() {
    try {
        const [tasksRes, campsRes] = await Promise.all([
            fetch('/api/tasks/all'),
            fetch('/api/campaigns'),
        ]);
        const tasks = Array.isArray(await tasksRes.json()) ? await tasksRes.json() : [];
        const camps = Array.isArray(await campsRes.json()) ? await campsRes.json() : [];
        const taskSel = document.getElementById('attackgraph-task-select');
        const campSel = document.getElementById('attackgraph-campaign-select');
        if (taskSel) {
            taskSel.innerHTML = '<option value="">Select task run...</option>' +
                tasks.map(t => `<option value="${escapeHtml(t.task_id)}">${escapeHtml(t.task_id)} — ${escapeHtml(t.status || 'unknown')} (${t.findings_count || 0} findings)</option>`).join('');
        }
        if (campSel) {
            campSel.innerHTML = '<option value="">Select campaign...</option>' +
                camps.map(c => `<option value="${escapeHtml(c.id)}">${escapeHtml(c.name || c.id)} — ${escapeHtml(c.status)} (${c.findings_total || 0} findings)</option>`).join('');
        }
    } catch (e) { /* silent */ }
}

function onAttackGraphTaskChange() {
    const campSel = document.getElementById('attackgraph-campaign-select');
    if (campSel) campSel.value = '';
    attackGraphSource = 'task';
    renderAttackGraph();
}

function onAttackGraphCampaignChange() {
    const taskSel = document.getElementById('attackgraph-task-select');
    if (taskSel) taskSel.value = '';
    attackGraphSource = 'campaign';
    renderAttackGraph();
}

async function renderAttackGraph() {
    const canvas = document.getElementById('attackgraph-canvas');
    if (!canvas) return;
    const taskSel = document.getElementById('attackgraph-task-select');
    const campSel = document.getElementById('attackgraph-campaign-select');
    const taskId = taskSel ? taskSel.value : '';
    const campId = campSel ? campSel.value : '';
    if (!taskId && !campId) {
        canvas.innerHTML = '<p class="muted">Pick a task run or campaign to visualize its correlated attack paths.</p>';
        return;
    }
    const q = taskId ? `task_id=${encodeURIComponent(taskId)}` : `campaign_id=${encodeURIComponent(campId)}`;
    canvas.innerHTML = '<p class="muted">Correlating findings &amp; laying out attack graph…</p>';
    try {
        const res = await fetch(`/api/correlation/graph?${q}`);
        const data = await res.json();
        if (data.error) {
            canvas.innerHTML = `<p class="muted">${escapeHtml(data.error)}</p>`;
            return;
        }
        attackGraphData = data;
        drawAttackGraph(data);
    } catch (e) {
        canvas.innerHTML = `<p class="muted">Attack graph failed: ${escapeHtml(e.message)}</p>`;
    }
}

function drawAttackGraph(data) {
    const graph = data.graph || {};
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];
    const canvas = document.getElementById('attackgraph-canvas');
    const legendEl = document.getElementById('attackgraph-legend');
    if (!nodes.length) {
        canvas.innerHTML = '<p class="muted">No correlated findings to visualize for this source.</p>';
        if (legendEl) legendEl.classList.add('hidden');
        return;
    }

    // ── Force-directed layout (hand-rolled; no CDN — offline-first) ──
    const W = 960, H = 540;
    const pos = forceLayout(nodes, edges, W, H);

    const sevColor = n => ATTACK_SEV_COLORS[n.severity] || ATTACK_SEV_COLORS.unknown;
    const isPath = n => n.type === 'path';
    const nodeR = n => isPath(n) ? 26 : 15;

    let svg = `<svg id="attackgraph-svg" width="100%" height="${H}" viewBox="0 0 ${W} ${H}" class="attackgraph-svg" xmlns="http://www.w3.org/2000/svg">`;
    svg += `<defs><marker id="ag-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 Z" fill="#7c8a99"/></marker></defs>`;
    svg += `<rect width="${W}" height="${H}" fill="#0b1119" rx="8"/>`;
    svg += `<g id="attackgraph-world">`;

    // Edges (behind nodes)
    for (const e of edges) {
        const a = pos[e.source], b = pos[e.target];
        if (!a || !b) continue;
        const chain = e.type === 'chain';
        const stroke = chain ? '#00ff88' : '#7c8a99';
        const dash = chain ? '6,4' : 'none';
        const curve = chain
            ? `M ${a.x} ${a.y} C ${a.x + 50} ${a.y}, ${b.x - 50} ${b.y}, ${b.x} ${b.y}`
            : `M ${a.x} ${a.y} L ${b.x} ${b.y}`;
        svg += `<path d="${curve}" fill="none" stroke="${stroke}" stroke-width="${chain ? 2 : 1.2}" stroke-dasharray="${dash}" marker-end="url(#ag-arrow)"><title>${chain ? '🔗 chained finding' : 'finding → path'} ${escapeXml(e.source)} → ${escapeXml(e.target)}</title></path>`;
    }

    // Nodes
    for (const n of nodes) {
        const p = pos[n.id];
        const color = sevColor(n);
        const r = nodeR(n);
        const label = n.label || n.id;
        const short = label.length > 26 ? label.slice(0, 25) + '…' : label;
        const pathIcon = isPath(n) ? '🎯 ' : '';
        const click = `onclick="attackGraphNodeClick('${escapeXml(n.id)}')"`;
        svg += `<g ${click} style="cursor:pointer">`;
        // halo for path nodes
        if (isPath(n)) {
            svg += `<circle cx="${p.x}" cy="${p.y}" r="${r + 5}" fill="none" stroke="${color}" stroke-width="1" opacity="0.35"/>`;
        }
        svg += `<circle cx="${p.x}" cy="${p.y}" r="${r}" fill="#0d1620" stroke="${color}" stroke-width="2.5"/>`;
        svg += `<text x="${p.x}" y="${p.y + 4}" text-anchor="middle" fill="${color}" font-size="${isPath(n) ? 11 : 8}" font-weight="bold">${pathIcon}${escapeXml(short)}</text>`;
        svg += `<title>${escapeXml(label)} [${escapeXml(n.severity || 'unknown')}]${isPath(n) ? ' (attack path) — click for details' : ' (finding) — click for details'}</title>`;
        svg += `</g>`;
    }

    svg += `</g></svg>`;
    canvas.innerHTML = svg;

    // Legend
    if (legendEl) {
        legendEl.innerHTML = `
            <span class="legend-item">${['critical','high','medium','low','info'].map(s =>
                `<span class="legend-item"><span class="dot" style="background:${ATTACK_SEV_COLORS[s]}"></span> ${s}</span>`).join('')}</span>
            <span class="legend-item"><span class="dot chain"></span> chained finding</span>
            <span class="legend-item"><span class="dot seq"></span> belongs to path</span>
            <span class="legend-item"><span class="dot succ"></span> 🎯 attack path</span>`;
        legendEl.classList.remove('hidden');
    }

    // Bind interactions
    initAttackGraphInteractions(nodes, edges, pos, W, H);
}

function forceLayout(nodes, edges, W, H) {
    // Fruchterman–Reingold-style: repulsion between all nodes, attraction
    // along edges, deterministic seed + fixed iteration count so re-renders
    // of the same data are stable.
    const pos = {};
    nodes.forEach((n, i) => {
        const ang = (i / Math.max(nodes.length, 1)) * Math.PI * 2;
        const rad = Math.min(W, H) * 0.33;
        pos[n.id] = { x: W / 2 + Math.cos(ang) * rad, y: H / 2 + Math.sin(ang) * rad };
    });
    const k = Math.sqrt((W * H) / Math.max(nodes.length, 1)) * 1.6;
    for (let iter = 0; iter < 160; iter++) {
        const disp = {};
        nodes.forEach(n => disp[n.id] = { x: 0, y: 0 });
        // Repulsion
        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                const a = nodes[i], b = nodes[j];
                let dx = pos[a.id].x - pos[b.id].x;
                let dy = pos[a.id].y - pos[b.id].y;
                let d = Math.max(Math.hypot(dx, dy), 0.01);
                const f = (k * k) / d;
                disp[a.id].x += (dx / d) * f;
                disp[a.id].y += (dy / d) * f;
                disp[b.id].x -= (dx / d) * f;
                disp[b.id].y -= (dy / d) * f;
            }
        }
        // Attraction along edges
        for (const e of edges) {
            const a = pos[e.source], b = pos[e.target];
            if (!a || !b) continue;
            let dx = a.x - b.x, dy = a.y - b.y;
            let d = Math.max(Math.hypot(dx, dy), 0.01);
            const f = (d * d) / k;
            disp[e.source].x -= (dx / d) * f;
            disp[e.source].y -= (dy / d) * f;
            disp[e.target].x += (dx / d) * f;
            disp[e.target].y += (dy / d) * f;
        }
        // Apply with temperature cooling
        const temp = Math.max(0.05, 1 - iter / 160);
        nodes.forEach(n => {
            const d = Math.max(Math.hypot(disp[n.id].x, disp[n.id].y), 0.01);
            const move = Math.min(d, temp * k);
            pos[n.id].x += (disp[n.id].x / d) * move;
            pos[n.id].y += (disp[n.id].y / d) * move;
            pos[n.id].x = Math.max(20, Math.min(W - 20, pos[n.id].x));
            pos[n.id].y = Math.max(20, Math.min(H - 20, pos[n.id].y));
        });
    }
    return pos;
}

function initAttackGraphInteractions(nodes, edges, pos, W, H) {
    const svg = document.getElementById('attackgraph-svg');
    if (!svg) return;
    const world = document.getElementById('attackgraph-world');
    const view = attackGraphView;
    view.scale = 1; view.tx = 0; view.ty = 0;
    attackGraphLayoutCache = { nodes, edges, pos, W, H };

    const applyTransform = () => {
        world.setAttribute('transform', `translate(${view.tx} ${view.ty}) scale(${view.scale})`);
        drawAttackGraphMinimap(nodes, edges, pos, W, H);
    };

    svg.addEventListener('wheel', (ev) => {
        ev.preventDefault();
        const factor = ev.deltaY < 0 ? 1.12 : 0.89;
        view.scale = Math.max(0.2, Math.min(5, view.scale * factor));
        applyTransform();
    }, { passive: false });

    let dragging = false, lastX = 0, lastY = 0;
    svg.addEventListener('mousedown', (ev) => {
        if (ev.target.closest('g[onclick]')) return; // let node clicks through
        dragging = true; lastX = ev.clientX; lastY = ev.clientY;
        svg.style.cursor = 'grabbing';
    });
    window.addEventListener('mousemove', (ev) => {
        if (!dragging) return;
        view.tx += ev.clientX - lastX;
        view.ty += ev.clientY - lastY;
        lastX = ev.clientX; lastY = ev.clientY;
        applyTransform();
    });
    window.addEventListener('mouseup', () => { dragging = false; svg.style.cursor = 'default'; });

    // Minimap click → center the viewport on the clicked world point.
    // World→screen is screenX = tx + worldX * scale, so to center world
    // point (mx, my): tx = svgW/2 - mx*scale, ty = svgH/2 - my*scale.
    const mm = document.getElementById('attackgraph-minimap');
    const mmCanvas = document.getElementById('attackgraph-minimap-canvas');
    if (mm && mmCanvas) {
        mm.classList.remove('hidden');
        mmCanvas.addEventListener('click', (ev) => {
            const svgRect = svg.getBoundingClientRect();
            const rect = mmCanvas.getBoundingClientRect();
            const mx = (ev.clientX - rect.left) / rect.width * W;
            const my = (ev.clientY - rect.top) / rect.height * H;
            view.tx = svgRect.width / 2 - mx * view.scale;
            view.ty = svgRect.height / 2 - my * view.scale;
            applyTransform();
        });
    }
    applyTransform();
}

function drawAttackGraphMinimap(nodes, edges, pos, W, H) {
    const canvas = document.getElementById('attackgraph-minimap-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const mw = canvas.width, mh = canvas.height;
    const sx = mw / W, sy = mh / H;
    ctx.clearRect(0, 0, mw, mh);
    ctx.fillStyle = '#0b1119';
    ctx.fillRect(0, 0, mw, mh);
    // edges
    ctx.strokeStyle = '#2a3a4d';
    ctx.lineWidth = 0.7;
    for (const e of edges) {
        const a = pos[e.source], b = pos[e.target];
        if (!a || !b) continue;
        ctx.beginPath();
        ctx.moveTo(a.x * sx, a.y * sy);
        ctx.lineTo(b.x * sx, b.y * sy);
        ctx.stroke();
    }
    // nodes
    for (const n of nodes) {
        const p = pos[n.id];
        ctx.fillStyle = ATTACK_SEV_COLORS[n.severity] || ATTACK_SEV_COLORS.unknown;
        ctx.beginPath();
        ctx.arc(p.x * sx, p.y * sy, n.type === 'path' ? 3 : 2, 0, Math.PI * 2);
        ctx.fill();
    }
    // viewport rect: visible world region is [-tx/scale, (svgW-tx)/scale]
    // in world units → scaled to minimap px (mw/W, mh/H).
    const svg = document.getElementById('attackgraph-svg');
    const svgRect = svg ? svg.getBoundingClientRect() : { width: W, height: H };
    const view = attackGraphView;
    const vx = (-view.tx / view.scale / W) * mw;
    const vy = (-view.ty / view.scale / H) * mh;
    const vw = Math.min(mw, (svgRect.width / view.scale / W) * mw);
    const vh = Math.min(mh, (svgRect.height / view.scale / H) * mh);
    ctx.strokeStyle = '#00ff88';
    ctx.lineWidth = 1.2;
    ctx.strokeRect(vx, vy, vw, vh);
}

async function attackGraphNodeClick(nodeId) {
    const detailEl = document.getElementById('attackgraph-detail');
    if (!detailEl || !attackGraphData) return;
    const paths = attackGraphData.paths || [];
    const findings = attackGraphData.findings || [];
    // Node ids are '<path_id>' (path) or '<path_id>_finding_<i>' (finding)
    const m = nodeId.match(/^(.*)_finding_(\d+)$/);
    const pathId = m ? m[1] : nodeId;
    const path = paths.find(p => p.id === pathId);
    if (!path) {
        detailEl.innerHTML = '<div class="attackgraph-detail-panel muted">Path not found for this node.</div>';
        return;
    }
    const sevColor = ATTACK_SEV_COLORS[path.severity] || ATTACK_SEV_COLORS.unknown;
    let html = `<div class="attackgraph-detail-panel">`;
    html += `<div class="graph-detail-header"><h4 style="color:${sevColor}">${escapeHtml(path.title || pathId)}</h4>
             <span class="sev-pill" style="color:${sevColor};border-color:${sevColor}">${escapeHtml(path.severity || 'unknown')}</span>
             <span class="tool-pill">score ${path.score || 0}</span>
             <span class="tool-pill">conf ${Math.round((path.confidence || 0) * 100)}%</span></div>`;

    if (m) {
        // Finding node → show the specific finding
        const idx = parseInt(m[2], 10);
        const fkeys = path.findings || [];
        const fkey = fkeys[idx];
        const f = findings.find(x => (x.dedupe_key && x.dedupe_key === fkey) || (x.title && x.title === fkey)) ||
                  (path.finding_details && path.finding_details[idx]);
        if (f) {
            html += `<div class="graph-detail-section"><div class="graph-detail-label">FINDING</div>
                <div>${escapeHtml(f.title || fkey)}</div>
                <div class="muted" style="font-size:10px;font-family:var(--font-mono)">${escapeHtml((f.evidence || f.source_tool || '') + '')}</div></div>`;
        }
    }

    if (path.kill_chain_phases && path.kill_chain_phases.length) {
        html += `<div class="graph-detail-section"><div class="graph-detail-label">KILL CHAIN</div>
            <div>${path.kill_chain_phases.map(p => escapeHtml(p)).join(' → ')} (${Math.round((path.kill_chain_progress || 0) * 100)}%)</div></div>`;
    }
    if (path.attack_techniques && path.attack_techniques.length) {
        html += `<div class="graph-detail-section"><div class="graph-detail-label">ATT&CK</div>
            <div>${path.attack_techniques.map(t => `<code>${escapeHtml(t.id)}</code> ${escapeHtml(t.name || '')}`).join(', ')}</div></div>`;
    }
    if (path.finding_details && path.finding_details.length) {
        html += `<div class="graph-detail-section"><div class="graph-detail-label">LINKED FINDINGS</div>
            <div class="muted" style="font-size:10px">${path.finding_details.map(fd => `[${escapeHtml(fd.severity || '')}] ${escapeHtml(fd.title || '')} (${escapeHtml(fd.source_tool || '')})`).join('<br>')}</div></div>`;
    }
    if (path.remediation && path.remediation.length) {
        html += `<div class="graph-detail-section"><div class="graph-detail-label">REMEDIATION</div>
            <div class="muted" style="font-size:10px">${path.remediation.map(r => '• ' + escapeHtml(r)).join('<br>')}</div></div>`;
    }
    html += '</div>';
    detailEl.innerHTML = html;
    detailEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function resetAttackGraphView() {
    const svg = document.getElementById('attackgraph-svg');
    const world = document.getElementById('attackgraph-world');
    if (!svg || !world) return;
    attackGraphView.scale = 1; attackGraphView.tx = 0; attackGraphView.ty = 0;
    world.setAttribute('transform', 'translate(0 0) scale(1)');
    // Redraw the minimap from the cached layout so it doesn't go blank
    if (attackGraphLayoutCache) {
        const { nodes, edges, pos, W, H } = attackGraphLayoutCache;
        drawAttackGraphMinimap(nodes, edges, pos, W, H);
    }
}

// ═══════════════════════════════════════════════════════════════
// MITRE ATT&CK Matrix Heatmap (v5.4) — tactic × technique grid
// ═══════════════════════════════════════════════════════════════
let attackMatrixData = null;
let attackMatrixSource = null;  // 'task' | 'campaign'

async function loadAttackMatrixSources() {
    try {
        const [tasksRes, campsRes] = await Promise.all([
            fetch('/api/tasks/all'),
            fetch('/api/campaigns'),
        ]);
        const tasks = Array.isArray(await tasksRes.json()) ? await tasksRes.json() : [];
        const camps = Array.isArray(await campsRes.json()) ? await campsRes.json() : [];
        const taskSel = document.getElementById('attackmatrix-task-select');
        const campSel = document.getElementById('attackmatrix-campaign-select');
        if (taskSel) {
            taskSel.innerHTML = '<option value="">Select task run...</option>' +
                tasks.map(t => `<option value="${escapeHtml(t.task_id)}">${escapeHtml(t.task_id)} — ${escapeHtml(t.status || 'unknown')} (${t.findings_count || 0} findings)</option>`).join('');
        }
        if (campSel) {
            campSel.innerHTML = '<option value="">Select campaign...</option>' +
                camps.map(c => `<option value="${escapeHtml(c.id)}">${escapeHtml(c.name || c.id)} — ${escapeHtml(c.status)} (${c.findings_total || 0} findings)</option>`).join('');
        }
    } catch (e) { /* silent */ }
}

function onAttackMatrixTaskChange() {
    const campSel = document.getElementById('attackmatrix-campaign-select');
    if (campSel) campSel.value = '';
    attackMatrixSource = 'task';
    renderAttackMatrix();
}

function onAttackMatrixCampaignChange() {
    const taskSel = document.getElementById('attackmatrix-task-select');
    if (taskSel) taskSel.value = '';
    attackMatrixSource = 'campaign';
    renderAttackMatrix();
}

async function renderAttackMatrix() {
    const taskSel = document.getElementById('attackmatrix-task-select');
    const campSel = document.getElementById('attackmatrix-campaign-select');
    const table = document.getElementById('attackmatrix-table');
    const summaryEl = document.getElementById('attackmatrix-summary');
    const legendEl = document.getElementById('attackmatrix-legend');
    const detailEl = document.getElementById('attackmatrix-detail');
    if (detailEl) detailEl.innerHTML = '';
    let params = '';
    if (attackMatrixSource === 'campaign' && campSel && campSel.value) {
        params = `?campaign_id=${encodeURIComponent(campSel.value)}`;
    } else if (taskSel && taskSel.value) {
        params = `?task_id=${encodeURIComponent(taskSel.value)}`;
    } else {
        if (summaryEl) summaryEl.innerHTML = '';
        if (legendEl) legendEl.innerHTML = '';
        if (table) table.innerHTML = '<p class="muted">Pick a task run or campaign to build the MITRE ATT&CK heatmap. Each cell = a discovered technique (severity-colored); click a cell for findings, evidence &amp; the attack paths that chain it.</p>';
        return;
    }
    try {
        const res = await fetch(`/api/attack/matrix${params}`);
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.error || `HTTP ${res.status}`);
        }
        attackMatrixData = await res.json();
        drawAttackMatrix();
    } catch (e) {
        if (summaryEl) summaryEl.innerHTML = `<p class="muted">Matrix error: ${escapeHtml(e.message)}</p>`;
    }
}

function drawAttackMatrix() {
    const table = document.getElementById('attackmatrix-table');
    const summaryEl = document.getElementById('attackmatrix-summary');
    const legendEl = document.getElementById('attackmatrix-legend');
    if (!attackMatrixData || !table) return;
    const { tactics, rows, summary, total_findings, total_paths, total_techniques } = attackMatrixData;
    const sevColors = ATTACK_SEV_COLORS;

    // ── Summary strip ──
    if (summaryEl) {
        const sevLabel = { critical: '🔴 Critical', high: '🟠 High', medium: '🟡 Medium', low: '🟢 Low', info: '⚪ Info' };
        const parts = (summary && Object.keys(summary).length)
            ? ['critical', 'high', 'medium', 'low', 'info']
                .filter(s => summary[s] > 0)
                .map(s => `${sevLabel[s]}: <b>${summary[s]}</b>`).join(' · ')
            : 'No severity breakdown';
        summaryEl.innerHTML = `<p class="muted">${total_techniques} technique(s) across ${tactics.length} tactic column(s) · ` +
            `${total_findings} finding(s) · ${total_paths} attack path(s) — ${parts}</p>`;
    }

    // ── Legend ──
    if (legendEl) {
        legendEl.innerHTML = ['critical', 'high', 'medium', 'low', 'info']
            .map(s => `<span class="am-legend-item"><span class="am-swatch" style="background:${sevColors[s]}"></span>${s}</span>`).join('');
    }

    // Group techniques by tactic (only tactics with data get columns; empty
    // standard columns still render dimmed for the full-matrix feel)
    const byTactic = {};
    rows.forEach((r, i) => { r.__idx = i; (byTactic[r.tactic] = byTactic[r.tactic] || []).push(r); });
    const colTactics = tactics.filter(t => byTactic[t]);
    const emptyTactics = tactics.filter(t => !byTactic[t]);
    const maxRows = Math.max(1, ...colTactics.map(t => byTactic[t].length));

    let html = '<thead><tr><th class="am-corner">TACTIC \\ TECHNIQUE</th>' +
        colTactics.map(t => `<th class="am-tactic-head"><div class="am-tactic-name">${escapeHtml(t)}</div><div class="am-tactic-count">${byTactic[t].length}</div></th>`).join('') +
        (emptyTactics.length ? `<th class="am-tactic-head am-empty-head" title="No techniques discovered in these tactics">${emptyTactics.map(t => escapeHtml(t)).join(' · ')}</th>` : '') +
        '</tr></thead>';

    html += '<tbody>';
    for (let r = 0; r < maxRows; r++) {
        html += '<tr>';
        if (r === 0) html += `<td class="am-corner" rowspan="${maxRows}">severity</td>`;
        for (const t of colTactics) {
            const tech = byTactic[t][r];
            if (tech) {
                const color = sevColors[tech.severity] || sevColors.unknown;
                html += `<td class="am-cell" style="background:${color};">` +
                    `<div class="am-cell-inner" onclick="showAttackMatrixDetail(${tech.__idx})" title="${escapeHtml(tech.name)} — ${tech.findings_count} findings, ${tech.path_count} paths">` +
                    `<div class="am-cell-id">${escapeHtml(tech.id)}</div>` +
                    `<div class="am-cell-count">${tech.findings_count}</div>` +
                    `</div></td>`;
            } else {
                html += '<td class="am-cell am-cell-empty"></td>';
            }
        }
        if (emptyTactics.length) html += '<td class="am-cell am-cell-void"></td>';
        html += '</tr>';
    }
    html += '</tbody>';
    table.innerHTML = html;
}

function showAttackMatrixDetail(idx) {
    const detailEl = document.getElementById('attackmatrix-detail');
    if (!detailEl || !attackMatrixData) return;
    const row = attackMatrixData.rows[idx];
    if (!row) { detailEl.innerHTML = ''; return; }
    const sevColors = ATTACK_SEV_COLORS;
    const color = sevColors[row.severity] || sevColors.unknown;
    let html = `<div class="attackmatrix-detail-panel">` +
        `<h4><span class="am-sev-badge" style="background:${color}">${escapeHtml(row.severity)}</span> ` +
        `<span class="am-tech-id">${escapeHtml(row.id)}</span> ${escapeHtml(row.name)}</h4>` +
        `<div class="am-detail-meta muted">Tactic: <b>${escapeHtml(row.tactic)}</b> · ` +
        `${row.findings_count} finding(s) · ${row.path_count} attack path(s)` +
        `${row.score ? ` · max path score <b>${row.score}</b>` : ''}</div>`;
    if (row.sources && row.sources.length) {
        html += `<div class="am-detail-section"><span class="muted">Sources:</span> ${row.sources.map(s => `<code>${escapeHtml(s)}</code>`).join(' ')}</div>`;
    }
    if (row.targets && row.targets.length) {
        html += `<div class="am-detail-section"><span class="muted">Targets:</span> ${row.targets.map(t => `<code>${escapeHtml(t)}</code>`).join(' ')}</div>`;
    }
    if (row.paths && row.paths.length) {
        html += `<div class="am-detail-section"><span class="muted">Linked attack paths:</span><ul>` +
            row.paths.map(p => `<li>${escapeHtml(p)}</li>`).join('') + `</ul></div>`;
    }
    if (row.evidence && row.evidence.length) {
        html += `<div class="am-detail-section"><span class="muted">Evidence:</span><ul class="am-evidence">` +
            row.evidence.map(e => `<li><code>${escapeHtml(e)}</code></li>`).join('') + `</ul></div>`;
    }
    html += '</div>';
    detailEl.innerHTML = html;
}

// ═══════════════════════════════════════════════════════════════
// Results Area
// ═══════════════════════════════════════════════════════════════
function showResultsTab(tab) {
    document.querySelectorAll('.results-content').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('.results-tabs .tab').forEach(t => t.classList.remove('active'));
    const target = document.getElementById(`results-${tab}`);
    if (target) target.classList.remove('hidden');
    const tabs = document.querySelectorAll('.results-tabs .tab');
    for (const t of tabs) {
        if ((t.dataset.tab || t.textContent.toLowerCase()).includes(tab)) t.classList.add('active');
    }
    // Refresh campaign mini-view when Campaign tab is selected
    if (tab.includes('campaign') && currentCampaignId) {
        refreshCampaignData();
    }
    // Load vector memory panel when Memory tab is selected
    if (tab === 'memory') {
        loadMemoryPanel();
    }
    // Load offline knowledge base when KB tab is selected
    if (tab === 'kb') {
        loadKBPanel();
    }
    // Load Mission Control panel when Mission tab is selected
    if (tab === 'mission') {
        loadMissionControl();
    }
    // Refresh ATT&CK sources when the matrix tab is selected
    if (tab === 'attackmatrix') {
        loadAttackMatrixSources();
    }
}

function appendLiveOutput(data) {
    const el = document.getElementById('live-output');
    const timestamp = new Date().toLocaleTimeString();
    const result = data.result || data;
    const output = result.summary || result.stdout || result.stderr || JSON.stringify(result, null, 2);
    el.textContent = `[${timestamp}] ${result.tool || data.tool || 'tool'} (exit: ${result.exit_code ?? '?'}):\n${output}\n\n${el.textContent}`;
}

function addCommandToLog(data) {
    const result = data.result || data;
    const entry = {
        time: new Date().toLocaleTimeString(),
        tool: result.tool,
        args: result.args,
        exit_code: result.exit_code,
        duration: result.duration_seconds,
    };
    commandLog.unshift(entry);

    const log = document.getElementById('command-log');
    log.innerHTML = commandLog.map(c => `
        <div class="safety-item">
            <span class="label">${c.time} ${escapeHtml(c.tool)}</span>
            <span class="value">${c.exit_code === 0 ? '✓' : '✗'} ${c.duration || ''}s</span>
        </div>
    `).join('');
}

// ═══════════════════════════════════════════════════════════════
// Sessions & Safety
// ═══════════════════════════════════════════════════════════════
async function loadSessions() {
    try {
        const res = await fetch('/api/sessions');
        const sessions = await res.json();
        const el = document.getElementById('sessions-list-content');
        if (sessions.length === 0) {
            el.innerHTML = '<p class="muted">No past sessions.</p>';
            return;
        }
        el.innerHTML = sessions.map(s => `
            <div class="safety-item">
                <span class="label">${escapeHtml(s.name)}</span>
                <span class="value">${s.tool_calls} tools</span>
            </div>
        `).join('');
    } catch (e) {
        console.error('Sessions load failed:', e);
    }
}

async function loadSafety() {
    try {
        const res = await fetch('/api/safety');
        const data = await res.json();
        const el = document.getElementById('safety-info-content');
        el.innerHTML = `
            <div class="safety-item">
                <span class="label">Allowed Targets</span>
                <span class="value">${data.allowed_targets?.length || 0} ranges</span>
            </div>
            <div class="safety-item">
                <span class="label">Blocked Targets</span>
                <span class="value">${data.blocked_targets?.length || 0} hosts</span>
            </div>
            <div class="safety-item">
                <span class="label">Confirm Required</span>
                <span class="value">${data.require_confirmation?.length || 0} tools</span>
            </div>
        `;
    } catch (e) {
        console.error('Safety load failed:', e);
    }
}

// ═══════════════════════════════════════════════════════════════
// Panel Toggle
// ═══════════════════════════════════════════════════════════════
function togglePanel(id) {
    document.getElementById(id).classList.toggle('collapsed');
}

// ═══════════════════════════════════════════════════════════════
// C2 Campaign Dashboard
// ═══════════════════════════════════════════════════════════════
let currentCampaignId = null;
let campaignPollTimer = null;
let campaignRefreshTimer = null;

// Coalesce the burst of SocketIO events fired on a single target completion
// (multi_target_progress + campaign_target_update + campaign_update each
// trigger refreshCampaignData, which does 3 fetches) into one refresh cycle.
function debouncedCampaignRefresh() {
    if (campaignRefreshTimer) clearTimeout(campaignRefreshTimer);
    campaignRefreshTimer = setTimeout(() => {
        campaignRefreshTimer = null;
        refreshCampaignData();
    }, 250);
}

function toggleCampaignPanel() {
    const panel = document.getElementById('campaign-panel');
    panel.classList.toggle('hidden');
    if (!panel.classList.contains('hidden') && currentCampaignId) {
        refreshCampaignData();
    }
}

function openCampaignPanel() {
    const panel = document.getElementById('campaign-panel');
    panel.classList.remove('hidden');
    refreshCampaignData();
    loadCompareSelects();
}

async function refreshCampaignData() {
    if (!currentCampaignId) return;
    try {
        const [detailRes, heatmapRes, riskRes] = await Promise.all([
            fetch(`/api/campaigns/${currentCampaignId}`),
            fetch(`/api/campaigns/${currentCampaignId}/heatmap`),
            fetch(`/api/campaigns/${currentCampaignId}/risk`),
        ]);
        const detail = await detailRes.json();
        const heatmap = await heatmapRes.json();
        const risk = await riskRes.json();
        if (detail.error) return;
        renderCampaignDetail(detail);
        renderCampaignHeatmap(heatmap);
        renderCampaignRiskGauge(risk);
        renderCampaignDriftGauges(detail);
        renderCampaignMiniView(detail, risk);
    } catch (e) {
        console.error('Campaign refresh failed:', e);
    }
}

function renderCampaignDetail(campaign) {
    document.getElementById('campaign-id-display').textContent = campaign.id;
    document.getElementById('camp-targets-total').textContent = campaign.per_target ? Object.keys(campaign.per_target).length : 0;
    document.getElementById('camp-targets-complete').textContent = campaign.completed_targets || 0;
    document.getElementById('camp-targets-active').textContent = campaign.active_targets || 0;
    document.getElementById('camp-targets-failed').textContent = campaign.failed_targets || 0;
    document.getElementById('camp-findings-total').textContent = campaign.findings_total || 0;
    document.getElementById('camp-risk-score').textContent = (campaign.risk_score || 0).toFixed(1);
    document.getElementById('camp-drift-avg').textContent = (campaign.drift_avg || 0).toFixed(3);
    // Color risk score
    const riskEl = document.getElementById('camp-risk-score');
    riskEl.style.color = campaign.risk_score >= 75 ? 'var(--accent-red)' :
                          campaign.risk_score >= 50 ? 'var(--accent-orange)' :
                          campaign.risk_score >= 25 ? 'var(--accent-yellow)' : 'var(--accent-green)';
    // Render per-target grid
    const grid = document.getElementById('campaign-target-grid');
    if (!campaign.per_target || Object.keys(campaign.per_target).length === 0) {
        grid.innerHTML = '<p class="muted">No targets.</p>';
        return;
    }
    grid.innerHTML = Object.values(campaign.per_target).map(t => {
        const statusColor = t.status === 'complete' ? 'var(--accent-green)' :
                           t.status === 'running' ? 'var(--accent-yellow)' :
                           t.status === 'failed' || t.status === 'error' ? 'var(--accent-red)' :
                           'var(--text-muted)';
        const progressPct = t.progress || 0;
        return `
            <div class="target-card" onclick="openTargetDrilldown('${escapeHtml(t.target)}')" title="Click to drill down: steps, drift, findings, timeline" data-ctrl-help="Open the full per-target drill-down for ${escapeHtml(t.target)} — step list with drift scores, findings with evidence, and the start/finish timeline pulled from the saved multi_* task state.">
                <div class="target-header">
                    <span class="target-name">${escapeHtml(t.target)}</span>
                    <span class="target-status" style="color:${statusColor}">${escapeHtml(t.status)}</span>
                </div>
                <div class="target-progress">
                    <div class="target-progress-bar">
                        <div class="target-progress-fill" style="width:${progressPct}%;background:${statusColor}"></div>
                    </div>
                    <span class="target-progress-label">${t.completed_steps || 0}/${t.total_steps || 0} steps (${progressPct}%)</span>
                </div>
                <div class="target-findings">
                    <span class="target-finding-badge crit">${t.findings_by_severity?.critical || 0}</span>
                    <span class="target-finding-badge high">${t.findings_by_severity?.high || 0}</span>
                    <span class="target-finding-badge med">${t.findings_by_severity?.medium || 0}</span>
                    <span class="target-finding-badge low">${t.findings_by_severity?.low || 0}</span>
                    <span class="target-finding-badge info">${t.findings_by_severity?.info || 0}</span>
                </div>
                ${t.error ? `<div class="target-error">${escapeHtml(t.error)}</div>` : ''}
            </div>
        `;
    }).join('');
}

function renderCampaignHeatmap(heatmap) {
    const el = document.getElementById('campaign-heatmap');
    if (heatmap.error || !heatmap.tools || heatmap.tools.length === 0) {
        el.innerHTML = '<p class="muted">No findings to display.</p>';
        return;
    }
    const sevs = heatmap.severities;
    const sevColors = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#eab308', info: '#64748b' };
    let html = '<table class="heatmap-table"><thead><tr><th>Tool</th>';
    for (const s of sevs) html += `<th style="color:${sevColors[s]}">${s.slice(0,3).toUpperCase()}</th>`;
    html += '<th>TOT</th></tr></thead><tbody>';
    for (const tool of heatmap.tools) {
        html += `<tr><td class="hm-tool">${escapeHtml(tool)}</td>`;
        let rowTotal = 0;
        for (const s of sevs) {
            const count = (heatmap.grid[tool] || {})[s] || 0;
            rowTotal += count;
            const intensity = count > 0 ? Math.min(1.0, count / 5) : 0;
            html += `<td class="hm-cell" style="background:${sevColors[s]};opacity:${0.15 + intensity * 0.85}">${count || ''}</td>`;
        }
        html += `<td class="hm-total">${rowTotal}</td></tr>`;
    }
    html += '</tbody></table>';
    el.innerHTML = html;
}

function renderCampaignRiskGauge(risk) {
    if (risk.error) return;
    const canvas = document.getElementById('risk-gauge-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const cx = 40, cy = 45, r = 32;
    const score = risk.total_risk || 0;
    const angle = (score / 100) * Math.PI;
    ctx.clearRect(0, 0, 80, 80);
    // Background arc
    ctx.beginPath();
    ctx.arc(cx, cy, r, Math.PI, 0);
    ctx.strokeStyle = '#1e3a5f';
    ctx.lineWidth = 6;
    ctx.stroke();
    // Score arc
    const color = score >= 75 ? '#ef4444' : score >= 50 ? '#f97316' : score >= 25 ? '#f59e0b' : '#22c55e';
    ctx.beginPath();
    ctx.arc(cx, cy, r, Math.PI, Math.PI + angle);
    ctx.strokeStyle = color;
    ctx.lineWidth = 6;
    ctx.lineCap = 'round';
    ctx.stroke();
    document.getElementById('risk-gauge-label').textContent = score.toFixed(0);
    document.getElementById('risk-gauge-label').style.color = color;
}

function renderCampaignDriftGauges(campaign) {
    const el = document.getElementById('campaign-drift-gauges');
    if (!campaign.per_target || Object.keys(campaign.per_target).length === 0) {
        el.innerHTML = '<p class="muted">No drift data.</p>';
        return;
    }
    el.innerHTML = Object.values(campaign.per_target).map(t => {
        const drift = t.drift_score || 0;
        const conf = t.drift_confidence || 'N/A';
        const confColor = conf === 'high' ? 'var(--accent-green)' :
                          conf === 'medium' ? 'var(--accent-yellow)' :
                          conf === 'low' ? 'var(--accent-orange)' : 'var(--text-muted)';
        return `
            <div class="drift-gauge-item">
                <span class="drift-target">${escapeHtml(t.target)}</span>
                <div class="drift-bar">
                    <div class="drift-fill" style="width:${drift * 100}%;background:${confColor}"></div>
                </div>
                <span class="drift-label" style="color:${confColor}">${(drift * 100).toFixed(0)}%</span>
                <span class="drift-conf" style="color:${confColor}">${conf}</span>
            </div>
        `;
    }).join('');
}

function renderCampaignMiniView(campaign, risk) {
    const el = document.getElementById('campaign-mini-content');
    if (!el) return;
    const total = campaign.per_target ? Object.keys(campaign.per_target).length : 0;
    el.innerHTML = `
        <div class="camp-mini-stats">
            <span><b>${escapeHtml(campaign.name || 'Campaign')}</b> — ${campaign.status}</span>
            <span>${campaign.completed_targets || 0}/${total} targets · ${campaign.findings_total || 0} findings</span>
            <span>Risk: <b style="color:${(risk.total_risk || 0) >= 50 ? 'var(--accent-red)' : 'var(--accent-green)'}">${(risk.total_risk || 0).toFixed(1)}</b></span>
        </div>
    `;
}

async function createCampaign() {
    const name = document.getElementById('camp-name')?.value?.trim() || 'Campaign';
    const targetsRaw = document.getElementById('camp-targets-input')?.value?.trim() || '';
    const workflow = document.getElementById('camp-wf-select')?.value || '';
    const targets = targetsRaw.split(',').map(t => t.trim()).filter(Boolean);
    if (!targets.length) {
        addSystemMessage('❌ No targets specified for campaign');
        return;
    }
    try {
        const res = await fetch('/api/campaigns', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, targets, workflow, description: `Campaign: ${name}` }),
        });
        const data = await res.json();
        if (data.error) {
            addSystemMessage(`❌ Campaign creation failed: ${escapeHtml(data.error)}`);
            return;
        }
        currentCampaignId = data.id;
        document.getElementById('campaign-id-display').textContent = data.id;
        clearPrioPlan(); // a new campaign starts with no stale priority plan
        addSystemMessage(`📡 Campaign created: ${escapeHtml(name)} — ${targets.length} targets`);
        openCampaignPanel();
        refreshCampaignData();
    } catch (e) {
        addSystemMessage(`❌ Campaign creation error: ${escapeHtml(e.message)}`);
    }
}

async function startCampaignRun() {
    if (!currentCampaignId) {
        addSystemMessage('❌ No active campaign. Create one first.');
        return;
    }
    try {
        const res = await fetch(`/api/campaigns/${currentCampaignId}/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ priority_plan: campaignPrioPlan }),
        });
        const data = await res.json();
        if (data.error) {
            addSystemMessage(`❌ Campaign start failed: ${escapeHtml(data.error)}`);
        } else {
            addSystemMessage(`📡 Campaign started: ${escapeHtml(data.workflow)} against ${data.targets?.length || 0} targets` + (data.prioritized ? ' — ⚡ priority plan applied' : ''));
            // Auto-refresh while campaign runs
            if (campaignPollTimer) clearInterval(campaignPollTimer);
            campaignPollTimer = setInterval(() => {
                if (currentCampaignId) refreshCampaignData();
            }, 5000);
        }
    } catch (e) {
        addSystemMessage(`❌ Campaign start error: ${escapeHtml(e.message)}`);
    }
}

async function loadCampaignSelectOptions() {
    try {
        const res = await fetch('/api/workflows');
        const workflows = await res.json();
        const sel = document.getElementById('camp-wf-select');
        if (sel) {
            sel.innerHTML = '<option value="">Select workflow...</option>' +
                workflows.map(w => `<option value="${escapeHtml(w.name)}">${escapeHtml(w.name)}</option>`).join('');
        }
    } catch (e) { /* silent */ }
}

// ═══════════════════════════════════════════════════════════════
// Parallel Multi-Workflow (v5.3) — cross-workflow correlation
// ═══════════════════════════════════════════════════════════════
async function runParallelWorkflows() {
    if (!currentCampaignId) {
        addSystemMessage('❌ No active campaign. Create one first.');
        return;
    }
    const input = document.getElementById('parallel-wf-input');
    const status = document.getElementById('parallel-status');
    const result = document.getElementById('parallel-result');
    const names = (input?.value || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!names.length) {
        if (status) status.textContent = '⚠️ Enter at least one workflow name';
        return;
    }
    if (result) { result.classList.remove('hidden'); result.innerHTML = '<p class="muted">Starting parallel run…</p>'; }
    if (status) status.textContent = `⚙️ ${names.length} workflow(s) queued`;
    try {
        const res = await fetch(`/api/campaigns/${currentCampaignId}`);
        const campaign = await res.json();
        const targets = campaign.targets || [];
        if (!targets.length) {
            if (status) status.textContent = '❌ Campaign has no targets';
            return;
        }
        const jobs = names.map(w => ({
            workflow: w,
            targets,
            variables: { target: targets[0] },
        }));
        const start = await fetch('/api/workflows/parallel', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jobs, campaign_id: currentCampaignId }),
        });
        const data = await start.json();
        if (data.error) {
            if (status) status.textContent = `❌ ${escapeHtml(data.error)}`;
            return;
        }
        if (status) status.textContent = `▶ ${data.jobs} job(s) running in background`;
        addSystemMessage(`⚙️ Parallel run started: ${names.length} workflows against ${targets.length} targets`);
    } catch (e) {
        if (status) status.textContent = `❌ ${escapeHtml(e.message)}`;
        addSystemMessage(`❌ Parallel start error: ${escapeHtml(e.message)}`);
    }
}

function renderParallelResult(data) {
    const result = document.getElementById('parallel-result');
    const status = document.getElementById('parallel-status');
    if (!result) return;
    result.classList.remove('hidden');
    if (data.error) {
        result.innerHTML = `<p class="compare-error">❌ ${escapeHtml(data.error)}</p>`;
        return;
    }
    if (status) status.textContent = `✅ ${data.jobs_total || 0} jobs · ${data.paths_correlated || 0} cross-workflow paths · risk ${data.risk_score || 0}/100`;
    result.innerHTML = `
        <div class="compare-verdict">
            <strong>${data.jobs_total || 0}</strong> jobs · <strong>${data.findings_total || 0}</strong> merged findings ·
            <strong>${data.paths_correlated || 0}</strong> cross-workflow attack paths · risk <strong>${data.risk_score || 0}/100</strong>
        </div>
        ${data.report_path ? `<p class="muted" style="font-size:10px;font-family:var(--font-mono)">📄 ${escapeHtml(data.report_path)}</p>` : ''}`;
    addSystemMessage(`⚙️ Parallel run complete: ${data.paths_correlated || 0} cross-workflow paths (${data.status || 'unknown'})`);
    if (currentCampaignId) refreshCampaignData();
}

// ═══════════════════════════════════════════════════════════════
// Auto Target Prioritizer (v5.2) — LLM-driven pre-flight ranking
// ═══════════════════════════════════════════════════════════════
let campaignPrioPlan = null;

async function prioritizeCampaign() {
    if (!currentCampaignId) {
        addSystemMessage('❌ No active campaign. Create one first.');
        return;
    }
    const list = document.getElementById('campaign-prio-list');
    const label = document.getElementById('prio-mode-label');
    if (list) {
        list.classList.remove('hidden');
        list.innerHTML = '<p class="muted">Ranking targets by exploitability…</p>';
    }
    try {
        const res = await fetch(`/api/campaigns/${currentCampaignId}/prioritize`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
        });
        const data = await res.json();
        if (data.error) {
            addSystemMessage(`❌ Prioritization failed: ${escapeHtml(data.error)}`);
            if (list) list.innerHTML = `<p class="compare-error">${escapeHtml(data.error)}</p>`;
            return;
        }
        campaignPrioPlan = data.ordered_targets || [];
        if (label) {
            label.textContent = data.used_llm
                ? '🤖 LLM ranked ' + campaignPrioPlan.length + ' targets'
                : '⚠️ Heuristic fallback: ' + (data.fallback_reason || 'LLM unavailable');
        }
        renderPrioList(list, data);
        addSystemMessage(`⚡ Priority plan ready — ${campaignPrioPlan.length} targets ranked` +
            (data.used_llm ? ' (LLM)' : ' (heuristic)'));
    } catch (e) {
        addSystemMessage(`❌ Prioritization error: ${escapeHtml(e.message)}`);
        if (list) list.innerHTML = `<p class="compare-error">${escapeHtml(e.message)}</p>`;
    }
}

function renderPrioList(el, data) {
    const plan = data.ordered_targets || [];
    if (!plan.length) {
        el.innerHTML = '<p class="muted">No targets ranked.</p>';
        return;
    }
    const tierColor = t => ({ critical: 'var(--accent-red)', high: 'var(--accent-orange)',
                               medium: 'var(--accent-yellow)', low: '#84cc16',
                               info: 'var(--text-muted)' }[t] || 'var(--text-muted)');
    el.innerHTML = plan.map(e => `
        <div class="prio-entry">
            <span class="prio-rank">#${e.rank}</span>
            <span class="prio-target">${escapeHtml(e.target)}</span>
            <span class="prio-score" style="color:${tierColor(e.tier)}">${e.score}</span>
            <span class="prio-tier" style="color:${tierColor(e.tier)}">${escapeHtml(e.tier)}</span>
            <span class="prio-agg" title="Retry budget multiplier">${e.aggressiveness}x</span>
            <span class="prio-why" title="${escapeHtml(e.rationale || '')}">${escapeHtml((e.rationale || '').slice(0, 80))}</span>
        </div>`).join('');
}

function clearPrioPlan() {
    campaignPrioPlan = null;
    const list = document.getElementById('campaign-prio-list');
    if (list) {
        list.classList.add('hidden');
        list.innerHTML = '';
    }
    const label = document.getElementById('prio-mode-label');
    if (label) label.textContent = 'Heuristic fallback available';
}

// ═══════════════════════════════════════════════════════════════
// Campaign Comparison (side-by-side view)
// ═══════════════════════════════════════════════════════════════
async function loadCompareSelects() {
    try {
        const res = await fetch('/api/campaigns');
        const campaigns = await res.json();
        const opts = campaigns.map(c =>
            `<option value="${escapeHtml(c.id)}">${escapeHtml(c.name || c.id)} (${c.status}, ${c.findings_total} findings)</option>`
        ).join('');
        const selA = document.getElementById('compare-campaign-a');
        const selB = document.getElementById('compare-campaign-b');
        if (selA && selB) {
            const curA = selA.value, curB = selB.value;
            selA.innerHTML = '<option value="">Select campaign A...</option>' + opts;
            selB.innerHTML = '<option value="">Select campaign B...</option>' + opts;
            if (curA) selA.value = curA;
            if (curB) selB.value = curB;
        }
    } catch (e) { console.error('Compare select load failed:', e); }
}

async function runCampaignCompare() {
    const a = document.getElementById('compare-campaign-a').value;
    const b = document.getElementById('compare-campaign-b').value;
    const box = document.getElementById('compare-results');
    if (!a || !b) {
        box.classList.remove('hidden');
        box.innerHTML = '<p class="muted">Select two campaigns to compare.</p>';
        return;
    }
    box.classList.remove('hidden');
    box.innerHTML = '<p class="muted">Comparing…</p>';
    try {
        const res = await fetch(`/api/campaigns/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
        const data = await res.json();
        if (data.error) {
            box.innerHTML = `<p class="compare-error">${escapeHtml(data.error)}</p>`;
            return;
        }
        renderCampaignCompare(box, data);
    } catch (e) {
        box.innerHTML = `<p class="compare-error">Compare failed: ${escapeHtml(e.message)}</p>`;
    }
}

function sevColor(sev) {
    return { critical: 'var(--accent-red)', high: 'var(--accent-orange)',
             medium: 'var(--accent-yellow)', low: '#84cc16', info: 'var(--text-muted)' }[sev] || 'var(--text-muted)';
}

function renderCampaignCompare(box, data) {
    const A = data.campaign_a, B = data.campaign_b;

    // ── Side-by-side summary cards ──
    const summaryCard = (c) => `
        <div class="compare-card">
            <div class="compare-card-title">${escapeHtml(c.name || c.id)}</div>
            <div class="compare-card-sub">${escapeHtml(c.id)} · ${escapeHtml(c.status)} · ${escapeHtml(c.workflow || 'no workflow')}</div>
            <div class="compare-metrics">
                <div class="compare-metric"><span class="compare-metric-value">${c.findings_total}</span><span class="compare-metric-label">Findings</span></div>
                <div class="compare-metric"><span class="compare-metric-value">${c.targets.length}</span><span class="compare-metric-label">Targets</span></div>
                <div class="compare-metric"><span class="compare-metric-value" style="color:${c.risk.score >= 75 ? 'var(--accent-red)' : c.risk.score >= 50 ? 'var(--accent-orange)' : c.risk.score >= 25 ? 'var(--accent-yellow)' : 'var(--accent-green)'}">${c.risk.score.toFixed(1)}</span><span class="compare-metric-label">Risk</span></div>
                <div class="compare-metric"><span class="compare-metric-value">${c.drift_avg.toFixed(3)}</span><span class="compare-metric-label">Drift</span></div>
            </div>
            <div class="compare-sev-row">${['critical','high','medium','low','info'].map(s =>
                `<span class="compare-sev" style="color:${sevColor(s)}">${s}: ${c.severity_counts[s] || 0}</span>`
            ).join('')}</div>
        </div>`;

    const sevPill = (sev) => `<span class="sev-pill" style="color:${sevColor(sev)};border-color:${sevColor(sev)}">${escapeHtml(sev)}</span>`;
    const toolPill = (t) => t ? `<span class="tool-pill">${escapeHtml(t)}</span>` : '';

    // ── Overlapping vulnerabilities ──
    const overlapHtml = data.overlap.length === 0
        ? '<p class="muted">No overlapping vulnerabilities.</p>'
        : `<div class="compare-list">${data.overlap.map(o => `
            <div class="compare-item overlap-item">
                <div class="compare-item-main">
                    ${sevPill(o.severity_a)} ${toolPill(o.source_tool)}
                    <span class="compare-item-title">${escapeHtml(o.dedupe_key)}</span>
                    ${o.persistent ? '<span class="persistent-badge" title="Same host hit in both engagements">♻ persistent</span>' : ''}
                </div>
                <div class="compare-item-meta">
                    <span>A: ${o.count_a} on ${o.targets_a.join(', ')}</span>
                    <span>B: ${o.count_b} on ${o.targets_b.join(', ')}</span>
                </div>
            </div>`).join('')}</div>`;

    // ── Unique findings per side ──
    const uniqueHtml = (list) => list.length === 0
        ? '<p class="muted">None.</p>'
        : `<div class="compare-list">${list.map(u => `
            <div class="compare-item">
                <div class="compare-item-main">${sevPill(u.severity)} ${toolPill(u.source_tool)}
                    <span class="compare-item-title">${escapeHtml(u.dedupe_key)}</span>
                    <span class="compare-item-count">×${u.count}</span></div>
                <div class="compare-item-meta"><span>${u.targets.join(', ')}</span></div>
            </div>`).join('')}</div>`;

    // ── Per-target overlap (same host, same vuln) ──
    const perTargetHtml = data.per_target_overlap.length === 0
        ? '<p class="muted">No shared targets with matching vulnerabilities.</p>'
        : `<div class="compare-list">${data.per_target_overlap.map(p => `
            <div class="compare-item">
                <div class="compare-item-main"><span class="target-name">🎯 ${escapeHtml(p.target)}</span></div>
                <div class="compare-item-meta">${p.vulns.map(v => `${sevPill(v.severity)} ${escapeHtml(v.dedupe_key)}`).join(' ')}</div>
            </div>`).join('')}</div>`;

    // ── Attack paths ──
    const pathHtml = (list, label) => list.length === 0
        ? `<p class="muted">No ${label} segments.</p>`
        : `<div class="compare-path">${list.map((s, i) =>
            `<span class="path-seg" style="border-color:${sevColor(s.severity)}" title="${escapeHtml(s.targets.join(', '))}">${sevPill(s.severity)} ${escapeHtml(s.source_tool)} → ${escapeHtml(s.dedupe_key)}</span>${i < list.length - 1 ? '<span class="path-arrow">→</span>' : ''}`
        ).join('')}</div>`;

    box.innerHTML = `
        <div class="compare-summary-cards">
            ${summaryCard(A)}
            <div class="compare-vs-big">⚔️</div>
            ${summaryCard(B)}
        </div>
        <div class="compare-verdict">
            <strong>${data.overlap_count}</strong> overlapping findings ·
            <strong>${data.unique_a_count}</strong> unique to A ·
            <strong>${data.unique_b_count}</strong> unique to B ·
            <strong>${data.common_targets.length}</strong> common targets
        </div>
        <div class="compare-block"><h4>♻ Overlapping Vulnerabilities</h4>${overlapHtml}</div>
        <div class="compare-grid-2">
            <div class="compare-block"><h4>🔺 Unique to A</h4>${uniqueHtml(data.unique_a)}</div>
            <div class="compare-block"><h4>🔻 Unique to B</h4>${uniqueHtml(data.unique_b)}</div>
        </div>
        <div class="compare-block"><h4>🎯 Persistent Exposure (same host, same vuln)</h4>${perTargetHtml}</div>
        <div class="compare-block"><h4>🧭 Attack Paths</h4>
            <div class="compare-path-label">Shared (both campaigns):</div>${pathHtml(data.attack_paths.shared, 'shared')}
            <div class="compare-path-label">A only:</div>${pathHtml(data.attack_paths.a_only, 'A-only')}
            <div class="compare-path-label">B only:</div>${pathHtml(data.attack_paths.b_only, 'B-only')}
        </div>
        <div class="compare-block" style="margin-top:12px">
            <button class="btn-primary" onclick="generateCampaignBrief()">🧠 LLM Analyst Brief</button>
            <div id="campaign-brief" style="margin-top:8px"></div>
        </div>`;
    lastCompareData = data;
}

let lastCompareData = null;

async function generateCampaignBrief() {
    const box = document.getElementById('campaign-brief');
    if (!lastCompareData) { box.innerHTML = '<p class="muted">Run a comparison first.</p>'; return; }
    box.innerHTML = '<p class="muted">🧠 Asking the local LLM for an analyst brief…</p>';
    try {
        const res = await fetch(`/api/campaigns/${lastCompareData.campaign_a.id}/brief`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ compare: lastCompareData }),
        });
        const data = await res.json();
        box.innerHTML = data.brief
            ? `<div class="compare-brief">${escapeHtml(data.brief).replace(/\n/g, '<br>')}</div>`
            : `<p class="muted">${escapeHtml(data.error || 'No brief')}</p>`;
    } catch (e) {
        box.innerHTML = `<p class="muted">Brief failed: ${escapeHtml(e.message)}</p>`;
    }
}

// ═══════════════════════════════════════════════════════════════
// v5.5: Campaign Persistence, Snapshots, Trends, Gantt, Drill-Down,
// Auto-Start Chain, Chained Waves, Reconnection buffer
// ═══════════════════════════════════════════════════════════════

function setPersistStatus(msg) {
    const el = document.getElementById('persist-status');
    if (el) el.textContent = msg;
}
function showPersistResult(html) {
    const el = document.getElementById('persist-result');
    if (el) { el.classList.remove('hidden'); el.innerHTML = html; }
}

async function saveCampaign() {
    if (!currentCampaignId) { setPersistStatus('❌ No active campaign'); return; }
    setPersistStatus('💾 Saving…');
    try {
        const res = await fetch(`/api/campaigns/${currentCampaignId}/save`, { method: 'POST' });
        const data = await res.json();
        setPersistStatus(data.error ? `❌ ${data.error}` : '✅ Saved to disk');
        showPersistResult(data.error ? `<p class="compare-error">${escapeHtml(data.error)}</p>`
            : `<p class="muted" style="font-family:var(--font-mono);font-size:10px">state: ${escapeHtml(data.path)}<br>report: ${escapeHtml(data.report_path || '')}</p>`);
    } catch (e) { setPersistStatus(`❌ ${e.message}`); }
}

async function snapshotCampaign() {
    if (!currentCampaignId) { setPersistStatus('❌ No active campaign'); return; }
    setPersistStatus('📸 Snapshotting…');
    try {
        const res = await fetch(`/api/campaigns/${currentCampaignId}/snapshot`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ label: 'mid-run capture' }),
        });
        const data = await res.json();
        setPersistStatus(data.error ? `❌ ${data.error}` : `✅ Snapshot ${data.snapshot_id} captured`);
        showPersistResult(`<p class="muted">Snapshot ${escapeHtml(data.snapshot_id)} · ${data.findings_total} findings · risk ${data.risk_score}</p>`);
    } catch (e) { setPersistStatus(`❌ ${e.message}`); }
}

async function diffCampaign() {
    if (!currentCampaignId) { setPersistStatus('❌ No active campaign'); return; }
    setPersistStatus('🔍 Diffing…');
    try {
        const res = await fetch(`/api/campaigns/${currentCampaignId}/diff`);
        const data = await res.json();
        if (data.error) { setPersistStatus(`❌ ${data.error}`); showPersistResult(`<p class="compare-error">${escapeHtml(data.error)}</p>`); return; }
        setPersistStatus(`✅ ${data.new_findings_count} new findings since snapshot`);
        const sevDelta = Object.entries(data.severity_delta || {}).filter(([, n]) => n !== 0)
            .map(([s, n]) => `<span class="compare-sev" style="color:${sevColor(s)}">${s}: ${n > 0 ? '+' : ''}${n}</span>`).join(' ');
        showPersistResult(`
            <div class="compare-block">
                <div class="compare-item-main">Snapshot ${escapeHtml(data.label)} (${escapeHtml(data.captured)}) → final ${escapeHtml(data.final_status)}</div>
                <div class="compare-metrics">
                    <div class="compare-metric"><span class="compare-metric-value">${data.findings_total_before}→${data.findings_total_after}</span><span class="compare-metric-label">Findings</span></div>
                    <div class="compare-metric"><span class="compare-metric-value">${data.risk_before}→${data.risk_after}</span><span class="compare-metric-label">Risk (Δ${data.risk_delta})</span></div>
                </div>
                <div class="compare-sev-row">${sevDelta || '<span class="muted">no severity change</span>'}</div>
                ${data.new_findings.length ? `<div class="compare-list">${data.new_findings.map(f =>
                    `<div class="compare-item"><div class="compare-item-main">${sevPill(f.severity)} <span class="compare-item-title">${escapeHtml(f.title || '')}</span></div><div class="compare-item-meta">${escapeHtml(f.target)} · ${escapeHtml(f.evidence || '').slice(0, 120)}</div></div>`
                ).join('')}</div>` : '<p class="muted">No new findings after snapshot.</p>'}
            </div>`);
    } catch (e) { setPersistStatus(`❌ ${e.message}`); }
}

async function loadCampaignHistory() {
    const list = document.getElementById('campaign-history-list');
    const status = document.getElementById('history-status');
    if (list) { list.classList.remove('hidden'); list.innerHTML = '<p class="muted">Loading history…</p>'; }
    try {
        const res = await fetch('/api/campaigns/history');
        const camps = await res.json();
        if (!camps.length) {
            if (list) list.innerHTML = '<p class="muted">No campaign history yet. Run a campaign and click “Save to Disk”.</p>';
            if (status) status.textContent = '';
            return;
        }
        if (status) status.textContent = `${camps.length} campaign(s)`;
        if (list) list.innerHTML = `<div class="compare-list">${camps.map(c => `
            <div class="compare-item">
                <div class="compare-item-main">
                    <span class="compare-item-title">${escapeHtml(c.name || c.id)}</span>
                    ${c.archived ? '<span class="persistent-badge">🗂 archived</span>' : '<span class="persistent-badge" style="color:var(--accent-green);border-color:var(--accent-green)">● live</span>'}
                    <span class="compare-item-meta">${escapeHtml(c.status)} · ${c.findings_total} findings · risk ${c.risk_score}</span>
                </div>
                <div class="compare-item-meta">${escapeHtml(c.created || '')} · ${c.target_count} targets</div>
                <div style="display:flex;gap:6px;margin-top:6px">
                    <button class="tactical-btn execute" onclick="loadHistoryCampaign('${escapeHtml(c.id)}')">📂 Load</button>
                    <button class="tactical-btn" onclick="compareWithHistory('${escapeHtml(c.id)}')">⚔️ Compare</button>
                </div>
            </div>`).join('')}</div>`;
    } catch (e) {
        if (list) list.innerHTML = `<p class="compare-error">${escapeHtml(e.message)}</p>`;
    }
}

async function loadHistoryCampaign(id) {
    try {
        const res = await fetch(`/api/campaigns/${encodeURIComponent(id)}/load`, { method: 'POST' });
        const data = await res.json();
        if (data.error) { addSystemMessage(`❌ ${escapeHtml(data.error)}`); return; }
        currentCampaignId = id;
        addSystemMessage(`🗂 Loaded campaign ${escapeHtml(id)} — open the C2 panel to review`);
        openCampaignPanel();
    } catch (e) { addSystemMessage(`❌ ${escapeHtml(e.message)}`); }
}

async function compareWithHistory(id) {
    try {
        const res = await fetch(`/api/campaigns/${encodeURIComponent(id)}/load`, { method: 'POST' });
        const data = await res.json();
        if (data.error) { addSystemMessage(`❌ ${escapeHtml(data.error)}`); return; }
        const sel = document.getElementById('compare-campaign-b');
        if (sel) {
            sel.value = id;
            const ev = new Event('change');
            sel.dispatchEvent(ev);
        }
        await loadCompareSelects();
        addSystemMessage(`🗂 Loaded ${escapeHtml(id)} for comparison`);
    } catch (e) { /* silent */ }
}

async function loadCampaignTrends() {
    const el = document.getElementById('campaign-trends');
    const status = document.getElementById('trends-status');
    if (el) { el.classList.remove('hidden'); el.innerHTML = '<p class="muted">Scanning all campaigns…</p>'; }
    try {
        const res = await fetch('/api/campaigns/trends');
        const data = await res.json();
        if (status) status.textContent = `${data.campaigns_scanned || 0} campaign(s) · ${data.persistent_exposures || 0} persistent`;
        if (!data.leaderboard || !data.leaderboard.length) {
            if (el) el.innerHTML = '<p class="muted">No exposures found across campaigns yet.</p>';
            return;
        }
        if (el) el.innerHTML = `<div class="compare-list">${data.leaderboard.map(x => {
            const heat = Object.entries(x.severity_heat || {}).filter(([, n]) => n > 0)
                .map(([s, n]) => `<span class="compare-sev" style="color:${sevColor(s)}">${s}:${n}</span>`).join(' ');
            const trendColor = x.trend.includes('rising') ? 'var(--accent-red)' : x.trend.includes('declining') ? 'var(--accent-green)' : 'var(--accent-yellow)';
            return `<div class="compare-item">
                <div class="compare-item-main">
                    ${sevPill(x.worst_severity)} <span class="compare-item-title">${escapeHtml(x.dedupe_key)}</span>
                    <span class="compare-item-count">×${x.occurrences}</span>
                    <span class="persistent-badge" style="color:${trendColor};border-color:${trendColor}">${escapeHtml(x.trend)}</span>
                    ${x.persistent ? '<span class="persistent-badge">♻ persistent</span>' : ''}
                </div>
                <div class="compare-item-meta">${heat || '<span class="muted">no heat</span>'} · targets: ${escapeHtml((x.targets || []).join(', '))}</div>
            </div>`;
        }).join('')}</div>`;
    } catch (e) {
        if (el) el.innerHTML = `<p class="compare-error">${escapeHtml(e.message)}</p>`;
    }
}

async function loadCampaignGantt() {
    const el = document.getElementById('campaign-gantt');
    const status = document.getElementById('gantt-status');
    if (!currentCampaignId) { if (status) status.textContent = '❌ No active campaign'; return; }
    if (el) { el.classList.remove('hidden'); el.innerHTML = '<p class="muted">Building timeline…</p>'; }
    try {
        const res = await fetch(`/api/campaigns/${currentCampaignId}/gantt`);
        const data = await res.json();
        const runs = data.runs || [];
        if (!runs.length) {
            if (status) status.textContent = 'No parallel runs found';
            if (el) el.innerHTML = '<p class="muted">No multi-target runs recorded for this campaign yet.</p>';
            return;
        }
        if (status) status.textContent = `${runs.length} run(s)`;
        // Compute global min/max for the time axis
        const allTimes = [];
        runs.forEach(r => { if (r.started) allTimes.push(new Date(r.started).getTime()); if (r.finished) allTimes.push(new Date(r.finished).getTime()); });
        const t0 = Math.min(...allTimes), t1 = Math.max(...allTimes);
        const span = Math.max(1, t1 - t0);
        const bar = (start, finish, color, label, title) => {
            const s = start ? new Date(start).getTime() : t0;
            const f = finish ? new Date(finish).getTime() : t1;
            const left = ((s - t0) / span) * 100;
            const width = Math.max(2, ((f - s) / span) * 100);
            return `<div class="gantt-row"><span class="gantt-label">${escapeHtml(label)}</span><div class="gantt-track"><div class="gantt-bar" style="left:${left}%;width:${width}%;background:${color}" title="${escapeHtml(title || label)}"></div></div></div>`;
        };
        let html = '<div class="gantt-wrap"><div class="gantt-axis"><span>start</span><span>finish</span></div>';
        runs.forEach(r => {
            html += `<div class="gantt-run-header">${escapeHtml(r.workflow)} ${r.parallel ? '⚡parallel' : ''} · <code>${escapeHtml(r.run_id || '')}</code></div>`;
            const jobs = r.jobs || {};
            Object.entries(jobs).forEach(([name, j]) => {
                html += bar(j.started, j.finished, 'var(--accent-cyan)', name, `job ${name}`);
            });
            (r.targets || []).forEach(t => {
                html += bar(t.started, t.finished, t.status === 'complete' ? 'var(--accent-green)' : t.status === 'failed' ? 'var(--accent-red)' : 'var(--accent-yellow)', `${t.target} (${t.status})`, t.target);
            });
        });
        html += '</div>';
        if (el) el.innerHTML = html;
    } catch (e) {
        if (el) el.innerHTML = `<p class="compare-error">${escapeHtml(e.message)}</p>`;
    }
}

async function openTargetDrilldown(target) {
    const el = document.getElementById('campaign-drilldown');
    if (!currentCampaignId) return;
    el.classList.remove('hidden');
    el.innerHTML = `<p class="muted">Loading drill-down for ${escapeHtml(target)}…</p>`;
    try {
        const res = await fetch(`/api/campaigns/${currentCampaignId}/drilldown`);
        const data = await res.json();
        const t = (data.targets || {})[target];
        if (!t) { el.innerHTML = '<p class="muted">No drill-down data.</p>'; return; }
        const sevP = (sev) => `<span class="sev-pill" style="color:${sevColor(sev)};border-color:${sevColor(sev)}">${escapeHtml(sev)}</span>`;
        el.innerHTML = `
            <div class="compare-block">
                <div class="compare-item-main"><span class="target-name">🎯 ${escapeHtml(target)}</span> ${sevP(t.status)} <span class="compare-item-meta">${t.progress}% · drift ${t.drift_score}</span></div>
                <div class="compare-item-meta">started ${escapeHtml(t.started || '—')} · finished ${escapeHtml(t.finished || '—')} · task ${escapeHtml(t.task_id || '—')}</div>
                ${t.findings && t.findings.length ? `<div style="margin-top:6px"><b>Findings:</b></div><div class="compare-list">${t.findings.map(f =>
                    `<div class="compare-item"><div class="compare-item-main">${sevP(f.severity)} <span class="compare-item-title">${escapeHtml(f.title || '')}</span></div><div class="compare-item-meta">${escapeHtml(f.evidence || '')}</div></div>`
                ).join('')}</div>` : '<p class="muted">No retained findings.</p>'}
                ${t.steps && t.steps.length ? `<div style="margin-top:6px"><b>Steps (${t.steps.length}):</b></div><div class="compare-list">${t.steps.map(s =>
                    `<div class="compare-item"><div class="compare-item-main"><span class="compare-item-title">${escapeHtml(s.step || s.tool || 'step')}</span> <span class="compare-item-meta">${escapeHtml(s.status || '')} · drift ${s.drift_score ?? 0}</span></div><div class="compare-item-meta">${escapeHtml(s.command || s.description || '')}</div></div>`
                ).join('')}</div>` : '<p class="muted">No step list saved.</p>'}
            </div>`;
    } catch (e) {
        el.innerHTML = `<p class="compare-error">${escapeHtml(e.message)}</p>`;
    }
}

async function startCampaignChain() {
    if (!currentCampaignId) { addSystemMessage('❌ No active campaign'); return; }
    const status = document.getElementById('chain-status');
    const result = document.getElementById('chain-result');
    if (status) status.textContent = '🔁 Starting chain…';
    if (result) { result.classList.remove('hidden'); result.innerHTML = '<p class="muted">Chain running — LLM picks each next objective…</p>'; }
    try {
        const res = await fetch(`/api/campaigns/${currentCampaignId}/chain`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
        });
        const data = await res.json();
        if (data.error) { if (status) status.textContent = `❌ ${data.error}`; return; }
        if (status) status.textContent = `▶ chain ${data.chain_id} started`;
        addSystemMessage(`🔁 Campaign auto-start chain launched: ${escapeHtml(data.chain_id)}`);
    } catch (e) {
        if (status) status.textContent = `❌ ${e.message}`;
    }
}

async function runParallelChain() {
    if (!currentCampaignId) { addSystemMessage('❌ No active campaign'); return; }
    const status = document.getElementById('parallel-status');
    const input = document.getElementById('parallel-wf-input');
    const names = (input?.value || '').split(',').map(s => s.trim()).filter(Boolean);
    try {
        const res = await fetch(`/api/campaigns/${currentCampaignId}`);
        const campaign = await res.json();
        const targets = campaign.targets || [];
        if (!names.length || !targets.length) { if (status) status.textContent = '⚠️ Enter workflows + campaign needs targets'; return; }
        const jobs = names.map(w => ({ workflow: w, targets, variables: { target: targets[0] } }));
        const start = await fetch('/api/workflows/parallel-chain', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jobs, campaign_id: currentCampaignId, max_waves: 3 }),
        });
        const data = await start.json();
        if (data.error) { if (status) status.textContent = `❌ ${data.error}`; return; }
        if (status) status.textContent = `🔁 chained waves ${data.chain_id} started (${data.max_waves} waves)`;
        addSystemMessage(`🔁 Chained parallel waves launched: ${escapeHtml(data.chain_id)}`);
    } catch (e) {
        if (status) status.textContent = `❌ ${e.message}`;
    }
}

// ═══════════════════════════════════════════════════════════════
// Ctrl+Hold Tooltip System (v5.5)
// ═══════════════════════════════════════════════════════════════
// Hold the LEFT CONTROL key while hovering any clickable/input element to
// see a specific, detailed description of what it does. Elements opt in via
// data-ctrl-help attributes; generic fallbacks cover buttons/inputs/links.
let ctrlHeld = false;
let ctrlTooltipEl = null;
let ctrlHoverTarget = null;
let ctrlHoverTimer = null;

const CTRL_HELP_FALLBACKS = [
    { sel: 'button', desc: 'Activate this action. Most buttons run a tool, workflow, or dashboard update.' },
    { sel: 'input[type="text"], input:not([type]), textarea', desc: 'Text entry field. Press Enter (chat) or tab out to commit your input.' },
    { sel: 'input[type="checkbox"]', desc: 'Toggle switch. Enables or disables the associated mode.' },
    { sel: 'select', desc: 'Dropdown selector. Choose an option to filter or configure this panel.' },
    { sel: 'a', desc: 'Link — navigates to the referenced resource.' },
    { sel: '[onclick]', desc: 'Clickable element. Select it to perform its action.' },
    { sel: '.tab', desc: 'Tab — switches the results panel to this view.' },
    { sel: '.target-card', desc: 'Target card — click to open the per-target drill-down (steps, drift, findings, timeline).' },
    { sel: '.tactical-btn', desc: 'Tactical action button — execute or dismiss an AI-suggested next step.' },
    { sel: '.memory-target-row', desc: 'Stored target — click to query all past findings for this host from vector memory.' },
    { sel: '.attackgraph-canvas svg g[onclick], .attackmatrix-table td', desc: 'Graph/matrix element — click for detail.' },
    { sel: '.quick-cmd', desc: 'Quick command — one-click send a common pentest command to the LLM.' },
    { sel: '.attack-chain', desc: 'Attack chain — click to run this preset attack chain via the LLM.' },
];

function ensureCtrlTooltipEl() {
    if (ctrlTooltipEl) return;
    ctrlTooltipEl = document.createElement('div');
    ctrlTooltipEl.id = 'ctrl-tooltip';
    ctrlTooltipEl.style.cssText = 'display:none;position:fixed;z-index:99999;max-width:340px;padding:8px 10px;' +
        'background:#0b1220;border:1px solid var(--accent-cyan, #22d3ee);border-radius:8px;' +
        'color:var(--text, #e2e8f0);font-size:11.5px;line-height:1.45;box-shadow:0 6px 20px rgba(0,0,0,.55);' +
        'pointer-events:none;font-family:inherit;';
    document.body.appendChild(ctrlTooltipEl);
}

function ctrlTooltipText(el) {
    if (!el) return null;
    // Walk up from the target to find a data-ctrl-help or a fallback match
    let node = el;
    while (node && node !== document.body) {
        const explicit = node.getAttribute && node.getAttribute('data-ctrl-help');
        if (explicit) return explicit;
        node = node.parentElement;
    }
    for (const fb of CTRL_HELP_FALLBACKS) {
        if (el.matches && el.matches(fb.sel)) return fb.desc;
    }
    return null;
}

function showCtrlTooltip(x, y) {
    ensureCtrlTooltipEl();
    const text = ctrlTooltipText(ctrlHoverTarget);
    if (!text) { hideCtrlTooltip(); return; }
    ctrlTooltipEl.textContent = '🔧 ' + text;
    ctrlTooltipEl.style.display = 'block';
    // Keep the bubble inside the viewport
    const pad = 12;
    const bw = ctrlTooltipEl.offsetWidth, bh = ctrlTooltipEl.offsetHeight;
    let left = x + 14, top = y + 14;
    if (left + bw > window.innerWidth - pad) left = x - bw - 14;
    if (top + bh > window.innerHeight - pad) top = y - bh - 14;
    ctrlTooltipEl.style.left = left + 'px';
    ctrlTooltipEl.style.top = top + 'px';
}

function hideCtrlTooltip() {
    if (ctrlTooltipEl) ctrlTooltipEl.style.display = 'none';
    if (ctrlHoverTimer) { clearTimeout(ctrlHoverTimer); ctrlHoverTimer = null; }
}

function initCtrlTooltips() {
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Control' || e.keyCode === 17) {
            ctrlHeld = true;
            if (ctrlHoverTarget) { showCtrlTooltip(ctrlHoverTarget._cx || 0, ctrlHoverTarget._cy || 0); }
        }
    });
    document.addEventListener('keyup', (e) => {
        if (e.key === 'Control' || e.keyCode === 17) { ctrlHeld = false; hideCtrlTooltip(); }
    });
    document.addEventListener('mouseover', (e) => {
        if (!e.target || !e.target.closest) return;
        const el = e.target.closest('button, input, select, textarea, a, .tab, .target-card, .tactical-btn, .quick-cmd, .attack-chain, [onclick], .memory-target-row');
        if (!el) { ctrlHoverTarget = null; hideCtrlTooltip(); return; }
        ctrlHoverTarget = el;
        el._cx = e.clientX; el._cy = e.clientY;
        if (ctrlHeld) showCtrlTooltip(e.clientX, e.clientY);
    });
    document.addEventListener('mousemove', (e) => {
        if (ctrlHeld && ctrlHoverTarget && ctrlHoverTarget === (e.target && e.target.closest ? e.target.closest('button, input, select, textarea, a, .tab, .target-card, .tactical-btn, .quick-cmd, .attack-chain, [onclick], .memory-target-row') : null)) {
            ctrlHoverTarget._cx = e.clientX; ctrlHoverTarget._cy = e.clientY;
            showCtrlTooltip(e.clientX, e.clientY);
        }
    });
    document.addEventListener('mouseout', (e) => {
        if (ctrlHoverTarget && e.target && (e.target === ctrlHoverTarget || ctrlHoverTarget.contains && ctrlHoverTarget.contains(e.target))) {
            // keep tooltip while moving within the element; hide when leaving it
            if (!ctrlHoverTarget.contains(e.relatedTarget)) { hideCtrlTooltip(); }
        }
    });
    // Never let ctrl stick if the window loses focus
    window.addEventListener('blur', () => { ctrlHeld = false; hideCtrlTooltip(); });
}

// ═══════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
}

function formatMarkdown(text) {
    return (text || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/```([\s\S]*?)```/g, '<pre>$1</pre>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\n/g, '<br>');
}

// ═══════════════════════════════════════════════════════════════
// Mission Control (v4.2) — Autonomous Kill Chain Visualizer
// ═══════════════════════════════════════════════════════════════
const MISSION_PHASE_COLORS = {
    recon: 'var(--accent-cyan)',
    vuln: 'var(--accent-orange)',
    exploit: 'var(--accent-red)',
    postex: 'var(--accent-purple)',
};

const MISSION_SEV_COLORS = {
    critical: '#ef4444', high: '#f97316', medium: '#f59e0b',
    low: '#eab308', info: '#64748b',
};

const RETRY_LEVEL_COLORS = {
    retry: 'var(--accent-yellow)',
    alternative: 'var(--accent-orange)',
    llm_suggest: 'var(--accent-red)',
    skip_phase: 'var(--accent-purple)',
    exhausted: 'var(--accent-red)',
};

async function loadMissionControl() {
    try {
        const res = await fetch('/api/autonomous/mission-control');
        const data = await res.json();
        renderMissionControl(data);
    } catch (e) {
        console.error('Mission Control load failed:', e);
    }
}

function renderMissionControl(data) {
    if (!data || data.error) {
        data = { state: 'idle', targets: [], retry_history: [], timeline: [] };
    }
    renderMissionSummary(data);
    renderMissionGrid(data.targets || []);
    renderMissionHeatmap(data.targets || []);
    renderMissionRetry(data.retry_history || []);
    renderMissionTimeline(data.timeline || [], data.targets || []);
}

function renderMissionSummary(data) {
    const el = document.getElementById('mission-summary');
    if (!el) return;
    const state = (data.state || 'idle').toUpperCase();
    const stateColor = data.state === 'running' ? 'var(--accent-green)' :
                       data.state === 'paused' ? 'var(--accent-yellow)' :
                       data.state === 'complete' ? 'var(--accent-cyan)' :
                       data.state === 'failed' ? 'var(--accent-red)' :
                       'var(--text-muted)';
    if (data.state === 'idle' || (data.targets_count || 0) === 0) {
        el.innerHTML = '<p class="muted">No autonomous engagement running. Start one to see live kill-chain progress here.</p>';
        return;
    }
    const elapsed = Math.round(data.elapsed_seconds || 0);
    const h = Math.floor(elapsed / 3600), m = Math.floor((elapsed % 3600) / 60), s = elapsed % 60;
    const elapsedStr = `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
    el.innerHTML = `
        <div class="mission-stat-row">
            <div class="mission-stat"><span class="ms-val">${state}</span><span class="ms-label" style="color:${stateColor}">State</span></div>
            <div class="mission-stat"><span class="ms-val">${data.targets_count || 0}</span><span class="ms-label">Targets</span></div>
            <div class="mission-stat"><span class="ms-val">${data.targets_completed || 0}</span><span class="ms-label">Completed</span></div>
            <div class="mission-stat"><span class="ms-val">${data.total_steps || 0}</span><span class="ms-label">Steps</span></div>
            <div class="mission-stat"><span class="ms-val">${data.total_findings || 0}</span><span class="ms-label">Findings</span></div>
            <div class="mission-stat"><span class="ms-val">${elapsedStr}</span><span class="ms-label">Elapsed</span></div>
        </div>
        ${data.objective ? `<div class="mission-objective">🎯 <strong>Objective:</strong> ${escapeHtml(data.objective)}</div>` : ''}
    `;
}

function renderMissionGrid(targets) {
    const el = document.getElementById('mission-grid');
    if (!el) return;
    if (!targets.length) {
        el.innerHTML = '';
        return;
    }
    el.innerHTML = targets.map(t => {
        const phaseColor = MISSION_PHASE_COLORS[t.current_phase] || 'var(--accent-cyan)';
        const statusColor = t.completed ? 'var(--accent-green)' :
                            t.retry_level_raw > 0 ? 'var(--accent-red)' :
                            'var(--accent-yellow)';
        const tierBadge = t.priority_tier === 'hot' ? '<span class="mc-tier hot">🔥 HOT</span>' :
                          t.priority_tier === 'chilled' ? '<span class="mc-tier chilled">🧊 CHILLED</span>' : '';
        const retryBadge = t.retry_level_raw > 0
            ? `<span class="mc-retry-badge" style="color:${RETRY_LEVEL_COLORS[t.retry_level] || 'var(--accent-red)'}">↻ ${escapeHtml(t.retry_level)}</span>`
            : '';
        const bars = (t.phase_bars || []).map(p => {
            const color = MISSION_PHASE_COLORS[p.phase] || 'var(--accent-cyan)';
            const current = p.is_current ? ' mc-current' : '';
            return `
                <div class="mc-phase${current}">
                    <div class="mc-phase-label">
                        <span>${p.phase.toUpperCase()}</span>
                        <span class="mc-phase-meta">${p.iterations}/${p.budget} iters · ${p.findings} finds${p.failures ? ` · ⚠️${p.failures}` : ''}</span>
                    </div>
                    <div class="mc-bar">
                        <div class="mc-bar-fill" style="width:${p.pct}%;background:${color}"></div>
                        ${p.is_current ? '<div class="mc-pulse"></div>' : ''}
                    </div>
                </div>`;
        }).join('');
        const sev = t.severity_counts || {};
        const sevBadges = ['critical','high','medium','low','info'].map(s =>
            `<span class="sev-dot sev-${s}" title="${s}: ${sev[s] || 0}">${sev[s] || 0}</span>`).join(' ');
        const transitions = (t.phase_transitions || []).map(pt =>
            `${pt.phase}`).join(' → ');
        return `
            <div class="target-card mc-target-card">
                <div class="target-header">
                    <span class="target-name">${escapeHtml(t.target)}</span>
                    <span class="mc-target-right">${tierBadge}${retryBadge}</span>
                </div>
                <div class="mc-phase-row">${bars}</div>
                <div class="mc-footer">
                    <span class="mc-phase-name" style="color:${phaseColor}">▶ ${escapeHtml(t.current_phase).toUpperCase()}</span>
                    <span class="mc-status" style="color:${statusColor}">${t.completed ? '✓ COMPLETE' : '⏳ ACTIVE'}</span>
                </div>
                <div class="mc-sev-row">${sevBadges}</div>
                ${transitions ? `<div class="mc-transitions">🔁 ${escapeHtml(transitions)}</div>` : ''}
                ${t.last_error ? `<div class="target-error">${escapeHtml(String(t.last_error).slice(0, 140))}</div>` : ''}
            </div>`;
    }).join('');
}

function renderMissionHeatmap(targets) {
    const el = document.getElementById('mission-heatmap');
    if (!el) return;
    const sevs = ['critical', 'high', 'medium', 'low', 'info'];
    let hasAny = false;
    let html = '<table class="heatmap-table"><thead><tr><th>Target</th>';
    for (const s of sevs) html += `<th style="color:${MISSION_SEV_COLORS[s]}">${s.slice(0,3).toUpperCase()}</th>`;
    html += '<th>TOT</th></tr></thead><tbody>';
    for (const t of targets) {
        const sev = t.severity_counts || {};
        let rowTotal = 0;
        for (const s of sevs) rowTotal += sev[s] || 0;
        if (rowTotal === 0 && !t.completed) continue;
        hasAny = true;
        html += `<tr><td class="hm-tool">${escapeHtml(t.target)}</td>`;
        for (const s of sevs) {
            const count = sev[s] || 0;
            const intensity = count > 0 ? Math.min(1.0, count / 5) : 0;
            html += `<td class="hm-cell" style="background:${MISSION_SEV_COLORS[s]};opacity:${0.12 + intensity * 0.88}">${count || ''}</td>`;
        }
        html += `<td class="hm-total">${rowTotal}</td></tr>`;
    }
    html += '</tbody></table>';
    el.innerHTML = hasAny ? html : '<p class="muted">No findings yet.</p>';
}

function renderMissionRetry(history) {
    const el = document.getElementById('mission-retry');
    if (!el) return;
    if (!history.length) {
        el.innerHTML = '<p class="muted">No retry escalations.</p>';
        return;
    }
    el.innerHTML = history.map((r, i) => {
        const color = RETRY_LEVEL_COLORS[r.level] || 'var(--accent-red)';
        return `
            <div class="mc-retry-entry">
                <span class="mc-retry-time">${escapeHtml((r.ts || '').slice(11, 19))}</span>
                <span class="mc-retry-level" style="color:${color}">↻ ${escapeHtml(r.level).toUpperCase()}</span>
                <span class="mc-retry-target">${escapeHtml(r.target)}</span>
                <span class="mc-retry-phase">[${escapeHtml(r.phase)}]</span>
                ${r.last_tool ? `<code>${escapeHtml(r.last_tool)}</code>` : ''}
                ${r.last_error ? `<span class="mc-retry-err">${escapeHtml(String(r.last_error).slice(0, 80))}</span>` : ''}
            </div>`;
    }).reverse().join('');
}

function renderMissionTimeline(timeline, targets) {
    const el = document.getElementById('mission-timeline');
    if (!el) return;
    // The mission_control() payload always carries the global timeline
    // (phase_start + phase_complete events). Only fall back to merging
    // per-target phase_transitions when that global timeline is absent,
    // otherwise every transition would render twice (advance_phase() and
    // _transition_phase() both record the same transition).
    let merged = [...(timeline || [])];
    if (!merged.length) {
        for (const t of targets) {
            for (const pt of (t.phase_transitions || [])) {
                merged.push({
                    ts: pt.ts, target: t.target, event: 'phase_complete', phase: pt.phase,
                });
            }
        }
    }
    if (!merged.length) {
        el.innerHTML = '<p class="muted">No phase transitions yet.</p>';
        return;
    }
    // Sort by timestamp
    merged.sort((a, b) => String(a.ts || '').localeCompare(String(b.ts || '')));
    el.innerHTML = merged.slice(-60).map(ev => {
        const color = MISSION_PHASE_COLORS[(ev.phase || '').toLowerCase()] || 'var(--accent-cyan)';
        const icon = ev.event === 'phase_complete' ? '🏁' : '▶';
        return `
            <div class="mc-timeline-entry">
                <span class="mc-tl-dot" style="background:${color}"></span>
                <span class="mc-tl-time">${escapeHtml((ev.ts || '').slice(11, 19))}</span>
                <span class="mc-tl-icon">${icon}</span>
                <span class="mc-tl-target">${escapeHtml(ev.target)}</span>
                <span class="mc-tl-phase" style="color:${color}">${escapeHtml(ev.phase)}</span>
                <span class="mc-tl-event">${escapeHtml(ev.event)}</span>
            </div>`;
    }).join('');
}