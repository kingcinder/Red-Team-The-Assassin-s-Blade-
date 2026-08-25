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
    loadStatus();
    loadSessions();
    loadSafety();
    initInput();
    initTabs();
    initAutonomousToggle();
    loadCampaignSelectOptions();
});

// ═══════════════════════════════════════════════════════════════
// WebSocket
// ═══════════════════════════════════════════════════════════════
function initSocket() {
    socket = io();

    socket.on('connect', () => {
        console.log('Connected to RedTeam Harness v2');
        updateLLMStatus(true);
    });

    socket.on('disconnect', () => updateLLMStatus(false));

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

    // ── Campaign events ──
    socket.on('campaign_target_update', (data) => {
        if (data.campaign_id === currentCampaignId) {
            refreshCampaignData();
        }
    });

    socket.on('campaign_update', (data) => {
        if (data.campaign_id === currentCampaignId) {
            refreshCampaignData();
        }
    });

    socket.on('campaign_complete', (data) => {
        if (data.campaign_id === currentCampaignId) {
            refreshCampaignData();
            addSystemMessage(`📡 Campaign ${data.status}: ${data.error || 'all targets processed'}`);
            if (campaignPollTimer) {
                clearInterval(campaignPollTimer);
                campaignPollTimer = null;
            }
        }
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
// Results Area
// ═══════════════════════════════════════════════════════════════
function showResultsTab(tab) {
    document.querySelectorAll('.results-content').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('.results-tabs .tab').forEach(t => t.classList.remove('active'));
    const target = document.getElementById(`results-${tab}`);
    if (target) target.classList.remove('hidden');
    const tabs = document.querySelectorAll('.results-tabs .tab');
    for (const t of tabs) {
        if (t.textContent.toLowerCase().includes(tab)) t.classList.add('active');
    }
    // Refresh campaign mini-view when Campaign tab is selected
    if (tab.includes('campaign') && currentCampaignId) {
        refreshCampaignData();
    }
    // Load vector memory panel when Memory tab is selected
    if (tab === 'memory') {
        loadMemoryPanel();
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
            <div class="target-card">
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
            body: JSON.stringify({}),
        });
        const data = await res.json();
        if (data.error) {
            addSystemMessage(`❌ Campaign start failed: ${escapeHtml(data.error)}`);
        } else {
            addSystemMessage(`📡 Campaign started: ${escapeHtml(data.workflow)} against ${data.targets?.length || 0} targets`);
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